# XDP Redirect — 基于 eBPF Map 的内核层数据包重定向

## 目录

- [实验目标](#实验目标)
- [数据包转发路径](#数据包转发路径)
- [eBPF Map 结构详解](#ebpf-map-结构详解)
- [XDP 程序段](#xdp-程序段)
- [Checksum 处理策略](#checksum-处理策略)
- [关键设计决策](#关键设计决策)
- [已知问题与解决方案](#已知问题与解决方案)
- [环境要求](#环境要求)
- [从零复现](#从零复现)
- [验证与调试](#验证与调试)
- [清理](#清理)
- [文件说明](#文件说明)

---

## 实验目标

在**不经过内核协议栈**的前提下，用 XDP 程序在两个 network namespace 之间转发数据包：

```
NS1 (10.0.1.1)                                      NS2 (10.0.1.2)
    │                                                     │
  v1-ns1 ──── v1-host [XDP] ════ v2-host [XDP] ──── v2-ns2
                  ↑                    ↑
             xdp_redirect_map     xdp_redirect_map
             (同一程序实例，共享 maps)
```

ping 从 NS1 发出后，数据包**在 v1-host 的 XDP 钩子处被拦截**，直接重定向到 v2-host 的发送队列，绕过宿主机的 IP 路由和 TCP/IP 协议栈，再由 veth 驱动送入 NS2。

---

## 数据包转发路径

以 NS1 → NS2 方向为例：

```
NS1 发出 ICMP echo request
  │
  ▼ v1-ns1（veth NS 侧，挂 xdp_pass）
  │
  ▼ v1-host（veth 宿主机侧，挂 xdp_redirect_map）
       XDP 程序执行：
       1. 查 redirect_params[ingress_ifindex] → 目标 MAC（v2-ns2 的 MAC）
       2. 改写 eth->h_dest
       3. 全量重算 IP / L4 checksum（fix_checksums）
       4. 查 tx_port[ingress_ifindex] → 目标 ifindex（v2-host）
       5. bpf_redirect_map(&tx_port, in_ifindex, XDP_PASS) → XDP_REDIRECT
  │
  ▼ veth 驱动调用 veth_xdp_xmit → 将帧入队 v2-host 的 XDP TX 环
  │
  ▼ v2-ns2（veth NS 侧，挂 xdp_pass，满足 peer-has-XDP 要求）
  │
  ▼ NS2 内核协议栈收到帧，生成 echo reply，走反向路径回 NS1
```

---

## eBPF Map 结构详解

项目使用两张转发 Map，由 v1-host 和 v2-host **共享同一实例**：

### `tx_port` — `BPF_MAP_TYPE_DEVMAP`

```c
struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __type(key,   int);   /* 入方向 ifindex */
    __type(value, int);   /* 出方向 ifindex */
    __uint(max_entries, 256);
} tx_port SEC(".maps");
```

填充内容（双向）：

```
key=ifindex(v1-host)  →  value=ifindex(v2-host)   # NS1 → NS2
key=ifindex(v2-host)  →  value=ifindex(v1-host)   # NS2 → NS1
```

**DEVMAP 的特殊性**：`bpf_redirect_map` 配合 DEVMAP 时，内核会在 XDP 程序返回后批量执行 `ndo_xdp_xmit`，比 `bpf_redirect` 更高效，也是 veth 驱动唯一支持的 XDP 重定向路径。

### `redirect_params` — `BPF_MAP_TYPE_HASH`

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key,   int);                    /* 入方向 ifindex */
    __type(value, unsigned char[ETH_ALEN]); /* 目标 MAC 地址（6 字节） */
    __uint(max_entries, 128);
} redirect_params SEC(".maps");
```

填充内容：

```
key=ifindex(v1-host)  →  value=MAC(v2-ns2)   # 改写目标 MAC，使帧被 NS2 接受
key=ifindex(v2-host)  →  value=MAC(v1-ns1)   # 改写目标 MAC，使帧被 NS1 接受
```

**为什么要改写目标 MAC**：原始帧的目标 MAC 是 v1-host 自身（ARP 的目标是网关），经 XDP 改写后必须换成最终接收方的 MAC，否则帧会被 NS2 内的 veth 过滤丢弃。

### `xdp_stats` — `BPF_MAP_TYPE_ARRAY`

```c
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key,   __u32);   /* XDP 动作编号（0=ABORTED 1=DROP 2=PASS 3=TX 4=REDIRECT） */
    __type(value, __u64);   /* 计数 */
    __uint(max_entries, 64);
} xdp_stats SEC(".maps");
```

每个 XDP 程序退出前调用 `xdp_stats_record_action`，将计数写入此 Map，供用户态读取统计。

### Map 共享机制

两个接口使用**同一个程序实例**，天然共享同一套 Map：

```bash
# 只在 v1-host 加载一次，获取程序 ID
ip link set dev v1-host xdp obj xdp_prog_kern.o sec xdp_redirect_map
V1_PROG=$(bpftool net show dev v1-host | grep "driver id" | awk '{print $NF}')

# 将同一程序实例 attach 到 v2-host（共享 maps，无需重新加载）
bpftool net attach xdp id $V1_PROG dev v2-host
```

更新一次 Map 即对两个接口同时生效。

---

## XDP 程序段

`xdp_prog_kern.c` 中包含两个 SEC：

| Section | 函数 | 挂载位置 | 用途 |
|---------|------|----------|------|
| `xdp_redirect_map` | `xdp_redirect_map_func` | v1-host、v2-host | 查 Map 改写目标 MAC，全量重算 checksum，重定向到对端 |
| `xdp_pass` | `xdp_pass_func` | v1-ns1、v2-ns2 | 直接返回 `XDP_PASS`，满足 veth `ndo_xdp_xmit` 要求 |

---

## Checksum 处理策略

### 全量重算（`xdp_redirect_map`）

redirect 程序无法得知入包是否携带 `CHECKSUM_PARTIAL`（XDP 无法读 `skb->ip_summed`），因此对所有协议字段从零重算：

| 层 | 方法 | 原因 |
|----|------|------|
| IPv4 header | `bpf_csum_diff(iph, sizeof(struct iphdr), ...)` | 编译期常量 20 字节，verifier 接受 |
| 伪首部（IPv4/IPv6） | `bpf_csum_diff` over 栈 struct | 无 packet-pointer 限制 |
| L4 header + payload | `csum_loop()`（逐 16 位字循环） | 变长 packet 数据，每步独立 bounds check |

L4 payload 超过 1500 字节（`CSUM_MAX_WORDS * 2`）时返回 `-1`，调用方退回 `XDP_PASS` 交由内核软件补全。

---

## 关键设计决策

| 问题 | 选择 | 原因 |
|------|------|------|
| `bpf_redirect` vs `bpf_redirect_map` | `bpf_redirect_map` | veth 的 `veth_xdp_xmit` 只对 DEVMAP 路径生效 |
| 两套 Map vs 共享 Map | 共享（同一程序实例） | 配置一次双向生效，避免状态不一致 |
| 仅单侧挂 XDP vs 双侧 | **双侧都挂** | XDP 只处理入方向，双向通信各需一个入口 |
| namespace 侧是否挂 XDP | **必须挂** `xdp_pass` | `veth_xdp_xmit` 要求 peer 有 native XDP 程序，否则返回 `-ENXIO` |
| native XDP vs generic（skb）模式 | native | generic 模式在 TX 路径上无法绕过 skb，触发不了 `ndo_xdp_xmit` |
| TX checksum offload（ethtool）vs XDP 重算 | **XDP 内重算** | 无需修改发送侧配置，对所有协议透明，`fix_checksums` 统一处理 |

---

## 已知问题与解决方案

### veth TX Checksum Offload 导致 TCP 不通

**现象**：ping 双向通，但 TCP 连接永远超时。

**根本原因**：

veth 默认开启 `tx-checksum-ip-generic`。发送 TCP 包时内核将校验和标记为 `CHECKSUM_PARTIAL`——即"由驱动在 TX 时填充"。XDP 运行在 veth 驱动的 **RX 入口**，此时校验和尚未被计算，包就已经被 redirect。对端收到校验和无效的 TCP 包，内核协议栈静默丢弃，不回 RST。ICMP ping 不受影响，因为 raw socket 在发出前已用 `CHECKSUM_COMPLETE` 算好完整校验和。

```
NS1 TCP 发送路径：

  TCP stack 生成 SYN（checksum = CHECKSUM_PARTIAL，驱动填充）
     │
     ▼ v1-ns1 TX → v1-host RX
     │
     ▼ XDP 在此拦截并 redirect  ← 校验和尚未填充！
     │
     ▼ v2-ns2 收到：checksum invalid → InErrs++ → 静默丢弃
     │
     └─ NS1 等不到 SYN-ACK，connect() timeout
```

**本项目的解决方案**：

在 `fix_checksums()` 中，XDP 程序对每个转发包**主动重算所有 IP 和 L4 校验和**。将校验和字段清零后从头计算，这对已完整的校验和也是正确的，因此无需区分 `CHECKSUM_PARTIAL` 和 `CHECKSUM_COMPLETE`，无需修改发送侧的 ethtool 配置。

**诊断方法**（若 TCP 仍不通时）：

```bash
# 在 NS2 中查看 TCP 统计，InErrs 应为 0
ip netns exec ns2 cat /proc/net/snmp | grep Tcp

# 对比 InSegs 和 InErrs：InErrs == InSegs 说明全部是校验和错误
```

---

## 环境要求

| 组件 | 最低版本 |
|------|----------|
| Linux 内核 | 5.9+（DEVMAP 支持 `bpf_redirect_map`） |
| clang / llvm | 10+ |
| bpftool | 与内核版本匹配 |

安装依赖（Ubuntu / Debian）：

```bash
sudo apt install clang llvm libelf-dev libpcap-dev build-essential \
                 libc6-dev-i386 m4 libbpf-dev xdp-tools
sudo apt install linux-headers-$(uname -r)
sudo apt install linux-tools-common linux-tools-generic
sudo apt install tcpdump iperf3
```

---

## 从零复现

### 第一步：编译

```bash
make clean && make
```

生成：
- `xdp_prog_kern.o` — 内核侧 BPF 字节码（含三个 SEC）
- `xdp_prog_user`   — 用户态 Map 配置工具

### 第二步：一键设置并运行

```bash
sudo bash setup_netns.sh
```

脚本完成以下操作：

1. 清理旧的 namespace、veth、BPF 挂载和 pinned map
2. 创建 network namespace `ns1`、`ns2`
3. 创建两对 veth：`v1-ns1 ↔ v1-host`、`v2-ns2 ↔ v2-host`
4. 配置 IP 地址和默认路由
5. 关闭宿主机侧的 `rp_filter`（否则内核因源 IP 不符路由表而丢包）
6. 写入静态 ARP 条目，避免 STALE → PROBE 导致 TCP SYN-ACK 延迟
7. 在 `v1-ns1`、`v2-ns2` 上加载 `xdp_pass`（满足 `veth_xdp_xmit` 要求）
8. 在 `v1-host` 加载 `xdp_redirect_map`，再将同一程序 attach 到 `v2-host`（共享 maps）
9. Pin maps 到 `/sys/fs/bpf/xdp/globals/`
10. 调用 `xdp_prog_user` 填充双向转发规则

### 第三步：验证连通性

#### ICMP（ping）

```bash
sudo ip netns exec ns1 ping 10.0.1.2
```

预期输出：

```
PING 10.0.1.2 (10.0.1.2) 56(84) bytes of data.
64 bytes from 10.0.1.2: icmp_seq=1 ttl=64 time=0.xxx ms
64 bytes from 10.0.1.2: icmp_seq=2 ttl=64 time=0.xxx ms
```

#### TCP

```bash
# 终端 A：NS2 监听
sudo ip netns exec ns2 nc -l -p 8080

# 终端 B：NS1 连接并发送数据
sudo ip netns exec ns1 bash -c 'echo "hello tcp" | nc -w2 10.0.1.2 8080'
```

验证端口可达（收到 RST 即说明包到达了 NS2）：

```bash
sudo ip netns exec ns1 nc -zv 10.0.1.2 8080
# 期望：Connection to 10.0.1.2 8080 port [tcp/*] succeeded!
```

测试大流量（验证无丢包）：

```bash
# NS2 接收并统计字节数
sudo ip netns exec ns2 bash -c 'nc -l -p 8080 | wc -c' &

# NS1 发送 100 MB
sudo ip netns exec ns1 bash -c 'dd if=/dev/zero bs=1M count=100 | nc -w5 10.0.1.2 8080'
# 期望：NS2 侧输出 104857600
```

用 iperf3 测带宽：

```bash
sudo ip netns exec ns2 iperf3 -s -p 5201 &
sudo ip netns exec ns1 iperf3 -c 10.0.1.2 -p 5201 -t 5
```

#### UDP

```bash
# 终端 A：NS2 监听 UDP
sudo ip netns exec ns2 nc -u -l -p 9090

# 终端 B：NS1 发送 UDP 数据报
sudo ip netns exec ns1 bash -c 'echo "hello udp" | nc -u -w1 10.0.1.2 9090'
```

UDP 吞吐测试：

```bash
sudo ip netns exec ns2 iperf3 -s -p 5202 &
sudo ip netns exec ns1 iperf3 -c 10.0.1.2 -p 5202 -u -b 1G -t 5
```

---

## 验证与调试

### 负向验证：卸载 XDP

ping 通后卸载宿主机侧的 XDP 程序，ping 应立即断开——证明连通性**完全由 XDP redirect 提供**，而非内核路由。

```bash
sudo ip link set dev v1-host xdp off
sudo ip link set dev v2-host xdp off

sudo ip netns exec ns1 ping 10.0.1.2
# 预期：立即卡住或 Destination Host Unreachable
```

恢复：

```bash
sudo bash setup_netns.sh
```

### 查看 XDP 统计

```bash
# 查看各 XDP 动作计数（0=ABORTED 1=DROP 2=PASS 3=TX 4=REDIRECT）
bpftool map dump pinned /sys/fs/bpf/xdp/globals/xdp_stats
```

### 查看 Map 内容

```bash
# 确认转发规则已填充
bpftool map dump pinned /sys/fs/bpf/xdp/globals/tx_port
bpftool map dump pinned /sys/fs/bpf/xdp/globals/redirect_params
```

### 抓包验证

```bash
# 在宿主机侧抓包，观察 XDP 改写后的帧
sudo tcpdump -i v1-host -n -e &
sudo ip netns exec ns1 ping -c3 10.0.1.2
```

### 查看 BPF 程序信息

```bash
# 列出已加载的 XDP 程序
bpftool net show

# 查看程序 SEC 列表和指令数
bpftool prog show
```

---

## 清理

```bash
sudo ip netns del ns1
sudo ip netns del ns2
sudo ip link del v1-host 2>/dev/null
sudo ip link del v2-host 2>/dev/null
sudo rm -rf /sys/fs/bpf/xdp/
```

或直接重新运行 `setup_netns.sh`（脚本开头会自动清理）。

---

## 文件说明

```
.
├── Makefile                  # 编译脚本
├── xdp_prog_kern.c           # XDP 内核程序（三个 SEC：redirect / icmp_echo / pass）
├── xdp_prog_user.c           # 用户态工具，通过 bpftool 更新 pinned map
├── setup_netns.sh            # 一键建拓扑、加载程序、配置规则
├── env.sh                    # 依赖安装命令参考
├── common/
│   ├── parsing_helpers.h     # 以太网 / IP / ICMP / TCP / UDP 头解析
│   ├── rewrite_helpers.h     # MAC / IP 地址改写、VLAN tag 操作
│   ├── checksum_helpers.h    # checksum 计算（csum_loop / bpf_csum_diff 封装）
│   └── xdp_stats.h           # xdp_stats map 定义 + xdp_stats_record_action
└── README.md                 # 本文件
```

### `xdp_prog_kern.c` 中的程序段

| Section | 函数 | Checksum 策略 | 用途 |
|---------|------|---------------|------|
| `xdp_redirect_map` | `xdp_redirect_map_func` | 全量重算（`fix_checksums`） | 查 Map 改写 MAC，重定向到对端接口 |
| `xdp_pass` | `xdp_pass_func` | 无 | 返回 `XDP_PASS`，挂在 NS 侧满足 veth 要求 |
