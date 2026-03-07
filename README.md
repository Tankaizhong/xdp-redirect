# XDP Redirect — 基于 eBPF Map 的内核层数据包重定向

## 目录

- [实验目标](#实验目标)
- [原理说明](#原理说明)
- [eBPF Map 结构详解](#ebpf-map-结构详解)
- [关键设计决策](#关键设计决策)
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


## 数据包转发路径（以 NS1→NS2 为例）

```
NS1 发出 ICMP echo request
  │
  ▼ v1-ns1（veth NS 侧，挂 xdp_pass）
  │
  ▼ v1-host（veth 宿主机侧，挂 xdp_redirect_map）
       XDP 程序执行：
       1. 查 redirect_params[ingress_ifindex] → 目标 MAC（v2-ns2 的 MAC）
       2. 改写 eth->h_dest
       3. 查 tx_port[ingress_ifindex] → 目标 ifindex（v2-host）
       4. bpf_redirect_map(&tx_port, in_ifindex, XDP_PASS) 返回 XDP_REDIRECT
  │
  ▼ veth 驱动调用 veth_xdp_xmit → 将帧入队 v2-host 的 XDP TX 环
  │
  ▼ v2-ns2（veth NS 侧，挂 xdp_pass，满足 peer-has-XDP 要求）
  │
  ▼ NS2 内核协议栈收到帧，生成 echo reply，走反向路径回 NS1
```

---

## eBPF Map 结构详解

项目使用两张 Map，由 v1-host 和 v2-host **共享同一实例**：

### 1. `tx_port` — `BPF_MAP_TYPE_DEVMAP`

```c
struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __type(key,   int);   /* 入方向 ifindex（从哪个口收到的） */
    __type(value, int);   /* 出方向 ifindex（重定向到哪个口） */
    __uint(max_entries, 256);
} tx_port SEC(".maps");
```

填充内容（双向）：

```
key=ifindex(v1-host)  →  value=ifindex(v2-host)   # NS1→NS2
key=ifindex(v2-host)  →  value=ifindex(v1-host)   # NS2→NS1
```

**DEVMAP 的特殊性**：`bpf_redirect_map` 配合 DEVMAP 使用时，内核会在 XDP 程序返回后统一批量执行 `ndo_xdp_xmit`，比 `bpf_redirect` 直接调用更高效，也是 veth 驱动唯一支持的 XDP 重定向路径。

### 2. `redirect_params` — `BPF_MAP_TYPE_HASH`

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
key=ifindex(v1-host)  →  value=MAC(v2-ns2)   # 改写目标 MAC，使帧能被 NS2 接受
key=ifindex(v2-host)  →  value=MAC(v1-ns1)   # 改写目标 MAC，使帧能被 NS1 接受
```

**为什么要改写目标 MAC**：veth 驱动和 NS 内的网卡都会根据以太网帧的目标 MAC 做过滤。原始帧的目标 MAC 是 v1-host 自己的（ARP 请求的目标是网关），经 XDP 改写后必须换成最终接收方（v2-ns2）的 MAC，否则帧会被 NS2 的 veth 丢弃。

### 3. `xdp_stats` — `BPF_MAP_TYPE_ARRAY`

```c
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key,   __u32);   /* XDP 动作编号（0=ABORTED,1=DROP,2=PASS,3=TX,4=REDIRECT） */
    __type(value, __u64);   /* 该动作的计数 */
    __uint(max_entries, 64);
} xdp_stats SEC(".maps");
```

每个 XDP 程序退出前都会调用 `xdp_stats_record_action`，将计数写入此 Map，供用户态读取统计。

### Map 共享机制

两个接口（v1-host、v2-host）使用**同一个程序实例**，因此天然共享同一套 Map：

```bash
# 只在 v1-host 加载一次，获取程序 ID
ip link set dev v1-host xdp obj xdp_prog_kern.o sec xdp_redirect_map
V1_PROG=$(bpftool net show dev v1-host | grep "driver id" | awk '{print $NF}')

# 将同一程序实例 attach 到 v2-host（共享 maps，无需重新加载）
bpftool net attach xdp id $V1_PROG dev v2-host
```

这样两个接口的 `tx_port` 和 `redirect_params` 指向同一块内核内存，更新一次即对两个接口同时生效。

---


## 环境要求

| 组件 | 最低版本 |
|------|----------|
| Linux 内核 | 5.9+（DEVMAP 支持 `bpf_redirect_map`） |
| clang / llvm | 10+ |
| bpftool | 与内核版本匹配 |

安装依赖（Ubuntu / Debian）：

```bash
sudo apt install clang llvm libelf-dev libpcap-dev build-essential libc6-dev-i386 m4 libbpf-dev
sudo apt install linux-headers-$(uname -r)
sudo apt install linux-tools-common linux-tools-generic
sudo apt install tcpdump
```

---

## 从零复现

### 第一步：编译

```bash
make clean && make
```

生成：
- `xdp_prog_kern.o` — 内核侧 BPF 字节码
- `xdp_prog_user`   — 用户态 Map 配置工具

### 第二步：一键设置并运行

```bash
sudo bash setup_netns.sh
```

脚本完成以下操作：

1. 创建 network namespace `ns1`、`ns2`
2. 创建两对 veth：`v1-ns1 ↔ v1-host`、`v2-ns2 ↔ v2-host`
3. 配置 IP 地址和默认路由
4. 关闭宿主机侧的 rp_filter（否则内核因源 IP 不符合路由表而丢包）
5. 在 `v1-ns1`、`v2-ns2` 上加载 `xdp_pass`（满足 `veth_xdp_xmit` 要求）
6. 在 `v1-host` 加载 `xdp_redirect_map`，再将同一程序 attach 到 `v2-host`
7. Pin Map 到 `/sys/fs/bpf/xdp/globals/`
8. 调用 `xdp_prog_user` 填充双向转发规则

### 第三步：测试连通性

```bash
# 从 NS1 ping NS2
sudo ip netns exec ns1 ping 10.0.1.2
```

预期输出：

```
PING 10.0.1.2 (10.0.1.2) 56(84) bytes of data.
64 bytes from 10.0.1.2: icmp_seq=1 ttl=64 time=0.xxx ms
64 bytes from 10.0.1.2: icmp_seq=2 ttl=64 time=0.xxx ms
```

### 第四步：卸载 XDP 验证（负向验证）

ping 通后，卸载宿主机侧的 XDP 程序，ping 应立即断开——这证明连通性**完全由 XDP redirect 提供**，而非内核路由。

```bash
# 卸载宿主机侧 XDP（namespace 侧的 xdp_pass 不影响此实验结论）
sudo ip link set dev v1-host xdp off
sudo ip link set dev v2-host xdp off
```

再次 ping：

```bash
sudo ip netns exec ns1 ping 10.0.1.2
```

预期输出：

```
# ping 立即卡住或输出：
From 10.0.1.1 icmp_seq=1 Destination Host Unreachable
```

原因：宿主机侧 veth 没有 IP 地址，内核路由表中也没有 10.0.1.0/24 的路由，两个 namespace 之间唯一的转发路径就是 XDP redirect。卸载后无任何路径可达，ping 必然失败。

恢复：

```bash
sudo bash setup_netns.sh
```


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
├── xdp_prog_kern.c           # XDP 内核程序（xdp_redirect_map + xdp_pass）
├── xdp_prog_user.c           # 用户态工具，通过 bpftool 更新 pinned map
├── setup_netns.sh            # 一键建拓扑、加载程序、配置规则
├── env.sh                    # 依赖安装命令
├── common/
│   ├── parsing_helpers.h     # 以太网/IP/ICMP 头解析
│   └── rewrite_helpers.h     # MAC/IP 地址改写辅助
└── README.md                 # 本文件
```

### `xdp_prog_kern.c` 中的程序段

| Section | 函数 | 用途 |
|---------|------|------|
| `xdp_redirect_map` | `xdp_redirect_map_func` | **本实验使用**：查 Map 动态重定向 |
| `xdp_pass` | `xdp_pass_func` | 直接返回 `XDP_PASS`，挂在 NS 侧满足 veth 要求 |
