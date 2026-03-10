# XDP IPIP Overlay — 基于 eBPF 的容器跨宿主机网络方案

## 目录

- [项目简介](#项目简介)
- [架构设计](#架构设计)
- [eBPF Map 结构](#ebpf-map-结构)
- [XDP 程序段](#xdp-程序段)
- [数据包转发路径](#数据包转发路径)
- [Checksum 处理策略](#checksum-处理策略)
- [Map 共享机制](#map-共享机制)
- [环境要求](#环境要求)
- [部署流程](#部署流程)
- [动态扩缩容](#动态扩缩容)
- [验证与调试](#验证与调试)
- [关键设计决策](#关键设计决策)
- [已知问题与解决方案](#已知问题与解决方案)
- [清理](#清理)
- [文件说明](#文件说明)

---

## 项目简介

在**不经过内核协议栈**的前提下，用 XDP 程序实现容器网络的数据平面：

- **同宿主机 pod 互通**：XDP 直接 redirect，veth 到 veth，零拷贝转发
- **跨宿主机 pod 互通**：XDP 封装 IPIP 隧道头 → 物理网卡发出 → 对端 XDP 解封 → 投递到目标 pod

所有转发决策基于 eBPF map 查表，支持**动态增删宿主机和容器**，无需重新编译或重新加载 XDP 程序。

---

## 架构设计

```
VM1 (192.168.1.1)                         VM2 (192.168.1.2)
┌──────────────────────────────┐         ┌──────────────────────────────┐
│                              │         │                              │
│  ┌─ ns_pod1 (10.244.1.10) ─┐│         │┌─ ns_pod3 (10.244.2.10) ─┐  │
│  │  pod1-ns                 ││         ││  pod3-ns                 │  │
│  └──────┬───────────────────┘│         │└──────┬───────────────────┘  │
│         │                    │         │       │                      │
│  ┌─ ns_pod2 (10.244.1.11) ─┐│         │┌─ ns_pod4 (10.244.2.11) ─┐  │
│  │  pod2-ns                 ││         ││  pod4-ns                 │  │
│  └──────┬───────────────────┘│         │└──────┬───────────────────┘  │
│         │                    │         │       │                      │
│  pod1-host ◄─ xdp_pod_egress│         │pod3-host ◄─ xdp_pod_egress  │
│  pod2-host ◄─ xdp_pod_egress│         │pod4-host ◄─ xdp_pod_egress  │
│                              │         │                              │
│  ens33 ◄──── xdp_eth_ingress│         │ens33 ◄──── xdp_eth_ingress  │
└─────┬────────────────────────┘         └─────┬────────────────────────┘
      │                                        │
      └──────── 物理网络 / 交换机 ──────────────┘
```

每台宿主机上的 XDP 程序运行在 root namespace，pod 使用独立的 netns + veth pair 隔离网络。这与真实 Kubernetes 节点的网络模型完全一致。

---

## eBPF Map 结构

### `routing_map` — 全局路由查找表

```c
struct route_entry {
    __u32         host_ip;       /* 目标容器所在宿主机 IP */
    unsigned char host_mac[6];   /* 目标宿主机物理 MAC */
};
// Key: __u32 pod_ip (network byte order)
// Type: BPF_MAP_TYPE_HASH, max_entries=1024
```

发送端查此表判断目的容器位置。若 `host_ip == 本机 IP`，走本地投递；否则封装 IPIP 隧道。

### `delivery_map` — 本地终端投递表

```c
struct delivery_entry {
    __u32         ifindex;      /* 本地容器 veth 接口索引 */
    unsigned char pod_mac[6];   /* 容器 MAC 地址 */
};
// Key: __u32 pod_ip (network byte order)
// Type: BPF_MAP_TYPE_HASH, max_entries=1024
```

本地投递和 IPIP 解封后，根据内层 dst_ip 查找目标容器的 veth 接口和 MAC。

### `host_config` — 本机宿主信息

```c
struct host_info {
    __u32         host_ip;       /* 本机宿主 IP */
    __u32         eth_ifindex;   /* 物理网卡 ifindex */
    unsigned char eth_mac[6];    /* 物理网卡 MAC */
};
// Key: __u32 = 0 (单条记录)
// Type: BPF_MAP_TYPE_ARRAY, max_entries=1
```

XDP 程序通过此表获取本机信息，用于判断本地/远程路径和构建 IPIP 外层头。

### `tx_ports` — DEVMAP 转发端口注册

```c
// Key: int ifindex, Value: int ifindex (identity map)
// Type: BPF_MAP_TYPE_DEVMAP, max_entries=256
```

所有可能的 redirect 目标（pod veth + 物理网卡）必须注册到此 DEVMAP，`bpf_redirect_map()` 才能正常工作。veth 驱动的 `ndo_xdp_xmit` 只对 DEVMAP 路径生效。

---

## XDP 程序段

`xdp_prog_kern.c` 中包含三个 SEC：

| Section | 挂载位置 | 功能 |
|---------|----------|------|
| `xdp_pod_egress` | 各 pod 的 host 侧 veth | 处理 pod 发出的包：查 routing_map 判断本地 redirect 或 IPIP 封装 |
| `xdp_eth_ingress` | 物理网卡（如 ens33） | 接收物理网络的 IPIP 包：解封后查 delivery_map 投递到本地 pod |
| `xdp_pass` | 各 pod 的 ns 侧 veth | 无操作，仅满足 veth `ndo_xdp_xmit` 要求 peer 必须有 native XDP 程序 |

---

## 数据包转发路径

### 同宿主机（pod1 → pod2，均在 VM1）

```
pod1 发送 ICMP echo request
  │
  ▼ pod1-ns TX → pod1-host RX
  │
  ▼ XDP(xdp_pod_egress) 执行：
       1. 解析 dst_ip = 10.244.1.11
       2. routing_map[10.244.1.11] → host_ip=192.168.1.1（本机）
       3. delivery_map[10.244.1.11] → ifindex=pod2-host, mac=POD2_MAC
       4. 改写 eth: dst=POD2_MAC, src=ETH_MAC
       5. fix_checksums()（处理 CHECKSUM_PARTIAL）
       6. bpf_redirect_map(&tx_ports, pod2-host_ifindex, XDP_PASS)
  │
  ▼ pod2-host TX → pod2-ns RX → pod2 内核协议栈收到
```

### 跨宿主机（pod1@VM1 → pod3@VM2）

**发送侧（VM1）：**

```
pod1 发送
  │
  ▼ pod1-ns TX → pod1-host RX
  │
  ▼ XDP(xdp_pod_egress) 执行：
       1. 解析 dst_ip = 10.244.2.10
       2. routing_map[10.244.2.10] → host_ip=192.168.1.2, mac=VM2_ETH_MAC
       3. host_ip ≠ 本机 → IPIP 封装路径
       4. fix_checksums()（修复内层校验和）
       5. bpf_xdp_adjust_head(-20) 扩展 20 字节空间
       6. 构建新 eth: dst=VM2_ETH_MAC, src=VM1_ETH_MAC, proto=ETH_P_IP
       7. 构建 outer IP: src=192.168.1.1, dst=192.168.1.2, proto=IPIP(4), DF=1
       8. 计算 outer IP checksum
       9. bpf_redirect_map(&tx_ports, ens33_ifindex, XDP_PASS)
  │
  ▼ ens33 TX → 物理网络 → VM2 ens33 RX
```

**接收侧（VM2）：**

```
ens33 RX（收到 IPIP 封装包）
  │
  ▼ XDP(xdp_eth_ingress) 执行：
       1. 解析 outer IP: proto=IPIP(4) → 确认是隧道包
       2. 解析 inner IP: dst=10.244.2.10（在剥离前读取）
       3. delivery_map[10.244.2.10] → ifindex=pod3-host, mac=POD3_MAC
       4. bpf_xdp_adjust_head(+20) 剥离 outer IP header
       5. bpf_xdp_adjust_head(-14) 创建新 eth header 空间
       6. 构建 eth: dst=POD3_MAC, src=VM2_ETH_MAC, proto=ETH_P_IP
       7. fix_checksums()
       8. bpf_redirect_map(&tx_ports, pod3-host_ifindex, XDP_PASS)
  │
  ▼ pod3-host TX → pod3-ns RX → pod3 内核协议栈收到
```

非 IPIP 协议的包（如宿主机自身的 SSH、ARP 等）不会被 `xdp_eth_ingress` 拦截，直接 `XDP_PASS` 交给内核正常处理。

---

## Checksum 处理策略

### 为什么需要重算

veth 默认开启 `tx-checksum-ip-generic`。发送 TCP/UDP 包时内核将校验和标记为 `CHECKSUM_PARTIAL`，即"由驱动在 TX 时填充"。XDP 运行在 veth 的 RX 入口，此时校验和尚未计算，包就已被 redirect。若不重算，对端会因校验和无效而静默丢弃。

### 全量重算策略

`fix_checksums()` 对每个转发包从零重算所有 IP 和 L4 校验和：

| 层 | 方法 | 原因 |
|----|------|------|
| IPv4 header | `bpf_csum_diff(iph, 20, ...)` | 编译期常量，verifier 接受 |
| 伪首部 | `bpf_csum_diff` over 栈 struct | 无 packet-pointer 限制 |
| L4 header + payload | `csum_loop()` 逐 16 位字循环 | 变长数据，每步独立 bounds check |

将校验和字段清零后从头计算，对 `CHECKSUM_PARTIAL` 和 `CHECKSUM_COMPLETE` 都正确，无需区分，无需修改 ethtool 配置。

L4 payload 超过 1500 字节时返回 `-1`，调用方退回 `XDP_PASS` 交由内核软件补全。

---

## Map 共享机制

每台宿主机上，`xdp_pod_egress`（所有 pod veth 共享同一程序实例）和 `xdp_eth_ingress`（物理网卡）**共享同一组 maps**：

```
setup_host.sh 初始化流程：
  1. 创建临时 veth，加载 xdp_pod_egress → 创建 maps
  2. Pin maps 到 /sys/fs/bpf/xdp_ipip/{routing_map,delivery_map,...}
  3. Pin 程序到 /sys/fs/bpf/xdp_ipip/pod_egress_prog
  4. bpftool prog load xdp_eth_ingress --map pinned → 复用已有 maps
  5. 清理临时 veth

add_pod.sh 添加 pod 流程：
  1. 创建 netns + veth
  2. bpftool net attach xdp id <pinned_prog_id> dev <pod-host>  ← 复用程序+maps
  3. 更新 delivery_map、tx_ports、routing_map
```

更新任意 map 即对所有程序实例同时生效。

---

## 环境要求

| 组件 | 最低版本 |
|------|----------|
| Linux 内核 | 5.9+（DEVMAP 支持 `bpf_redirect_map`） |
| clang / llvm | 10+ |
| bpftool | 与内核版本匹配 |
| libbpf-dev | 0.8+ |

安装依赖（Ubuntu / Debian）：

```bash
sudo apt install clang llvm libelf-dev libpcap-dev libbpf-dev build-essential \
                 linux-headers-$(uname -r) linux-tools-common linux-tools-generic \
                 tcpdump iperf3
```

---

## 部署流程

假设两台 VM 网络互通：

| 机器 | 宿主机 IP | 物理网卡 | Pod 子网 |
|------|-----------|----------|----------|
| VM1  | 192.168.1.1 | ens33 | 10.244.1.0/24 |
| VM2  | 192.168.1.2 | ens33 | 10.244.2.0/24 |

### 第一步：两台 VM 都编译

```bash
make clean && make
```

生成 `xdp_prog_kern.o`（BPF 字节码）和 `xdp_prog_user`（用户态配置工具）。

### 第二步：初始化宿主机

在每台 VM 上运行一次，挂载 bpffs、加载 XDP 到物理网卡、创建共享 maps：

```bash
# VM1
sudo bash setup_host.sh 192.168.1.1 ens33

# VM2
sudo bash setup_host.sh 192.168.1.2 ens33
```

### 第三步：添加 Pod

```bash
# VM1 上添加两个 pod
sudo bash add_pod.sh pod1 10.244.1.10
sudo bash add_pod.sh pod2 10.244.1.11

# VM2 上添加两个 pod
sudo bash add_pod.sh pod3 10.244.2.10
sudo bash add_pod.sh pod4 10.244.2.11
```

每个 `add_pod.sh` 会自动完成：创建 netns → 创建 veth → 配置 IP → 加载 XDP → 更新 maps。

### 第四步：注册跨宿主机路由

本机的 pod 在 `add_pod.sh` 时已自动注册路由。远程 pod 需要手动通告：

```bash
# 获取对端 MAC
VM2_MAC=$(ssh vm2 "cat /sys/class/net/ens33/address")
VM1_MAC=$(ssh vm1 "cat /sys/class/net/ens33/address")

# 在 VM1 上，注册 VM2 的所有 pod
sudo bash add_remote_route.sh 10.244.2.10 192.168.1.2 $VM2_MAC
sudo bash add_remote_route.sh 10.244.2.11 192.168.1.2 $VM2_MAC

# 在 VM2 上，注册 VM1 的所有 pod
sudo bash add_remote_route.sh 10.244.1.10 192.168.1.1 $VM1_MAC
sudo bash add_remote_route.sh 10.244.1.11 192.168.1.1 $VM1_MAC
```

### 第五步：验证

```bash
# 同宿主机（VM1 内部）
sudo ip netns exec ns_pod1 ping 10.244.1.11

# 跨宿主机（VM1 → VM2）
sudo ip netns exec ns_pod1 ping 10.244.2.10

# 反向（VM2 → VM1）
sudo ip netns exec ns_pod3 ping 10.244.1.10

# TCP 测试
sudo ip netns exec ns_pod3 nc -l -p 8080 &
sudo ip netns exec ns_pod1 bash -c 'echo "hello across hosts" | nc -w2 10.244.2.10 8080'
```

---

## 动态扩缩容

### 新增 Pod（在已有宿主机上）

```bash
# 在 VM1 上新增 pod5
sudo bash add_pod.sh pod5 10.244.1.20

# 在所有远程宿主机上通告新 pod
# VM2 上执行：
sudo bash add_remote_route.sh 10.244.1.20 192.168.1.1 $VM1_MAC
```

### 删除 Pod

```bash
# 在 VM1 上删除 pod5
sudo bash del_pod.sh pod5 10.244.1.20

# 在所有远程宿主机上清理路由
# VM2 上执行：
sudo ./xdp_prog_user route del 10.244.1.20
```

### 新增宿主机（VM3）

```bash
# 1. 在 VM3 上编译并初始化
make clean && make
sudo bash setup_host.sh 192.168.1.3 ens33

# 2. 在 VM3 上添加 pod
sudo bash add_pod.sh pod5 10.244.3.10
sudo bash add_pod.sh pod6 10.244.3.11

# 3. 在 VM3 上注册 VM1 和 VM2 的所有 pod
sudo bash add_remote_route.sh 10.244.1.10 192.168.1.1 $VM1_MAC
sudo bash add_remote_route.sh 10.244.1.11 192.168.1.1 $VM1_MAC
sudo bash add_remote_route.sh 10.244.2.10 192.168.1.2 $VM2_MAC
sudo bash add_remote_route.sh 10.244.2.11 192.168.1.2 $VM2_MAC

# 4. 在 VM1 和 VM2 上注册 VM3 的 pod
VM3_MAC=$(ssh vm3 "cat /sys/class/net/ens33/address")

# VM1 上：
sudo bash add_remote_route.sh 10.244.3.10 192.168.1.3 $VM3_MAC
sudo bash add_remote_route.sh 10.244.3.11 192.168.1.3 $VM3_MAC

# VM2 上：
sudo bash add_remote_route.sh 10.244.3.10 192.168.1.3 $VM3_MAC
sudo bash add_remote_route.sh 10.244.3.11 192.168.1.3 $VM3_MAC
```

### 用户态工具命令参考

```bash
# 添加/更新路由
./xdp_prog_user route   add <pod_ip> <host_ip> <host_mac>
./xdp_prog_user route   del <pod_ip>

# 添加/删除本地投递
./xdp_prog_user deliver add <pod_ip> <ifname|ifindex> <pod_mac>
./xdp_prog_user deliver del <pod_ip>

# 设置宿主机信息
./xdp_prog_user host    set <host_ip> <eth_ifname|ifindex> <eth_mac>

# 注册/注销 DEVMAP 端口
./xdp_prog_user txport  add <ifname|ifindex>
./xdp_prog_user txport  del <ifname|ifindex>

# 查看 map 内容
./xdp_prog_user dump [routing|delivery|host|txport|all]
```

---

## 验证与调试

### 抓包查看 IPIP 封装

```bash
# 在发送侧宿主机的物理网卡抓包（proto 4 = IPIP）
sudo tcpdump -i ens33 -n -e proto 4

# 在接收侧同样可以抓
sudo tcpdump -i ens33 -n -e 'ip proto 4'
```

### 负向验证：卸载 XDP

```bash
# 卸载后跨宿主机 ping 应立即断开——证明通信完全由 XDP 提供
sudo ip link set dev ens33 xdp off
sudo ip netns exec ns_pod1 ping 10.244.2.10
# 预期：超时或 Destination Host Unreachable
```

### 查看 Map 内容

```bash
./xdp_prog_user dump all

# 或直接用 bpftool
bpftool map dump pinned /sys/fs/bpf/xdp_ipip/routing_map
bpftool map dump pinned /sys/fs/bpf/xdp_ipip/delivery_map
bpftool map dump pinned /sys/fs/bpf/xdp_ipip/host_config
bpftool map dump pinned /sys/fs/bpf/xdp_ipip/tx_ports
```

### 查看 BPF 程序状态

```bash
# 列出已加载的 XDP 程序
bpftool net show

# 查看程序详情
bpftool prog show
```

### TCP 不通时的诊断

```bash
# 查看 pod 内的 TCP 统计，InErrs 应为 0
ip netns exec ns_pod3 cat /proc/net/snmp | grep Tcp

# InErrs == InSegs 说明全部是校验和错误 → fix_checksums 未生效
# 检查 pod-host 和 eth 接口上的 XDP 是否共享同一组 maps
bpftool net show
bpftool prog show
```

---

## 关键设计决策

| 问题 | 选择 | 原因 |
|------|------|------|
| 隧道协议 | IPIP（proto=4） | 最简单的 L3-in-L3 封装，XDP 内只需 `adjust_head(±20)` |
| `bpf_redirect` vs `bpf_redirect_map` | `bpf_redirect_map` | veth 的 `veth_xdp_xmit` 只对 DEVMAP 路径生效 |
| 转发决策 | 纯 map 查表 | 支持动态增删 pod/host，无需重编译 |
| namespace 侧是否挂 XDP | **必须挂** `xdp_pass` | `veth_xdp_xmit` 要求 peer 有 native XDP 程序，否则返回 `-ENXIO` |
| native XDP vs generic（skb）模式 | native | generic 模式触发不了 `ndo_xdp_xmit` |
| Checksum | XDP 内全量重算 | 无需修改 ethtool，对 `CHECKSUM_PARTIAL` 和 `CHECKSUM_COMPLETE` 都正确 |
| Map 共享 | pin + `bpftool prog load --map pinned` | 同一宿主机上所有 XDP 程序共享转发表 |

---

## 已知问题与解决方案

### veth TX Checksum Offload 导致 TCP 不通

**现象**：ping 双向通，TCP 超时。

**根因**：veth 默认开启 `tx-checksum-ip-generic`，TCP 包的校验和标记为 `CHECKSUM_PARTIAL`。XDP 在 RX 入口拦截时校验和尚未填充，redirect 后对端收到校验和无效的包，静默丢弃。

**解决**：`fix_checksums()` 对每个转发包主动重算所有校验和，清零后从头计算，对已完整和部分校验和都正确。

### 物理网卡不支持 native XDP

**现象**：`setup_host.sh` 报错 `XDP program not supported on device`。

**解决**：部分虚拟网卡（如 VMware vmxnet3）不支持 native XDP，需要用 generic 模式：

```bash
ip link set dev ens33 xdpgeneric obj xdp_prog_kern.o sec xdp_eth_ingress
```

注意 generic 模式下 pod veth 的 redirect 可能受限，建议使用支持 native XDP 的网卡（如 virtio-net）。

### MTU 问题

IPIP 封装增加 20 字节外层 IP 头。若物理网卡 MTU=1500，内层包最大为 1480 字节。建议：

```bash
# 方案一：缩小 pod MTU
ip netns exec ns_pod1 ip link set dev pod1-ns mtu 1480

# 方案二：增大物理网卡 MTU
ip link set dev ens33 mtu 1520
```

---

## 清理

### 删除单个 Pod

```bash
sudo bash del_pod.sh <pod_name> <pod_ip>
# 然后在所有远程宿主机上：
./xdp_prog_user route del <pod_ip>
```

### 清理整个宿主机

```bash
sudo bash teardown_host.sh ens33
```

---

## 文件说明

```
.
├── Makefile                    # 编译脚本
├── README.md                   # 本文件
│
├── xdp_prog_kern.c            # XDP 内核程序（三个 SEC: pod_egress / eth_ingress / pass）
├── xdp_prog_user.c            # 用户态 Map 管理工具（route/deliver/host/txport/dump）
│
├── setup_host.sh              # 宿主机初始化（每台 VM 运行一次）
├── add_pod.sh                 # 动态添加 pod
├── del_pod.sh                 # 动态删除 pod
├── add_remote_route.sh        # 注册远程 pod 路由
├── teardown_host.sh           # 清理宿主机上所有 XDP 资源
│
└── common/
    ├── xdp_maps.h             # eBPF Map 定义（routing/delivery/host_config/tx_ports）
    ├── parsing_helpers.h      # 以太网 / IP / TCP / UDP / ICMP 头解析
    └── checksum_helpers.h     # 校验和计算（csum_loop / bpf_csum_diff 封装）
```

### 脚本调用关系

```
初始部署：
  setup_host.sh  ──→  挂载 bpffs、创建共享 maps、加载 xdp_eth_ingress
       │
       ▼（每个 pod 执行一次）
  add_pod.sh     ──→  创建 netns + veth、加载 xdp_pod_egress、更新 maps
       │
       ▼（在每台远程宿主机上执行）
  add_remote_route.sh ──→  更新远程宿主机的 routing_map

动态扩容：
  add_pod.sh + add_remote_route.sh（在所有其他宿主机上）

缩容：
  del_pod.sh + xdp_prog_user route del（在所有其他宿主机上）

新增宿主机：
  setup_host.sh + add_pod.sh + 双向 add_remote_route.sh

完全清理：
  teardown_host.sh
```
