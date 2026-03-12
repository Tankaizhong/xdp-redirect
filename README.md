# XDP IPIP Overlay — 基于 eBPF 的容器跨宿主机网络方案（Docker 版）

## 目录

- [项目简介](#项目简介)
- [架构设计](#架构设计)
- [与原版（netns）的区别](#与原版netns的区别)
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

**本版本使用 Docker 容器替代裸 netns 模拟 Pod**，更贴近真实 Kubernetes 环境，且可以在 Pod 内运行任意服务。

---

## 架构设计

```
VM1 (192.168.1.1)                         VM2 (192.168.1.2)
┌──────────────────────────────┐         ┌──────────────────────────────┐
│                              │         │                              │
│  ┌─ xdp_pod1 (10.244.1.10)─┐│         │┌─ xdp_pod3 (10.244.2.10)─┐  │
│  │  Docker: xdp-overlay net ││         ││  Docker: xdp-overlay net │  │
│  └──────┬───────────────────┘│         │└──────┬───────────────────┘  │
│         │                    │         │       │                      │
│  ┌─ xdp_pod2 (10.244.1.11)─┐│         │┌─ xdp_pod4 (10.244.2.11)─┐  │
│  │  Docker: xdp-overlay net ││         ││  Docker: xdp-overlay net │  │
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

每个 Pod 是一个 Docker 容器，连接到专用 bridge 网络 `xdp-overlay`（子网 `10.244.0.0/16`）并指定固定 IP。Docker 自动创建并管理 veth pair，`add_pod.sh` 通过读取容器的 `iflink` 找到宿主机侧 veth，然后在其上挂载 `xdp_pod_egress` 程序。容器状态（veth 名、pod IP）保存到 `/var/run/xdp-overlay/<pod_name>.env`，供 `del_pod.sh` 和 `teardown_host.sh` 使用。

---

## 与原版（netns）的区别

| 维度 | 原版（裸 netns） | Docker 版 |
|------|-----------------|-----------|
| Pod 创建 | `ip netns add` | `docker run --network=xdp-overlay --ip=<pod_ip>` |
| veth 管理 | 手动 `ip link add veth ... netns` | Docker bridge 自动创建和管理 veth pair |
| netns 来源 | iproute2 创建 | 容器进程的 netns（Docker 管理） |
| veth 名查找 | 预知（自定义命名） | 通过容器 `iflink` 动态查找 |
| 状态持久化 | 无 | `/var/run/xdp-overlay/<pod>.env` |
| Pod 内环境 | 空 netns，无进程 | 完整容器，可运行任意服务 |
| 进入 Pod | `ip netns exec ns_pod1 ...` | `docker exec -it xdp_pod1 sh` |
| Pod 命名 | ns_pod1 | 容器: xdp_pod1 |
| XDP/Map 逻辑 | 完全相同 | **完全相同**，零改动 |
| C 代码改动 | — | **无**（内核 BPF + 用户态工具均不变） |

核心原理：Docker 容器本质上也是 Linux netns + cgroup。`--network=none` 关闭 Docker 自带的网络栈，我们接管后手动配置 veth + XDP，效果与裸 netns 完全一致。

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

### `tx_ports` — DEVMAP 转发端口注册

```c
// Key: int ifindex, Value: int ifindex (identity map)
// Type: BPF_MAP_TYPE_DEVMAP, max_entries=256
```

所有可能的 redirect 目标必须注册到此 DEVMAP。

---

## XDP 程序段

| Section | 挂载位置 | 功能 |
|---------|----------|------|
| `xdp_pod_egress` | 各 pod 的 host 侧 veth | 处理 pod 发出的包：查 routing_map 判断本地 redirect 或 IPIP 封装 |
| `xdp_eth_ingress` | 物理网卡（如 ens33） | 接收物理网络的 IPIP 包：解封后查 delivery_map 投递到本地 pod |
| `xdp_pass` | 各 pod 的容器侧 veth | 无操作，仅满足 veth `ndo_xdp_xmit` 要求 peer 必须有 native XDP 程序 |

---

## 数据包转发路径

### 同宿主机（pod1 → pod2，均在 VM1）

```
pod1 容器发送 ICMP echo request
  │
  ▼ pod1-ns TX → pod1-host RX
  │
  ▼ XDP(xdp_pod_egress) 执行：
       1. 解析 dst_ip = 10.244.1.11
       2. routing_map[10.244.1.11] → host_ip=192.168.1.1（本机）
       3. delivery_map[10.244.1.11] → ifindex=pod2-host, mac=POD2_MAC
       4. 改写 eth: dst=POD2_MAC, src=ETH_MAC
       5. fix_checksums()
       6. bpf_redirect_map(&tx_ports, pod2-host_ifindex, XDP_PASS)
  │
  ▼ pod2-host TX → pod2-ns RX → pod2 容器内核协议栈收到
```

### 跨宿主机（pod1@VM1 → pod3@VM2）

**发送侧（VM1）：**

```
pod1 容器发送
  │
  ▼ pod1-ns TX → pod1-host RX
  │
  ▼ XDP(xdp_pod_egress) 执行：
       1. 解析 dst_ip = 10.244.2.10
       2. routing_map[10.244.2.10] → host_ip=192.168.1.2, mac=VM2_ETH_MAC
       3. host_ip ≠ 本机 → IPIP 封装路径
       4. fix_checksums()（修复内层校验和）
       5. bpf_xdp_adjust_head(-20) 扩展空间
       6. 构建 outer eth + outer IP (proto=IPIP)
       7. bpf_redirect_map(&tx_ports, ens33_ifindex, XDP_PASS)
  │
  ▼ ens33 TX → 物理网络 → VM2 ens33 RX
```

**接收侧（VM2）：**

```
ens33 RX
  │
  ▼ XDP(xdp_eth_ingress) 执行：
       1. 解析 outer IP: proto=IPIP(4)
       2. 读取 inner IP: dst=10.244.2.10
       3. delivery_map[10.244.2.10] → ifindex=pod3-host, mac=POD3_MAC
       4. 剥离 outer IP，构建新 eth header
       5. fix_checksums()
       6. bpf_redirect_map(&tx_ports, pod3-host_ifindex, XDP_PASS)
  │
  ▼ pod3-host TX → pod3-ns RX → pod3 容器收到
```

---

## Checksum 处理策略

veth 默认开启 `tx-checksum-ip-generic`，TCP/UDP 校验和标记为 `CHECKSUM_PARTIAL`。XDP 在 RX 入口拦截时校验和尚未计算，redirect 后对端会丢弃。

`fix_checksums()` 对每个转发包从零重算所有 IP 和 L4 校验和，清零后从头计算，对 `CHECKSUM_PARTIAL` 和 `CHECKSUM_COMPLETE` 都正确。

---

## Map 共享机制

```
setup_host.sh 初始化流程：
  1. xdp_prog_user load xdp_prog_kern.o
       → 一次性加载所有程序 + 创建共享 maps
       → pin 到 /sys/fs/bpf/xdp_ipip_*
  2. ip link set dev ens33 xdpgeneric pinned ...
       → 挂载 xdp_eth_ingress（generic 模式兼容 VM 网卡）

add_pod.sh 添加 Docker pod 流程：
  1. docker run --network=xdp-overlay --ip=<pod_ip> → 启动容器
       → Docker 自动创建 veth pair
  2. 读取容器 iflink → 找到宿主机侧 veth 名
  3. 保存状态到 /var/run/xdp-overlay/<pod>.env
  4. ip link set dev <veth-host> xdp pinned ...
       → 复用同一程序实例，共享全部 maps
  5. xdp_prog_user deliver/txport/route → 更新共享 maps
```

---

## 环境要求

| 组件 | 最低版本 |
|------|----------|
| Linux 内核 | 5.9+ |
| Docker | 20.10+（需要 `--network=none` 和 `--privileged`） |
| clang / llvm | 10+ |
| libbpf-dev | 0.5+ |
| iproute2 | 任意现代版本 |

安装依赖（Ubuntu / Debian）：

```bash
# eBPF 编译依赖
sudo apt install clang llvm libbpf-dev build-essential \
                 linux-headers-$(uname -r) \
                 tcpdump iperf3

# Docker
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
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

### 第二步：构建 Pod 镜像 & 初始化宿主机

```bash
# VM1
sudo bash scripts/setup_host.sh 192.168.1.1 ens33

# VM2
sudo bash scripts/setup_host.sh 192.168.1.2 ens33
```

`setup_host.sh` 会自动构建 `xdp-pod` Docker 镜像。

### 第三步：添加 Pod

```bash
# VM1 上添加两个 pod
sudo bash scripts/add_pod.sh pod1 10.244.1.10
sudo bash scripts/add_pod.sh pod2 10.244.1.11

# VM2 上添加两个 pod
sudo bash scripts/add_pod.sh pod3 10.244.2.10
sudo bash scripts/add_pod.sh pod4 10.244.2.11
```

每个 `add_pod.sh` 会自动完成：启动容器 → 链接 netns → 创建 veth → 配置 IP → 加载 XDP → 更新 maps。

也可以指定自定义 Docker 镜像：

```bash
# 第三个参数为镜像名
sudo bash scripts/add_pod.sh web1 10.244.1.20 nginx:alpine
```

### 第四步：注册跨宿主机路由

```bash
VM2_MAC=$(ssh vm2 "cat /sys/class/net/ens33/address")
VM1_MAC=$(ssh vm1 "cat /sys/class/net/ens33/address")

# 在 VM1 上注册 VM2 的 pod
sudo bash scripts/add_remote_route.sh 10.244.2.10 192.168.1.2 $VM2_MAC
sudo bash scripts/add_remote_route.sh 10.244.2.11 192.168.1.2 $VM2_MAC

# 在 VM2 上注册 VM1 的 pod
sudo bash scripts/add_remote_route.sh 10.244.1.10 192.168.1.1 $VM1_MAC
sudo bash scripts/add_remote_route.sh 10.244.1.11 192.168.1.1 $VM1_MAC
```

### 第五步：验证

```bash
# 通过 docker exec 测试（推荐）
docker exec xdp_pod1 ping -c3 10.244.1.11      # 同宿主机
docker exec xdp_pod1 ping -c3 10.244.2.10      # 跨宿主机

# 或通过 ip netns exec 测试
sudo ip netns exec ns_pod1 ping -c3 10.244.2.10

# TCP 测试
docker exec -d xdp_pod3 nc -l -p 8080
docker exec xdp_pod1 sh -c 'echo "hello across hosts" | nc -w2 10.244.2.10 8080'

# 在 pod 内运行 iperf3
docker exec -d xdp_pod3 iperf3 -s
docker exec xdp_pod1 iperf3 -c 10.244.2.10
```

---

## 动态扩缩容

### 新增 Pod

```bash
# 在 VM1 上新增 pod5
sudo bash scripts/add_pod.sh pod5 10.244.1.20

# 在所有远程宿主机上通告
sudo bash scripts/add_remote_route.sh 10.244.1.20 192.168.1.1 $VM1_MAC
```

### 删除 Pod

```bash
# 在 VM1 上删除 pod5
sudo bash scripts/del_pod.sh pod5 10.244.1.20

# 在所有远程宿主机上清理路由
sudo ./xdp_prog_user route del 10.244.1.20
```

### 新增宿主机

```bash
# 1. 编译 + 初始化
make clean && make
sudo bash scripts/setup_host.sh 192.168.1.3 ens33

# 2. 添加 pod
sudo bash scripts/add_pod.sh pod5 10.244.3.10

# 3. 双向注册路由（同原版）
```

### 用户态工具命令参考

```bash
sudo ./xdp_prog_user load xdp_prog_kern.o      # 加载程序
sudo ./xdp_prog_user host get                    # 读取宿主机信息
sudo ./xdp_prog_user host set <ip> <iface> <mac> # 设置宿主机信息
sudo ./xdp_prog_user route add <pod_ip> <host_ip> <host_mac>
sudo ./xdp_prog_user deliver add <pod_ip> <iface> <pod_mac>
sudo ./xdp_prog_user txport add <iface>
sudo ./xdp_prog_user dump                        # 查看所有 map
```

---

## 验证与调试

### 查看运行中的 Pod 容器

```bash
docker ps --filter "name=xdp_"
```

### 进入 Pod 调试

```bash
docker exec -it xdp_pod1 sh

# 在容器内查看网络配置
ip addr show
ip route show
cat /proc/net/snmp | grep Tcp
```

### 抓包查看 IPIP 封装

```bash
sudo tcpdump -i ens33 -n -e proto 4
```

### 查看 Map 内容

```bash
sudo ./xdp_prog_user dump
```

### 查看 XDP 程序挂载状态

```bash
ip link show
# 接口行带 prog/xdp id <N> 即为已挂载
```

### TCP 不通时的诊断

```bash
# 进入 pod 查看 TCP 统计
docker exec xdp_pod3 cat /proc/net/snmp | grep Tcp

# InErrs == InSegs 说明校验和错误
sudo ./xdp_prog_user dump
```

---

## 关键设计决策

| 问题 | 选择 | 原因 |
|------|------|------|
| Pod 实现 | Docker `--network=none` | 完整容器环境，可运行任意服务；netns 原理不变 |
| 隧道协议 | IPIP（proto=4） | 最简单的 L3-in-L3 封装 |
| `bpf_redirect_map` | DEVMAP 路径 | veth 的 `ndo_xdp_xmit` 要求 |
| 转发决策 | 纯 map 查表 | 动态增删，无需重编译 |
| namespace 侧 XDP | `xdp_pass` | `veth_xdp_xmit` 要求 peer 有 native XDP |
| Checksum | XDP 内全量重算 | 处理 `CHECKSUM_PARTIAL` |
| Map 共享 | `bpf_object__load` + pin | 所有程序共享转发表 |

---

## 已知问题与解决方案

### Docker 容器无法加载 XDP 对象

**现象**：`ip link set xdp obj` 在容器 netns 中失败。

**解决**：确保 `xdp_prog_kern.o` 路径在宿主机上可访问。脚本通过 `ip netns exec` 从宿主机执行加载，而非在容器内执行。

### veth TX Checksum Offload 导致 TCP 不通

**现象**：ping 通，TCP 超时。

**解决**：`fix_checksums()` 已处理。与裸 netns 版本完全相同。

### 容器重启后网络丢失

**现象**：容器 restart 后 PID 变化，netns 链接失效。

**解决**：容器使用 `sleep infinity` 常驻，不建议 restart。如需重建，先 `del_pod.sh` 再 `add_pod.sh`。

### 物理网卡不支持 native XDP

**现象**：VM 内常见网卡（vmxnet3、e1000）不支持 native XDP，`xdp off` 无法卸载以 generic 模式加载的程序。

**解决**：`setup_host.sh` 已内建处理，使用 `xdpgeneric pinned` 加载，并在 `teardown_host.sh` 中同时执行 `xdp off`、`xdpgeneric off`、`xdpdrv off` 三种卸载，无需手动干预。

### MTU 问题

IPIP 封装增加 20 字节。建议在 Pod 内或通过 Docker 调整 MTU：

```bash
# 在 pod 容器内
docker exec xdp_pod1 ip link set dev pod1-ns mtu 1480

# 或增大物理网卡 MTU
ip link set dev ens33 mtu 1520
```

---

## 清理

### 删除单个 Pod

```bash
sudo bash scripts/del_pod.sh <pod_name> <pod_ip>
# 远程宿主机：
sudo ./xdp_prog_user route del <pod_ip>
```

### 清理整个宿主机

```bash
sudo bash scripts/teardown_host.sh ens33
```

### 清理 Docker 镜像

```bash
docker rmi xdp-pod
```

---

## 文件说明

```
.
├── Makefile                    # 编译脚本
├── README.md                   # 本文件
├── Dockerfile.pod              # Pod 容器镜像（alpine + 网络工具）
│
├── xdp_prog_kern.c            # XDP 内核程序（三个 SEC，无改动）
├── xdp_prog_user.c            # 用户态工具（libbpf，无改动）
│
├── common/
│   ├── xdp_maps.h             # eBPF Map 定义
│   ├── parsing_helpers.h      # 头解析
│   └── checksum_helpers.h     # 校验和计算
│
└── scripts/
    ├── setup_host.sh          # 宿主机初始化（含 Docker 镜像构建）
    ├── add_pod.sh             # 动态添加 pod（Docker 容器）
    ├── del_pod.sh             # 动态删除 pod（停止容器 + 清理）
    ├── add_remote_route.sh    # 注册远程 pod 路由（无改动）
    └── teardown_host.sh       # 清理所有资源（含 Docker 容器）
```

### 脚本调用关系

```
初始部署：
  scripts/setup_host.sh
    ├─ docker build -t xdp-pod (构建 Pod 镜像)
    ├─ xdp_prog_user load (加载 BPF 程序)
    └─ ip link set xdp pinned (挂载 xdp_eth_ingress)
       │
       ▼（每个 pod 执行一次）
  scripts/add_pod.sh
    ├─ docker run --network=xdp-overlay --ip (启动容器，Docker 自动建 veth)
    ├─ iflink 查找宿主机侧 veth 名
    ├─ 保存状态到 /var/run/xdp-overlay/<pod>.env
    ├─ ip link set xdp pinned (挂载 xdp_pod_egress)
    └─ xdp_prog_user deliver/txport/route (更新 maps)
       │
       ▼（在每台远程宿主机上执行）
  scripts/add_remote_route.sh
    └─ xdp_prog_user route add

缩容：
  scripts/del_pod.sh
    ├─ docker rm -f (删除容器)
    ├─ rm netns 链接
    └─ xdp_prog_user deliver/route/txport del

完全清理：
  scripts/teardown_host.sh
    ├─ xdpgeneric/xdpdrv/xdp off (卸载 eth XDP，恢复 MTU)
    ├─ 逐容器清理 eBPF map 条目 (deliver/route/txport del)
    ├─ docker rm -f xdp_* (删除所有 pod 容器)
    ├─ docker network rm xdp-overlay
    ├─ rm /var/run/xdp-overlay/*.env (清理状态文件)
    └─ rm pinned maps/progs
```
