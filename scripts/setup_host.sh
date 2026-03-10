#!/bin/bash
# ============================================================================
# setup_host.sh – 在真实宿主机（VM）上初始化 XDP IPIP overlay 环境
#
# 在每台 VM 上运行一次，完成：
#   1. 挂载 bpffs、创建 pin 目录
#   2. 加载 xdp_eth_ingress 到物理网卡
#   3. 设置 host_config（本机 IP、eth 接口信息）
#   4. 注册 eth 接口到 tx_ports DEVMAP
#
# 用法：
#   sudo bash setup_host.sh <host_ip> <eth_interface>
#
# 示例：
#   VM1: sudo bash setup_host.sh 192.168.1.1 ens33
#   VM2: sudo bash setup_host.sh 192.168.1.2 ens33
#
# 真实拓扑：
#
#   VM1 (192.168.1.1)                    VM2 (192.168.1.2)
#   ┌────────────────────────┐          ┌────────────────────────┐
#   │ pod1-host ◄─ XDP(egr)  │          │ pod3-host ◄─ XDP(egr)  │
#   │ pod2-host ◄─ XDP(egr)  │          │ pod4-host ◄─ XDP(egr)  │
#   │ ens33     ◄─ XDP(eth)  │          │ ens33     ◄─ XDP(eth)  │
#   └─────────┬──────────────┘          └─────────┬──────────────┘
#             │          物理网络 / 交换机          │
#             └────────────────────────────────────┘
# ============================================================================

set -e

if [ $# -lt 2 ]; then
    echo "用法: $0 <host_ip> <eth_interface>"
    echo "示例: $0 192.168.1.1 ens33"
    exit 1
fi

HOST_IP="$1"
ETH_DEV="$2"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
XDP_OBJ="${SCRIPT_DIR}/xdp_prog_kern.o"
XDP_USER="${SCRIPT_DIR}/xdp_prog_user"
PIN_BASE="/sys/fs/bpf/xdp_ipip"

# ── 前置检查 ─────────────────────────────────────────────────────────────────

if [ ! -f "$XDP_OBJ" ]; then
    echo "错误: $XDP_OBJ 不存在，请先运行 make"
    exit 1
fi
if [ ! -f "$XDP_USER" ]; then
    echo "错误: $XDP_USER 不存在，请先运行 make"
    exit 1
fi
if ! ip link show "$ETH_DEV" &>/dev/null; then
    echo "错误: 接口 $ETH_DEV 不存在"
    echo "可用接口:"
    ip -br link show | awk '{print "  "$1}'
    exit 1
fi

ETH_MAC=$(cat /sys/class/net/"$ETH_DEV"/address)
ETH_IDX=$(cat /sys/class/net/"$ETH_DEV"/ifindex)

echo "=========================================="
echo "  XDP IPIP Overlay 宿主机初始化"
echo "=========================================="
echo "  宿主机 IP:  $HOST_IP"
echo "  物理网卡:   $ETH_DEV (ifindex=$ETH_IDX, mac=$ETH_MAC)"
echo ""

# ── 1. 挂载 bpffs ────────────────────────────────────────────────────────────

echo "=== 挂载 bpffs ==="
if ! mount | grep -q '/sys/fs/bpf type bpf'; then
    mkdir -p /sys/fs/bpf
    mount -t bpf bpf /sys/fs/bpf
    echo "  已挂载 bpffs"
else
    echo "  bpffs 已存在"
fi
mkdir -p "$PIN_BASE"

# ── 2. 清理旧的 XDP 程序（如果有）────────────────────────────────────────────

echo "=== 清理旧 XDP 程序 ==="
ip link set dev "$ETH_DEV" xdp off 2>/dev/null || true
rm -f "$PIN_BASE/eth_ingress_prog"
echo "  已清理 $ETH_DEV 上的旧 XDP"

# ── 3. 加载 xdp_pod_egress（创建共享 maps 的基准程序）─────────────────────────

# 先用一个临时的 dummy veth 加载 xdp_pod_egress，目的是创建 maps
# 然后 pin maps，后续所有 pod 和 eth 程序都复用这些 maps
echo "=== 创建共享 maps ==="

# 如果已经有 pinned maps，跳过
if [ -f "$PIN_BASE/routing_map" ] && [ -f "$PIN_BASE/delivery_map" ]; then
    echo "  pinned maps 已存在，跳过创建"
else
    # 创建临时 veth 加载程序（获取 maps）
    ip link add xdp-init-ns type veth peer name xdp-init-host 2>/dev/null || true
    ip link set xdp-init-host up
    ip link set xdp-init-ns up

    # 加载 xdp_pod_egress 到临时接口
    ip link set dev xdp-init-host xdp obj "$XDP_OBJ" sec xdp_pod_egress

    INIT_PROG=$(bpftool net show dev xdp-init-host 2>/dev/null | grep "driver id" | awk '{print $NF}')
    if [ -z "$INIT_PROG" ]; then
        echo "错误: 无法加载初始化程序"
        ip link del xdp-init-host 2>/dev/null || true
        exit 1
    fi

    # Pin maps
    get_map_id() {
        local prog_id=$1 map_name=$2
        for mid in $(bpftool prog show id "$prog_id" 2>/dev/null \
                     | grep -o 'map_ids [0-9,]*' | cut -d' ' -f2 | tr ',' ' '); do
            name=$(bpftool map show id "$mid" 2>/dev/null | awk 'NR==1{print $4}')
            [ "$name" = "$map_name" ] && echo "$mid" && return
        done
    }

    ROUTING_ID=$(get_map_id "$INIT_PROG" routing_map)
    DELIVERY_ID=$(get_map_id "$INIT_PROG" delivery_map)
    HOST_CFG_ID=$(get_map_id "$INIT_PROG" host_config)
    TX_PORTS_ID=$(get_map_id "$INIT_PROG" tx_ports)

    bpftool map pin id "$ROUTING_ID"  "$PIN_BASE/routing_map"
    bpftool map pin id "$DELIVERY_ID" "$PIN_BASE/delivery_map"
    bpftool map pin id "$HOST_CFG_ID" "$PIN_BASE/host_config"
    bpftool map pin id "$TX_PORTS_ID" "$PIN_BASE/tx_ports"
    echo "  maps pinned: routing=$ROUTING_ID delivery=$DELIVERY_ID host_config=$HOST_CFG_ID tx_ports=$TX_PORTS_ID"

    # 同时 pin xdp_pod_egress 程序本身，后续 add_pod.sh 复用
    bpftool prog pin id "$INIT_PROG" "$PIN_BASE/pod_egress_prog"
    echo "  xdp_pod_egress pinned (prog id=$INIT_PROG)"

    # 清理临时 veth
    ip link set dev xdp-init-host xdp off 2>/dev/null || true
    ip link del xdp-init-host 2>/dev/null || true
fi

# ── 4. 加载 xdp_eth_ingress（复用共享 maps）──────────────────────────────────

echo "=== 加载 xdp_eth_ingress → $ETH_DEV ==="

bpftool prog load "$XDP_OBJ" "$PIN_BASE/eth_ingress_prog" \
    type xdp \
    map name routing_map  pinned "$PIN_BASE/routing_map" \
    map name delivery_map pinned "$PIN_BASE/delivery_map" \
    map name host_config  pinned "$PIN_BASE/host_config" \
    map name tx_ports     pinned "$PIN_BASE/tx_ports" \
    pinmaps "$PIN_BASE" 2>/dev/null || true

ETH_PROG_ID=$(bpftool prog show pinned "$PIN_BASE/eth_ingress_prog" 2>/dev/null | head -1 | awk '{print $1}' | tr -d ':')

if [ -n "$ETH_PROG_ID" ]; then
    bpftool net attach xdp id "$ETH_PROG_ID" dev "$ETH_DEV"
    echo "  xdp_eth_ingress → $ETH_DEV (prog id=$ETH_PROG_ID)"
else
    echo "警告: bpftool prog load 失败，尝试直接加载（maps 不共享）"
    ip link set dev "$ETH_DEV" xdp obj "$XDP_OBJ" sec xdp_eth_ingress
    echo "  xdp_eth_ingress → $ETH_DEV (独立 maps)"
fi

# ── 5. 配置 host_config 和注册 eth tx_port ────────────────────────────────────

echo "=== 配置宿主机信息 ==="

"$XDP_USER" host set "$HOST_IP" "$ETH_DEV" "$ETH_MAC"
"$XDP_USER" txport add "$ETH_DEV"

# ── 完成 ─────────────────────────────────────────────────────────────────────

echo ""
echo "=========================================="
echo "  宿主机初始化完成！"
echo "=========================================="
echo ""
echo "下一步："
echo "  1. 添加本地 pod:"
echo "     sudo bash add_pod.sh <pod_name> <pod_ip>"
echo ""
echo "  2. 添加远程 pod 路由（在本机执行，告诉本机某个 pod 在远程宿主机上）:"
echo "     sudo bash add_remote_route.sh <pod_ip> <remote_host_ip> <remote_host_mac>"
echo ""
echo "  3. 查看 map 内容:"
echo "     $XDP_USER dump"
