#!/bin/bash
# ============================================================================
# setup_host.sh – 在真实宿主机（VM）上初始化 XDP IPIP overlay 环境
#
# 在每台 VM 上运行一次，完成：
#   1. 挂载 bpffs、创建 pin 目录
#   2. 加载 BPF 程序，pin 所有 maps 和程序到 /sys/fs/bpf/xdp_ipip/
#   3. 将 xdp_eth_ingress 挂载到物理网卡
#   4. 设置 host_config（本机 IP、eth 接口信息）
#   5. 注册 eth 接口到 tx_ports DEVMAP
#
# 用法：
#   sudo bash setup_host.sh <host_ip> <eth_interface>
#
# 示例：
#   VM1: sudo bash setup_host.sh 192.168.1.1 ens33
#   VM2: sudo bash setup_host.sh 192.168.1.2 ens33
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
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
XDP_OBJ="${ROOT_DIR}/xdp_prog_kern.o"
XDP_USER="${ROOT_DIR}/xdp_prog_user"
PIN_PFX="/sys/fs/bpf/xdp_ipip_"

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
# No subdirectory needed: pins go flat under /sys/fs/bpf/

# ── 2. 清理旧的 XDP 程序（如果有）──────────────────────────────────────────

echo "=== 清理旧 XDP 程序 ==="
ip link set dev "$ETH_DEV" xdp off 2>/dev/null || true
echo "  已清理 $ETH_DEV 上的旧 XDP"

# ── 3. 加载 BPF 程序，pin maps 和 progs ────────────────────────────────────

echo "=== 加载 BPF 程序 ==="
"$XDP_USER" load "$XDP_OBJ"

# ── 4. 将 xdp_eth_ingress 挂载到物理网卡 ────────────────────────────────────

echo "=== 挂载 xdp_eth_ingress → $ETH_DEV ==="
ip link set dev "$ETH_DEV" xdp pinned "${PIN_PFX}eth_ingress_prog"
echo "  xdp_eth_ingress → $ETH_DEV"

# ── 5. 配置 host_config 和注册 eth tx_port ──────────────────────────────────

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
echo "     sudo bash scripts/add_pod.sh <pod_name> <pod_ip>"
echo ""
echo "  2. 添加远程 pod 路由（在本机执行）:"
echo "     sudo bash scripts/add_remote_route.sh <pod_ip> <remote_host_ip> <remote_host_mac>"
echo ""
echo "  3. 查看 map 内容:"
echo "     $XDP_USER dump"
