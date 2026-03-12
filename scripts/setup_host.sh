#!/bin/bash
# ============================================================================
# setup_host.sh – 在真实宿主机（VM）上初始化 XDP IPIP overlay 环境（Docker 版）
#
# 在每台 VM 上运行一次，完成：
#   1. 检查 Docker 环境
#   2. 构建 pod 镜像
#   3. 挂载 bpffs、创建 pin 目录
#   4. 加载 BPF 程序，pin 所有 maps 和程序到 /sys/fs/bpf/xdp_ipip_*
#   5. 将 xdp_eth_ingress 挂载到物理网卡
#   6. 设置 host_config（本机 IP、eth 接口信息）
#   7. 注册 eth 接口到 tx_ports DEVMAP
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
if ! command -v docker &>/dev/null; then
    echo "错误: docker 未安装，请先安装 Docker"
    echo "  curl -fsSL https://get.docker.com | sh"
    exit 1
fi
if ! docker info &>/dev/null; then
    echo "错误: Docker 服务未运行"
    echo "  sudo systemctl start docker"
    exit 1
fi

ETH_MAC=$(cat /sys/class/net/"$ETH_DEV"/address)
ETH_IDX=$(cat /sys/class/net/"$ETH_DEV"/ifindex)

echo "=========================================="
echo "  XDP IPIP Overlay 宿主机初始化 (Docker)"
echo "=========================================="
echo "  宿主机 IP:  $HOST_IP"
echo "  物理网卡:   $ETH_DEV (ifindex=$ETH_IDX, mac=$ETH_MAC)"
echo ""

# ── 1. 构建 Pod Docker 镜像 ──────────────────────────────────────────────

echo "=== 构建 Pod 镜像 ==="
if docker image inspect xdp-pod &>/dev/null; then
    echo "  镜像 xdp-pod 已存在，跳过构建"
else
    if [ -f "$ROOT_DIR/Dockerfile.pod" ]; then
        docker build -t xdp-pod -f "$ROOT_DIR/Dockerfile.pod" "$ROOT_DIR"
        echo "  镜像 xdp-pod 构建完成"
    else
        echo "警告: Dockerfile.pod 不存在，add_pod.sh 将使用默认镜像"
    fi
fi

# ── 2. 挂载 bpffs ────────────────────────────────────────────────────────────

echo "=== 挂载 bpffs ==="
if ! mount | grep -q '/sys/fs/bpf type bpf'; then
    mkdir -p /sys/fs/bpf
    mount -t bpf bpf /sys/fs/bpf
    echo "  已挂载 bpffs"
else
    echo "  bpffs 已存在"
fi

# 确保 netns 目录存在
mkdir -p /var/run/netns

# ── 3. 清理旧的 XDP 程序（如果有）──────────────────────────────────────────

echo "=== 清理旧 XDP 程序 ==="
ip link set dev "$ETH_DEV" xdp off        2>/dev/null || true
ip link set dev "$ETH_DEV" xdpgeneric off 2>/dev/null || true
ip link set dev "$ETH_DEV" xdpdrv off     2>/dev/null || true
echo "  已清理 $ETH_DEV 上的旧 XDP"

# ── 4. 加载 BPF 程序，pin maps 和 progs ────────────────────────────────────

echo "=== 加载 BPF 程序 ==="
"$XDP_USER" load "$XDP_OBJ"

# ── 5. 将 xdp_eth_ingress 挂载到物理网卡 ────────────────────────────────────

echo "=== 挂载 xdp_eth_ingress → $ETH_DEV ==="
ip link set dev "$ETH_DEV" xdpgeneric pinned "${PIN_PFX}eth_ingress_prog"
echo "  xdp_eth_ingress → $ETH_DEV"

echo "=== 设置 $ETH_DEV MTU ==="
ip link set dev "$ETH_DEV" mtu 1480
echo "  $ETH_DEV MTU → 1480"

# ── 6. 配置 host_config 和注册 eth tx_port ──────────────────────────────────

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
echo "  1. 添加本地 pod（Docker 容器）:"
echo "     sudo bash scripts/add_pod.sh <pod_name> <pod_ip>"
echo ""
echo "  2. 添加远程 pod 路由（在本机执行）:"
echo "     sudo bash scripts/add_remote_route.sh <pod_ip> <remote_host_ip> <remote_host_mac>"
echo ""
echo "  3. 进入容器:"
echo "     docker exec -it xdp_<pod_name> sh"
echo ""
echo "  4. 查看 map 内容:"
echo "     $XDP_USER dump"
