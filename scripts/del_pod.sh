#!/bin/bash
# ============================================================================
# del_pod.sh – 删除一个 Docker pod
#
# 用法：
#   sudo bash del_pod.sh <pod_name> <pod_ip>
#
# 示例：
#   sudo bash del_pod.sh pod1 10.244.1.10
#
# 注意：删除后还需要在所有远程宿主机上执行：
#   ./xdp_prog_user route del <pod_ip>
# ============================================================================

set -e

if [ $# -lt 2 ]; then
    echo "用法: $0 <pod_name> <pod_ip>"
    echo "示例: $0 pod1 10.244.1.10"
    exit 1
fi

POD_NAME="$1"
POD_IP="$2"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
XDP_USER="${ROOT_DIR}/xdp_prog_user"
STATE_DIR="/var/run/xdp-overlay"

CONTAINER_NAME="xdp_${POD_NAME}"
STATE_FILE="${STATE_DIR}/${POD_NAME}.env"

echo "=== 删除 Pod: $POD_NAME ($POD_IP) ==="

# 从状态文件读取 veth 名（add_pod.sh 保存的）
VETH_HOST=""
NS_NAME="ns_${POD_NAME}"
if [ -f "$STATE_FILE" ]; then
    VETH_HOST=$(grep '^VETH_HOST=' "$STATE_FILE" | cut -d= -f2)
    NS_NAME=$(grep '^NS_NAME='   "$STATE_FILE" | cut -d= -f2 || echo "ns_${POD_NAME}")
fi

# 1. 卸载 host 侧 XDP
if [ -n "$VETH_HOST" ]; then
    ip link set dev "$VETH_HOST" xdp off 2>/dev/null || true
    echo "  卸载 XDP: $VETH_HOST"
else
    echo "  警告: 未找到状态文件，跳过 XDP 卸载"
fi

# 2. 删除 eBPF map 条目
"$XDP_USER" deliver del "$POD_IP"   2>/dev/null || true
"$XDP_USER" route   del "$POD_IP"   2>/dev/null || true
[ -n "$VETH_HOST" ] && "$XDP_USER" txport del "$VETH_HOST" 2>/dev/null || true
echo "  清理 maps"

# 3. 删除 netns 链接
rm -f "/var/run/netns/$NS_NAME"
echo "  删除 netns 链接: $NS_NAME"

# 4. 停止并删除容器（Docker 会自动回收 veth pair）
if docker ps -a --format '{{.Names}}' | grep -qw "$CONTAINER_NAME"; then
    docker rm -f "$CONTAINER_NAME" 2>/dev/null || true
    echo "  删除容器: $CONTAINER_NAME"
else
    echo "  容器 $CONTAINER_NAME 不存在（已被清理）"
fi

# 5. 删除状态文件
rm -f "$STATE_FILE"

echo ""
echo "=== Pod $POD_NAME 已删除 ==="
echo ""
echo "还需要在所有远程宿主机上清理路由:"
echo "  ./xdp_prog_user route del $POD_IP"
