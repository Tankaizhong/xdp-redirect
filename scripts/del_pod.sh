#!/bin/bash
# ============================================================================
# del_pod.sh – 从当前宿主机上删除一个 pod
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
XDP_USER="${SCRIPT_DIR}/xdp_prog_user"

NS_NAME="ns_${POD_NAME}"
VETH_HOST="${POD_NAME}-host"

echo "=== 删除 Pod: $POD_NAME ($POD_IP) ==="

# 1. 卸载 XDP
ip link set dev "$VETH_HOST" xdp off 2>/dev/null || true
echo "  卸载 XDP: $VETH_HOST"

# 2. 删除 map 条目
"$XDP_USER" deliver del "$POD_IP" 2>/dev/null || true
"$XDP_USER" route del "$POD_IP" 2>/dev/null || true
"$XDP_USER" txport del "$VETH_HOST" 2>/dev/null || true
echo "  清理 maps"

# 3. 删除 netns（会自动删除 veth pair）
ip netns del "$NS_NAME" 2>/dev/null || true
echo "  删除 namespace: $NS_NAME"

echo ""
echo "=== Pod $POD_NAME 已删除 ==="
echo ""
echo "还需要在所有远程宿主机上清理路由:"
echo "  ./xdp_prog_user route del $POD_IP"
