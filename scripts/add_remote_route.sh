#!/bin/bash
# ============================================================================
# add_remote_route.sh – 在本机的 routing_map 中注册远程 pod
#
# 当远程宿主机上新增了一个 pod，需要在本机执行此脚本，
# 告诉本机的 XDP 程序：该 pod_ip 在哪台远程宿主机上。
#
# 用法：
#   sudo bash add_remote_route.sh <pod_ip> <remote_host_ip> <remote_host_mac>
#
# 示例：
#   # 在 VM1 上注册 VM2 的 pod
#   sudo bash add_remote_route.sh 10.244.2.10 192.168.1.2 aa:bb:cc:dd:ee:ff
#
# 批量注册：
#   # 在 VM1 上注册 VM2 的所有 pod
#   for ip in 10.244.2.10 10.244.2.11 10.244.2.20; do
#       sudo bash add_remote_route.sh $ip 192.168.1.2 aa:bb:cc:dd:ee:ff
#   done
# ============================================================================

set -e

if [ $# -lt 3 ]; then
    echo "用法: $0 <pod_ip> <remote_host_ip> <remote_host_mac>"
    echo "示例: $0 10.244.2.10 192.168.1.2 aa:bb:cc:dd:ee:ff"
    exit 1
fi

POD_IP="$1"
REMOTE_HOST_IP="$2"
REMOTE_HOST_MAC="$3"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
XDP_USER="${ROOT_DIR}/xdp_prog_user"

echo "=== 添加远程路由 ==="
"$XDP_USER" route add "$POD_IP" "$REMOTE_HOST_IP" "$REMOTE_HOST_MAC"
echo "  本机 routing_map: $POD_IP → host=$REMOTE_HOST_IP mac=$REMOTE_HOST_MAC"
