#!/bin/bash
# add_pod_base.sh – 添加 pod（Docker bridge 原生配置，不挂载 XDP）
#
# 用法：sudo bash add_pod_base.sh <pod_name> <pod_ip> [docker_image]

set -e

if [ $# -lt 2 ]; then
    echo "用法: $0 <pod_name> <pod_ip> [docker_image]"
    echo "示例: $0 pod1 10.244.1.10"
    exit 1
fi

POD_NAME="$1"
POD_IP="$2"
# 默认镜像与你之前保持一致
DOCKER_IMAGE="${3:-xdp-pod}"

# 为了与 XDP 容器区分，前缀改为 base_
CONTAINER_NAME="base_${POD_NAME}"
# 依然使用同一个 Docker 网络，保证测试环境的网络拓扑完全一致
DOCKER_NET="xdp-overlay"

# ── 前置检查 ──────────────────────────────────────────────────────────────────

docker network inspect "$DOCKER_NET" &>/dev/null \
    || { echo "错误: Docker 网络 $DOCKER_NET 不存在，请先创建它"; exit 1; }

# ── 1. 清理旧容器（如已存在）─────────────────────────────────────────────────

if docker ps -a --format '{{.Names}}' | grep -qw "$CONTAINER_NAME"; then
    echo "清理旧的 Base 容器: $CONTAINER_NAME"
    docker rm -f "$CONTAINER_NAME" 2>/dev/null || true
fi

# ── 2. 启动容器 ────────────────────────────────────────────────────────────────

echo "正在启动 Base 容器 (原生网络模式)..."
docker run -d \
    --name "$CONTAINER_NAME" \
    --network="$DOCKER_NET" \
    --ip="$POD_IP" \
    --cap-add=NET_ADMIN \
    --privileged \
    "$DOCKER_IMAGE" \
    sleep infinity >/dev/null

# ── 3. 找到 host 侧 veth (仅供监控/对比使用) ───────────────────────────────────

PEER_IDX=$(docker exec "$CONTAINER_NAME" cat /sys/class/net/eth0/iflink)
VETH_HOST=$(ip -o link show | awk -F': ' -v idx="$PEER_IDX" '$1 == idx {gsub(/@.*/, "", $2); print $2}')

[ -z "$VETH_HOST" ] && echo "错误: 找不到 host 侧 veth" && exit 1

echo "host 侧 veth: $VETH_HOST (未挂载任何 XDP 程序)"
echo "Checksum Offload: 保持系统默认开启 (Native Bridge 模式)"

echo ""
echo "Base Pod $POD_NAME ($POD_IP) 添加完成"
echo "  进入容器: docker exec -it $CONTAINER_NAME sh"