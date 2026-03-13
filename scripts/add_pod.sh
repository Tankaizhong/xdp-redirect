#!/bin/bash
# add_pod.sh – 添加 pod（Docker bridge 默认配置 + XDP 程序）
#
# 用法：sudo bash add_pod.sh <pod_name> <pod_ip> [docker_image]

set -e

if [ $# -lt 2 ]; then
    echo "用法: $0 <pod_name> <pod_ip> [docker_image]"
    echo "示例: $0 pod1 10.244.1.10"
    exit 1
fi

POD_NAME="$1"
POD_IP="$2"
DOCKER_IMAGE="${3:-xdp-pod}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
XDP_USER="${ROOT_DIR}/xdp_prog_user"
PIN_PFX="/sys/fs/bpf/xdp_ipip_"
STATE_DIR="/var/run/xdp-overlay"

CONTAINER_NAME="xdp_${POD_NAME}"
DOCKER_NET="xdp-overlay"

# ── 前置检查 ──────────────────────────────────────────────────────────────────

[ ! -f "${PIN_PFX}routing_map" ]     && echo "错误: maps 不存在，请先运行 setup_host.sh" && exit 1
[ ! -f "${PIN_PFX}pod_egress_prog" ] && echo "错误: pod_egress_prog 不存在，请先运行 setup_host.sh" && exit 1
docker network inspect "$DOCKER_NET" &>/dev/null \
    || { echo "错误: Docker 网络 xdp-overlay 不存在，请先运行 setup_host.sh"; exit 1; }

# 读取本机 IP 和 MAC
HOST_CFG=$("$XDP_USER" host get 2>/dev/null || true)
HOST_IP=$(echo "$HOST_CFG" | awk '{print $1}')
ETH_MAC=$(echo "$HOST_CFG" | awk '{print $2}')
[ -z "$HOST_IP" ] || [ "$HOST_IP" = "0.0.0.0" ] && echo "错误: 请先运行 setup_host.sh" && exit 1

# ── 1. 清理旧容器（如已存在）─────────────────────────────────────────────────

if docker ps -a --format '{{.Names}}' | grep -qw "$CONTAINER_NAME"; then
    OLD_STATE="${STATE_DIR}/${POD_NAME}.env"
    if [ -f "$OLD_STATE" ]; then
        OLD_VETH=$(grep '^VETH_HOST=' "$OLD_STATE" | cut -d= -f2)
        [ -n "$OLD_VETH" ] && ip link set dev "$OLD_VETH" xdp off 2>/dev/null || true
    fi
    rm -f "$OLD_STATE"
    docker rm -f "$CONTAINER_NAME" 2>/dev/null || true
fi

# ── 3. 启动容器 ────────────────────────────────────────────────────────────────

docker run -d \
    --name "$CONTAINER_NAME" \
    --network="$DOCKER_NET" \
    --ip="$POD_IP" \
    --cap-add=NET_ADMIN \
    --privileged \
    "$DOCKER_IMAGE" \
    sleep infinity >/dev/null

# ── 4. 找到 host 侧 veth ───────────────────────────────────────────────────────

PEER_IDX=$(docker exec "$CONTAINER_NAME" cat /sys/class/net/eth0/iflink)
VETH_HOST=$(ip -o link show | awk -F': ' -v idx="$PEER_IDX" '$1 == idx {gsub(/@.*/, "", $2); print $2}')
[ -z "$VETH_HOST" ] && echo "错误: 找不到 host 侧 veth" && exit 1
echo "host 侧 veth: $VETH_HOST"

# ── 5. 保存状态 ────────────────────────────────────────────────────────────────

mkdir -p "$STATE_DIR"
cat > "${STATE_DIR}/${POD_NAME}.env" <<EOF
VETH_HOST=${VETH_HOST}
POD_IP=${POD_IP}
EOF

# ── 6. 加载 XDP 程序 ───────────────────────────────────────────────────────────

# ip link set dev "$VETH_HOST" xdp pinned "${PIN_PFX}pod_egress_prog"
ip link set dev "$VETH_HOST" xdpgeneric pinned "${PIN_PFX}pod_egress_prog"
echo "xdp_pod_egress → $VETH_HOST"

# 禁用 veth 两侧的 TX checksum offload。
# 容器发出的包内核会设置 CHECKSUM_PARTIAL（伪首部），依赖 NIC 硬件补全；
# 但经过 XDP redirect 的包绕过了 TX offload，必须由 fix_inner_checksums 补全。
# 这里强制两侧用软件计算，保证 XDP 看到的始终是完整校验和。
ethtool -K "$VETH_HOST" tx off 2>/dev/null || true
CONTAINER_PID=$(docker inspect -f '{{.State.Pid}}' "$CONTAINER_NAME")
nsenter -n -t "$CONTAINER_PID" -- ethtool -K eth0 tx off 2>/dev/null || true
echo "checksum offload disabled on $VETH_HOST and container eth0"

# ── 7. 更新 eBPF maps ──────────────────────────────────────────────────────────

POD_MAC=$(docker exec "$CONTAINER_NAME" cat /sys/class/net/eth0/address)
"$XDP_USER" deliver add "$POD_IP" "$VETH_HOST" "$POD_MAC"
"$XDP_USER" txport add "$VETH_HOST"
"$XDP_USER" route add "$POD_IP" "$HOST_IP" "$ETH_MAC"

echo ""
echo "Pod $POD_NAME ($POD_IP) 添加完成"
echo "  进入容器: docker exec -it $CONTAINER_NAME sh"
