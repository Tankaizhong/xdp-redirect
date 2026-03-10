#!/bin/bash
# ============================================================================
# add_pod.sh – 在当前宿主机上动态添加一个 pod（容器）
#
# 操作：
#   1. 创建 pod netns + veth pair
#   2. 配置 pod IP
#   3. 在 pod 侧挂 xdp_pass（满足 veth peer 要求）
#   4. 在 host 侧挂 xdp_pod_egress（复用共享 maps）
#   5. 更新 delivery_map、tx_ports、routing_map（本地条目）
#
# 用法：
#   sudo bash add_pod.sh <pod_name> <pod_ip> [host_ip]
#
# 示例：
#   sudo bash add_pod.sh pod1 10.244.1.10
#   sudo bash add_pod.sh pod2 10.244.1.11
#   sudo bash add_pod.sh pod5 10.244.1.20       # 动态新增
#
# pod_name 用于：
#   - netns 名称: ns_<pod_name>      (如 ns_pod1)
#   - veth 接口:  <pod_name>-ns      (pod 侧)
#                 <pod_name>-host    (host 侧)
# ============================================================================

set -e

if [ $# -lt 2 ]; then
    echo "用法: $0 <pod_name> <pod_ip> [host_ip]"
    echo "示例: $0 pod1 10.244.1.10"
    echo ""
    echo "  pod_name  — pod 名称（如 pod1），会创建 ns_pod1 命名空间"
    echo "  pod_ip    — pod 的 IP 地址（如 10.244.1.10）"
    echo "  host_ip   — 本机宿主 IP（可选，默认从 host_config 读取）"
    exit 1
fi

POD_NAME="$1"
POD_IP="$2"
HOST_IP="${3:-}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
XDP_OBJ="${SCRIPT_DIR}/xdp_prog_kern.o"
XDP_USER="${SCRIPT_DIR}/xdp_prog_user"
PIN_BASE="/sys/fs/bpf/xdp_ipip"

NS_NAME="ns_${POD_NAME}"
VETH_NS="${POD_NAME}-ns"
VETH_HOST="${POD_NAME}-host"

# ── 前置检查 ─────────────────────────────────────────────────────────────────

if [ ! -f "$XDP_OBJ" ]; then
    echo "错误: $XDP_OBJ 不存在"; exit 1
fi
if [ ! -f "$PIN_BASE/routing_map" ]; then
    echo "错误: 共享 maps 不存在，请先运行 setup_host.sh"; exit 1
fi
if [ ! -f "$PIN_BASE/pod_egress_prog" ]; then
    echo "错误: pinned pod_egress_prog 不存在，请先运行 setup_host.sh"; exit 1
fi

# 如果未指定 HOST_IP，尝试从 host_config 推断
if [ -z "$HOST_IP" ]; then
    # bpftool map dump 输出的 host_config 第一个 4 字节就是 host_ip
    HOST_IP_HEX=$(bpftool map dump pinned "$PIN_BASE/host_config" 2>/dev/null \
        | grep -A1 'value:' | tail -1 | awk '{printf "%s.%s.%s.%s", strtonum("0x"$1), strtonum("0x"$2), strtonum("0x"$3), strtonum("0x"$4)}')
    if [ -z "$HOST_IP_HEX" ] || [ "$HOST_IP_HEX" = "0.0.0.0" ]; then
        echo "错误: 无法从 host_config 读取宿主机 IP，请用第三个参数指定"
        exit 1
    fi
    HOST_IP="$HOST_IP_HEX"
fi

ETH_MAC=$(bpftool map dump pinned "$PIN_BASE/host_config" 2>/dev/null \
    | grep -A1 'value:' | tail -1 \
    | awk '{printf "%s:%s:%s:%s:%s:%s", $9,$10,$11,$12,$13,$14}' 2>/dev/null || echo "")

echo "=========================================="
echo "  添加 Pod: $POD_NAME"
echo "=========================================="
echo "  Pod IP:    $POD_IP"
echo "  Netns:     $NS_NAME"
echo "  Veth:      $VETH_HOST ↔ $VETH_NS"
echo "  宿主机 IP: $HOST_IP"
echo ""

# ── 1. 创建 netns 和 veth ────────────────────────────────────────────────────

echo "=== 创建网络 ==="

# 如果已存在则先清理
if ip netns list | grep -qw "$NS_NAME"; then
    echo "  清理已有 $NS_NAME..."
    ip link set dev "$VETH_HOST" xdp off 2>/dev/null || true
    ip netns del "$NS_NAME" 2>/dev/null || true
    ip link del "$VETH_HOST" 2>/dev/null || true
fi

ip netns add "$NS_NAME"

ip link add "$VETH_NS" type veth peer name "$VETH_HOST"
ip link set "$VETH_NS" netns "$NS_NAME"

# ── 2. 配置 Pod IP ───────────────────────────────────────────────────────────

echo "=== 配置 Pod IP ==="

ip netns exec "$NS_NAME" ip link set lo up
ip netns exec "$NS_NAME" ip addr add "${POD_IP}/24" dev "$VETH_NS"
ip netns exec "$NS_NAME" ip link set "$VETH_NS" up
ip netns exec "$NS_NAME" ip route add default dev "$VETH_NS"

ip link set "$VETH_HOST" up

echo "  $NS_NAME: $POD_IP/24 on $VETH_NS"

# ── 3. 加载 XDP 程序 ─────────────────────────────────────────────────────────

echo "=== 加载 XDP ==="

# Pod 侧: xdp_pass（满足 veth peer 的 ndo_xdp_xmit 要求）
ip netns exec "$NS_NAME" ip link set dev "$VETH_NS" xdp obj "$XDP_OBJ" sec xdp_pass
echo "  xdp_pass → $NS_NAME/$VETH_NS"

# Host 侧: 复用 pinned 的 xdp_pod_egress 程序（共享 maps）
EGRESS_PROG_ID=$(bpftool prog show pinned "$PIN_BASE/pod_egress_prog" 2>/dev/null | head -1 | awk '{print $1}' | tr -d ':')

if [ -n "$EGRESS_PROG_ID" ]; then
    bpftool net attach xdp id "$EGRESS_PROG_ID" dev "$VETH_HOST"
    echo "  xdp_pod_egress → $VETH_HOST (shared prog id=$EGRESS_PROG_ID)"
else
    echo "警告: 无法读取 pinned prog，直接加载（maps 不共享）"
    ip link set dev "$VETH_HOST" xdp obj "$XDP_OBJ" sec xdp_pod_egress
fi

# ── 4. 更新 eBPF maps ────────────────────────────────────────────────────────

echo "=== 更新转发表 ==="

POD_MAC=$(ip netns exec "$NS_NAME" cat /sys/class/net/"$VETH_NS"/address)

# delivery_map: 本机投递
"$XDP_USER" deliver add "$POD_IP" "$VETH_HOST" "$POD_MAC"

# tx_ports: 注册 veth 到 DEVMAP
"$XDP_USER" txport add "$VETH_HOST"

# routing_map: 本地路由（host_ip = 自己）
ETH_DEV_MAC=$(cat /sys/class/net/"$VETH_HOST"/address 2>/dev/null || echo "$ETH_MAC")
# 使用宿主机 eth MAC（而非 veth MAC）作为 routing_map 的 host_mac
# 因为远程主机也要查这个表，host_mac 应该是物理网卡 MAC
"$XDP_USER" route add "$POD_IP" "$HOST_IP" "$ETH_MAC"

# ── 完成 ─────────────────────────────────────────────────────────────────────

echo ""
echo "=========================================="
echo "  Pod $POD_NAME ($POD_IP) 添加完成！"
echo "=========================================="
echo ""
echo "本机 pod 互通测试:"
echo "  ip netns exec $NS_NAME ping <其他本地pod_ip>"
echo ""
echo "跨宿主机通信还需要在远程宿主机上执行:"
echo "  sudo bash add_remote_route.sh $POD_IP $HOST_IP $ETH_MAC"
echo ""
echo "删除此 pod:"
echo "  sudo bash del_pod.sh $POD_NAME $POD_IP"
