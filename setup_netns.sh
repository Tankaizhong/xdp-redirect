#!/bin/bash
# 模拟拓扑：NS1 (10.0.1.1) <-> v1-host [XDP] v2-host <-> NS2 (10.0.1.2)
#
# 设计说明：
#   rp_filter    — XDP 在内核 IP 协议栈之前拦截包，rp_filter 永远看不到被
#                  redirect 的包，无需关闭。
#   静态 ARP     — ARP 报文同样经过 XDP redirect，动态 ARP 解析可正常工作，
#                  无需预填静态条目。
#   TX checksum  — fix_checksums() 在 XDP 内对每个转发包全量重算 IP/L4 校验和，
#                  无需用 ethtool 关闭 tx-checksum-ip-generic。

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
XDP_OBJ="${SCRIPT_DIR}/xdp_prog_kern.o"
XDP_PROG_USER="${SCRIPT_DIR}/xdp_prog_user"
XDP_SEC="xdp_redirect_map"

# ── 前置检查 ──────────────────────────────────────────────────────────────────

if [ ! -f "$XDP_OBJ" ]; then
    echo "错误: $XDP_OBJ 不存在，请先运行 make"
    exit 1
fi

if [ ! -f "$XDP_PROG_USER" ]; then
    echo "错误: $XDP_PROG_USER 不存在，请先运行 make"
    exit 1
fi

# ── 1. 清理旧环境 ─────────────────────────────────────────────────────────────

ip link set dev v1-host xdp off 2>/dev/null || true
ip link set dev v2-host xdp off 2>/dev/null || true
ip netns del ns1 2>/dev/null || true
ip netns del ns2 2>/dev/null || true
ip link del v1-host 2>/dev/null || true
ip link del v2-host 2>/dev/null || true
rm -rf /sys/fs/bpf/xdp/

# ── 2. 创建 network namespace ─────────────────────────────────────────────────

ip netns add ns1
ip netns add ns2

# ── 3. 创建 veth pair 并移入 namespace ───────────────────────────────────────

ip link add v1-ns1 type veth peer name v1-host
ip link set v1-ns1 netns ns1

ip link add v2-ns2 type veth peer name v2-host
ip link set v2-ns2 netns ns2

# ── 4. 配置 IP 地址和路由 ─────────────────────────────────────────────────────

ip netns exec ns1 ip addr add 10.0.1.1/24 dev v1-ns1
ip netns exec ns1 ip link set v1-ns1 up
ip netns exec ns1 ip link set lo up
ip netns exec ns1 ip route add default dev v1-ns1

ip netns exec ns2 ip addr add 10.0.1.2/24 dev v2-ns2
ip netns exec ns2 ip link set v2-ns2 up
ip netns exec ns2 ip link set lo up
ip netns exec ns2 ip route add default dev v2-ns2

ip link set v1-host up
ip link set v2-host up

# ── 5. 获取接口信息 ───────────────────────────────────────────────────────────

V1_HOST_IDX=$(cat /sys/class/net/v1-host/ifindex)
V2_HOST_IDX=$(cat /sys/class/net/v2-host/ifindex)
V1_NS1_MAC=$(ip netns exec ns1 cat /sys/class/net/v1-ns1/address)
V2_NS2_MAC=$(ip netns exec ns2 cat /sys/class/net/v2-ns2/address)

echo ""
echo "=== 拓扑信息 ==="
echo "NS1: 10.0.1.1  v1-ns1 MAC=$V1_NS1_MAC"
echo "NS2: 10.0.1.2  v2-ns2 MAC=$V2_NS2_MAC"
echo "宿主机: v1-host ifindex=$V1_HOST_IDX  v2-host ifindex=$V2_HOST_IDX"
echo ""

# ── 6. 加载 XDP 程序 ──────────────────────────────────────────────────────────

echo "=== 加载 XDP 程序 ==="

mkdir -p /sys/fs/bpf/xdp/globals

# namespace 侧必须挂 xdp_pass，否则 veth_xdp_xmit 因 peer 无 XDP 返回 -ENXIO
ip netns exec ns1 ip link set dev v1-ns1 xdp obj "$XDP_OBJ" sec xdp_pass
ip netns exec ns2 ip link set dev v2-ns2 xdp obj "$XDP_OBJ" sec xdp_pass
echo "  xdp_pass → v1-ns1, v2-ns2"

# 只在 v1-host 加载一次程序，v2-host attach 同一实例以共享 maps
if ! ip link set dev v1-host xdp obj "$XDP_OBJ" sec "$XDP_SEC"; then
    echo "错误: v1-host 加载失败"; exit 1
fi

V1_PROG=$(bpftool net show dev v1-host 2>/dev/null | grep "driver id" | awk '{print $NF}')
echo "  $XDP_SEC → v1-host (prog id=$V1_PROG)"

ip link set dev v2-host xdp off 2>/dev/null || true
if ! bpftool net attach xdp id "$V1_PROG" dev v2-host; then
    echo "错误: v2-host attach 失败"; exit 1
fi

V2_PROG=$(bpftool net show dev v2-host 2>/dev/null | grep "driver id" | awk '{print $NF}')
echo "  $XDP_SEC → v2-host (prog id=$V2_PROG)"

if [ "$V1_PROG" = "$V2_PROG" ]; then
    echo "  ✓ 同一程序实例，maps 完全共享"
else
    echo "  ✗ 程序 ID 不一致（v1=$V1_PROG v2=$V2_PROG），请检查"
    exit 1
fi

# ── 7. Pin maps ───────────────────────────────────────────────────────────────

get_map_id() {
    local prog_id=$1 map_name=$2
    for mid in $(bpftool prog show id "$prog_id" 2>/dev/null \
                 | grep -o 'map_ids [0-9,]*' | cut -d' ' -f2 | tr ',' ' '); do
        name=$(bpftool map show id "$mid" 2>/dev/null | awk 'NR==1{print $4}')
        [ "$name" = "$map_name" ] && echo "$mid" && return
    done
}

TX_PORT_ID=$(get_map_id "$V1_PROG" tx_port)
REDIRECT_ID=$(get_map_id "$V1_PROG" redirect_params)
STATS_ID=$(get_map_id "$V1_PROG" xdp_stats)

# 确认 /sys/fs/bpf 已挂载为 bpffs，否则 pin 会静默失败
if ! mount | grep -q 'type bpf'; then
    mount -t bpf bpf /sys/fs/bpf
fi

bpftool map pin id "$TX_PORT_ID"  /sys/fs/bpf/xdp/globals/tx_port     || { echo "错误: pin tx_port 失败"; exit 1; }
bpftool map pin id "$REDIRECT_ID" /sys/fs/bpf/xdp/globals/redirect_params || { echo "错误: pin redirect_params 失败"; exit 1; }
bpftool map pin id "$STATS_ID"    /sys/fs/bpf/xdp/globals/xdp_stats    || { echo "错误: pin xdp_stats 失败"; exit 1; }
echo "  pinned: tx_port(id=$TX_PORT_ID)  redirect_params(id=$REDIRECT_ID)  xdp_stats(id=$STATS_ID)"

# ── 8. 填充转发规则 ───────────────────────────────────────────────────────────

echo ""
echo "=== 配置转发规则 ==="

"$XDP_PROG_USER" -d v1-host -r v2-host --dest-mac "$V2_NS2_MAC"
"$XDP_PROG_USER" -d v2-host -r v1-host --dest-mac "$V1_NS1_MAC"

# ── 完成 ──────────────────────────────────────────────────────────────────────

echo ""
echo "=== 配置完成 ==="
echo ""
echo "测试连通性："
echo "  ip netns exec ns1 ping 10.0.1.2"
echo "  ip netns exec ns2 nc -l -p 8080"
echo "  ip netns exec ns1 nc -zv 10.0.1.2 8080"
echo ""
echo "查看 XDP 统计："
echo "  bpftool map dump pinned /sys/fs/bpf/xdp/globals/xdp_stats"
echo ""
echo "清理："
echo "  ip netns del ns1; ip netns del ns2; ip link del v1-host; ip link del v2-host; rm -rf /sys/fs/bpf/xdp/"
