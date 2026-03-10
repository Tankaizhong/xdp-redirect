#!/bin/bash
# ============================================================================
# teardown_host.sh – 清理当前宿主机上的所有 XDP IPIP overlay 资源
#
# 用法：
#   sudo bash teardown_host.sh <eth_interface>
#
# 示例：
#   sudo bash teardown_host.sh ens33
# ============================================================================

set -e

ETH_DEV="${1:-}"
PIN_PFX="/sys/fs/bpf/xdp_ipip_"

echo "=== 清理 XDP IPIP Overlay ==="

# 1. 卸载 eth 上的 XDP
if [ -n "$ETH_DEV" ]; then
    ip link set dev "$ETH_DEV" xdp off 2>/dev/null || true
    echo "  卸载 XDP: $ETH_DEV"
fi

# 2. 查找并清理所有 pod veth 上的 XDP
for ns in $(ip netns list 2>/dev/null | awk '/^ns_pod/ || /^ns_/{print $1}'); do
    ip netns del "$ns" 2>/dev/null || true
    echo "  删除 namespace: $ns"
done

# 清理可能残留的 pod veth
for dev in $(ip -br link show 2>/dev/null | awk '/-host/{print $1}'); do
    ip link set dev "$dev" xdp off 2>/dev/null || true
    ip link del "$dev" 2>/dev/null || true
    echo "  删除 veth: $dev"
done

# 3. 清理 pinned maps 和程序
rm -f "${PIN_PFX}"routing_map "${PIN_PFX}"delivery_map \
      "${PIN_PFX}"host_config "${PIN_PFX}"tx_ports \
      "${PIN_PFX}"pod_egress_prog "${PIN_PFX}"eth_ingress_prog
echo "  清理 pinned: ${PIN_PFX}*"

echo ""
echo "=== 清理完成 ==="
