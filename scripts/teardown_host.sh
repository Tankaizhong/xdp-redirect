#!/bin/bash
# ============================================================================
# teardown_host.sh – 清理当前宿主机上的所有 XDP IPIP overlay 资源（Docker 版）
# ============================================================================

set -e

ETH_DEV="${1:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
XDP_USER="${ROOT_DIR}/xdp_prog_user"
PIN_PFX="/sys/fs/bpf/xdp_ipip_"
STATE_DIR="/var/run/xdp-overlay"

echo "=== 清理 XDP IPIP Overlay (Docker) ==="

# 1. 卸载 eth 上的 XDP，恢复 MTU
if [ -n "$ETH_DEV" ]; then
    ip link set dev "$ETH_DEV" xdp off        2>/dev/null || true
    ip link set dev "$ETH_DEV" xdpgeneric off 2>/dev/null || true
    ip link set dev "$ETH_DEV" xdpdrv off     2>/dev/null || true
    ip link set dev "$ETH_DEV" mtu 1500 2>/dev/null || true
    echo "  卸载 XDP + 恢复 MTU: $ETH_DEV"
fi

# 2. 清理所有 xdp_ 前缀的 Docker 容器
echo "=== 清理 Docker 容器 ==="
# 修复 1: 加上 `|| true` 防止 grep 找不到容器时触发 set -e 导致脚本意外退出
for container in $(docker ps -a --format '{{.Names}}' 2>/dev/null | grep '^xdp_' || true); do
    pod_name="${container#xdp_}"
    state_file="${STATE_DIR}/${pod_name}.env"
    pod_ip=""
    veth_host=""

    # 优先从状态文件读取 veth 名和 pod IP
    if [ -f "$state_file" ]; then
        veth_host=$(grep '^VETH_HOST=' "$state_file" | cut -d= -f2 || true)
        pod_ip=$(grep '^POD_IP='    "$state_file" | cut -d= -f2 || true)
    fi

    # 卸载 host 侧 veth 上的 XDP
    if [ -n "$veth_host" ]; then
        if ip link show dev "$veth_host" 2>/dev/null | grep -q "prog/xdp"; then
            echo "  卸载 XDP: $veth_host"
            ip link set dev "$veth_host" xdp off        2>/dev/null || true
            ip link set dev "$veth_host" xdpgeneric off 2>/dev/null || true
            ip link set dev "$veth_host" xdpdrv off     2>/dev/null || true
        else
            echo "  跳过卸载 (未检测到 XDP): $veth_host"
        fi
    fi

    # 清理 eBPF map 条目 (修复 2: 加入 timeout 防止 map 损坏时 C 程序死锁挂起)
    if [ -f "$XDP_USER" ] && [ -n "$pod_ip" ]; then
        timeout 5s "$XDP_USER" deliver del "$pod_ip"  2>/dev/null || true
        timeout 5s "$XDP_USER" route   del "$pod_ip"  2>/dev/null || true
    fi
    if [ -f "$XDP_USER" ] && [ -n "$veth_host" ]; then
        timeout 5s "$XDP_USER" txport  del "$veth_host" 2>/dev/null || true
    fi

    # 删除容器 (修复 3: 加入 timeout 强制超时，防止内核 veth 异常导致 Docker daemon 卡死)
    timeout 10s docker rm -f "$container" >/dev/null 2>&1 || echo "  [警告] 容器 $container 删除超时或失败，可能需要手动介入"
    echo "  删除容器: $container${pod_ip:+ (ip: $pod_ip)}${veth_host:+ (veth: $veth_host)}"

    # 删除状态文件
    rm -f "$state_file"
done

# 3. 清理 eth 的 txport 条目
if [ -f "$XDP_USER" ] && [ -n "$ETH_DEV" ]; then
    timeout 5s "$XDP_USER" txport del "$ETH_DEV" 2>/dev/null || true
fi

# 4. 清理残留状态文件
if [ -d "$STATE_DIR" ]; then
    rm -f "${STATE_DIR}"/*.env
    rmdir "$STATE_DIR" 2>/dev/null || true
    echo "  清理状态目录: $STATE_DIR"
fi

# 5. 清理可能残留的 netns 链接
# 修复 4: 防止通配符匹配不到文件时触发 set -e
for ns in /var/run/netns/ns_*; do
    [ -e "$ns" ] || continue
    rm -f "$ns"
    echo "  删除残留 netns 链接: $(basename "$ns")"
done

# 6. 清理 Docker 网络
if docker network inspect xdp-overlay >/dev/null 2>&1; then
    docker network rm xdp-overlay >/dev/null 2>&1 || true
    echo "  删除 Docker 网络: xdp-overlay"
fi

# 7. 清理 pinned maps 和程序
rm -f "${PIN_PFX}"routing_map "${PIN_PFX}"delivery_map \
      "${PIN_PFX}"host_config "${PIN_PFX}"tx_ports \
      "${PIN_PFX}"pod_egress_prog "${PIN_PFX}"eth_ingress_prog
echo "  清理 pinned: ${PIN_PFX}*"

echo ""
echo "=== 清理完成 ==="
echo ""
echo "如需清理 pod 镜像:"
echo "  docker rmi xdp-pod"