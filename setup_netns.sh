#!/bin/bash
# 模拟拓扑：NS1 (10.0.1.1) <-> v1_host [XDP] v2_host <-> NS2 (10.0.1.2)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
XDP_PROG_USER="${SCRIPT_DIR}/xdp_prog_user"
XDP_OBJ="${SCRIPT_DIR}/xdp_prog_kern.o"
XDP_SEC="xdp_redirect_map"

# 加载 XDP 程序的函数
load_xdp() {
    local ifname=$1
    local bpf_obj=$2
    local section=$3
    local output

    echo "尝试加载 XDP 程序到 $ifname..."

    # 方法1: 尝试 native XDP
    output=$(ip link set dev $ifname xdp obj $bpf_obj sec $section 2>&1)
    if [ $? -eq 0 ]; then
        echo "  成功加载 (native XDP)"
        return 0
    fi

    # 方法2: 尝试 SKB 模式 (通用 XDP，兼容虚拟机)
    output=$(ip link set dev $ifname xdp obj $bpf_obj sec $section mode skb 2>&1)
    if [ $? -eq 0 ]; then
        echo "  成功加载 (skb mode)"
        return 0
    fi

    # 方法3: 尝试 xdpgeneric
    output=$(ip link set dev $ifname xdpgeneric obj $bpf_obj sec $section 2>&1)
    if [ $? -eq 0 ]; then
        echo "  成功加载 (xdpgeneric)"
        return 0
    fi

    # 显示错误信息
    echo "  错误: 加载失败"
    echo "  $output"
    return 1
}

# 1. 清理环境
ip netns del ns1 2>/dev/null || true
ip netns del ns2 2>/dev/null || true
ip link del v1-host 2>/dev/null || true
ip link del v2-host 2>/dev/null || true
ip link del v1-ns1 2>/dev/null || true
ip link del v2-ns2 2>/dev/null || true

# 卸载已加载的 XDP 程序
ip link set dev v1-host xdp off 2>/dev/null || true
ip link set dev v2-host xdp off 2>/dev/null || true

# 2. 先创建网络命名空间
ip netns add ns1
ip netns add ns2

# 3. 创建 veth pair 并移入 namespace
ip link add v1-ns1 type veth peer name v1-host
ip link set v1-ns1 netns ns1

ip link add v2-ns2 type veth peer name v2-host
ip link set v2-ns2 netns ns2

# 4. 配置 NS1 内的 IP 和路由
ip netns exec ns1 ip addr add 10.0.1.1/24 dev v1-ns1
ip netns exec ns1 ip link set v1-ns1 up
ip netns exec ns1 ip link set lo up
# 默认路由指向宿主机
ip netns exec ns1 ip route add default dev v1-ns1


# 5. 配置 NS2 内的 IP 和路由
ip netns exec ns2 ip addr add 10.0.1.2/24 dev v2-ns2
ip netns exec ns2 ip link set v2-ns2 up
ip netns exec ns2 ip link set lo up
ip netns exec ns2 ip route add default dev v2-ns2

# 6. 配置宿主机端的接口
ip link set v1-host up
ip link set v2-host up

# # 宿主机到 ns1
# ip route add 10.0.1.1/32 dev v1-host
# # 宿主机到 ns2
# ip route add 10.0.1.2/32 dev v2-host




# 7. 获取关键信息
V1_HOST=v1-host
V2_HOST=v2-host
V1_HOST_IDX=$(cat /sys/class/net/v1-host/ifindex)
V2_HOST_IDX=$(cat /sys/class/net/v2-host/ifindex)
V1_NS1_MAC=$(ip netns exec ns1 cat /sys/class/net/v1-ns1/address)
V2_NS2_MAC=$(ip netns exec ns2 cat /sys/class/net/v2-ns2/address)
# 宿主机端接口的 MAC 地址（XDP 程序需要用这些）
V1_HOST_MAC=$(cat /sys/class/net/v1-host/address)
V2_HOST_MAC=$(cat /sys/class/net/v2-host/address)

# 8. 必须：关闭宿主机的反向路径过滤 (RP Filter)
# 否则内核会因为收到的包源IP不符合路由表而丢弃包
sysctl -w net.ipv4.conf.v1-host.rp_filter=0
sysctl -w net.ipv4.conf.v2-host.rp_filter=0
sysctl -w net.ipv4.conf.all.rp_filter=0

echo ""
echo "=== 网络命名空间配置完成 ==="
echo "NS1 (10.0.1.1, MAC: $V1_NS1_MAC)"
echo "NS2 (10.0.1.2, MAC: $V2_NS2_MAC)"
echo ""
echo "宿主机接口:"
echo "v1-host: ifindex=$V1_HOST_IDX (连接 NS1)"
echo "v2-host: ifindex=$V2_HOST_IDX (连接 NS2)"
echo ""

# 9. 检查依赖
# 检查 XDP 对象文件是否存在
if [ ! -f "$XDP_OBJ" ]; then
    echo "错误: $XDP_OBJ 不存在，请先运行 make"
    exit 1
fi

# 检查 xdp_prog_user 是否存在
if [ ! -f "$XDP_PROG_USER" ]; then
    echo "错误: $XDP_PROG_USER 不存在，请先运行 make"
    exit 1
fi

# 必须：给 namespace 侧接口加载 xdp_pass，否则 veth_xdp_xmit 会因 peer 无 XDP 而返回 -ENXIO
echo "加载 xdp_pass 到 namespace 侧接口..."
ip netns exec ns1 ip link set dev v1-ns1 xdp obj "$XDP_OBJ" sec xdp_pass
ip netns exec ns2 ip link set dev v2-ns2 xdp obj "$XDP_OBJ" sec xdp_pass

# 10. 加载 XDP 程序到两个接口（共享同一套 maps）
echo "=== 加载 XDP 程序 ==="

rm -rf /sys/fs/bpf/xdp/
mkdir -p /sys/fs/bpf/xdp/globals

# 10.1 只在 v1-host 加载一次程序，创建 maps
echo "加载 XDP 程序到 v1-host..."
if ! ip link set dev v1-host xdp obj "$XDP_OBJ" sec "$XDP_SEC"; then
    echo "错误: v1-host 加载失败"; exit 1
fi

# 获取程序 ID（bpftool net show 格式: "v1-host(75) driver id 231"）
V1_PROG=$(bpftool net show dev v1-host 2>/dev/null | grep "driver id" | awk '{print $NF}')
echo "  XDP 程序 ID: $V1_PROG"

# 10.2 将同一程序实例 attach 到 v2-host → 共享 maps
# 先确保 v2-host 没有旧程序（如有则卸载）
ip link set dev v2-host xdp off 2>/dev/null || true
echo "将同一程序 attach 到 v2-host（共享 maps）..."
if ! bpftool net attach xdp id $V1_PROG dev v2-host; then
    echo "错误: v2-host attach 失败"; exit 1
fi

V2_PROG=$(bpftool net show dev v2-host 2>/dev/null | grep "driver id" | awk '{print $NF}')
echo "  v1-host prog=$V1_PROG  v2-host prog=$V2_PROG"
[ "$V1_PROG" = "$V2_PROG" ] && echo "  ✓ 同一程序，maps 完全共享" \
                             || echo "  ✗ 程序 ID 不一致，请检查"

# 10.3 Pin 共享的 maps（通过程序 ID 找到 map ID）
get_map_id() {
    local prog_id=$1 map_name=$2
    for mid in $(bpftool prog show id $prog_id 2>/dev/null \
                 | grep -o 'map_ids [0-9,]*' | cut -d' ' -f2 | tr ',' ' '); do
        name=$(bpftool map show id $mid 2>/dev/null | awk 'NR==1{print $4}')
        [ "$name" = "$map_name" ] && echo $mid && return
    done
}
TX_PORT_ID=$(get_map_id $V1_PROG tx_port)
REDIRECT_ID=$(get_map_id $V1_PROG redirect_params)
echo "  共享 maps: tx_port=$TX_PORT_ID redirect_params=$REDIRECT_ID"
bpftool map pin id $TX_PORT_ID   /sys/fs/bpf/xdp/globals/tx_port
bpftool map pin id $REDIRECT_ID  /sys/fs/bpf/xdp/globals/redirect_params

echo ""
echo "=== 配置重定向规则 ==="

# 11 & 12. 更新共享 maps 一次，两个接口都生效
echo "配置 v1-host -> v2-host 重定向..."
$XDP_PROG_USER -d v1-host -r v2-host --dest-mac $V2_NS2_MAC

echo "配置 v2-host -> v1-host 重定向..."
$XDP_PROG_USER -d v2-host -r v1-host --dest-mac $V1_NS1_MAC

echo ""
echo "=== 配置完成 ==="
echo ""
echo ">>> 运行步骤 <<<"
echo "1. 开启一个终端监控日志: sudo cat /sys/kernel/debug/tracing/trace_pipe"
echo ""
echo "2. 在 NS1 中发起 ping 测试:"
echo "   ip netns exec ns1 ping 10.0.1.2"
