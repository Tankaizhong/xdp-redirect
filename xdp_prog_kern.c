/* SPDX-License-Identifier: GPL-2.0 */
/*
 * xdp_prog_kern.c – 基于 XDP 的容器 overlay 网络 (IPIP 隧道)
 *
 * 架构 (每个 host 命名空间):
 *
 * pod1-host ◄─ XDP(xdp_pod_egress)     pod2-host ◄─ XDP(xdp_pod_egress)
 * │                                          │
 * └──────────────┬───────────────────────┘
 * │
 * eth1-nsX ◄─ XDP(xdp_eth_ingress)
 * │
 * physical network / veth to root NS
 *
 * SEC("xdp_pod_egress") — 运行在 pod 侧的 veth (host 侧)
 * 0. 如果是 ARP → XDP_PASS (由 bridge 处理; 跨主机 pod 位于不同 /24 子网,
 *    pod 通过本地网关路由, 无跨主机 ARP)
 * 1. 解析内层 IPv4 dst_ip
 * 2. 查找 routing_map[dst_ip] → {host_ip, host_mac}
 * 3. 如果 host_ip == 本地 host IP → 本地交付:
 *    a. 查找 delivery_map[dst_ip] → {ifindex, pod_mac}
 *    b. 修改目的 MAC 为 pod_mac, 源 MAC 为本地 eth MAC
 *    c. 修复校验和
 *    d. bpf_redirect_map(&tx_ports, ifindex) → 直接 veth-to-veth
 * 4. 如果 host_ip != 本地 host IP → IPIP 封装:
 *    a. bpf_xdp_adjust_head() 预留外层 IP 头 (20 字节)
 *    b. 构建外层: src=本地 host_ip, dst=host_ip, proto=IPPROTO_IPIP
 *    c. 修改 eth: src=本地 eth_mac, dst=host_mac (来自 routing_map)
 *    d. 修复外层 IP 校验和
 *    e. bpf_redirect_map(&tx_ports, eth_ifindex) → 发送到物理网络
 *
 * SEC("xdp_eth_ingress") — 运行在 eth 接口 (面向物理网络)
 * 1. 解析外层 IPv4 头
 * 2. 如果协议 != IPPROTO_IPIP → XDP_PASS (非隧道流量)
 * 3. 通过 bpf_xdp_adjust_head(+20) 剥离外层 IP 头
 * 4. 解析内层 IPv4 dst_ip
 * 5. 查找 delivery_map[inner_dst_ip] → {ifindex, pod_mac}
 * 6. 修改目的 MAC 为 pod_mac
 * 7. 修复内层数据包校验和
 * 8. bpf_redirect_map(&tx_ports, ifindex) → 交付给本地 pod
 *
 * SEC("xdp_pass") – 命名空间侧 veth 对端的空操作程序
 */

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* IPPROTO_IPIP = 4, 定义在 linux/in.h 但有时可能缺失 */
#ifndef IPPROTO_IPIP
#define IPPROTO_IPIP 4
#endif

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

#include "common/parsing_helpers.h"
#include "common/checksum_helpers.h"
#include "common/xdp_maps.h"

/* ────────────────────────────────────────────────────────────────────────────
 * fix_inner_checksums – 重新计算内层数据包的 IP 和 L4 校验和
 * 策略与原项目相同: 清零后完全重新计算, 以处理发送方 tx-offload
 * 产生的 CHECKSUM_PARTIAL
 * ──────────────────────────────────────────────────────────────────────────── */
static __always_inline int fix_inner_checksums(void *data, void *data_end)
{
	struct hdr_cursor nh = { .pos = data };
	struct ethhdr *eth;
	int eth_type;

	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type < 0)
		return -1;

	if (eth_type == bpf_htons(ETH_P_IP)) {
		struct iphdr *iph;
		void  *l4hdr;
		__u16  l4_len;
		int    ip_proto;

		ip_proto = parse_iphdr(&nh, data_end, &iph);
		if (ip_proto < 0)
			return -1;

		if (update_iph_checksum(iph, data_end) < 0)
			return -1;

		l4_len = bpf_ntohs(iph->tot_len) - ((__u16)iph->ihl << 2);
		l4hdr  = nh.pos;

		if (ip_proto == IPPROTO_TCP) {
			struct tcphdr *tcph;
			if (parse_tcphdr(&nh, data_end, &tcph) < 0)
				return 0;
			if (update_ipv4_l4_checksum(iph, &tcph->check,
						    l4hdr, l4_len, data_end) < 0)
				return -1;
		} else if (ip_proto == IPPROTO_UDP) {
			struct udphdr *udph;
			if (parse_udphdr(&nh, data_end, &udph) < 0)
				return -1;
			if (update_ipv4_l4_checksum(iph, &udph->check,
						    l4hdr, l4_len, data_end) < 0)
				return -1;
		} else if (ip_proto == IPPROTO_ICMP) {
			struct icmphdr *icmph;
			if (parse_icmphdr(&nh, data_end, &icmph) < 0)
				return -1;
			if (update_icmp_checksum(icmph, l4_len, data_end) < 0)
				return -1;
		}
	}
	/* IPv6 内层数据包: 本版本暂不处理 */
	return 0;
}

/* ────────────────────────────────────────────────────────────────────────────
 * SEC("xdp_pod_egress") – Pod 侧 veth 处理器 (从 pod 发出)
 *
 * 此程序挂载在每个 pod 的 veth 对的 HOST 侧
 * 当 pod 发送数据包时, 会到达这里。我们决定:
 * - ARP 请求 → XDP 直接回复 (无需内核介入)
 * - 本地交付 (同一主机) → 重定向到目标 pod 的 veth
 * - 远程交付 → IPIP 封装 → 重定向到 eth 接口
 * ──────────────────────────────────────────────────────────────────────────── */
SEC("xdp_pod_egress")
int xdp_pod_egress_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
	struct hdr_cursor nh = { .pos = data };
	struct ethhdr *eth;
	struct iphdr  *iph;
	int eth_type, ip_proto;
	__u32 dst_ip;

	/* 解析以太网头 */
	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type < 0)
		return XDP_PASS;

	/* ARP 由 bridge 内核处理 */
	if (eth_type == bpf_htons(ETH_P_ARP))
		// bpf_printk("egress: received ARP request, passing to kernel\n");
		return XDP_PASS;

	/* ── 以下处理 IPv4 数据包 ─────────────────────────────────────── */
	if (eth_type != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	ip_proto = parse_iphdr(&nh, data_end, &iph);
	if (ip_proto < 0)
		return XDP_PASS;

	dst_ip = iph->daddr; /* 网络字节序 */

	/* 查找 routing_map 确定目标 pod 所属的 host */
	struct route_entry *route = bpf_map_lookup_elem(&routing_map, &dst_ip);
	if (!route) {
		// bpf_printk("egress: no route for dst %pI4 proto %d, PASS\n",
		// 	   &dst_ip, ip_proto);
		/* 在传递给内核前修复 CHECKSUM_PARTIAL: veth+XDP 可能
		 * 不保留 ip_summed, 所以 TX offload 无法完成校验和 */
		data     = (void *)(long)ctx->data;
		data_end = (void *)(long)ctx->data_end;
		// fix_inner_checksums(data, data_end);
		// bpf_printk("no checksum");
		return XDP_PASS; /* 未知目的地, 交给内核处理 */
	}

	/* 获取本地 host 配置 */
	__u32 zero = 0;
	struct host_info *local = bpf_map_lookup_elem(&host_config, &zero);
	if (!local) {
		// bpf_printk("egress: host_config missing, PASS\n");
		return XDP_PASS;
	}

	if (route->host_ip == local->host_ip) {
		/* ── 本地交付: 同一主机 ────────────────────────────── */
		struct delivery_entry *target = bpf_map_lookup_elem(&delivery_map, &dst_ip);
		if (!target) {
			// bpf_printk("egress: local dst %pI4 not in delivery_map, PASS\n",
			// 	   &dst_ip);
			return XDP_PASS;
		}

		// bpf_printk("egress: local dst %pI4 -> ifindex %d\n", &dst_ip, target->ifindex);

		/* 修改 L2: 目的=pod_mac, 源=本地 eth_mac */
		memcpy(eth->h_dest,   target->pod_mac,  ETH_ALEN);
		memcpy(eth->h_source, local->eth_mac,    ETH_ALEN);

		/* 修复校验和 (处理 CHECKSUM_PARTIAL) */
		data     = (void *)(long)ctx->data;
		data_end = (void *)(long)ctx->data_end;
		// if (fix_inner_checksums(data, data_end) < 0) {
		// 	bpf_printk("egress: local fix_csum failed, PASS\n");
		// 	return XDP_PASS;
		// }

		/* 通过 DEVMAP 重定向到目标 pod 的 veth */
		return bpf_redirect_map(&tx_ports, target->ifindex, XDP_PASS);

	} else {
		/* ── 远程交付: IPIP 封装 ─────────────────── */

		// bpf_printk("egress: IPIP dst %pI4 -> host %pI4\n",
		// 	   &dst_ip, &route->host_ip);

		/* 保存内层数据包长度用于外层 IP tot_len */
		__u16 inner_len = bpf_ntohs(iph->tot_len);

		/* 在封装前修复内层校验和 (因为此时还可以方便地解析内层 L4 头) */
		data     = (void *)(long)ctx->data;
		data_end = (void *)(long)ctx->data_end;
		if (fix_inner_checksums(data, data_end) < 0) {
			// bpf_printk("egress: IPIP fix_csum failed, PASS\n");
			return XDP_PASS;
		}

		/* 预留外层 IP 头空间 (20 字节) */
		if (bpf_xdp_adjust_head(ctx, -(int)sizeof(struct iphdr))) {
			// bpf_printk("egress: adjust_head failed, PASS\n");
			return XDP_PASS;
		}

		/* adjust_head 后重新获取数据指针 */
		data     = (void *)(long)ctx->data;
		data_end = (void *)(long)ctx->data_end;

		/* 需要空间: eth 头 + 外层 IP 头 */
		struct ethhdr *new_eth = data;
		if ((void *)(new_eth + 1) > data_end)
			return XDP_PASS;

		struct iphdr *outer_iph = (void *)(new_eth + 1);
		if ((void *)(outer_iph + 1) > data_end)
			return XDP_PASS;

	/* 从偏移 +20 处读取旧的 eth 头 (sizeof(iphdr)) */
		struct ethhdr *old_eth = (struct ethhdr *)((void *)new_eth + sizeof(struct iphdr));
		if ((void *)(old_eth + 1) > data_end)
			return XDP_PASS;

		/* 构建新的以太网头 */
		memcpy(new_eth->h_dest,   route->host_mac, ETH_ALEN);
		memcpy(new_eth->h_source, local->eth_mac,   ETH_ALEN);
		new_eth->h_proto = bpf_htons(ETH_P_IP);

		/* 构建外层 IPv4 头 */
		outer_iph->version  = 4;
		outer_iph->ihl      = 5;
		outer_iph->tos      = 0;
		outer_iph->tot_len  = bpf_htons(sizeof(struct iphdr) + inner_len);
		outer_iph->id       = 0;
		outer_iph->frag_off = bpf_htons(0x4000); /* DF 位 */
		outer_iph->ttl      = 64;
		outer_iph->protocol = IPPROTO_IPIP;
		outer_iph->check    = 0;
		outer_iph->saddr    = local->host_ip;
		outer_iph->daddr    = route->host_ip;

		/* 计算外层 IP 校验和 */
		outer_iph->check = compute_iph_csum(outer_iph);

		/* 重定向到 eth 接口 */
		// bpf_printk("egress: IPIP redirect to eth ifindex %d\n",
		// 	   local->eth_ifindex);
		return bpf_redirect_map(&tx_ports, local->eth_ifindex, XDP_PASS);
	}
}

/* ────────────────────────────────────────────────────────────────────────────
 * SEC("xdp_eth_ingress") – Eth 侧处理器 (IPIP 解封装)
 *
 * 挂载在 host 命名空间内的 eth 接口
 * 接收来自物理网络 (或模拟线路) 的数据包
 * - 如果外层 IP 协议 == IPPROTO_IPIP → 解封装并交付给 pod
 * - 否则 → XDP_PASS 给正常内核栈处理
 * ──────────────────────────────────────────────────────────────────────────── */
SEC("xdp_eth_ingress")
int xdp_eth_ingress_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
	struct hdr_cursor nh = { .pos = data };
	struct ethhdr *eth;
	struct iphdr  *outer_iph;
	int eth_type, ip_proto;

	/* 解析外层以太网 */
	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	/* 解析外层 IPv4 */
	ip_proto = parse_iphdr(&nh, data_end, &outer_iph);
	if (ip_proto < 0)
		return XDP_PASS;

	/* 只处理 IPIP 隧道数据包 */
	if (ip_proto != IPPROTO_IPIP) {
		// bpf_printk("ingress: proto %d (not IPIP), PASS\n", ip_proto);
		return XDP_PASS;
	}

	int outer_hdr_len = outer_iph->ihl * 4;
	if (outer_hdr_len < 20 || outer_hdr_len > 60)
		return XDP_PASS;

	/* 在修改数据包前解析内层 IP 获取 dst_ip */
	struct iphdr *inner_iph = nh.pos;
	if ((void *)(inner_iph + 1) > data_end)
		return XDP_PASS;

	__u32 inner_dst_ip = inner_iph->daddr;

	// bpf_printk("ingress: IPIP inner dst %pI4\n", &inner_dst_ip);

	/* 查找内层目标 IP 的交付目标 */
	struct delivery_entry *target = bpf_map_lookup_elem(&delivery_map, &inner_dst_ip);
	if (!target) {
		// bpf_printk("ingress: inner dst %pI4 not in delivery_map, PASS\n",
		// 	   &inner_dst_ip);
		return XDP_PASS; /* 未知 pod, 交给内核处理 */
	}

	/* 获取本地 host 配置用于源 MAC */
	__u32 zero = 0;
	struct host_info *local = bpf_map_lookup_elem(&host_config, &zero);
	if (!local) {
		// bpf_printk("ingress: host_config missing, PASS\n");
		return XDP_PASS;
	}

	/* 剥离外层 IP 头
	 * adjust_head(+outer_hdr_len) 将数据向前移动 outer_hdr_len 字节
	 * 因为数据包是 [eth(14)][outer_IP(outer_hdr_len)][inner_IP...]
	 * data 原来在字节 0 (eth 起始位置). +outer_hdr_len 后, data 到达
	 * 字节 outer_hdr_len, 正好是内层 IP 之前 sizeof(ethhdr) 字节处
	 * (inner_IP 从 14+outer_hdr_len 开始). 我们会在 data 处写入新 eth 头,
	 * 覆盖外层 IP 头的尾部 — 这没问题
	 */
	if (bpf_xdp_adjust_head(ctx, outer_hdr_len))
		return XDP_PASS;

	data     = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	struct ethhdr *new_eth = data;
	if ((void *)(new_eth + 1) > data_end)
		return XDP_PASS;

	/* 构建本地交付的新以太网头 */
	memcpy(new_eth->h_dest,   target->pod_mac, ETH_ALEN);
	memcpy(new_eth->h_source, local->eth_mac,   ETH_ALEN);
	new_eth->h_proto = bpf_htons(ETH_P_IP);

	/* 修复内层校验和 */
	if (fix_inner_checksums(data, data_end) < 0) {
		// bpf_printk("ingress: fix_csum failed, PASS\n");
		return XDP_PASS;
	}

	/* 通过 DEVMAP 交付给本地 pod */
	// bpf_printk("ingress: deliver inner dst %pI4 -> ifindex %d\n",
	// 	   &inner_dst_ip, target->ifindex);
	return bpf_redirect_map(&tx_ports, target->ifindex, XDP_PASS);
}

/* ────────────────────────────────────────────────────────────────────────────
 * SEC("xdp_pass") – 命名空间侧 veth 对端的空操作程序
 * veth 驱动需要: veth_xdp_xmit 需要对端支持 native XDP
 * ──────────────────────────────────────────────────────────────────────────── */
SEC("xdp_pass")
int xdp_pass_func(struct xdp_md *ctx)
{
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
