/* SPDX-License-Identifier: GPL-2.0 */
/*
 * xdp_prog_kern.c – XDP-based container overlay networking with IPIP tunneling.
 *
 * Architecture (per host namespace):
 *
 *   pod1-host ◄─ XDP(xdp_pod_egress)     pod2-host ◄─ XDP(xdp_pod_egress)
 *       │                                      │
 *       └──────────────┬───────────────────────┘
 *                      │
 *                  eth1-nsX ◄─ XDP(xdp_eth_ingress)
 *                      │
 *                 physical network / veth to root NS
 *
 * SEC("xdp_pod_egress") — runs on pod-facing veth (host side).
 *   0. If ARP request → check routing_map, reply with host veth MAC.
 *   1. Parse inner IPv4 dst_ip.
 *   2. Look up routing_map[dst_ip] → {host_ip, host_mac}.
 *   3. If host_ip == local host IP → local delivery:
 *        a. Look up delivery_map[dst_ip] → {ifindex, pod_mac}.
 *        b. Rewrite dst MAC to pod_mac, src MAC to local eth MAC.
 *        c. Fix checksums.
 *        d. bpf_redirect_map(&tx_ports, ifindex) → direct veth-to-veth.
 *   4. If host_ip != local host IP → IPIP encapsulation:
 *        a. bpf_xdp_adjust_head() to prepend outer IP header (20 bytes).
 *        b. Build outer: src=local_host_ip, dst=host_ip, proto=IPPROTO_IPIP.
 *        c. Rewrite eth: src=local_eth_mac, dst=host_mac (from routing_map).
 *        d. Fix outer IP checksum.
 *        e. bpf_redirect_map(&tx_ports, eth_ifindex) → send to wire.
 *
 * SEC("xdp_eth_ingress") — runs on eth interface (facing the physical network).
 *   1. Parse outer IPv4 header.
 *   2. If protocol != IPPROTO_IPIP → XDP_PASS (not our tunnel traffic).
 *   3. Strip outer IP header via bpf_xdp_adjust_head(+20).
 *   4. Parse inner IPv4 dst_ip.
 *   5. Look up delivery_map[inner_dst_ip] → {ifindex, pod_mac}.
 *   6. Rewrite dst MAC to pod_mac.
 *   7. Fix checksums on inner packet.
 *   8. bpf_redirect_map(&tx_ports, ifindex) → deliver to local pod.
 *
 * SEC("xdp_pass") – No-op program for namespace-side veth peers.
 */

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* IPPROTO_IPIP = 4, defined in linux/in.h but sometimes missing */
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
 * ARP packet layout (for Ethernet + IPv4):
 *
 *   struct arphdr        (8 bytes: hrd, pro, hln, pln, op)
 *   sender MAC           (6 bytes)
 *   sender IP            (4 bytes)
 *   target MAC           (6 bytes)
 *   target IP            (4 bytes)
 *
 * Total ARP payload = 8 + 6 + 4 + 6 + 4 = 28 bytes
 * ──────────────────────────────────────────────────────────────────────────── */

struct arp_ipv4_payload {
	unsigned char sender_mac[ETH_ALEN];
	__be32        sender_ip;
	unsigned char target_mac[ETH_ALEN];
	__be32        target_ip;
} __attribute__((packed));

/* ────────────────────────────────────────────────────────────────────────────
 * handle_arp – XDP ARP 代答
 *
 * 收到 pod 发出的 ARP request 时：
 *   1. 检查 target IP 是否在 routing_map 中（即我们知道这个目标）
 *   2. 如果知道，构造 ARP reply，用 host 侧 veth 的入口 MAC 回应
 *   3. XDP_TX 原路发回给 pod
 *
 * 这样 pod 的内核就能解析邻居，顺利把 IP 包发出来交给 xdp_pod_egress。
 * ──────────────────────────────────────────────────────────────────────────── */
static __always_inline int handle_arp(struct xdp_md *ctx)
{
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;

	/* ARP header 紧跟 Ethernet header */
	struct arphdr *arph = (void *)(eth + 1);
	if ((void *)(arph + 1) > data_end)
		return XDP_PASS;

	/* 只处理 Ethernet + IPv4 的 ARP request */
	if (arph->ar_hrd != bpf_htons(ARPHRD_ETHER) ||
	    arph->ar_pro != bpf_htons(ETH_P_IP) ||
	    arph->ar_hln != ETH_ALEN ||
	    arph->ar_pln != 4 ||
	    arph->ar_op  != bpf_htons(ARPOP_REQUEST))
		return XDP_PASS;

	/* ARP payload 紧跟 ARP header */
	struct arp_ipv4_payload *arp_data = (void *)(arph + 1);
	if ((void *)(arp_data + 1) > data_end)
		return XDP_PASS;

	/* 检查 target IP 是否在 routing_map 中（我们管理的 pod IP） */
	__u32 target_ip = arp_data->target_ip; /* 已经是 network byte order */
	struct route_entry *route = bpf_map_lookup_elem(&routing_map, &target_ip);
	if (!route)
		return XDP_PASS; /* 不认识的 IP，交给内核处理 */

	/* ── 构造 ARP reply ─────────────────────────────────────────────── */

	/* 用入口接口（host 侧 veth）的 MAC 作为回应
	 * 因为 xdp_pod_egress 在转发 IP 包时会改写 MAC，
	 * 这里只要给 pod 一个有效的 MAC 让它能发包就行。
	 * 我们用 eth->h_dest（即 host 侧 veth 的 MAC，广播时为 ff:ff:ff:ff:ff:ff）
	 * 不对——广播包的 h_dest 是 ff:ff:ff:ff:ff:ff。
	 * 用 host_config 里的 eth_mac 作为回应 MAC。
	 */
	__u32 zero = 0;
	struct host_info *local = bpf_map_lookup_elem(&host_config, &zero);
	if (!local)
		return XDP_PASS;

	/* 保存 sender 信息（即发起 ARP 的 pod） */
	unsigned char sender_mac[ETH_ALEN];
	__be32 sender_ip;
	memcpy(sender_mac, arp_data->sender_mac, ETH_ALEN);
	sender_ip = arp_data->sender_ip;

	/* ARP reply: op = 2 */
	arph->ar_op = bpf_htons(ARPOP_REPLY);

	/* ARP payload: sender = 我们（用 eth_mac 代答），target = 原来的 sender */
	memcpy(arp_data->sender_mac, local->eth_mac, ETH_ALEN);
	arp_data->sender_ip = target_ip;
	memcpy(arp_data->target_mac, sender_mac, ETH_ALEN);
	arp_data->target_ip = sender_ip;

	/* Ethernet header: dst = 原 sender（pod），src = 我们的 MAC */
	memcpy(eth->h_dest,   sender_mac,    ETH_ALEN);
	memcpy(eth->h_source, local->eth_mac, ETH_ALEN);

	/* XDP_TX: 从同一个接口（host 侧 veth）发回给 pod */
	return XDP_TX;
}

/* ────────────────────────────────────────────────────────────────────────────
 * fix_inner_checksums – recompute IP + L4 checksums for the inner packet.
 * Same strategy as original project: zero + full recompute to handle
 * CHECKSUM_PARTIAL from sender's tx-offload.
 * ──────────────────────────────────────────────────────────────────────────── */
static __always_inline int fix_inner_checksums(void *data, void *data_end)
{
	struct hdr_cursor nh = { .pos = data };
	struct ethhdr *eth;
	int eth_type;

	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type < 0)
		return 0;

	if (eth_type == bpf_htons(ETH_P_IP)) {
		struct iphdr *iph;
		void  *l4hdr;
		__u16  l4_len;
		int    ip_proto;

		ip_proto = parse_iphdr(&nh, data_end, &iph);
		if (ip_proto < 0)
			return 0;

		if (update_iph_checksum(iph, data_end) < 0)
			return 0;

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
				return 0;
			if (update_ipv4_l4_checksum(iph, &udph->check,
						    l4hdr, l4_len, data_end) < 0)
				return -1;
		} else if (ip_proto == IPPROTO_ICMP) {
			struct icmphdr *icmph;
			if (parse_icmphdr(&nh, data_end, &icmph) < 0)
				return 0;
			if (update_icmp_checksum(icmph, l4_len, data_end) < 0)
				return -1;
		}
	}
	/* IPv6 inner packets: not handled in this version */
	return 0;
}

/* ────────────────────────────────────────────────────────────────────────────
 * SEC("xdp_pod_egress") – Pod-facing veth handler (egress from pod).
 *
 * This program is attached to the HOST side of each pod's veth pair.
 * When a pod sends a packet, it arrives here. We decide:
 *   - ARP request → XDP reply directly (no kernel involvement)
 *   - local delivery (same host) → redirect to target pod's veth
 *   - remote delivery → IPIP encapsulate → redirect to eth interface
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
	// bpf_printk("receive");
	/* Parse Ethernet header */
	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type < 0)
		return XDP_PASS;

	/* ── ARP 代答：在 XDP 层直接回复，不依赖内核 proxy_arp ────────── */
	if (eth_type == bpf_htons(ETH_P_ARP))
		// return handle_arp(ctx);
		// bpf_printk("arp");
		return XDP_PASS;

	/* ── 以下处理 IPv4 数据包 ─────────────────────────────────────── */
	if (eth_type != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	ip_proto = parse_iphdr(&nh, data_end, &iph);
	if (ip_proto < 0)
		return XDP_PASS;

	dst_ip = iph->daddr; /* network byte order */

	/* Look up routing_map to find which host owns the destination pod */
	struct route_entry *route = bpf_map_lookup_elem(&routing_map, &dst_ip);
	if (!route) {
		bpf_printk("egress: no route for dst %x proto %d, PASS\n",
			   bpf_ntohl(dst_ip), ip_proto);
		return XDP_PASS; /* unknown destination, let kernel handle */
	}

	/* Get local host config */
	__u32 zero = 0;
	struct host_info *local = bpf_map_lookup_elem(&host_config, &zero);
	if (!local) {
		bpf_printk("egress: host_config missing, PASS\n");
		return XDP_PASS;
	}

	if (route->host_ip == local->host_ip) {
		/* ── Local delivery: same host ────────────────────────────── */
		struct delivery_entry *target = bpf_map_lookup_elem(&delivery_map, &dst_ip);
		if (!target) {
			bpf_printk("egress: local dst %x not in delivery_map, PASS\n",
				   bpf_ntohl(dst_ip));
			return XDP_PASS;
		}

		bpf_printk("egress: local dst %x -> ifindex %d\n",
			   bpf_ntohl(dst_ip), target->ifindex);

		/* Rewrite L2: dst=pod_mac, src=local_eth_mac */
		memcpy(eth->h_dest,   target->pod_mac,  ETH_ALEN);
		memcpy(eth->h_source, local->eth_mac,    ETH_ALEN);

		/* Fix checksums (handle CHECKSUM_PARTIAL) */
		data     = (void *)(long)ctx->data;
		data_end = (void *)(long)ctx->data_end;
		if (fix_inner_checksums(data, data_end) < 0) {
			bpf_printk("egress: local fix_csum failed, PASS\n");
			return XDP_PASS;
		}

		/* Redirect to target pod's veth via DEVMAP */
		return bpf_redirect_map(&tx_ports, target->ifindex, XDP_PASS);

	} else {
		/* ── Remote delivery: IPIP encapsulation ─────────────────── */

		bpf_printk("egress: IPIP dst %x -> host %x\n",
			   bpf_ntohl(dst_ip), bpf_ntohl(route->host_ip));

		/* Save inner packet length for outer IP tot_len */
		__u16 inner_len = bpf_ntohs(iph->tot_len);

		/* Fix inner checksums BEFORE encapsulation (while we can
		 * still parse the inner L4 headers easily) */
		data     = (void *)(long)ctx->data;
		data_end = (void *)(long)ctx->data_end;
		if (fix_inner_checksums(data, data_end) < 0) {
			bpf_printk("egress: IPIP fix_csum failed, PASS\n");
			return XDP_PASS;
		}

		/* Prepend space for outer IP header (20 bytes) */
		if (bpf_xdp_adjust_head(ctx, -(int)sizeof(struct iphdr))) {
			bpf_printk("egress: adjust_head failed, PASS\n");
			return XDP_PASS;
		}

		/* Re-evaluate data pointers after adjust_head */
		data     = (void *)(long)ctx->data;
		data_end = (void *)(long)ctx->data_end;

		/* Need room for: eth header + outer IP header */
		struct ethhdr *new_eth = data;
		if ((void *)(new_eth + 1) > data_end)
			return XDP_PASS;

		struct iphdr *outer_iph = (void *)(new_eth + 1);
		if ((void *)(outer_iph + 1) > data_end)
			return XDP_PASS;

		/* Read old eth header from offset +20 (sizeof(iphdr)) */
		struct ethhdr *old_eth = (struct ethhdr *)((void *)new_eth + sizeof(struct iphdr));
		if ((void *)(old_eth + 1) > data_end)
			return XDP_PASS;

		/* Build new Ethernet header */
		memcpy(new_eth->h_dest,   route->host_mac, ETH_ALEN);
		memcpy(new_eth->h_source, local->eth_mac,   ETH_ALEN);
		new_eth->h_proto = bpf_htons(ETH_P_IP);

		/* Build outer IPv4 header */
		outer_iph->version  = 4;
		outer_iph->ihl      = 5;
		outer_iph->tos      = 0;
		outer_iph->tot_len  = bpf_htons(sizeof(struct iphdr) + inner_len);
		outer_iph->id       = 0;
		outer_iph->frag_off = bpf_htons(0x4000); /* DF bit */
		outer_iph->ttl      = 64;
		outer_iph->protocol = IPPROTO_IPIP;
		outer_iph->check    = 0;
		outer_iph->saddr    = local->host_ip;
		outer_iph->daddr    = route->host_ip;

		/* Compute outer IP checksum */
		outer_iph->check = compute_iph_csum(outer_iph);

		/* Redirect to eth interface */
		bpf_printk("egress: IPIP redirect to eth ifindex %d\n",
			   local->eth_ifindex);
		return bpf_redirect_map(&tx_ports, local->eth_ifindex, XDP_PASS);
	}
}

/* ────────────────────────────────────────────────────────────────────────────
 * SEC("xdp_eth_ingress") – Eth-facing handler (IPIP decapsulation).
 *
 * Attached to the eth interface inside the host namespace.
 * Receives packets from the physical network (or simulated wire).
 *   - If outer IP protocol == IPPROTO_IPIP → decapsulate and deliver to pod.
 *   - Otherwise → XDP_PASS to normal kernel stack.
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

	/* Parse outer Ethernet */
	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	/* Parse outer IPv4 */
	ip_proto = parse_iphdr(&nh, data_end, &outer_iph);
	if (ip_proto < 0)
		return XDP_PASS;

	/* Only handle IPIP tunneled packets */
	if (ip_proto != IPPROTO_IPIP) {
		bpf_printk("ingress: proto %d (not IPIP), PASS\n", ip_proto);
		return XDP_PASS;
	}

	int outer_hdr_len = outer_iph->ihl * 4;
	if (outer_hdr_len < 20 || outer_hdr_len > 60)
		return XDP_PASS;

	/* Parse inner IP to get dst_ip BEFORE we modify the packet */
	struct iphdr *inner_iph = nh.pos;
	if ((void *)(inner_iph + 1) > data_end)
		return XDP_PASS;

	__u32 inner_dst_ip = inner_iph->daddr;

	bpf_printk("ingress: IPIP inner dst %x\n", bpf_ntohl(inner_dst_ip));

	/* Look up delivery target for inner dst IP */
	struct delivery_entry *target = bpf_map_lookup_elem(&delivery_map, &inner_dst_ip);
	if (!target) {
		bpf_printk("ingress: inner dst %x not in delivery_map, PASS\n",
			   bpf_ntohl(inner_dst_ip));
		return XDP_PASS; /* unknown pod, let kernel handle */
	}

	/* Get local host config for src MAC */
	__u32 zero = 0;
	struct host_info *local = bpf_map_lookup_elem(&host_config, &zero);
	if (!local) {
		bpf_printk("ingress: host_config missing, PASS\n");
		return XDP_PASS;
	}

	/* Strip outer IP header.
	 * adjust_head(+outer_hdr_len) moves data forward by outer_hdr_len bytes.
	 * Since the packet is [eth(14)][outer_IP(outer_hdr_len)][inner_IP...],
	 * data was at byte 0 (eth start). After +outer_hdr_len, data lands at
	 * byte outer_hdr_len, which is exactly sizeof(ethhdr) bytes BEFORE inner_IP
	 * (inner_IP starts at 14+outer_hdr_len). We will write the new eth header
	 * at data, overwriting the tail of the outer IP header — that's fine.
	 */
	if (bpf_xdp_adjust_head(ctx, outer_hdr_len))
		return XDP_PASS;

	data     = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	struct ethhdr *new_eth = data;
	if ((void *)(new_eth + 1) > data_end)
		return XDP_PASS;

	/* Build new Ethernet header for local delivery */
	memcpy(new_eth->h_dest,   target->pod_mac, ETH_ALEN);
	memcpy(new_eth->h_source, local->eth_mac,   ETH_ALEN);
	new_eth->h_proto = bpf_htons(ETH_P_IP);

	/* Fix inner checksums */
	if (fix_inner_checksums(data, data_end) < 0) {
		bpf_printk("ingress: fix_csum failed, PASS\n");
		return XDP_PASS;
	}

	/* Deliver to local pod via DEVMAP */
	bpf_printk("ingress: deliver inner dst %x -> ifindex %d\n",
		   bpf_ntohl(inner_dst_ip), target->ifindex);
	return bpf_redirect_map(&tx_ports, target->ifindex, XDP_PASS);
}

/* ────────────────────────────────────────────────────────────────────────────
 * SEC("xdp_pass") – No-op program for namespace-side veth peers.
 * Required by veth driver: veth_xdp_xmit needs peer to have native XDP.
 * ──────────────────────────────────────────────────────────────────────────── */
SEC("xdp_pass")
int xdp_pass_func(struct xdp_md *ctx)
{
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
