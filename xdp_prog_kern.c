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
 * SEC("xdp_pass") — no-op for namespace-side veth peers.
 */

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
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

	/* Parse Ethernet + IPv4 to get destination pod IP */
	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	ip_proto = parse_iphdr(&nh, data_end, &iph);
	if (ip_proto < 0)
		return XDP_PASS;

	dst_ip = iph->daddr; /* network byte order */

	/* Look up routing_map to find which host owns the destination pod */
	struct route_entry *route = bpf_map_lookup_elem(&routing_map, &dst_ip);
	if (!route)
		return XDP_PASS; /* unknown destination, let kernel handle */

	/* Get local host config */
	__u32 zero = 0;
	struct host_info *local = bpf_map_lookup_elem(&host_config, &zero);
	if (!local)
		return XDP_PASS;

	if (route->host_ip == local->host_ip) {
		/* ── Local delivery: same host ────────────────────────────── */
		struct delivery_entry *target = bpf_map_lookup_elem(&delivery_map, &dst_ip);
		if (!target)
			return XDP_PASS;

		/* Rewrite L2: dst=pod_mac, src=local_eth_mac */
		memcpy(eth->h_dest,   target->pod_mac,  ETH_ALEN);
		memcpy(eth->h_source, local->eth_mac,    ETH_ALEN);

		/* Fix checksums (handle CHECKSUM_PARTIAL) */
		data     = (void *)(long)ctx->data;
		data_end = (void *)(long)ctx->data_end;
		if (fix_inner_checksums(data, data_end) < 0)
			return XDP_PASS;

		/* Redirect to target pod's veth via DEVMAP */
		return bpf_redirect_map(&tx_ports, target->ifindex, XDP_PASS);

	} else {
		/* ── Remote delivery: IPIP encapsulation ─────────────────── */

		/* Save inner packet length for outer IP tot_len */
		__u16 inner_len = bpf_ntohs(iph->tot_len);

		/* Fix inner checksums BEFORE encapsulation (while we can
		 * still parse the inner L4 headers easily) */
		data     = (void *)(long)ctx->data;
		data_end = (void *)(long)ctx->data_end;
		if (fix_inner_checksums(data, data_end) < 0)
			return XDP_PASS;

		/* Prepend space for outer IP header (20 bytes) */
		if (bpf_xdp_adjust_head(ctx, -(int)sizeof(struct iphdr)))
			return XDP_PASS;

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

		/* The old eth header is now 20 bytes into the packet.
		 * We need to copy it to the new position and build
		 * the outer IP header in between.
		 *
		 * Actually, after adjust_head, the layout is:
		 *   [20 bytes new space][old eth header][old IP header][...]
		 *
		 * We want:
		 *   [new eth header][outer IP header][inner IP header][...]
		 *
		 * So we need to:
		 *   1. Read the old eth header (at offset 20)
		 *   2. Write new eth header at offset 0
		 *   3. Write outer IP header at offset 14
		 *   ... but that would overlap with old eth at offset 20.
		 *
		 * Better approach: adjust_head gives us 20 extra bytes at front.
		 * Layout after adjust_head(-20):
		 *   new_data[0..13]  = garbage (new space for eth)
		 *   new_data[14..19] = garbage (new space, part of eth+ip)
		 *   new_data[20..33] = old eth header (14 bytes)
		 *   new_data[34..53] = old IP header (the inner IP)
		 *   new_data[54..]   = old L4 payload
		 *
		 * We want:
		 *   new_data[0..13]  = new eth header
		 *   new_data[14..33] = outer IP header (20 bytes)
		 *   new_data[34..53] = inner IP header (the original)
		 *   new_data[54..]   = L4 payload
		 *
		 * So we copy old eth (at +20) to position 0, then write
		 * outer IP at position 14. The inner IP at 34 is untouched.
		 */

		/* Read old eth header from offset +20 (sizeof(iphdr)) */
		struct ethhdr *old_eth = (struct ethhdr *)((void *)new_eth + sizeof(struct iphdr));
		if ((void *)(old_eth + 1) > data_end)
			return XDP_PASS;

		/* Copy eth type from old header (should be ETH_P_IP) */
		__be16 old_h_proto = old_eth->h_proto;

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
	if (ip_proto != IPPROTO_IPIP)
		return XDP_PASS;

	/* nh.pos now points to the inner IP header.
	 * We need to strip the outer IP header (20 bytes) and reconstruct
	 * an Ethernet header for the inner packet.
	 *
	 * Strategy: use bpf_xdp_adjust_head(+20) to remove outer IP,
	 * then the old Ethernet header is effectively replaced by the
	 * inner IP. We actually need to:
	 *
	 * Current layout:
	 *   [eth 14][outer IP 20][inner IP 20][L4...]
	 *
	 * After adjust_head(+20):
	 *   data starts at what was [outer IP + 6], which is:
	 *   [last 6 bytes of outer IP][inner IP 20][L4...]
	 *   We have 14 bytes of space that we can use as new eth header
	 *   (the head moved forward by 20, but we still have 14 bytes
	 *    before inner IP).
	 *
	 * Actually, the cleanest approach:
	 *   adjust_head(+(outer_ip_hdr_len)) to eat the outer IP header.
	 *   But that leaves [eth header][inner IP][L4...], which is what
	 *   we want! Except the eth header still has old MACs/proto.
	 *
	 * Wait — adjust_head moves data pointer forward. If outer IHL=5:
	 *   Before: data → [eth:14][outerIP:20][innerIP:20][L4]
	 *   adjust_head(+20): data → [eth bytes 20..33 = last 8 of outerIP + ...
	 *
	 * That's wrong. Let me think again.
	 *
	 * Better approach: We know the inner IP starts at nh.pos.
	 * The offset from data to inner IP = 14 (eth) + outer_ihl*4.
	 * We want to strip outer IP but keep ethernet-sized space.
	 *
	 * So: adjust_head by (outer_ihl * 4) bytes forward.
	 * After: data points to (old_data + 20).
	 * Layout: [14 bytes: tail of old eth + start of outer IP][inner IP][L4]
	 * We overwrite those 14 bytes as a new eth header.
	 */

	int outer_hdr_len = outer_iph->ihl * 4;
	if (outer_hdr_len < 20 || outer_hdr_len > 60)
		return XDP_PASS;

	/* Parse inner IP to get dst_ip BEFORE we modify the packet */
	struct iphdr *inner_iph = nh.pos;
	if ((void *)(inner_iph + 1) > data_end)
		return XDP_PASS;

	__u32 inner_dst_ip = inner_iph->daddr;

	/* Look up delivery target for inner dst IP */
	struct delivery_entry *target = bpf_map_lookup_elem(&delivery_map, &inner_dst_ip);
	if (!target)
		return XDP_PASS; /* unknown pod, let kernel handle */

	/* Get local host config for src MAC */
	__u32 zero = 0;
	struct host_info *local = bpf_map_lookup_elem(&host_config, &zero);
	if (!local)
		return XDP_PASS;

	/* Strip outer IP header */
	if (bpf_xdp_adjust_head(ctx, outer_hdr_len))
		return XDP_PASS;

	/* Re-evaluate data pointers */
	data     = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	/* Now data points to where outer IP used to end = inner IP start.
	 * But we need an Ethernet header before the inner IP.
	 * So we adjust back by ETH_HLEN (14 bytes). */
	if (bpf_xdp_adjust_head(ctx, -(int)(sizeof(struct ethhdr))))
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
	if (fix_inner_checksums(data, data_end) < 0)
		return XDP_PASS;

	/* Deliver to local pod via DEVMAP */
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
