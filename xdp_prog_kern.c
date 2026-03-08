/* SPDX-License-Identifier: GPL-2.0 */
/*
 * xdp_prog_kern.c – XDP redirect between two network namespaces.
 *
 * SEC("xdp_redirect_map") – L2 forwarding via DEVMAP.
 *      Rewrites the destination MAC from redirect_params and redirects via
 *      tx_port DEVMAP.  Fully recomputes IP/L4 checksums before forwarding
 *      to handle CHECKSUM_PARTIAL packets from the sender's tx-offload.
 *
 * SEC("xdp_pass") – no-op, attached to namespace-side veth so that
 *      veth_xdp_xmit finds a native XDP program on the peer interface.
 */
#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define IPPROTO_ICMPV6 58
#define ETH_ALEN 6
#include "common/parsing_helpers.h"
#include "common/rewrite_helpers.h"
#include "common/checksum_helpers.h"
#include "common/xdp_stats.h"

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif


/* ── Shared maps ─────────────────────────────────────────────────────────── */

struct {
	__uint(type, BPF_MAP_TYPE_DEVMAP);
	__type(key, int);
	__type(value, int);
	__uint(max_entries, 256);
} tx_port SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key,  int);                      /* ingress ifindex */
	__type(value, unsigned char[ETH_ALEN]); /* destination MAC */
	__uint(max_entries, 128);
} redirect_params SEC(".maps");

/* ── SEC("xdp_redirect_map") ─────────────────────────────────────────────── */
/*
 * Full checksum recompute strategy
 * ---------------------------------
 * Packets arriving at the redirect program may carry CHECKSUM_PARTIAL: the
 * L4 checksum field holds only the pseudo-header sum, awaiting hardware
 * completion.  XDP has no access to skb->ip_summed, so we zero every checksum
 * field and recompute from scratch using csum_loop() + bpf_csum_diff() for
 * the pseudo-header.  This is correct whether the original was partial or
 * already complete.
 *
 * Returns  0  on success (checksums updated, or nothing to update).
 * Returns -1  if the L4 payload exceeds CSUM_MAX_WORDS * 2 bytes; the caller
 *             should XDP_PASS so the kernel stack handles it in software.
 */
static __always_inline int fix_checksums(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
	struct hdr_cursor nh = { .pos = data };
	struct ethhdr *eth;
	int eth_type;

	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type < 0)
		return 0; /* non-IP: nothing to fix */

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

	} else if (eth_type == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6h;
		void  *l4hdr;
		__u32  l4_len;
		int    ip_proto;

		ip_proto = parse_ip6hdr(&nh, data_end, &ip6h);
		if (ip_proto < 0)
			return 0;

		l4_len = bpf_ntohs(ip6h->payload_len);
		l4hdr  = nh.pos;

		if (ip_proto == IPPROTO_TCP) {
			struct tcphdr *tcph;

			if (parse_tcphdr(&nh, data_end, &tcph) < 0)
				return 0;
			if (update_ipv6_l4_checksum(ip6h, &tcph->check,
						    IPPROTO_TCP,
						    l4hdr, l4_len, data_end) < 0)
				return -1;

		} else if (ip_proto == IPPROTO_UDP) {
			struct udphdr *udph;

			if (parse_udphdr(&nh, data_end, &udph) < 0)
				return 0;
			if (update_ipv6_l4_checksum(ip6h, &udph->check,
						    IPPROTO_UDP,
						    l4hdr, l4_len, data_end) < 0)
				return -1;

		} else if (ip_proto == IPPROTO_ICMPV6) {
			struct icmp6hdr *icmp6h;

			if (parse_icmp6hdr(&nh, data_end, &icmp6h) < 0)
				return 0;
			if (update_ipv6_l4_checksum(ip6h, &icmp6h->icmp6_cksum,
						    IPPROTO_ICMPV6,
						    l4hdr, l4_len, data_end) < 0)
				return -1;
		}
	}

	return 0;
}

SEC("xdp_redirect_map")
int xdp_redirect_map_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
	struct hdr_cursor nh = { .pos = data };
	struct ethhdr *eth;
	int eth_type;
	int action    = XDP_PASS;
	int in_ifindex = ctx->ingress_ifindex;
	unsigned char *dst_mac;

	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type == -1)
		goto out;

	dst_mac = bpf_map_lookup_elem(&redirect_params, &in_ifindex);
	if (!dst_mac)
		goto out;

	memcpy(eth->h_dest, dst_mac, ETH_ALEN);

	/* Full recompute: handles CHECKSUM_PARTIAL from sender's offload. */
	if (fix_checksums(ctx) < 0)
		goto out; /* XDP_PASS: kernel completes checksum in software */

	action = bpf_redirect_map(&tx_port, in_ifindex, XDP_PASS);

out:
	return xdp_stats_record_action(ctx, action);
}

SEC("xdp_pass")
int xdp_pass_func(struct xdp_md *ctx)
{
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
