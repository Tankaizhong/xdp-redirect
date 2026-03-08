/* SPDX-License-Identifier: GPL-2.0 */
/*
 * xdp_prog_kern.c
 *
 * Two independent XDP program sections:
 *
 *  SEC("xdp_icmp_echo")   – packet inspection / ICMP echo reply
 *      Parses Ethernet + IP/IPv6 + ICMP headers, swaps addresses, and
 *      returns the packet with XDP_TX.  Uses an *incremental* checksum
 *      update (bpf_csum_diff over the changed 4-byte icmphdr_common) so
 *      only the delta from ECHO→ECHOREPLY is recomputed—no full scan of
 *      the payload is needed.
 *
 *  SEC("xdp_redirect_map") – L2 forwarding / redirect
 *      Rewrites the destination MAC from the redirect_params map and
 *      redirects via the tx_port DEVMAP.  Uses a *full* checksum
 *      recompute (csum_loop over the entire L4 payload) because the
 *      ingress packet may carry a CHECKSUM_PARTIAL value from the
 *      sender's checksum-offload engine, and XDP has no access to
 *      skb->ip_summed to detect this.
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

/* ── SEC("xdp_icmp_echo") ────────────────────────────────────────────────── */
/*
 * Incremental ICMP checksum update strategy
 * -----------------------------------------
 * When only the `type` byte changes (ECHO_REQUEST → ECHO_REPLY), recomputing
 * the full checksum wastes cycles scanning the entire payload.  Instead we use
 * the RFC 1624 incremental formula via bpf_csum_diff():
 *
 *   new_csum = fold( bpf_csum_diff(old_region, new_region, ~old_csum) )
 *
 * Steps:
 *  1. Save original checksum  (old_csum = icmphdr->cksum).
 *  2. Zero the checksum field so the saved stack copy reflects the "all-zero"
 *     state that was used when the sender computed the original checksum.
 *     (The checksum field is excluded from the checksum computation.)
 *  3. Copy the header to a stack buffer (icmphdr_old).
 *  4. Write the new type byte into the packet.
 *  5. Call icmp_checksum_diff(~old_csum, icmphdr_new, &icmphdr_old).
 *     bpf_csum_diff() returns:  seed + sum(new) - sum(old)  (ones-complement).
 *     With seed = ~old_csum this expands to the correct new checksum after
 *     csum_fold_helper() folds it to 16 bits and inverts.
 *
 * icmphdr_old is a stack object, so bpf_csum_diff() has no packet-range
 * restriction on it.  icmphdr_new is a packet pointer whose 4-byte range was
 * established by parse_icmphdr_common(); sizeof(struct icmphdr_common) == 4
 * satisfies the multiple-of-4 requirement of bpf_csum_diff().
 */
SEC("xdp_icmp_echo")
int xdp_icmp_echo_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
	struct hdr_cursor nh = { .pos = data };
	struct ethhdr *eth;
	int eth_type, ip_type, icmp_type;
	struct iphdr   *iphdr;
	struct ipv6hdr *ipv6hdr;
	struct icmphdr_common *icmphdr;
	struct icmphdr_common  icmphdr_old;
	__u16 echo_reply, old_csum;
	__u32 action = XDP_PASS;

	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type == bpf_htons(ETH_P_IP)) {
		ip_type = parse_iphdr(&nh, data_end, &iphdr);
		if (ip_type != IPPROTO_ICMP)
			goto out;
		swap_src_dst_ipv4(iphdr);
		echo_reply = ICMP_ECHOREPLY;
	} else if (eth_type == bpf_htons(ETH_P_IPV6)) {
		ip_type = parse_ip6hdr(&nh, data_end, &ipv6hdr);
		if (ip_type != IPPROTO_ICMPV6)
			goto out;
		swap_src_dst_ipv6(ipv6hdr);
		echo_reply = ICMPV6_ECHO_REPLY;
	} else {
		goto out;
	}

	icmp_type = parse_icmphdr_common(&nh, data_end, &icmphdr);
	if (eth_type == bpf_htons(ETH_P_IP)   && icmp_type != ICMP_ECHO)
		goto out;
	if (eth_type == bpf_htons(ETH_P_IPV6) && icmp_type != ICMPV6_ECHO_REQUEST)
		goto out;

	swap_src_dst_mac(eth);

	/*
	 * Incremental checksum update:
	 *   seed = ~old_csum  (one's complement of the original checksum)
	 *   bpf_csum_diff computes: seed + sum(new_region) - sum(old_region)
	 *   csum_fold_helper folds 64-bit result → 16-bit and inverts.
	 */
	old_csum      = icmphdr->cksum;
	icmphdr->cksum = 0;
	icmphdr_old   = *icmphdr;        /* stack copy before modification */
	icmphdr->type = echo_reply;
	icmphdr->cksum = icmp_checksum_diff(~old_csum, icmphdr, &icmphdr_old);

	action = XDP_TX;
out:
	return xdp_stats_record_action(ctx, action);
}

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
