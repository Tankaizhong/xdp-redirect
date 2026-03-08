/* SPDX-License-Identifier: (GPL-2.0-or-later OR BSD-2-clause) */
/*
 * Checksum computation helpers for XDP programs.
 *
 * Design note – why not bpf_csum_diff() for all cases?
 * -------------------------------------------------------
 * bpf_csum_diff() accepts a PTR_TO_PACKET argument.  The BPF verifier checks
 * helper memory accesses as:
 *
 *   ptr->off + umax(size) <= ptr->range   (where range = r in verifier output)
 *
 * ptr->range is set by the last *constant-offset* bounds check the verifier
 * saw for that register (e.g. "if (iph + 1 > data_end)").  A subsequent
 * variable-offset check such as "if (iph + hdr_len > data_end)" does NOT
 * update the original pointer's range.  Therefore bpf_csum_diff(iph, hdr_len)
 * fails when umax(hdr_len) > (r - off).
 *
 * Fixes applied:
 *  - IPv4 header checksum: use sizeof(struct iphdr) = 20 (compile-time
 *    constant) after confirming ihl == 5.  This keeps r == off + 20 and the
 *    size argument == 20, so the verifier accepts it.
 *  - L4 / ICMP data checksum: replaced bpf_csum_diff() over packet data with
 *    csum_loop(), a simple word loop whose per-iteration "ptr+1 > data_end"
 *    check satisfies the verifier at every step.
 *  - Pseudo-header checksum: bpf_csum_diff() over a *stack* struct is always
 *    fine – no packet-pointer range restriction applies.
 */

#ifndef __CHECKSUM_HELPERS_H
#define __CHECKSUM_HELPERS_H

#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/*
 * Maximum number of 16-bit words handled by csum_loop().
 * 750 words = 1500 bytes, covering a full Ethernet MTU payload.
 * Packets with L4 length > 2 * CSUM_MAX_WORDS are passed to the kernel
 * stack via XDP_PASS so it can finish the checksum in software.
 */
#define CSUM_MAX_WORDS 750

/* Fold a 64-bit running sum into a 16-bit one's complement checksum. */
static __always_inline __u16 csum_fold_helper(__u64 csum)
{
	csum = (csum & 0xffff) + (csum >> 16);
	csum = (csum & 0xffff) + (csum >> 16);
	return ~(__u16)csum;
}

/*
 * csum_loop - compute a running internet checksum over packet data.
 *
 * Iterates word-by-word (2 bytes at a time) up to CSUM_MAX_WORDS iterations.
 * Each iteration performs its own "ptr + 1 > data_end" check so the BPF
 * verifier sees a valid bounded packet access per word.
 *
 * Returns an unfolded 64-bit sum; call csum_fold_helper() on the total when
 * all contributions (pseudo-header + L4 data) have been accumulated.
 */
static __always_inline __u64 csum_loop(void *data, __u32 len, void *data_end)
{
	__u16 *p = (__u16 *)data;
	__u64 sum = 0;
	int i;

	for (i = 0; i < CSUM_MAX_WORDS; i++) {
		/* Stop when we've covered len bytes or hit the packet end. */
		if ((__u32)(i * 2) >= len || (void *)(p + 1) > data_end)
			break;
		sum += *p;
		p++;
	}

	/* Odd trailing byte: place in the high byte, per RFC 1071. */
	if (len & 1) {
		__u8 *b = (__u8 *)data + (len - 1);

		if ((void *)(b + 1) <= data_end)
			sum += (__u64)*b << 8;
	}

	return sum;
}

/*
 * update_iph_checksum - recompute the IPv4 header checksum in-place.
 *
 * Only handles standard headers (IHL = 5, 20 bytes).  Headers with IP
 * options are left untouched (return 0) – they are vanishingly rare in
 * veth / container traffic and the kernel will handle them via XDP_PASS.
 *
 * Using sizeof(struct iphdr) = 20 (compile-time constant) as the size
 * argument to bpf_csum_diff() keeps the access within the verifier's
 * already-established range of 20 bytes from iph.
 *
 * Returns 0 on success, -1 if the bounds check fails.
 */
static __always_inline int update_iph_checksum(struct iphdr *iph,
					       void *data_end)
{
	__u64 csum;

	if (iph->ihl != 5)
		return 0; /* options not supported; pass without modification */

	if ((void *)(iph + 1) > data_end)
		return -1;

	iph->check = 0;
	/* sizeof(struct iphdr) == 20 is a compile-time constant; the verifier
	 * accepts it because the "iph + 1 > data_end" check above already
	 * proved exactly 20 bytes are accessible. */
	csum = bpf_csum_diff(0, 0, (__be32 *)iph, sizeof(struct iphdr), 0);
	iph->check = csum_fold_helper(csum);
	return 0;
}

/* IPv4 pseudo-header for TCP/UDP checksum. */
struct ipv4_ph {
	__be32 src;
	__be32 dst;
	__u8   zero;
	__u8   proto;
	__be16 len;
};

/*
 * update_ipv4_l4_checksum - recompute an IPv4 TCP or UDP checksum in-place.
 *
 *   iph        - IPv4 header
 *   csum_field - &tcph->check or &udph->check
 *   l4hdr      - start of the L4 header (= start of TCP/UDP header)
 *   l4_len     - total L4 bytes: IP total_len − IP header_len
 *   data_end   - ctx->data_end
 *
 * The pseudo-header sum is computed via bpf_csum_diff() on a stack struct
 * (no packet-pointer range restriction).  The L4 header + payload sum uses
 * csum_loop() which does per-word bounds checks acceptable to the verifier.
 *
 * Returns 0 on success, -1 if the packet is too large or out-of-bounds.
 */
static __always_inline int update_ipv4_l4_checksum(struct iphdr *iph,
						   __sum16 *csum_field,
						   void *l4hdr,
						   __u16 l4_len,
						   void *data_end)
{
	struct ipv4_ph pseudo = {};
	__u64 csum;

	if (l4_len > CSUM_MAX_WORDS * 2)
		return -1; /* too large; caller should XDP_PASS */
	if ((void *)l4hdr + l4_len > data_end)
		return -1;

	pseudo.src   = iph->saddr;
	pseudo.dst   = iph->daddr;
	pseudo.zero  = 0;
	pseudo.proto = iph->protocol;
	pseudo.len   = bpf_htons(l4_len);

	*csum_field = 0;
	/* Pseudo-header is on the stack – bpf_csum_diff() is safe here. */
	csum  = bpf_csum_diff(0, 0, (__be32 *)&pseudo, sizeof(pseudo), 0);
	/* L4 header + payload via loop (avoids variable-size packet access). */
	csum += csum_loop(l4hdr, l4_len, data_end);
	*csum_field = csum_fold_helper(csum);
	return 0;
}

/* IPv6 pseudo-header for TCP/UDP/ICMPv6 checksum. */
struct ipv6_ph {
	struct in6_addr src;
	struct in6_addr dst;
	__be32          len;
	__u8            zeros[3];
	__u8            next_hdr;
};

/*
 * update_ipv6_l4_checksum - recompute an IPv6 TCP, UDP, or ICMPv6 checksum.
 *
 *   ip6h       - IPv6 header
 *   csum_field - checksum field inside the L4 header
 *   proto      - IPPROTO_TCP / IPPROTO_UDP / IPPROTO_ICMPV6
 *   l4hdr      - start of the L4 header
 *   l4_len     - ip6h->payload_len (no extension headers assumed)
 *   data_end   - ctx->data_end
 *
 * Returns 0 on success, -1 on failure.
 */
static __always_inline int update_ipv6_l4_checksum(struct ipv6hdr *ip6h,
						   __sum16 *csum_field,
						   __u8 proto,
						   void *l4hdr,
						   __u32 l4_len,
						   void *data_end)
{
	struct ipv6_ph pseudo = {};
	__u64 csum;

	if (l4_len > CSUM_MAX_WORDS * 2)
		return -1;
	if ((void *)l4hdr + l4_len > data_end)
		return -1;

	pseudo.src      = ip6h->saddr;
	pseudo.dst      = ip6h->daddr;
	pseudo.len      = bpf_htonl(l4_len);
	pseudo.next_hdr = proto;
	/* pseudo.zeros zero-initialised by {} */

	*csum_field = 0;
	csum  = bpf_csum_diff(0, 0, (__be32 *)&pseudo, sizeof(pseudo), 0);
	csum += csum_loop(l4hdr, l4_len, data_end);
	*csum_field = csum_fold_helper(csum);
	return 0;
}

/*
 * update_icmp_checksum - recompute an ICMPv4 checksum in-place.
 *
 * ICMPv4 uses no pseudo-header; the checksum covers the entire ICMP message
 * (header + data).
 *
 * Returns 0 on success, -1 on failure.
 */
static __always_inline int update_icmp_checksum(struct icmphdr *icmph,
						__u16 icmp_len,
						void *data_end)
{
	__u64 csum;

	if (icmp_len > CSUM_MAX_WORDS * 2)
		return -1;
	if ((void *)icmph + icmp_len > data_end)
		return -1;

	icmph->checksum = 0;
	csum = csum_loop(icmph, icmp_len, data_end);
	icmph->checksum = csum_fold_helper(csum);
	return 0;
}

/*
 * icmp_checksum_diff - incremental ICMP/ICMPv6 checksum update.
 *
 * Used when only the type byte of an ICMP header changes (e.g. ECHO →
 * ECHOREPLY).  Computes the difference between the old and new 4-byte
 * icmphdr_common regions and folds it into the existing checksum.
 *
 *   seed         - one's complement of the original checksum (~old_csum)
 *   icmphdr_new  - pointer to the (already-modified) header in the packet
 *   icmphdr_old  - stack copy of the header taken before modification
 *
 * Both structs are exactly sizeof(struct icmphdr_common) = 4 bytes, which
 * is a multiple of 4 as required by bpf_csum_diff().  icmphdr_old is on
 * the stack so there is no packet-pointer range restriction; icmphdr_new is
 * a packet pointer whose 4-byte range was established by parse_icmphdr_common.
 */
static __always_inline __u16 icmp_checksum_diff(
		__u16 seed,
		struct icmphdr_common *icmphdr_new,
		struct icmphdr_common *icmphdr_old)
{
	__u32 size = sizeof(struct icmphdr_common);
	__u64 csum;

	csum = bpf_csum_diff((__be32 *)icmphdr_old, size,
			     (__be32 *)icmphdr_new, size, seed);
	return csum_fold_helper(csum);
}

#endif /* __CHECKSUM_HELPERS_H */
