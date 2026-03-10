/* SPDX-License-Identifier: (GPL-2.0-or-later OR BSD-2-clause) */
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

#define CSUM_MAX_WORDS 750

static __always_inline __u16 csum_fold_helper(__u64 csum)
{
	csum = (csum & 0xffff) + (csum >> 16);
	csum = (csum & 0xffff) + (csum >> 16);
	return ~(__u16)csum;
}

static __always_inline __u64 csum_loop(void *data, __u32 len, void *data_end)
{
	__u16 *p = (__u16 *)data;
	__u64 sum = 0;
	int i;

	for (i = 0; i < CSUM_MAX_WORDS; i++) {
		if ((__u32)(i * 2) >= len || (void *)(p + 1) > data_end)
			break;
		sum += *p;
		p++;
	}

	if (len & 1) {
		__u8 *b = (__u8 *)data + (len - 1);
		if ((void *)(b + 1) <= data_end)
			sum += (__u64)*b << 8;
	}

	return sum;
}

static __always_inline int update_iph_checksum(struct iphdr *iph,
					       void *data_end)
{
	__u64 csum;

	if (iph->ihl != 5)
		return 0;

	if ((void *)(iph + 1) > data_end)
		return -1;

	iph->check = 0;
	csum = bpf_csum_diff(0, 0, (__be32 *)iph, sizeof(struct iphdr), 0);
	iph->check = csum_fold_helper(csum);
	return 0;
}

struct ipv4_ph {
	__be32 src;
	__be32 dst;
	__u8   zero;
	__u8   proto;
	__be16 len;
};

static __always_inline int update_ipv4_l4_checksum(struct iphdr *iph,
						   __sum16 *csum_field,
						   void *l4hdr,
						   __u16 l4_len,
						   void *data_end)
{
	struct ipv4_ph pseudo = {};
	__u64 csum;

	if (l4_len > CSUM_MAX_WORDS * 2)
		return -1;
	if ((void *)l4hdr + l4_len > data_end)
		return -1;

	pseudo.src   = iph->saddr;
	pseudo.dst   = iph->daddr;
	pseudo.zero  = 0;
	pseudo.proto = iph->protocol;
	pseudo.len   = bpf_htons(l4_len);

	*csum_field = 0;
	csum  = bpf_csum_diff(0, 0, (__be32 *)&pseudo, sizeof(pseudo), 0);
	csum += csum_loop(l4hdr, l4_len, data_end);
	*csum_field = csum_fold_helper(csum);
	return 0;
}

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
 * compute_iph_csum - compute IPv4 header checksum for a freshly built header.
 * The header must be on the stack (not packet pointer) or already bounds-checked.
 */
static __always_inline __u16 compute_iph_csum(struct iphdr *iph)
{
	__u16 *p = (__u16 *)iph;
	__u32 sum = 0;

	/* Standard 20-byte IPv4 header = 10 x 16-bit words */
	#pragma unroll
	for (int i = 0; i < 10; i++)
		sum += p[i];

	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	return ~(__u16)sum;
}

#endif /* __CHECKSUM_HELPERS_H */
