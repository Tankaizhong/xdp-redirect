/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define IPPROTO_ICMPV6 58
#define ETH_ALEN 6
#include "common/parsing_helpers.h"
#include "common/rewrite_helpers.h"

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

/* Forward declaration */
static __always_inline __u32 xdp_stats_record_action(struct xdp_md *ctx, __u32 action);

struct {
	__uint(type, BPF_MAP_TYPE_DEVMAP);
	__type(key, int);
	__type(value, int);
	__uint(max_entries, 256);
} tx_port SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key,  int);              /* ingress ifindex */
	__type(value, unsigned char[ETH_ALEN]); /* destination MAC */
	__uint(max_entries, 128);
} redirect_params SEC(".maps");

SEC("xdp_redirect_map")
int xdp_redirect_map_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh;
	struct ethhdr *eth;
	int eth_type;
	int action = XDP_PASS;
	int in_ifindex = ctx->ingress_ifindex;
	unsigned char *dst_mac;

	nh.pos = data;

	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type == -1)
		goto out;

	/* Look up destination MAC based on ingress ifindex */
	dst_mac = bpf_map_lookup_elem(&redirect_params, &in_ifindex);
	if (!dst_mac)
		goto out;

	/* Set the destination MAC address */
	memcpy(eth->h_dest, dst_mac, ETH_ALEN);

	/* Use bpf_redirect_map with DEVMAP for proper native XDP redirect */
	action = bpf_redirect_map(&tx_port, in_ifindex, XDP_PASS);

out:
	return xdp_stats_record_action(ctx, action);
}

SEC("xdp_pass")
int xdp_pass_func(struct xdp_md *ctx)
{
	return XDP_PASS;
}

/* Statistics for XDP actions */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 64);
} xdp_stats SEC(".maps");

static __always_inline __u32 xdp_stats_record_action(struct xdp_md *ctx, __u32 action)
{
	__u32 key = action;
	__u64 *count;

	count = bpf_map_lookup_elem(&xdp_stats, &key);
	if (count)
		*count += 1;

	return action;
}

char _license[] SEC("license") = "GPL";
