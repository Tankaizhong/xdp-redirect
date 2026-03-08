/* SPDX-License-Identifier: (GPL-2.0-or-later OR BSD-2-clause) */
/*
 * XDP action statistics map and helper.
 *
 * Include this header in exactly one kernel .c file per BPF object.
 * The map is pinned under /sys/fs/bpf/xdp/globals/xdp_stats by bpftool
 * when the object is loaded.
 */

#ifndef __XDP_STATS_H
#define __XDP_STATS_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 5); /* XDP actions: ABORTED=0 DROP=1 PASS=2 TX=3 REDIRECT=4 */
} xdp_stats SEC(".maps");

static __always_inline __u32 xdp_stats_record_action(struct xdp_md *ctx, __u32 action)
{
	__u64 *count = bpf_map_lookup_elem(&xdp_stats, &action);

	if (count)
		*count += 1;

	return action;
}

#endif /* __XDP_STATS_H */
