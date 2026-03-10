/* SPDX-License-Identifier: GPL-2.0 */
/*
 * xdp_maps.h – eBPF map definitions for XDP IPIP overlay routing.
 *
 * Two maps implement a minimal container networking data plane:
 *
 *   routing_map    – global route table: pod_ip → (host_ip, host_mac)
 *                    Used by the egress XDP (on pod-facing veth) to decide:
 *                      • local pod  → redirect directly via delivery_map
 *                      • remote pod → encapsulate in IPIP, send via eth
 *
 *   delivery_map   – local delivery table: pod_ip → (ifindex, pod_mac)
 *                    Used on both paths:
 *                      • local redirect: look up target veth ifindex + MAC
 *                      • IPIP decap (on eth-facing XDP): after stripping
 *                        outer IP, look up inner dst_ip to find local pod
 */

#ifndef __XDP_MAPS_H
#define __XDP_MAPS_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define ETH_ALEN 6

/* ── routing_map: pod_ip → remote host info ──────────────────────────────── */

struct route_entry {
	__u32         host_ip;            /* 目标容器所在宿主机 IP */
	unsigned char host_mac[ETH_ALEN]; /* 目标宿主机物理 MAC */
	__u16         _pad;               /* 对齐到 4 字节 */
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key,   __u32);              /* pod IP (network byte order) */
	__type(value, struct route_entry);
	__uint(max_entries, 1024);
} routing_map SEC(".maps");

/* ── delivery_map: pod_ip → local veth info ─────────────────────────────── */

struct delivery_entry {
	__u32         ifindex;             /* 本地容器 veth 在宿主 NS 中的 ifindex */
	unsigned char pod_mac[ETH_ALEN];   /* 容器 MAC 地址 */
	__u16         _pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key,   __u32);              /* pod IP (network byte order) */
	__type(value, struct delivery_entry);
	__uint(max_entries, 1024);
} delivery_map SEC(".maps");

/* ── host_info: index 0 = this host's IP, index 1 = eth ifindex ─────────── */
/*
 * We store the local host's own IP and eth ifindex so the XDP program
 * can build the outer IPIP header and know which interface to redirect
 * IPIP-encapsulated packets to.
 */

struct host_info {
	__u32         host_ip;         /* 本机宿主 IP (network byte order) */
	__u32         eth_ifindex;     /* 本机 eth 接口 ifindex */
	unsigned char eth_mac[ETH_ALEN]; /* 本机 eth MAC */
	__u16         _pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key,   __u32);
	__type(value, struct host_info);
	__uint(max_entries, 1);
} host_config SEC(".maps");

/* ── tx_ports: DEVMAP for bpf_redirect_map ──────────────────────────────── */
/*
 * All redirect targets (pod veth ifindex + eth ifindex) must be in a DEVMAP
 * for bpf_redirect_map() to work with veth's ndo_xdp_xmit.
 *
 * Key = ifindex, Value = ifindex (identity map, just registers the device).
 */
struct {
	__uint(type, BPF_MAP_TYPE_DEVMAP);
	__type(key,   int);
	__type(value, int);
	__uint(max_entries, 256);
} tx_ports SEC(".maps");

#endif /* __XDP_MAPS_H */
