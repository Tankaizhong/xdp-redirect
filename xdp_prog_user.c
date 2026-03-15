/* SPDX-License-Identifier: GPL-2.0 */
/*
 * xdp_prog_user.c – libbpf-based map management tool (no bpftool required).
 *
 * Subcommands:
 *   load    <obj_file>                          – load BPF obj, pin maps+progs
 *   route   add <pod_ip> <host_ip> <host_mac>  – add routing_map entry
 *   deliver add <pod_ip> <ifname> <pod_mac>    – add delivery_map entry
 *   host    set <host_ip> <eth_ifname> <eth_mac> – set host_config[0]
 *   host    get                                 – print host_ip and eth_mac
 *   txport  add <ifname|ifindex>               – register ifindex in tx_ports
 *   dump                                        – dump all maps
 *
 * All map operations use pinned paths under /sys/fs/bpf/xdp_ipip/
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <net/if.h>
#include <arpa/inet.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define ETH_ALEN  6
/* All pins live flat under /sys/fs/bpf/, prefixed with xdp_ipip_ */
#define PIN_PFX   "/sys/fs/bpf/xdp_ipip_"
#define PIN_BASE  "/sys/fs/bpf"

/* ── structs matching common/xdp_maps.h ─────────────────────────────────── */

struct route_entry {
	__u32         host_ip;
	unsigned char host_mac[ETH_ALEN];
	__u16         _pad;
};

struct delivery_entry {
	__u32         ifindex;
	unsigned char pod_mac[ETH_ALEN];
	__u16         _pad;
};

struct host_info {
	__u32         host_ip;
	__u32         eth_ifindex;
	unsigned char eth_mac[ETH_ALEN];
	__u16         _pad;
};

/* ── helpers ─────────────────────────────────────────────────────────────── */

static int parse_mac(const char *str, unsigned char *mac)
{
	int v[ETH_ALEN];
	if (sscanf(str, "%x:%x:%x:%x:%x:%x",
		   &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) != ETH_ALEN)
		return -1;
	for (int i = 0; i < ETH_ALEN; i++)
		mac[i] = (unsigned char)v[i];
	return 0;
}

static int open_map(const char *name)
{
	char path[256];
	snprintf(path, sizeof(path), PIN_PFX "%s", name);
	int fd = bpf_obj_get(path);
	if (fd < 0)
		fprintf(stderr, "bpf_obj_get(%s): %s\n", path, strerror(errno));
	return fd;
}

static int get_ifindex(const char *s)
{
	int idx = if_nametoindex(s);
	if (idx == 0)
		idx = atoi(s);
	if (idx <= 0) {
		fprintf(stderr, "Invalid interface: %s\n", s);
		return -1;
	}
	return idx;
}

/* ── load <obj_file> ─────────────────────────────────────────────────────── */

static int cmd_load(const char *obj_file)
{
	/* Idempotent: skip if already fully pinned */
	if (access(PIN_PFX "routing_map", F_OK) == 0 &&
	    access(PIN_PFX "eth_ingress_prog", F_OK) == 0) {
		printf("already pinned, skipping load\n");
		return 0;
	}

	struct bpf_object *obj = bpf_object__open_file(obj_file, NULL);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "bpf_object__open_file(%s): %s\n",
			obj_file, strerror(errno));
		return 1;
	}

	/* Force XDP type for all programs (section names are non-standard) */
	struct bpf_program *prog;
	bpf_object__for_each_program(prog, obj)
		bpf_program__set_type(prog, BPF_PROG_TYPE_XDP);

	if (bpf_object__load(obj)) {
		fprintf(stderr, "bpf_object__load: %s\n", strerror(errno));
		bpf_object__close(obj);
		return 1;
	}

	/* Pin each map individually to flat path PIN_PFX<map_name> */
	static const char *map_names[] = {
		"routing_map", "delivery_map", "host_config", "tx_ports",
	};
	for (int i = 0; i < 4; i++) {
		struct bpf_map *map =
			bpf_object__find_map_by_name(obj, map_names[i]);
		if (!map) {
			fprintf(stderr, "map %s not found\n", map_names[i]);
			bpf_object__close(obj);
			return 1;
		}
		char pin_path[256];
		snprintf(pin_path, sizeof(pin_path), PIN_PFX "%s", map_names[i]);
		/* Remove stale pin if present from a previous failed run */
		unlink(pin_path);
		if (bpf_map__pin(map, pin_path)) {
			fprintf(stderr, "bpf_map__pin(%s): %s\n",
				pin_path, strerror(errno));
			bpf_object__close(obj);
			return 1;
		}
		printf("pinned map: %s\n", pin_path);
	}

	/* Pin programs to flat path PIN_PFX<prog_pin_name> */
	static const struct { const char *func; const char *pin; } progs[] = {
		{ "xdp_pod_egress_func",  "pod_egress_prog"  },
		{ "xdp_eth_ingress_func", "eth_ingress_prog" },
		{ "xdp_pass_func",        "pass_prog"        },
	};
	for (int i = 0; i < 3; i++) {
		prog = bpf_object__find_program_by_name(obj, progs[i].func);
		if (!prog) {
			fprintf(stderr, "program %s not found\n", progs[i].func);
			bpf_object__close(obj);
			return 1;
		}
		char pin_path[256];
		snprintf(pin_path, sizeof(pin_path), PIN_PFX "%s", progs[i].pin);
		unlink(pin_path);
		if (bpf_program__pin(prog, pin_path)) {
			fprintf(stderr, "bpf_program__pin(%s): %s\n",
				pin_path, strerror(errno));
			bpf_object__close(obj);
			return 1;
		}
		printf("pinned prog: %s → %s\n", progs[i].func, pin_path);
	}

	bpf_object__close(obj);
	return 0;
}

/* ── route add <pod_ip> <host_ip> <host_mac> ─────────────────────────────── */

static int cmd_route_add(int argc, char **argv)
{
	if (argc < 3) {
		fprintf(stderr, "Usage: route add <pod_ip> <host_ip> <host_mac>\n");
		return 1;
	}

	struct in_addr pod_addr, host_addr;
	struct route_entry val = {};

	if (inet_pton(AF_INET, argv[0], &pod_addr) != 1) {
		fprintf(stderr, "Invalid pod IP: %s\n", argv[0]); return 1;
	}
	if (inet_pton(AF_INET, argv[1], &host_addr) != 1) {
		fprintf(stderr, "Invalid host IP: %s\n", argv[1]); return 1;
	}
	if (parse_mac(argv[2], val.host_mac) < 0) {
		fprintf(stderr, "Invalid MAC: %s\n", argv[2]); return 1;
	}
	val.host_ip = host_addr.s_addr;

	int fd = open_map("routing_map");
	if (fd < 0) return 1;

	int ret = bpf_map_update_elem(fd, &pod_addr.s_addr, &val, BPF_ANY);
	if (ret)
		fprintf(stderr, "map update: %s\n", strerror(errno));
	else
		printf("routing_map: %s → host=%s mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
		       argv[0], argv[1],
		       val.host_mac[0], val.host_mac[1], val.host_mac[2],
		       val.host_mac[3], val.host_mac[4], val.host_mac[5]);
	close(fd);
	return ret ? 1 : 0;
}

/* ── deliver add <pod_ip> <ifname> <pod_mac> ─────────────────────────────── */

static int cmd_deliver_add(int argc, char **argv)
{
	if (argc < 3) {
		fprintf(stderr,
			"Usage: deliver add <pod_ip> <ifname|ifindex> <pod_mac>\n");
		return 1;
	}

	struct in_addr pod_addr;
	struct delivery_entry val = {};

	if (inet_pton(AF_INET, argv[0], &pod_addr) != 1) {
		fprintf(stderr, "Invalid pod IP: %s\n", argv[0]); return 1;
	}
	val.ifindex = get_ifindex(argv[1]);
	if ((int)val.ifindex < 0) return 1;
	if (parse_mac(argv[2], val.pod_mac) < 0) {
		fprintf(stderr, "Invalid MAC: %s\n", argv[2]); return 1;
	}

	int fd = open_map("delivery_map");
	if (fd < 0) return 1;

	int ret = bpf_map_update_elem(fd, &pod_addr.s_addr, &val, BPF_ANY);
	if (ret)
		fprintf(stderr, "map update: %s\n", strerror(errno));
	else
		printf("delivery_map: %s → ifindex=%d mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
		       argv[0], val.ifindex,
		       val.pod_mac[0], val.pod_mac[1], val.pod_mac[2],
		       val.pod_mac[3], val.pod_mac[4], val.pod_mac[5]);
	close(fd);
	return ret ? 1 : 0;
}

/* ── host set <host_ip> <eth_ifname> <eth_mac> ───────────────────────────── */

static int cmd_host_set(int argc, char **argv)
{
	if (argc < 3) {
		fprintf(stderr,
			"Usage: host set <host_ip> <eth_ifname|ifindex> <eth_mac>\n");
		return 1;
	}

	struct in_addr host_addr;
	struct host_info val = {};

	if (inet_pton(AF_INET, argv[0], &host_addr) != 1) {
		fprintf(stderr, "Invalid host IP: %s\n", argv[0]); return 1;
	}
	val.host_ip = host_addr.s_addr;
	val.eth_ifindex = get_ifindex(argv[1]);
	if ((int)val.eth_ifindex < 0) return 1;
	if (parse_mac(argv[2], val.eth_mac) < 0) {
		fprintf(stderr, "Invalid MAC: %s\n", argv[2]); return 1;
	}

	int fd = open_map("host_config");
	if (fd < 0) return 1;

	__u32 key = 0;
	int ret = bpf_map_update_elem(fd, &key, &val, BPF_ANY);
	if (ret)
		fprintf(stderr, "map update: %s\n", strerror(errno));
	else
		printf("host_config[0]: ip=%s eth_ifindex=%d mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
		       argv[0], val.eth_ifindex,
		       val.eth_mac[0], val.eth_mac[1], val.eth_mac[2],
		       val.eth_mac[3], val.eth_mac[4], val.eth_mac[5]);
	close(fd);
	return ret ? 1 : 0;
}

/* ── host get ────────────────────────────────────────────────────────────── */

static int cmd_host_get(void)
{
	int fd = open_map("host_config");
	if (fd < 0) return 1;

	__u32 key = 0;
	struct host_info val = {};
	int ret = bpf_map_lookup_elem(fd, &key, &val);
	if (ret) {
		fprintf(stderr, "map lookup: %s\n", strerror(errno));
		close(fd);
		return 1;
	}

	struct in_addr addr = { .s_addr = val.host_ip };
	printf("%s %02x:%02x:%02x:%02x:%02x:%02x\n",
	       inet_ntoa(addr),
	       val.eth_mac[0], val.eth_mac[1], val.eth_mac[2],
	       val.eth_mac[3], val.eth_mac[4], val.eth_mac[5]);
	close(fd);
	return 0;
}

/* ── txport add <ifname|ifindex> ─────────────────────────────────────────── */

static int cmd_txport_add(int argc, char **argv)
{
	if (argc < 1) {
		fprintf(stderr, "Usage: txport add <ifname|ifindex>\n");
		return 1;
	}

	int ifindex = get_ifindex(argv[0]);
	if (ifindex < 0) return 1;

	int fd = open_map("tx_ports");
	if (fd < 0) return 1;

	int ret = bpf_map_update_elem(fd, &ifindex, &ifindex, BPF_ANY);
	if (ret)
		fprintf(stderr, "map update: %s\n", strerror(errno));
	else
		printf("tx_ports: ifindex=%d → ifindex=%d\n", ifindex, ifindex);
	close(fd);
	return ret ? 1 : 0;
}

/* ── dump ─────────────────────────────────────────────────────────────────── */

static void dump_routing_map(void)
{
	int fd = open_map("routing_map");
	if (fd < 0) return;

	printf("\n=== routing_map ===\n");
	__u32 key = 0, next;
	struct route_entry val;
	int first = 1;

	while (bpf_map_get_next_key(fd, first ? NULL : &key, &next) == 0) {
		key = next; first = 0;
		if (bpf_map_lookup_elem(fd, &key, &val) == 0) {
			struct in_addr pod  = { .s_addr = key };
			struct in_addr host = { .s_addr = val.host_ip };
			char pod_s[INET_ADDRSTRLEN], host_s[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, &pod,  pod_s,  sizeof(pod_s));
			inet_ntop(AF_INET, &host, host_s, sizeof(host_s));
			printf("  pod=%-16s host=%-16s mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
			       pod_s, host_s,
			       val.host_mac[0], val.host_mac[1], val.host_mac[2],
			       val.host_mac[3], val.host_mac[4], val.host_mac[5]);
		}
	}
	if (first) printf("  (empty)\n");
	close(fd);
}

static void dump_delivery_map(void)
{
	int fd = open_map("delivery_map");
	if (fd < 0) return;

	printf("\n=== delivery_map ===\n");
	__u32 key = 0, next;
	struct delivery_entry val;
	int first = 1;

	while (bpf_map_get_next_key(fd, first ? NULL : &key, &next) == 0) {
		key = next; first = 0;
		if (bpf_map_lookup_elem(fd, &key, &val) == 0) {
			struct in_addr pod = { .s_addr = key };
			char pod_s[INET_ADDRSTRLEN];
			char ifname[IF_NAMESIZE] = {};
			inet_ntop(AF_INET, &pod, pod_s, sizeof(pod_s));
			if_indextoname(val.ifindex, ifname);
			printf("  pod=%-16s ifindex=%-4d(%-12s) mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
			       pod_s, val.ifindex, ifname,
			       val.pod_mac[0], val.pod_mac[1], val.pod_mac[2],
			       val.pod_mac[3], val.pod_mac[4], val.pod_mac[5]);
		}
	}
	if (first) printf("  (empty)\n");
	close(fd);
}

static void dump_host_config(void)
{
	int fd = open_map("host_config");
	if (fd < 0) return;

	printf("\n=== host_config ===\n");
	__u32 key = 0;
	struct host_info val = {};
	if (bpf_map_lookup_elem(fd, &key, &val) == 0) {
		struct in_addr addr = { .s_addr = val.host_ip };
		char ip_s[INET_ADDRSTRLEN];
		char ifname[IF_NAMESIZE] = {};
		inet_ntop(AF_INET, &addr, ip_s, sizeof(ip_s));
		if_indextoname(val.eth_ifindex, ifname);
		printf("  host_ip=%-16s eth=%d(%s) mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
		       ip_s, val.eth_ifindex, ifname,
		       val.eth_mac[0], val.eth_mac[1], val.eth_mac[2],
		       val.eth_mac[3], val.eth_mac[4], val.eth_mac[5]);
	}
	close(fd);
}

static void dump_tx_ports(void)
{
	int fd = open_map("tx_ports");
	if (fd < 0) return;

	printf("\n=== tx_ports ===\n");
	int key = 0, next, val;
	int first = 1;

	while (bpf_map_get_next_key(fd, first ? NULL : &key, &next) == 0) {
		key = next; first = 0;
		if (bpf_map_lookup_elem(fd, &key, &val) == 0) {
			char ifname[IF_NAMESIZE] = {};
			if_indextoname(val, ifname);
			printf("  ifindex=%d (%s)\n", val, ifname);
		}
	}
	if (first) printf("  (empty)\n");
	close(fd);
}

static int cmd_dump(void)
{
	dump_routing_map();
	dump_delivery_map();
	dump_host_config();
	dump_tx_ports();
	return 0;
}

/* ── main ─────────────────────────────────────────────────────────────────── */

static void print_usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s <command> [args...]\n"
		"\n"
		"Commands:\n"
		"  load    <obj_file>                          – load BPF obj, pin maps+progs\n"
		"  route   add <pod_ip> <host_ip> <host_mac>\n"
		"  deliver add <pod_ip> <ifname|ifindex> <pod_mac>\n"
		"  host    set <host_ip> <eth_ifname|ifindex> <eth_mac>\n"
		"  host    get                                 – print host_ip eth_mac\n"
		"  txport  add <ifname|ifindex>\n"
		"  dump\n",
		prog);
}

int main(int argc, char **argv)
{
	if (argc < 2) { print_usage(argv[0]); return 1; }

	if (strcmp(argv[1], "load") == 0 && argc >= 3)
		return cmd_load(argv[2]);

	if (strcmp(argv[1], "route") == 0 && argc > 2 && strcmp(argv[2], "add") == 0)
		return cmd_route_add(argc - 3, argv + 3);

	if (strcmp(argv[1], "deliver") == 0 && argc > 2 && strcmp(argv[2], "add") == 0)
		return cmd_deliver_add(argc - 3, argv + 3);

	if (strcmp(argv[1], "host") == 0 && argc > 2 && strcmp(argv[2], "set") == 0)
		return cmd_host_set(argc - 3, argv + 3);

	if (strcmp(argv[1], "host") == 0 && argc > 2 && strcmp(argv[2], "get") == 0)
		return cmd_host_get();

	if (strcmp(argv[1], "txport") == 0 && argc > 2 && strcmp(argv[2], "add") == 0)
		return cmd_txport_add(argc - 3, argv + 3);

	if (strcmp(argv[1], "dump") == 0)
		return cmd_dump();

	print_usage(argv[0]);
	return 1;
}
