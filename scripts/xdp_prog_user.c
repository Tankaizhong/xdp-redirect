/* SPDX-License-Identifier: GPL-2.0 */
/*
 * xdp_prog_user.c – User-space tool for populating XDP IPIP overlay maps.
 *
 * Subcommands:
 *   route   add <pod_ip> <host_ip> <host_mac>     – add routing_map entry
 *   deliver add <pod_ip> <ifindex> <pod_mac>       – add delivery_map entry
 *   host    set <host_ip> <eth_ifindex> <eth_mac>  – set host_config[0]
 *   txport  add <ifindex>                          – register ifindex in tx_ports DEVMAP
 *   dump                                           – dump all maps
 *
 * All map operations use pinned paths under /sys/fs/bpf/xdp_ipip/
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>
#include <net/if.h>
#include <arpa/inet.h>

#define ETH_ALEN 6
#define PIN_BASE "/sys/fs/bpf/xdp_ipip"

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

static int run_cmd(const char *cmd)
{
	int status = system(cmd);
	if (status < 0) {
		fprintf(stderr, "system() failed: %s\n", strerror(errno));
		return -1;
	}
	if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
		fprintf(stderr, "command failed (exit %d): %s\n",
			WEXITSTATUS(status), cmd);
		return -1;
	}
	return 0;
}

/* ── route add <pod_ip> <host_ip> <host_mac> ────────────────────────────── */
static int cmd_route_add(int argc, char **argv)
{
	if (argc < 3) {
		fprintf(stderr, "Usage: route add <pod_ip> <host_ip> <host_mac>\n");
		return 1;
	}

	struct in_addr pod_addr, host_addr;
	unsigned char host_mac[ETH_ALEN];

	if (inet_pton(AF_INET, argv[0], &pod_addr) != 1) {
		fprintf(stderr, "Invalid pod IP: %s\n", argv[0]);
		return 1;
	}
	if (inet_pton(AF_INET, argv[1], &host_addr) != 1) {
		fprintf(stderr, "Invalid host IP: %s\n", argv[1]);
		return 1;
	}
	if (parse_mac(argv[2], host_mac) < 0) {
		fprintf(stderr, "Invalid MAC: %s\n", argv[2]);
		return 1;
	}

	/* Key: pod_ip as 4 bytes (network byte order) */
	unsigned char *kb = (unsigned char *)&pod_addr.s_addr;

	/* Value: struct route_entry = { host_ip(4), host_mac(6), pad(2) } = 12 bytes */
	unsigned char *vb = (unsigned char *)&host_addr.s_addr;

	char cmd[512];
	snprintf(cmd, sizeof(cmd),
		 "bpftool map update pinned " PIN_BASE "/routing_map "
		 "key %d %d %d %d "
		 "value %d %d %d %d %d %d %d %d %d %d 0 0",
		 kb[0], kb[1], kb[2], kb[3],
		 vb[0], vb[1], vb[2], vb[3],
		 host_mac[0], host_mac[1], host_mac[2],
		 host_mac[3], host_mac[4], host_mac[5]);

	printf("routing_map: %s → host=%s mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
	       argv[0], argv[1],
	       host_mac[0], host_mac[1], host_mac[2],
	       host_mac[3], host_mac[4], host_mac[5]);

	return run_cmd(cmd);
}

/* ── deliver add <pod_ip> <ifname_or_index> <pod_mac> ────────────────────── */
static int cmd_deliver_add(int argc, char **argv)
{
	if (argc < 3) {
		fprintf(stderr, "Usage: deliver add <pod_ip> <ifname_or_index> <pod_mac>\n");
		return 1;
	}

	struct in_addr pod_addr;
	unsigned char pod_mac[ETH_ALEN];
	int ifindex;

	if (inet_pton(AF_INET, argv[0], &pod_addr) != 1) {
		fprintf(stderr, "Invalid pod IP: %s\n", argv[0]);
		return 1;
	}

	/* Try as interface name first, fall back to numeric */
	ifindex = if_nametoindex(argv[1]);
	if (ifindex == 0) {
		ifindex = atoi(argv[1]);
		if (ifindex <= 0) {
			fprintf(stderr, "Invalid interface: %s\n", argv[1]);
			return 1;
		}
	}

	if (parse_mac(argv[2], pod_mac) < 0) {
		fprintf(stderr, "Invalid MAC: %s\n", argv[2]);
		return 1;
	}

	unsigned char *kb = (unsigned char *)&pod_addr.s_addr;

	/* Value: struct delivery_entry = { ifindex(4), pod_mac(6), pad(2) } = 12 bytes */
	unsigned char ifb[4];
	ifb[0] = ifindex & 0xff;
	ifb[1] = (ifindex >> 8) & 0xff;
	ifb[2] = (ifindex >> 16) & 0xff;
	ifb[3] = (ifindex >> 24) & 0xff;

	char cmd[512];
	snprintf(cmd, sizeof(cmd),
		 "bpftool map update pinned " PIN_BASE "/delivery_map "
		 "key %d %d %d %d "
		 "value %d %d %d %d %d %d %d %d %d %d 0 0",
		 kb[0], kb[1], kb[2], kb[3],
		 ifb[0], ifb[1], ifb[2], ifb[3],
		 pod_mac[0], pod_mac[1], pod_mac[2],
		 pod_mac[3], pod_mac[4], pod_mac[5]);

	printf("delivery_map: %s → ifindex=%d mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
	       argv[0], ifindex,
	       pod_mac[0], pod_mac[1], pod_mac[2],
	       pod_mac[3], pod_mac[4], pod_mac[5]);

	return run_cmd(cmd);
}

/* ── host set <host_ip> <eth_ifname> <eth_mac> ──────────────────────────── */
static int cmd_host_set(int argc, char **argv)
{
	if (argc < 3) {
		fprintf(stderr, "Usage: host set <host_ip> <eth_ifname_or_index> <eth_mac>\n");
		return 1;
	}

	struct in_addr host_addr;
	unsigned char eth_mac[ETH_ALEN];
	int eth_ifindex;

	if (inet_pton(AF_INET, argv[0], &host_addr) != 1) {
		fprintf(stderr, "Invalid host IP: %s\n", argv[0]);
		return 1;
	}

	eth_ifindex = if_nametoindex(argv[1]);
	if (eth_ifindex == 0) {
		eth_ifindex = atoi(argv[1]);
		if (eth_ifindex <= 0) {
			fprintf(stderr, "Invalid interface: %s\n", argv[1]);
			return 1;
		}
	}

	if (parse_mac(argv[2], eth_mac) < 0) {
		fprintf(stderr, "Invalid MAC: %s\n", argv[2]);
		return 1;
	}

	unsigned char *hb = (unsigned char *)&host_addr.s_addr;
	unsigned char ifb[4];
	ifb[0] = eth_ifindex & 0xff;
	ifb[1] = (eth_ifindex >> 8) & 0xff;
	ifb[2] = (eth_ifindex >> 16) & 0xff;
	ifb[3] = (eth_ifindex >> 24) & 0xff;

	/* Value: struct host_info = { host_ip(4), eth_ifindex(4), eth_mac(6), pad(2) } = 16 bytes */
	char cmd[512];
	snprintf(cmd, sizeof(cmd),
		 "bpftool map update pinned " PIN_BASE "/host_config "
		 "key 0 0 0 0 "
		 "value %d %d %d %d %d %d %d %d %d %d %d %d %d %d 0 0",
		 hb[0], hb[1], hb[2], hb[3],
		 ifb[0], ifb[1], ifb[2], ifb[3],
		 eth_mac[0], eth_mac[1], eth_mac[2],
		 eth_mac[3], eth_mac[4], eth_mac[5]);

	printf("host_config[0]: ip=%s eth_ifindex=%d mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
	       argv[0], eth_ifindex,
	       eth_mac[0], eth_mac[1], eth_mac[2],
	       eth_mac[3], eth_mac[4], eth_mac[5]);

	return run_cmd(cmd);
}

/* ── txport add <ifname_or_index> ────────────────────────────────────────── */
static int cmd_txport_add(int argc, char **argv)
{
	if (argc < 1) {
		fprintf(stderr, "Usage: txport add <ifname_or_index>\n");
		return 1;
	}

	int ifindex = if_nametoindex(argv[0]);
	if (ifindex == 0) {
		ifindex = atoi(argv[0]);
		if (ifindex <= 0) {
			fprintf(stderr, "Invalid interface: %s\n", argv[0]);
			return 1;
		}
	}

	char cmd[512];
	snprintf(cmd, sizeof(cmd),
		 "bpftool map update pinned " PIN_BASE "/tx_ports "
		 "key %d 0 0 0 value %d 0 0 0",
		 ifindex, ifindex);

	printf("tx_ports: ifindex=%d → ifindex=%d\n", ifindex, ifindex);

	return run_cmd(cmd);
}

/* ── dump ────────────────────────────────────────────────────────────────── */
static int cmd_dump(void)
{
	printf("\n=== routing_map ===\n");
	run_cmd("bpftool map dump pinned " PIN_BASE "/routing_map 2>/dev/null || echo '(empty)'");

	printf("\n=== delivery_map ===\n");
	run_cmd("bpftool map dump pinned " PIN_BASE "/delivery_map 2>/dev/null || echo '(empty)'");

	printf("\n=== host_config ===\n");
	run_cmd("bpftool map dump pinned " PIN_BASE "/host_config 2>/dev/null || echo '(empty)'");

	printf("\n=== tx_ports ===\n");
	run_cmd("bpftool map dump pinned " PIN_BASE "/tx_ports 2>/dev/null || echo '(empty)'");

	return 0;
}

static void print_usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s <command> [args...]\n"
		"\n"
		"Commands:\n"
		"  route   add <pod_ip> <host_ip> <host_mac>\n"
		"  deliver add <pod_ip> <ifname|ifindex> <pod_mac>\n"
		"  host    set <host_ip> <eth_ifname|ifindex> <eth_mac>\n"
		"  txport  add <ifname|ifindex>\n"
		"  dump\n",
		prog);
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		print_usage(argv[0]);
		return 1;
	}

	if (strcmp(argv[1], "route") == 0 && argc > 2 && strcmp(argv[2], "add") == 0)
		return cmd_route_add(argc - 3, argv + 3);

	if (strcmp(argv[1], "deliver") == 0 && argc > 2 && strcmp(argv[2], "add") == 0)
		return cmd_deliver_add(argc - 3, argv + 3);

	if (strcmp(argv[1], "host") == 0 && argc > 2 && strcmp(argv[2], "set") == 0)
		return cmd_host_set(argc - 3, argv + 3);

	if (strcmp(argv[1], "txport") == 0 && argc > 2 && strcmp(argv[2], "add") == 0)
		return cmd_txport_add(argc - 3, argv + 3);

	if (strcmp(argv[1], "dump") == 0)
		return cmd_dump();

	print_usage(argv[0]);
	return 1;
}
