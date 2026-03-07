/* SPDX-License-Identifier: GPL-2.0 */
/*
 * XDP Redirect Configuration Tool
 * Uses pinned maps to configure redirect
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <sys/wait.h>
#include <net/if.h>
#include <linux/if_ether.h>

#define MAX_IFACE_LEN 32

struct config {
    char ifname_in[MAX_IFACE_LEN];
    char ifname_out[MAX_IFACE_LEN];
    unsigned char dst_mac[ETH_ALEN];
    int has_mac;
};

static void print_usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [OPTIONS]\n", prog);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -d <ifname>    Input interface name (ingress)\n");
    fprintf(stderr, "  -r <ifname>    Redirect to interface (egress)\n");
    fprintf(stderr, "  --dest-mac <MAC>  Destination MAC address (XX:XX:XX:XX:XX:XX)\n");
    fprintf(stderr, "Example:\n");
    fprintf(stderr, "  %s -d v1-host -r v2-host --dest-mac 11:22:33:44:55:66\n", prog);
}

static int parse_mac(const char *str, unsigned char *mac)
{
    int values[ETH_ALEN];
    if (sscanf(str, "%x:%x:%x:%x:%x:%x",
               &values[0], &values[1], &values[2],
               &values[3], &values[4], &values[5]) != ETH_ALEN) {
        return -1;
    }
    for (int i = 0; i < ETH_ALEN; i++)
        mac[i] = (unsigned char)values[i];
    return 0;
}

static int get_ifindex(const char *ifname)
{
    int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        fprintf(stderr, "Error: interface '%s' not found\n", ifname);
        return -1;
    }
    return ifindex;
}

static int run_bpftool(const char *cmd)
{
    int status = system(cmd);
    if (status < 0) {
        fprintf(stderr, "Error running bpftool: %s\n", strerror(errno));
        return -1;
    }
    if (WIFEXITED(status))
        return WEXITSTATUS(status);
    return -1;
}

int main(int argc, char **argv)
{
    struct config cfg = {};
    int opt;
    int ret = EXIT_SUCCESS;

    static struct option long_options[] = {
        {"dest-mac", required_argument, 0, 't'},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "d:r:t:", long_options, NULL)) != -1) {
        switch (opt) {
        case 'd':
            strncpy(cfg.ifname_in, optarg, MAX_IFACE_LEN - 1);
            break;
        case 'r':
            strncpy(cfg.ifname_out, optarg, MAX_IFACE_LEN - 1);
            break;
        case 't':
            if (parse_mac(optarg, cfg.dst_mac) < 0) {
                fprintf(stderr, "Error: invalid destination MAC format\n");
                return EXIT_FAILURE;
            }
            cfg.has_mac = 1;
            break;
        default:
            print_usage(argv[0]);
            return EXIT_FAILURE;
        }
    }

    /* Validate required arguments */
    if (!cfg.ifname_in[0] || !cfg.ifname_out[0]) {
        fprintf(stderr, "Error: both -d and -r options are required\n");
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    if (!cfg.has_mac) {
        fprintf(stderr, "Error: --dest-mac option is required\n");
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    /* Get interface indices */
    int ifindex_in = get_ifindex(cfg.ifname_in);
    int ifindex_out = get_ifindex(cfg.ifname_out);
    if (ifindex_in < 0 || ifindex_out < 0)
        return EXIT_FAILURE;

    printf("Configuring redirect: %s (ifindex=%d) -> %s (ifindex=%d)\n",
           cfg.ifname_in, ifindex_in, cfg.ifname_out, ifindex_out);

    /* Update tx_port map using pinned path */
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "bpftool map update pinned /sys/fs/bpf/xdp/globals/tx_port key %d 0 0 0 value %d 0 0 0",
             ifindex_in, ifindex_out);

    if (run_bpftool(cmd) < 0) {
        fprintf(stderr, "Error: failed to update tx_port map\n");
        ret = EXIT_FAILURE;
        goto cleanup;
    }
    printf("Updated tx_port map: %d -> %d (%s)\n", ifindex_in, ifindex_out, cfg.ifname_out);

    /* Update redirect_params map using pinned path.
     * bpftool parses bare numbers as decimal, so use %d not %02x.
     * (%02x produces "5e" which bpftool rejects as invalid decimal) */
    snprintf(cmd, sizeof(cmd),
             "bpftool map update pinned /sys/fs/bpf/xdp/globals/redirect_params key %d 0 0 0 value %d %d %d %d %d %d",
             ifindex_in,
             cfg.dst_mac[0], cfg.dst_mac[1], cfg.dst_mac[2],
             cfg.dst_mac[3], cfg.dst_mac[4], cfg.dst_mac[5]);

    if (run_bpftool(cmd) < 0) {
        fprintf(stderr, "Error: failed to update redirect_params map\n");
        ret = EXIT_FAILURE;
        goto cleanup;
    }
    printf("Updated redirect_params map: %d -> %02x:%02x:%02x:%02x:%02x:%02x\n",
           ifindex_in,
           cfg.dst_mac[0], cfg.dst_mac[1], cfg.dst_mac[2],
           cfg.dst_mac[3], cfg.dst_mac[4], cfg.dst_mac[5]);

    printf("Configuration complete!\n");

cleanup:
    return ret;
}
