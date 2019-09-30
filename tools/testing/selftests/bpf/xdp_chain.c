// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2019, Oracle and/or its affiliates. All rights reserved. */

#include <linux/bpf.h>
#include <linux/if_link.h>
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <sys/resource.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "bpf/bpf.h"
#include "bpf/libbpf.h"

static int ifindex;
static __u32 xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
static char *dest = NULL, *ifname = NULL;

static void cleanup(int sig)
{
	int ret;

	fprintf(stderr, "  Cleaning up\n");
	if ((ret = bpf_set_link_xdp_chain(ifindex, -1, -1, xdp_flags)))
		fprintf(stderr, "Warning: Unable to clear XDP prog: %s\n",
			strerror(-ret));
	if (sig)
		exit(1);
}

static void show_usage(const char *prog)
{
	fprintf(stderr,
		"usage: %s [OPTS] -I interface destination\n\n"
		"OPTS:\n"
		"    -I interface		interface name\n"
		"    -N			Run in driver mode\n"
		"    -S			Run in skb mode\n"
		"    -p pin_path		path to pin chain call map\n"
		"    -x			Exit after setup\n"
		"    -c			Cleanup and exit\n",
		prog);
}

static int run_ping(bool should_fail, const char *msg)
{
	char cmd[256];
	bool success;
	int ret;

	snprintf(cmd, sizeof(cmd), "ping -c 1 -W 1 -I %s %s >/dev/null", ifname, dest);

	printf("  %s: ", msg);

	ret = system(cmd);

	success = (!!ret == should_fail);
	printf(success ? "PASS\n" : "FAIL\n");

	return !success;
}

int main(int argc, char **argv)
{
	__u32 mode_flags = XDP_FLAGS_DRV_MODE | XDP_FLAGS_SKB_MODE;
	int pass_prog_fd = -1, drop_prog_fd = -1, map_fd = -1;
	const char *filename = "xdp_dummy.o", *pin_path = NULL;
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	struct bpf_program *pass_prog, *drop_prog;
	__u32 map_key, prog_id, chain_map_id;
	struct xdp_chain_acts acts = {};
	struct bpf_prog_info info = {};
	__u32 info_len = sizeof(info);
	const char *optstr = "I:NSp:xc";
	bool setup_only = false, cleanup_only = false;
	struct bpf_object *obj;
	int opt, ret = 1;

	while ((opt = getopt(argc, argv, optstr)) != -1) {
		switch (opt) {
		case 'I':
			ifname = optarg;
			ifindex = if_nametoindex(ifname);
			if (!ifindex) {
				fprintf(stderr, "Could not get interface %s\n",
					ifname);
				return 1;
			}
			break;
		case 'N':
			xdp_flags |= XDP_FLAGS_DRV_MODE;
			break;
		case 'S':
			xdp_flags |= XDP_FLAGS_SKB_MODE;
			break;
		case 'x':
			setup_only = true;
			break;
		case 'c':
			cleanup_only = true;
			break;
		case 'p':
			pin_path = optarg;
			break;
		default:
			show_usage(basename(argv[0]));
			return 1;
		}
	}

	if (!ifname) {
		show_usage(basename(argv[0]));
		return 1;
	}

	if (cleanup_only) {
		if (pin_path)
			unlink(pin_path);
		cleanup(0);
		return 0;
	}

	if (!setup_only && optind == argc) {
		show_usage(basename(argv[0]));
		return 1;
	}
	dest = argv[optind];

	if ((xdp_flags & mode_flags) == mode_flags) {
		fprintf(stderr, "-N or -S can be specified, not both.\n");
		show_usage(basename(argv[0]));
		return 1;
	}

	if (setrlimit(RLIMIT_MEMLOCK, &r)) {
		perror("setrlimit(RLIMIT_MEMLOCK)");
		return 1;
	}

	if (bpf_prog_load(filename, BPF_PROG_TYPE_XDP, &obj, &pass_prog_fd)) {
		fprintf(stderr, "load of %s failed\n", filename);
		return 1;
	}

	pass_prog = bpf_object__find_program_by_title(obj, "xdp_dummy");
	drop_prog = bpf_object__find_program_by_title(obj, "xdp_drop");

	if (!pass_prog || !drop_prog) {
		fprintf(stderr, "could not find xdp programs\n");
		return 1;
	}
	pass_prog_fd = bpf_program__fd(pass_prog);
	drop_prog_fd = bpf_program__fd(drop_prog);
	if (pass_prog_fd < 0 || drop_prog_fd < 0) {
		fprintf(stderr, "could not find xdp programs\n");
		goto done;
	}

	ret = bpf_obj_get_info_by_fd(pass_prog_fd, &info, &info_len);
	if (ret) {
		fprintf(stderr, "unable to get program ID from kernel\n");
		goto done;
	}
	map_key = info.id;
	map_fd = bpf_create_map(BPF_MAP_TYPE_XDP_CHAIN,
				sizeof(map_key), sizeof(acts),
				2, 0);

	if (map_fd < 0) {
		fprintf(stderr, "unable to create chain call map: %s\n", strerror(errno));
		goto done;
	}

	if (pin_path && (ret = bpf_obj_pin(map_fd, pin_path))) {
		fprintf(stderr, "unable to pin map at %s: %s\n", pin_path,
			strerror(errno));
		goto done;
	}


#define RUN_PING(should_fail, err) if ((ret = run_ping(should_fail, err))) goto done;

	if (!setup_only) {
		RUN_PING(false, "Pre-setup ping test");

		signal(SIGINT, cleanup);
		signal(SIGTERM, cleanup);
	}

	if ((ret = bpf_set_link_xdp_chain(ifindex, pass_prog_fd, map_fd, xdp_flags)) < 0) {
		fprintf(stderr, "Link set xdp fd failed for %s: %s\n", ifname,
			strerror(-ret));
		goto done;
	}

	if ((ret = bpf_get_link_xdp_chain(ifindex, &prog_id, &chain_map_id, 0)) < 0) {
		fprintf(stderr, "Unable to get xdp IDs for %s: '%s'\n", ifname, strerror(-ret));
		goto done;
	}
	printf("  XDP prog ID: %u Chain map ID: %u\n", prog_id, chain_map_id);

	if (!setup_only) {
		sleep(1);
		RUN_PING(false, "Empty map test");
	}

	acts.wildcard_act = drop_prog_fd;
	if (bpf_map_update_elem(map_fd, &map_key, &acts, 0)) {
		fprintf(stderr, "unable to insert into map: %s\n", strerror(errno));
		goto done;
	}

	if (setup_only) {
		printf("Setup done; exiting.\n");
		ret = 0;
		goto done;
	}

	sleep(1);

	RUN_PING(true, "Wildcard act test");

	if (bpf_map_delete_elem(map_fd, &map_key)) {
		fprintf(stderr, "unable to delete from map: %s\n", strerror(errno));
		goto done;
	}
	sleep(1);

	RUN_PING(false, "Post-delete map test");

	acts.wildcard_act = 0;
	acts.pass_act = drop_prog_fd;
	if (bpf_map_update_elem(map_fd, &map_key, &acts, 0)) {
		fprintf(stderr, "unable to insert into map: %s\n", strerror(errno));
		goto done;
	}
	sleep(1);

	RUN_PING(true, "Pass act test");


	if ((ret = bpf_set_link_xdp_chain(ifindex, -1, -1, xdp_flags)) < 0) {
		fprintf(stderr, "Link clear xdp fd failed for %s: '%s'\n", ifname, strerror(-ret));
		goto done;
	}
	sleep(1);

	RUN_PING(false, "Post-delete prog test");


done:
	cleanup(ret);

	if (pass_prog_fd > 0)
		close(pass_prog_fd);
	if (drop_prog_fd > 0)
		close(drop_prog_fd);
	if (map_fd > 0)
		close(map_fd);

	return ret;
}
