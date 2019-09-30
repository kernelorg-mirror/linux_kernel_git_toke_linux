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
	if ((ret = bpf_set_link_xdp_fd(ifindex, -1, xdp_flags)))
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
		"    -c			Cleanup and exit\n"
		"    -v			Verbose eBPF logging\n",
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

struct bpf_program {
	/* Index in elf obj file, for relocation use. */
	int idx;
	char *name;
	int prog_ifindex;
	char *section_name;
	/* section_name with / replaced by _; makes recursive pinning
	 * in bpf_object__pin_programs easier
	 */
	char *pin_name;
	struct bpf_insn *insns;
	size_t insns_cnt, main_prog_cnt;
	enum bpf_prog_type type;

	struct reloc_desc {
		enum {
			RELO_LD64,
			RELO_CALL,
			RELO_DATA,
		} type;
		int insn_idx;
		union {
			int map_idx;
			int text_off;
		};
	} *reloc_desc;
	int nr_reloc;
	int log_level;

	struct {
		int nr;
		int *fds;
	} instances;
	bpf_program_prep_t preprocessor;

	struct bpf_object *obj;
	void *priv;
	bpf_program_clear_priv_t clear_priv;

	enum bpf_attach_type expected_attach_type;
	void *func_info;
	__u32 func_info_rec_size;
	__u32 func_info_cnt;

	struct bpf_capabilities *caps;

	void *line_info;
	__u32 line_info_rec_size;
	__u32 line_info_cnt;
	__u32 prog_flags;
};

static int printfunc(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
	__u32 mode_flags = XDP_FLAGS_DRV_MODE | XDP_FLAGS_SKB_MODE;
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	bool setup_only = false, cleanup_only = false;
	struct bpf_program *pass_prog, *drop_prog, *prog;
	int pass_prog_fd = -1, drop_prog_fd = -1;
	const char *filename = "xdp_dummy.o";
	int opt, ret = 1, log_level = 0;
	const char *optstr = "I:NSxcv";
	struct bpf_object *obj;
	u32 prog_id;

	struct bpf_object_open_attr open_attr = {
						 .file = filename,
						 .prog_type = BPF_PROG_TYPE_XDP,
	};

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
		case 'v':
			log_level = 7;
			break;
		case 'c':
			cleanup_only = true;
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

	if (log_level)
		libbpf_set_print(printfunc);

	obj = bpf_object__open_xattr(&open_attr);

	bpf_object__for_each_program(prog, obj) {
		bpf_program__set_type(prog, BPF_PROG_TYPE_XDP);
		prog->prog_flags = BPF_F_CHAIN_CALLS;
		prog->log_level = log_level;
		if ((ret = bpf_program__load(prog, "GPL", 0))) {
			fprintf(stderr, "unable to load program: %s\n", strerror(-ret));
			return 1;
		}
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


#define RUN_PING(should_fail, err) if ((ret = run_ping(should_fail, err))) goto done;

	if (!setup_only) {
		RUN_PING(false, "Pre-setup ping test");

		signal(SIGINT, cleanup);
		signal(SIGTERM, cleanup);
	}

	if ((ret = bpf_set_link_xdp_fd(ifindex, pass_prog_fd, xdp_flags)) < 0) {
		fprintf(stderr, "Link set xdp fd failed for %s: %s\n", ifname,
			strerror(-ret));
		goto done;
	}

	if (!setup_only) {
		sleep(1);
		RUN_PING(false, "Empty map test");
	}

	if (bpf_prog_chain_add(pass_prog_fd, -1, drop_prog_fd)) {
		fprintf(stderr, "unable to add chain prog wildcard: %s (%d)\n", strerror(errno), errno);
		goto done;
	}

	if (bpf_prog_chain_get(pass_prog_fd, -1, &prog_id)) {
		fprintf(stderr, "unable to get chain prog wildcard: %s (%d)\n", strerror(errno), errno);
		goto done;
	}
	printf("Next program attached with ID: %u\n", prog_id);

	if (setup_only) {
		printf("Setup done; exiting.\n");
		ret = 0;
		goto done;
	}

	sleep(1);

	RUN_PING(true, "Wildcard act test");

	if (bpf_prog_chain_del(pass_prog_fd, -1)) {
		fprintf(stderr, "unable to delete chain prog: %s\n", strerror(errno));
		goto done;
	}
	sleep(1);

	RUN_PING(false, "Post-delete map test");

	if (bpf_prog_chain_add(pass_prog_fd, XDP_PASS, drop_prog_fd)) {
		fprintf(stderr, "unable to add chain prog PASS: %s\n", strerror(errno));
		goto done;
	}
	sleep(1);

	RUN_PING(true, "Pass act test");


	if ((ret = bpf_set_link_xdp_fd(ifindex, -1, xdp_flags)) < 0) {
		fprintf(stderr, "Link clear xdp fd failed for %s: '%s'\n", ifname, strerror(-ret));
		goto done;
	}
	sleep(1);

	RUN_PING(false, "Post-delete prog test");


done:
	if (!setup_only)
		cleanup(ret);

	if (pass_prog_fd > 0)
		close(pass_prog_fd);
	if (drop_prog_fd > 0)
		close(drop_prog_fd);

	return ret;
}
