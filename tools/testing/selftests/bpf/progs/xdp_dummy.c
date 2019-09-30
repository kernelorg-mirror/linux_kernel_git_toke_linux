// SPDX-License-Identifier: GPL-2.0

#define KBUILD_MODNAME "xdp_dummy"
#include <linux/bpf.h>
#include "bpf_helpers.h"

SEC("xdp_dummy")
int xdp_dummy_prog(struct xdp_md *ctx)
{
	return XDP_PASS;
}

SEC("xdp_drop")
int xdp_drop_prog(struct xdp_md *ctx)
{
	return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
