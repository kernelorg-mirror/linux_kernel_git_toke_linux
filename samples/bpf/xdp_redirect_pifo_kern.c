/* Copyright (c) 2017 Covalent IO, Inc. http://covalent.io
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 */
#define KBUILD_MODNAME "foo"
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_PIFO);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
	__uint(max_entries, 1024);
} pifo_map SEC(".maps");

/* Count RX packets, as XDP bpf_prog doesn't get direct TX-success
 * feedback.  Redirect TX errors can be caught via a tracepoint.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, long);
	__uint(max_entries, 1);
} rxcnt SEC(".maps");

/* map to store egress interface mac address */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, __be64);
	__uint(max_entries, 1);
} tx_mac SEC(".maps");

static void swap_src_dst_mac(void *data)
{
	unsigned short *p = data;
	unsigned short dst[3];

	dst[0] = p[0];
	dst[1] = p[1];
	dst[2] = p[2];
	p[0] = p[3];
	p[1] = p[4];
	p[2] = p[5];
	p[3] = dst[0];
	p[4] = dst[1];
	p[5] = dst[2];
}

SEC("xdp_redirect_pifo")
int xdp_redirect_map_pifo(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	int rc = XDP_DROP;
	long *value;
	u32 key = 0;
	u64 nh_off;
	int vport;

	nh_off = sizeof(*eth);
	if (data + nh_off > data_end)
		return rc;

	/* constant virtual port */
	vport = 0;

	/* count packet in global counter */
	value = bpf_map_lookup_elem(&rxcnt, &key);
	if (value)
		*value += 1;

	swap_src_dst_mac(data);

	/* send packet out physical port */
	return bpf_redirect_map(&pifo_map, vport, 0);
}

char _license[] SEC("license") = "GPL";
