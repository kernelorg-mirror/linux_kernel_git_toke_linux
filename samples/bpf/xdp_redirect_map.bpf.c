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

#include "vmlinux.h"
#include "xdp_sample.bpf.h"
#include "xdp_sample_shared.h"

/* The 2nd xdp prog on egress does not support skb mode, so we define two
 * maps, tx_port_general and tx_port_native.
 */
struct {
	__uint(type, BPF_MAP_TYPE_DEVMAP);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
	__uint(max_entries, 1);
} tx_port_general SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_DEVMAP);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(struct bpf_devmap_val));
	__uint(max_entries, 1);
} tx_port_native SEC(".maps");

struct pifo_map {
	__uint(type, BPF_MAP_TYPE_PIFO_XDP);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
	__uint(max_entries, 10240);
	__uint(map_extra, 8192); /* range */
} pifo SEC(".maps");


/* store egress interface mac address */
const volatile __u8 tx_mac_addr[ETH_ALEN];
const volatile int tgt_ifindex;

static __always_inline int xdp_redirect_map(struct xdp_md *ctx, void *redirect_map)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	u32 key = bpf_get_smp_processor_id();
	struct ethhdr *eth = data;
	struct datarec *rec;
	u64 nh_off;

	nh_off = sizeof(*eth);
	if (data + nh_off > data_end)
		return XDP_DROP;

	rec = bpf_map_lookup_elem(&rx_cnt, &key);
	if (!rec)
		return XDP_PASS;
	NO_TEAR_INC(rec->processed);
	swap_src_dst_mac(data);
	return bpf_redirect_map(redirect_map, 0, 0);
}

SEC("xdp")
int xdp_redirect_map_general(struct xdp_md *ctx)
{
	return xdp_redirect_map(ctx, &tx_port_general);
}

SEC("xdp")
int xdp_redirect_map_native(struct xdp_md *ctx)
{
	return xdp_redirect_map(ctx, &tx_port_native);
}

SEC("xdp/devmap")
int xdp_redirect_map_egress(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	u8 *mac_addr = (u8 *) tx_mac_addr;
	struct ethhdr *eth = data;
	u64 nh_off;

	nh_off = sizeof(*eth);
	if (data + nh_off > data_end)
		return XDP_DROP;

	barrier_var(mac_addr); /* prevent optimizing out memcpy */
	__builtin_memcpy(eth->h_source, mac_addr, ETH_ALEN);

	return XDP_PASS;
}

/* Redirect require an XDP bpf_prog loaded on the TX device */
SEC("xdp")
int xdp_redirect_dummy_prog(struct xdp_md *ctx)
{
	return XDP_PASS;
}

SEC("xdp")
int xdp_redirect_map_queue(struct xdp_md *ctx)
{
	int ret;
	ret = xdp_redirect_map(ctx, &pifo);

	if (ret == XDP_REDIRECT)
		bpf_schedule_iface_dequeue(ctx, tgt_ifindex, 0);

	return ret;
}

SEC("xdp_dequeue")
void *xdp_redirect_deq_func(struct dequeue_ctx *ctx)
{
	struct xdp_md *pkt;
	__u64 prio = 0;

	pkt = (void *)bpf_packet_dequeue(ctx, &pifo, 0, &prio);
	if (!pkt)
		return NULL;

	return pkt;
}

char _license[] SEC("license") = "GPL";
