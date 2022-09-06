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

#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC 1
#endif

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

struct elem {
	struct bpf_timer t;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct elem);
} timermap SEC(".maps");

int timer_init = 0;

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

__u64 num_queued = 0;
#define BATCH_SIZE 128

static int xdp_timer_cb(void *map, int *key, struct bpf_timer *timer)
{
	struct xdp_md *pkt;
	__u64 prio = 0;
	int i;

	for (i = 0; i < BATCH_SIZE; i++) {
		pkt = (void *)bpf_packet_dequeue_xdp(&pifo, 0, &prio);
		if (!pkt)
			break;

		num_queued--;
		bpf_packet_send(pkt, tgt_ifindex, 0);
	}

	bpf_packet_flush();
	if (num_queued)
		bpf_timer_start(timer, 0 /* call asap */, 0);

	return 0;
}

SEC("xdp")
int xdp_redirect_map_timer(struct xdp_md *ctx)
{
	struct bpf_timer *timer;
	int array_key = 0;
	int ret;

	timer = bpf_map_lookup_elem(&timermap, &array_key);
	if (!timer)
		return XDP_ABORTED;

	if (!timer_init) {
		bpf_timer_init(timer, &timermap, CLOCK_MONOTONIC);
		bpf_timer_set_callback(timer, xdp_timer_cb);
		timer_init = 1;
	}

	ret = xdp_redirect_map(ctx, &pifo);

	if (ret == XDP_REDIRECT) {
		num_queued++;
		bpf_timer_start(timer, 0 /* call asap */, 0);
	}

	return ret;
}
char _license[] SEC("license") = "GPL";
