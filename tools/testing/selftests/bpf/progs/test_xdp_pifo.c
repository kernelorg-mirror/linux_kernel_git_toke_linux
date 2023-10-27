// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "bpf_kfuncs.h"

#define CLOCK_MONOTONIC			1

#define META_COOKIE_VAL 0x42424242

struct bpf_map;

extern struct xdp_frame *xdp_packet_dequeue(struct bpf_map *map, __u64 flags,
					    __u64 *rank) __ksym;
extern int xdp_packet_drop(struct xdp_frame *pkt) __ksym;
extern int xdp_packet_send(struct xdp_frame *pkt, int ifindex, __u64 flags) __ksym;
extern int xdp_packet_flush(void) __ksym;

/* Description
 *  Initializes an xdp-type dynptr from xdp_frame
 * Returns
 *  Error code
 */
extern int bpf_dynptr_from_xdp_frame(struct xdp_frame *xdp, __u64 flags,
                                     struct bpf_dynptr *ptr__uninit) __ksym;


struct {
	__uint(type, BPF_MAP_TYPE_PIFO_XDP);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
	__uint(max_entries, 1024);
	__uint(map_extra, 8192); /* range */
} pifo_map SEC(".maps");

struct elem {
	struct bpf_timer t;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct elem);
} array SEC(".maps");

__u16 prio = 3;
int tgt_ifindex = 0;

int timer_init = 0;

__u16 pkt_count = 0;
__u16 drop_above = 2;

static int xdp_timer_cb(void *map, int *key, struct bpf_timer *timer)
{
	__u64 prio = 0, pkt_prio = 0;
	struct xdp_frame *pkt;
	struct ethhdr *eth;
	struct bpf_map *pmap = (void *)&pifo_map;
	int i;

	for (i = 0; i < 3; i++) {
		struct bpf_dynptr ptr;

		pkt = xdp_packet_dequeue(pmap, 0, &prio);
		if (!pkt)
			return 0;

		if (bpf_dynptr_from_xdp_frame(pkt, 0, &ptr))
			return 0;

		eth = bpf_dynptr_slice(&ptr, 0, NULL, sizeof(*eth));
		if (!eth)
			return 0;

		pkt_prio = eth->h_proto;
		if (pkt_prio != prio || ++pkt_count > drop_above) {
			bpf_printk("drop %lu != %lu %d\n", pkt_prio, prio, pkt_count);
			xdp_packet_drop(pkt);
		} else {
			bpf_printk("send to %d\n", tgt_ifindex);
			xdp_packet_send(pkt, tgt_ifindex, 0);
		}
	}

	xdp_packet_flush();

	return 0;
}

SEC("xdp")
int xdp_pifo_timer(struct xdp_md *xdp)
{
	void *data, *data_end, *data_meta;
	struct bpf_timer *timer;
	struct ethhdr *eth;
	int array_key = 0;
	__u32 *meta_val;
	int ret;

	timer = bpf_map_lookup_elem(&array, &array_key);
	if (!timer)
		return XDP_ABORTED;

	if (!timer_init) {
		bpf_timer_init(timer, &array, CLOCK_MONOTONIC);
		bpf_timer_set_callback(timer, xdp_timer_cb);
		timer_init = 1;
	}

	if (bpf_xdp_adjust_meta(xdp, -(int)sizeof(__u32)))
		return XDP_ABORTED;

	data  = (void *)(long)xdp->data;
	data_end = (void *)(long)xdp->data_end;
	data_meta = (void *)(long)xdp->data_meta;
	eth = data;
	meta_val = data_meta;

	if (eth + 1 > data_end || meta_val + 1 > data)
		return XDP_DROP;

	/* We write the priority into the ethernet proto field so userspace can
	 * pick it back out and confirm that it's correct
	 */
	eth->h_proto = --prio;
	*meta_val = META_COOKIE_VAL;
	ret = bpf_redirect_map(&pifo_map, prio, 0);
	if (tgt_ifindex && ret == XDP_REDIRECT)
		bpf_timer_start(timer, 0 /* call asap */, 0);
	return ret;
}

__u16 check_prio = 0;
__u16 seen_good_pkts = 0;

SEC("xdp")
int xdp_check_pkt(struct xdp_md *xdp)
{
	void *data = (void *)(long)xdp->data;
	void *data_end = (void *)(long)xdp->data_end;
	struct ethhdr *eth = data;

	if (eth + 1 > data_end)
		return XDP_DROP;

	if (eth->h_proto == check_prio) {
		check_prio++;
		seen_good_pkts++;
		return XDP_DROP;
	}

	return XDP_PASS;
}

__u16 seen_return_pkts = 0;

SEC("raw_tracepoint/xdp_frame_return")
int xdp_check_return(struct bpf_raw_tracepoint_args* ctx)
{
	struct xdp_frame *frm = (struct xdp_frame *)ctx->args[0];
	__u32 metasize, meta;
	void *data;

	metasize = BPF_CORE_READ(frm, metasize);
	if (metasize != sizeof(__u32))
		goto out;

	data = BPF_CORE_READ(frm, data);
	if (!data)
		goto out;

	if (bpf_probe_read_kernel(&meta, sizeof(meta), data-metasize))
		goto out;

	if (meta == META_COOKIE_VAL)
		seen_return_pkts++;
out:
	return 0;

}

char _license[] SEC("license") = "GPL";
