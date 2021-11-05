// SPDX-License-Identifier: GPL-2.0
#include "linux/bpf.h"
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_PIFO);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
	__uint(max_entries, 1024);
} pifo_map SEC(".maps");

__u16 prio = 3;
__u16 exp_prio = 0;

SEC("xdp")
int xdp_pifo(struct xdp_md *xdp)
{
	void *data = (void *)(long)xdp->data;
	void *data_end = (void *)(long)xdp->data_end;
	struct ethhdr *eth = data;

	if (eth + 1 > data_end)
		return XDP_DROP;

	/* We write the priority into the ethernet proto field so userspace can
	 * pick it back out and confirm that it's correct
	 */
	eth->h_proto = --prio;
	return bpf_redirect_map(&pifo_map, prio, 0);
}

__u16 pkt_count = 0;

SEC("dequeue")
void *dequeue_pifo(struct dequeue_ctx *ctx)
{
	__u64 prio = 0, pkt_prio = 0;
	void *data, *data_end;
	struct xdp_md *pkt;
	struct ethhdr *eth;

	pkt = (void *)bpf_packet_dequeue(ctx, &pifo_map, 0, &prio);
	if (!pkt)
		return NULL;

	data = (void *)(long)pkt->data;
	data_end = (void *)(long)pkt->data_end;
	eth = data;

	if (eth + 1 <= data_end)
		pkt_prio = eth->h_proto;

	if (prio != exp_prio++ || pkt_prio != prio) {
		bpf_packet_drop(ctx, pkt);
		return NULL;
	}

	if (++pkt_count > 2) {
		bpf_packet_drop(ctx, pkt);
		pkt = NULL;
	}
	return pkt;
}

char _license[] SEC("license") = "GPL";
