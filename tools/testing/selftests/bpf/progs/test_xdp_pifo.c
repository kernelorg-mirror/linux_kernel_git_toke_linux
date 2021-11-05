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
	eth->h_proto = prio--;
	return bpf_redirect_map(&pifo_map, prio, 0);
}

__u16 pkt_count = 0;

SEC("dequeue")
int dequeue_pifo(struct dequeue_ctx *ctx)
{
	void *pkt;

	pkt = (void *)bpf_packet_dequeue(ctx, &pifo_map, 0);
	if (!pkt)
		return 0;

	if (++pkt_count > 2)
		return bpf_packet_drop(ctx, pkt);
	else
		return bpf_packet_return(ctx, pkt);
}

char _license[] SEC("license") = "GPL";
