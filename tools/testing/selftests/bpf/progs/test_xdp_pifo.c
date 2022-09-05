// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <time.h>

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

SEC("xdp")
int xdp_pifo(struct xdp_md *xdp)
{
	void *data = (void *)(long)xdp->data;
	void *data_end = (void *)(long)xdp->data_end;
	struct ethhdr *eth = data;
	int ret;

	if (eth + 1 > data_end)
		return XDP_DROP;

	/* We write the priority into the ethernet proto field so userspace can
	 * pick it back out and confirm that it's correct
	 */
	eth->h_proto = --prio;
	ret = bpf_redirect_map(&pifo_map, prio, 0);
	if (tgt_ifindex && ret == XDP_REDIRECT)
		bpf_schedule_iface_dequeue(xdp, tgt_ifindex, 0);
	return ret;
}


static int xdp_timer_cb(void *map, int *key, struct bpf_timer *timer)
{
	__u64 prio = 0, pkt_prio = 0;
	void *data, *data_end;
	struct xdp_md *pkt;
	struct ethhdr *eth;
	int i;

	for (i = 0; i < 3; i++) {
		pkt = (void *)bpf_packet_dequeue_xdp(&pifo_map, 0, &prio);
		if (!pkt)
			return 0;

		data = (void *)(long)pkt->data;
		data_end = (void *)(long)pkt->data_end;
		eth = data;

		if (eth + 1 <= data_end)
			pkt_prio = eth->h_proto;

		if (pkt_prio != prio || ++pkt_count > drop_above) {
			bpf_printk("drop %lu != %lu %d\n", pkt_prio, prio, pkt_count);
			bpf_packet_drop_xdp(pkt);
		} else {
			bpf_printk("send to %d\n", tgt_ifindex);
			bpf_packet_send(pkt, tgt_ifindex, 0);
		}
	}

	bpf_packet_flush();

	return 0;
}

SEC("xdp")
int xdp_pifo_timer(struct xdp_md *xdp)
{
	void *data = (void *)(long)xdp->data;
	void *data_end = (void *)(long)xdp->data_end;
	struct ethhdr *eth = data;
	int ret;

	struct bpf_timer *timer;
	int array_key = 0;

	timer = bpf_map_lookup_elem(&array, &array_key);
	if (!timer)
		return XDP_ABORTED;

	if (!timer_init) {
		bpf_timer_init(timer, &array, CLOCK_MONOTONIC);
		bpf_timer_set_callback(timer, xdp_timer_cb);
		timer_init = 1;
	}

	if (eth + 1 > data_end)
		return XDP_DROP;

	/* We write the priority into the ethernet proto field so userspace can
	 * pick it back out and confirm that it's correct
	 */
	eth->h_proto = --prio;
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

SEC("xdp")
int xdp_pifo_inc(struct xdp_md *xdp)
{
	void *data = (void *)(long)xdp->data;
	void *data_end = (void *)(long)xdp->data_end;
	struct ethhdr *eth = data;
	int ret;

	if (eth + 1 > data_end)
		return XDP_DROP;

	/* We write the priority into the ethernet proto field so userspace can
	 * pick it back out and confirm that it's correct
	 */
	eth->h_proto = prio;
	ret = bpf_redirect_map(&pifo_map, prio, 0);
	prio += 10;
	return ret;
}

SEC("xdp_dequeue")
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

	if (pkt_prio != prio || ++pkt_count > drop_above) {
		bpf_packet_drop(ctx, pkt);
		return NULL;
	}

	return pkt;
}

char _license[] SEC("license") = "GPL";
