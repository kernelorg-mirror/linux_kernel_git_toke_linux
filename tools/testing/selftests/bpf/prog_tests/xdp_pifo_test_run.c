// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <network_helpers.h>
#include <net/if.h>
#include <linux/if_link.h>

#include "test_xdp_pifo.skel.h"

static void run_xdp_prog(int prog_fd, void *data, size_t data_size, int repeat)
{
	struct xdp_md ctx_in = {};
	DECLARE_LIBBPF_OPTS(bpf_test_run_opts, opts,
			    .data_in = data,
			    .data_size_in = data_size,
			    .ctx_in = &ctx_in,
			    .ctx_size_in = sizeof(ctx_in),
			    .repeat = repeat,
			    .flags = BPF_F_TEST_XDP_LIVE_FRAMES,
		);
	int err;

	ctx_in.data_end = ctx_in.data + sizeof(pkt_v4);
	err = bpf_prog_test_run_opts(prog_fd, &opts);
	ASSERT_OK(err, "bpf_prog_test_run(valid)");
}

static void __test_xdp_pifo_live(struct test_xdp_pifo *skel,
				 struct bpf_program *xdp_prog,
				 bool new_netns)
{
	int err, ifindex_src, ifindex_dst;
	struct nstoken *nstoken = NULL;
	struct ipv4_packet data;
	struct bpf_link *link;
	int xdp_prog_fd;
	LIBBPF_OPTS(bpf_xdp_attach_opts, opts,
		    .old_prog_fd = -1);

	if (new_netns) {
		SYS(out, "ip netns add testns");
		nstoken = open_netns("testns");
		if (!ASSERT_OK_PTR(nstoken, "setns"))
			goto out;
	}

	SYS(out, "ip link add veth_src type veth peer name veth_dst");
	SYS(out, "ip link set dev veth_src up");
	SYS(out, "ip link set dev veth_dst up");

	ifindex_src = if_nametoindex("veth_src");
	ifindex_dst = if_nametoindex("veth_dst");
	if (!ASSERT_NEQ(ifindex_src, 0, "ifindex_src") ||
	    !ASSERT_NEQ(ifindex_dst, 0, "ifindex_dst"))
		goto out;

	skel->bss->tgt_ifindex = ifindex_src;
	skel->data->drop_above = 3;

	err = test_xdp_pifo__load(skel);
	ASSERT_OK(err, "load skel");

	link = bpf_program__attach_xdp(skel->progs.xdp_check_pkt, ifindex_dst);
	if (!ASSERT_OK_PTR(link, "xdp prog_attach"))
		goto out;
	skel->links.xdp_check_pkt = link;

	link = bpf_program__attach(skel->progs.xdp_check_return);
	if (!ASSERT_OK_PTR(link, "trace prog_attach"))
		goto out;
	skel->links.xdp_check_return = link;

	xdp_prog_fd = bpf_program__fd(xdp_prog);
	data = pkt_v4;

	run_xdp_prog(xdp_prog_fd, &data, sizeof(data), 3);

	/* wait for the packets to be flushed */
	kern_sync_rcu();

	ASSERT_EQ(skel->bss->seen_good_pkts, 3, "live packets OK");
	ASSERT_EQ(skel->bss->seen_return_pkts, 3, "return packets OK");

out:
	test_xdp_pifo__destroy(skel);
	SYS(out, "ip link del dev veth_src");
	if (new_netns) {
		if (nstoken)
			close_netns(nstoken);
		system("ip netns del testns");
	}
}

void test_xdp_pifo_live_timer(void)
{
	struct test_xdp_pifo *skel = NULL;

	skel = test_xdp_pifo__open();
	if (!ASSERT_OK_PTR(skel, "skel"))
		return;

	__test_xdp_pifo_live(skel, skel->progs.xdp_pifo_timer, false);
}
