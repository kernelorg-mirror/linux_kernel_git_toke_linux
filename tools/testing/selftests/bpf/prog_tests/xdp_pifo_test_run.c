// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <network_helpers.h>
#include "test_xdp_pifo.skel.h"

static void run_xdp_prog(int prog_fd, void *data, size_t data_size)
{
	struct xdp_md ctx_in = {};
	DECLARE_LIBBPF_OPTS(bpf_test_run_opts, opts,
			    .data_in = data,
			    .data_size_in = data_size,
			    .ctx_in = &ctx_in,
			    .ctx_size_in = sizeof(ctx_in),
			    .repeat = 3,
			    .flags = BPF_F_TEST_XDP_LIVE_FRAMES,
		);
	int err;

	ctx_in.data_end = ctx_in.data + sizeof(pkt_v4);
	err = bpf_prog_test_run_opts(prog_fd, &opts);
	ASSERT_OK(err, "bpf_prog_test_run(valid)");
}

static void run_dequeue_prog(int prog_fd, int exp_proto)
{
	struct ipv4_packet data_out;
	DECLARE_LIBBPF_OPTS(bpf_test_run_opts, opts,
			    .data_out = &data_out,
			    .data_size_out = sizeof(data_out),
			    .repeat = 1,
		);
	int err;

	err = bpf_prog_test_run_opts(prog_fd, &opts);
	ASSERT_OK(err, "bpf_prog_test_run(valid)");
	ASSERT_EQ(opts.retval, exp_proto == -1 ? 0 : 1, "valid-retval");
	if (exp_proto >= 0) {
		ASSERT_EQ(opts.data_size_out, sizeof(pkt_v4), "valid-datasize");
		ASSERT_EQ(data_out.eth.h_proto, exp_proto, "valid-pkt");
	} else {
		ASSERT_EQ(opts.data_size_out, 0, "no-pkt-returned");
	}
}

void test_xdp_pifo(void)
{
	struct test_xdp_pifo *skel = NULL;
	struct ipv4_packet data;
	int xdp_prog_fd, dequeue_prog_fd;

	skel = test_xdp_pifo__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel"))
		return;

	xdp_prog_fd = bpf_program__fd(skel->progs.xdp_pifo);
	dequeue_prog_fd = bpf_program__fd(skel->progs.dequeue_pifo);
	data = pkt_v4;

	run_xdp_prog(xdp_prog_fd, &data, sizeof(data));

	/* kernel program queues packets with prio 2, 1, 0 (in that order), we
	 * should get back 0 and 1, and 2 should get dropped on dequeue
	 */
	run_dequeue_prog(dequeue_prog_fd, 0);
	run_dequeue_prog(dequeue_prog_fd, 1);
	run_dequeue_prog(dequeue_prog_fd, -1);

	test_xdp_pifo__destroy(skel);
}
