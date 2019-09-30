#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

# xdp_chain tests
#   Here we setup and teardown configuration required to run
#   xdp_chain, exercising its options.
#
#   Setup is similar to xdping tests.
#
# Topology:
# ---------
#     root namespace   |     tc_ns0 namespace
#                      |
#      ----------      |     ----------
#      |  veth1  | --------- |  veth0  |
#      ----------    peer    ----------
#
# Device Configuration
# --------------------
# Root namespace with BPF
# Device names and addresses:
#	veth1 IP: 10.1.1.200
#
# Namespace tc_ns0 with BPF
# Device names and addresses:
#       veth0 IPv4: 10.1.1.100
#	xdp_chain binary run inside this
#

readonly TARGET_IP="10.1.1.100"
readonly TARGET_NS="xdp_ns0"

readonly LOCAL_IP="10.1.1.200"

setup()
{
	ip netns add $TARGET_NS
	ip link add veth0 type veth peer name veth1
	ip link set veth0 netns $TARGET_NS
	ip netns exec $TARGET_NS ip addr add ${TARGET_IP}/24 dev veth0
	ip addr add ${LOCAL_IP}/24 dev veth1
	ip netns exec $TARGET_NS ip link set veth0 up
	ip link set veth1 up
}

cleanup()
{
	set +e
	ip netns delete $TARGET_NS 2>/dev/null
	ip link del veth1 2>/dev/null
}

die()
{
        echo "$@" >&2
        exit 1
}

test()
{
	args="$1"

	ip netns exec $TARGET_NS ./xdp_chain $args || die "XDP chain test error"
}

set -e

server_pid=0

trap cleanup EXIT

setup

test "-I veth0 -S $LOCAL_IP"

echo "OK. All tests passed"
exit 0
