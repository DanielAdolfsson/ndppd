#!/bin/bash
#
# A hand-driven network-namespace sandbox, kept from before the automated
# suite in test/integration existed.  That suite covers everything this
# script's plain "up" mode does, and covers it unprivileged and with
# assertions -- use it instead for anything routine.
#
# What is kept here and nowhere else is the "mld-up" mode, which builds the
# same topology with multicast flooding disabled and an MLD querier running
# on both bridges.  That reproduces issue #55: a snooping switch forwards
# solicited-node multicast only to ports that have reported interest, ndppd
# does not report interest in the addresses it proxies for, and so it is
# bypassed entirely.  The automated suite has no MLD coverage, so until it
# does, this is the only reproduction in the tree.
#
# Unlike the automated suite this needs root -- it creates namespaces and
# bridges in the host's own network stack, and leaves them there until
# "down" is run.
#
#   sudo ./test/manual/netns-sandbox.sh up        # or mld-up
#   sudo ./test/manual/netns-sandbox.sh ndppd     # in a second terminal
#   sudo ./test/manual/netns-sandbox.sh ping1
#   sudo ./test/manual/netns-sandbox.sh down
#
# Build ndppd first; "ndppd" below runs the binary from the repository root.

set -u

here="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
root="$(CDPATH= cd -- "${here}/../.." && pwd)"

case "${1-}" in
"down")
  ip netns del ndppd.0
  ip netns del ndppd.rt
  ip netns del ndppd.1
  ip link del ndppd.br0
  ip link del ndppd.br1
  exit 0
  ;;

"up" | "mld-up")
  ip netns add ndppd.0
  ip netns add ndppd.rt
  ip netns add ndppd.1

  ip link add ndppd.0 type veth peer name ndppd.0b
  ip link add ndppd.rt0 type veth peer name ndppd.rt0b
  ip link add ndppd.rt1 type veth peer name ndppd.rt1b
  ip link add ndppd.1 type veth peer name ndppd.1b

  ip link set ndppd.0 netns ndppd.0
  ip link set ndppd.rt0 netns ndppd.rt
  ip link set ndppd.rt1 netns ndppd.rt
  ip link set ndppd.1 netns ndppd.1

  ip link add name ndppd.br0 type bridge
  ip link add name ndppd.br1 type bridge

  ip link set ndppd.0b master ndppd.br0
  ip link set ndppd.rt0b master ndppd.br0
  ip link set ndppd.rt1b master ndppd.br1
  ip link set ndppd.1b master ndppd.br1

  if [ "${1}" = "mld-up" ]; then
    ip link set ndppd.0b type bridge_slave mcast_flood off
    ip link set ndppd.rt0b type bridge_slave mcast_flood off
    ip link set ndppd.rt1b type bridge_slave mcast_flood off
    ip link set ndppd.1b type bridge_slave mcast_flood off
    ip link set dev ndppd.br0 type bridge mcast_querier 1
    ip link set dev ndppd.br1 type bridge mcast_querier 1
  else
    ip link set ndppd.0b type bridge_slave mcast_flood on
    ip link set ndppd.rt0b type bridge_slave mcast_flood on
    ip link set ndppd.rt1b type bridge_slave mcast_flood on
    ip link set ndppd.1b type bridge_slave mcast_flood on
    ip link set dev ndppd.br0 type bridge mcast_querier 0
    ip link set dev ndppd.br1 type bridge mcast_querier 0
  fi

  ip link set ndppd.0b up
  ip link set ndppd.rt0b up
  ip link set ndppd.rt1b up
  ip link set ndppd.1b up

  ip link set ndppd.br0 up
  ip link set ndppd.br1 up

  ip netns exec ndppd.0 ip link set ndppd.0 up
  ip netns exec ndppd.rt ip link set ndppd.rt0 up
  ip netns exec ndppd.rt ip link set ndppd.rt1 up
  ip netns exec ndppd.1 ip link set ndppd.1 up

  ip netns exec ndppd.0 ip -6 addr add dead::1/64 dev ndppd.0
  ip netns exec ndppd.0 ip -6 addr add dead::2/64 dev ndppd.0

  while ! ip netns exec ndppd.0 ip -6 route add default dev ndppd.0 src dead::1 &>/dev/null; do
    sleep 1
  done

  ip netns exec ndppd.rt ip -6 addr add dead::/64 dev ndppd.rt0
  ip netns exec ndppd.rt ip -6 addr add dead:1::/64 dev ndppd.rt1

  ip netns exec ndppd.1 ip -6 addr add dead:1::1/64 dev ndppd.1
  ip netns exec ndppd.1 ip -6 addr add dead:1::2/64 dev ndppd.1

  while ! ip netns exec ndppd.1 ip -6 route add default dev ndppd.1 src dead:1::1 &>/dev/null; do
    sleep 1
  done

  ip netns exec ndppd.rt sysctl -q net.ipv6.conf.all.forwarding=1
  ;;

"ndppd")
  ip netns exec ndppd.rt "${root}/ndppd" -c "${here}/ndppd.test.conf" -vvv
  ;;

"ping0")
  ip netns exec ndppd.1 ping -6 dead::1
  ;;

"ping1")
  ip netns exec ndppd.0 ping -6 dead:1::1
  ;;

*)
  echo "usage: $0 {up|mld-up|ndppd|ping0|ping1|down}" >&2
  exit 1
  ;;
esac
