#!/bin/bash

case "$1" in
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

  if [ "$1" = "mld-up" ]; then
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

  ip netns exec ndppd.0 ip -6 addr add dead::1 dev ndppd.0
  ip netns exec ndppd.0 ip -6 route add default dev ndppd.0

  ip netns exec ndppd.rt ip -6 addr add dead:: dev ndppd.rt0
  ip netns exec ndppd.rt ip -6 route add dead::/64 dev ndppd.rt0

  ip netns exec ndppd.rt ip -6 addr add dead:1:: dev ndppd.rt1
  ip netns exec ndppd.rt ip -6 route add dead:1::/64 dev ndppd.rt1

  ip netns exec ndppd.1 ip -6 addr add dead:1::1 dev ndppd.1
  ip netns exec ndppd.1 ip -6 route add default dev ndppd.1

  ip netns exec ndppd.rt sysctl net.ipv6.conf.all.forwarding=1
  ;;

"ndppd")
  ip netns exec ndppd.rt ./ndppd -c ndppd.test.conf -vvv
  ;;

"ping0")
  ip netns exec ndppd.1 ping -6 dead::1
  ;;

"ping1")
  ip netns exec ndppd.0 ping -6 dead:1::1
  ;;
esac
