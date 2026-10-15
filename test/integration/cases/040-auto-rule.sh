#!/bin/bash
# An `auto` rule asks the kernel routing table which interface the target
# lives behind, instead of naming it in the configuration. It is the mode
# ndppd.conf-dist shows first, and the one issue #68 is about.
#
# It does not work on this branch. Two independent defects are reproduced
# below; the reachability assertion is marked TODO so the suite stays green
# while they remain open.
set -u
. "$LIB/topology.sh"
. "$LIB/assert.sh"

topo_up

topo_ndppd_start "
route-ttl 30000
proxy rt0 {
    router yes
    timeout 500
    ttl 30000
    rule 2001:db8:0:1::/64 {
        auto
    }
}"

todo "auto mode is broken on master; see the two assertions below"
assert_reachable up "$TOPO_DOWN_HOST" \
    "an auto rule makes the downstream host reachable"

# ndppd does resolve the route and solicit on the right interface...
assert_log_matches "opening interface 'rt1'" \
    "auto mode resolved the target to the downstream interface"
assert_log_matches "write_solicit.*taddr=$TOPO_DOWN_HOST" \
    "auto mode solicited the target downstream"

# ...and the target does answer...
assert_log_matches "read_advert.*taddr=$TOPO_DOWN_HOST" \
    "the downstream host answered the solicitation"

# ...but ndppd throws the answer away.
#
# KNOWN BUG: iface.cc only accepts an advertisement if some rule has a
# daughter interface whose name matches the one it arrived on:
#
#     ru->addr() == taddr && ru->daughter() && ru->daughter()->name() == ...
#
# An auto rule never has a daughter -- rule::create(proxy, addr, bool) only
# sets _addr and _aut -- so the condition can never hold and every
# advertisement for an auto rule is discarded. The session then times out
# and is marked invalid. The check arrived with the autowire series
# (commit a008fad) and is not present in 0.2.5.
assert_log_matches "advert was ignored" \
    "current behaviour: the advertisement is discarded (auto rules have no daughter interface)"

todo "iface.cc discards adverts for auto rules; see commit a008fad"
assert_log_not_matches "advert was ignored" \
    "ndppd accepts an advertisement for an auto rule"

assert_summary
