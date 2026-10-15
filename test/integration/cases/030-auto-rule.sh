#!/usr/bin/env bash
# An `auto` rule resolves the downstream interface from the routing table
# rather than from the config, which is what makes it survive an interface
# being renamed or appearing late.  ndppd must find the route, solicit on
# the interface the route names, and answer only once the target replies.
set -u
. "$LIB/topology.sh"
. "$LIB/assert.sh"

topo_up

assert_unreachable up "$TOPO_DOWN_HOST" \
    "downstream host is unreachable before ndppd starts"

topo_ndppd_start "
proxy rt0 {
    router yes
    rule 2001:db8:0:1::/64 {
        auto
    }
}"

assert_reachable up "$TOPO_DOWN_HOST" \
    "an auto rule makes the downstream host reachable"

assert_alive "ndppd is still running"

# The point of auto: the interface came from the routing table, and rt1 is
# where the 2001:db8:0:1::/64 route points.
assert_log_matches "Write NS iface=rt1, tgt=$TOPO_DOWN_HOST" \
    "ndppd resolved the downstream interface from the routing table"
assert_log_matches "Write NA tgt=$TOPO_DOWN_HOST" \
    "ndppd advertised the target upstream"

assert_summary
