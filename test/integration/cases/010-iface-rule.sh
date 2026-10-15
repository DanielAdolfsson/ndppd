#!/usr/bin/env bash
# An `iface` rule is the most common ndppd configuration: proxy for a prefix
# that lives behind a named downstream interface.  ndppd must solicit the
# target on that interface and answer upstream only once the target replies.
set -u
. "$LIB/topology.sh"
. "$LIB/assert.sh"

topo_up

# Without ndppd the upstream router has nobody to answer its solicitation,
# so the downstream host is unreachable.  If this ever passes, the topology
# is wrong and every other assertion in this file is meaningless.
assert_unreachable up "$TOPO_DOWN_HOST" \
    "downstream host is unreachable before ndppd starts"

topo_ndppd_start "
proxy rt0 {
    router yes
    rule 2001:db8:0:1::/64 {
        iface rt1
    }
}"

assert_reachable up "$TOPO_DOWN_HOST" \
    "an iface rule makes the downstream host reachable"

assert_alive "ndppd is still running"

assert_log_matches "Handle NS .*tgt=$TOPO_DOWN_HOST" \
    "ndppd logged the incoming neighbor solicitation"
assert_log_matches "Write NS iface=rt1, tgt=$TOPO_DOWN_HOST" \
    "ndppd solicited the target on the downstream interface"
assert_log_matches "Write NA tgt=$TOPO_DOWN_HOST" \
    "ndppd advertised the target upstream"

assert_summary
