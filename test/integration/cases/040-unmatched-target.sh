#!/usr/bin/env bash
# ndppd must answer only for the prefixes it was configured for.  A proxy
# that answers for everything on the link is worse than no proxy at all: it
# blackholes every address the operator did not mean to delegate.
set -u
. "$LIB/topology.sh"
. "$LIB/assert.sh"

topo_up

# A second downstream address, outside the configured rule.
topo_add_down_addr "2001:db8:0:2::2/64"
topo_ns rt ip -6 route add 2001:db8:0:2::/64 dev rt1

topo_ndppd_start "
proxy rt0 {
    router yes
    rule 2001:db8:0:1::/64 {
        iface rt1
    }
}"

assert_reachable up "$TOPO_DOWN_HOST" \
    "the address inside the rule is reachable"

assert_unreachable up "2001:db8:0:2::2" \
    "an address outside every rule stays unreachable"

assert_alive "ndppd is still running"

assert_log_matches "no rule matches tgt=2001:db8:0:2::2" \
    "ndppd said why it dropped the unmatched solicitation"
assert_log_not_matches "Write NA tgt=2001:db8:0:2::2" \
    "ndppd never advertised the unmatched address"

assert_summary
