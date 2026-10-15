#!/bin/bash
# A `static` rule answers solicitations immediately, without first checking
# that anything is actually there. It is the right choice when the operator
# knows the prefix is theirs and wants no resolution latency -- and the
# wrong choice when they do not, which is why the daemon warns about broad
# static prefixes.
set -u
. "$LIB/topology.sh"
. "$LIB/assert.sh"

topo_up

topo_ndppd_start "
proxy rt0 {
    router yes
    timeout 500
    ttl 30000
    rule 2001:db8:0:1::/64 {
        static
    }
}"

assert_reachable up "$TOPO_DOWN_HOST" \
    "a static rule makes the downstream host reachable"

assert_log_matches "write_advert.*taddr=$TOPO_DOWN_HOST" \
    "ndppd advertised the target upstream"
assert_log_not_matches "write_solicit" \
    "a static rule answers without soliciting the target first"

assert_summary
