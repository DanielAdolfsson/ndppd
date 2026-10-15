#!/bin/bash
# ndppd must answer only for addresses its rules cover. Answering more
# broadly would blackhole traffic for the rest of the on-link prefix, which
# on a shared provider segment means hijacking other tenants' addresses.
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

# Inside the upstream /48, but outside the proxied /64.
OUTSIDE="2001:db8:0:9::1"

assert_unreachable up "$OUTSIDE" \
    "an address outside the rule's prefix stays unreachable"
assert_log_not_matches "write_advert.*taddr=$OUTSIDE" \
    "ndppd did not advertise an address outside its rule"
assert_log_matches "checking 2001:db8:0:1::/64 against $OUTSIDE" \
    "ndppd considered and rejected the out-of-prefix target"

assert_summary
