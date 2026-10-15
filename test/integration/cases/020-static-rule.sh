#!/usr/bin/env bash
# A `static` rule answers for a prefix without checking whether anything is
# actually there.  It is the right configuration when the operator knows the
# topology and does not want the probe round-trip, and the wrong one when
# they do not -- so the test asserts both halves: it answers for the host
# that exists, and it also answers for one that does not.
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
        static
    }
}"

assert_reachable up "$TOPO_DOWN_HOST" \
    "a static rule makes the downstream host reachable"

assert_alive "ndppd is still running"

# A static rule claims the whole prefix, so ndppd advertises for addresses
# behind it whether or not anything answers.  The host is unreachable --
# nothing is there -- but ndppd must have advertised for it anyway, which
# is what distinguishes static from iface.
assert_log_matches "Write NA tgt=$TOPO_DOWN_HOST" \
    "ndppd advertised the target upstream"
assert_log_not_matches "Write NS" \
    "a static rule solicits nothing downstream"

assert_summary
