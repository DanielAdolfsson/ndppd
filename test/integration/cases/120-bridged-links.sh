#!/usr/bin/env bash
# ndppd routes between two links, so the links have to be separate.  Bridge
# the upstream interface together with the downstream one -- the usual
# Proxmox shape, uplink NIC and guest taps all ports of vmbr0 -- and the
# guests' own advertisements reach the upstream router directly and
# contradict ndppd's.  It fails intermittently rather than outright, so
# ndppd says so at startup instead of leaving it to be diagnosed.  See #81.
set -u
. "$LIB/topology.sh"
. "$LIB/assert.sh"

topo_up

# --- separate links: nothing to warn about ---------------------------------

topo_ndppd_start "
proxy rt0 {
    rule 2001:db8:0:1::/64 {
        iface rt1
    }
    rule 2001:db8:0:1:1::/80 {
        static
    }
}"

assert_alive "ndppd is running"
assert_log_not_matches "warning +[|]" \
    "separate links routed downstream produce no warning"

topo_ndppd_stop

# --- a static rule routed back out the proxied interface -------------------
#
# This is the configuration in #81: the proxied prefix is on-link on the
# interface being proxied.  Here 2001:db8:0:5::/64 has no route of its own,
# so it falls under the /48 on rt0.

topo_ndppd_start "
proxy rt0 {
    rule 2001:db8:0:5::/64 {
        static
    }
}"

assert_alive "ndppd is running"
assert_log_matches "warning +[|] proxy rt0: rule 2001:db8:0:5::/64 is routed out rt0 .*which is rt0 itself" \
    "a static rule routed back upstream is warned about"

topo_ndppd_stop

# --- upstream and downstream in one bridge ---------------------------------

topo_bridge rt br0 rt0 rt1
assert_ok $? "rt0 and rt1 can be bridged together"

topo_ndppd_start "
proxy rt0 {
    rule 2001:db8:0:1::/64 {
        iface rt1
    }
}
proxy br0 {
    rule 2001:db8:0:2::/64 {
        iface rt1
    }
}"

assert_alive "ndppd keeps running -- this is a warning, not an error"
assert_log_matches "warning +[|] proxy rt0: rule 2001:db8:0:1::/64 uses interface rt1, which is bridged with rt0 \(bridge br0\)" \
    "two ports of the same bridge are warned about"
assert_log_matches "warning +[|] proxy br0: rule 2001:db8:0:2::/64 uses interface rt1, which is bridged with br0 \(bridge br0\)" \
    "proxying a bridge into one of its own ports is warned about"

assert_summary
