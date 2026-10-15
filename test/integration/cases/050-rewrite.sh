#!/usr/bin/env bash
# `rewrite` lets a rule advertise one prefix upstream while soliciting a
# different one downstream -- a public prefix in front of addresses that are
# really ULAs.  ndppd rewrites only the neighbor discovery; forwarding the
# traffic afterwards is someone else's job, so this case asserts on the
# discovery exchange rather than on reachability.
set -u
. "$LIB/topology.sh"
. "$LIB/assert.sh"

PUBLIC="2001:db8:0:a::2"
INTERNAL="$TOPO_DOWN_HOST"

topo_up

topo_ndppd_start "
proxy rt0 {
    router yes
    rule 2001:db8:0:a::/64 {
        iface rt1
        rewrite 2001:db8:0:1::/64
    }
}"

UP_MAC="$(topo_mac up up0)"
RT_MAC="$(topo_mac rt rt0)"

# Solicit the public address from upstream and wait for the advertisement.
out="$(topo_ns up python3 "$LIB/ndtool.py" probe \
    --iface up0 --src-mac "$UP_MAC" --dst-mac 33:33:ff:00:00:02 \
    --src-ip "$TOPO_UP_HOST" --dst-ip ff02::1:ff00:2 --target "$PUBLIC" 2>&1)"
rc=$?

assert_exit 0 "$rc" "ndppd advertised the public address"
diag "$out"

assert_alive "ndppd is still running"

assert_log_matches "Write NS iface=rt1, tgt=$INTERNAL" \
    "ndppd solicited the rewritten address downstream"
assert_log_matches "Write NA tgt=$PUBLIC" \
    "ndppd advertised the public address upstream"
assert_log_not_matches "Write NA tgt=$INTERNAL" \
    "the internal address is never advertised upstream"

assert_summary
