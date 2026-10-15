#!/bin/bash
# Regression test for issue #68, "session::send_solicit spuriously fails to
# find an interface in auto mode".
#
# Two downstream addresses sit behind one routing-table entry. The first
# solicitation resolves the route and opens the interface; the second finds
# the same route object with its interface already cached.
#
# KNOWN BUG: route::ifa() returns the interface only on the call that opens
# it --
#
#     ptr<iface> route::ifa() {
#         if (!_ifa) { ... return _ifa = iface::open_ifd(_ifname); }
#         return ptr<iface>();          // <- null once _ifa is cached
#     }
#
# -- so every later target behind the same route gets a null interface,
# proxy.cc skips add_iface(), and the session solicits on nothing. The log
# signature is exactly the one in issue #68: `_ifaces.size() = 0` followed
# by "session is now invalid". The route list is rebuilt every route-ttl
# milliseconds, which resets the cache and is why the failure looks
# intermittent in production.
#
# The fix is to return _ifa instead of a null ptr. This has been present
# since 0.2.2 (commit 6723f2f).
set -u
. "$LIB/topology.sh"
. "$LIB/assert.sh"

topo_up

SECOND="2001:db8:0:1::3"
topo_add_down_addr "$SECOND/64"

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

# Touch the first target so the route object caches its interface.
topo_ns up ping -6 -c 1 -W 3 "$TOPO_DOWN_HOST" >/dev/null 2>&1 || true

assert_log_matches "opening interface 'rt1'" \
    "the first target opened the downstream interface"
assert_log_matches "send_solicit\(\) \(_ifaces.size\(\) = 1\)" \
    "the first target had an interface to solicit on"

# Now a second target behind the same route.
topo_ns up ping -6 -c 1 -W 3 "$SECOND" >/dev/null 2>&1 || true

assert_log_matches "send_solicit\(\) \(_ifaces.size\(\) = 0\)" \
    "current behaviour: the second target has no interface to solicit on"

todo "route::ifa() returns null once _ifa is cached; see src/route.cc"
assert_log_not_matches "send_solicit\(\) \(_ifaces.size\(\) = 0\)" \
    "every target behind a route gets an interface to solicit on"

assert_summary
