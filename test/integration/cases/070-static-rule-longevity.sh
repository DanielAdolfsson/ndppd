#!/bin/bash
# A static rule under sustained upstream traffic, run past its valid-ttl.
#
# A static session has no downstream interface -- that is the whole point of
# static -- but nd_session_update() did not know that.  When VALID aged into
# STALE it called nd_iface_send_ns(session->iface, ...) with no NULL check,
# and nd_iface_send_ns() reads iface->lladdr as its first act.
#
# The transition only probes when the session was recently solicited, so it
# needed upstream traffic to reach: a static rule nobody was using survived,
# and a static rule carrying traffic died roughly valid-ttl after it
# started.  valid-ttl is clamped to a 10s minimum by the parser, so that is
# the wait here.
#
# A static session now stays VALID while it is in use.  That is a second
# fix as much as the first: ageing it into STALE would have stopped it
# answering for stale-ttl plus invalid-ttl while nothing was wrong.
set -u
. "$LIB/topology.sh"
. "$LIB/assert.sh"

topo_up

topo_ndppd_start "
valid-ttl 10000
invalid-ttl 10000

proxy rt0 {
    router yes
    rule 2001:db8:0:1::/64 {
        static
    }
}"

UP_MAC="$(topo_mac up up0)"

assert_reachable up "$TOPO_DOWN_HOST" \
    "the static rule works to begin with"

# Keep soliciting, so the session's last-solicited time stays current and
# ndppd decides the session is worth re-probing as it ages out of VALID.
# ping alone will not do: once the upstream kernel has a neighbor cache
# entry it stops asking.
for _ in $(seq 1 16); do
    topo_ns up python3 "$LIB/ndtool.py" send-ns \
        --iface up0 --src-mac "$UP_MAC" --dst-mac 33:33:ff:00:00:02 \
        --src-ip "$TOPO_UP_HOST" --dst-ip ff02::1:ff00:2 \
        --target "$TOPO_DOWN_HOST" >/dev/null 2>&1
    sleep 1
    topo_ndppd_alive || break
done

assert_alive "ndppd survives a static rule outliving its valid-ttl"

# Still answering, which is the half that a crash would have hidden.
assert_reachable up "$TOPO_DOWN_HOST" \
    "the static rule still works after outliving its valid-ttl"

# It must not have tried to solicit anything. A static rule has no
# downstream interface to solicit on, and the attempt is what used to be
# fatal.
assert_log_not_matches "Write NS" \
    "the static session solicited nothing at any point"

assert_log_not_matches "VALID -> STALE" \
    "the static session never entered STALE"

assert_summary
