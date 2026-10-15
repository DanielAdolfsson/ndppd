#!/bin/bash
# A static rule under sustained upstream traffic, run past its valid-ttl.
#
# A static session has no downstream interface -- that is the whole point of
# static -- but nd_session_update() does not know that.  When VALID ages
# into STALE it calls nd_iface_send_ns(session->iface, ...) with no NULL
# check, and nd_iface_send_ns() reads iface->lladdr as its first act.
#
# The transition only probes when the session was recently solicited, so it
# needs upstream traffic to reach: a static rule nobody is using survives,
# and a static rule carrying traffic dies roughly valid-ttl after it starts.
# valid-ttl is clamped to a 10s minimum by the parser, so that is the wait.
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

todo "static sessions probe on a NULL interface when VALID ages out (see plan/)"
if topo_ndppd_alive; then
    _result 0 "ndppd survives a static rule outliving its valid-ttl"
else
    _result 1 "ndppd survives a static rule outliving its valid-ttl"
fi

# Pinned alongside it: an assertion on *current* behaviour, so the crash
# cannot quietly change shape while the bug is open.  When it is fixed this
# one starts failing, which is the reminder to delete the todo above.
if topo_ndppd_alive; then
    _result 1 "current behaviour: the daemon is gone"
    diag "  ndppd survived -- if the NULL-interface probe was fixed, remove the todo above"
else
    _result 0 "current behaviour: the daemon is gone"
    diag "  last log lines:"
    tail -4 "$(topo_logfile)" | sed 's/^/#     /'
fi

assert_summary
