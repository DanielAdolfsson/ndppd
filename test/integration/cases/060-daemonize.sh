#!/bin/bash
# ndppd normally runs daemonized under an init system. Daemonizing has
# broken proxying before -- issue #39 was ALLMULTI being lost when the
# parent exited -- so the suite checks that a backgrounded ndppd still
# proxies, and that the pidfile names the process that is actually running.
set -u
. "$LIB/topology.sh"
. "$LIB/assert.sh"

topo_up

PIDFILE="$TOPO_RUN/ndppd.pid"

printf '%s\n' "
proxy rt0 {
    router yes
    timeout 500
    ttl 30000
    rule 2001:db8:0:1::/64 {
        iface rt1
    }
}" > "$(topo_conffile)"

# -d detaches, so this returns immediately rather than needing a job.
topo_ns rt "$NDPPD_BINARY" -c "$(topo_conffile)" -p "$PIDFILE" -d \
    > "$(topo_logfile)" 2>&1
assert_exit 0 $? "ndppd -d exits successfully after detaching"

sleep 1

if [ -s "$PIDFILE" ]; then
    _result 0 "a pidfile was written"
    DPID="$(cat "$PIDFILE")"
    if kill -0 "$DPID" 2>/dev/null; then
        _result 0 "the pid in the pidfile belongs to a running process"
    else
        _result 1 "the pid in the pidfile belongs to a running process"
        diag "  pidfile contained $DPID, which is not running"
    fi
else
    _result 1 "a pidfile was written"
    _result 1 "the pid in the pidfile belongs to a running process"
    DPID=""
fi

assert_reachable up "$TOPO_DOWN_HOST" \
    "a daemonized ndppd still proxies solicitations"

[ -n "${DPID:-}" ] && kill "$DPID" 2>/dev/null

assert_summary
