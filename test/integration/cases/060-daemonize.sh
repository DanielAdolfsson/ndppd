#!/usr/bin/env bash
# `-d` forks into the background and `-p` records the child's PID under an
# exclusive flock, so a second instance cannot start against the same file.
#
# Two things here come straight out of #93.  The parent and the child share
# the AF_PACKET socket across the fork, and the parent's atexit cleanup used
# to drop the interface's promiscuous membership on its way out -- leaving
# the surviving daemon unable to see the solicitations it exists to answer.
# And the PID write check compared write()'s return to 0 instead of the byte
# count, so every successful daemonize logged a failure.
set -u
. "$LIB/topology.sh"
. "$LIB/assert.sh"

topo_up

PIDFILE="$(topo_rundir)/ndppd.pid"
CONF="$(topo_conffile)"
LOG="$(topo_logfile)"

cat > "$CONF" <<CONFEOF
proxy rt0 {
    router yes
    rule 2001:db8:0:1::/64 {
        iface rt1
    }
}
CONFEOF

daemon_pid=""
cleanup_daemon() {
    [ -n "$daemon_pid" ] && kill "$daemon_pid" 2>/dev/null
    return 0
}
trap 'cleanup_daemon; topo_down' EXIT

# The parent exits immediately, so this foreground call returns as soon as
# the fork is done.
topo_ns rt stdbuf -oL -eL "$NDPPD_BINARY" -c "$CONF" -vvv -d -p "$PIDFILE" > "$LOG" 2>&1
assert_exit 0 "$?" "ndppd -d returned success"

for _ in $(seq 1 40); do
    [ -s "$PIDFILE" ] && break
    sleep 0.1
done

assert_ok "$([ -s "$PIDFILE" ] && echo 0 || echo 1)" "a PID file was written"

daemon_pid="$(cat "$PIDFILE" 2>/dev/null)"
diag "daemon pid: ${daemon_pid:-none}"

assert_ok "$(kill -0 "$daemon_pid" 2>/dev/null && echo 0 || echo 1)" \
    "the daemon is running under the PID in the file"

# The spurious error from the old write() check.
assert_log_not_matches "Failed to write PID file" \
    "daemonizing did not log a PID file error"

sleep 1

# The real point: the surviving child can still see solicitations.  If the
# parent's cleanup had dropped promiscuous mode on the shared socket, this
# is where it would show up.
assert_reachable up "$TOPO_DOWN_HOST" \
    "the daemonized process still proxies after the parent exits"

# A second instance must refuse rather than fight over the interface.
second="$(topo_ns rt "$NDPPD_BINARY" -c "$CONF" -d -p "$PIDFILE" 2>&1)"
rc=$?
assert_ok "$([ "$rc" -ne 0 ] && echo 0 || echo 1)" \
    "a second daemon on the same pidfile refuses to start"
diag "second instance said: $second"

assert_summary
