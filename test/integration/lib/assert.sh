# ndppd - NDP Proxy Daemon
# Copyright (C) 2011-2026  Daniel Adolfsson <daniel@ashen.se>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# Assertion vocabulary for the integration cases.
#
# Cases emit unnumbered TAP ("ok - description"); run.sh renumbers them into
# a single stream. A case exits non-zero if any non-TODO assertion failed.

ASSERT_FAILURES=0
ASSERT_TODO=""

# todo "<reason>" marks the *next* assertion as a known failure: it is
# reported but does not fail the run. Used to pin down bugs that the suite
# has reproduced but that are out of scope to fix here. Delete the todo line
# when the bug is fixed and the assertion starts enforcing the fix.
todo() { ASSERT_TODO="$1"; }

diag() { printf '# %s\n' "$*"; }

_result() { # $1=pass(0/1) $2=description
    local pass="$1" desc="$2" reason="$ASSERT_TODO"
    ASSERT_TODO=""

    if [ "$pass" -eq 0 ]; then
        if [ -n "$reason" ]; then
            printf 'ok - %s # TODO %s\n' "$desc" "$reason"
        else
            printf 'ok - %s\n' "$desc"
        fi
        return 0
    fi

    if [ -n "$reason" ]; then
        printf 'not ok - %s # TODO %s\n' "$desc" "$reason"
    else
        printf 'not ok - %s\n' "$desc"
        ASSERT_FAILURES=$((ASSERT_FAILURES + 1))
    fi
    return 1
}

assert_ok()   { _result "$([ "$1" = "0" ] && echo 0 || echo 1)" "$2"; }
assert_true() { if "$@" >/dev/null 2>&1; then _result 0 "$ASSERT_DESC"; else _result 1 "$ASSERT_DESC"; fi; }

# assert_reachable <ns> <address> <description>
#
# topo_ping rather than a ping command line: the per-packet timeout is in
# seconds on Linux and milliseconds on FreeBSD, so the backend owns the
# dialect and this file states the intent.
assert_reachable() {
    local ns="$1" addr="$2" desc="$3"
    if topo_ping "$ns" 2 3 "$addr"; then
        _result 0 "$desc"
    else
        _result 1 "$desc" || diag "  $addr was not reachable from namespace '$ns'"
    fi
}

# assert_unreachable <ns> <address> <description>
assert_unreachable() {
    local ns="$1" addr="$2" desc="$3"
    if topo_ping "$ns" 1 2 "$addr"; then
        _result 1 "$desc" || diag "  $addr was unexpectedly reachable from '$ns'"
    else
        _result 0 "$desc"
    fi
}

# assert_log_matches <extended-regex> <description>
assert_log_matches() {
    local re="$1" desc="$2"
    if grep -Eq -- "$re" "$(topo_logfile)" 2>/dev/null; then
        _result 0 "$desc"
    else
        _result 1 "$desc" || diag "  no line in the ndppd log matched: $re"
    fi
}

# assert_log_not_matches <extended-regex> <description>
assert_log_not_matches() {
    local re="$1" desc="$2"
    if grep -Eq -- "$re" "$(topo_logfile)" 2>/dev/null; then
        _result 1 "$desc" || diag "  unexpected log line matching: $re"
        grep -E -- "$re" "$(topo_logfile)" | head -3 | sed 's/^/#   /'
    else
        _result 0 "$desc"
    fi
}

assert_exit() { # $1=expected $2=actual $3=description
    if [ "$1" = "$2" ]; then _result 0 "$3"
    else _result 1 "$3" || diag "  expected exit $1, got $2"; fi
}

assert_summary() {
    [ "$ASSERT_FAILURES" -eq 0 ] && exit 0
    diag "$ASSERT_FAILURES assertion(s) failed"
    exit 1
}

# assert_alive <description> -- the daemon under test is still running.
# A case that drives ndppd into a crash must say so, or the failure arrives
# disguised as "the host was unreachable".
assert_alive() {
    if topo_ndppd_alive; then
        _result 0 "$1"
    else
        _result 1 "$1" || diag "  the ndppd process is no longer running"
        tail -5 "$(topo_logfile)" 2>/dev/null | sed 's/^/#   /'
    fi
}
