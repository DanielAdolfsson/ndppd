#!/usr/bin/env bash
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
# Runs the integration cases and emits TAP.
#
# Usage:
#   test/integration/run.sh [--binary PATH] [case-name ...]
#
# The suite drives a daemon binary plus a configuration file and asserts on
# observable behaviour only. It makes no assumptions about ndppd's internals,
# so it can be pointed at any build -- or at another implementation
# altogether -- with --binary.

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
export LIB="$HERE/lib"
# The source tree, so a case can check the binary against the documentation
# shipped alongside it.
export SRCDIR="$(cd "$HERE/../.." && pwd)"

NDPPD_BINARY="${NDPPD_BINARY:-$HERE/../../ndppd}"
SELECT=()

while [ $# -gt 0 ]; do
    case "$1" in
        --binary) NDPPD_BINARY="$2"; shift 2 ;;
        --binary=*) NDPPD_BINARY="${1#*=}"; shift ;;
        --list) ls "$HERE/cases" | sed 's/\.sh$//'; exit 0 ;;
        -h|--help) sed -n '18,27p' "$0"; exit 0 ;;
        *) SELECT+=("$1"); shift ;;
    esac
done

skip_all() {
    echo "TAP version 13"
    echo "1..0 # SKIP $1"
    exit 0
}

# --- preconditions -------------------------------------------------------

[ -x "$NDPPD_BINARY" ] || skip_all "ndppd binary not found at $NDPPD_BINARY (run 'make' first)"

# The backend owns everything platform-specific, including what this host
# must provide before the suite can run at all.  Sourcing it here costs
# nothing -- a backend file only defines functions.
case "$(uname -s)" in
    Linux)   . "$LIB/topology-linux.sh" ;;
    FreeBSD) . "$LIB/topology-freebsd.sh" ;;
    *)       skip_all "no topology backend for $(uname -s)" ;;
esac

if ! PREFLIGHT="$(topo_platform_preflight)"; then
    skip_all "$PREFLIGHT"
fi

export NDPPD_BINARY

# --- case isolation ------------------------------------------------------
#
# On Linux each case gets its own user+network namespace, so a case that
# leaves interfaces or a stray daemon behind cannot affect the next one --
# the namespace and everything in it is reclaimed when the process exits.
#
# FreeBSD has no unprivileged equivalent, and a VNET jail is already a
# separate network stack owned by a name rather than by a process.  Cases
# name their jails after their own PID and destroy them on exit, which
# gives the same isolation without a second mechanism.

if [ "$(uname -s)" = "Linux" ]; then
    run_case() { unshare -Urn bash "$1"; }
else
    run_case() { bash "$1"; }
fi

# --- run -----------------------------------------------------------------

cases=()
if [ "${#SELECT[@]}" -gt 0 ]; then
    for s in "${SELECT[@]}"; do
        if [ -f "$HERE/cases/$s" ]; then cases+=("$HERE/cases/$s")
        elif [ -f "$HERE/cases/$s.sh" ]; then cases+=("$HERE/cases/$s.sh")
        else echo "no such case: $s" >&2; exit 2; fi
    done
else
    for f in "$HERE"/cases/*.sh; do cases+=("$f"); done
fi

echo "TAP version 13"

n=0
failed=0

for case_file in "${cases[@]}"; do
    name="$(basename "$case_file" .sh)"
    echo "# Subtest: $name"

    output="$(run_case "$case_file" 2>&1)"
    rc=$?

    while IFS= read -r line; do
        case "$line" in
            "ok - "*)     n=$((n+1)); echo "ok $n - ${line#ok - }" ;;
            "not ok - "*) n=$((n+1)); echo "not ok $n - ${line#not ok - }" ;;
            "#"*)         echo "$line" ;;
            "")           ;;
            # Anything else -- a shell job-control notice, a sanitizer
            # report, a stray warning -- becomes a TAP comment rather than
            # corrupting the stream.
            *)            echo "# $line" ;;
        esac
    done <<< "$output"

    if [ $rc -ne 0 ]; then
        failed=1
        # A case that dies before emitting anything would otherwise vanish.
        if [ -z "$output" ]; then
            n=$((n+1))
            echo "not ok $n - $name produced no output (exit $rc)"
        fi
    fi
done

echo "1..$n"

if [ $failed -ne 0 ]; then
    echo "# FAILED"
    exit 1
fi

echo "# passed $n"
