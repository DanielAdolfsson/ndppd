#!/bin/bash
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

for tool in unshare nsenter ip ping stdbuf; do
    command -v "$tool" >/dev/null 2>&1 || skip_all "missing required tool: $tool"
done

# Unprivileged user namespaces are not available everywhere -- some
# distributions and container runtimes disable them. Rather than demanding
# root, say why the suite cannot run and skip cleanly.
if ! unshare -Urn true 2>/dev/null; then
    skip_all "unprivileged user+network namespaces are unavailable on this host"
fi

export NDPPD_BINARY

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

    # Each case gets its own user+network namespace, so a case that leaves
    # interfaces or a stray daemon behind cannot affect the next one -- the
    # namespace and everything in it is reclaimed when the process exits.
    output="$(unshare -Urn bash "$case_file" 2>&1)"
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
