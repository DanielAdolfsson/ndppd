# ndppd - NDP Proxy Daemon
# Copyright (C) 2026  Daniel Adolfsson <daniel@ashen.se>
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
# Builds the three-namespace test topology.
#
#     ns:up  ---- veth ---- ns:rt ---- veth ---- ns:down
#   2001:db8::1/48      2001:db8::2/48          2001:db8:0:1::2/64
#                   2001:db8:0:1::1/64
#
# "up" is the upstream router. It believes the entire 2001:db8::/48 is
# on-link, so to reach anything downstream it emits a neighbor solicitation
# onto the link and waits for someone to claim the address. Nobody does --
# that is ndppd's job.
#
# ndppd runs in "rt" and proxies for the 2001:db8:0:1::/64 that actually
# lives behind it. This is the situation every ndppd deployment is in: a
# provider that routes a prefix on-link rather than to a next hop.
#
# Everything here runs unprivileged. `unshare -Urn` (applied by run.sh)
# grants CAP_NET_ADMIN inside a user namespace, which is enough for veth
# pairs, addresses, promiscuous mode, the forwarding sysctl and AF_PACKET
# sockets. Additional namespaces are created by parking a child process in
# its own netns and moving one end of a veth into it by PID -- `ip netns`
# needs a bind mount under /run/netns and would reintroduce the root
# requirement this harness exists to avoid.

TOPO_RUN=""
TOPO_NDPPD_PID=""

# Addresses are added with `nodad`: duplicate address detection would
# otherwise hold every address "tentative" for the first second of each
# case, and a tentative source address makes ping fail for reasons that have
# nothing to do with ndppd.
TOPO_UP_ADDR="2001:db8::1/48"
TOPO_RT_UP_ADDR="2001:db8::2/48"
TOPO_RT_DOWN_ADDR="2001:db8:0:1::1/64"
TOPO_DOWN_ADDR="2001:db8:0:1::2/64"
TOPO_DOWN_HOST="2001:db8:0:1::2"

topo_logfile() { printf '%s/ndppd.log\n' "$TOPO_RUN"; }
topo_conffile() { printf '%s/ndppd.conf\n' "$TOPO_RUN"; }

_topo_mknetns() { # $1=name; echoes the holder PID
    # stdout/stderr must be detached, or the $( ) capturing this function
    # blocks until the backgrounded holder exits.
    unshare -n sh -c "echo \$\$ > $TOPO_RUN/$1.pid; exec sleep 600" >/dev/null 2>&1 &
    local i
    for i in $(seq 1 100); do
        [ -s "$TOPO_RUN/$1.pid" ] && break
        sleep 0.05
    done
    cat "$TOPO_RUN/$1.pid"
}

# topo_ns <up|rt|down> <command...>
topo_ns() {
    local ns="$1"; shift
    nsenter -t "$(cat "$TOPO_RUN/$ns.pid")" -n "$@"
}

topo_up() {
    TOPO_RUN="$(mktemp -d)"

    _topo_mknetns up   >/dev/null
    _topo_mknetns rt   >/dev/null
    _topo_mknetns down >/dev/null

    ip link add up0 type veth peer name rt0
    ip link add rt1 type veth peer name down0

    ip link set up0   netns "$(cat "$TOPO_RUN/up.pid")"
    ip link set rt0   netns "$(cat "$TOPO_RUN/rt.pid")"
    ip link set rt1   netns "$(cat "$TOPO_RUN/rt.pid")"
    ip link set down0 netns "$(cat "$TOPO_RUN/down.pid")"

    topo_ns up   ip link set lo up
    topo_ns rt   ip link set lo up
    topo_ns down ip link set lo up
    topo_ns up   ip link set up0 up
    topo_ns rt   ip link set rt0 up
    topo_ns rt   ip link set rt1 up
    topo_ns down ip link set down0 up

    topo_ns up   ip -6 addr add "$TOPO_UP_ADDR"      dev up0   nodad
    topo_ns rt   ip -6 addr add "$TOPO_RT_UP_ADDR"   dev rt0   nodad
    topo_ns rt   ip -6 addr add "$TOPO_RT_DOWN_ADDR" dev rt1   nodad
    topo_ns down ip -6 addr add "$TOPO_DOWN_ADDR"    dev down0 nodad

    topo_ns down ip -6 route add default via 2001:db8:0:1::1 dev down0
    topo_ns rt   sysctl -qw net.ipv6.conf.all.forwarding=1
}

# topo_add_down_addr <address/prefix> -- give the downstream host another
# address, used by cases that need two targets behind one route.
topo_add_down_addr() {
    topo_ns down ip -6 addr add "$1" dev down0 nodad
}

# topo_ndppd_start <config-text> [extra args...]
topo_ndppd_start() {
    local conf="$1"; shift
    printf '%s\n' "$conf" > "$(topo_conffile)"

    topo_ns rt "$NDPPD_BINARY" -c "$(topo_conffile)" -vvv "$@" \
        > "$(topo_logfile)" 2>&1 &
    TOPO_NDPPD_PID=$!

    # Give it time to open its sockets and set ALLMULTI before the first
    # solicitation arrives.
    sleep 1
}

topo_ndppd_stop() {
    [ -z "$TOPO_NDPPD_PID" ] && return 0
    kill "$TOPO_NDPPD_PID" 2>/dev/null
    # Reap this job only. A bare `wait` would also wait on the namespace
    # holders, which sleep for ten minutes by design.
    wait "$TOPO_NDPPD_PID" 2>/dev/null
    TOPO_NDPPD_PID=""
    return 0
}

topo_down() {
    topo_ndppd_stop
    local ns pid
    for ns in up rt down; do
        [ -s "$TOPO_RUN/$ns.pid" ] || continue
        pid="$(cat "$TOPO_RUN/$ns.pid")"
        kill "$pid" 2>/dev/null
        wait "$pid" 2>/dev/null
    done
    [ -n "$TOPO_RUN" ] && rm -rf "$TOPO_RUN"
    return 0
}

trap 'topo_down' EXIT
