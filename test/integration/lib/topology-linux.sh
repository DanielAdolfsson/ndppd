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
# Linux topology backend: network namespaces, veth pairs, iproute2.
#
# Everything here runs unprivileged.  `unshare -Urn` (applied by run.sh)
# grants CAP_NET_ADMIN inside a user namespace, which covers veth pairs,
# addresses, promiscuous mode, the forwarding sysctl and AF_PACKET sockets.
# Extra namespaces are made by parking a child in its own netns and moving a
# veth end in by PID -- `ip netns` would want a bind mount under /run/netns
# and would reintroduce the root requirement this harness exists to avoid.
#
# See topology.sh for the contract this implements.

topo_platform_preflight() {
    local tool
    for tool in unshare nsenter ip ping stdbuf; do
        command -v "$tool" >/dev/null 2>&1 || {
            echo "missing required tool: $tool"
            return 1
        }
    done

    # Unprivileged user namespaces are not available everywhere -- some
    # distributions and container runtimes disable them.  Rather than
    # demanding root, say why the suite cannot run and skip cleanly.
    unshare -Urn true 2>/dev/null || {
        echo "unprivileged user+network namespaces are unavailable on this host"
        return 1
    }

    # `ping` is three different programs.  iputils takes `-6 -c -W`;
    # inetutils and some busybox builds do not, and a ping that cannot be
    # driven this way reports every target as unreachable -- which reads as
    # an ndppd bug rather than as a missing dependency.  This also catches a
    # host with no IPv6 at all.
    ping -6 -c 1 -W 1 ::1 >/dev/null 2>&1 || {
        echo "ping cannot reach ::1 with '-6 -c 1 -W 1' (needs an iputils-style ping and IPv6)"
        return 1
    }

    return 0
}

_topo_mkns() { # $1=name
    # stdout/stderr must be detached, or a $( ) capturing this function
    # blocks until the backgrounded holder exits.
    unshare -n sh -c "echo \$\$ > $TOPO_RUN/$1.pid; exec sleep 600" >/dev/null 2>&1 &
    local i
    for i in $(seq 1 100); do
        [ -s "$TOPO_RUN/$1.pid" ] && break
        sleep 0.05
    done
}

# topo_ns <up|rt|down> <command...>
topo_ns() {
    local ns="$1"; shift
    nsenter -t "$(cat "$TOPO_RUN/$ns.pid")" -n "$@"
}

topo_build() {
    _topo_mkns up
    _topo_mkns rt
    _topo_mkns down

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

    # Written through procfs rather than with sysctl(8): /proc/sys/net is
    # resolved against the *reading* process's network namespace, so this
    # reaches ns:rt through the shared /proc mount and leaves the host
    # alone.  It also drops a procps dependency, and a failure here is loud
    # rather than a silently unrouted topology.
    topo_ns rt sh -c 'echo 1 > /proc/sys/net/ipv6/conf/all/forwarding' || {
        echo "Bail out! could not enable IPv6 forwarding in ns:rt"
        exit 1
    }
}

topo_teardown() {
    local ns pid
    for ns in up rt down; do
        [ -s "$TOPO_RUN/$ns.pid" ] || continue
        pid="$(cat "$TOPO_RUN/$ns.pid")"
        kill "$pid" 2>/dev/null
        wait "$pid" 2>/dev/null
    done
    return 0
}

topo_add_down_addr() {
    topo_ns down ip -6 addr add "$1" dev down0 nodad
}

topo_mac() {
    topo_ns "$1" ip -o link show "$2" | sed -n 's/.*link\/ether \([0-9a-f:]*\).*/\1/p'
}

# topo_ping <ns> <count> <wait-seconds> <address>
#
# iputils takes the per-packet reply timeout in *seconds*.  FreeBSD's takes
# it in milliseconds; see the FreeBSD backend.
topo_ping() {
    local ns="$1" count="$2" wait="$3" addr="$4"
    topo_ns "$ns" ping -6 -c "$count" -W "$wait" "$addr" >/dev/null 2>&1
}
