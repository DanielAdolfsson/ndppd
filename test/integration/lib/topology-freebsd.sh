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
# FreeBSD topology backend: VNET jails, epair interfaces, ifconfig.
#
# The Linux backend builds its three network stacks out of unprivileged
# user+network namespaces.  FreeBSD has no unprivileged equivalent: a VNET
# jail and an epair are both root operations, so this backend requires root
# and run.sh says so rather than skipping with a confusing message.  That is
# the one property the two backends cannot share.  Run it in a disposable
# VM -- which is what the FreeBSD CI job is.
#
# The mapping is otherwise one-to-one:
#
#   unshare -n holder process      ->  jail -c vnet persist
#   ip link add ... type veth      ->  ifconfig epair create
#   ip link set X netns PID        ->  ifconfig X vnet <jail>
#   nsenter -t PID -n <cmd>        ->  jexec <jail> <cmd>
#   ip -6 addr add ... nodad       ->  ifconfig ... inet6, dad_count=0
#   /proc/sys/.../forwarding       ->  sysctl net.inet6.ip6.forwarding=1
#
# See topology.sh for the contract this implements.

# Jail names are per-process: run.sh runs each case in its own process, and
# two cases running concurrently must not collide on a name.  A jail name
# may not contain a dot.
TOPO_JAIL_PREFIX="ndppd_$$"

topo_platform_preflight() {
    local tool
    for tool in jail jexec jls ifconfig ping stdbuf sysctl; do
        command -v "$tool" >/dev/null 2>&1 || {
            echo "missing required tool: $tool"
            return 1
        }
    done

    # There is no unprivileged path here, unlike on Linux.  Say that
    # plainly: "missing required tool: jail" would be a lie.
    [ "$(id -u)" = "0" ] || {
        echo "the FreeBSD backend needs root (VNET jails and epair are privileged)"
        return 1
    }

    # VNET is a kernel option.  It is in GENERIC, but a custom kernel can
    # leave it out, and every jail below would then fail one at a time.
    [ "$(sysctl -n kern.features.vimage 2>/dev/null)" = "1" ] || {
        echo "this kernel has no VIMAGE support, so VNET jails cannot be created"
        return 1
    }

    # FreeBSD's ping takes the per-packet timeout in milliseconds, so this
    # is the same one-second probe the Linux backend runs. It confirms both
    # the flag dialect and that the host has IPv6 at all.
    ping -6 -c 1 -W 1000 ::1 >/dev/null 2>&1 || {
        echo "ping cannot reach ::1 with '-6 -c 1 -W 1000' (needs IPv6 and a FreeBSD-style ping)"
        return 1
    }

    return 0
}

_topo_jail() { # $1=ns -- the jail name for a namespace
    printf '%s_%s\n' "$TOPO_JAIL_PREFIX" "$1"
}

_topo_mkjail() { # $1=ns
    # allow.raw_sockets is what lets ping(8) run inside the jail at all.
    # allow.socket_af widens the permitted address families beyond
    # inet/inet6/unix/route; ndppd's routing-socket and BPF paths stay
    # inside the default set, but a denial here would surface as an
    # unexplained failure to open a socket, and the suite is not a security
    # boundary.
    #
    # path=/ gives the jail the host filesystem: this backend isolates the
    # network stack and nothing else, and ndppd needs to reach /dev/bpf.
    jail -c name="$(_topo_jail "$1")" path=/ vnet persist \
        allow.raw_sockets allow.socket_af >/dev/null

    # The Linux backend gets `nodad` per address.  FreeBSD's equivalent is
    # per-stack, and each VNET jail has its own: without it every address
    # stays tentative for a second and a tentative source address makes
    # ping fail for reasons that have nothing to do with ndppd.
    jexec "$(_topo_jail "$1")" sysctl -q net.inet6.ip6.dad_count=0
    jexec "$(_topo_jail "$1")" ifconfig lo0 up
}

# topo_ns <up|rt|down> <command...>
topo_ns() {
    local ns="$1"; shift
    jexec "$(_topo_jail "$ns")" "$@"
}

# _topo_link <a-name> <a-ns> <b-name> <b-ns>
#
# One epair becomes one cable.  The ends are renamed *after* they land in
# their jail: an interface moved between vnets does not reliably keep a
# name given to it in another one, and the case files name rt0 and rt1 in
# the configuration they hand to ndppd, so the names have to be right.
_topo_link() {
    local a_name="$1" a_ns="$2" b_name="$3" b_ns="$4"

    local a b
    a="$(ifconfig epair create)"
    b="${a%a}b"

    ifconfig "$a" vnet "$(_topo_jail "$a_ns")"
    ifconfig "$b" vnet "$(_topo_jail "$b_ns")"

    topo_ns "$a_ns" ifconfig "$a" name "$a_name"
    topo_ns "$b_ns" ifconfig "$b" name "$b_name"

    topo_ns "$a_ns" ifconfig "$a_name" up
    topo_ns "$b_ns" ifconfig "$b_name" up

    # Remember one end per link so teardown can destroy it before the jails
    # go away.  Destroying either end takes the pair with it.
    printf '%s %s\n' "$a_ns" "$a_name" >> "$TOPO_RUN/links"
}

# _topo_addr <ns> <iface> <address/prefixlen>
_topo_addr() {
    local ns="$1" iface="$2" cidr="$3"
    local addr="${cidr%/*}" plen="${cidr#*/}"
    # `alias` so that the second and later addresses on an interface are
    # added rather than replacing the first -- see topo_add_down_addr.
    topo_ns "$ns" ifconfig "$iface" inet6 "$addr" prefixlen "$plen" alias
}

topo_build() {
    : > "$TOPO_RUN/links"

    _topo_mkjail up
    _topo_mkjail rt
    _topo_mkjail down

    _topo_link up0 up   rt0   rt
    _topo_link rt1 rt   down0 down

    _topo_addr up   up0   "$TOPO_UP_ADDR"
    _topo_addr rt   rt0   "$TOPO_RT_UP_ADDR"
    _topo_addr rt   rt1   "$TOPO_RT_DOWN_ADDR"
    _topo_addr down down0 "$TOPO_DOWN_ADDR"

    topo_ns down route -6 -q add default 2001:db8:0:1::1

    topo_ns rt sysctl -q net.inet6.ip6.forwarding=1 || {
        echo "Bail out! could not enable IPv6 forwarding in the rt jail"
        exit 1
    }
}

topo_teardown() {
    # Interfaces first.  Tearing down a VNET jail that still owns epair
    # interfaces has a long history of panicking the host kernel, and a
    # panic in CI costs a whole job rather than one assertion.
    local ns iface
    if [ -s "$TOPO_RUN/links" ]; then
        while read -r ns iface; do
            [ -n "$ns" ] || continue
            topo_ns "$ns" ifconfig "$iface" destroy 2>/dev/null
        done < "$TOPO_RUN/links"
    fi

    for ns in up rt down; do
        jail -r "$(_topo_jail "$ns")" 2>/dev/null
    done
    return 0
}

topo_add_down_addr() {
    _topo_addr down down0 "$1"
}

topo_mac() {
    topo_ns "$1" ifconfig "$2" \
        | sed -n 's/^[[:space:]]*ether \([0-9a-f:]*\).*/\1/p'
}

# topo_ping <ns> <count> <wait-seconds> <address>
#
# FreeBSD's ping takes the per-packet reply timeout in *milliseconds* where
# iputils takes seconds.  A shared "-W 3" would mean three milliseconds
# here and fail every reachability assertion in the suite.
topo_ping() {
    local ns="$1" count="$2" wait="$3" addr="$4"
    topo_ns "$ns" ping -6 -c "$count" -W "$((wait * 1000))" "$addr" >/dev/null 2>&1
}
