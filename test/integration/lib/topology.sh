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
# The three-host test topology, and the lifecycle of the daemon under test.
#
#     ns:up  ---- link ---- ns:rt ---- link ---- ns:down
#   2001:db8::1/48      2001:db8::2/48          2001:db8:0:1::2/64
#                   2001:db8:0:1::1/64
#                        [ ndppd ]
#
# "up" is the upstream router.  It believes the entire 2001:db8::/48 is
# on-link, so to reach anything downstream it emits a neighbor solicitation
# onto the link and waits for someone to claim the address.  Nobody does --
# that is ndppd's job.  This is the situation every ndppd deployment is in:
# a provider that routes a prefix on-link rather than to a next hop.
#
# This file is platform-independent.  Everything that needs a kernel's own
# vocabulary for "a separate network stack" lives in a backend:
#
#   topology-linux.sh     network namespaces, veth pairs, iproute2
#   topology-freebsd.sh   VNET jails, epair interfaces, ifconfig
#
# A backend must provide exactly these, and nothing else may differ:
#
#   topo_platform_preflight   print why this host cannot run the suite and
#                             return 1; return 0 when it can
#   topo_build                create the three stacks, the two links, the
#                             addresses and the routes
#   topo_teardown             destroy them
#   topo_ns <ns> <cmd...>     run a command inside one of the stacks
#   topo_add_down_addr <cidr> give the downstream host another address
#   topo_mac <ns> <iface>     the interface's hardware address
#   topo_ping <ns> <count> <wait-seconds> <addr>
#                             ping, in the local ping's dialect
#
# Interface names are part of the contract too: a case names rt0 and rt1 in
# the ndppd configuration it writes, so both backends must deliver
# interfaces under exactly those names.
#
# Keeping the seam here rather than in the cases is what lets the same
# cases run unmodified on both platforms -- no case file names an interface
# type, a namespace mechanism or a tool.

TOPO_RUN=""
TOPO_NDPPD_PID=""

# Addresses are added without duplicate address detection: DAD would
# otherwise hold every address tentative for the first second of each case,
# and a tentative source address makes ping fail for reasons that have
# nothing to do with ndppd.
TOPO_UP_ADDR="2001:db8::1/48"
TOPO_UP_HOST="2001:db8::1"
TOPO_RT_UP_ADDR="2001:db8::2/48"
TOPO_RT_DOWN_ADDR="2001:db8:0:1::1/64"
TOPO_DOWN_ADDR="2001:db8:0:1::2/64"
TOPO_DOWN_HOST="2001:db8:0:1::2"

# A second downstream address whose low three bytes make the solicited-node
# multicast MAC 33:33:ff:xx:xx:xx differ from 33:33:fe:xx:xx:xx -- see
# case 080.
TOPO_DOWN_EUI_ADDR="2001:db8:0:1::fe00:abcd/64"
TOPO_DOWN_EUI_HOST="2001:db8:0:1::fe00:abcd"

topo_logfile() { printf '%s/ndppd.log\n' "$TOPO_RUN"; }
topo_conffile() { printf '%s/ndppd.conf\n' "$TOPO_RUN"; }
topo_rundir() { printf '%s\n' "$TOPO_RUN"; }

# --- backend selection ---------------------------------------------------

TOPO_PLATFORM="$(uname -s)"

case "$TOPO_PLATFORM" in
    Linux)   . "$LIB/topology-linux.sh" ;;
    FreeBSD) . "$LIB/topology-freebsd.sh" ;;
    *)
        echo "Bail out! no topology backend for $TOPO_PLATFORM" >&2
        exit 1
        ;;
esac

# --- the parts that are the same everywhere ------------------------------

topo_up() {
    TOPO_RUN="$(mktemp -d)"
    topo_build
}

# topo_ndppd_start <config-text> [extra args...]
topo_ndppd_start() {
    local conf="$1"; shift
    printf '%s\n' "$conf" > "$(topo_conffile)"

    # stdbuf: ndppd logs with printf(3), so with stdout on a file instead of
    # a terminal the C library buffers it in 4 KiB blocks and a case that
    # greps the log while the daemon is still running sees an empty file.
    # stdbuf(1) is in the base system on both platforms.
    topo_ns rt stdbuf -oL -eL "$NDPPD_BINARY" -c "$(topo_conffile)" -vvv "$@" \
        > "$(topo_logfile)" 2>&1 &
    TOPO_NDPPD_PID=$!

    # Give it time to open its sockets and enter promiscuous mode before the
    # first solicitation arrives.
    sleep 1
}

topo_ndppd_stop() {
    [ -z "$TOPO_NDPPD_PID" ] && return 0
    kill "$TOPO_NDPPD_PID" 2>/dev/null
    # Reap this job only.  A bare `wait` would also wait on the namespace
    # holders, which sleep for ten minutes by design.
    wait "$TOPO_NDPPD_PID" 2>/dev/null
    TOPO_NDPPD_PID=""
    return 0
}

# Whether the daemon we started is still alive.  A case that drives ndppd
# into a crash needs to say so rather than reporting "unreachable".
topo_ndppd_alive() {
    [ -n "$TOPO_NDPPD_PID" ] && kill -0 "$TOPO_NDPPD_PID" 2>/dev/null
}

topo_down() {
    topo_ndppd_stop
    topo_teardown
    [ -n "$TOPO_RUN" ] && rm -rf "$TOPO_RUN"
    return 0
}

trap 'topo_down' EXIT
