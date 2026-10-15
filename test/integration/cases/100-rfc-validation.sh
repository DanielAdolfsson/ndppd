#!/usr/bin/env bash
# The checks RFC 4861 states as MUST, and that #93 added.
#
# Each of these is a packet no cooperating kernel will send, which is
# exactly why they need a hand-built one: a proxy that answers them is
# answering an attacker, and the only way to notice is to ask.
#
# The configuration deliberately includes a rule that would match a
# multicast target.  Without the 7.1.1 check ndppd would find that rule and
# answer; with it the packet never reaches rule matching at all.  A test
# that relied on "no rule matches" would pass for the wrong reason.
set -u
. "$LIB/topology.sh"
. "$LIB/assert.sh"

topo_up

topo_ndppd_start "
proxy rt0 {
    router yes
    rule 2001:db8:0:1::/64 {
        static
    }
    rule ff02::/16 {
        static
    }
}"

UP_MAC="$(topo_mac up up0)"
RT_MAC="$(topo_mac rt rt0)"

# probe_expect <0|1> <description> [extra ndtool args...]
probe_expect() {
    local want="$1" desc="$2"; shift 2
    local out rc

    out="$(topo_ns up python3 "$LIB/ndtool.py" probe \
        --iface up0 --src-mac "$UP_MAC" --dst-mac "$RT_MAC" \
        --src-ip "$TOPO_UP_HOST" --timeout 1 --retries 2 "$@" 2>&1)"
    rc=$?

    if [ "$rc" -eq "$want" ]; then
        _result 0 "$desc"
    else
        _result 1 "$desc"
        diag "  ndtool said: $out"
    fi
}

# The control. If this does not answer, nothing below means anything.
probe_expect 0 "a well-formed solicitation is answered" \
    --dst-ip "$TOPO_DOWN_HOST" --target "$TOPO_DOWN_HOST"

# RFC 4861 6.1.1: the hop limit MUST be 255. Anything lower has been
# forwarded, which means it came from off-link and must not be trusted.
probe_expect 1 "a solicitation with hop limit 64 is discarded" \
    --dst-ip "$TOPO_DOWN_HOST" --target "$TOPO_DOWN_HOST" --hop-limit 64

probe_expect 1 "a solicitation with hop limit 1 is discarded" \
    --dst-ip "$TOPO_DOWN_HOST" --target "$TOPO_DOWN_HOST" --hop-limit 1

# RFC 4861 7.1.1: the target address MUST NOT be multicast. The config has
# a rule that would match ff02::1, so a reply here would be ndppd's own
# decision rather than an accident of rule matching.
probe_expect 1 "a solicitation with a multicast target is discarded" \
    --dst-ip ff02::1 --target ff02::1

probe_expect 1 "a solicitation targeting a solicited-node address is discarded" \
    --dst-ip "$TOPO_DOWN_HOST" --target ff02::1:ff00:2

assert_alive "ndppd is still running"

# The control again, after all of the above: a discarded packet must not
# have left the daemon unable to answer the next good one.
probe_expect 0 "a well-formed solicitation is still answered afterwards" \
    --dst-ip "$TOPO_DOWN_HOST" --target "$TOPO_DOWN_HOST"

assert_summary
