#!/bin/bash
# Unicast neighbor unreachability detection -- the failure #93 was opened
# for, and the one that makes a proxy look like it works and then stop.
#
# Once a neighbor entry exists, NUD refreshes it with a unicast NS sent
# straight to the proxy's MAC, and RFC 4861 7.7.3 says that probe SHOULD
# omit the source link-layer address option because the sender already
# knows the address.  ndppd used to hard-return when the option was absent,
# so it either dropped the probe or replied with an unsolicited NA to
# ff02::1 -- and an unsolicited NA does not satisfy a NUD PROBE transition
# (7.3.5).  The upstream entry went FAILED every few minutes.
#
# Linux always includes the option on its own probes, so the packet has to
# be built by hand.
set -u
. "$LIB/topology.sh"
. "$LIB/assert.sh"

topo_up

topo_ndppd_start "
proxy rt0 {
    router yes
    rule 2001:db8:0:1::/64 {
        iface rt1
    }
}"

# Establish the session first: NUD only probes an entry that already exists.
assert_reachable up "$TOPO_DOWN_HOST" \
    "the target is reachable, so a neighbor entry now exists"

UP_MAC="$(topo_mac up up0)"
RT_MAC="$(topo_mac rt rt0)"
diag "upstream $UP_MAC, proxy $RT_MAC"

# The probe: unicast to the proxy's MAC and to the target's unicast
# address, with no source link-layer option.
out="$(topo_ns up python3 "$LIB/ndtool.py" probe \
    --iface up0 --src-mac "$UP_MAC" --dst-mac "$RT_MAC" \
    --src-ip "$TOPO_UP_HOST" --dst-ip "$TOPO_DOWN_HOST" \
    --target "$TOPO_DOWN_HOST" --no-sllao 2>&1)"
rc=$?

assert_exit 0 "$rc" "a unicast NS with no SLLAO is answered"
diag "$out"

if [ "$rc" -eq 0 ]; then
    # The flag is the whole point.  An advertisement without SOLICITED does
    # not move a neighbor entry out of PROBE, so the entry fails anyway and
    # the symptom is unchanged.
    case "$out" in
        *solicited*) _result 0 "the advertisement has the SOLICITED flag set" ;;
        *) _result 1 "the advertisement has the SOLICITED flag set"
           diag "  an unsolicited NA does not satisfy a NUD PROBE transition" ;;
    esac

    # It must come back to the prober, not to all-nodes multicast.
    case "$out" in
        *"ip_dst=$TOPO_UP_HOST"*) _result 0 "the advertisement was unicast back to the prober" ;;
        *) _result 1 "the advertisement was unicast back to the prober"
           diag "  expected ip_dst=$TOPO_UP_HOST" ;;
    esac
fi

assert_alive "ndppd is still running"

assert_summary
