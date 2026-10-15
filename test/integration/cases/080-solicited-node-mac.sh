#!/usr/bin/env bash
# The Ethernet destination of an outgoing solicitation.
#
# The solicited-node multicast MAC is 33:33 followed by the last four bytes
# of the IPv6 *destination* ff02::1:ffXX:XXXX -- so always 33:33:ff:.. .
# ndppd used to build it from the last four bytes of the *target*, which for
# any EUI-64 address puts 0xfe there instead of 0xff.  Targets never saw the
# probe, sessions stayed INCOMPLETE, and running tcpdump "fixed" it by
# flooding the frame to every port.  Fixed in #93.
#
# A veth peer cannot catch this on its own: it accepts the frame on the
# strength of the IPv6 destination alone, because there is no hardware
# filter in the path.  So the case looks at the frame.
set -u
. "$LIB/topology.sh"
. "$LIB/assert.sh"

topo_up
topo_add_down_addr "$TOPO_DOWN_EUI_ADDR"

read -r SOLICITED_IP SOLICITED_MAC < <(python3 "$LIB/ndtool.py" solicited-node "$TOPO_DOWN_EUI_HOST")
diag "target $TOPO_DOWN_EUI_HOST -> $SOLICITED_IP at $SOLICITED_MAC"

topo_ndppd_start "
proxy rt0 {
    router yes
    rule 2001:db8:0:1::/64 {
        iface rt1
    }
}"

capture="$(topo_rundir)/down.capture"

# Watch the downstream link, then make ndppd solicit.
topo_ns down python3 "$LIB/ndtool.py" sniff \
    --iface down0 --seconds 8 --type NS --target "$TOPO_DOWN_EUI_HOST" --count 1 \
    > "$capture" 2>&1 &
sniffer=$!

sleep 0.5

UP_MAC="$(topo_mac up up0)"
topo_ns up python3 "$LIB/ndtool.py" send-ns \
    --iface up0 --src-mac "$UP_MAC" --dst-mac 33:33:ff:00:ab:cd \
    --src-ip "$TOPO_UP_HOST" --dst-ip "$SOLICITED_IP" \
    --target "$TOPO_DOWN_EUI_HOST" >/dev/null 2>&1

wait "$sniffer" 2>/dev/null
captured="$(cat "$capture")"

assert_ok "$([ -n "$captured" ] && echo 0 || echo 1)" \
    "ndppd solicited the EUI-64 target downstream"
diag "$captured"

assert_alive "ndppd is still running"

if [ -n "$captured" ]; then
    got="$(printf '%s\n' "$captured" | sed -n 's/.*eth_dst=\([0-9a-f:]*\).*/\1/p' | head -1)"

    if [ "$got" = "$SOLICITED_MAC" ]; then
        _result 0 "the solicitation went to the solicited-node MAC $SOLICITED_MAC"
    else
        _result 1 "the solicitation went to the solicited-node MAC $SOLICITED_MAC"
        diag "  got $got -- 33:33:fe:.. means the MAC is being built from the target, not the destination"
    fi

    # The destination address itself must be the solicited-node address,
    # not the target and not all-nodes.
    ip_dst="$(printf '%s\n' "$captured" | sed -n 's/.*ip_dst=\([0-9a-f:]*\).*/\1/p' | head -1)"
    if [ "$ip_dst" = "$SOLICITED_IP" ]; then
        _result 0 "the solicitation went to $SOLICITED_IP"
    else
        _result 1 "the solicitation went to $SOLICITED_IP"
        diag "  got $ip_dst"
    fi
fi

assert_summary
