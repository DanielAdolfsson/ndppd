/*
 * This file is part of ndppd.
 *
 * Copyright (C) 2011-2026  Daniel Adolfsson <daniel@ashen.se>
 *
 * ndppd is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * ndppd is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with ndppd.  If not, see <https://www.gnu.org/licenses/>.
 */

/*
 * The bridging checks in proxy.c.
 *
 * ndppd only works when the upstream link and the link the targets live on
 * are separate.  Bridge the two together -- the usual Proxmox shape, with
 * the uplink NIC and the guests' taps all ports of vmbr0 -- and the guests'
 * own neighbor advertisements reach the upstream router directly, where they
 * contradict the ones ndppd sends on their behalf.  The result is flaky
 * rather than broken, which is what makes it so hard to diagnose from a bug
 * report.  See #81.
 *
 * The checks only warn, so what is asserted is the number of warnings each
 * returns.  Bridge membership comes from fake_bridge_of[], and the routing
 * table from fake_route().
 */
#include <string.h>

#include "fake.h"
#include "ndppd.h"
#include "tap.h"

static nd_proxy_t ndL_proxy;
static nd_rule_t ndL_rule;

static nd_proxy_t *proxy_with(nd_mode_t mode, const char *prefix, int pflen, nd_iface_t *rule_iface)
{
    ndL_proxy = (nd_proxy_t){ 0 };
    strcpy(ndL_proxy.ifname, "up0");
    ndL_proxy.iface = &fake_iface_up;
    ndL_proxy.rules = &ndL_rule;

    ndL_rule = (nd_rule_t){ 0 };
    ndL_rule.proxy = &ndL_proxy;
    ndL_rule.addr = fake_addr(prefix);
    ndL_rule.prefix = pflen;
    ndL_rule.mode = mode;
    ndL_rule.table = 254;
    ndL_rule.iface = rule_iface;

    return &ndL_proxy;
}

void test_proxy(void)
{
    tap_begin("proxy");

    /* --- iface rules ------------------------------------------------------- */

    {
        fake_reset();
        nd_proxy_t *p = proxy_with(ND_MODE_IFACE, "2001:db8:0:1::", 64, &fake_iface_down);

        ok_int(nd_proxy_check_links(p), 0, "separate, unbridged links are not warned about");

        /* The downstream side being a bridge is the normal, working setup:
         * the guests share a bridge with each other, not with upstream. */
        fake_bridge_of[FAKE_IF_DOWN_INDEX] = FAKE_IF_BRIDGE_INDEX;
        ok_int(nd_proxy_check_links(p), 0, "a downstream bridge that upstream is not part of is fine");

        fake_bridge_of[FAKE_IF_UP_INDEX] = FAKE_IF_BRIDGE_INDEX;
        ok_int(nd_proxy_check_links(p), 1, "upstream and downstream ports of the same bridge are warned about");
    }

    {
        fake_reset();

        /* Two different bridges are two different links. */
        fake_bridge_of[FAKE_IF_UP_INDEX] = FAKE_IF_UP_INDEX;
        fake_bridge_of[FAKE_IF_DOWN_INDEX] = FAKE_IF_BRIDGE_INDEX;
        nd_proxy_t *p = proxy_with(ND_MODE_IFACE, "2001:db8:0:1::", 64, &fake_iface_down);
        ok_int(nd_proxy_check_links(p), 0, "proxying one bridge into another is fine");

        /* Proxying the bridge itself while the target is one of its ports. */
        fake_bridge_of[FAKE_IF_DOWN_INDEX] = FAKE_IF_UP_INDEX;
        ok_int(nd_proxy_check_links(p), 1, "a rule interface that is a port of the proxied bridge is warned about");
    }

    {
        fake_reset();
        nd_proxy_t *p = proxy_with(ND_MODE_IFACE, "2001:db8:0:1::", 64, &fake_iface_up);
        ok_int(nd_proxy_check_links(p), 1, "a rule pointing back at the proxied interface is warned about");
    }

    {
        fake_reset();
        fake_bridge_of[FAKE_IF_UP_INDEX] = FAKE_IF_BRIDGE_INDEX;
        fake_bridge_of[FAKE_IF_DOWN_INDEX] = FAKE_IF_BRIDGE_INDEX;

        /* nd_proxy_check_links() is about the interface a rule names; static
         * and auto rules name none. */
        nd_proxy_t *p = proxy_with(ND_MODE_STATIC, "2001:db8:0:1::", 64, NULL);
        ok_int(nd_proxy_check_links(p), 0, "a static rule names no interface to check");
    }

    /* --- static rules, against the routing table ---------------------------- */

    {
        fake_reset();
        nd_proxy_t *p = proxy_with(ND_MODE_STATIC, "2001:db8:0:1::", 64, NULL);

        ok_int(nd_proxy_check_routes(p), 0, "a static rule with no route at all is not warned about");

        fake_route("2001:db8:0:1::/64", FAKE_IF_DOWN_INDEX, 254);
        ok_int(nd_proxy_check_routes(p), 0, "a static rule routed downstream is fine");
    }

    {
        /* The configuration in #81: the prefix is on-link on vmbr0, and
         * vmbr0 is what is being proxied. */
        fake_reset();
        nd_proxy_t *p = proxy_with(ND_MODE_STATIC, "2001:db8:0:1::", 64, NULL);
        fake_route("2001:db8:0:1::/64", FAKE_IF_UP_INDEX, 254);
        ok_int(nd_proxy_check_routes(p), 1, "a static rule routed back out the proxied interface is warned about");
    }

    {
        fake_reset();
        nd_proxy_t *p = proxy_with(ND_MODE_STATIC, "2001:db8:0:1::", 64, NULL);
        fake_route("2001:db8:0:1::/64", FAKE_IF_DOWN_INDEX, 254);
        fake_bridge_of[FAKE_IF_UP_INDEX] = FAKE_IF_BRIDGE_INDEX;
        fake_bridge_of[FAKE_IF_DOWN_INDEX] = FAKE_IF_BRIDGE_INDEX;
        ok_int(nd_proxy_check_routes(p), 1, "a static rule routed to a bridge-mate of upstream is warned about");
    }

    {
        /* A covering route upstream is how most providers deliver the
         * prefix.  What matters is the most specific match. */
        fake_reset();
        nd_proxy_t *p = proxy_with(ND_MODE_STATIC, "2001:db8:0:1::", 64, NULL);
        fake_route("2001:db8:0:1::/64", FAKE_IF_DOWN_INDEX, 254);
        fake_route("2001:db8::/48", FAKE_IF_UP_INDEX, 254);
        ok_int(nd_proxy_check_routes(p), 0, "a covering route upstream does not hide a specific one downstream");
    }

    {
        fake_reset();
        nd_proxy_t *p = proxy_with(ND_MODE_STATIC, "2001:db8:0:1::", 64, NULL);
        fake_route("2001:db8:0:1::/64", FAKE_IF_UP_INDEX, 100);
        ok_int(nd_proxy_check_routes(p), 0, "a route in another table is not consulted");
    }

    {
        /* Auto rules resolve per target and already refuse a route back out
         * the proxied interface, and a covering upstream route alongside more
         * specific downstream ones is a normal auto setup. */
        fake_reset();
        nd_proxy_t *p = proxy_with(ND_MODE_AUTO, "2001:db8::", 48, NULL);
        fake_route("2001:db8::/48", FAKE_IF_UP_INDEX, 254);
        ok_int(nd_proxy_check_routes(p), 0, "auto rules are not checked against the routing table");
    }
}
