/*
 * This file is part of ndppd.
 *
 * Copyright (C) 2011-2019  Daniel Adolfsson <daniel@ashen.se>
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
#include <net/if.h>
#include <stdio.h>
#include <string.h>

#include "ndppd.h"

static nd_proxy_t *ndL_proxies;

extern int nd_conf_invalid_ttl;
extern int nd_conf_valid_ttl;
extern int nd_conf_stale_ttl;
extern int nd_conf_retrans_limit;
extern int nd_conf_retrans_time;
extern bool nd_conf_keepalive;

nd_proxy_t *nd_proxy_find(const char *ifname)
{
    nd_proxy_t *proxy;

    ND_LL_SEARCH(ndL_proxies, proxy, next, !strcmp(proxy->ifname, ifname));

    return proxy;
}

nd_proxy_t *nd_proxy_create(const char *ifname)
{
    nd_proxy_t *proxy = nd_proxy_find(ifname);

    if (proxy) {
        nd_log_error("Proxy already exists for interface \"%s\"", ifname);
        return NULL;
    }

    proxy = ND_NEW(nd_proxy_t);

    *proxy = (nd_proxy_t){ 0 };
    strcpy(proxy->ifname, ifname);

    ND_LL_PREPEND(ndL_proxies, proxy, next);

    return proxy;
}

void nd_proxy_handle_ns(nd_proxy_t *proxy, const nd_addr_t *src, const nd_addr_t *dst, const nd_addr_t *tgt,
                        const nd_lladdr_t *src_ll)
{
    (void)dst;

    nd_log_trace("Handle NS src=%s [%s], dst=%s, tgt=%s", //
                 nd_ntoa(src), nd_ll_ntoa(src_ll), nd_ntoa(dst), nd_ntoa(tgt));

    nd_session_t *session = nd_session_find(tgt, proxy);

    if (!session) {
        nd_rule_t *rule;
        ND_LL_SEARCH(proxy->rules, rule, next, nd_addr_match(&rule->addr, tgt, rule->prefix));

        if (!rule) {
            nd_log_debug("proxy %s: no rule matches tgt=%s, drop NS", proxy->ifname, nd_ntoa(tgt));
            return;
        }

        session = nd_session_create(rule, tgt);
    }

    nd_session_handle_ns(session, src, src_ll);
}

/* Describes how interface `index` shares a link with the proxied interface,
 * or returns NULL if it does not.  The proxy only works when the upstream link
 * and the link the targets live on are separate: if they are bridged, the
 * targets' own neighbor advertisements reach the upstream router directly and
 * contradict the ones ndppd sends on their behalf.  See #81. */
static const char *ndL_shared_link(const nd_proxy_t *proxy, unsigned index, char *buf, size_t buflen)
{
    if (index == proxy->iface->index) {
        snprintf(buf, buflen, "which is %s itself", proxy->ifname);
        return buf;
    }

    unsigned bridge = nd_iface_bridge(proxy->iface->index);

    if (!bridge || bridge != nd_iface_bridge(index))
        return NULL;

    char name[IF_NAMESIZE];
    snprintf(buf, buflen, "which is bridged with %s (bridge %s)", proxy->ifname, nd_iface_name(bridge, name));
    return buf;
}

int nd_proxy_check_links(nd_proxy_t *proxy)
{
    int count = 0;
    char why[IF_NAMESIZE * 2 + 64];

    ND_LL_FOREACH (proxy->rules, rule, next) {
        if (rule->mode != ND_MODE_IFACE || !rule->iface)
            continue;

        if (!ndL_shared_link(proxy, rule->iface->index, why, sizeof(why)))
            continue;

        nd_log_warning("proxy %s: rule %s/%d uses interface %s, %s. Upstream and downstream must be separate "
                       "links for ndppd to work; take %s out of the bridge.",
                       proxy->ifname, nd_ntoa(&rule->addr), rule->prefix, rule->iface->name, why, proxy->ifname);
        count++;
    }

    return count;
}

int nd_proxy_check_routes(nd_proxy_t *proxy)
{
    int count = 0;
    char why[IF_NAMESIZE * 2 + 64];
    char name[IF_NAMESIZE];

    if (!proxy->iface)
        return 0;

    /* Only static rules: they answer for every address in the prefix, so a
     * route that sends the prefix back towards upstream is always wrong.  An
     * auto rule resolves each target on its own, and already declines targets
     * routed out the proxied interface. */
    ND_LL_FOREACH (proxy->rules, rule, next) {
        if (rule->mode != ND_MODE_STATIC)
            continue;

        nd_rt_route_t *route = nd_rt_find_route(&rule->addr, rule->table);

        if (!route || !route->pflen || !ndL_shared_link(proxy, route->oif, why, sizeof(why)))
            continue;

        nd_log_warning("proxy %s: rule %s/%d is routed out %s (route %s/%d), %s. The proxied prefix must be "
                       "routed to a link separate from upstream.",
                       proxy->ifname, nd_ntoa(&rule->addr), rule->prefix, nd_iface_name(route->oif, name),
                       nd_ntoa(&route->dst), route->pflen, why);
        count++;
    }

    return count;
}

void nd_proxy_check_all_routes()
{
    ND_LL_FOREACH (ndL_proxies, proxy, next)
        nd_proxy_check_routes(proxy);
}

bool nd_proxy_startup()
{
    ND_LL_FOREACH (ndL_proxies, proxy, next) {
        if (!(proxy->iface = nd_iface_open(proxy->ifname, 0)))
            return false;

        proxy->iface->proxy = proxy;

        ND_LL_FOREACH (proxy->rules, rule, next) {
            if (rule->ifname[0] && !(rule->iface = nd_iface_open(rule->ifname, 0))) {
                return false;
            }
        }

        nd_proxy_check_links(proxy);
    }

    return true;
}
