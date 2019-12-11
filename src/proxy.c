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

#include <string.h>

#include "addr.h"
#include "iface.h"
#include "ndppd.h"
#include "neigh.h"
#include "proxy.h"
#include "rtnl.h"
#include "rule.h"

static nd_proxy_t *ndL_proxies;

extern int nd_conf_invalid_ttl;
extern int nd_conf_valid_ttl;
extern int nd_conf_renew;
extern int nd_conf_retrans_limit;
extern int nd_conf_retrans_time;
extern bool nd_conf_keepalive;

nd_proxy_t *nd_proxy_create(const char *ifname)
{
    nd_proxy_t *proxy;

    ND_LL_SEARCH(ndL_proxies, proxy, next, !strcmp(proxy->ifname, ifname));

    if (proxy)
    {
        nd_log_error("Proxy already exists for interface \"%s\"", ifname);
        return NULL;
    }

    proxy = ND_ALLOC(nd_proxy_t);

    ND_LL_PREPEND(ndL_proxies, proxy, next);

    proxy->iface = NULL;
    proxy->rules = NULL;
    proxy->neighs = NULL;
    proxy->router = false;

    strcpy(proxy->ifname, ifname);

    return proxy;
}

void nd_proxy_handle_ns(nd_proxy_t *proxy, nd_addr_t *src, __attribute__((unused)) nd_addr_t *dst, nd_addr_t *tgt,
                        uint8_t *src_ll)
{
    nd_log_trace("Handle NA src=%s [%x:%x:%x:%x:%x:%x], dst=%s, tgt=%s", nd_addr_to_string(src), src_ll[0], src_ll[1],
                 src_ll[2], src_ll[3], src_ll[4], src_ll[5], nd_addr_to_string(dst), nd_addr_to_string(tgt));

    nd_neigh_t *neigh;

    ND_LL_FOREACH_NODEF(proxy->neighs, neigh, next_in_proxy)
    {
        if (!nd_addr_eq(&neigh->tgt, tgt))
            continue;

        if (neigh->state == ND_STATE_VALID || neigh->state == ND_STATE_VALID_REFRESH)
        {
            neigh->used_at = nd_current_time;
            nd_iface_write_na(proxy->iface, src, src_ll, tgt, proxy->router);
            return;
        }

        return;
    }

    /* If we get down here it means we don't have any valid sessions we can use.
     * See if we can find one more more matching rules. */

    nd_rule_t *rule;
    ND_LL_SEARCH(proxy->rules, rule, next, nd_addr_match(&rule->addr, tgt, rule->prefix));

    if (!rule)
        return;

    neigh = nd_alloc_neigh();
    neigh->touched_at = nd_current_time;
    neigh->tgt = *tgt;

    ND_LL_PREPEND(proxy->neighs, neigh, next_in_proxy);

    if (rule->is_auto)
    {
        /* TODO: Loop through valid routes. */

        nd_rtnl_route_t *route = nd_rtnl_find_route(tgt, 254);

        if (!route || route->oif == proxy->iface->index)
        {
            /* Could not find a matching route. */
            neigh->state = ND_STATE_INVALID;
            return;
        }

        if (!(neigh->iface = nd_iface_open(NULL, route->oif)))
        {
            /* Could not open interface. */
            neigh->state = ND_STATE_INVALID;
            return;
        }
    }
    else if ((neigh->iface = rule->iface))
    {
        neigh->iface->refs++;
    }

    if (neigh->iface)
    {
        neigh->state = ND_STATE_INCOMPLETE;
        nd_iface_write_ns(neigh->iface, tgt);

        ND_LL_PREPEND(neigh->iface->neighs, neigh, next_in_iface);
    }
    else
    {
        neigh->state = ND_STATE_VALID;
        nd_iface_write_na(proxy->iface, src, src_ll, tgt, proxy->router);
    }
}

void nd_proxy_update_neighs(nd_proxy_t *proxy)
{
    ND_LL_FOREACH_S(proxy->neighs, neigh, tmp, next_in_proxy)
    {
        switch (neigh->state)
        {
        case ND_STATE_INCOMPLETE:
            if ((nd_current_time - neigh->touched_at) < nd_conf_retrans_time)
                break;

            neigh->touched_at = nd_current_time;

            if (++neigh->attempt > 3)
            {
                neigh->state = ND_STATE_INVALID;
                break;
            }

            nd_iface_write_ns(neigh->iface, &neigh->tgt);
            break;

        case ND_STATE_INVALID:
            if ((nd_current_time - neigh->touched_at) < nd_conf_invalid_ttl)
                break;

            ND_LL_DELETE(neigh->iface->neighs, neigh, next_in_iface);
            ND_LL_DELETE(proxy->neighs, neigh, next_in_proxy);

            nd_iface_close(neigh->iface);
            nd_free_neigh(neigh);
            break;

        case ND_STATE_VALID:
            if (nd_current_time - neigh->touched_at < nd_conf_valid_ttl - nd_conf_renew)
                break;





            /* TODO: Send solicit. */
            break;

        case ND_STATE_VALID_REFRESH:
            if ((nd_current_time - neigh->touched_at) < nd_conf_retrans_time)
                break;

            if (++neigh->attempt > 3)
            {
                neigh->state = ND_STATE_INVALID;
                neigh->touched_at = nd_current_time;
                break;
            }

            /* TODO: Send solicit. */
            break;
        }
    }
}

bool nd_proxy_startup()
{
    ND_LL_FOREACH(ndL_proxies, proxy, next)
    {
        if (!(proxy->iface = nd_iface_open(proxy->ifname, 0)))
            return false;

        if (proxy->promisc)
            nd_iface_set_promisc(proxy->iface, true);
        else
            nd_iface_set_allmulti(proxy->iface, true);

        ND_LL_FOREACH(proxy->rules, rule, next)
        {
            if (rule->ifname[0] && !(rule->iface = nd_iface_open(rule->ifname, 0)))
                return false;
        }
    }

    return true;
}
