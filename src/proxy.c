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

#include "ndppd.h"

static nd_proxy_t *ndL_proxies;

extern int nd_conf_invalid_ttl;
extern int nd_conf_valid_ttl;
extern int nd_conf_stale_ttl;
extern int nd_conf_renew;
extern int nd_conf_retrans_limit;
extern int nd_conf_retrans_time;
extern bool nd_conf_keepalive;

nd_proxy_t *nd_proxy_create(const char *ifname)
{
    nd_proxy_t *proxy;

    ND_LL_SEARCH(ndL_proxies, proxy, next, !strcmp(proxy->ifname, ifname));

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
            return;
        }

        session = nd_session_create(rule, tgt);
    }

    nd_session_handle_ns(session, src, src_ll);
}

bool nd_proxy_startup()
{
    ND_LL_FOREACH (ndL_proxies, proxy, next) {
        if (!(proxy->iface = nd_iface_open(proxy->ifname, 0))) {
            return false;
        }

        proxy->iface->proxy = proxy;

        ND_LL_FOREACH (proxy->rules, rule, next) {
            if (rule->ifname[0] && !(rule->iface = nd_iface_open(rule->ifname, 0))) {
                return false;
            }
        }
    }

    return true;
}
