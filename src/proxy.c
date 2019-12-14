// This file is part of ndppd.
//
// Copyright (C) 2011-2019  Daniel Adolfsson <daniel@ashen.se>
//
// ndppd is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// ndppd is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with ndppd.  If not, see <https://www.gnu.org/licenses/>.
#include <string.h>

#include "addr.h"
#include "iface.h"
#include "ndppd.h"
#include "proxy.h"
#include "rt.h"
#include "rule.h"
#include "session.h"

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

    if (proxy)
    {
        nd_log_error("Proxy already exists for interface \"%s\"", ifname);
        return NULL;
    }

    proxy = ND_ALLOC(nd_proxy_t);

    ND_LL_PREPEND(ndL_proxies, proxy, next);

    proxy->iface = NULL;
    proxy->rules = NULL;
    proxy->sessions = NULL;
    proxy->router = false;

    strcpy(proxy->ifname, ifname);

    return proxy;
}

void nd_proxy_handle_ns(nd_proxy_t *proxy, nd_addr_t *src, __attribute__((unused)) nd_addr_t *dst, nd_addr_t *tgt,
                        uint8_t *src_ll)
{
    nd_log_trace("Handle NA src=%s [%x:%x:%x:%x:%x:%x], dst=%s, tgt=%s", nd_aton(src), src_ll[0], src_ll[1], src_ll[2],
                 src_ll[3], src_ll[4], src_ll[5], nd_aton(dst), nd_aton(tgt));

    nd_session_t *session;

    ND_LL_FOREACH_NODEF(proxy->sessions, session, next_in_proxy)
    {
        if (!nd_addr_eq(&session->tgt, tgt))
            continue;

        if (session->state == ND_STATE_VALID || session->state == ND_STATE_STALE)
        {
            session->atime = nd_current_time;
            nd_iface_write_na(proxy->iface, src, src_ll, tgt, proxy->router);
            return;
        }

        return;
    }

    // If we get down here it means we don't have any valid sessions we can use.
    // See if we can find one more more matching rules.

    nd_rule_t *rule;
    ND_LL_SEARCH(proxy->rules, rule, next, nd_addr_match(&rule->addr, tgt, rule->prefix));

    if (!rule)
        return;

    session = nd_alloc_session();
    ND_LL_PREPEND(proxy->sessions, session, next_in_proxy);

    session->mtime = nd_current_time;
    session->atime = nd_current_time;
    session->rtime = nd_current_time;
    session->tgt = *tgt;

    if (rule->is_auto)
    {
        /* TODO: Loop through valid routes. */

        nd_rt_route_t *route = nd_rt_find_route(tgt, rule->table);

        if (!route || route->oif == proxy->iface->index)
        {
            // Could not find a matching route.
            session->state = ND_STATE_INVALID;
            return;
        }

        if (!(session->iface = nd_iface_open(NULL, route->oif)))
        {
            // Could not open interface.
            session->state = ND_STATE_INVALID;
            return;
        }
    }
    else if ((session->iface = rule->iface))
    {
        session->iface->refcount++;
    }

    if (session->iface)
    {
        session->state = ND_STATE_INCOMPLETE;
        session->rcount = 0;
        nd_iface_write_ns(session->iface, tgt);

        ND_LL_PREPEND(session->iface->sessions, session, next_in_iface);
    }
    else
    {
        session->state = ND_STATE_VALID;
        nd_iface_write_na(proxy->iface, src, src_ll, tgt, proxy->router);
    }
}

static void ndL_update_session(nd_proxy_t *proxy, nd_session_t *session)
{
    switch (session->state)
    {
    case ND_STATE_INCOMPLETE:
        if (nd_current_time - session->mtime < nd_conf_retrans_time)
            break;

        session->mtime = nd_current_time;

        if (++session->rcount > nd_conf_retrans_limit)
        {
            session->state = ND_STATE_INVALID;
            nd_log_debug("session [%s] %s INCOMPLETE -> INVALID", proxy->ifname, nd_aton(&session->tgt));
            break;
        }

        nd_iface_write_ns(session->iface, &session->tgt);
        break;

    case ND_STATE_INVALID:
        if (nd_current_time - session->mtime < nd_conf_invalid_ttl)
            break;

        ND_LL_DELETE(session->iface->sessions, session, next_in_iface);
        ND_LL_DELETE(proxy->sessions, session, next_in_proxy);

        nd_iface_close(session->iface);
        nd_free_session(session);
        nd_log_debug("session [%s] %s INVALID -> (deleted)", proxy->ifname, nd_aton(&session->tgt));
        break;

    case ND_STATE_VALID:
        if (nd_current_time - session->mtime < nd_conf_valid_ttl)
            break;

        session->mtime = nd_current_time;
        session->rtime = nd_current_time;
        session->state = ND_STATE_STALE;
        session->rcount = 0;

        nd_log_debug("session [%s] %s VALID -> STALE", proxy->ifname, nd_aton(&session->tgt));
        nd_iface_write_ns(session->iface, &session->tgt);
        break;

    case ND_STATE_STALE:
        if (nd_current_time - session->mtime >= nd_conf_stale_ttl)
        {
            session->mtime = nd_current_time;
            session->state = ND_STATE_INVALID;
            nd_log_debug("session [%s] %s STALE -> INVALID", proxy->ifname, nd_aton(&session->tgt));
        }
        else
        {
            // We will only retransmit if nd_conf_keepalive is true, or if the last incoming NS
            // request was made less than nd_conf_valid_ttl milliseconds ago.
            if (!nd_conf_keepalive && nd_current_time - session->atime > nd_conf_valid_ttl)
                break;

            long time = session->rcount && !(session->rcount % nd_conf_retrans_limit)
                            ? ((1 << session->rcount / 3) * nd_conf_retrans_time)
                            : nd_conf_retrans_time;

            if (nd_current_time - session->rtime < time)
                break;

            session->rcount++;
            session->rtime = nd_current_time;
            nd_iface_write_ns(session->iface, &session->tgt);
        }
        break;
    }
}

void nd_proxy_update_all()
{
    ND_LL_FOREACH(ndL_proxies, proxy, next)
    {
        ND_LL_FOREACH_S(proxy->sessions, session, tmp, next_in_proxy)
        {
            ndL_update_session(proxy, session);
        }
    }
}

bool nd_proxy_startup()
{
    ND_LL_FOREACH(ndL_proxies, proxy, next)
    {
        if (!(proxy->iface = nd_iface_open(proxy->ifname, 0)))
            return false;

        proxy->iface->proxy = proxy;

#ifdef __linux__
        if (proxy->promisc)
            nd_iface_set_promisc(proxy->iface, true);
        else
            nd_iface_set_allmulti(proxy->iface, true);
#endif

        ND_LL_FOREACH(proxy->rules, rule, next)
        {
            if (rule->ifname[0] && !(rule->iface = nd_iface_open(rule->ifname, 0)))
                return false;
        }
    }

    return true;
}
