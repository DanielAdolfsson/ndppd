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
#include "rule.h"
#include "session.h"

extern int nd_conf_invalid_ttl;
extern int nd_conf_valid_ttl;
extern int nd_conf_stale_ttl;
extern int nd_conf_renew;
extern int nd_conf_retrans_limit;
extern int nd_conf_retrans_time;
extern bool nd_conf_keepalive;

static nd_session_t *ndL_free_sessions;

static void ndL_up(nd_session_t *session)
{
    if (!session->autowired)
    {
        // Add route
    }
}

static void ndL_down(nd_session_t *session)
{
    if (session->autowired)
    {
        // Remove route
    }
}

void nd_session_handle_ns(nd_session_t *session, nd_addr_t *src, uint8_t *src_ll)
{
    if (session->state != ND_STATE_VALID && session->state != ND_STATE_STALE)
        return;

    session->last_announce = nd_current_time;
    nd_iface_write_na(session->proxy->iface, src, src_ll, &session->tgt, session->proxy->router);
}

void nd_session_handle_na(nd_session_t *session)
{
    if (session->state != ND_STATE_VALID)
    {
        ndL_up(session);
        session->state = ND_STATE_VALID;
        session->mtime = nd_current_time;
    }

    session->last_announce = nd_current_time;
}

nd_session_t *nd_session_create(nd_proxy_t *proxy, nd_rule_t *rule, nd_addr_t *tgt)
{
    nd_session_t *session = ndL_free_sessions;

    if (session)
        ND_LL_DELETE(ndL_free_sessions, session, next_in_proxy);
    else
        session = ND_ALLOC(nd_session_t);

    ND_LL_PREPEND(proxy->sessions, session, next_in_proxy);

    memset(session, 0, sizeof(nd_session_t));

    session->proxy = proxy;
    session->mtime = nd_current_time;
    session->rtime = nd_current_time;
    session->tgt = *tgt;

    if (rule->is_auto)
    {
        nd_rt_route_t *route = nd_rt_find_route(tgt, rule->table);

        if (!route || route->oif == proxy->iface->index ||!(session->iface = nd_iface_open(NULL, route->oif)))
        {
            session->state = ND_STATE_INVALID;
            return session;
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
    }

    return session;
}

void nd_session_update(nd_session_t *session)
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
            nd_log_debug("session [%s] %s INCOMPLETE -> INVALID", session->proxy->ifname, nd_aton(&session->tgt));
            break;
        }

        nd_iface_write_ns(session->iface, &session->tgt);
        break;

    case ND_STATE_INVALID:
        if (nd_current_time - session->mtime < nd_conf_invalid_ttl)
            break;

        ndL_down(session);

        if (session->iface)
        {
            ND_LL_DELETE(session->iface->sessions, session, next_in_iface);
            nd_iface_close(session->iface);
        }

        ND_LL_DELETE(session->proxy->sessions, session, next_in_proxy);
        ND_LL_PREPEND(ndL_free_sessions, session, next_in_proxy);

        nd_log_debug("session [%s] %s INVALID -> (deleted)", session->proxy->ifname, nd_aton(&session->tgt));
        break;

    case ND_STATE_VALID:
        if (nd_current_time - session->mtime < nd_conf_valid_ttl)
            break;

        session->mtime = nd_current_time;
        session->rtime = nd_current_time;
        session->state = ND_STATE_STALE;
        session->rcount = 0;

        nd_log_debug("session [%s] %s VALID -> STALE", session->proxy->ifname, nd_aton(&session->tgt));
        nd_iface_write_ns(session->iface, &session->tgt);
        break;

    case ND_STATE_STALE:
        if (nd_current_time - session->mtime >= nd_conf_stale_ttl)
        {
            session->mtime = nd_current_time;
            session->state = ND_STATE_INVALID;
            nd_log_debug("session [%s] %s STALE -> INVALID", session->proxy->ifname, nd_aton(&session->tgt));
        }
        else
        {
            // We will only retransmit if nd_conf_keepalive is true, or if the last incoming NS
            // request was made less than nd_conf_valid_ttl milliseconds ago.
            if (!nd_conf_keepalive && nd_current_time - session->last_announce > nd_conf_valid_ttl)
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
