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
    if (session->iface && !session->autowired && !session->rule->is_auto && session->rule->autowire)
    {
        nd_rt_add_route(&session->tgt, 128, session->iface->index, session->rule->table);
        session->autowired = true;
    }
}

static void ndL_down(nd_session_t *session)
{
    if (session->iface && session->autowired)
    {
        nd_rt_remove_route(&session->tgt, 128, session->rule->table);
        session->autowired = false;
    }
}

void nd_session_handle_ns(nd_session_t *session, nd_addr_t *src, uint8_t *src_ll)
{
    session->ins_time = nd_current_time;

    if (session->state != ND_STATE_VALID && session->state != ND_STATE_STALE)
        return;

    nd_iface_write_na(session->rule->proxy->iface, src, src_ll, &session->tgt, session->rule->proxy->router);
}

void nd_session_handle_na(nd_session_t *session)
{
    if (session->state != ND_STATE_VALID)
    {
        nd_log_debug("session [%s] %s -> VALID", session->rule->proxy->ifname, nd_aton(&session->tgt));

        ndL_up(session);
        session->state = ND_STATE_VALID;
        session->state_time = nd_current_time;
    }
}

nd_session_t *nd_session_create(nd_rule_t *rule, nd_addr_t *tgt)
{
    nd_session_t *session = ndL_free_sessions;

    if (session)
        ND_LL_DELETE(ndL_free_sessions, session, next_in_proxy);
    else
        session = ND_ALLOC(nd_session_t);

    ND_LL_PREPEND(rule->proxy->sessions, session, next_in_proxy);

    memset(session, 0, sizeof(nd_session_t));

    session->rule = rule;
    session->state_time = nd_current_time;
    session->tgt = *tgt;

    if (rule->is_auto)
    {
        nd_rt_route_t *route = nd_rt_find_route(tgt, rule->table);

        if (!route || route->oif == rule->proxy->iface->index ||!(session->iface = nd_iface_open(NULL, route->oif)))
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
        ND_LL_PREPEND(session->iface->sessions, session, next_in_iface);

        session->state = ND_STATE_INCOMPLETE;
        session->ons_count = 1;
        session->ons_time = nd_current_time;
        nd_iface_write_ns(session->iface, tgt);

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
        if (nd_current_time - session->ons_time < nd_conf_retrans_time)
            break;

        if (++session->ons_count > nd_conf_retrans_limit)
        {
            session->state = ND_STATE_INVALID;
            session->state_time = nd_current_time;
            nd_log_debug("session [%s] %s INCOMPLETE -> INVALID", session->rule->proxy->ifname, nd_aton(&session->tgt));
            break;
        }

        nd_iface_write_ns(session->iface, &session->tgt);
        break;

    case ND_STATE_INVALID:
        if (nd_current_time - session->state_time < nd_conf_invalid_ttl)
            break;

        ndL_down(session);

        if (session->iface)
        {
            ND_LL_DELETE(session->iface->sessions, session, next_in_iface);
            nd_iface_close(session->iface);
        }

        ND_LL_DELETE(session->rule->proxy->sessions, session, next_in_proxy);
        ND_LL_PREPEND(ndL_free_sessions, session, next_in_proxy);

        nd_log_debug("session [%s] %s INVALID -> (deleted)", session->rule->proxy->ifname, nd_aton(&session->tgt));
        break;

    case ND_STATE_VALID:
        if (nd_current_time - session->state_time < nd_conf_valid_ttl)
            break;

        session->state = ND_STATE_STALE;
        session->state_time = nd_current_time;
        session->ons_time = nd_current_time;

        nd_log_debug("session [%s] %s VALID -> STALE", session->rule->proxy->ifname, nd_aton(&session->tgt));

        if (nd_conf_keepalive || nd_current_time - session->ins_time < nd_conf_valid_ttl)
        {
            session->ons_count = 1;
            nd_iface_write_ns(session->iface, &session->tgt);
        }
        else
        {
            session->ons_count = 0;
        }

        break;

    case ND_STATE_STALE:
        if (nd_current_time - session->state_time >= nd_conf_stale_ttl)
        {
            session->state = ND_STATE_INVALID;
            session->state_time = nd_current_time;
            nd_log_debug("session [%s] %s STALE -> INVALID", session->rule->proxy->ifname, nd_aton(&session->tgt));
        }
        else
        {
            // We will only retransmit if nd_conf_keepalive is true, or if the last incoming NS
            // request was made less than nd_conf_valid_ttl milliseconds ago.

            if (!nd_conf_keepalive && nd_current_time - session->ins_time > nd_conf_valid_ttl)
                break;

            long time = session->ons_count && !(session->ons_count % nd_conf_retrans_limit)
                            ? ((1 << session->ons_count / 3) * nd_conf_retrans_time)
                            : nd_conf_retrans_time;

            if (nd_current_time - session->ons_time < time)
                break;

            session->ons_count++;
            session->ons_time = nd_current_time;
            nd_iface_write_ns(session->iface, &session->tgt);
        }
        break;
    }
}
