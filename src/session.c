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

extern int nd_conf_invalid_ttl;
extern int nd_conf_valid_ttl;
extern int nd_conf_stale_ttl;
extern int nd_conf_renew;
extern int nd_conf_retrans_limit;
extern int nd_conf_retrans_time;
extern bool nd_conf_keepalive;

#ifndef NDPPD_SESSION_BUCKETS
#    define NDPPD_SESSION_BUCKETS 64
#endif

#define NDL_BUCKET(a) (nd_addr_hash(a) % NDPPD_SESSION_BUCKETS)

static nd_session_t *ndL_sessions[NDPPD_SESSION_BUCKETS];
static nd_session_t *ndL_sessions_r[NDPPD_SESSION_BUCKETS];

static void ndL_up(nd_session_t *session)
{
    if (session->iface && !session->autowired && session->rule->autowire) {
        nd_rt_add_route(&session->tgt, 128, session->iface->index, session->rule->table);
        session->autowired = true;
    }
}

static void ndL_down(nd_session_t *session)
{
    if (session->iface && session->autowired) {
        nd_rt_remove_route(&session->tgt, 128, session->rule->table);
        session->autowired = false;
    }
}

void nd_session_handle_ns(nd_session_t *session, const nd_addr_t *src, const nd_lladdr_t *src_ll)
{
    session->ins_time = nd_current_time;

    if (session->state != ND_STATE_VALID && session->state != ND_STATE_STALE) {
        nd_sub_t *sub;
        ND_LL_SEARCH(session->subs, sub, next, nd_addr_eq(&sub->addr, src) && nd_ll_addr_eq(&sub->lladdr, src_ll));

        if (!sub) {
            sub = ND_NEW(nd_sub_t);
            sub->addr = *src;
            sub->lladdr = *src_ll;
            ND_LL_PREPEND(session->subs, sub, next);
        }

        return;
    }

    nd_lladdr_t *tgt_ll = !nd_ll_addr_is_unspecified(&session->rule->target) ? &session->rule->target : NULL;

    if (nd_addr_is_unspecified(src)) {
        static const nd_lladdr_t allnodes_ll = { .u8 = { 0x33, 0x33, [5] = 1 } };
        static const nd_addr_t allnodes = { .u8 = { 0xff, 0x02, [15] = 1 } };
        nd_iface_send_na(session->rule->proxy->iface, &allnodes, &allnodes_ll, //
                         &session->tgt, tgt_ll, session->rule->proxy->router);
    } else {
        nd_iface_send_na(session->rule->proxy->iface, src, src_ll, //
                         &session->tgt, tgt_ll, session->rule->proxy->router);
    }
}

void nd_session_handle_na(nd_session_t *session)
{
    if (session->state == ND_STATE_VALID) {
        return;
    }

    nd_lladdr_t *tgt_ll = !nd_ll_addr_is_unspecified(&session->rule->target) ? &session->rule->target : NULL;

    ND_LL_FOREACH_S (session->subs, sub, tmp, next) {
        nd_iface_send_na(session->rule->proxy->iface, &sub->addr, &sub->lladdr, //
                         &session->tgt, tgt_ll, session->rule->proxy->router);
        ND_DELETE(sub);
    }

    session->subs = NULL;

    if (session->state != ND_STATE_VALID) {
        nd_log_debug("Session [%s] %s -> VALID", session->rule->proxy->ifname, nd_ntoa(&session->tgt));

        ndL_up(session);
        session->state = ND_STATE_VALID;
        session->state_time = nd_current_time;
    }
}

nd_session_t *nd_session_create(nd_rule_t *rule, const nd_addr_t *tgt)
{
    nd_session_t *session = ND_NEW(nd_session_t);

    *session = (nd_session_t){
        .rule = rule,
        .state_time = nd_current_time,
        .tgt = *tgt,
    };

    nd_addr_combine(&rule->rewrite_tgt, tgt, rule->rewrite_pflen, &session->tgt_r);

    ND_LL_PREPEND(ndL_sessions[NDL_BUCKET(&session->tgt)], session, next);
    ND_LL_PREPEND(ndL_sessions_r[NDL_BUCKET(&session->tgt_r)], session, next_r);

    if (rule->mode == ND_MODE_AUTO) {
        nd_rt_route_t *route = nd_rt_find_route(tgt, rule->table);

        if (!route || route->oif == rule->proxy->iface->index || !(session->iface = nd_iface_open(NULL, route->oif))) {
            session->state = ND_STATE_INVALID;
            return session;
        }
    } else if ((session->iface = rule->iface)) {
        session->iface->refcount++;
    }

    if (session->iface) {
        session->state = ND_STATE_INCOMPLETE;
        session->ons_count = 1;
        session->ons_time = nd_current_time;
        nd_iface_send_ns(session->iface, &session->tgt_r);
    } else if (rule->mode == ND_MODE_STATIC) {
        session->state = ND_STATE_VALID;
    }

    return session;
}

void nd_session_update(nd_session_t *session)
{
    switch (session->state) {
    case ND_STATE_INCOMPLETE:
        if (nd_current_time - session->ons_time < nd_conf_retrans_time) {
            break;
        }

        if (++session->ons_count > nd_conf_retrans_limit) {
            session->state = ND_STATE_INVALID;
            session->state_time = nd_current_time;
            nd_log_debug("session [%s] %s INCOMPLETE -> INVALID", //
                         session->rule->proxy->ifname, nd_ntoa(&session->tgt));
            break;
        }

        nd_iface_send_ns(session->iface, &session->tgt_r);
        break;

    case ND_STATE_INVALID:
        if (nd_current_time - session->state_time < nd_conf_invalid_ttl) {
            break;
        }

        ndL_down(session);

        if (session->iface) {
            nd_iface_close(session->iface);
        }

        ND_LL_FOREACH_S (session->subs, sub, tmp, next) {
            ND_DELETE(sub);
        }

        ND_LL_DELETE(ndL_sessions[NDL_BUCKET(&session->tgt)], session, next);
        ND_LL_DELETE(ndL_sessions_r[NDL_BUCKET(&session->tgt_r)], session, next_r);

        nd_log_debug("session [%s] %s INVALID -> (deleted)", //
                     session->rule->proxy->ifname, nd_ntoa(&session->tgt));

        ND_DELETE(session);
        break;

    case ND_STATE_VALID:
        if (nd_current_time - session->state_time < nd_conf_valid_ttl) {
            break;
        }

        session->state = ND_STATE_STALE;
        session->state_time = nd_current_time;
        session->ons_time = nd_current_time;

        nd_log_debug("session [%s] %s VALID -> STALE", //
                     session->rule->proxy->ifname, nd_ntoa(&session->tgt));

        if (nd_conf_keepalive || nd_current_time - session->ins_time < nd_conf_valid_ttl) {
            session->ons_count = 1;
            nd_iface_send_ns(session->iface, &session->tgt_r);
        } else {
            session->ons_count = 0;
        }

        break;

    case ND_STATE_STALE:
        if (nd_current_time - session->state_time >= nd_conf_stale_ttl) {
            session->state = ND_STATE_INVALID;
            session->state_time = nd_current_time;

            nd_log_debug("session [%s] %s STALE -> INVALID", //
                         session->rule->proxy->ifname, nd_ntoa(&session->tgt));
        } else {
            // We will only retransmit if nd_conf_keepalive is true, or if the last incoming NS
            // request was made less than nd_conf_valid_ttl milliseconds ago.

            if (!nd_conf_keepalive && nd_current_time - session->ins_time > nd_conf_valid_ttl) {
                break;
            }

            long time = session->ons_count && !(session->ons_count % nd_conf_retrans_limit)
                            ? ((1 << session->ons_count / 3) * nd_conf_retrans_time)
                            : nd_conf_retrans_time;

            if (nd_current_time - session->ons_time < time) {
                break;
            }

            session->ons_count++;
            session->ons_time = nd_current_time;
            nd_iface_send_ns(session->iface, &session->tgt_r);
        }
        break;
    }
}

nd_session_t *nd_session_find(const nd_addr_t *tgt, const nd_proxy_t *proxy)
{
    nd_session_t *session;
    ND_LL_SEARCH(ndL_sessions[NDL_BUCKET(tgt)], session, next,
                 session->rule->proxy == proxy && nd_addr_eq(&session->tgt, tgt));
    return session;
}

nd_session_t *nd_session_find_r(const nd_addr_t *tgt, const nd_iface_t *iface)
{
    nd_session_t *session;
    ND_LL_SEARCH(ndL_sessions_r[NDL_BUCKET(tgt)], session, next_r,
                 session->iface == iface && nd_addr_eq(&session->tgt_r, tgt));
    return session;
}

void nd_session_update_all()
{
    for (int i = 0; i < NDPPD_SESSION_BUCKETS; i++) {
        ND_LL_FOREACH_S (ndL_sessions[i], session, tmp, next) {
            nd_session_update(session);
        }
    }
}
