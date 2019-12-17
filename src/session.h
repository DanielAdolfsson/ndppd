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
#ifndef NDPPD_SESSION_H
#define NDPPD_SESSION_H

#include "ndppd.h"
#include "rt.h"

typedef enum {
    //! Address resolution is in progress.
    ND_STATE_INCOMPLETE,

    ND_STATE_VALID,

    ND_STATE_STALE,

    //! Resolution failed, and further Neighbor Solicitation messages will be ignored until
    //! the session is removed or a Neighbor Advertisement is received.
    ND_STATE_INVALID,

} nd_state_t;

struct nd_session {
    nd_session_t *next_in_proxy;
    nd_session_t *next_in_iface;
    nd_rule_t *rule;
    nd_addr_t tgt;
    nd_addr_t real_tgt;
    int ons_count;   /* Number of outgoing NS messages. */
    long ons_time;   /* Last time we sent a NS message. */
    long ins_time;   /* Last time this session was the target of an incoming NS. */
    long state_time; /* Time when session entered it's current state. */
    nd_state_t state;
    nd_iface_t *iface;
    bool autowired; /* If this session had a route set up. */
};

nd_session_t *nd_session_create(nd_rule_t *rule, const nd_addr_t *tgt);
void nd_session_update(nd_session_t *session);
void nd_session_handle_ns(nd_session_t *session, const nd_addr_t *src, const nd_lladdr_t *src_ll);
void nd_session_handle_na(nd_session_t *session);

#endif /* NDPPD_SESSION_H */
