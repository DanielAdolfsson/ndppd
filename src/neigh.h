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
#ifndef NDPPD_NEIGH_H
#define NDPPD_NEIGH_H

#include "ndppd.h"

typedef enum
{
    /*
     * Address resolution is in progress.
     */
    ND_STATE_INCOMPLETE,

    /*
     *
     */
    ND_STATE_VALID,

    /*
     * Resolution was successful, but this entry is getting old.
     */
    ND_STATE_VALID_REFRESH,

    /*
     * Resolution failed, and further Neighbor Solicitation messages will be ignored until
     * the session is removed or a Neighbor Advertisement is received.
     */
    ND_STATE_INVALID,

} nd_state_t;

struct nd_neigh
{
    nd_neigh_t *next_in_proxy;
    nd_neigh_t *next_in_iface;
    nd_addr_t tgt;
    int attempt;
    long touched_at;
    long used_at;
    nd_state_t state;
    nd_iface_t *iface;
};

nd_neigh_t *nd_alloc_neigh();
void nd_free_neigh(nd_neigh_t *session);
void nd_session_send_ns(nd_neigh_t *session);

#endif /* NDPPD_NEIGH_H */
