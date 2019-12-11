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
#ifndef NDPPD_RTNL_H
#define NDPPD_RTNL_H

#include "ndppd.h"

typedef struct nd_rtnl_route nd_rtnl_route_t;
typedef struct nd_rtnl_addr nd_rtnl_addr_t;

struct nd_rtnl_route
{
    nd_rtnl_route_t *next;
    nd_addr_t addr;
    unsigned int oif;
    int pflen;
    int table;
    int metrics;
};

struct nd_rtnl_addr
{
    nd_rtnl_addr_t *next;
    int iif;
    nd_addr_t addr;
    int pflen;
};

extern long nd_rtnl_dump_timeout;

bool nd_rtnl_open();
void nd_rtnl_cleanup();
bool nd_rtnl_query_addresses();
bool nd_rtnl_query_routes();
nd_rtnl_route_t *nd_rtnl_find_route(nd_addr_t *addr, int table);

#endif /* NDPPD_RTNL_H */
