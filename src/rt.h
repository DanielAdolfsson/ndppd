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
#ifndef NDPPD_RT_H
#define NDPPD_RT_H

#include "ndppd.h"

typedef struct nd_rt_route nd_rt_route_t;
typedef struct nd_rt_addr nd_rt_addr_t;

struct nd_rt_route
{
    nd_rt_route_t *next;
    nd_addr_t dst;
    unsigned oif;
    int pflen;
    int table;
    bool owned; // If this route is owned by ndppd.
};

struct nd_rt_addr
{
    nd_rt_addr_t *next;
    unsigned iif;
    nd_addr_t addr;
    int pflen;
};

extern long nd_rt_dump_timeout;

bool nd_rt_open();
void nd_rt_cleanup();
bool nd_rt_query_addresses();
bool nd_rt_query_routes();
nd_rt_route_t *nd_rt_find_route(nd_addr_t *addr, int table);
bool nd_rt_add_route(nd_addr_t *dst, int pflen, unsigned oif, unsigned table);

#endif // NDPPD_RT_H
