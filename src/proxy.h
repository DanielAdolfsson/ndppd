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
#ifndef NDPPD_PROXY_H
#define NDPPD_PROXY_H

#include <net/if.h>

#include "ndppd.h"

struct nd_proxy {
    nd_proxy_t *next;
    char ifname[IF_NAMESIZE];

    nd_iface_t *iface;
    nd_rule_t *rules;
    nd_session_t *sessions;
    bool router;
    bool promisc;
};

nd_proxy_t *nd_proxy_create(const char *ifname);
void nd_proxy_handle_ns(nd_proxy_t *proxy, const nd_addr_t *src, const nd_addr_t *dst, const nd_addr_t *tgt, const nd_lladdr_t *src_ll);
bool nd_proxy_startup();
void nd_proxy_update_all();

#endif // NDPPD_PROXY_H
