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
#ifndef NDPPD_RULE_H
#define NDPPD_RULE_H

#include <net/if.h>

#include "ndppd.h"

typedef enum {
    ND_MODE_UNKNOWN,
    ND_MODE_STATIC,
    ND_MODE_IFACE, // Use a specific interface
    ND_MODE_AUTO,
} nd_mode_t;

struct nd_rule {
    nd_rule_t *next;
    nd_proxy_t *proxy;

    char ifname[IF_NAMESIZE];

    nd_lladdr_t target;
    nd_addr_t addr;
    int prefix;

    nd_addr_t rewrite_tgt;
    int rewrite_pflen;

    nd_iface_t *iface;
    bool autowire;
    int table;
    nd_mode_t mode;
};

nd_rule_t *nd_rule_create(nd_proxy_t *proxy);

#endif // NDPPD_RULE_H
