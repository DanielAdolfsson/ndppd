/*
 * This file is part of ndppd.
 *
 * Copyright (C) 2011-2026  Daniel Adolfsson <daniel@ashen.se>
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
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fake.h"
#include "ndppd.h"

/* Owned by ndppd.c in the real binary; the test drives it directly. */
long nd_current_time = 1000000;
bool nd_daemonized;
bool nd_opt_daemonize;

fake_ns_t fake_ns[FAKE_MAX];
int fake_ns_count;

fake_na_t fake_na[FAKE_MAX];
int fake_na_count;

fake_route_op_t fake_route_ops[FAKE_MAX];
int fake_route_op_count;

nd_iface_t fake_iface_up = {
    .name = "up0",
    .index = FAKE_IF_UP_INDEX,
    .lladdr = { .u8 = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 } },
};

nd_iface_t fake_iface_down = {
    .name = "down0",
    .index = FAKE_IF_DOWN_INDEX,
    .lladdr = { .u8 = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x02 } },
};

static nd_rt_route_t *ndL_fake_routes;

void fake_reset(void)
{
    fake_ns_count = 0;
    fake_na_count = 0;
    fake_route_op_count = 0;

    memset(fake_ns, 0, sizeof(fake_ns));
    memset(fake_na, 0, sizeof(fake_na));
    memset(fake_route_ops, 0, sizeof(fake_route_ops));

    while (ndL_fake_routes) {
        nd_rt_route_t *next = ndL_fake_routes->next;
        free(ndL_fake_routes);
        ndL_fake_routes = next;
    }

    fake_iface_up.refcount = 0;
    fake_iface_down.refcount = 0;
}

nd_addr_t fake_addr(const char *str)
{
    nd_addr_t addr = { { 0, 0, 0, 0 } };

    if (inet_pton(AF_INET6, str, &addr) != 1) {
        fprintf(stderr, "fake_addr: not an IPv6 address: %s\n", str);
        abort();
    }

    return addr;
}

nd_lladdr_t fake_lladdr(const char *str)
{
    struct ether_addr *ea = ether_aton(str);

    if (!ea) {
        fprintf(stderr, "fake_lladdr: not a link-layer address: %s\n", str);
        abort();
    }

    nd_lladdr_t ll;
    memcpy(&ll, ea, sizeof(ll));
    return ll;
}

void fake_route(const char *cidr, unsigned oif, unsigned table)
{
    char buf[64];
    snprintf(buf, sizeof(buf), "%s", cidr);

    char *slash = strchr(buf, '/');
    unsigned pflen = 128;

    if (slash) {
        *slash = 0;
        pflen = (unsigned)atoi(slash + 1);
    }

    nd_rt_route_t *route = calloc(1, sizeof(nd_rt_route_t));
    route->dst = fake_addr(buf);
    route->pflen = pflen;
    route->oif = oif;
    route->table = table;

    /* rt.c keeps the route list sorted most-specific first and
     * nd_rt_find_route() returns the first match; appending here preserves
     * that ordering as long as tests add specific routes before general
     * ones, which is how a real table comes back from the kernel. */
    nd_rt_route_t **tail = &ndL_fake_routes;
    while (*tail)
        tail = &(*tail)->next;
    *tail = route;
}

/*
 * iface.c replacements.
 */

nd_iface_t *nd_iface_open(const char *if_name, unsigned int if_index)
{
    nd_iface_t *iface = NULL;

    if (if_name)
        iface = !strcmp(if_name, fake_iface_up.name)     ? &fake_iface_up
                : !strcmp(if_name, fake_iface_down.name) ? &fake_iface_down
                                                         : NULL;
    else if (if_index == FAKE_IF_UP_INDEX)
        iface = &fake_iface_up;
    else if (if_index == FAKE_IF_DOWN_INDEX)
        iface = &fake_iface_down;

    if (iface)
        iface->refcount++;

    return iface;
}

void nd_iface_close(nd_iface_t *iface)
{
    if (iface && iface->refcount > 0)
        iface->refcount--;
}

ssize_t nd_iface_send_ns(nd_iface_t *iface, const nd_addr_t *tgt)
{
    if (fake_ns_count < FAKE_MAX) {
        fake_ns[fake_ns_count].iface = iface;
        fake_ns[fake_ns_count].tgt = *tgt;
        fake_ns_count++;
    }

    return 0;
}

ssize_t nd_iface_send_na(nd_iface_t *iface, const nd_addr_t *dst, const nd_lladdr_t *dst_ll, //
                         const nd_addr_t *tgt, const nd_lladdr_t *tgt_ll, bool router)
{
    if (fake_na_count < FAKE_MAX) {
        fake_na_t *na = &fake_na[fake_na_count++];
        na->iface = iface;
        na->dst = *dst;
        na->dst_ll = dst_ll ? *dst_ll : (nd_lladdr_t){ { 0, 0, 0, 0, 0, 0 } };
        na->tgt = *tgt;
        na->has_tgt_ll = tgt_ll != NULL;
        na->tgt_ll = tgt_ll ? *tgt_ll : (nd_lladdr_t){ { 0, 0, 0, 0, 0, 0 } };
        na->router = router;
    }

    return 0;
}

bool nd_iface_startup(void)
{
    return true;
}

void nd_iface_cleanup(void)
{
}

/*
 * rt.c replacements.
 */

long nd_rt_dump_timeout;

nd_rt_route_t *nd_rt_find_route(const nd_addr_t *addr, unsigned table)
{
    ND_LL_FOREACH (ndL_fake_routes, route, next) {
        if (route->table == table && nd_addr_match(&route->dst, addr, route->pflen))
            return route;
    }

    return NULL;
}

static void ndL_record_route_op(const nd_addr_t *dst, unsigned pflen, unsigned oif, unsigned table, bool added)
{
    if (fake_route_op_count >= FAKE_MAX)
        return;

    fake_route_op_t *op = &fake_route_ops[fake_route_op_count++];
    op->dst = *dst;
    op->pflen = pflen;
    op->oif = oif;
    op->table = table;
    op->added = added;
}

bool nd_rt_add_route(nd_addr_t *dst, unsigned pflen, unsigned oif, unsigned table)
{
    ndL_record_route_op(dst, pflen, oif, table, true);
    return true;
}

bool nd_rt_remove_route(nd_addr_t *dst, unsigned pflen, unsigned table)
{
    ndL_record_route_op(dst, pflen, 0, table, false);
    return true;
}

bool nd_rt_open(void)
{
    return true;
}

void nd_rt_cleanup(void)
{
}

bool nd_rt_query_addresses(void)
{
    return true;
}

bool nd_rt_query_routes(void)
{
    return true;
}

void nd_rt_remove_owned_routes(void)
{
}
