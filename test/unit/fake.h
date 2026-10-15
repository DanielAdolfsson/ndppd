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

/*
 * Fakes for the two things session.c talks to that need a kernel: the packet
 * interface and the routing table.
 *
 * The unit test binary links session.o, proxy.o, rule.o and conf.o against
 * these instead of iface.o, rt.o and io.o.  That buys three things the
 * integration suite cannot give us:
 *
 *   - every emitted NS and NA is recorded and can be asserted on exactly,
 *     rather than inferred from whether a ping got through;
 *   - nd_current_time is a plain variable, so a 30-second TTL transition is
 *     tested by assigning to it rather than by sleeping;
 *   - nd_iface_send_ns() tolerates a NULL interface, so a code path that
 *     would segfault against the real iface.c is observable as a recorded
 *     send with iface == NULL instead of killing the test run.
 */
#ifndef NDPPD_TEST_FAKE_H
#define NDPPD_TEST_FAKE_H

#include "ndppd.h"

#define FAKE_MAX 64

typedef struct {
    nd_iface_t *iface; /* NULL is recorded, not dereferenced. */
    nd_addr_t tgt;
} fake_ns_t;

typedef struct {
    nd_iface_t *iface;
    nd_addr_t dst;
    nd_lladdr_t dst_ll;
    nd_addr_t tgt;
    nd_lladdr_t tgt_ll;
    bool has_tgt_ll; /* false means "use the interface's own address". */
    bool router;
} fake_na_t;

typedef struct {
    nd_addr_t dst;
    unsigned pflen;
    unsigned oif;
    unsigned table;
    bool added; /* false = removed */
} fake_route_op_t;

extern fake_ns_t fake_ns[FAKE_MAX];
extern int fake_ns_count;

extern fake_na_t fake_na[FAKE_MAX];
extern int fake_na_count;

extern fake_route_op_t fake_route_ops[FAKE_MAX];
extern int fake_route_op_count;

/* Two interfaces, enough for "upstream proxy" and "downstream target". */
extern nd_iface_t fake_iface_up;
extern nd_iface_t fake_iface_down;

#define FAKE_IF_UP_INDEX 1
#define FAKE_IF_DOWN_INDEX 2

/* Clears recorded sends, recorded route operations and the fake routing
 * table, and resets both interface refcounts. Call at the top of each test. */
void fake_reset(void);

/* fake_route("2001:db8:0:1::/64", FAKE_IF_DOWN_INDEX, 254) */
void fake_route(const char *cidr, unsigned oif, unsigned table);

/* Parse helpers so tests read as addresses rather than as byte arrays. */
nd_addr_t fake_addr(const char *str);
nd_lladdr_t fake_lladdr(const char *str);

#endif /* NDPPD_TEST_FAKE_H */
