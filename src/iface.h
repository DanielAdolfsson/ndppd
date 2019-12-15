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
#ifndef NDPPD_IFACE_H
#define NDPPD_IFACE_H

#include "ndppd.h"

#include <net/if.h>

struct nd_iface {
    nd_iface_t *next;
    int refcount;

    char name[IF_NAMESIZE];
    uint8_t lladdr[6];

    uint index;

    int old_allmulti;
    int old_promisc;

    nd_proxy_t *proxy;
    nd_session_t *sessions; // All sessions expecting NA messages to arrive here.

#ifndef __linux__
    nd_io_t *bpf_io;
#endif
};

extern bool nd_iface_no_restore_flags;

nd_iface_t *nd_iface_open(const char *if_name, unsigned int if_index);
void nd_iface_close(nd_iface_t *iface);
ssize_t nd_iface_write_ns(nd_iface_t *iface, nd_addr_t *tgt);
ssize_t nd_iface_write_na(nd_iface_t *iface, nd_addr_t *dst, uint8_t *dst_ll, nd_addr_t *tgt, bool router);
void nd_iface_get_local_addr(nd_iface_t *iface, nd_addr_t *addr);
bool nd_iface_set_allmulti(nd_iface_t *iface, bool on);
bool nd_iface_set_promisc(nd_iface_t *iface, bool on);
bool nd_iface_startup();
void nd_iface_cleanup();

#endif // NDPPD_IFACE_H
