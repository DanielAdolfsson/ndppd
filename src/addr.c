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
#include <arpa/inet.h>
#include <string.h>

#ifdef __linux__
#    include <netinet/ether.h>
#else
#    include <sys/types.h>

#    include <net/ethernet.h>
#    include <sys/socket.h>
#endif

#include "ndppd.h"

const char *nd_ntoa(const nd_addr_t *addr)
{
    static int index;
    static char buf[3][64];

    if (addr == NULL) {
        return "(null)";
    }

    return inet_ntop(AF_INET6, addr, buf[index++ % 3], 64);
}

bool nd_addr_is_multicast(const nd_addr_t *addr)
{
    return addr->u8[0] == 0xff;
}

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
static const uint32_t ndL_masks[] = {
    0x80000000, 0xc0000000, 0xe0000000, 0xf0000000, 0xf8000000, 0xfc000000, 0xfe000000, 0xff000000,
    0xff800000, 0xffc00000, 0xffe00000, 0xfff00000, 0xfff80000, 0xfffc0000, 0xfffe0000, 0xffff0000,
    0xffff8000, 0xffffc000, 0xffffe000, 0xfffff000, 0xfffff800, 0xfffffc00, 0xfffffe00, 0xffffff00,
    0xffffff80, 0xffffffc0, 0xffffffe0, 0xfffffff0, 0xfffffff8, 0xfffffffc, 0xfffffffe, 0xffffffff,
};
#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
static const uint32_t ndL_masks[] = {
    0x00000080, 0x000000c0, 0x000000e0, 0x000000f0, 0x000000f8, 0x000000fc, 0x000000fe, 0x000000ff,
    0x000080ff, 0x0000c0ff, 0x0000e0ff, 0x0000f0ff, 0x0000f8ff, 0x0000fcff, 0x0000feff, 0x0000ffff,
    0x0080ffff, 0x00c0ffff, 0x00e0ffff, 0x00f0ffff, 0x00f8ffff, 0x00fcffff, 0x00feffff, 0x00ffffff,
    0x80ffffff, 0xc0ffffff, 0xe0ffffff, 0xf0ffffff, 0xf8ffffff, 0xfcffffff, 0xfeffffff, 0xffffffff,
};
#else
#    error __BYTE_ORDER__ is not defined
#endif

bool nd_addr_eq(const nd_addr_t *first, const nd_addr_t *second)
{
    return first->u32[0] == second->u32[0] && first->u32[1] == second->u32[1] && first->u32[2] == second->u32[2] &&
           first->u32[3] == second->u32[3];
}

bool nd_addr_match(const nd_addr_t *first, const nd_addr_t *second, unsigned pflen)
{
    if (pflen > 128) {
        return false;
    } else if (pflen == 0) {
        return true;
    } else if (pflen == 128) {
        return nd_addr_eq(first, second);
    }

    for (unsigned i = 0, top = (pflen - 1) >> 5; i <= top; i++) {
        uint32_t mask = i < top ? 0xffffffff : ndL_masks[(pflen - 1) & 31];

        if ((first->u32[i] ^ second->u32[i]) & mask) {
            return false;
        }
    }

    return true;
}

void nd_addr_combine(const nd_addr_t *first, const nd_addr_t *second, unsigned pflen, nd_addr_t *result)
{
    if (pflen == 0) {
        *result = *second;
        return;
    }

    if (pflen >= 128) {
        *result = *first;
        return;
    }

    for (unsigned i = 0, top = (pflen - 1) >> 5; i < 4; i++) {
        if (i == top) {
            uint32_t mask = ndL_masks[(pflen - 1) & 31];
            result->u32[i] = (first->u32[i] & mask) | (second->u32[i] & ~mask);
        } else if (i < top) {
            result->u32[i] = first->u32[i];
        } else {
            result->u32[i] = second->u32[i];
        }
    }
}

static int ndL_count_bits(uint32_t n)
{
    n = (n & 0x55555555) + ((n >> 1) & 0x55555555);
    n = (n & 0x33333333) + ((n >> 2) & 0x33333333);
    n = (n & 0x0f0f0f0f) + ((n >> 4) & 0x0f0f0f0f);
    n = (n & 0x00ff00ff) + ((n >> 8) & 0x00ff00ff);
    n = (n & 0x0000ffff) + ((n >> 16) & 0x0000ffff);
    return n;
}

int nd_mask_to_pflen(const nd_addr_t *netmask)
{
    return ndL_count_bits(netmask->u32[0]) + ndL_count_bits(netmask->u32[1]) + ndL_count_bits(netmask->u32[2]) +
           ndL_count_bits(netmask->u32[3]);
}

void nd_mask_from_pflen(unsigned pflen, nd_addr_t *netmask)
{
    if (pflen == 0) {
        *netmask = (nd_addr_t){ 0 };
        return;
    }

    if (pflen >= 128) {
        memset(netmask, 0xff, sizeof(nd_addr_t));
        return;
    }

    for (unsigned i = 0, top = (pflen - 1) >> 5; i < 4; i++) {
        if (i == top) {
            netmask->u32[i] = ndL_masks[(pflen - 1) & 31];
        } else if (i < top) {
            netmask->u32[i] = 0xffffffff;
        } else {
            netmask->u32[i] = 0;
        }
    }
}

bool nd_addr_is_unspecified(const nd_addr_t *addr)
{
    return addr->u32[0] == 0 && addr->u32[1] == 0 && addr->u32[2] == 0 && addr->u32[3] == 0;
}

const char *nd_ll_ntoa(const nd_lladdr_t *addr)
{
    static int index;
    static char buf[3][64];

    if (addr == NULL) {
        return "(null)";
    }

    return ether_ntoa_r((struct ether_addr *)addr, buf[index++ % 3]);
}

bool nd_ll_addr_is_unspecified(const nd_lladdr_t *lladdr)
{
    return !lladdr->u8[0] && !lladdr->u8[1] && !lladdr->u8[2] && !lladdr->u8[3] && !lladdr->u8[4] && !lladdr->u8[5];
}
