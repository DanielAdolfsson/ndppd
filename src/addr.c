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
#include <arpa/inet.h>
#include <string.h>

#ifndef __linux__
#    include <sys/socket.h>
#    define s6_addr32 __u6_addr.__u6_addr32
#endif

#include "ndppd.h"

//! Returns the string representation of <tt>addr</tt>.
//! @note This function returns a pointer to static data. It uses three different static arrays
//!       to allow the function to be chained.
const char *nd_aton(nd_addr_t *addr)
{
    static int index;
    static char buf[3][64];

    if (addr == NULL)
        return "(null)";

    int n = index++ % 3;

    return inet_ntop(AF_INET6, addr, buf[n], sizeof(buf[n]));
}

//! Returns true if <tt>addr</tt> is a multicast address.
bool nd_addr_is_multicast(nd_addr_t *addr)
{
    return addr->s6_addr[0] == 0xff;
}

bool nd_addr_is_unicast(nd_addr_t *addr)
{
    return !(addr->s6_addr32[2] == 0 && addr->s6_addr32[3] == 0) && addr->s6_addr[0] != 0xff;
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

//! Returns true if <tt>first</tt> and <tt>second</tt> are the same.
bool nd_addr_eq(nd_addr_t *first, nd_addr_t *second)
{
    return first->s6_addr32[0] == second->s6_addr32[0] && first->s6_addr32[1] == second->s6_addr32[1] &&
           first->s6_addr32[2] == second->s6_addr32[2] && first->s6_addr32[3] == second->s6_addr32[3];
}

//! Returns true if the first <tt>pflen</tt> bits are the same in <tt>first</tt> and <tt>second</tt>.
bool nd_addr_match(nd_addr_t *first, nd_addr_t *second, unsigned pflen)
{
    if (pflen > 128)
        return false;
    else if (pflen == 0)
        return true;
    else if (pflen == 128)
        return nd_addr_eq(first, second);

    for (unsigned i = 0, top = (pflen - 1) >> 5U; i <= top; i++)
    {
        uint32_t mask = i < top ? 0xffffffff : ndL_masks[(pflen - 1) & 31U];

        if ((first->s6_addr32[i] ^ second->s6_addr32[i]) & mask)
            return false;
    }

    return true;
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

int nd_addr_to_pflen(nd_addr_t *netmask)
{
    return ndL_count_bits(netmask->s6_addr32[0]) + ndL_count_bits(netmask->s6_addr32[1]) +
           ndL_count_bits(netmask->s6_addr32[2]) + ndL_count_bits(netmask->s6_addr32[3]);
}

void nd_addr_from_pflen(unsigned pflen, nd_addr_t *netmask)
{
    if (pflen >= 97)
    {
        netmask->s6_addr32[0] = 0xffffffff;
        netmask->s6_addr32[1] = 0xffffffff;
        netmask->s6_addr32[2] = 0xffffffff;
        netmask->s6_addr32[3] = ndL_masks[pflen - 97];
    }
    else if (pflen >= 65)
    {
        netmask->s6_addr32[0] = 0xffffffff;
        netmask->s6_addr32[1] = 0xffffffff;
        netmask->s6_addr32[2] = ndL_masks[pflen - 65];
        netmask->s6_addr32[3] = 0x00000000;
    }
    else if (pflen >= 33)
    {
        netmask->s6_addr32[0] = 0xffffffff;
        netmask->s6_addr32[1] = ndL_masks[pflen - 33];
        netmask->s6_addr32[2] = 0x00000000;
        netmask->s6_addr32[3] = 0x00000000;
    }
    else if (pflen >= 1)
    {
        netmask->s6_addr32[0] = ndL_masks[pflen - 1];
        netmask->s6_addr32[1] = 0x00000000;
        netmask->s6_addr32[2] = 0x00000000;
        netmask->s6_addr32[3] = 0x00000000;
    }
    else
    {
        netmask->s6_addr32[0] = 0x00000000;
        netmask->s6_addr32[1] = 0x00000000;
        netmask->s6_addr32[2] = 0x00000000;
        netmask->s6_addr32[3] = 0x00000000;
    }
}
