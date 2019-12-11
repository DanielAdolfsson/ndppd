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

#include "ndppd.h"

/*! Get the string representation of the specified address.
 *
 * @note This function returns a pointer to static data. It uses three different static arrays
 * to allow the function to be chained.
 *
 * @param addr
 * @return
 */
const char *nd_addr_to_string(nd_addr_t *addr)
{
    static int index;
    static char buf[3][64];

    if (addr == NULL)
        return "(null)";

    int n = index++ % 3;

    return inet_ntop(AF_INET6, addr, buf[n], sizeof(buf[n]));
}

/*! Returns true if the specified address is a multicast address. */
bool nd_addr_is_multicast(nd_addr_t *addr)
{
    return addr->s6_addr[0] == 0xff;
}

bool nd_addr_is_unicast(nd_addr_t *addr)
{
    return !(addr->s6_addr32[2] == 0 && addr->s6_addr32[3] == 0) && addr->s6_addr[0] != 0xff;
}

/*! Compares two addresses using the specified prefix length.
 *
 * @param first
 * @param second
 * @param pflen
 * @return true if there is a match
 */
bool nd_addr_match(nd_addr_t *first, nd_addr_t *second, int pflen)
{
    if (pflen < 0 || pflen > 128)
        return false;

    if (pflen == 0)
        return true;

    if (pflen == 128)
        return first->s6_addr32[0] == second->s6_addr32[0] && first->s6_addr32[1] == second->s6_addr32[1] &&
               first->s6_addr32[2] == second->s6_addr32[2] && first->s6_addr32[3] == second->s6_addr32[3];

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    const uint32_t masks[] = {
        0x80000000, 0xc0000000, 0xe0000000, 0xf0000000, 0xf8000000, 0xfc000000, 0xfe000000, 0xff000000,
        0xff800000, 0xffc00000, 0xffe00000, 0xfff00000, 0xfff80000, 0xfffc0000, 0xfffe0000, 0xffff0000,
        0xffff8000, 0xffffc000, 0xffffe000, 0xfffff000, 0xfffff800, 0xfffffc00, 0xfffffe00, 0xffffff00,
        0xffffff80, 0xffffffc0, 0xffffffe0, 0xfffffff0, 0xfffffff8, 0xfffffffc, 0xfffffffe, 0xffffffff,
    };
#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    const uint32_t masks[] = {
        0x00000080, 0x000000c0, 0x000000e0, 0x000000f0, 0x000000f8, 0x000000fc, 0x000000fe, 0x000000ff,
        0x000080ff, 0x0000c0ff, 0x0000e0ff, 0x0000f0ff, 0x0000f8ff, 0x0000fcff, 0x0000feff, 0x0000ffff,
        0x0080ffff, 0x00c0ffff, 0x00e0ffff, 0x00f0ffff, 0x00f8ffff, 0x00fcffff, 0x00feffff, 0x00ffffff,
        0x80ffffff, 0xc0ffffff, 0xe0ffffff, 0xf0ffffff, 0xf8ffffff, 0xfcffffff, 0xfeffffff, 0xffffffff,
    };
#else
#    error __BYTE_ORDER__ is not defined
#endif

    for (unsigned int i = 0, top = (unsigned int)(pflen - 1) >> 5U; i <= top; i++)
    {
        uint32_t mask = i < top ? 0xffffffff : masks[(unsigned int)(pflen - 1) & 31U];

        if ((first->s6_addr32[i] ^ second->s6_addr32[i]) & mask)
            return false;
    }

    return true;
}

bool nd_addr_eq(nd_addr_t *first, nd_addr_t *second)
{
    return first->s6_addr32[0] == second->s6_addr32[0] && first->s6_addr32[1] == second->s6_addr32[1] &&
           first->s6_addr32[2] == second->s6_addr32[2] && first->s6_addr32[3] == second->s6_addr32[3];
}
