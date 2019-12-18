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
#ifndef NDPPD_ADDR_H
#define NDPPD_ADDR_H

#include "ndppd.h"

/*! Returns true if <tt>addr</tt> is a multicast address. */
bool nd_addr_is_multicast(const nd_addr_t *addr);

/*! Returns the string representation of <tt>addr</tt>.
 *
 * @note This function returns a pointer to static data. It uses three different static arrays
 *       to allow the function to be chained.
 */
const char *nd_ntoa(const nd_addr_t *addr);

/*! Returns true if the first <tt>pflen</tt> bits are the same in <tt>first</tt> and <tt>second</tt>. */
bool nd_addr_match(const nd_addr_t *first, const nd_addr_t *second, unsigned pflen);

/*! Returns true if <tt>first</tt> and <tt>second</tt> are the same. */
bool nd_addr_eq(const nd_addr_t *first, const nd_addr_t *second);

int nd_mask_to_pflen(const nd_addr_t *netmask);

void nd_mask_from_pflen(unsigned pflen, nd_addr_t *netmask);

void nd_addr_combine(const nd_addr_t *first, const nd_addr_t *second, unsigned pflen, nd_addr_t *result);

bool nd_addr_is_unspecified(const nd_addr_t *addr);

/*! Returns the string representation of link-layer address <tt>addr</tt>.
 *
 * @note This function returns a pointer to static data. It uses three different static arrays
 *       to allow the function to be chained.
 */
const char *nd_ll_ntoa(const nd_lladdr_t *addr);

#endif /* NDPPD_ADDR_H */
