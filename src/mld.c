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
#include "mld.h"
#include "iface.h"
#include "ndppd.h"

static nd_ml_t *ndL_first_ml, *ndL_first_free_ml;

nd_ml_t *nd_mld_watch(const char *ifname)
{
    nd_iface_t *iface = nd_iface_open(ifname, 0);

    if (iface == NULL) {
        return NULL;
    }

    (void)ndL_first_free_ml;
    (void)ndL_first_ml;
    (void) ifname;
    return NULL;
}





