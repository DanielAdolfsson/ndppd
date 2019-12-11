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
#include <string.h>

#include "neigh.h"
#include "ndppd.h"

static nd_neigh_t *ndL_free_neighs;

nd_neigh_t *nd_alloc_neigh()
{
    nd_neigh_t *neigh = ndL_free_neighs;

    if (neigh)
        ND_LL_DELETE(ndL_free_neighs, neigh, next_in_proxy);
    else
        neigh = ND_ALLOC(nd_neigh_t);

    memset(neigh, 0, sizeof(nd_neigh_t));

    return neigh;
}

void nd_free_neigh(nd_neigh_t *session)
{
    ND_LL_PREPEND(ndL_free_neighs, session, next_in_proxy);
}


