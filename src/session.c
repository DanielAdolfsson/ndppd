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

#include "ndppd.h"
#include "session.h"

static nd_session_t *ndL_free_sessions;

nd_session_t *nd_alloc_session()
{
    nd_session_t *session = ndL_free_sessions;

    if (session)
        ND_LL_DELETE(ndL_free_sessions, session, next_in_proxy);
    else
        session = ND_ALLOC(nd_session_t);

    memset(session, 0, sizeof(nd_session_t));

    return session;
}

void nd_free_session(nd_session_t *session)
{
    ND_LL_PREPEND(ndL_free_sessions, session, next_in_proxy);
}
