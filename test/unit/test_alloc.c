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
 * alloc.c is a slab allocator with free lists bucketed by size.  Every
 * session, subscriber and rule comes out of it, and a session is allocated
 * and freed for every target that ever appears on the link -- so a block
 * handed out twice, or a free list that loses a block each time round,
 * shows up as corruption or unbounded growth on a long-running daemon
 * rather than as an immediate crash.
 */
#include <string.h>

#include "ndppd.h"
#include "tap.h"

void test_alloc(void)
{
    tap_begin("alloc");

    /* --- blocks are distinct and usable -------------------------------- */

    {
        enum { N = 256 };
        void *ptrs[N];
        bool overlap = false;

        for (int i = 0; i < N; i++) {
            ptrs[i] = nd_alloc(sizeof(nd_session_t));
            memset(ptrs[i], i & 0xff, sizeof(nd_session_t));
        }

        for (int i = 0; i < N && !overlap; i++) {
            /* Each block still holds what was written to it, which no
             * block can if two of them overlap. */
            unsigned char want = (unsigned char)(i & 0xff);
            unsigned char *p = ptrs[i];

            for (size_t j = 0; j < sizeof(nd_session_t); j++)
                if (p[j] != want)
                    overlap = true;

            for (int k = 0; k < i; k++)
                if (ptrs[i] == ptrs[k])
                    overlap = true;
        }

        ok(!overlap, "256 live allocations are distinct and keep their contents");

        for (int i = 0; i < N; i++)
            nd_free(ptrs[i], sizeof(nd_session_t));
    }

    /* --- freed blocks come back ----------------------------------------- */

    {
        /* The whole point of the free list: a daemon that churns sessions
         * must not grow without bound.  If freeing did not recycle, this
         * loop would allocate a hundred thousand distinct blocks. */
        void *first = nd_alloc(sizeof(nd_sub_t));
        nd_free(first, sizeof(nd_sub_t));

        void *second = nd_alloc(sizeof(nd_sub_t));
        ok(first == second, "a freed block is handed back out again");
        nd_free(second, sizeof(nd_sub_t));

        bool reused = true;
        for (int i = 0; i < 100000; i++) {
            void *p = nd_alloc(sizeof(nd_sub_t));
            if (p != first)
                reused = false;
            nd_free(p, sizeof(nd_sub_t));
        }

        ok(reused, "100000 alloc/free cycles reuse a single block");
    }

    /* --- different sizes do not share a free list ------------------------ */

    {
        void *small = nd_alloc(sizeof(nd_sub_t));
        nd_free(small, sizeof(nd_sub_t));

        void *large = nd_alloc(sizeof(nd_rule_t));
        ok(large != small || sizeof(nd_rule_t) == sizeof(nd_sub_t),
           "a small freed block is not handed out for a larger request");
        nd_free(large, sizeof(nd_rule_t));
    }

    /* --- nd_strdup -------------------------------------------------------- */

    {
        const char *src = "/etc/ndppd.conf";
        char *copy = nd_strdup(src);

        ok(copy != NULL, "nd_strdup returns a pointer");
        ok(copy != src, "nd_strdup copies rather than aliasing");
        ok_str(copy, src, "nd_strdup preserves the string");

        char *empty = nd_strdup("");
        ok_str(empty, "", "nd_strdup handles the empty string");
    }
}
