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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ndppd.h"
#include "tap.h"

void test_addr(void);
void test_alloc(void);
void test_conf(void);
void test_proxy(void);
void test_session(void);

int main(int argc, char *argv[])
{
    /* The negative configuration cases expect parse errors, and a hundred
     * of them scrolling past is noise.  -v puts the log back. */
    bool verbose = false;

    for (int i = 1; i < argc; i++)
        if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--verbose"))
            verbose = true;

    nd_opt_verbosity = verbose ? ND_LOG_TRACE : ND_LOG_ERROR;

    printf("TAP version 13\n");

    test_addr();
    test_alloc();
    test_conf();
    test_proxy();
    test_session();

    printf("1..%d\n", tap_count);

    if (tap_failed) {
        printf("# FAILED %d of %d\n", tap_failed, tap_count);
        return 1;
    }

    printf("# passed %d\n", tap_count);
    return 0;
}
