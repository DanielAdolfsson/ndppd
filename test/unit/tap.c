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
#include <stdarg.h>
#include <stdio.h>

#include "tap.h"

int tap_count;
int tap_failed;
const char *tap_group = "";
const char *tap_todo_reason;

void tap_diag(const char *fmt, ...)
{
    va_list va;
    va_start(va, fmt);
    printf("# ");
    vprintf(fmt, va);
    printf("\n");
    va_end(va);
}

void tap_begin(const char *name)
{
    tap_group = name;
    printf("# Subtest: %s\n", name);
}
