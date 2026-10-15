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
 * A TAP 13 emitter in plain C99 with no dependencies beyond libc.
 *
 * ndppd is expected to build with nothing but a compiler, on platforms as
 * old and as odd as the ones in #67 and #73.  A unit suite that dragged in
 * a test framework would make that claim untestable precisely where it
 * matters most, so this is the whole framework: a counter and four macros.
 */
#ifndef NDPPD_TEST_TAP_H
#define NDPPD_TEST_TAP_H

#include <stdio.h>
#include <string.h>

extern int tap_count;
extern int tap_failed;
extern const char *tap_group;
extern const char *tap_todo_reason;

void tap_diag(const char *fmt, ...);
void tap_begin(const char *name);

/* ok(cond, "description", ...) is the only assertion the suite needs.  The
 * rest are thin wrappers that produce a better diagnostic on failure. */
#define ok(cond, ...)                                                                                                  \
    do {                                                                                                               \
        int _c = !!(cond);                                                                                             \
        printf("%sok %d - %s: ", _c ? "" : "not ", ++tap_count, tap_group);                                            \
        printf(__VA_ARGS__);                                                                                           \
        printf("\n");                                                                                                  \
        if (!_c) {                                                                                                     \
            tap_failed++;                                                                                              \
            tap_diag("  failed at %s:%d", __FILE__, __LINE__);                                                         \
            tap_diag("  expression: %s", #cond);                                                                       \
        }                                                                                                              \
    } while (0)

#define ok_int(got, want, ...)                                                                                         \
    do {                                                                                                               \
        long _g = (long)(got), _w = (long)(want);                                                                      \
        int _c = _g == _w;                                                                                             \
        printf("%sok %d - %s: ", _c ? "" : "not ", ++tap_count, tap_group);                                            \
        printf(__VA_ARGS__);                                                                                           \
        printf("\n");                                                                                                  \
        if (!_c) {                                                                                                     \
            tap_failed++;                                                                                              \
            tap_diag("  failed at %s:%d", __FILE__, __LINE__);                                                         \
            tap_diag("  got %ld, want %ld", _g, _w);                                                                   \
        }                                                                                                              \
    } while (0)

#define ok_str(got, want, ...)                                                                                         \
    do {                                                                                                               \
        const char *_g = (got), *_w = (want);                                                                          \
        int _c = _g && _w && !strcmp(_g, _w);                                                                          \
        printf("%sok %d - %s: ", _c ? "" : "not ", ++tap_count, tap_group);                                            \
        printf(__VA_ARGS__);                                                                                           \
        printf("\n");                                                                                                  \
        if (!_c) {                                                                                                     \
            tap_failed++;                                                                                              \
            tap_diag("  failed at %s:%d", __FILE__, __LINE__);                                                         \
            tap_diag("  got \"%s\", want \"%s\"", _g ? _g : "(null)", _w ? _w : "(null)");                             \
        }                                                                                                              \
    } while (0)

/* todo("reason"); ok_todo(...) marks an assertion as a known failure: it is
 * reported, and counted, but does not fail the run.  Used to pin a bug the
 * suite reproduces but that is out of scope to fix in the same change.
 * Delete the todo() line and switch ok_todo back to ok when the bug is
 * fixed, and the assertion starts enforcing the fix. */
#define todo(reason) (tap_todo_reason = (reason))

#define ok_todo(cond, ...)                                                                                             \
    do {                                                                                                               \
        int _c = !!(cond);                                                                                             \
        printf("%sok %d - %s: ", _c ? "" : "not ", ++tap_count, tap_group);                                            \
        printf(__VA_ARGS__);                                                                                           \
        printf(" # TODO %s\n", tap_todo_reason ? tap_todo_reason : "known failure");                                   \
        tap_todo_reason = NULL;                                                                                        \
    } while (0)

#endif /* NDPPD_TEST_TAP_H */
