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
#ifndef NDPPD_H
#define NDPPD_H

#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define NDPPD_VERSION "1.0-beta1"

typedef struct nd_iface nd_iface_t;
typedef struct nd_sio nd_sio_t;
typedef struct nd_proxy nd_proxy_t;
typedef struct nd_conf nd_conf_t;
typedef struct in6_addr nd_addr_t;
typedef struct nd_conf_rule nd_conf_rule_t;
typedef struct nd_conf_proxy nd_conf_proxy_t;
typedef struct nd_rule nd_rule_t;
typedef struct nd_neigh nd_neigh_t;

extern long nd_current_time;
extern bool nd_daemonized;
extern bool nd_opt_syslog;
extern bool nd_opt_daemonize;

#define ND_LL_PREPEND(head, el, next)                                                                                  \
    do                                                                                                                 \
    {                                                                                                                  \
        (el)->next = (head);                                                                                           \
        (head) = (el);                                                                                                 \
    } while (0)

#define ND_LL_DELETE(head, el, next)                                                                                   \
    do                                                                                                                 \
    {                                                                                                                  \
        __typeof(el) _last = (head);                                                                                   \
        while (_last != NULL && _last->next != (el))                                                                   \
            _last = _last->next;                                                                                       \
        if (_last)                                                                                                     \
            _last->next = (el)->next;                                                                                  \
        if ((head) == (el))                                                                                            \
            (head) = (el)->next;                                                                                       \
    } while (0)

#define ND_LL_COUNT(head, count, next)                                                                                 \
    do                                                                                                                 \
    {                                                                                                                  \
        (count) = 0;                                                                                                   \
        for (__typeof(head) _el = (head); _el; _el = _el->next)                                                        \
            (count)++;                                                                                                 \
    } while (0)

#define ND_LL_FOREACH(head, el, next) for (__typeof(head)(el) = (head); (el); (el) = (el)->next)

#define ND_LL_FOREACH_S(head, el, tmp, next)                                                                           \
    for (__typeof(head)(el) = (head), (tmp) = (head) ? (head)->next : NULL; (el);                                      \
         (el) = (tmp), (tmp) = (el) ? (el)->next : NULL)

#define ND_LL_FOREACH_S_NODEF(head, el, tmp, next)                                                                     \
    for ((el) = (head), (tmp) = (head) ? (head)->next : NULL; (el); (el) = (tmp), (tmp) = (el) ? (el)->next : NULL)

#define ND_LL_FOREACH_NODEF(head, el, next) for ((el) = (head); (el); (el) = (el)->next)

#define ND_LL_SEARCH(head, el, next, pred)                                                                             \
    do                                                                                                                 \
    {                                                                                                                  \
        for (el = (head); el && !(pred); el = el->next)                                                                \
            ;                                                                                                          \
    } while (0)

#include "alloc.h"
#include "log.h"

#endif /* NDPPD_H */
