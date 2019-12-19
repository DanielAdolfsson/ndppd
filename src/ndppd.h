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

#include <net/if.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define NDPPD_VERSION "1.0-beta1"

/*
 * Types.
 */

typedef struct nd_iface nd_iface_t;
typedef struct nd_io nd_io_t;
typedef struct nd_proxy nd_proxy_t;
typedef struct nd_rule nd_rule_t;
typedef struct nd_session nd_session_t;
typedef union nd_addr nd_addr_t;
typedef struct nd_lladdr nd_lladdr_t;
typedef struct nd_rt_route nd_rt_route_t;
typedef struct nd_rt_addr nd_rt_addr_t;
typedef struct nd_ml nd_ml_t;
typedef struct nd_sub nd_sub_t;

typedef void(nd_io_handler_t)(nd_io_t *io, int events);

/*
 * Enums.
 */

typedef enum {
    //! Address resolution is in progress.
    ND_STATE_INCOMPLETE,

    ND_STATE_VALID,

    ND_STATE_STALE,

    //! Resolution failed, and further Neighbor Solicitation messages will be ignored until
    //! the session is removed or a Neighbor Advertisement is received.
    ND_STATE_INVALID,

} nd_state_t;

typedef enum {
    ND_MODE_UNKNOWN,
    ND_MODE_STATIC,
    ND_MODE_IFACE, // Use a specific interface
    ND_MODE_AUTO,
} nd_mode_t;

typedef enum {
    ND_LOG_ERROR,
    ND_LOG_INFO,
    ND_LOG_DEBUG,
    ND_LOG_TRACE,
} nd_loglevel_t;

/*
 * Structs.
 */

union nd_addr {
    uint32_t u32[4];
    uint8_t u8[16];
} __attribute__((packed));

struct nd_lladdr {
    uint8_t u8[6];
} __attribute__((packed));

struct nd_proxy {
    nd_proxy_t *next;
    char ifname[IF_NAMESIZE];

    nd_lladdr_t target;

    nd_iface_t *iface;
    nd_rule_t *rules;
    bool router;
};

struct nd_session {
    nd_session_t *next;   /* Next session in ndL_sessions. */
    nd_session_t *next_r; /* Next session in ndL_sessions_r. */
    nd_rule_t *rule;      /* */
    nd_addr_t tgt;        /* Target address. */
    nd_addr_t tgt_r;      /* Rewritten target address. */
    int ons_count;        /* Number of outgoing NS messages. */
    long ons_time;        /* Last time we sent a NS message. */
    long ins_time;        /* Last time this session was the target of an incoming NS. */
    long state_time;      /* Time when session entered it's current state. */
    nd_state_t state;
    nd_iface_t *iface;
    nd_sub_t *subs;
    bool autowired; /* If this session had a route set up. */
};

struct nd_sub {
    nd_sub_t *next;
    nd_addr_t addr;
    nd_lladdr_t lladdr;
};

struct nd_rule {
    nd_rule_t *next;
    nd_proxy_t *proxy;

    char ifname[IF_NAMESIZE];

    nd_lladdr_t target;
    nd_addr_t addr;
    int prefix;

    nd_addr_t rewrite_tgt;
    int rewrite_pflen;

    nd_iface_t *iface;
    bool autowire;
    int table;
    nd_mode_t mode;
};

struct nd_iface {
    nd_iface_t *next;
    int refcount;

    char name[IF_NAMESIZE];
    nd_lladdr_t lladdr;

    uint index;

    nd_proxy_t *proxy;

#ifndef __linux__
    nd_io_t *bpf_io;
#endif
};

struct nd_ml {
    nd_ml_t *next;
    nd_iface_t *iface;
    nd_addr_t mcast;
    long last_seen;
};

struct nd_rt_route {
    nd_rt_route_t *next;
    nd_addr_t dst;
    unsigned oif;
    unsigned pflen;
    unsigned table;
    bool owned; // If this route is owned by ndppd.
};

struct nd_rt_addr {
    nd_rt_addr_t *next;
    unsigned iif;
    nd_addr_t addr;
    unsigned pflen;
};

struct nd_io {
    nd_io_t *next;
    int fd;
    uintptr_t data;
    nd_io_handler_t *handler;
};

/*
 * Macros.
 */

#define ND_UNUSED __attribute__((unused))
#define ND_ALIGNED(x) __attribute((aligned(x)))

#define ND_LL_PREPEND(head, el, next)                                                                                  \
    do {                                                                                                               \
        (el)->next = (head);                                                                                           \
        (head) = (el);                                                                                                 \
    } while (0)

#define ND_LL_DELETE(head, el, next)                                                                                   \
    do {                                                                                                               \
        __typeof(el) _last = (head);                                                                                   \
        while (_last != NULL && _last->next != (el))                                                                   \
            _last = _last->next;                                                                                       \
        if (_last)                                                                                                     \
            _last->next = (el)->next;                                                                                  \
        if ((head) == (el))                                                                                            \
            (head) = (el)->next;                                                                                       \
    } while (0)

#define ND_LL_COUNT(head, count, next)                                                                                 \
    do {                                                                                                               \
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
    do {                                                                                                               \
        for (el = (head); el && !(pred); el = el->next)                                                                \
            ;                                                                                                          \
    } while (0)

#define ND_NEW(type) (type *)nd_alloc(sizeof(type))
#define ND_DELETE(ptr) nd_free((ptr), sizeof((ptr)[0]))

/*
 * ndppd.c
 */

extern long nd_current_time;
extern bool nd_daemonized;
extern bool nd_opt_syslog;
extern bool nd_opt_daemonize;

/*
 * addr.c
 */

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

uint32_t nd_addr_hash(const nd_addr_t *addr);

/*! Returns the string representation of link-layer address <tt>addr</tt>.
 *
 * @note This function returns a pointer to static data. It uses three different static arrays
 *       to allow the function to be chained.
 */
const char *nd_ll_ntoa(const nd_lladdr_t *addr);

bool nd_ll_addr_is_unspecified(const nd_lladdr_t *lladdr);

/*
 * proxy.c
 */

nd_proxy_t *nd_proxy_create(const char *ifname);
void nd_proxy_handle_ns(nd_proxy_t *proxy, const nd_addr_t *src, const nd_addr_t *dst, const nd_addr_t *tgt,
                        const nd_lladdr_t *src_ll);
bool nd_proxy_startup();

/*
 * session.c
 */

nd_session_t *nd_session_create(nd_rule_t *rule, const nd_addr_t *tgt);
void nd_session_update(nd_session_t *session);
void nd_session_handle_ns(nd_session_t *session, const nd_addr_t *src, const nd_lladdr_t *src_ll);
void nd_session_handle_na(nd_session_t *session);
nd_session_t *nd_session_find(const nd_addr_t *tgt, const nd_proxy_t *proxy);
nd_session_t *nd_session_find_r(const nd_addr_t *tgt, const nd_iface_t *iface);
void nd_session_update_all();

/*
 * rule.c
 */

nd_rule_t *nd_rule_create(nd_proxy_t *proxy);

/*
 * alloc.c
 */

void *nd_alloc(size_t size);
void nd_free(void *ptr, size_t size);
char *nd_strdup(const char *str);
void nd_alloc_cleanup();

/*
 * conf.c
 */

bool nd_conf_load(const char *path);

/*
 * iface.c
 */

nd_iface_t *nd_iface_open(const char *if_name, unsigned int if_index);
void nd_iface_close(nd_iface_t *iface);
ssize_t nd_iface_send_ns(nd_iface_t *iface, const nd_addr_t *tgt);
ssize_t nd_iface_send_na(nd_iface_t *iface, const nd_addr_t *dst, const nd_lladdr_t *dst_ll, //
                         const nd_addr_t *tgt, const nd_lladdr_t *tgt_ll, bool router);
bool nd_iface_startup();
void nd_iface_cleanup();

/*
 * io.c
 */

nd_io_t *nd_io_socket(int domain, int type, int protocol);
nd_io_t *nd_io_open(const char *file, int oflag);
void nd_io_close(nd_io_t *io);
bool nd_io_bind(nd_io_t *io, const struct sockaddr *addr, size_t addrlen);
ssize_t nd_io_send(nd_io_t *io, const struct sockaddr *addr, size_t addrlen, const void *msg, size_t msglen);
ssize_t nd_io_recv(nd_io_t *io, struct sockaddr *addr, size_t addrlen, void *msg, size_t msglen);
bool nd_io_poll();
ssize_t nd_io_read(nd_io_t *io, void *buf, size_t count);
ssize_t nd_io_write(nd_io_t *io, void *buf, size_t count);

/*
 * log.h
 */

extern nd_loglevel_t nd_opt_verbosity;
extern bool nd_opt_syslog;

void nd_log_printf(nd_loglevel_t level, const char *fmt, ...);

#ifdef NDPPD_NO_TRACE
#    define nd_log_trace(fmt, ...) (void)
#else
#    define nd_log_trace(fmt, ...) nd_log_printf(ND_LOG_TRACE, fmt, ##__VA_ARGS__)
#endif

#define nd_log_error(fmt, ...) nd_log_printf(ND_LOG_ERROR, fmt, ##__VA_ARGS__)
#define nd_log_info(fmt, ...) nd_log_printf(ND_LOG_INFO, fmt, ##__VA_ARGS__)
#define nd_log_debug(fmt, ...) nd_log_printf(ND_LOG_DEBUG, fmt, ##__VA_ARGS__)

/*
 * rt.c
 */

extern long nd_rt_dump_timeout;

bool nd_rt_open();
void nd_rt_cleanup();
bool nd_rt_query_addresses();
bool nd_rt_query_routes();
nd_rt_route_t *nd_rt_find_route(const nd_addr_t *addr, unsigned table);
bool nd_rt_add_route(nd_addr_t *dst, unsigned pflen, unsigned oif, unsigned table);
bool nd_rt_remove_route(nd_addr_t *dst, unsigned pflen, unsigned table);
void nl_rt_remove_owned_routes();

#endif /* NDPPD_H */
