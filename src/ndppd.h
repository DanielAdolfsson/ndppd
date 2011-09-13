// ndppd - NDP Proxy Daemon
// Copyright (C) 2011  Daniel Adolfsson
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

#ifndef __NDPPD_H
#define __NDPPD_H

#include <netinet/ip6.h>

#define __NDPPD_NS_BEGIN   namespace ndppd {
#define __NDPPD_NS_END     }

#define NDPPD_VERSION "0.1-alpha"

#include "log.h"
#include "ptr.h"
#include "conf.h"
#include "address.h"

#include "iface.h"
#include "proxy.h"
#include "session.h"
#include "rule.h"

#if 0

#define NDPPD_LOG_FATAL     10
#define NDPPD_LOG_ERROR     20
#define NDPPD_LOG_WARNING   30
#define NDPPD_LOG_BUG       40
#define NDPPD_LOG_NOTICE    50
#define NDPPD_LOG_INFO      60
#define NDPPD_LOG_DEBUG     70

#ifdef DEBUG
#define DBG(...) log_printf(NDPPD_LOG_DEBUG,   __VA_ARGS__)
#else
#define DBG(...)
#endif

#define ERR(...) log_printf(NDPPD_LOG_ERROR,   __VA_ARGS__)
#define WRN(...) log_printf(NDPPD_LOG_WARNING, __VA_ARGS__)
#define BUG(...) log_printf(NDPPD_LOG_BUG,     __VA_ARGS__)
#define NFO(...) log_printf(NDPPD_LOG_INFO,    __VA_ARGS__)
#define NCE(...) log_printf(NDPPD_LOG_NOTICE,  __VA_ARGS__)
#define FTL(...) log_printf(NDPPD_LOG_FATAL,   __VA_ARGS__)

#ifndef NULL
#define NULL   ((void *)0)
#endif

#ifndef null
#define null   0
#endif

#ifndef TRUE
#define TRUE   1
#endif

#ifndef FALSE
#define FALSE  0
#endif

typedef struct net_socket     net_socket_t;
typedef struct proxy          proxy_t;
typedef struct rule           rule_t;
typedef struct list           list_t;
typedef struct list_item      list_item_t;
typedef struct ndpsn          ndpsn_t;

struct list
{
   list_item_t *first, *last;
   int count;
};

struct list_item
{
   list_t *list;
   list_item_t *next, *prev;
   void *ptr;
};

struct net_socket
{
   int fd;
   char iface[64];

   list_t ndpsn_list;

   list_t proxy_list;
};

struct ndpsn
{
   net_socket_t *sns, *ans;
   struct in6_addr saddr, aaddr, taddr;
   int ttl;
};

struct proxy
{
   net_socket_t *ns;
   list_t rule_list;
};

struct rule
{
   proxy_t *proxy;
   struct in6_addr addr;
   struct in6_addr mask;
};

/* log.c */
void log_printf(int level, const char *fmt, ...);

/* icmp6.c */
net_socket_t *net_open(const char *iface);
int net_read(net_socket_t *ns, struct in6_addr *saddr, unsigned char *msg, size_t size);

/* conf.c */
int conf_load(const char *path);

/* list.c */
list_item_t *list_add(list_t *list, void *ptr);
void list_remove(list_item_t *li);
void list_clear(list_t *list);
void list_init(list_t *list);

/* ndpsn.c */
ndpsn_t *ndpsn_new(net_socket_t *ns, struct in6_addr *saddr, struct in6_addr *taddr);

/* util.c */
int util_parse_addr6(const char *ip, struct in6_addr *addr, struct in6_addr *mask);
int util_match_addr6(struct in6_addr *addr1, struct in6_addr *addr2, struct in6_addr *mask);
const char *util_ntop6(struct in6_addr *addr, struct in6_addr *mask);
int util_prefix2mask(int prefix, struct in6_addr *mask);
int util_mask2prefix(struct in6_addr *mask);


/* proxy.h */
proxy_t *proxy_new(const char *iface);

/* rule.h */
rule_t *rule_new(proxy_t *p, struct in6_addr *addr, struct in6_addr *mask);

#endif

#endif /* __NDPPD_H */
 
 
