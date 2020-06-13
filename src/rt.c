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
#include <errno.h>
#include <string.h>
#include <sys/socket.h>

#ifdef __linux__
#    include <linux/rtnetlink.h>
#    define RTPROT_NDPPD 72
#else
#    include <net/if.h>
#    include <net/if_dl.h>
#    include <net/route.h>
#    include <netinet/in.h>
#    include <stdlib.h>
#    include <sys/sysctl.h>
#    include <unistd.h>
#endif

#include "ndppd.h"

#ifdef __clang__
#    pragma clang diagnostic ignored "-Waddress-of-packed-member"
#endif

// Our AF_ROUTE or AF_NETLINK socket.
static nd_io_t *ndL_io;

// All IPV6 routes on the system.
static nd_rt_route_t *ndL_routes;

// All IPv6 addresses on the system.
static nd_rt_addr_t *ndL_addrs;

long nd_rt_dump_timeout;

static void ndL_new_route(nd_rt_route_t *route)
{
    nd_rt_route_t *new_route;

    ND_LL_FOREACH_NODEF (ndL_routes, new_route, next) {
        if ((nd_addr_eq(&new_route->dst, &route->dst) && new_route->pflen == route->pflen &&
             new_route->table == route->table))
            return;
    }

    new_route = ND_NEW(nd_rt_route_t);

    *new_route = *route;

    // This will ensure the linked list is kept sorted, so it will be easier to find a match.

    nd_rt_route_t *prev = NULL;

    ND_LL_FOREACH (ndL_routes, cur, next) {
        if (new_route->pflen >= cur->pflen)
            break;

        prev = cur;
    }

    if (prev) {
        new_route->next = prev->next;
        prev->next = new_route;
    } else {
        ND_LL_PREPEND(ndL_routes, new_route, next);
    }

    nd_log_debug("rt(event): New route %s/%d dev %d table %d %s", //
                 nd_ntoa(&route->dst), route->pflen, route->oif, route->table, route->owned ? "owned" : "");
}

static void ndL_delete_route(nd_rt_route_t *route)
{
    nd_rt_route_t *prev = NULL, *cur;

    ND_LL_FOREACH_NODEF (ndL_routes, cur, next) {
        if ((nd_addr_eq(&cur->dst, &route->dst) && cur->oif == route->oif && cur->pflen == route->pflen &&
             cur->table == route->table)) {
            break;
        }

        prev = cur;
    }

    if (!cur) {
        return;
    }

    if (prev) {
        prev->next = cur->next;
    } else {
        ndL_routes = cur->next;
    }

    nd_log_debug("rt(event): Delete route %s/%d dev %d table %d", //
                 nd_ntoa(&cur->dst), cur->pflen, cur->oif, cur->table);

    ND_DELETE(cur);
}

static void ndL_new_addr(unsigned index, nd_addr_t *addr, unsigned pflen)
{
    nd_rt_addr_t *rt_addr;

    ND_LL_FOREACH_NODEF (ndL_addrs, rt_addr, next) {
        if (rt_addr->iif == index && nd_addr_eq(&rt_addr->addr, addr) && rt_addr->pflen == pflen) {
            return;
        }
    }

    rt_addr = ND_NEW(nd_rt_addr_t);

    ND_LL_PREPEND(ndL_addrs, rt_addr, next);

    rt_addr->pflen = pflen;
    rt_addr->iif = index;
    rt_addr->addr = *addr;

    nd_log_debug("rt(event): New address %s/%d if %d", nd_ntoa(addr), pflen, index);
}

static void ndL_delete_addr(unsigned int index, nd_addr_t *addr, unsigned pflen)
{
    nd_rt_addr_t *prev = NULL, *rt_addr;

    ND_LL_FOREACH_NODEF (ndL_addrs, rt_addr, next) {
        if (rt_addr->iif == index && nd_addr_eq(&rt_addr->addr, addr) && rt_addr->pflen == pflen) {
            nd_log_debug("rt(event): Delete address %s/%d if %d", nd_ntoa(addr), pflen, index);

            if (prev) {
                prev->next = rt_addr->next;
            } else {
                ndL_addrs = rt_addr->next;
            }

            ND_DELETE(rt_addr);
            return;
        }

        prev = rt_addr;
    }
}

#ifdef __linux__
static void ndL_handle_newaddr(struct ifaddrmsg *msg, int length)
{
    nd_addr_t *addr = NULL;

    for (struct rtattr *rta = IFA_RTA(msg); RTA_OK(rta, length); rta = RTA_NEXT(rta, length)) {
        if (rta->rta_type == IFA_ADDRESS) {
            addr = (nd_addr_t *)RTA_DATA(rta);
        }
    }

    if (!addr) {
        return;
    }

    ndL_new_addr(msg->ifa_index, addr, msg->ifa_prefixlen);
}

static void ndL_handle_deladdr(struct ifaddrmsg *msg, int length)
{
    nd_addr_t *addr = NULL;

    for (struct rtattr *rta = IFA_RTA(msg); RTA_OK(rta, length); rta = RTA_NEXT(rta, length)) {
        if (rta->rta_type == IFA_ADDRESS) {
            addr = (nd_addr_t *)RTA_DATA(rta);
        }
    }

    if (!addr) {
        return;
    }

    ndL_delete_addr(msg->ifa_index, addr, msg->ifa_prefixlen);
}

static void ndL_handle_newroute(struct rtmsg *msg, int rtl)
{
    nd_addr_t *dst = NULL;
    int oif = 0;

    for (struct rtattr *rta = RTM_RTA(msg); RTA_OK(rta, rtl); rta = RTA_NEXT(rta, rtl)) {
        if (rta->rta_type == RTA_OIF) {
            oif = *(int *)RTA_DATA(rta);
        } else if (rta->rta_type == RTA_DST) {
            dst = (nd_addr_t *)RTA_DATA(rta);
        }
    }

    if (!dst || !oif) {
        return;
    }

    nd_rt_route_t route = {
        .table = msg->rtm_table,
        .pflen = msg->rtm_dst_len,
        .oif = oif,
        .dst = *dst,
        .owned = msg->rtm_protocol == RTPROT_NDPPD,
    };

    ndL_new_route(&route);
}

static void ndL_handle_delroute(struct rtmsg *msg, int rtl)
{
    nd_addr_t *dst = NULL;
    int oif = 0;

    for (struct rtattr *rta = RTM_RTA(msg); RTA_OK(rta, rtl); rta = RTA_NEXT(rta, rtl)) {
        if (rta->rta_type == RTA_OIF) {
            oif = *(int *)RTA_DATA(rta);
        } else if (rta->rta_type == RTA_DST) {
            dst = (nd_addr_t *)RTA_DATA(rta);
        }
    }

    if (!dst || !oif) {
        return;
    }

    nd_rt_route_t route = {
        .table = msg->rtm_table,
        .pflen = msg->rtm_dst_len,
        .oif = oif,
        .dst = *dst,
    };

    ndL_delete_route(&route);
}

static void ndL_io_handler(__attribute__((unused)) nd_io_t *unused1, __attribute__((unused)) int unused2)
{
    uint8_t buf[4096];

    for (;;) {
        ssize_t len = nd_io_recv(ndL_io, NULL, 0, buf, sizeof(buf));

        if (len < 0) {
            return;
        }

        for (struct nlmsghdr *hdr = (struct nlmsghdr *)buf; NLMSG_OK(hdr, len); hdr = NLMSG_NEXT(hdr, len)) {
            if (hdr->nlmsg_type == NLMSG_DONE) {
                nd_rt_dump_timeout = 0;
                break;
            }

            if (hdr->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *e = (struct nlmsgerr *)NLMSG_DATA(hdr);
                nd_log_error("rt: Netlink: %s (%d)", strerror(-e->error), e->msg.nlmsg_type);
                continue;
            }

            if (hdr->nlmsg_type == RTM_NEWROUTE) {
                ndL_handle_newroute((struct rtmsg *)NLMSG_DATA(hdr), RTM_PAYLOAD(hdr));
            } else if (hdr->nlmsg_type == RTM_DELROUTE) {
                ndL_handle_delroute((struct rtmsg *)NLMSG_DATA(hdr), RTM_PAYLOAD(hdr));
            } else if (hdr->nlmsg_type == RTM_NEWADDR) {
                ndL_handle_newaddr((struct ifaddrmsg *)NLMSG_DATA(hdr), IFA_PAYLOAD(hdr));
            } else if (hdr->nlmsg_type == RTM_DELADDR) {
                ndL_handle_deladdr((struct ifaddrmsg *)NLMSG_DATA(hdr), IFA_PAYLOAD(hdr));
            }
        }
    }
}
#else
static void ndL_get_rtas(int addrs, struct sockaddr *sa, struct sockaddr **rtas)
{
    for (int i = 0; i < RTAX_MAX; i++) {
        if (addrs & (1 << i)) {
            rtas[i] = sa;
            sa = (void *)sa + ((sa->sa_len + sizeof(u_long) - 1) & ~(sizeof(u_long) - 1));
        } else {
            rtas[i] = NULL;
        }
    }
}

static void ndL_handle_rt(struct rt_msghdr *hdr)
{
    struct sockaddr *rtas[RTAX_MAX];
    ndL_get_rtas(hdr->rtm_addrs, (struct sockaddr *)(hdr + 1), rtas);

    if (!rtas[RTAX_DST] || rtas[RTAX_DST]->sa_family != AF_INET6) {
        return;
    }

    nd_addr_t *dst = (nd_addr_t *)&((struct sockaddr_in6 *)rtas[RTAX_DST])->sin6_addr;
    unsigned pflen = 0;

    if (rtas[RTAX_NETMASK]) {
        nd_addr_t *netmask = (nd_addr_t *)&((struct sockaddr_in6 *)rtas[RTAX_NETMASK])->sin6_addr;
        pflen = nd_mask_to_pflen(netmask);
    }

    // FIXME: Should we use RTAX_GATEWAY to get the interface index?

    nd_rt_route_t route = {
        .dst = *dst,
        .oif = hdr->rtm_index,
        .pflen = pflen,
#    ifdef __FreeBSD__
        .table = 0,
#    else
        .table = hdr->rtm_tableid,
#    endif
        .owned = (hdr->rtm_flags & RTF_PROTO3) != 0,
    };

    if (hdr->rtm_type == RTM_GET || hdr->rtm_type == RTM_ADD) {
        ndL_new_route(&route);
    } else if (hdr->rtm_type == RTM_DELETE) {
        ndL_delete_route(&route);
    }
}

static void ndL_handle_ifa(struct ifa_msghdr *hdr)
{
    struct sockaddr *rtas[RTAX_MAX];
    ndL_get_rtas(hdr->ifam_addrs, (struct sockaddr *)(hdr + 1), rtas);

    if (!rtas[RTAX_IFA] || rtas[RTAX_IFA]->sa_family != AF_INET6) {
        return;
    }

    nd_addr_t *ifa = (nd_addr_t *)&((struct sockaddr_in6 *)rtas[RTAX_IFA])->sin6_addr;
    unsigned pflen = 0;

    if (rtas[RTAX_NETMASK]) {
        nd_addr_t *netmask = (nd_addr_t *)&((struct sockaddr_in6 *)rtas[RTAX_NETMASK])->sin6_addr;
        pflen = nd_mask_to_pflen(netmask);
    }

    if (hdr->ifam_type == RTM_NEWADDR) {
        ndL_new_addr(hdr->ifam_index, ifa, pflen);
    } else if (hdr->ifam_type == RTM_DELADDR) {
        ndL_delete_addr(hdr->ifam_index, ifa, pflen);
    }
}

typedef struct {
    u_short msglen;
    u_char version;
    u_char type;
} ndL_msghdr_t;

static void ndL_handle(void *buf, size_t buflen)
{
    for (size_t i = 0; i < buflen;) {
        ndL_msghdr_t *hdr = (ndL_msghdr_t *)(buf + i);
        i += hdr->msglen;

        if (i > buflen) {
            break;
        }

        switch (hdr->type) {
        case RTM_ADD:
        case RTM_GET:
        case RTM_DELETE:
            ndL_handle_rt((struct rt_msghdr *)hdr);
            break;

        case RTM_NEWADDR:
        case RTM_DELADDR:
            ndL_handle_ifa((struct ifa_msghdr *)hdr);
            break;
        }
    }
}

static bool ndL_dump(int type)
{
    int mib[] = { CTL_NET, PF_ROUTE, 0, 0, type, 0 };

    size_t size;
    if (sysctl(mib, 6, NULL, &size, NULL, 0) < 0) {
        nd_log_error("sysctl(): %s", strerror(errno));
        return false;
    }

    void *buf = malloc(size);

    // FIXME: Potential race condition as the number of routes might have increased since the previous syscall().
    if (sysctl(mib, 6, buf, &size, NULL, 0) < 0) {
        free(buf);
        nd_log_error("sysctl(): %s", strerror(errno));
        return false;
    }

    ndL_handle(buf, size);

    free(buf);
    return true;
}

static void ndL_io_handler(__attribute__((unused)) nd_io_t *unused1, __attribute__((unused)) int unused2)
{
    uint8_t buf[4096];

    for (;;) {
        ssize_t len = nd_io_recv(ndL_io, NULL, 0, buf, sizeof(buf));

        if (len < 0) {
            return;
        }

        ndL_handle(buf, len);
    }
}

#endif

bool nd_rt_open()
{
    if (ndL_io != NULL) {
        return true;
    }

#ifdef __linux__
    if (!(ndL_io = nd_io_socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE))) {
        nd_log_error("Failed to open netlink socket: %s", strerror(errno));
        return false;
    }

    struct sockaddr_nl addr = {
        .nl_family = AF_NETLINK,
        .nl_groups = (1 << (RTNLGRP_IPV6_IFADDR - 1)) | (1 << (RTNLGRP_IPV6_ROUTE - 1)),
    };

    if (!nd_io_bind(ndL_io, (struct sockaddr *)&addr, sizeof(addr))) {
        nd_log_error("Failed to bind netlink socket: %s", strerror(errno));
        nd_io_close(ndL_io);
        ndL_io = NULL;
        return false;
    }
#else
    if (!(ndL_io = nd_io_socket(AF_ROUTE, SOCK_RAW, AF_INET6))) {
        nd_log_error("Failed to open routing socket: %s", strerror(errno));
        return false;
    }
#endif

    ndL_io->handler = ndL_io_handler;

    return true;
}

void nd_rt_cleanup()
{
    if (ndL_io) {
        nd_io_close(ndL_io);
    }
}

bool nd_rt_query_routes()
{
#ifdef __linux__
    if (nd_rt_dump_timeout)
        return false;

    struct {
        struct nlmsghdr hdr;
        struct rtmsg msg;
    } req = {
        .hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg)),
        .hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,
        .hdr.nlmsg_type = RTM_GETROUTE,
        .msg.rtm_protocol = RTPROT_UNSPEC,
        .msg.rtm_table = RT_TABLE_UNSPEC,
        .msg.rtm_family = AF_INET6,
    };

    struct sockaddr_nl addr = { .nl_family = AF_NETLINK };

    nd_rt_dump_timeout = nd_current_time + 5000;

    nd_io_send(ndL_io, (struct sockaddr *)&addr, sizeof(addr), &req, sizeof(req));
    return true;
#else
    return ndL_dump(NET_RT_DUMP);
#endif
}

bool nd_rt_query_addresses()
{
#ifdef __linux__
    if (nd_rt_dump_timeout)
        return false;

    struct {
        struct nlmsghdr hdr;
        struct ifaddrmsg msg;
    } req = {
        .hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg)),
        .hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,
        .hdr.nlmsg_type = RTM_GETADDR,
        .hdr.nlmsg_seq = 1,
        .msg.ifa_family = AF_INET6,
    };

    struct sockaddr_nl addr = { .nl_family = AF_NETLINK };

    nd_rt_dump_timeout = nd_current_time + 5000;

    nd_io_send(ndL_io, (struct sockaddr *)&addr, sizeof(addr), &req, sizeof(req));
    return true;
#else
    return ndL_dump(NET_RT_IFLIST);
#endif
}

nd_rt_route_t *nd_rt_find_route(const nd_addr_t *addr, unsigned table)
{
    ND_LL_FOREACH (ndL_routes, route, next) {
        if (nd_addr_match(&route->dst, addr, route->pflen) && route->table == table)
            return route;
    }

    return NULL;
}

bool nd_rt_add_route(nd_addr_t *dst, unsigned pflen, unsigned oif, unsigned table)
{
#ifdef __linux__
    struct __attribute__((packed)) {
        struct nlmsghdr hdr;
        struct rtmsg msg;
        struct rtattr oif_attr __attribute__((aligned(NLMSG_ALIGNTO)));
        uint32_t oif;
        struct rtattr dst_attr __attribute__((aligned(RTA_ALIGNTO)));
        nd_addr_t dst;
        // struct rtattr exp_attr __attribute__((aligned(RTA_ALIGNTO)));
        // uint32_t exp;
    } req = {
        .msg.rtm_protocol = RTPROT_NDPPD,
        .msg.rtm_family = AF_INET6,
        .msg.rtm_dst_len = pflen,
        .msg.rtm_table = table,
        .msg.rtm_scope = RT_SCOPE_UNIVERSE,
        .oif_attr.rta_type = RTA_OIF,
        .oif_attr.rta_len = RTA_LENGTH(sizeof(req.oif)),
        .oif = oif,
        .dst_attr.rta_type = RTA_DST,
        .dst_attr.rta_len = RTA_LENGTH(sizeof(req.dst)),
        .dst = *dst,
        .hdr.nlmsg_type = RTM_NEWROUTE,
        .hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE,
        .hdr.nlmsg_len = sizeof(req),
        // .exp_attr.rta_type = RTA_EXPIRES,
        // .exp_attr.rta_len = RTA_LENGTH(sizeof(req.exp)),
        // .exp = 60,
    };

    struct sockaddr_nl addr = { .nl_family = AF_NETLINK };

    return nd_io_send(ndL_io, (struct sockaddr *)&addr, sizeof(addr), &req, sizeof(req)) >= 0;
#else
    struct {
        struct rt_msghdr hdr;
        struct sockaddr_in6 dst;
        struct sockaddr_dl dl __aligned(sizeof(u_long));
        struct sockaddr_in6 mask __aligned(sizeof(u_long));
    } msg = {
        .hdr.rtm_type = RTM_ADD,
        .hdr.rtm_version = RTM_VERSION,
        .hdr.rtm_pid = getpid(),
        .hdr.rtm_flags = RTF_UP | RTF_PROTO3,
        .hdr.rtm_msglen = sizeof(msg),
        .hdr.rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK,
        .hdr.rtm_index = oif,
#    ifndef __FreeBSD__
        msg.hdr->rtm_tableid = table,
#    endif
        .dst.sin6_family = AF_INET6,
        .dst.sin6_len = sizeof(msg.dst),
        .dst.sin6_addr = *(struct in6_addr *)dst,
        .dl.sdl_family = AF_LINK,
        .dl.sdl_index = oif,
        .dl.sdl_len = sizeof(msg.dl),
        .mask.sin6_family = AF_INET6,
        .mask.sin6_len = sizeof(msg.mask),
    };

    nd_mask_from_pflen(pflen, (nd_addr_t *)&msg.mask.sin6_addr);

    nd_log_info("rt: Adding route %s/%d table %d", nd_ntoa(dst), pflen, table);

    return nd_io_write(ndL_io, &msg, sizeof(msg)) >= 0;
#endif
}

bool nd_rt_remove_route(nd_addr_t *dst, unsigned pflen, unsigned table)
{
#ifdef __linux__
    struct __attribute__((packed)) {
        struct nlmsghdr hdr;
        struct rtmsg msg;
        struct rtattr dst_attr __attribute__((aligned(NLMSG_ALIGNTO)));
        nd_addr_t dst;
    } req = {
        .msg.rtm_protocol = RTPROT_NDPPD,
        .msg.rtm_family = AF_INET6,
        .msg.rtm_dst_len = pflen,
        .msg.rtm_table = table,
        .msg.rtm_scope = RT_SCOPE_UNIVERSE,
        .dst_attr.rta_type = RTA_DST,
        .dst_attr.rta_len = RTA_LENGTH(sizeof(req.dst)),
        .dst = *dst,
        .hdr.nlmsg_type = RTM_DELROUTE,
        .hdr.nlmsg_flags = NLM_F_REQUEST,
        .hdr.nlmsg_len = sizeof(req),
    };

    struct sockaddr_nl addr = { .nl_family = AF_NETLINK };

    return nd_io_send(ndL_io, (struct sockaddr *)&addr, sizeof(addr), &req, sizeof(req)) >= 0;
#else
    struct __attribute__((packed)) {
        struct rt_msghdr hdr;
        struct sockaddr_in6 dst;
        struct sockaddr_in6 mask __aligned(sizeof(u_long));
    } req = {
        .hdr.rtm_type = RTM_DELETE,
        .hdr.rtm_version = RTM_VERSION,
        .hdr.rtm_pid = getpid(),
        .hdr.rtm_msglen = sizeof(req),
        .hdr.rtm_addrs = RTA_DST | RTA_NETMASK,
#    ifndef __FreeBSD__
        .hdr.rtm_tableid = table,
#    endif
        .dst.sin6_family = AF_INET6,
        .dst.sin6_len = sizeof(req.dst),
        .dst.sin6_addr = *(struct in6_addr *)dst,
        .mask.sin6_family = AF_INET6,
        .mask.sin6_len = sizeof(req.mask),
    };

    nd_mask_from_pflen(pflen, (nd_addr_t *)&req.mask.sin6_addr);

    nd_log_info("rt: Removing route %s/%d table %d", nd_ntoa(dst), pflen, table);

    return nd_io_write(ndL_io, &req, sizeof(req)) >= 0;
#endif
}

void nd_rt_remove_owned_routes()
{
    ND_LL_FOREACH_S (ndL_routes, route, tmp, next) {
        if (route->owned) {
            nd_rt_remove_route(&route->dst, route->pflen, route->table);
        }
    }
}

bool nd_rt_add_neigh(nd_addr_t *dst, unsigned oif)
{
    struct __attribute__((packed)) {
        struct nlmsghdr hdr;
        struct ndmsg msg;
        struct rtattr dst_attr __attribute__((aligned(NLMSG_ALIGNTO)));
        nd_addr_t dst;
    } req = {
        .hdr.nlmsg_type = RTM_NEWNEIGH,
        .hdr.nlmsg_flags = NLM_F_REQUEST,
        .hdr.nlmsg_len = sizeof(req),
        .msg.ndm_family = AF_INET6,
        .msg.ndm_state = NUD_PERMANENT,
        .msg.ndm_flags = NTF_PROXY,
        .msg.ndm_ifindex = oif,
        .dst_attr.rta_type = NDA_DST,
        .dst_attr.rta_len = RTA_LENGTH(sizeof(req.dst)),
        .dst = *dst,
    };

    struct sockaddr_nl addr = { .nl_family = AF_NETLINK };

    return nd_io_send(ndL_io, (struct sockaddr *)&addr, sizeof(addr), &req, sizeof(req)) >= 0;
}

bool nd_rt_remove_neigh(nd_addr_t *dst, unsigned oif)
{
    struct __attribute__((packed)) {
        struct nlmsghdr hdr;
        struct ndmsg msg;
        struct rtattr dst_attr __attribute__((aligned(NLMSG_ALIGNTO)));
        nd_addr_t dst;
    } req = {
        .hdr.nlmsg_type = RTM_DELNEIGH,
        .hdr.nlmsg_flags = NLM_F_REQUEST,
        .hdr.nlmsg_len = sizeof(req),
        .msg.ndm_family = AF_INET6,
        .msg.ndm_state = NUD_PERMANENT,
        .msg.ndm_flags = NTF_PROXY,
        .msg.ndm_ifindex = oif,
        .dst_attr.rta_type = NDA_DST,
        .dst_attr.rta_len = RTA_LENGTH(sizeof(req.dst)),
        .dst = *dst,
    };

    struct sockaddr_nl addr = { .nl_family = AF_NETLINK };

    return nd_io_send(ndL_io, (struct sockaddr *)&addr, sizeof(addr), &req, sizeof(req)) >= 0;
}