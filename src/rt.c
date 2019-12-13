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
#else
#    include <net/if.h>
#    include <net/route.h>
#    include <stdlib.h>
#    include <sys/sysctl.h>
#    include <unistd.h>
#endif

#include "addr.h"
#include "io.h"
#include "ndppd.h"
#include "rt.h"

static nd_io_t *ndL_io;
static nd_rt_route_t *ndL_routes, *ndL_free_routes;
static nd_rt_addr_t *ndL_addrs, *ndL_free_addrs;

long nd_rt_dump_timeout;

static void ndL_new_route(unsigned int oif, nd_addr_t *dst, int pflen, int table)
{
    nd_rt_route_t *route;

    ND_LL_FOREACH_NODEF(ndL_routes, route, next)
    {
        if (nd_addr_eq(&route->addr, dst) && route->pflen == pflen && route->table == table)
            return;
    }

    if ((route = ndL_free_routes))
        ND_LL_DELETE(ndL_free_routes, route, next);
    else
        route = ND_ALLOC(nd_rt_route_t);

    route->addr = *dst;
    route->pflen = pflen;
    route->oif = oif;
    route->table = table;

    /*
     * This will ensure the linked list is kept sorted, so it will be easier to find a match.
     */

    nd_rt_route_t *prev = NULL;

    ND_LL_FOREACH(ndL_routes, cur, next)
    {
        if (route->pflen >= cur->pflen && route->metrics <= cur->metrics)
            break;

        prev = cur;
    }

    if (prev)
    {
        route->next = prev->next;
        prev->next = route;
    }
    else
    {
        ND_LL_PREPEND(ndL_routes, route, next);
    }

    nd_log_debug("rt: new route %s/%d dev %d table %d", nd_aton(dst), pflen, oif, table);
}

static void ndL_delete_route(unsigned int oif, nd_addr_t *dst, int pflen, int table)
{
    nd_rt_route_t *prev = NULL, *route;

    ND_LL_FOREACH_NODEF(ndL_routes, route, next)
    {
        if (nd_addr_eq(&route->addr, dst) && route->oif == oif && route->pflen == pflen && route->table == table)
            break;

        prev = route;
    }

    if (!route)
        return;

    if (prev)
        prev->next = route->next;
    else
        ndL_routes = route->next;

    nd_log_debug("rt: delete route %s/%d dev %d table %d", nd_aton(dst), pflen, oif, table);
    ND_LL_PREPEND(ndL_free_routes, route, next);
}

static void ndL_new_addr(unsigned int index, nd_addr_t *addr, int pflen)
{
    nd_rt_addr_t *rt_addr;

    ND_LL_FOREACH_NODEF(ndL_addrs, rt_addr, next)
    {
        if (rt_addr->iif == index && nd_addr_eq(&rt_addr->addr, addr) && rt_addr->pflen == pflen)
            return;
    }

    if ((rt_addr = ndL_free_addrs))
        ND_LL_DELETE(ndL_free_addrs, rt_addr, next);
    else
        rt_addr = ND_ALLOC(nd_rt_addr_t);

    ND_LL_PREPEND(ndL_addrs, rt_addr, next);

    rt_addr->pflen = pflen;
    rt_addr->iif = index;
    rt_addr->addr = *addr;

    nd_log_debug("rt: new address %s/%d if %d", nd_aton(addr), pflen, index);
}

static void ndL_delete_addr(unsigned int index, nd_addr_t *addr, int pflen)
{
    nd_rt_addr_t *prev = NULL, *rt_addr;

    ND_LL_FOREACH_NODEF(ndL_addrs, rt_addr, next)
    {
        if (rt_addr->iif == index && nd_addr_eq(&rt_addr->addr, addr) && rt_addr->pflen == pflen)
        {
            nd_log_debug("rt: delete address %s/%d if %d", nd_aton(addr), pflen, index);

            if (prev)
                prev->next = rt_addr->next;
            else
                ndL_addrs = rt_addr->next;

            ND_LL_PREPEND(ndL_free_addrs, rt_addr, next);
            return;
        }

        prev = rt_addr;
    }
}

#ifdef __linux__
static void ndL_handle_newaddr(struct ifaddrmsg *msg, int length)
{
    nd_addr_t *addr = NULL;

    for (struct rtattr *rta = IFA_RTA(msg); RTA_OK(rta, length); rta = RTA_NEXT(rta, length))
    {
        if (rta->rta_type == IFA_ADDRESS)
            addr = (nd_addr_t *)RTA_DATA(rta);
    }

    if (!addr)
        return;

    ndL_new_addr(msg->ifa_index, addr, msg->ifa_prefixlen);
}

static void ndL_handle_deladdr(struct ifaddrmsg *msg, int length)
{
    nd_addr_t *addr = NULL;

    for (struct rtattr *rta = IFA_RTA(msg); RTA_OK(rta, length); rta = RTA_NEXT(rta, length))
    {
        if (rta->rta_type == IFA_ADDRESS)
            addr = (nd_addr_t *)RTA_DATA(rta);
    }

    if (!addr)
        return;

    ndL_delete_addr(msg->ifa_index, addr, msg->ifa_prefixlen);
}

static void ndL_handle_newroute(struct rtmsg *msg, int rtl)
{
    nd_addr_t *dst = NULL;
    int oif = 0;

    for (struct rtattr *rta = RTM_RTA(msg); RTA_OK(rta, rtl); rta = RTA_NEXT(rta, rtl))
    {
        if (rta->rta_type == RTA_OIF)
            oif = *(int *)RTA_DATA(rta);
        else if (rta->rta_type == RTA_DST)
            dst = (nd_addr_t *)RTA_DATA(rta);
    }

    if (!dst || !oif)
        return;

    ndL_new_route(oif, dst, msg->rtm_dst_len, msg->rtm_table);
}

static void ndL_handle_delroute(struct rtmsg *msg, int rtl)
{
    nd_addr_t *dst = NULL;
    int oif = 0;

    for (struct rtattr *rta = RTM_RTA(msg); RTA_OK(rta, rtl); rta = RTA_NEXT(rta, rtl))
    {
        if (rta->rta_type == RTA_OIF)
            oif = *(int *)RTA_DATA(rta);
        else if (rta->rta_type == RTA_DST)
            dst = (nd_addr_t *)RTA_DATA(rta);
    }

    if (!dst || !oif)
        return;

    ndL_delete_route(oif, dst, msg->rtm_dst_len, msg->rtm_table);
}

static void ndL_io_handler(__attribute__((unused)) nd_io_t *unused1, __attribute__((unused)) int unused2)
{
    uint8_t buf[4096];

    for (;;)
    {
        ssize_t len = nd_io_recv(ndL_io, NULL, 0, buf, sizeof(buf));

        if (len < 0)
            /* Failed. */
            return;

        for (struct nlmsghdr *hdr = (struct nlmsghdr *)buf; NLMSG_OK(hdr, len); hdr = NLMSG_NEXT(hdr, len))
        {
            if (hdr->nlmsg_type == NLMSG_DONE)
            {
                nd_rt_dump_timeout = 0;
                break;
            }

            if (hdr->nlmsg_type == NLMSG_ERROR)
            {
                struct nlmsgerr *e = (struct nlmsgerr *)NLMSG_DATA(hdr);
                nd_log_error("rt: Error \"%s\", type=%d", strerror(-e->error), e->msg.nlmsg_type);
                continue;
            }

            if (hdr->nlmsg_type == RTM_NEWROUTE)
                ndL_handle_newroute((struct rtmsg *)NLMSG_DATA(hdr), RTM_PAYLOAD(hdr));
            else if (hdr->nlmsg_type == RTM_DELROUTE)
                ndL_handle_delroute((struct rtmsg *)NLMSG_DATA(hdr), RTM_PAYLOAD(hdr));
            else if (hdr->nlmsg_type == RTM_NEWADDR)
                ndL_handle_newaddr((struct ifaddrmsg *)NLMSG_DATA(hdr), IFA_PAYLOAD(hdr));
            else if (hdr->nlmsg_type == RTM_DELADDR)
                ndL_handle_deladdr((struct ifaddrmsg *)NLMSG_DATA(hdr), IFA_PAYLOAD(hdr));
        }
    }
}
#else
static void ndL_get_rtas(int addrs, struct sockaddr *sa, struct sockaddr **rtas)
{
    for (int i = 0; i < RTAX_MAX; i++)
    {
        if (addrs & (1 << i))
        {
            rtas[i] = sa;
            sa = (void *)sa + ((sa->sa_len + sizeof(u_long) - 1) & ~(sizeof(u_long) - 1));
        }
        else
        {
            rtas[i] = NULL;
        }
    }
}

static void ndL_handle_rt(struct rt_msghdr *hdr)
{
    struct sockaddr *rtas[RTAX_MAX];
    ndL_get_rtas(hdr->rtm_addrs, (struct sockaddr *)(hdr + 1), rtas);

    if (!rtas[RTAX_DST] || rtas[RTAX_DST]->sa_family != AF_INET6)
        return;

    int pflen = rtas[RTAX_NETMASK] ? nd_addr_to_pflen(&((struct sockaddr_in6 *)rtas[RTAX_NETMASK])->sin6_addr) : 128;

    nd_addr_t *dst = &((struct sockaddr_in6 *)rtas[RTAX_DST])->sin6_addr;

#    ifdef __FreeBSD__
    int tableid = 0;
#    else
    int tableid = hdr->rtm_tableid;
#    endif

    if (hdr->rtm_type == RTM_GET || hdr->rtm_type == RTM_ADD)
        ndL_new_route(hdr->rtm_index, dst, pflen, tableid);
    else if (hdr->rtm_type == RTM_DELETE)
        ndL_delete_route(hdr->rtm_index, dst, pflen, tableid);
}

static void ndL_handle_ifa(struct ifa_msghdr *hdr)
{
    struct sockaddr *rtas[RTAX_MAX];
    ndL_get_rtas(hdr->ifam_addrs, (struct sockaddr *)(hdr + 1), rtas);

    if (!rtas[RTAX_IFA] || rtas[RTAX_IFA]->sa_family != AF_INET6)
        return;

    int pflen = rtas[RTAX_NETMASK] ? nd_addr_to_pflen(&((struct sockaddr_in6 *)rtas[RTAX_NETMASK])->sin6_addr) : 128;

    nd_addr_t *ifa = &((struct sockaddr_in6 *)rtas[RTAX_IFA])->sin6_addr;

    if (hdr->ifam_type == RTM_NEWADDR)
        ndL_new_addr(hdr->ifam_index, ifa, pflen);
    else if (hdr->ifam_type == RTM_DELADDR)
        ndL_delete_addr(hdr->ifam_index, ifa, pflen);
}

typedef struct
{
    u_short msglen;
    u_char version;
    u_char type;
} ndL_msghdr_t;

static void ndL_handle(void *buf, size_t buflen)
{
    for (size_t i = 0; i < buflen;)
    {
        ndL_msghdr_t *hdr = (ndL_msghdr_t *)(buf + i);
        i += hdr->msglen;

        if (i > buflen)
            break;

        switch (hdr->type)
        {
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
    if (sysctl(mib, 6, NULL, &size, NULL, 0) < 0)
    {
        nd_log_error("sysctl(): %s", strerror(errno));
        return false;
    }

    void *buf = malloc(size);

    /* FIXME: Potential race condition as the number of routes might have increased since the previous syscall(). */
    if (sysctl(mib, 6, buf, &size, NULL, 0) < 0)
    {
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

    for (;;)
    {
        ssize_t len = nd_io_recv(ndL_io, NULL, 0, buf, sizeof(buf));

        if (len < 0)
            /* Failed. */
            return;

        ndL_handle(buf, len);
    }
}

#endif

bool nd_rt_open()
{
    if (ndL_io != NULL)
        return true;

#ifdef __linux__
    if (!(ndL_io = nd_io_socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE)))
    {
        nd_log_error("Failed to open netlink socket: %s", strerror(errno));
        return false;
    }

    struct sockaddr_nl addr;
    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_groups = (1 << (RTNLGRP_IPV6_IFADDR - 1)) | (1 << (RTNLGRP_IPV6_ROUTE - 1));

    if (!nd_io_bind(ndL_io, (struct sockaddr *)&addr, sizeof(addr)))
    {
        nd_log_error("Failed to bind netlink socket: %s", strerror(errno));
        nd_io_close(ndL_io);
        ndL_io = NULL;
        return false;
    }
#else
    if (!(ndL_io = nd_io_socket(AF_ROUTE, SOCK_RAW, AF_INET6)))
    {
        nd_log_error("Failed to open routing socket: %s", strerror(errno));
        return false;
    }
#endif

    ndL_io->handler = ndL_io_handler;

    return true;
}

void nd_rt_cleanup()
{
    if (ndL_io)
        nd_io_close(ndL_io);
}

bool nd_rt_query_routes()
{
#ifdef __linux__
    if (nd_rt_dump_timeout)
        return false;

    struct
    {
        struct nlmsghdr hdr;
        struct rtmsg msg;
    } req;

    memset(&req, 0, sizeof(req));

    req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.hdr.nlmsg_type = RTM_GETROUTE;

    req.msg.rtm_protocol = RTPROT_UNSPEC;
    req.msg.rtm_table = RT_TABLE_UNSPEC;
    req.msg.rtm_family = AF_INET6;

    struct sockaddr_nl addr;
    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;

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

    struct
    {
        struct nlmsghdr hdr;
        struct ifaddrmsg msg;
    } req;

    memset(&req, 0, sizeof(req));

    req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
    req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.hdr.nlmsg_type = RTM_GETADDR;
    req.hdr.nlmsg_seq = 1;

    req.msg.ifa_family = AF_INET6;

    struct sockaddr_nl addr;
    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;

    nd_rt_dump_timeout = nd_current_time + 5000;

    nd_io_send(ndL_io, (struct sockaddr *)&addr, sizeof(addr), &req, sizeof(req));
    return true;
#else
    return ndL_dump(NET_RT_IFLIST);
#endif
}

nd_rt_route_t *nd_rt_find_route(nd_addr_t *addr, int table)
{
    ND_LL_FOREACH(ndL_routes, route, next)
    {
        if (nd_addr_match(&route->addr, addr, route->pflen) && route->table == table)
            return route;
    }

    return NULL;
}