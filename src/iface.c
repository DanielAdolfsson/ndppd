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
#include <net/if.h>
#include <netinet/in.h>

// Need to include netinet/in.h first on FreeBSD.
#include <netinet/icmp6.h>
#include <netinet/ip6.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>

#ifdef __linux__
#    include <linux/filter.h>
#    include <linux/if_ether.h>
#    include <linux/if_packet.h>
#    include <netinet/if_ether.h>
#else
#    include <fcntl.h>
#    include <net/bpf.h>
#    include <net/ethernet.h>
#    include <net/if_dl.h>
#    include <sys/sysctl.h>
#endif

#include "addr.h"
#include "iface.h"
#include "io.h"
#include "ndppd.h"
#include "proxy.h"
#include "session.h"

#ifdef __clang__
#    pragma clang diagnostic ignored "-Waddress-of-packed-member"
#endif

extern int nd_conf_invalid_ttl;
extern int nd_conf_valid_ttl;
extern int nd_conf_renew;
extern int nd_conf_retrans_limit;
extern int nd_conf_retrans_time;
extern bool nd_conf_keepalive;

static nd_iface_t *ndL_first_iface, *ndL_first_free_iface;
static nd_io_t *ndL_io;

//! Used when daemonizing to make sure the parent process does not restore these flags upon exit.
bool nd_iface_no_restore_flags;

typedef struct __attribute__((packed)) {
    struct ether_header eh;
    struct ip6_hdr ip6h;
} ndL_ip6_msg_t;

static void ndL_handle_ns(nd_iface_t *iface, struct ip6_hdr *ip6h, struct icmp6_hdr *ih, size_t len)
{
    if (!iface->proxy) {
        return;
    }

    if (len < sizeof(struct nd_neighbor_solicit)) {
        return;
    }

    struct nd_neighbor_solicit *ns = (struct nd_neighbor_solicit *)ih;

    nd_lladdr_t *src_ll = NULL;

    if (!nd_addr_is_unspecified((nd_addr_t *)&ip6h->ip6_src)) {
        // FIXME: Source link-layer address MUST be included in multicast solicitations and SHOULD be included in
        //        unicast solicitations. [https://tools.ietf.org/html/rfc4861#section-4.3].

        if (len - sizeof(struct nd_neighbor_solicit) < 8) {
            return;
        }

        struct nd_opt_hdr *opt = (struct nd_opt_hdr *)((void *)ns + sizeof(struct nd_neighbor_solicit));

        if (opt->nd_opt_len != 1 || opt->nd_opt_type != ND_OPT_SOURCE_LINKADDR) {
            return;
        }

        src_ll = (nd_lladdr_t *)((void *)opt + 2);
    }

    nd_proxy_handle_ns(iface->proxy, (nd_addr_t *)&ip6h->ip6_src, (nd_addr_t *)&ip6h->ip6_dst,
                       (nd_addr_t *)&ns->nd_ns_target, src_ll);
}

static void ndL_handle_na(nd_iface_t *iface, struct icmp6_hdr *ih, size_t len)
{
    if (len < sizeof(struct nd_neighbor_advert)) {
        return;
    }

    struct nd_neighbor_advert *na = (struct nd_neighbor_advert *)ih;

    nd_session_t *session;
    ND_LL_SEARCH(iface->sessions, session, next_in_iface,
                 nd_addr_eq(&session->real_tgt, (nd_addr_t *)&na->nd_na_target));

    if (!session) {
        return;
    }

    nd_session_handle_na(session);
}

static void ndL_handle_mlq(nd_iface_t *iface)
{
    (void)iface;
    nd_log_error("(mlq) in");
}

static void ndL_handle_mlr(nd_iface_t *iface)
{
    (void)iface;
    nd_log_error("(mlr) in");
}

static uint16_t ndL_calculate_checksum(uint32_t sum, const void *data, size_t length)
{
    uint8_t *p = (uint8_t *)data;

    for (size_t i = 0; i < length; i += 2) {
        if (i + 1 < length) {
            sum += ntohs(*(uint16_t *)p);
            p += 2;
        } else {
            sum += *p++;
        }

        if (sum > 0xffff) {
            sum -= 0xffff;
        }
    }

    return sum;
}

static uint16_t ndL_calculate_icmp6_checksum(struct ip6_hdr *ip6_hdr, struct icmp6_hdr *icmp6_hdr, size_t size)
{
    struct __attribute__((packed)) {
        struct in6_addr src;
        struct in6_addr dst;
        uint32_t len;
        uint8_t unused[3];
        uint8_t type;
        struct icmp6_hdr icmp6_hdr;
    } hdr = {
        .src = ip6_hdr->ip6_src,
        .dst = ip6_hdr->ip6_dst,
        .len = htonl(size),
        .type = IPPROTO_ICMPV6,
        .icmp6_hdr = *icmp6_hdr,
    };

    hdr.icmp6_hdr.icmp6_cksum = 0;

    uint16_t sum;
    sum = ndL_calculate_checksum(0xffff, &hdr, sizeof(hdr));
    sum = ndL_calculate_checksum(sum, icmp6_hdr + 1, size - sizeof(struct icmp6_hdr));

    return htons(~sum);
}

static void ndL_handle_msg(nd_iface_t *iface, ndL_ip6_msg_t *msg)
{
    size_t plen = ntohs(msg->ip6h.ip6_plen);
    size_t i = 0;

    if (msg->ip6h.ip6_nxt == IPPROTO_HOPOPTS) {
        /* We're gonna skip through hop-by-hop option. */
        struct ip6_hbh *hbh = (void *)(msg + 1) + i;

        if (plen - i < 8 || plen - i < 8U + (hbh->ip6h_len * 8U)) {
            return;
        }

        i += 8 + 8 * hbh->ip6h_len;

        if (hbh->ip6h_nxt != IPPROTO_ICMPV6) {
            return;
        }
    } else if (msg->ip6h.ip6_nxt != IPPROTO_ICMPV6) {
        return;
    }

    if (plen - i < sizeof(struct icmp6_hdr)) {
        return;
    }

    struct icmp6_hdr *ih = (struct icmp6_hdr *)((void *)(msg + 1) + i);
    uint16_t ilen = plen - i;

    if (ndL_calculate_icmp6_checksum(&msg->ip6h, ih, ilen) != ih->icmp6_cksum) {
        return;
    }

    if (ih->icmp6_type == ND_NEIGHBOR_SOLICIT) {
        ndL_handle_ns(iface, &msg->ip6h, ih, ilen);
    } else if (ih->icmp6_type == ND_NEIGHBOR_ADVERT) {
        ndL_handle_na(iface, ih, ilen);
    } else if (ih->icmp6_type == MLD_LISTENER_QUERY) {
        ndL_handle_mlq(iface);
    } else if (ih->icmp6_type == MLD_LISTENER_REPORT) {
        ndL_handle_mlr(iface);
    }
}

#ifdef __linux__
static void ndL_io_handler(nd_io_t *io, __attribute__((unused)) int events)
{
    struct sockaddr_ll lladdr = {
        .sll_family = AF_PACKET,
        .sll_protocol = htons(ETH_P_IPV6),
    };

    uint8_t buf[1024];

    for (;;) {
        ssize_t len = nd_io_recv(io, (struct sockaddr *)&lladdr, sizeof(lladdr), buf, sizeof(buf));

        if (len == 0) {
            return;
        }

        if (len < 0) {
            return;
        }

        nd_iface_t *iface;

        ND_LL_SEARCH(ndL_first_iface, iface, next, iface->index == (unsigned int)lladdr.sll_ifindex);

        if (!iface) {
            continue;
        }

        if ((size_t)len < sizeof(ndL_ip6_msg_t)) {
            continue;
        }

        ndL_ip6_msg_t *msg = (ndL_ip6_msg_t *)buf;

        if (msg->eh.ether_type != ntohs(ETHERTYPE_IPV6)) {
            continue;
        }

        if (ntohs(msg->ip6h.ip6_plen) != len - sizeof(ndL_ip6_msg_t)) {
            continue;
        }

        ndL_handle_msg(iface, msg);
    }
}
#else
static void ndL_io_handler(nd_io_t *io, __attribute__((unused)) int events)
{
    __attribute__((aligned(BPF_ALIGNMENT))) uint8_t buf[4096]; /* Depends on BIOCGBLEN */

    for (;;) {
        ssize_t len = nd_io_read(io, buf, sizeof(buf));

        if (len < 0) {
            if (errno == EAGAIN) {
                return;
            }

            nd_log_error("%s", strerror(errno));
        }

        for (size_t i = 0; i < (size_t)len;) {
            struct bpf_hdr *bpf_hdr = (struct bpf_hdr *)(buf + i);
            i += BPF_WORDALIGN(bpf_hdr->bh_hdrlen + bpf_hdr->bh_caplen);

            if (bpf_hdr->bh_caplen < sizeof(ndL_ip6_msg_t)) {
                continue;
            }

            ndL_ip6_msg_t *msg = (ndL_ip6_msg_t *)buf;

            if (msg->eh.ether_type != ntohs(ETHERTYPE_IPV6)) {
                continue;
            }

            if (ntohs(msg->ip6h.ip6_plen) != len - sizeof(ndL_ip6_msg_t)) {
                continue;
            }

            ndL_handle_msg((nd_iface_t *)io->data, msg);
        }
    }
}
#endif

static bool ndL_configure_filter(nd_io_t *io)
{
#ifndef __linux__
#    define sock_filter bpf_insn
#endif

    static struct sock_filter filter[] = {
        /* Load P->ether_type into A. */
        BPF_STMT(BPF_LD + BPF_H + BPF_ABS, offsetof(struct ether_header, ether_type)),
        /* Drop packet if A != ETHERTYPE_IPV6. */
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETHERTYPE_IPV6, 0, 17),
        /* Load next header offset into X. */
        BPF_STMT(BPF_LDX + BPF_W + BPF_IMM, sizeof(struct ether_header) + sizeof(struct ip6_hdr)),
        /* Load P->ip6_nxt. */
        BPF_STMT(BPF_LD + BPF_B + BPF_ABS, sizeof(struct ether_header) + offsetof(struct ip6_hdr, ip6_nxt)),

        /* Hop-by-hop */

        /* Skip if A != IPPROTO_HOPOPTS. */
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, IPPROTO_HOPOPTS, 0, 8),
        /* Load X->ip6h_nxt into A. */
        BPF_STMT(BPF_LD + BPF_B + BPF_IND, 0),
        /* Save A into [0(nxt)]. */
        BPF_STMT(BPF_ST, 0),
        /* Load ip6h_len into A. */
        BPF_STMT(BPF_LD + BPF_B + BPF_IND, 1),
        /* Multiply by 8. */
        BPF_STMT(BPF_ALU + BPF_MUL + BPF_K, 8),
        /* Add 6. */
        BPF_STMT(BPF_ALU + BPF_ADD + BPF_K, 8),
        /* Add X. */
        BPF_STMT(BPF_ALU + BPF_ADD + BPF_X, 0),
        /* Copy A to X. */
        BPF_STMT(BPF_MISC + BPF_TAX, 0),
        /* Load [0(nxt)] into A. */
        BPF_STMT(BPF_LD + BPF_MEM, 0),

        /* ICMPv6 */

        /* Fail if A != IPPROTO_ICMPV6. */
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, IPPROTO_ICMPV6, 0, 5),
        /* Load X->icmp6_type into A. */
        BPF_STMT(BPF_LD + BPF_B + BPF_IND, offsetof(struct icmp6_hdr, icmp6_type)),
        /* Succeed if A == ND_NEIGHBOR_SOLICIT. */
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ND_NEIGHBOR_SOLICIT, 4, 0),
        /* Succeed if A == ND_NEIGHBOR_SOLICIT. */
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ND_NEIGHBOR_ADVERT, 3, 0),
        /* Succeed if A == MLD_LISTENER_QUERY. */
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, MLD_LISTENER_QUERY, 2, 0),
        /* Succeed if A == MLD_LISTENER_REPORT. */
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, MLD_LISTENER_REPORT, 1, 0),
        /* Drop packet. */
        BPF_STMT(BPF_RET + BPF_K, 0),
        /* Keep packet. */
        BPF_STMT(BPF_RET + BPF_K, (u_int32_t)-1),
    };

#ifdef __linux__
    static struct sock_fprog fprog = {
        .len = sizeof(filter) / sizeof(filter[0]),
        .filter = filter,
    };

    if (setsockopt(io->fd, SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof(fprog)) == -1) {
        return false;
    }
#else
    static struct bpf_program fprog = {
        .bf_len = sizeof(filter) / sizeof(filter[0]),
        .bf_insns = filter,
    };

    if (ioctl(io->fd, BIOCSETF, &fprog) == -1) {
        return false;
    }
#endif

    return true;
}

nd_iface_t *nd_iface_open(const char *name, unsigned index)
{
    char tmp_name[IF_NAMESIZE];

    if (!name && !index) {
        return NULL;
    }

    if (name && index && if_nametoindex(name) != index) {
        nd_log_error("Expected interface %s to have index %d", name, index);
        return NULL;
    } else if (name && !(index = if_nametoindex(name))) {
        nd_log_error("Failed to get index of interface %s: %s", name, strerror(errno));
        return NULL;
    } else if (!(name = if_indextoname(index, tmp_name))) {
        nd_log_error("Failed to get name of interface index %d: %s", index, strerror(errno));
        return NULL;
    }

    /* If the specified interface is already opened, just increase the reference count. */

    nd_iface_t *iface;
    ND_LL_SEARCH(ndL_first_iface, iface, next, iface->index == index);

    if (iface) {
        iface->refcount++;
        return iface;
    }

#ifdef __linux__
    /* Determine link-layer address. */

    struct ifreq ifr = { 0 };
    strcpy(ifr.ifr_name, name);

    if (ioctl(ndL_io->fd, SIOCGIFHWADDR, &ifr) < 0) {
        nd_log_error("Failed to determine link-layer address: %s", strerror(errno));
        return NULL;
    }

    nd_lladdr_t *lladdr = (nd_lladdr_t *)ifr.ifr_hwaddr.sa_data;

    /* Enable ALLMULTI. */

    struct packet_mreq mreq = { .mr_ifindex = (int) index, .mr_type = PACKET_MR_ALLMULTI };

    if (setsockopt(ndL_io->fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) == -1) {
        nd_log_error("Could not configure ALLMULTI: %s", strerror(errno));
        return NULL;
    }

#else
    nd_io_t *io = NULL;

    /* This requires a cloning bpf device, but I hope most sane systems got them. */
    if (!(io = nd_io_open("/dev/bpf", O_RDWR))) {
        nd_log_error("Failed to open /dev/bpf");
        return NULL;
    }

    io->handler = ndL_io_handler;

    /* Set buffer length. */

    unsigned len = 4096; /* TODO: Configure */
    if (ioctl(io->fd, BIOCSBLEN, &len) < 0) {
        nd_log_error("BIOCSBLEN: %s", strerror(errno));
        nd_io_close(io);
        return NULL;
    }

    /* Bind to interface. */

    struct ifreq ifr;
    strcpy(ifr.ifr_name, name);
    if (ioctl(io->fd, BIOCSETIF, &ifr) < 0) {
        nd_log_error("Failed to bind to interface: %s", strerror(errno));
        nd_io_close(io);
        return NULL;
    }

    /* Promisc. */

    if (ioctl(io->fd, BIOCPROMISC, NULL) < 0) {
        nd_log_error("Failed to enable promiscuous mode: %s", strerror(errno));
        nd_io_close(io);
        return NULL;
    }

    /* Immediate */

    uint32_t enable = 1;
    if (ioctl(io->fd, BIOCIMMEDIATE, &enable) < 0) {
        nd_log_error("BIOCIMMEDIATE: %s", strerror(errno));
        nd_io_close(io);
        return NULL;
    }

    /* Determine link-layer address. */

    int mib[] = { CTL_NET, AF_ROUTE, 0, AF_LINK, NET_RT_IFLIST, (int)index };
    uint8_t sysctl_buf[512];
    size_t sysctl_buflen = sizeof(sysctl_buf);

    if (sysctl(mib, 6, sysctl_buf, &sysctl_buflen, NULL, 0) == -1) {
        nd_log_error("Failed to determine link-layer address: %s", strerror(errno));
        nd_io_close(io);
        return NULL;
    }

    if (!ndL_configure_filter(io)) {
        nd_log_error("Could not configure filter: %s", strerror(errno));
        nd_io_close(io);
        return NULL;
    }

    nd_lladdr_t *lladdr = (nd_lladdr_t *)LLADDR((struct sockaddr_dl *)(sysctl_buf + sizeof(struct if_msghdr)));
#endif

    iface = ndL_first_free_iface;

    if (iface) {
        ND_LL_DELETE(ndL_first_free_iface, iface, next);
    } else {
        iface = ND_ALLOC(nd_iface_t);
    }

    *iface = (nd_iface_t){
        .index = index,
        .refcount = 1,
        .old_allmulti = -1,
        .old_promisc = -1,
        .lladdr = *lladdr,
    };

    strcpy(iface->name, name);

    ND_LL_PREPEND(ndL_first_iface, iface, next);

#ifndef __linux__
    io->data = (uintptr_t)iface;
    iface->bpf_io = io;
#endif

    nd_log_info("New interface %s [%s]", iface->name, nd_ll_ntoa(lladdr));

    return iface;
}

void nd_iface_close(nd_iface_t *iface)
{
    if (--iface->refcount > 0) {
        return;
    }

#ifdef __linux__
    /* Disable ALLMULTI. */

    struct packet_mreq mreq = { .mr_ifindex = (int) iface->index, .mr_type = PACKET_MR_ALLMULTI };

    if (setsockopt(ndL_io->fd, SOL_PACKET, PACKET_DROP_MEMBERSHIP, &mreq, sizeof(mreq)) == -1) {
        nd_log_error("Could not disable ALLMULTI: %s", strerror(errno));
    }
#else
    nd_io_close(iface->bpf_io);
#endif

    ND_LL_DELETE(ndL_first_iface, iface, next);
    ND_LL_PREPEND(ndL_first_free_iface, iface, next);
}

static void ndL_get_local_addr(nd_iface_t *iface, nd_addr_t *addr)
{
    uint8_t *p = iface->lladdr.u8;
    *addr = (nd_addr_t){ .u8 = { 0xfe, 0x80, [8] = p[0] ^ 0x02U, p[1], p[2], 0xff, 0xfe, p[3], p[4], p[5] } };
}

static ssize_t ndL_send_icmp6(nd_iface_t *iface, ndL_ip6_msg_t *msg, size_t size, const nd_lladdr_t *lladdr)
{
    msg->eh.ether_type = htons(ETHERTYPE_IPV6);
    memcpy(msg->eh.ether_shost, &iface->lladdr, ETHER_ADDR_LEN);
    memcpy(msg->eh.ether_dhost, lladdr, ETHER_ADDR_LEN);

    msg->ip6h.ip6_flow = htonl((6U << 28U) | (0U << 20U) | 0U);
    msg->ip6h.ip6_plen = htons(size - sizeof(ndL_ip6_msg_t));
    msg->ip6h.ip6_hops = 255;
    msg->ip6h.ip6_nxt = IPPROTO_ICMPV6;

    struct icmp6_hdr *icmp6_hdr = (struct icmp6_hdr *)(msg + 1);
    uint16_t icmp6_len = size - sizeof(ndL_ip6_msg_t);
    icmp6_hdr->icmp6_cksum = ndL_calculate_icmp6_checksum(&msg->ip6h, icmp6_hdr, icmp6_len);

#ifdef __linux__
    struct sockaddr_ll ll = {
        .sll_family = AF_PACKET,
        .sll_ifindex = (int)iface->index,
    };

    return nd_io_send(ndL_io, (struct sockaddr *)&ll, sizeof(ll), msg, size);
#else
    return nd_io_write(iface->bpf_io, msg, size);
#endif
}

ssize_t nd_iface_send_na(nd_iface_t *iface, const nd_addr_t *dst, const nd_lladdr_t *dst_ll, const nd_addr_t *tgt,
                         bool router)
{
    struct __attribute__((packed)) {
        struct ether_header eh;
        struct ip6_hdr ip;
        struct nd_neighbor_advert na;
        struct nd_opt_hdr opt;
        struct ether_addr lladdr;
    } msg = {
        .ip.ip6_src = *(struct in6_addr *)tgt,
        .ip.ip6_dst = *(struct in6_addr *)dst,
        .na.nd_na_type = ND_NEIGHBOR_ADVERT,
        .na.nd_na_target = *(struct in6_addr *)tgt,
        .opt.nd_opt_type = ND_OPT_TARGET_LINKADDR,
        .opt.nd_opt_len = 1,
        .lladdr = *(struct ether_addr *)&iface->lladdr,
    };

    if (nd_addr_is_multicast(dst)) {
        msg.na.nd_na_flags_reserved |= ND_NA_FLAG_SOLICITED;
    }

    if (router) {
        msg.na.nd_na_flags_reserved |= ND_NA_FLAG_ROUTER;
    }

    nd_log_info("Write NA tgt=%s, dst=%s [%s dev %s]", //
                nd_ntoa(tgt), nd_ntoa(dst), nd_ll_ntoa(dst_ll), iface->name);

    return ndL_send_icmp6(iface, (ndL_ip6_msg_t *)&msg, sizeof(msg), dst_ll);
}

ssize_t nd_iface_send_ns(nd_iface_t *iface, const nd_addr_t *tgt)
{
    struct __attribute__((packed)) {
        struct ether_header eh;
        struct ip6_hdr ip;
        struct nd_neighbor_solicit ns;
        struct nd_opt_hdr opt;
        struct ether_addr lladdr;
    } msg = {
        .ns.nd_ns_type = ND_NEIGHBOR_SOLICIT,
        .ns.nd_ns_target = *(struct in6_addr *)tgt,
        .opt.nd_opt_type = ND_OPT_SOURCE_LINKADDR,
        .opt.nd_opt_len = 1,
        .lladdr = *(struct ether_addr *)&iface->lladdr,
    };

    ndL_get_local_addr(iface, (nd_addr_t *)&msg.ip.ip6_src);
    nd_log_trace("Write NS iface=%s, tgt=%s, src=%s", iface->name, nd_ntoa(tgt), nd_ntoa((nd_addr_t *)&msg.ip.ip6_src));

    static const nd_addr_t multicast = { .u8 = { 0xff, 0x02, [11] = 0x01, 0xff, 0, 0, 0 } };
    *(nd_addr_t *)&msg.ip.ip6_dst = multicast;
    (*(nd_addr_t *)&msg.ip.ip6_dst).u8[13] = tgt->u8[13];
    (*(nd_addr_t *)&msg.ip.ip6_dst).u8[14] = tgt->u8[14];
    (*(nd_addr_t *)&msg.ip.ip6_dst).u8[15] = tgt->u8[15];

    nd_lladdr_t ll_mcast = { 0x33, 0x33 };
    *(uint32_t *)&ll_mcast.u8[2] = tgt->u32[3];

    nd_log_trace("Write NS iface=%s, tgt=%s, src=%s", iface->name, nd_ntoa(tgt), nd_ntoa((nd_addr_t *)&msg.ip.ip6_src));

    return ndL_send_icmp6(iface, (ndL_ip6_msg_t *)&msg, sizeof(msg), &ll_mcast);
}

bool nd_iface_startup()
{
#ifdef __linux__
    if (!(ndL_io = nd_io_socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IPV6)))) {
        return false;
    }

    if (!ndL_configure_filter(ndL_io)) {
        nd_log_error("Failed to configure BPF: %s", strerror(errno));
        nd_io_close(ndL_io);
        ndL_io = NULL;
        return NULL;
    }

    ndL_io->handler = ndL_io_handler;
#endif

    return true;
}

void nd_iface_cleanup()
{
    ND_LL_FOREACH_S (ndL_first_iface, iface, tmp, next) {
        iface->refcount = 1;
        nd_iface_close(iface);
    }

    if (ndL_io) {
        nd_io_close(ndL_io);
    }
}
