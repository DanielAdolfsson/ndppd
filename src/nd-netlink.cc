//
//@file nd-netlink.cc
//
// Copyright 2016, Allied Telesis Labs New Zealand, Ltd
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

#include <sys/socket.h>
#include <errno.h>
#include <netlink/route/addr.h>
#include <arpa/inet.h>
#include "ndppd.h"
#include <algorithm>

NDPPD_NS_BEGIN

pthread_mutex_t cs_mutex = PTHREAD_MUTEX_INITIALIZER;

struct in6_addr*
address_create_ipv6(struct in6_addr *local)
{
    struct in6_addr *addr = (struct in6_addr *)calloc(1, sizeof(struct in6_addr));
    memcpy(addr, local, sizeof(struct in6_addr));
    return addr;
}

void if_add_to_list(int ifindex, const ptr<iface>& ifa)
{
    bool found = false;

    pthread_mutex_lock (&cs_mutex);
    for (std::vector<interface>::iterator it = interfaces.begin();
            it != interfaces.end(); it++) {
        if ((*it).ifindex == ifindex) {
            found = true;
            break;
        }
    }
    if (!found) {
        logger::debug() << "rule::add_iface() if=" << ifa->name();
        interface anInterface;
        anInterface._name = ifa->name();
        anInterface.ifindex = ifindex;
        interfaces.push_back(anInterface);
    }
    pthread_mutex_unlock (&cs_mutex);
}

void
if_addr_add(int ifindex, struct in6_addr *iaddr)
{
    pthread_mutex_lock (&cs_mutex);
    for (std::vector<interface>::iterator it = interfaces.begin();
         it != interfaces.end(); it++) {
        if ((*it).ifindex == ifindex) {
            address addr = address(*iaddr);
            logger::debug() << "Adding addr " << addr.to_string();
            std::list<address>::iterator it_addr;
            it_addr = std::find((*it).addresses.begin(), (*it).addresses.end(), addr);
            if (it_addr == (*it).addresses.end()) {
                (*it).addresses.push_back(addr);
            }
            break;
        }
    }
    free(iaddr);
    pthread_mutex_unlock (&cs_mutex);
}

void
if_addr_del(int ifindex, struct in6_addr *iaddr)
{
    pthread_mutex_lock (&cs_mutex);
    for (std::vector<interface>::iterator it = interfaces.begin();
         it != interfaces.end(); it++) {
        if ((*it).ifindex == ifindex) {
            address addr = address(*iaddr);
            logger::debug() << "Deleting addr " << addr.to_string();
            (*it).addresses.remove(addr);
            break;
        }
    }
    free(iaddr);
    pthread_mutex_unlock (&cs_mutex);
}

bool
if_addr_find(std::string iface, const struct in6_addr *iaddr)
{
    bool found = false;

    pthread_mutex_lock (&cs_mutex);
    for (std::vector<interface>::iterator it = interfaces.begin();
         it != interfaces.end(); it++) {
        if (iface.compare((*it)._name) == 0) {
            address addr = address(*iaddr);
            std::list<address>::iterator it_addr;
            it_addr = std::find((*it).addresses.begin(), (*it).addresses.end(), addr);
            if (it_addr != (*it).addresses.end()) {
                found = true;
                break;
            }
        }
    }
    pthread_mutex_unlock (&cs_mutex);
    return found;
}

static void
nl_msg_newaddr(struct nlmsghdr *hdr)
{
    struct ifaddrmsg *ifaddr =
        (struct ifaddrmsg *)(((char *) hdr) + (sizeof(struct nlmsghdr)));
    // parse the attributes
    struct nlattr *attrs[IFA_MAX + 1];
    struct nlattr *s = (struct nlattr *)(((char *) ifaddr) + (sizeof(struct ifaddrmsg)));
    int len = nlmsg_datalen(hdr) - sizeof(struct ifinfomsg);
    memset(&attrs, '\0', sizeof(attrs));
    nla_parse(attrs, IFA_MAX, s, len, NULL);

    struct in6_addr* addr = NULL;

    if (ifaddr->ifa_family == AF_INET6) {
        addr = address_create_ipv6((struct in6_addr *)nla_data(attrs[IFA_ADDRESS]));
        if_addr_add(ifaddr->ifa_index, addr);
    }
}

static void
nl_msg_deladdr(struct nlmsghdr *hdr)
{
    struct ifaddrmsg *ifaddr =
        (struct ifaddrmsg *)(((char *) hdr) + (sizeof(struct nlmsghdr)));
    // parse the attributes
    struct nlattr *attrs[IFA_MAX + 1];
    struct nlattr *s = (struct nlattr *)(((char *) ifaddr) + (sizeof(struct ifaddrmsg)));
    int len = nlmsg_datalen(hdr) - sizeof(struct ifinfomsg);
    memset(&attrs, '\0', sizeof(attrs));
    nla_parse(attrs, IFA_MAX, s, len, NULL);

    struct in6_addr* addr = NULL;

    if (ifaddr->ifa_family == AF_INET6) {
        addr = address_create_ipv6((struct in6_addr *)nla_data(attrs[IFA_ADDRESS]));
        if_addr_del(ifaddr->ifa_index, addr);
    }
}

static void
new_addr(struct nl_object *obj, void *p)
{
    struct rtnl_addr *addr = (struct rtnl_addr *) obj;
    struct nl_addr *local = rtnl_addr_get_local(addr);
    int family = rtnl_addr_get_family(addr);
    int ifindex = rtnl_addr_get_ifindex(addr);
    struct in6_addr* in_addr = NULL;

    char ipstr[INET6_ADDRSTRLEN];
    inet_ntop(family, nl_addr_get_binary_addr(local), ipstr, INET6_ADDRSTRLEN);

    switch (family) {
    case AF_INET:
        break;
    case AF_INET6:
        in_addr = address_create_ipv6((struct in6_addr *)nl_addr_get_binary_addr(local));
        if_addr_add(ifindex, in_addr);
        break;
    default:
        logger::error() << "Unknown message family: " << family;
    }
}

static int
nl_msg_handler(struct nl_msg *msg, void *arg)
{
    logger::debug() << "nl_msg_handler";
    struct nlmsghdr *hdr = nlmsg_hdr(msg);

    switch (hdr->nlmsg_type) {
    case RTM_NEWADDR:
        nl_msg_newaddr(hdr);
        break;
    case RTM_DELADDR:
        nl_msg_deladdr(hdr);
        break;
    default:
        logger::error() << "Unknown message type: " << hdr->nlmsg_type;
    }

    return NL_OK;
}

static void *
netlink_monitor(void *p)
{
    struct nl_sock *sock = (struct nl_sock *) p;
    struct nl_cache *addr_cache;

    // get all the current addresses
    if (rtnl_addr_alloc_cache(sock, &addr_cache) < 0) {
        perror("rtnl_addr_alloc_cache");
        return NULL;
    }

    // add existing addresses
    nl_cache_foreach(addr_cache, new_addr, NULL);
    // destroy the cache
    nl_cache_free(addr_cache);

    // switch to notification mode
    // disable sequence checking
    nl_socket_disable_seq_check(sock);
    // set the callback we want
    nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM, nl_msg_handler, NULL);

    // subscribe to the IPv6 address change callbacks
    nl_socket_add_memberships(sock, RTNLGRP_IPV6_IFADDR, 0);

    while (1)
    {
        nl_recvmsgs_default(sock);
    }
    return NULL;
}

static pthread_t monitor_thread;
static struct nl_sock *monitor_sock;
struct nl_sock *control_sock;

bool
netlink_setup()
{
    // create a netlink socket
    control_sock = nl_socket_alloc();
    nl_connect(control_sock, NETLINK_ROUTE);

    // create a thread to run the netlink monitor in
    // create a netlink socket
    monitor_sock = nl_socket_alloc();
    nl_connect(monitor_sock, NETLINK_ROUTE);
    // increase the recv buffer size to capture all notifications
    nl_socket_set_buffer_size(monitor_sock, 2048000, 0);

    pthread_create(&monitor_thread, NULL, netlink_monitor, monitor_sock);
    pthread_setname_np(monitor_thread, "netlink");
    if (pthread_setschedprio(monitor_thread, -10) < 0)
    {
        logger::warning() << "setschedprio: " << strerror(errno);
    }
    return true;
}

bool
netlink_teardown()
{
    void *res = 0;
    pthread_cancel(monitor_thread);
    pthread_join(monitor_thread, &res);
    nl_socket_free(monitor_sock);
    nl_socket_free(control_sock);
    return true;
}

NDPPD_NS_END
