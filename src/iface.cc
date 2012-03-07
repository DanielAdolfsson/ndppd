// ndppd - NDP Proxy Daemon
// Copyright (C) 2011  Daniel Adolfsson <daniel@priv.nu>
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
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstddef>

#include <unistd.h>

#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/ether.h>
#include <netpacket/packet.h>

#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/poll.h>

#include <linux/filter.h>

#include <string>
#include <vector>
#include <map>

#include "ndppd.h"

NDPPD_NS_BEGIN

std::map<std::string, weak_ptr<iface> > iface::_map;

bool iface::_map_dirty = false;

std::vector<struct pollfd> iface::_pollfds;

iface::iface() :
    _ifd(-1), _pfd(-1), _name("")
{
}

iface::~iface()
{
    logger::debug() << "iface::~iface()";

    if (_ifd >= 0)
        close(_ifd);

    if (_pfd >= 0) {
        if (_prev_allmulti >= 0) {
            allmulti(_prev_allmulti);
        }
        close(_pfd);
    }

    _map_dirty = true;
}

ptr<iface> iface::open_pfd(const std::string& name)
{
    int fd = 0;

    std::map<std::string, weak_ptr<iface> >::iterator it = _map.find(name);

    ptr<iface> ifa;

    if (it != _map.end()) {
        if (it->second->_pfd >= 0)
            return it->second;

        ifa = it->second;
    } else {
        // We need an _ifs, so let's set one up.
        ifa = open_ifd(name);
    }

    if (!ifa)
        return ptr<iface>();

    // Create a socket.

    if ((fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IPV6))) < 0) {
        logger::error() << "Unable to create socket";
        return ptr<iface>();
    }

    // Bind to the specified interface.

    struct sockaddr_ll lladdr;

    memset(&lladdr, 0, sizeof(struct sockaddr_ll));
    lladdr.sll_family   = AF_PACKET;
    lladdr.sll_protocol = htons(ETH_P_IPV6);

    if (!(lladdr.sll_ifindex = if_nametoindex(name.c_str()))) {
        close(fd);
        logger::error() << "Failed to bind to interface '" << name << "'";
        return ptr<iface>();
    }

    if (bind(fd, (struct sockaddr* )&lladdr, sizeof(struct sockaddr_ll)) < 0) {
        close(fd);
        logger::error() << "Failed to bind to interface '" << name << "'";
        return ptr<iface>();
    }

    // Switch to non-blocking mode.

    int on = 1;

    if (ioctl(fd, FIONBIO, (char* )&on) < 0) {
        close(fd);
        logger::error() << "Failed to switch to non-blocking on interface '" << name << "'";
        return ptr<iface>();
    }

    // Set up filter.

    static struct sock_filter filter[] = {
        // Load the ether_type.
        BPF_STMT(BPF_LD | BPF_H | BPF_ABS,
            offsetof(struct ether_header, ether_type)),
        // Bail if it's* not* ETHERTYPE_IPV6.
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ETHERTYPE_IPV6, 0, 5),
        // Load the next header type.
        BPF_STMT(BPF_LD | BPF_B | BPF_ABS,
            sizeof(struct ether_header) + offsetof(struct ip6_hdr, ip6_nxt)),
        // Bail if it's* not* IPPROTO_ICMPV6.
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_ICMPV6, 0, 3),
        // Load the ICMPv6 type.
        BPF_STMT(BPF_LD | BPF_B | BPF_ABS,
            sizeof(struct ether_header) + sizeof(ip6_hdr) + offsetof(struct icmp6_hdr, icmp6_type)),
        // Bail if it's* not* ND_NEIGHBOR_SOLICIT.
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ND_NEIGHBOR_SOLICIT, 0, 1),
        // Keep packet.
        BPF_STMT(BPF_RET | BPF_K, -1),
        // Drop packet.
        BPF_STMT(BPF_RET | BPF_K, 0)
    };

    static struct sock_fprog fprog = {
        8,
        filter
    };

    if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof(fprog)) < 0) {
        logger::error() << "Failed to set filter";
        return ptr<iface>();
    }

    // Set up an instance of 'iface'.

    ifa->_pfd = fd;

    // Eh. Allmulti.
    ifa->_prev_allmulti = ifa->allmulti(1);

    _map_dirty = true;

    return ifa;
}

ptr<iface> iface::open_ifd(const std::string& name)
{
    int fd;

    std::map<std::string, weak_ptr<iface> >::iterator it = _map.find(name);

    if ((it != _map.end()) && it->second->_ifd)
        return it->second;

    // Create a socket.

    if ((fd = socket(PF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) < 0) {
        logger::error() << "Unable to create socket";
        return ptr<iface>();
    }

    // Bind to the specified interface.

    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,& ifr, sizeof(ifr)) < 0) {
        close(fd);
        logger::error() << "Failed to bind to interface '" << name << "'";
        return ptr<iface>();
    }

    // Detect the link-layer address.

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    if (ioctl(fd, SIOCGIFHWADDR,& ifr) < 0) {
        close(fd);
        logger::error() << "Failed to detect link-layer address for interface '" << name << "'";
        return ptr<iface>();
    }

    logger::debug() << "fd=" << fd << ", hwaddr=" << ether_ntoa((const struct ether_addr* )&ifr.ifr_hwaddr.sa_data);;

    // Set max hops.

    int hops = 255;

    if (setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,& hops, sizeof(hops)) < 0) {
        close(fd);
        logger::error() << "iface::open_ifd() failed IPV6_MULTICAST_HOPS";
        return ptr<iface>();
    }

    if (setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS,& hops, sizeof(hops)) < 0) {
        close(fd);
        logger::error() << "iface::open_ifd() failed IPV6_UNICAST_HOPS";
        return ptr<iface>();
    }

    // Switch to non-blocking mode.

    int on = 1;

    if (ioctl(fd, FIONBIO, (char* )&on) < 0) {
        close(fd);
        logger::error() << "Failed to switch to non-blocking on interface '" << name << "'";
        return ptr<iface>();
    }

    // Set up filter.

    struct icmp6_filter filter;
    ICMP6_FILTER_SETBLOCKALL(&filter);
    ICMP6_FILTER_SETPASS(ND_NEIGHBOR_ADVERT,& filter);

    if (setsockopt(fd, IPPROTO_ICMPV6, ICMP6_FILTER,& filter, sizeof(filter)) < 0) {
        logger::error() << "Failed to set filter";
        return ptr<iface>();
    }

    // Set up an instance of 'iface'.

    ptr<iface> ifa;

    if (it == _map.end()) {
        ifa = new iface();
        ifa->_name = name;
        ifa->_ptr  = ifa;

        _map[name] = ifa;
    } else {
        ifa = it->second;
    }

    ifa->_ifd = fd;

    memcpy(&ifa->hwaddr, ifr.ifr_hwaddr.sa_data, sizeof(struct ether_addr));

    _map_dirty = true;

    return ifa;
}

ssize_t iface::read(int fd, struct sockaddr* saddr, uint8_t* msg, size_t size)
{
    struct msghdr mhdr;
    struct iovec iov;
    int len;

    if (!msg || (size < 0))
        return -1;

    iov.iov_len = size;
    iov.iov_base = (caddr_t)msg;

    memset(&mhdr, 0, sizeof(mhdr));
    mhdr.msg_name = (caddr_t)saddr;
    mhdr.msg_namelen = sizeof(struct sockaddr);
    mhdr.msg_iov =& iov;
    mhdr.msg_iovlen = 1;

    if ((len = recvmsg(fd,& mhdr, 0)) < 0)
        return -1;

    if (len < sizeof(struct icmp6_hdr))
        return -1;

    logger::debug() << "iface::read() len=" << len;

    return len;
}

ssize_t iface::write(int fd, const address& daddr, const uint8_t* msg, size_t size)
{
    struct sockaddr_in6 daddr_tmp;
    struct msghdr mhdr;
    struct iovec iov;

    memset(&daddr_tmp, 0, sizeof(struct sockaddr_in6));
    daddr_tmp.sin6_family = AF_INET6;
    daddr_tmp.sin6_port   = htons(IPPROTO_ICMPV6); // Needed?
    memcpy(&daddr_tmp.sin6_addr,& daddr.const_addr(), sizeof(struct in6_addr));

    iov.iov_len = size;
    iov.iov_base = (caddr_t)msg;

    memset(&mhdr, 0, sizeof(mhdr));
    mhdr.msg_name = (caddr_t)&daddr_tmp;
    mhdr.msg_namelen = sizeof(sockaddr_in6);
    mhdr.msg_iov =& iov;
    mhdr.msg_iovlen = 1;

    logger::debug() << "iface::write() daddr=" << daddr.to_string() << ", len=" << size;

    int len;

    if ((len = sendmsg(fd,& mhdr, 0)) < 0)
        return -1;

    return len;
}

ssize_t iface::read_solicit(address& saddr, address& daddr, address& taddr)
{
    struct sockaddr_ll t_saddr;
    uint8_t msg[256];
    ssize_t len;

    if ((len = read(_pfd, (struct sockaddr* )&t_saddr, msg, sizeof(msg))) < 0)
        return -1;

    struct ip6_hdr* ip6h =
          (struct ip6_hdr* )(msg + ETH_HLEN);

    struct nd_neighbor_solicit*  ns =
        (struct nd_neighbor_solicit* )(msg + ETH_HLEN + sizeof( struct ip6_hdr));

    taddr = ns->nd_ns_target;
    daddr = ip6h->ip6_dst;
    saddr = ip6h->ip6_src;

    logger::debug() << "iface::read_solicit() saddr=" << saddr.to_string() << ", daddr=" << daddr.to_string() << ", len=" << len;

    return len;
}

ssize_t iface::write_solicit(const address& taddr)
{
    char buf[128];

    memset(buf, 0, sizeof(buf));

    struct nd_neighbor_solicit* ns =
        (struct nd_neighbor_solicit* )&buf[0];

    struct nd_opt_hdr* opt =
        (struct nd_opt_hdr* )&buf[sizeof(struct nd_neighbor_solicit)];

    opt->nd_opt_type = ND_OPT_SOURCE_LINKADDR;
    opt->nd_opt_len  = 1;

    ns->nd_ns_type   = ND_NEIGHBOR_SOLICIT;

    memcpy(&ns->nd_ns_target,& taddr.const_addr(), sizeof(struct in6_addr));

    memcpy(buf + sizeof(struct nd_neighbor_solicit) + sizeof(struct nd_opt_hdr),& hwaddr, 6);

    // FIXME: Alright, I'm lazy.
    static address multicast("ff02::1:ff00:0000");

    address daddr;

    daddr = multicast;

    daddr.addr().s6_addr[13] = taddr.const_addr().s6_addr[13];
    daddr.addr().s6_addr[14] = taddr.const_addr().s6_addr[14];
    daddr.addr().s6_addr[15] = taddr.const_addr().s6_addr[15];

    logger::debug() << "iface::write_solicit() taddr=" << taddr.to_string() << ", daddr=" << daddr.to_string();

    return write(_ifd, daddr, (uint8_t* )buf, sizeof(struct nd_neighbor_solicit) + sizeof(struct nd_opt_hdr) + 6);
}

ssize_t iface::write_advert(const address& daddr, const address& taddr, bool router)
{
    char buf[128];

    memset(buf, 0, sizeof(buf));

    struct nd_neighbor_advert* na =
        (struct nd_neighbor_advert* )&buf[0];

    struct nd_opt_hdr* opt =
        (struct nd_opt_hdr* )&buf[sizeof(struct nd_neighbor_advert)];

    opt->nd_opt_type         = ND_OPT_TARGET_LINKADDR;
    opt->nd_opt_len          = 1;

    na->nd_na_type           = ND_NEIGHBOR_ADVERT;
    na->nd_na_flags_reserved = ND_NA_FLAG_SOLICITED | (router ? ND_NA_FLAG_ROUTER : 0);

    memcpy(&na->nd_na_target,& taddr.const_addr(), sizeof(struct in6_addr));

    memcpy(buf + sizeof(struct nd_neighbor_advert) + sizeof(struct nd_opt_hdr),& hwaddr, 6);

    logger::debug() << "iface::write_advert() daddr=" << daddr.to_string() << ", taddr=" << taddr.to_string();

    return write(_ifd, daddr, (uint8_t* )buf, sizeof(struct nd_neighbor_advert) +
        sizeof(struct nd_opt_hdr) + 6);
}

ssize_t iface::read_advert(address& saddr, address& taddr)
{
    struct sockaddr_in6 t_saddr;
    uint8_t msg[256];
    ssize_t len;

    if ((len = read(_ifd, (struct sockaddr* )&t_saddr, msg, sizeof(msg))) < 0)
        return -1;

    saddr = t_saddr.sin6_addr;

    if (((struct icmp6_hdr* )msg)->icmp6_type != ND_NEIGHBOR_ADVERT)
        return -1;

    taddr = ((struct nd_neighbor_solicit* )msg)->nd_ns_target;

    logger::debug() << "iface::read_advert() saddr=" << saddr.to_string() << ", taddr=" << taddr.to_string() << ", len=" << len;

    return len;
}

void iface::fixup_pollfds()
{
    _pollfds.resize(_map.size()*  2);

    int i = 0;

    logger::debug() << "iface::fixup_pollfds() _map.size()=" << _map.size();

    for (std::map<std::string, weak_ptr<iface> >::iterator it = _map.begin();
            it != _map.end(); it++) {
        _pollfds[i].fd      = it->second->_ifd;
        _pollfds[i].events  = POLLIN;
        _pollfds[i].revents = 0;
        i++;

        _pollfds[i].fd      = it->second->_pfd;
        _pollfds[i].events  = POLLIN;
        _pollfds[i].revents = 0;
        i++;
    }
}

void iface::remove_session(const ptr<session>& se)
{
    for (std::list<weak_ptr<session> >::iterator it = _sessions.begin();
            it != _sessions.end(); it++) {
        if (*it == se) {
            _sessions.erase(it);
            break;
        }
    }
}

void iface::add_session(const ptr<session>& se)
{
    _sessions.push_back(se);
}

void iface::cleanup()
{
    for (std::map<std::string, weak_ptr<iface> >::iterator it = _map.begin();
            it != _map.end(); ) {
        std::map<std::string, weak_ptr<iface> >::iterator c_it = it++;
        if (!c_it->second) {
            _map.erase(c_it);
        }
    }
}

int iface::poll_all()
{
    if (_map_dirty) {
        cleanup();
        fixup_pollfds();
        _map_dirty = false;
    }

    if (_pollfds.size() == 0) {
        ::sleep(1);
        return 0;
    }

    assert(_pollfds.size() == _map.size()*  2);

    int len;

    if ((len = ::poll(&_pollfds[0], _pollfds.size(), 50)) < 0) {
        return -1;
    }

    if (len == 0) {
        return 0;
    }

    std::map<std::string, weak_ptr<iface> >::iterator i_it = _map.begin();

    int i = 0;

    for (std::vector<struct pollfd>::iterator f_it = _pollfds.begin();
            f_it != _pollfds.end(); f_it++) {
        assert(i_it != _map.end());

        if (i && !(i % 2)) {
            i_it++;
        }

        bool is_pfd = i++ % 2;

        if (!(f_it->revents & POLLIN)) {
            continue;
        }

        ptr<iface> ifa = i_it->second;

        address saddr, daddr, taddr;

        if (is_pfd) {
            if (ifa->read_solicit(saddr, daddr, taddr) < 0) {
                logger::error() << "Failed to read from interface '%s'", ifa->_name.c_str();
                continue;
            }

            if (!saddr.is_unicast() || !daddr.is_multicast()) {
                continue;
            }

            if (ifa->_pr) {
                ifa->_pr->handle_solicit(saddr, daddr, taddr);
            }
        } else {
            if (ifa->read_advert(saddr, taddr) < 0) {
                logger::error() << "Failed to read from interface '%s'", ifa->_name.c_str();
                continue;
            }

            for (std::list<weak_ptr<session> >::iterator s_it = ifa->_sessions.begin();
                    s_it != ifa->_sessions.end(); s_it++) {
                assert(!s_it->is_null());

                const ptr<session> sess = *s_it;

                if ((sess->taddr() == taddr) && (sess->status() == session::WAITING)) {
                    sess->handle_advert();
                    break;
                }
            }
        }
    }

    return 0;
}

int iface::allmulti(int state)
{
    struct ifreq ifr;

    logger::debug() << "iface::allmulti() state=" << state << ", _name=\"" << _name << "\"";

    state = !!state;

    memset(&ifr, 0, sizeof(ifr));

    strncpy(ifr.ifr_name, _name.c_str(), IFNAMSIZ);

    if (ioctl(_pfd, SIOCGIFFLAGS, &ifr) < 0) {
        return -1;
    }

    int old_state = !!(ifr.ifr_flags & IFF_ALLMULTI);

    if (state == old_state) {
        return old_state;
    }

    if (state) {
        ifr.ifr_flags |= IFF_ALLMULTI;
    } else {
        ifr.ifr_flags &= ~IFF_ALLMULTI;
    }

    if (ioctl(_pfd, SIOCSIFFLAGS, &ifr) < 0) {
        return -1;
    }

    return old_state;
}

const std::string& iface::name() const
{
    return _name;
}

void iface::pr(const ptr<proxy>& pr)
{
    _pr = pr;
}

const ptr<proxy>& iface::pr() const
{
    return _pr;
}

NDPPD_NS_END
