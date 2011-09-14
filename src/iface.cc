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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

#include <string>
#include <vector>
#include <map>

#include "ndppd.h"
#include "iface.h"
#include "proxy.h"
#include "session.h"
#include "rule.h"

#if defined IPV6_PKTINFO && !defined IPV6_RECVPKTINFO
#define IPV6_RECVPKTINFO IPV6_PKTINFO
#endif

__NDPPD_NS_BEGIN

std::map<std::string, ptr<iface> > iface::_map;

std::vector<struct pollfd> iface::_pollfds;

iface::iface()
{
}

iface::~iface()
{
   DBG("iface destroyed");
}

ptr<iface> iface::open(const std::string& name)
{
   int fd;

   DBG("iface::open() name=\"%s\"", name.c_str());

   // Check if the interface is already opened.

   std::map<std::string, ptr<iface> >::iterator it = _map.find(name);

   if(it != _map.end())
      return (*it).second;

   // Create a socket.

   if((fd = socket(PF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) < 0)
   {
      ERR("Unable to create socket");
      return ptr<iface>::null();
   }

   // Bind to the specified interface.

   struct ifreq ifr;

   memset(&ifr, 0, sizeof(ifr));
   strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ - 1);
   ifr.ifr_name[IFNAMSIZ - 1] = '\0';

   if(setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) < 0)
   {
      close(fd);
      ERR("Failed to bind to interface '%s'", name.c_str());
      return ptr<iface>();
   }

   // Detect the link-layer address.

   memset(&ifr, 0, sizeof(ifr));
   strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ - 1);
   ifr.ifr_name[IFNAMSIZ - 1] = '\0';

   if(ioctl(fd, SIOCGIFHWADDR, &ifr) < 0)
   {
      close(fd);
      ERR("Failed to detect link-layer address for interface '%s'", name.c_str());
      return ptr<iface>();
   }

   DBG("fd=%d, hwaddr=%s", fd, ether_ntoa((const struct ether_addr *)&ifr.ifr_hwaddr.sa_data));

   // Switch to non-blocking mode.

   int on = 1;

   if(ioctl(fd, FIONBIO, (char *)&on) < 0)
   {
      close(fd);
      ERR("Failed to switch to non-blocking on interface '%s'", name.c_str());
      return ptr<iface>();
   }

   // We need the destination address, so let's turn on (RECV)PKTINFO.

   if(setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on)) < 0)
   {
      ERR("IPV6_RECVPKTINFO failed");
      return ptr<iface>();
   }

   // Set up filter.

   struct icmp6_filter filter;

   ICMP6_FILTER_SETBLOCKALL(&filter);
   ICMP6_FILTER_SETPASS(ND_NEIGHBOR_SOLICIT, &filter);
   ICMP6_FILTER_SETPASS(ND_NEIGHBOR_ADVERT, &filter);

   if(setsockopt(fd, IPPROTO_ICMPV6, ICMP6_FILTER, &filter, sizeof(filter)) < 0)
   {
      ERR("Failed to set filter");
      return ptr<iface>();
   }

   // Set up an instance of 'iface'.

   ptr<iface> ifa(new iface());

   ifa->_name     = name;
   ifa->_fd       = fd;
   ifa->_weak_ptr = ifa.weak_copy();

   memcpy(&ifa->hwaddr, ifr.ifr_hwaddr.sa_data, sizeof(struct ether_addr));

   _map[name] = ifa;

   fixup_pollfds();

   return ifa;
}

ssize_t iface::read(address& saddr, address& daddr, uint8_t *msg, size_t size)
{
   struct sockaddr_in6 saddr_tmp;
   struct msghdr mhdr;
   struct iovec iov;
   char cbuf[256];
   int len;

   if(!msg || (size < 0))
      return -1;

   iov.iov_len = size;
   iov.iov_base = (caddr_t) msg;

   memset(&mhdr, 0, sizeof(mhdr));
   mhdr.msg_name = (caddr_t)&saddr_tmp;
   mhdr.msg_namelen = sizeof(saddr_tmp);
   mhdr.msg_iov = &iov;
   mhdr.msg_iovlen = 1;
   mhdr.msg_control = cbuf;
   mhdr.msg_controllen = sizeof(cbuf);

   if((len = recvmsg(_fd, &mhdr, 0)) < 0)
      return -1;

   if(len < sizeof(struct icmp6_hdr))
      return -1;

   // Get the destination address.

   struct cmsghdr *cmsg;

   for(cmsg = CMSG_FIRSTHDR(&mhdr); cmsg; cmsg = CMSG_NXTHDR(&mhdr, cmsg))
   {
      if(cmsg->cmsg_type == IPV6_PKTINFO)
         break;
   }

   if(!cmsg)
      return -1;

   saddr = saddr_tmp.sin6_addr;
   daddr = ((struct in6_pktinfo *)CMSG_DATA(cmsg))->ipi6_addr;

   DBG("recv() saddr=%s, daddr=%s, len=%d",
       saddr.to_string().c_str(), daddr.to_string().c_str(), len);

   return len;
}

//ssize_t iface::write(address& saddr, address& daddr, uint8_t *msg, size_t size)

ssize_t iface::write(const address& daddr, const uint8_t *msg, size_t size)
{
   struct sockaddr_in6 daddr_tmp;
   struct msghdr mhdr;
   struct iovec iov;

   memset(&daddr_tmp, 0, sizeof(struct sockaddr_in6));
   //daddr_tmp.sin6_len    = sizeof(struct sockaddr_in6);
   daddr_tmp.sin6_family = AF_INET6;
   daddr_tmp.sin6_port   = htons(IPPROTO_ICMPV6); // Needed?
   memcpy(&daddr_tmp.sin6_addr, &daddr.const_addr(), sizeof(struct in6_addr));

   iov.iov_len = size;
   iov.iov_base = (caddr_t)msg;

   memset(&mhdr, 0, sizeof(mhdr));
   mhdr.msg_name = (caddr_t)&daddr_tmp;
   mhdr.msg_namelen = sizeof(sockaddr_in6);
   mhdr.msg_iov = &iov;
   mhdr.msg_iovlen = 1;

   /*mhdr.msg_control = (void *)cmsg;
   mhdr.msg_controllen = sizeof(chdr);*/

   int len;

   if((len = sendmsg(_fd, &mhdr, 0)) < 0)
      return -1;

   return len;
}

ssize_t iface::write_solicit(const address& taddr)
{
   struct nd_neighbor_solicit msg;

   // FIXME: Alright, I'm lazy.
   static address multicast("ff02::1:ff00:0000");

   address daddr;

   memset(&msg, 0, sizeof(struct nd_neighbor_solicit));

   msg.nd_ns_hdr.icmp6_type = ND_NEIGHBOR_SOLICIT;

   memcpy(&msg.nd_ns_target, &taddr.const_addr(), sizeof(struct in6_addr));

   daddr = multicast;

   daddr.addr().s6_addr[13] = taddr.const_addr().s6_addr[13];
   daddr.addr().s6_addr[14] = taddr.const_addr().s6_addr[14];
   daddr.addr().s6_addr[15] = taddr.const_addr().s6_addr[15];

   DBG("iface::write_solicit() taddr=%s, daddr=%s",
       taddr.to_string().c_str(), daddr.to_string().c_str());

   return write(daddr, (uint8_t *)&msg, sizeof(struct nd_neighbor_solicit));
}

ssize_t iface::write_advert(const address& daddr, const address& taddr)
{
   struct nd_neighbor_advert msg;


}

int iface::read_nd(address& saddr, address& daddr, address& taddr)
{
   uint8_t msg[256];

   if(read(saddr, daddr, msg, sizeof(msg)) < 0)
      return -1;

   switch(((struct icmp6_hdr *)msg)->icmp6_type)
   {
   case ND_NEIGHBOR_SOLICIT:
      taddr = ((struct nd_neighbor_solicit *)msg)->nd_ns_target;
      break;

   case ND_NEIGHBOR_ADVERT:
      break;

   default:
      return -1;
   }

   return ((struct icmp6_hdr *)msg)->icmp6_type;
}


void iface::fixup_pollfds()
{
   _pollfds.resize(_map.size());

   int i = 0;

   DBG("iface::fixup_pollfds() _map.size()=%d", _map.size());

   for(std::map<std::string, ptr<iface> >::iterator it = _map.begin();
       it != _map.end(); it++)
   {
      _pollfds[i].fd      = it->second->_fd;
      _pollfds[i].events  = POLLIN;
      _pollfds[i].revents = 0;
      i++;
   }
}

void iface::pr(const ptr<proxy>& pr)
{
   _proxy = pr;
}

const ptr<proxy>& iface::pr() const
{
   return _proxy;
}

void iface::remove_session(const ptr<session>& se)
{
   _sessions.remove(se);
}

void iface::add_session(const ptr<session>& se)
{
   _sessions.push_back(se);
}

int iface::poll_all()
{
   if(_pollfds.size() == 0)
   {
      ::sleep(1);
      return 0;
   }

#if 0
   DBG("iface::poll() _pollfds.size()=%d, _map.size()=%d",
       _pollfds.size(), _map.size());
#endif

   // TODO: Assert _pollfds.size() == _map.size().

   int len;

   if((len = ::poll(&_pollfds[0], _pollfds.size(), 100)) < 0)
      return -1;

   if(len == 0)
      return 0;

   std::vector<struct pollfd>::iterator fit;
   std::map<std::string, ptr<iface> >::iterator iit;

   for(fit = _pollfds.begin(), iit = _map.begin(); fit != _pollfds.end(); fit++, iit++)
   {
      if(!(fit->revents & POLLIN))
         continue;

      // We assume here that _pollfds is perfectly aligned with _map.

      ptr<iface> ifa = iit->second;

      //DBG("POLLIN on %s", ifa->_name.c_str());

      int icmp6_type;
      address saddr, daddr, taddr;

      if((icmp6_type = ifa->read_nd(saddr, daddr, taddr)) < 0)
      {
         ERR("Failed to read from interface '%s'", ifa->_name.c_str());
         continue;
      }

      if((icmp6_type == ND_NEIGHBOR_SOLICIT) && ifa->_proxy)
      {
         DBG("ND_NEIGHBOR_SOLICIT");

         // TODO: Check the cache for recent sessions.

         ifa->_proxy->handle_solicit(saddr, daddr, taddr);
      }
      else if(icmp6_type == ND_NEIGHBOR_ADVERT)
      {
         DBG("ND_NEIGHBOR_ADVERT");

         for(std::list<ptr<session> >::iterator s_it = ifa->_sessions.begin();
             s_it != ifa->_sessions.end(); s_it++)
         {
            /*if((*s_it)->addr() == taddr)
            {
               (*s_it)->handle_advert();
            }*/
         }
      }
   }

   return 0;
}


const std::string& iface::name() const
{
   return _name;
}

__NDPPD_NS_END
 
