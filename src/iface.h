// ndppd - NDP Proxy Daemon
// Copyright (C) 2011  Daniel Adolfsson <daniel.adolfsson@tuhox.com>
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
#ifndef __NDPPD_IFACE_H
#define __NDPPD_IFACE_H

#include <string>
#include <list>
#include <vector>
#include <map>

#include <sys/poll.h>
#include <net/ethernet.h>

#include "ndppd.h"

__NDPPD_NS_BEGIN

class proxy;
class session;

class iface
{
private:
   // Weak pointer so this object can reference itself.
   ptr<iface> _weak_ptr;

   static std::map<std::string, ptr<iface> > _map;

   // An array of objects used with ::poll.
   static std::vector<struct pollfd> _pollfds;

   // Updates the array above.
   static void fixup_pollfds();

   // Socket.
   int _fd;

   // Name of this interface.
   std::string _name;

   // An array of sessions that are monitoring this interface for
   // ND_NEIGHBOR_ADVERT messages.
   std::list<ptr<session> > _sessions;

   ptr<proxy> _proxy;

   // The link-layer address of this interface.
   struct ether_addr hwaddr;

   // Constructor.
   iface();

public:

   // Destructor.
   ~iface();

   // Opens the specified interface, and returns a pointer to
   // the object, or null if there was a problem.
   static ptr<iface> open(const std::string& name);

   static int poll_all();

   ssize_t read(address& saddr, address& daddr, uint8_t *msg, size_t size);

   ssize_t write(const address& daddr, const uint8_t *msg, size_t size);

   ssize_t write_solicit(const address& taddr);

   ssize_t write_advert(const address& daddr, const address& taddr);

   int read_nd(address& saddr, address& daddr, address& taddr);

   // Returns the name of the interface.
   const std::string& name() const;

   const ptr<proxy>& pr() const;

   void pr(const ptr<proxy>& pr);

   // Adds a session to be monitored for ND_NEIGHBOR_ADVERT messages.
   void add_session(const ptr<session>& se);

   void remove_session(const ptr<session>& se);

};

__NDPPD_NS_END

#endif // __NDPPD_IFACE_H
 
 
