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
#ifndef __NDPPD_PROXY_H
#define __NDPPD_PROXY_H

#include <string>
#include <vector>
#include <map>

#include <sys/poll.h>

#include "ndppd.h"

__NDPPD_NS_BEGIN

class iface;
class rule;

class proxy
{
private:
   ptr<iface> _ifa;

   std::list<ptr<rule> > _rules;

   std::list<ptr<session> > _sessions;

   ptr<proxy> _weak_ptr;

   proxy();

public:
   static ptr<proxy> create(const ptr<iface>& ifa);

   static ptr<proxy> open(const std::string& ifn);

   void handle_solicit(const address& saddr, const address& daddr,
      const address& taddr);

   void remove_session(const ptr<session>& se);

   ptr<rule> add_rule(const address& addr, const ptr<iface>& ifa);

   ptr<rule> add_rule(const address& addr);

   const ptr<iface>& ifa() const;
};

__NDPPD_NS_END

#endif // __NDPPD_PROXY_H
