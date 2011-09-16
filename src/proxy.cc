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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ndppd.h"

#include "proxy.h"
#include "iface.h"
#include "rule.h"
#include "session.h"

__NDPPD_NS_BEGIN

proxy::proxy()
{
}

ptr<proxy> proxy::create(const ptr<iface>& ifa)
{
   ptr<proxy> pr(new proxy());
   pr->_weak_ptr = pr.weak_copy();
   pr->_ifa      = ifa;

   ifa->pr(pr);

   DBG("proxy_create() ifa=%x =%x", (iface *)ifa, (proxy *)pr);

   return pr;
}

ptr<proxy> proxy::open(const std::string& ifname)
{
   return create(iface::open_pfd(ifname));
}

void proxy::handle_solicit(const address& saddr, const address& daddr,
   const address& taddr)
{
   DBG("proxy::handle_solicit() saddr=%s, taddr=%s",
       saddr.to_string().c_str(), taddr.to_string().c_str());

   // Let's check this proxy's list of sessions to see if we can
   // find one with the same target address.

   for(std::list<ptr<session> >::iterator sit = _sessions.begin();
       sit != _sessions.end(); sit++)
   {
      if((*sit)->taddr() == taddr)
      {
         switch((*sit)->status())
         {
         case session::WAITING:
         case session::INVALID:
            break;

         case session::VALID:
            (*sit)->send_solicit();
         }

         return;
      }
   }

   // Since we couldn't find a session that matched, we'll try to find
   // a matching rule instead, and then set up a new session.

   ptr<session> se;

   for(std::list<ptr<rule> >::iterator it = _rules.begin();
       it != _rules.end(); it++)
   {
      DBG("comparing %s against %s",
         (*it)->addr().to_string().c_str(), taddr.to_string().c_str());

      if((*it)->addr() == taddr)
      {
         if(se.is_null())
            se = session::create(_weak_ptr.strong_copy(), saddr, daddr, taddr);

         se->add_iface((*it)->ifa());
      }
   }

   if(se)
   {
      _sessions.push_back(se);
      se->send_solicit();
   }
}

ptr<rule> proxy::add_rule(const address& addr, const ptr<iface>& ifa)
{
   ptr<rule> ru(rule::create(_weak_ptr.strong_copy(), addr, ifa));
   _rules.push_back(ru);
   return ru;
}

ptr<rule> proxy::add_rule(const address& addr)
{
   ptr<rule> ru(rule::create(_weak_ptr.strong_copy(), addr));
   _rules.push_back(ru);
   return ru;
}

void proxy::remove_session(const ptr<session>& se)
{
   _sessions.remove(se);
}

const ptr<iface>& proxy::ifa() const
{
   return _ifa;
}

__NDPPD_NS_END

