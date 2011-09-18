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

proxy::proxy() :
   _router(true), _ttl(30000), _timeout(500)
{
}

strong_ptr<proxy> proxy::create(const strong_ptr<iface>& ifa)
{
   strong_ptr<proxy> pr(new proxy());
   pr->_ptr = pr;
   pr->_ifa = ifa;

   ifa->pr(pr);

   DBG("proxy::create() if=%x", ifa->name().c_str());

   return pr;
}

strong_ptr<proxy> proxy::open(const std::string& ifname)
{
   strong_ptr<iface> ifa = iface::open_pfd(ifname);

   if(ifa.is_null())
      return strong_ptr<proxy>();

   return create(ifa);
}

void proxy::handle_solicit(const address& saddr, const address& daddr,
   const address& taddr)
{
   DBG("proxy::handle_solicit() saddr=%s, taddr=%s",
       saddr.to_string().c_str(), taddr.to_string().c_str());

   // Let's check this proxy's list of sessions to see if we can
   // find one with the same target address.

   for(std::list<strong_ptr<session> >::iterator sit = _sessions.begin();
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
            (*sit)->send_advert();
         }

         return;
      }
   }

   // Since we couldn't find a session that matched, we'll try to find
   // a matching rule instead, and then set up a new session.

   strong_ptr<session> se;

   for(std::list<strong_ptr<rule> >::iterator it = _rules.begin();
       it != _rules.end(); it++)
   {
      strong_ptr<rule> ru = *it;

      DBG("comparing %s against %s",
          ru->addr().to_string().c_str(), taddr.to_string().c_str());

      if(ru->addr() == taddr)
      {
         if(se.is_null())
            se = session::create(_ptr, saddr, daddr, taddr);

         if(ru->ifa().is_null())
         {
            // This rule doesn't have an interface, and thus we'll consider
            // it "static" and immediately send the response.

            se->handle_advert();
            return;
         }

         se->add_iface((*it)->ifa());
      }
   }

   if(se)
   {
      _sessions.push_back(se);
      se->send_solicit();
   }
}

strong_ptr<rule> proxy::add_rule(const address& addr, const strong_ptr<iface>& ifa)
{
   strong_ptr<rule> ru(rule::create(_ptr, addr, ifa));
   _rules.push_back(ru);
   return ru;
}

strong_ptr<rule> proxy::add_rule(const address& addr)
{
   strong_ptr<rule> ru(rule::create(_ptr, addr));
   _rules.push_back(ru);
   return ru;
}

void proxy::remove_session(const strong_ptr<session>& se)
{
   _sessions.remove(se);
}

const strong_ptr<iface>& proxy::ifa() const
{
   return _ifa;
}

bool proxy::router() const
{
   return _router;
}

void proxy::router(bool val)
{
   _router = val;
}

int proxy::ttl() const
{
   return _ttl;
}

void proxy::ttl(int val)
{
   _ttl = (val >= 0) ? val : 30000;
}

int proxy::timeout() const
{
   return _timeout;
}

void proxy::timeout(int val)
{
   _timeout = (val >= 0) ? val : 500;
}

__NDPPD_NS_END

