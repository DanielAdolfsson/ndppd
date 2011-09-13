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
#include <algorithm>

#include "ndppd.h"
#include "proxy.h"
#include "iface.h"
#include "session.h"

__NDPPD_NS_BEGIN

session::session()
{
}

ptr<session> session::create(const ptr<proxy>& pr, const address& saddr,
   const address& daddr, const address& taddr)
{
   ptr<session> se(new session());

   se->_weak_ptr = se.weak_copy();
   se->_pr       = pr;
   se->_saddr    = saddr;
   se->_taddr    = taddr;
   se->_daddr    = daddr;

   DBG("session::create() pr=%x, saddr=%s, daddr=%s, taddr=%s, =%x",
      (proxy *)pr, saddr.to_string().c_str(), daddr.to_string().c_str(),
      taddr.to_string().c_str(), (session *)se);

   return se;
}

void session::add_iface(const ptr<iface>& ifa)
{
   if(std::find(_ifaces.begin(), _ifaces.end(), ifa) != _ifaces.end())
      return;

   ifa->add_session(_weak_ptr.strong_copy());
   _ifaces.push_back(ifa);
}

void session::send_solicit()
{
   DBG("sending solicit");

   for(std::list<ptr<iface> >::iterator it = _ifaces.begin();
       it != _ifaces.end(); it++)
   {
      DBG("   on %s", (*it)->name().c_str());
      (*it)->write_solicit(_taddr);
      // huhh hahh.
   }
}

/*void session::send_advert()
{
}*/

void session::handle_advert()
{


}

const address& session::taddr() const
{
   return _taddr;
}

const address& session::saddr() const
{
   return _saddr;
}

const address& session::daddr() const
{
   return _daddr;
}

int session::status() const
{
   return _status;
}

void refresh()
{

}


__NDPPD_NS_END

 
