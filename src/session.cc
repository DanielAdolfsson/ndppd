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
#include <algorithm>
#include <sstream>

#include "ndppd.h"
#include "proxy.h"
#include "iface.h"
#include "session.h"

NDPPD_NS_BEGIN

std::list<weak_ptr<session> > session::_sessions;

static address all_nodes = address("ff02::1");

void session::update_all(int elapsed_time)
{
    for (std::list<weak_ptr<session> >::iterator it = _sessions.begin();
            it != _sessions.end(); ) {
        if (!*it) {
            _sessions.erase(it++);
            continue;
        }

        ptr<session> se = *it++;

        if ((se->_ttl -= elapsed_time) >= 0) {
            continue;
        }

        switch (se->_status) {
        case session::WAITING:
            logger::debug() << "session is now invalid";
            se->_status = session::INVALID;
            se->_ttl    = se->_pr->deadtime();
            break;

        default:
            se->_pr->remove_session(se);
        }
    }
}

session::~session()
{
    logger::debug() << "session::~session() this=" << logger::format("%x", this);

    for (std::list<ptr<iface> >::iterator it = _ifaces.begin();
            it != _ifaces.end(); it++)
    {
        if (_autowire == true) {
            handle_auto_unwire((*it));
        }
                
        (*it)->remove_session(_ptr);
    }
}

ptr<session> session::create(const ptr<proxy>& pr, const address& saddr,
    const address& daddr, const address& taddr, bool auto_wire)
{
    ptr<session> se(new session());

    se->_ptr      = se;
    se->_pr       = pr;
    se->_saddr    = address("::") == saddr ? all_nodes : saddr;
    se->_taddr    = taddr;
    se->_daddr    = daddr;
    se->_autowire = auto_wire;
    se->_ttl      = pr->timeout();

    _sessions.push_back(se);

    logger::debug()
        << "session::create() pr=" << logger::format("%x", (proxy* )pr) << ", saddr=" << saddr
        << ", daddr=" << daddr << ", taddr=" << taddr << ", autowire=" << (auto_wire == true ? "yes" : "no") << " =" << logger::format("%x", (session* )se);

    return se;
}

void session::add_iface(const ptr<iface>& ifa)
{
    if (std::find(_ifaces.begin(), _ifaces.end(), ifa) != _ifaces.end())
        return;

    ifa->add_session(_ptr);
    _ifaces.push_back(ifa);
}

void session::send_solicit()
{
    logger::debug() << "session::send_solicit() (_ifaces.size() = " << _ifaces.size() << ")";

    for (std::list<ptr<iface> >::iterator it = _ifaces.begin();
            it != _ifaces.end(); it++) {
        logger::debug() << " - " << (*it)->name();
        (*it)->write_solicit(_taddr);
    }
}

void session::send_advert()
{
    _pr->ifa()->write_advert(_saddr, _taddr, _pr->router());
}

void session::handle_auto_wire(const ptr<iface>& ifa)
{
    logger::debug()
        << "session::handle_auto_wire() taddr=" << _taddr << ", ifa=" << ifa->name();
    
    std::stringstream route_cmd;
    route_cmd << "ip";
    route_cmd << " " << "-6";
    route_cmd << " " << "route";
    route_cmd << " " << "replace";
    route_cmd << " " << std::string(_taddr);
    route_cmd << " " << "dev";
    route_cmd << " " << ifa->name();
            
    logger::debug()
        << "session::system(" << route_cmd.str() << ")";
    
    system(route_cmd.str().c_str());
}

void session::handle_auto_unwire(const ptr<iface>& ifa)
{
    logger::debug()
        << "session::handle_auto_unwire() taddr=" << _taddr << ", ifa=" << ifa->name();
    
    std::stringstream route_cmd;
    route_cmd << "ip";
    route_cmd << " " << "-6";
    route_cmd << " " << "route";
    route_cmd << " " << "flush";
    route_cmd << " " << std::string(_taddr);
    route_cmd << " " << "dev";
    route_cmd << " " << ifa->name();
            
    logger::debug()
        << "session::system(" << route_cmd.str() << ")";
    
    system(route_cmd.str().c_str());
}

void session::handle_advert(const ptr<iface>& ifa)
{
    if (_autowire == true) {
        handle_auto_wire(ifa);
    }
    
    handle_advert();
}

void session::handle_advert()
{
    logger::debug()
        << "session::handle_advert() taddr=" << _taddr << ", ttl=" << _pr->ttl();
    
    _status = VALID;
    _ttl    = _pr->ttl();

    send_advert();
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

bool session::autowire() const
{
    return _autowire;
}

int session::status() const
{
    return _status;
}

void session::status(int val)
{
    _status = val;
}

NDPPD_NS_END
