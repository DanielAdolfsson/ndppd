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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ndppd.h"

#include "proxy.h"
#include "route.h"
#include "iface.h"
#include "rule.h"
#include "session.h"

NDPPD_NS_BEGIN

std::list<ptr<proxy> > proxy::_list;

proxy::proxy() :
    _router(true), _ttl(30000), _timeout(500)
{
}

ptr<proxy> proxy::create(const ptr<iface>& ifa)
{
    ptr<proxy> pr(new proxy());
    pr->_ptr = pr;
    pr->_ifa = ifa;

    _list.push_back(pr);

    ifa->pr(pr);

    logger::debug() << "proxy::create() if=" << ifa->name();

    return pr;
}

ptr<proxy> proxy::open(const std::string& ifname)
{
    ptr<iface> ifa = iface::open_pfd(ifname);

    if (!ifa) {
        return ptr<proxy>();
    }

    return create(ifa);
}

void proxy::handle_solicit(const address& saddr, const address& daddr,
    const address& taddr)
{
    logger::debug()
        << "proxy::handle_solicit() saddr=" << saddr.to_string()
        << ", taddr=" << taddr.to_string();

    // Let's check this proxy's list of sessions to see if we can
    // find one with the same target address.

    for (std::list<ptr<session> >::iterator sit = _sessions.begin();
            sit != _sessions.end(); sit++) {

        if ((*sit)->taddr() == taddr) {
            switch ((*sit)->status()) {
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

    ptr<session> se;

    for (std::list<ptr<rule> >::iterator it = _rules.begin();
            it != _rules.end(); it++) {
        ptr<rule> ru = *it;

        logger::debug() << "checking " << ru->addr() << " against " << taddr;

        if (ru->addr() == taddr) {
            if (!se) {
                se = session::create(_ptr, saddr, daddr, taddr);
            }

            if (ru->is_auto()) {
                ptr<route> rt = route::find(taddr);

                if (rt->ifname() == _ifa->name()) {
                    logger::debug() << "skipping route since it's using interface " << rt->ifname();
                } else {
                    ptr<iface> ifa = rt->ifa();

                    if (ifa && (ifa != ru->ifa())) {
                        se->add_iface(ifa);
                    }
                }
            } else if (!ru->ifa()) {
                // This rule doesn't have an interface, and thus we'll consider
                // it "static" and immediately send the response.
                se->handle_advert();
                return;
            } else {
                se->add_iface((*it)->ifa());
            }
        }
    }

    if (se) {
        _sessions.push_back(se);
        se->send_solicit();
    }
}

ptr<rule> proxy::add_rule(const address& addr, const ptr<iface>& ifa)
{
    ptr<rule> ru(rule::create(_ptr, addr, ifa));
    _rules.push_back(ru);
    return ru;
}

ptr<rule> proxy::add_rule(const address& addr, bool aut)
{
    ptr<rule> ru(rule::create(_ptr, addr, aut));
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

NDPPD_NS_END

