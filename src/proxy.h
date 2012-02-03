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
#pragma once

#include <string>
#include <vector>
#include <map>

#include <sys/poll.h>

#include "ndppd.h"

NDPPD_NS_BEGIN

class iface;
class rule;

class proxy {
public:
    static ptr<proxy> create(const ptr<iface>& ifa);

    static ptr<proxy> open(const std::string& ifn);

    void handle_solicit(const address& saddr, const address& daddr,
        const address& taddr);

    void remove_session(const ptr<session>& se);

    ptr<rule> add_rule(const address& addr, const ptr<iface>& ifa);

    ptr<rule> add_rule(const address& addr, bool aut = false);

    const ptr<iface>& ifa() const;

    bool router() const;

    void router(bool val);

    int timeout() const;

    void timeout(int val);

    int ttl() const;

    void ttl(int val);

private:
    static std::list<ptr<proxy> > _list;

    weak_ptr<proxy> _ptr;

    ptr<iface> _ifa;

    std::list<ptr<rule> > _rules;

    std::list<ptr<session> > _sessions;

    bool _router;

    int _ttl, _timeout;

    proxy();
};

NDPPD_NS_END
