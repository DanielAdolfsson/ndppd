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
class proxy;

class rule {
public:
    static ptr<rule> create(const ptr<proxy>& pr, const address& addr, const ptr<iface>& ifa);

    static ptr<rule> create(const ptr<proxy>& pr, const address& addr, bool stc = true);

    const address& addr() const;

    ptr<iface> ifa() const;

    bool is_auto() const;

    bool check(const address& addr) const;

private:
    weak_ptr<rule> _ptr;

    weak_ptr<proxy> _pr;

    ptr<iface> _ifa;

    address _addr;

    bool _aut;

    rule();
};

NDPPD_NS_END
