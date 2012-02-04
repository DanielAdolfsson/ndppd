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

#include <vector>

#include "ndppd.h"

NDPPD_NS_BEGIN

class proxy;
class iface;

class session {
private:
    weak_ptr<session> _ptr;

    weak_ptr<proxy> _pr;

    address _saddr, _daddr, _taddr;

    // An array of interfaces this session is monitoring for
    // ND_NEIGHBOR_ADVERT on.
    std::list<ptr<iface> > _ifaces;

    // The remaining time in miliseconds the object will stay in the
    // interface's session array or cache.
    int _ttl;

    int _status;

    static std::list<weak_ptr<session> > _sessions;

public:
    enum
    {
        WAITING, // Waiting for an advert response.
        VALID,   // Valid;
        INVALID  // Invalid;
    };

    static void update_all(int elapsed_time);

    // Destructor.
    ~session();

    static ptr<session> create(const ptr<proxy>& pr, const address& saddr,
        const address& daddr, const address& taddr);

    void add_iface(const ptr<iface>& ifa);

    const address& taddr() const;

    const address& daddr() const;

    const address& saddr() const;

    int status() const;

    void status(int val);

    void handle_advert();

    void send_advert();

    void send_solicit();

    void refesh();
};

NDPPD_NS_END
