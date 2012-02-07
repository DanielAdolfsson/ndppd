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
#include <list>
#include <vector>
#include <map>

#include <sys/poll.h>
#include <net/ethernet.h>

#include "ndppd.h"

NDPPD_NS_BEGIN

class session;
class proxy;

class iface {
public:

    // Destructor.
    ~iface();

    static ptr<iface> open_ifd(const std::string& name);

    static ptr<iface> open_pfd(const std::string& name);

    static int poll_all();

    static ssize_t read(int fd, struct sockaddr* saddr, uint8_t* msg, size_t size);

    static ssize_t write(int fd, const address& daddr, const uint8_t* msg, size_t size);

    // Writes a NB_NEIGHBOR_SOLICIT message to the _ifd socket.
    ssize_t write_solicit(const address& taddr);

    // Writes a NB_NEIGHBOR_ADVERT message to the _ifd socket;
    ssize_t write_advert(const address& daddr, const address& taddr, bool router);

    // Reads a NB_NEIGHBOR_SOLICIT message from the _pfd socket.
    ssize_t read_solicit(address& saddr, address& daddr, address& taddr);

    // Reads a NB_NEIGHBOR_ADVERT message from the _ifd socket;
    ssize_t read_advert(address& saddr, address& taddr);

    // Returns the name of the interface.
    const std::string& name() const;

    // Adds a session to be monitored for ND_NEIGHBOR_ADVERT messages.
    void add_session(const ptr<session>& se);

    void remove_session(const ptr<session>& se);

    void pr(const ptr<proxy>& pr);

    const ptr<proxy>& pr() const;

private:
    static std::map<std::string, weak_ptr<iface> > _map;

    static bool _map_dirty;

    // An array of objects used with ::poll.
    static std::vector<struct pollfd> _pollfds;

    // Updates the array above.
    static void fixup_pollfds();

    static void cleanup();

    // Weak pointer so this object can reference itself.
    weak_ptr<iface> _ptr;

    // The "generic" ICMPv6 socket for reading/writing NB_NEIGHBOR_ADVERT
    // messages as well as writing NB_NEIGHBOR_SOLICIT messages.
    int _ifd;

    // This is the PF_PACKET socket we use in order to read
    // NB_NEIGHBOR_SOLICIT messages.
    int _pfd;

    // Previous state of ALLMULTI for the interface.
    int _prev_allmulti;

    // Name of this interface.
    std::string _name;

    // An array of sessions that are monitoring this interface for
    // ND_NEIGHBOR_ADVERT messages.
    std::list<weak_ptr<session> > _sessions;

    weak_ptr<proxy> _pr;

    // The link-layer address of this interface.
    struct ether_addr hwaddr;

    // Turns on/off ALLMULTI for this interface - returns the previous state
    // or -1 if there was an error.
    int allmulti(int state);

    // Constructor.
    iface();
};

NDPPD_NS_END
