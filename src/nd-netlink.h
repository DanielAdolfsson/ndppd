//
// @file nd-netlink.h
//
// Copyright 2016, Allied Telesis Labs New Zealand, Ltd
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

NDPPD_NS_BEGIN

bool netlink_teardown();
bool netlink_setup();
bool if_addr_find(std::string iface, const struct in6_addr *iaddr);
void if_add_to_list(int ifindex, const ptr<iface>& ifa);

NDPPD_NS_END
