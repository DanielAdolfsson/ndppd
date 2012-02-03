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
#include <map>
#include <memory>
#include <vector>
#include <cstdarg>

#include "ndppd.h"

NDPPD_NS_BEGIN

class conf {
public:

private:
    std::string _value;

    bool _is_block;

    std::multimap<std::string, ptr<conf> > _map;

    void dump(logger& l, int level) const;

    static const char* skip(const char* str, bool all = true);

    bool parse_block(const char* *str);

    bool parse(const char* *str);

public:
    conf();

    static ptr<conf> load(const std::string& path);

    bool is_block() const;

    ptr<conf> operator[](const std::string& name) const;
    ptr<conf> operator()(const std::string& name, int index = 0) const;

    operator const std::string&() const;
    operator int() const;
    operator bool() const;

    bool as_bool() const;
    const std::string& as_str() const;
    int as_int() const;

    bool empty() const;

    std::vector<ptr<conf> > find_all(const std::string& name) const;

    ptr<conf> find(const std::string& name, int index = 0) const;

    void dump(int pri = LOG_INFO) const;

    operator const std::string&();

};

NDPPD_NS_END
