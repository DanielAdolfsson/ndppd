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
#include <cstdio>
#include <cstdarg>
#include <cstring>
#include <cctype>
#include <memory>
#include <iostream>
#include <fstream>
#include <netinet/ip6.h>

#include "ndppd.h"

NDPPD_NS_BEGIN

conf::conf() :
    _is_block(false)
{

}

const std::string &conf::value() const
{
    return _value;
}

bool conf::bool_value() const
{
    if (!strcasecmp(_value.c_str(), "true") || !strcasecmp(_value.c_str(), "yes"))
        return true;
    else
        return false;
}

int conf::int_value() const
{
    return atoi(_value.c_str());
}

void conf::value(const std::string &value)
{
    _value = value;
}

std::shared_ptr<conf> conf::load(const std::string &path)
{
    std::ifstream ifs;
    ifs.exceptions(std::ifstream::failbit | std::ifstream::badbit);

    try {
        ifs.open(path, std::ios::in);
        std::string buf((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
        ifs.close();
        const char *c_buf = buf.c_str();

        std::shared_ptr<conf> cf(new conf);

        if (cf->parse_block(&c_buf)) {
            logger l(LOG_DEBUG);
            cf->dump(l, 0);
            return cf;
        }

        logger::error() << "Could not parse configuration file";
    } catch (std::ifstream::failure e) {
        logger::error() << "Failed to load configuration file '" << path << "'";
    }

    return std::shared_ptr<conf>();
}

bool conf::is_block() const
{
    return _is_block;
}

const char *conf::skip(const char *str, bool all)
{
    if (!all) {
        while (*str && (*str != '\n') && isspace(*str))
            str++;

        return str;
    }

    while (*str) {
        while (*str && isspace(*str))
            str++;

        if (!*str)
            break;

        if ((*str == '#') || ((*str == '/') && (*(str + 1) == '/'))) {
            while (*str && (*str != '\n'))
                str++;
            continue;
        }

        if ((*str == '/') && (*(str + 1) == '*')) {
            while (*str) {
                if ((*str == '*') && (*(str + 1) == '/')) {
                    str += 2;
                    break;
                }
                str++;
            }
            continue;
        }

        break;
    }

    return str;
}

bool conf::parse_block(const char **str)
{
    const char *p = *str;

    _is_block = true;

    while (*p) {
        std::stringstream ss;

        p = skip(p);

        if (*p == '}') {
            *str = p;
            return true;
        }

        while (*p && isalpha(*p)) {
            ss << *p++;
        }

        p = skip(p);

        if (*p == '=') {
            p++;
        }

        std::shared_ptr<conf> cf(new conf);

        if (cf->parse(&p)) {
            _map.insert(std::pair<std::string, std::shared_ptr<conf> >(ss.str(), cf));
        }
    }

    *str = p;
    return true;
}

bool conf::parse(const char **str)
{
    const char *p = *str;
    std::stringstream ss;

    p = skip(p, false);

    if (!*p) {
        return false;
    } else if ((*p == '\'') || (*p == '"')) {
        for (char e = *p++; *p && (*p != e); p++)
            ss << *p;
    } else if (isalnum(*p)) {
        while (*p && (isalnum(*p) || strchr(":/.", *p)))
            ss << *p++;
    } else {
        return false;
    }

    _value = ss.str();

    p = skip(p, false);

    if (*p == '{') {
        p++;

        if (!parse_block(&p))
            return false;

        if (*p != '}')
            return false;

        p++;
    }

    *str = p;
    return true;
}

void conf::dump() const
{
    logger l(LOG_ERR);
    dump(l, 0);
}

void conf::dump(logger &l, int level) const
{
    int i;

    std::string pfx;
    for (int i = 0; i < level; i++) {
        pfx += "    ";
    }

    if (_value != "") {
        l << _value << " ";
    }

    if (_is_block) {
        l << "{" << logger::endl;

        std::multimap<std::string, std::shared_ptr<conf> >::const_iterator it;

        for (it = _map.begin(); it != _map.end(); it++) {
            l << pfx << "    " << it->first << " ";
            it->second->dump(l, level + 1);
        }

        l << pfx << "}" << logger::endl;
    }

    l << logger::endl;
}

std::shared_ptr<conf> conf::operator[](const std::string& name) const
{
    std::multimap<std::string, std::shared_ptr<conf> >::const_iterator it;

    if ((it = _map.find(name)) == _map.end())
        return std::shared_ptr<conf>();
    else
        return it->second;
}

std::vector<std::shared_ptr<conf> > conf::find(const std::string& name) const
{
    std::vector<std::shared_ptr<conf> > vec;
    std::multimap<std::string, std::shared_ptr<conf> >::const_iterator it;
    for (it = _map.find(name); it != _map.end(); it++) {
        vec.push_back(it->second);
    }
    return vec;
}

conf::operator const std::string&()
{
    return _value;
}

NDPPD_NS_END
