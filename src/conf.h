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
#ifndef __NDPPD_CONF_H
#define __NDPPD_CONF_H

#include <string>

#include <cstdarg>

#include "ndppd.h"

struct cfg_t;
struct cfg_opt_t;

__NDPPD_NS_BEGIN

class conf
{
private:
   static bool setup(::cfg_t *cfg);
   static void error_printf(::cfg_t *cfg, const char *fmt, va_list ap);
   static int validate_rule(::cfg_t *cfg, ::cfg_opt_t *opt);
public:
   static bool load(const std::string& path);
};

__NDPPD_NS_END

#endif // __NDPPD_CONF_H
 
 
