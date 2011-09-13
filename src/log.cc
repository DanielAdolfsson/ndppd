// ndppd - NDP Proxy Daemon
// Copyright (C) 2011  Daniel Adolfsson <daniel.adolfsson@tuhox.com>
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

#include "ndppd.h"

using namespace ndppd;

__NDPPD_NS_BEGIN

void log::puts(int level, const char *str)
{
   fprintf(stderr, "(%d) : %s\n", level, str);
}

void log::printf(int level, const char *fmt, ...)
{
   char buf[256];
   va_list args;
   int ret;

   va_start(args, fmt);

   if(vsnprintf(buf, sizeof(buf), fmt, args) > 0)
   {
      puts(level, buf);
   }

   va_end(args);
}

__NDPPD_NS_END
 
 
