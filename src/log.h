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
#ifndef __NDPPD_LOG_H
#define __NDPPD_LOG_H

#include <syslog.h>

#ifdef DEBUG
#define DBG(...) log::printf(LOG_DEBUG,   __VA_ARGS__)
#else
#define DBG(...)
#endif

#define ERR(...) log::printf(LOG_ERR,     __VA_ARGS__)
#define WRN(...) log::printf(LOG_WARNING, __VA_ARGS__)
#define CRT(...) log::printf(LOG_CRIT,    __VA_ARGS__)
#define NFO(...) log::printf(LOG_INFO,    __VA_ARGS__)
#define NCE(...) log::printf(LOG_NOTICE,  __VA_ARGS__)

__NDPPD_NS_BEGIN

class log
{
private:
   static const char *_level_str[];

   static bool _syslog;

public:
   static void puts(int level, const char *str);

   static void printf(int level, const char *fmt, ...);

   static void syslog(bool enable);
};

__NDPPD_NS_END

#endif // __NDPPD_LOG_H
