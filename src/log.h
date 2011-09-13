// ndppd - NDP Proxy Daemon
// Copyright (C) 2011  Daniel Adolfsson
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

#ifdef DEBUG
#define DBG(...) log::printf(log::L_DEBUG,   __VA_ARGS__)
#else
#define DBG(...)
#endif

#define ERR(...) log::printf(log::L_ERROR,   __VA_ARGS__)
#define WRN(...) log::printf(log::L_WARNING, __VA_ARGS__)
#define BUG(...) log::printf(log::L_BUG,     __VA_ARGS__)
#define NFO(...) log::printf(log::L_INFO,    __VA_ARGS__)
#define NCE(...) log::printf(log::L_NOTICE,  __VA_ARGS__)
#define FTL(...) log::printf(log::L_FATAL,   __VA_ARGS__)

__NDPPD_NS_BEGIN

class log
{
public:
   enum
   {
      L_FATAL,
      L_ERROR,
      L_WARNING,
      L_BUG,
      L_NOTICE,
      L_INFO,
      L_DEBUG
   };

   static void puts(int level, const char *str);

   static void printf(int level, const char *fmt, ...);
};

__NDPPD_NS_END

#endif // __NDPPD_LOG_H
 
 
