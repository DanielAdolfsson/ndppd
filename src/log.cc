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
#include <syslog.h>

#include "ndppd.h"

using namespace ndppd;

__NDPPD_NS_BEGIN

const char *log::_level_str[] =
{
    "fatal",
    "alert",
    "critical",
    "error",
    "warning",
    "notice",
    "info",
    "debug"
};

bool log::_syslog = false;

void log::puts(int level, const char *str)
{
    const char *ls;

    if ((level < 0) || (level > LOG_DEBUG))
        ls = "unknown";
    else
        ls = _level_str[level];

    if (_syslog)
        ::syslog(level, "(%s) %s", ls, str);
    else
        fprintf(stderr, "(% 8s) %s\n", ls, str);
}

void log::printf(int level, const char *fmt, ...)
{
    char buf[256];
    va_list args;
    int ret;

    va_start(args, fmt);

    if (vsnprintf(buf, sizeof(buf), fmt, args) > 0) {
        puts(level, buf);
    }

    va_end(args);
}

void log::syslog(bool sl)
{
    if (sl == _syslog)
        return;

    if (_syslog = sl) {
#ifdef DEBUG
        setlogmask(LOG_UPTO(LOG_DEBUG));
        openlog("ndppd", LOG_CONS | LOG_NDELAY | LOG_PERROR | LOG_PID, LOG_USER);
#else
        setlogmask(LOG_UPTO(LOG_INFO));
        openlog("ndppd", LOG_CONS, LOG_USER);
#endif
    }
    else
    {
        closelog();
    }
}

__NDPPD_NS_END
