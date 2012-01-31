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

#include <sstream>

#ifndef DISABLE_SYSLOG
#   include <syslog.h>
#else
#   define LOG_EMERG   0   /* system is unusable */
#   define LOG_ALERT   1   /* action must be taken immediately */
#   define LOG_CRIT    2   /* critical conditions */
#   define LOG_ERR     3   /* error conditions */
#   define LOG_WARNING 4   /* warning conditions */
#   define LOG_NOTICE  5   /* normal but significant condition */
#   define LOG_INFO    6   /* informational */
#   define LOG_DEBUG   7   /* debug-level messages */
#endif


/*#define DBG(...) logger(logger::DEBUG)   << logger::F(__VA_ARGS__) << logger::endl;
#define ERR(...) logger(logger::ERROR)   << logger::F(__VA_ARGS__) << logger::endl;
#define WRN(...) logger(logger::WARNING) << logger::F(__VA_ARGS__) << logger::endl;
#define NFO(...) logger(logger::INFO)    << logger::F(__VA_ARGS__) << logger::endl;*/

/* LOG_ERR; LOG_WARNING; LOG_CRIT; LOG_INFO; LOG_NOTICE */

NDPPD_NS_BEGIN

class logger
{
public:
    logger(int pri = LOG_INFO);

    logger(const logger &l);

    ~logger();

    static std::string format(const std::string &fmt, ...);

    static void syslog(bool enable);
    static bool syslog();

    static void max_pri(int pri);

    void flush();

    static bool verbosity(const std::string &name);

    logger& operator<<(const std::string &str);
    logger& operator<<(logger &(*pf)(logger &));
    logger& operator<<(int n);

    logger& force_log(bool b = true);

    static logger& endl(logger &__l);

    // Shortcuts.

    static logger error();
    static logger info();
    static logger warning();
    static logger debug();

private:
    int _pri;

    std::stringstream _ss;

    bool _force_log;

    struct pri_name {
        const char *name;
        int pri;
    };

    static const pri_name _pri_names[];

    static bool _syslog;

    static int _max_pri;


};

NDPPD_NS_END
