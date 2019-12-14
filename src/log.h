// This file is part of ndppd.
//
// Copyright (C) 2011-2019  Daniel Adolfsson <daniel@ashen.se>
//
// ndppd is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// ndppd is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with ndppd.  If not, see <https://www.gnu.org/licenses/>.
#ifndef NDPPD_LOG_H
#define NDPPD_LOG_H

#include <stdbool.h>

typedef enum
{
    ND_LOG_ERROR,
    ND_LOG_INFO,
    ND_LOG_DEBUG,
    ND_LOG_TRACE
} nd_loglevel_t;

extern nd_loglevel_t nd_opt_verbosity;
extern bool nd_opt_syslog;

void nd_log_printf(nd_loglevel_t level, const char *fmt, ...);

#ifdef NDPPD_NO_TRACE
#    define nd_log_trace(fmt, ...) (void)
#else
#    define nd_log_trace(fmt, ...) nd_log_printf(ND_LOG_TRACE, fmt, ##__VA_ARGS__)
#endif

#define nd_log_error(fmt, ...) nd_log_printf(ND_LOG_ERROR, fmt, ##__VA_ARGS__)
#define nd_log_info(fmt, ...) nd_log_printf(ND_LOG_INFO, fmt, ##__VA_ARGS__)
#define nd_log_debug(fmt, ...) nd_log_printf(ND_LOG_DEBUG, fmt, ##__VA_ARGS__)

#endif // NDPPD_LOG_H
