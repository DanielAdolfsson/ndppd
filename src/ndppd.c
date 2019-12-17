/*
 * This file is part of ndppd.
 *
 * Copyright (C) 2011-2019  Daniel Adolfsson <daniel@ashen.se>
 *
 * ndppd is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * ndppd is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with ndppd.  If not, see <https://www.gnu.org/licenses/>.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdint.h>
/**/
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#ifdef __linux__
#    include <sched.h>
#endif

#include "addr.h"
#include "conf.h"
#include "iface.h"
#include "io.h"
#include "ndppd.h"
#include "proxy.h"
#include "rt.h"

#ifndef NDPPD_CONFIG_PATH
#    define NDPPD_CONFIG_PATH "../ndppd.conf"
#endif

long nd_current_time;
bool nd_daemonized;

bool nd_opt_daemonize;
char *nd_opt_config_path;
char *nd_opt_pidfile_path;

static bool ndL_check_pidfile()
{
    int fd = open(nd_opt_pidfile_path, O_RDWR);

    if (fd == -1) {
        if (errno == ENOENT) {
            return true;
        }

        return false;
    }

    bool result = flock(fd, LOCK_EX | LOCK_NB) == 0;
    close(fd);
    return result;
}

static bool ndL_daemonize()
{
    int fd = open(nd_opt_pidfile_path, O_WRONLY | O_CREAT, 0644);

    if (fd == -1) {
        return false;
    }

    if (flock(fd, LOCK_EX | LOCK_NB) < 0) {
        close(fd);
        return false;
    }

    pid_t pid = fork();

    if (pid < 0) {
        // logger::error() << "Failed to fork during daemonize: " << logger::err();
        return false;
    }

    if (pid > 0) {
        char buf[21];
        int len = snprintf(buf, sizeof(buf), "%d", pid);

        if (ftruncate(fd, 0) == -1) {
            nd_log_error("Failed to write PID file: ftruncate(): %s", strerror(errno));
        } else if (write(fd, buf, len) != 0) {
            nd_log_error("Failed to write PID file: write(): %s", strerror(errno));
        }

        nd_iface_no_restore_flags = true;
        exit(0);
    }

    umask(0);

    pid_t sid = setsid();
    if (sid < 0) {
        // logger::error() << "Failed to setsid during daemonize: " << logger::err();
        return false;
    }

    if (chdir("/") < 0) {
        // logger::error() << "Failed to change path during daemonize: " << logger::err();
        return false;
    }

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    return true;
}

static void ndL_exit()
{
    nd_iface_cleanup();
    nd_rt_cleanup();
    nd_alloc_cleanup();
}

static void ndL_sig_exit(__attribute__((unused)) int sig)
{
    exit(0);
}

#ifdef __linux__
__attribute__((unused)) static bool ndL_netns(const char *name)
{
    char net_path[128];
    snprintf(net_path, sizeof(net_path), "/var/run/netns/%s", name);

    int fd = open(net_path, O_RDONLY | O_CLOEXEC);

    if (fd < 0) {
        nd_log_error("Cannot open network namespace \"%s\": %s\n", name, strerror(errno));
        return false;
    }

    if (setns(fd, CLONE_NEWNET) < 0) {
        nd_log_error("Could not set network namespace \"%s\": %s\n", name, strerror(errno));
        close(fd);
        return false;
    }

    close(fd);
    return true;
}
#endif

int main(int argc, char *argv[])
{
    atexit(ndL_exit);
    signal(SIGINT, ndL_sig_exit);
    signal(SIGTERM, ndL_sig_exit);

#ifdef __linux__
    char *netns = NULL;
#endif

    static struct option long_options[] = {
        { "config", 1, 0, 'c' },  //
        { "daemon", 0, 0, 'd' },  //
        { "verbose", 0, 0, 'v' }, //
        { "syslog", 0, 0, 1 },    //
        { "pidfile", 1, 0, 'p' }, //
#ifdef __linux__
        { "netns", 1, 0, 2 },
#endif
        { NULL, 0, 0, 0 },
    };

    for (int ch; (ch = getopt_long(argc, argv, "c:dp:v", long_options, NULL)) != -1;) {
        switch (ch) {
        case 'c':
            nd_opt_config_path = nd_strdup(optarg);
            break;

        case 'd':
            nd_opt_daemonize = true;
            break;

        case 'v':
            if (nd_opt_verbosity < ND_LOG_ERROR) {
                nd_opt_verbosity++;
            }
            break;

        case 'p':
            nd_opt_pidfile_path = nd_strdup(optarg);
            break;

        case 1:
            nd_opt_syslog = true;
            break;

#ifdef __linux__
        case 2:
            if (netns) {
                fprintf(stderr, "--netns can only be specified once");
                return -1;
            }
            netns = nd_strdup(optarg);
            break;
#endif

        default:
            break;
        }
    }

    struct timeval t1;
    gettimeofday(&t1, 0);
    nd_current_time = t1.tv_sec * 1000 + t1.tv_usec / 1000;

    nd_log_info("ndppd " NDPPD_VERSION);

    if (nd_opt_pidfile_path && !ndL_check_pidfile()) {
        nd_log_error("Failed to lock pidfile. Is ndppd already running?");
        return -1;
    }

    if (nd_opt_config_path == NULL) {
        nd_opt_config_path = NDPPD_CONFIG_PATH;
    }

    nd_log_info("Loading configuration \"%s\"...", nd_opt_config_path);

    if (!nd_conf_load(nd_opt_config_path)) {
        return -1;
    }

#ifdef __linux__
    if (netns && !ndL_netns(netns)) {
        return -1;
    }
#endif

    if (!nd_iface_startup()) {
        return -1;
    }

    if (!nd_proxy_startup()) {
        return -1;
    }

    if (!nd_rt_open()) {
        return -1;
    }

    if (nd_opt_daemonize && !ndL_daemonize()) {
        return -1;
    }

    nd_rt_query_routes();
    bool querying_routes = true;

    while (1) {
        if (nd_current_time >= nd_rt_dump_timeout) {
            nd_rt_dump_timeout = 0;
        }

        if (querying_routes && !nd_rt_dump_timeout) {
            querying_routes = false;
            nl_rt_remove_owned_routes();
            nd_rt_query_addresses();
        }

        if (!nd_io_poll()) {
            /* TODO: Error */
            break;
        }

        nd_proxy_update_all();

        gettimeofday(&t1, 0);
        nd_current_time = t1.tv_sec * 1000 + t1.tv_usec / 1000;
    }

    return 0;
}
