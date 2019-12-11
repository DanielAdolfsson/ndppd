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
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef NDPPD_NO_USE_EPOLL
#    include <fcntl.h>
#    include <sys/epoll.h>
#else
#    include <poll.h>
#    include <stdlib.h>
#    ifdef EPOLLIN
#        undef EPOLLIN
#    endif
#    define EPOLLIN POLLIN
#endif

#include "io.h"
#include "ndppd.h"

static nd_io_t *ndL_first_io, *ndL_first_free_io;

#ifndef NDPPD_NO_USE_EPOLL
static int ndL_epoll_fd;
#else
#    ifndef NDPPD_STATIC_POLLFDS_SIZE
#        define NDPPD_STATIC_POLLFDS_SIZE 8
#    endif

static struct pollfd static_pollfds[NDPPD_STATIC_POLLFDS_SIZE];
static struct pollfd *pollfds = static_pollfds;
static int pollfds_size = NDPPD_STATIC_POLLFDS_SIZE;
static int pollfds_count = 0;
static bool ndL_dirty;

static void ndL_refresh_pollfds()
{
    int count;

    ND_LL_COUNT(ndL_first_sio, count, next);

    if (count > pollfds_size)
    {
        int new_pollfds_size = count * 2;

        pollfds = (struct pollfd *)realloc(pollfds == static_pollfds ? NULL : pollfds,
                                           new_pollfds_size * sizeof(struct pollfd));

        /* TODO: Validate return value */

        pollfds_size = new_pollfds_size;
    }

    int index = 0;

    ND_LL_FOREACH(ndL_first_sio, sio, next)
    {
        pollfds[index].fd = io->fd;
        pollfds[index].revents = 0;
        pollfds[index].events = POLLIN;
        index++;
    }

    pollfds_count = index;
}
#endif

nd_io_t *nd_sio_create(int fd)
{
    nd_io_t *io = ndL_first_free_io;

    if (io)
        ND_LL_DELETE(ndL_first_free_io, io, next);
    else
        io = ND_ALLOC(nd_io_t);

    ND_LL_PREPEND(ndL_first_io, io, next);

    io->fd = fd;
    io->data = 0;
    io->handler = NULL;

    return io;
}

static nd_io_t *ndL_create(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);

    if (flags == -1)
    {
        nd_log_error("Could not read flags: %s", strerror(errno));
        close(fd);
        return false;
    }

    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
    {
        nd_log_error("Could not set flags: %s", strerror(errno));
        close(fd);
        return false;
    }

    nd_io_t *io = ndL_first_free_io;

    if (io)
        ND_LL_DELETE(ndL_first_free_io, io, next);
    else
        io = ND_ALLOC(nd_io_t);

    ND_LL_PREPEND(ndL_first_io, io, next);

    io->fd = fd;
    io->data = 0;
    io->handler = NULL;

#ifndef NDPPD_NO_USE_EPOLL
    if (ndL_epoll_fd <= 0 && (ndL_epoll_fd = epoll_create(1)) < 0)
    {
        nd_log_error("epoll_create() failed: %s", strerror(errno));
        return NULL;
    }

    struct epoll_event event = { .events = EPOLLIN, .data.ptr = io };

    if (epoll_ctl(ndL_epoll_fd, EPOLL_CTL_ADD, io->fd, &event) < 0)
    {
        nd_log_error("epoll_ctl() failed: %s", strerror(errno));
        return NULL;
    }
#else
    /* Make sure our pollfd array is updated. */
    ndL_dirty = true;
#endif

    return io;
}

nd_io_t *nd_io_socket(int domain, int type, int protocol)
{
    int fd = socket(domain, type, protocol);

    if (fd == -1)
    {
        nd_log_error("nd_io_socket(): Could not create socket: %s", strerror(errno));
        return NULL;
    }

    return ndL_create(fd);
}

nd_io_t *nd_io_open(const char *file, int oflag)
{
    int fd = open(file, oflag);

    if (fd == -1)
        return NULL;

    return ndL_create(fd);
}

void nd_io_close(nd_io_t *io)
{
    close(io->fd);

#ifdef NDPPD_NO_USE_EPOLL
    ndL_dirty = true;
#endif

    ND_LL_DELETE(ndL_first_io, io, next);
    ND_LL_PREPEND(ndL_first_free_io, io, next);
}

ssize_t nd_io_send(nd_io_t *io, const struct sockaddr *addr, size_t addrlen, const void *msg, size_t msglen)
{
    struct iovec iov;
    iov.iov_len = msglen;
    iov.iov_base = (caddr_t)msg;

    struct msghdr mhdr;
    memset(&mhdr, 0, sizeof(mhdr));
    mhdr.msg_name = (caddr_t)addr, mhdr.msg_namelen = addrlen;
    mhdr.msg_iov = &iov;
    mhdr.msg_iovlen = 1;

    ssize_t len;

    if ((len = sendmsg(io->fd, &mhdr, 0)) < 0)
    {
        printf("send err %s\n", strerror(errno));
        return -1;
    }

    return len;
}

ssize_t nd_io_recv(nd_io_t *io, struct sockaddr *addr, size_t addrlen, void *msg, size_t msglen)
{
    struct iovec iov;
    iov.iov_len = msglen;
    iov.iov_base = (caddr_t)msg;

    struct msghdr mhdr;
    memset(&mhdr, 0, sizeof(mhdr));
    mhdr.msg_name = (caddr_t)addr;
    mhdr.msg_namelen = addrlen;
    mhdr.msg_iov = &iov;
    mhdr.msg_iovlen = 1;

    int len;

    if ((len = recvmsg(io->fd, &mhdr, 0)) < 0)
    {
        if (errno != EAGAIN)
            nd_log_error("nd_sio_recv() failed: %s", strerror(errno));

        return -1;
    }

    return len;
}

bool nd_io_bind(nd_io_t *io, const struct sockaddr *addr, size_t addrlen)
{
    return bind(io->fd, addr, addrlen) == 0;
}

bool nd_io_poll()
{
#ifndef NDPPD_NO_USE_EPOLL
    struct epoll_event events[8];

    int count = epoll_wait(ndL_epoll_fd, events, 8, 250);

    if (count < 0)
    {
        nd_log_error("epoll() failed: %s", strerror(errno));
        return false;
    }

    for (int i = 0; i < count; i++)
    {
        nd_io_t *io = (nd_io_t *)events[i].data.ptr;

        if (io->handler)
            io->handler(io, events[i].events);
    }

#else
    if (ndL_dirty)
    {
        ndL_refresh_pollfds();
        ndL_dirty = false;
    }

    int len = poll(pollfds, pollfds_count, 250);

    if (len < 0)
        return false;

    if (len == 0)
        return true;

    for (int i = 0; i < pollfds_count; i++)
    {
        if (pollfds[i].revents == 0)
            continue;

        for (nd_sio_t *sio = ndL_first_sio; sio; sio = io->next)
        {
            if (io->fd == pollfds[i].fd)
            {
                if (io->handler != NULL)
                    io->handler(sio, pollfds[i].revents);

                break;
            }
        }
    }
#endif

    return true;
}

void nd_io_cleanup()
{
    ND_LL_FOREACH_S(ndL_first_io, sio, tmp, next)
    {
        nd_io_close(sio);
    }

#ifndef NDPPD_NO_USE_EPOLL
    if (ndL_epoll_fd > 0)
    {
        close(ndL_epoll_fd);
        ndL_epoll_fd = 0;
    }
#endif
}
