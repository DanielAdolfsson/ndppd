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
#    include <sys/epoll.h>
#else
#    include <poll.h>
#    include <stdlib.h>
#    ifdef EPOLLIN
#        undef EPOLLIN
#    endif
#    define EPOLLIN POLLIN
#endif

#include "ndppd.h"
#include "sio.h"

static nd_sio_t *ndL_first_sio, *ndL_first_free_sio;

#ifndef NDPPD_NO_USE_EPOLL
static int ndL_epoll_fd;
#else
#    ifndef NDPPD_STATIC_POLLFDS_SIZE
#        define NDPPD_STATIC_POLLFDS_SIZE 32
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
        pollfds[index].fd = sio->fd;
        pollfds[index].revents = 0;
        pollfds[index].events = POLLIN;
        index++;
    }

    pollfds_count = index;
}
#endif

nd_sio_t *nd_sio_open(int domain, int type, int protocol)
{
    int fd = socket(domain, type, protocol);

    if (fd < 0)
        return NULL;

    /* Non-blocking. */

    int on = 1;
    if (ioctl(fd, FIONBIO, (char *)&on) < 0)
    {
        close(fd);
        return NULL;
    }

    /* Allocate the nd_sio_t object. */

    nd_sio_t *sio = ndL_first_free_sio;

    if (sio)
        ND_LL_DELETE(ndL_first_free_sio, sio, next);
    else
        sio = ND_ALLOC(nd_sio_t);

    ND_LL_PREPEND(ndL_first_sio, sio, next);

    sio->fd = fd;

#ifndef NDPPD_NO_USE_EPOLL
    if (ndL_epoll_fd <= 0 && (ndL_epoll_fd = epoll_create(1)) < 0)
    {
        nd_log_error("epoll_create() failed: %s", strerror(errno));
        nd_sio_close(sio);
        return NULL;
    }

    struct epoll_event event = { .events = EPOLLIN, .data.ptr = sio };

    if (epoll_ctl(ndL_epoll_fd, EPOLL_CTL_ADD, fd, &event) < 0)
    {
        nd_log_error("epoll_ctl() failed: %s", strerror(errno));
        nd_sio_close(sio);
        return NULL;
    }

#else
    /* Make sure our pollfd array is updated. */
    ndL_dirty = true;
#endif

    return sio;
}

void nd_sio_close(nd_sio_t *sio)
{
    close(sio->fd);

#ifdef NDPPD_NO_USE_EPOLL
    ndL_dirty = true;
#endif

    ND_LL_DELETE(ndL_first_sio, sio, next);
    ND_LL_PREPEND(ndL_first_free_sio, sio, next);
}

ssize_t nd_sio_send(nd_sio_t *sio, const struct sockaddr *addr, size_t addrlen, const void *msg, size_t msglen)
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

    if ((len = sendmsg(sio->fd, &mhdr, 0)) < 0)
    {
        printf("send err %s\n", strerror(errno));
        return -1;
    }

    return len;
}

ssize_t nd_sio_recv(nd_sio_t *sio, struct sockaddr *addr, size_t addrlen, void *msg, size_t msglen)
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

    if ((len = recvmsg(sio->fd, &mhdr, 0)) < 0)
    {
        if (errno != EAGAIN)
            nd_log_error("nd_sio_recv() failed: %s", strerror(errno));

        return -1;
    }

    return len;
}

bool nd_sio_bind(nd_sio_t *sio, const struct sockaddr *addr, size_t addrlen)
{
    return bind(sio->fd, addr, addrlen) == 0;
}

bool nd_sio_poll()
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
        nd_sio_t *sio = (nd_sio_t *)events[i].data.ptr;

        if (sio->handler)
            sio->handler(sio, events[i].events);
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

        for (nd_sio_t *sio = ndL_first_sio; sio; sio = sio->next)
        {
            if (sio->fd == pollfds[i].fd)
            {
                if (sio->handler != NULL)
                    sio->handler(sio, pollfds[i].revents);

                break;
            }
        }
    }
#endif

    return true;
}

void nd_sio_cleanup()
{
    ND_LL_FOREACH_S(ndL_first_sio, sio, tmp, next)
    {
        nd_sio_close(sio);
    }

    if (ndL_epoll_fd > 0)
    {
        close(ndL_epoll_fd);
        ndL_epoll_fd = 0;
    }
}
