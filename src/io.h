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
#ifndef NDPPD_IO_H
#define NDPPD_IO_H

#include "ndppd.h"

typedef void(nd_io_handler_t)(nd_io_t *io, int events);

struct nd_io
{
    nd_io_t *next;
    int fd;
    uintptr_t data;
    nd_io_handler_t *handler;
};

nd_io_t *nd_io_socket(int domain, int type, int protocol);
nd_io_t *nd_io_open(const char *file, int oflag);
void nd_io_close(nd_io_t *io);
bool nd_io_bind(nd_io_t *io, const struct sockaddr *addr, size_t addrlen);
ssize_t nd_io_send(nd_io_t *io, const struct sockaddr *addr, size_t addrlen, const void *msg, size_t msglen);
ssize_t nd_io_recv(nd_io_t *io, struct sockaddr *addr, size_t addrlen, void *msg, size_t msglen);
bool nd_io_poll();
void nd_io_cleanup();

#endif /*NDPPD_IO_H*/
