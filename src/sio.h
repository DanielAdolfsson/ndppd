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
#ifndef NDPPD_SIO_H
#define NDPPD_SIO_H

#include "ndppd.h"

typedef void(nd_sio_handler_t)(nd_sio_t *sio, int events);

struct nd_sio
{
    nd_sio_t *next;
    int fd;
    uintptr_t data;
    nd_sio_handler_t *handler;
};

/* sio.c */
nd_sio_t *nd_sio_open(int domain, int type, int protocol);
void nd_sio_close(nd_sio_t *nio);
bool nd_sio_bind(nd_sio_t *sio, const struct sockaddr *addr, size_t addrlen);
ssize_t nd_sio_send(nd_sio_t *sio, const struct sockaddr *addr, size_t addrlen, const void *msg, size_t msglen);
ssize_t nd_sio_recv(nd_sio_t *sio, struct sockaddr *addr, size_t addrlen, void *msg, size_t msglen);
bool nd_sio_poll();
void nd_sio_cleanup();

#endif /* NDPPD_SIO_H */
