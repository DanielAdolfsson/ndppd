# NDPPD

This is the development branch for version 1.0 of *ndppd*.

Please read the manpages [ndppd.conf.5](ndppd.conf.5.adoc) and [ndppd.8](ndppd.8.adoc). 

## Status

***ndppd*** was rewritten from scratch using C (C99).

It's currently **highly experimental**, but I expect a beta to be ready by the end of the year.

## Description

***ndppd***, or ***NDP Proxy Daemon***, is a daemon that proxies *neighbor discovery* messages. It listens for *neighbor solicitations* on a
specified interface and responds with *neighbor advertisements* - as described in **RFC 4861** (section 7.2). 

There are several methods available when determining of a *neighbor advertisement* should be sent back:

The first method, and the most common, is the ***autoresolve*** method. It uses the routing table to determine how the target is reachable.
If a valid route exists, a *neighbor solicitation* is sent out through that interface. Only once ***ndppd*** receives a *neighbor advertisement*
from the target will it start responding to *neighbor solicitations*. 

The second method is the ***explicit*** method. A *neighbor solicitation* is sent through a manually provided interface. This
method also allows for the use of ***autowire*** which sets up a route to the specified target through said interface *if the target was found, and for the
duration of the session*.

The third method is the ***static*** method. When used, ***ndppd*** will immediately respond to *neighbor solicitation* messages immediately
without first querying an internal interface.

## Compiling

You must have *asciidoctor* installed in order to transpile the documentation.

In most cases, the following should be sufficient:

    make all && make install

## Contact

Daniel Adolfsson <daniel-at-ashen.se>  
https://github.com/DanielAdolfsson/ndppd
