# NDPPD

***ndppd***, or ***NDP Proxy Daemon***, is a daemon that proxies *neighbor discovery* messages. It listens for *neighbor solicitations* on a
specified interface and responds with *neighbor advertisements* - as described in **RFC 4861** (section 7.2). 

## Current status

Version 0.x is in maintenance, and is being replaced by `1.0-devel` which you can find [here](https://github.com/DanielAdolfsson/ndppd/tree/1.0-devel). `1.0` is not yet stable enough to be used in production, and I currently have no estimate when it is. Feel free to try it out if you like.

Latest stable release is 0.2.5:
- [Download](https://github.com/DanielAdolfsson/ndppd/releases/tag/0.2.5)
- [README](https://github.com/DanielAdolfsson/ndppd/blob/0.2.5/README)
