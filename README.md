# NDPPD

This is the development branch for version 1.0 of *ndppd*.

It's currently barely usable, but I hope to be able to have a beta ready before the end of the year.

Please read the manpages [ndppd.conf.5](ndppd.conf.5.adoc) and [ndppd.8](ndppd.8.adoc). 

## To do

### In progress

- [x] EPOLL support
- [x] rtnetlink: Tracking routes
- [x] rtnetlink: Tracking local addresses
- [ ] rtnetlink: Memory cleanup
- [ ] rtnetlink: Managing routes
- [x] Automatic detection of internal interfaces (auto)
- [ ] Automatically managing routes (autowire)
- [x] IPv6/ICMPv6 packet validation
- [ ] Reloading through SIGHUP
- [x] Configuration engine
- [x] Forwarding of Neighbor Solicitation messages
- [x] Forwarding of Neighbor Advertisement messages
- [x] Daemonization
- [x] Locking pidfiles
- [x] Syslog
- [x] Custom memory management (*nd_alloc*)
- [x] Refreshing and expiring sessions
- [x] Set and restore PROMISC and ALLMULTI

### Undecided
- [ ] Control socket
- [ ] Cleaning up pidfiles
