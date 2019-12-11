# NDPPD

Please read the manpages [ndppd.conf.5](ndppd.conf.5.adoc) and [ndppd.8](ndppd.8.adoc). 

## To do

### In progress

- [x] EPOLL support
- [x] rtnetlink: Tracking routes
- [x] rtnetlink: Tracking local addresses
- [ ] rtnetlink: Memory cleanup
- [ ] rtnetlink: Managing routes
- [x] Automatic detection of internal interfaces (auto)
- [ ] Automatically managing routes (autowire/autovia)
- [x] IPv6/ICMPv6 packet validation
- [ ] Reloading through SIGHUP
- [x] Configuration engine
- [x] Forwarding of Neighbor Solicitation messages
- [x] Forwarding of Neighbor Advertisement messages
- [x] Daemonization
- [x] Locking pidfiles
- [x] Syslog
- [x] Custom memory management (*nd_alloc*)
- [ ] Expiration of nd_neigh_t objects
- [ ] Refreshing nd_neigh_t if needed
- [x] Set and restore PROMISC and ALLMULTI

### Undecided
- [ ] Control socket
- [ ] Cleaning up pidfiles
