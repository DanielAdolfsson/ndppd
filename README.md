# ndppd — NDP Proxy Daemon (0.2.x)

**ndppd** proxies IPv6 Neighbor Discovery between interfaces, so a prefix
routed on-link to your gateway is reachable by the machines actually
holding those addresses behind it.

This is the **`0.2.x` maintenance branch** — the original C++
implementation. It works, and it is what most distributions package.

> ### This branch is in maintenance
>
> `0.2.x` takes **critical fixes only**: crashes, memory errors and
> similar. It does not take features, and the behavioural limitations
> below are not being fixed here.
>
> All new development happens on **[`main`][main]**, which is a ground-up
> C99 rewrite — see its [README][mainreadme]. `master` no longer exists;
> it was where this branch was developed, and every commit it had is here,
> at the same SHA.
>
> Note that **configuration files are not portable between the two**. 1.0
> reorganised the configuration file, and several keywords below have no
> 1.0 equivalent.

[main]: https://github.com/DanielAdolfsson/ndppd/tree/main
[mainreadme]: https://github.com/DanielAdolfsson/ndppd/blob/main/README.md

---

## What problem this solves

Providers commonly route a prefix to a machine *on-link* rather than to a
next hop: the upstream router believes the whole `2001:db8::/48` is on the
segment it shares with you, so to reach `2001:db8:0:1::5` it puts a
neighbor solicitation on the wire and waits for someone to claim the
address. Nothing does — the address is on a bridge, a container or a VLAN
behind you, one hop further on. The traffic never arrives.

ndppd listens for those solicitations, works out whether the address really
is reachable behind it, and answers for it (RFC 4861 §7.2).

Linux can do a little of this itself with `proxy_ndp`, but only one address
at a time (`ip -6 neigh add proxy <ip> dev <if>`), it cannot list what it
is proxying, and it answers without checking whether anything is there.
ndppd works on prefixes and confirms the target first.

---

## Limitations

Most "ndppd isn't working" reports are one of these.

- **Linux only.** This branch reads `/proc/net/ipv6_route` and
  `/proc/net/if_inet6` and uses `AF_PACKET` and `SO_BINDTODEVICE`. There is
  no BSD support here — 1.0 has it, via `AF_ROUTE` and `/dev/bpf`.
- **Unicast NUD probes need `promiscuous yes`.** Once a neighbor entry
  exists, the upstream router refreshes it with a unicast NS sent straight
  to the proxy's MAC, and multicast is not involved. By default ndppd puts
  the interface into all-multicast but *not* promiscuous mode, so it never
  sees those frames: the entry goes STALE and then FAILED after twenty or
  thirty minutes of otherwise working traffic. **If your proxy works and
  then stops, set `promiscuous yes` first.** This is also why "it works
  while tcpdump is running" is such a common report — tcpdump enables
  promiscuous mode as a side effect. (1.0 enables it unconditionally.)
- **It does not route.** ndppd answers discovery; moving the packets
  afterwards is the kernel's job and needs a route and
  `net.ipv6.conf.all.forwarding=1`. ndppd sets neither for you.
- **It does not send router advertisements.** Downstream machines still
  need an RA daemon, or static addressing.
- **Ethernet only.** The packet path assumes a link-layer header and a
  hardware address, so `tun`, `wg` and other point-to-point devices do not
  work. ([#72][i72])
- **MLD snooping will defeat it.** A snooping switch forwards
  solicited-node multicast only to ports that have reported interest, and
  ndppd does not report interest in the addresses it proxies for.
  ([#55][i55])
- **Interfaces must exist at startup.** ndppd gives up on an interface it
  cannot resolve at config-load time, which at boot is a race against
  Docker and libvirt bridges. Order the unit after whatever creates them.
- **Advertisements are sent from a raw ICMPv6 socket**, so the kernel
  chooses their IPv6 source address — it is the proxy host's own address,
  not the target being advertised. Neighbor implementations key on the
  Target Address field and generally accept this, but a strict upstream may
  not. 1.0 builds the frame itself and sources it from the target.

[i55]: https://github.com/DanielAdolfsson/ndppd/issues/55
[i72]: https://github.com/DanielAdolfsson/ndppd/issues/72

---

## Building

Needs `g++` and GNU make. No external dependencies — libconfuse has not
been required since 0.2.2.

```sh
make all && sudo make install
```

`PREFIX` defaults to `/usr/local`; the binary installs to `${PREFIX}/sbin`
and the man pages to `${PREFIX}/share/man`. `DESTDIR` is honoured for
packaging.

```sh
make DEBUG=1 all      # unoptimised, with debug logging compiled in
```

On FreeBSD and other BSDs the base system's `make` reports *"Need an
operator"* on the first line — use `gmake`. Note that the daemon itself
still will not run there; see [Limitations](#limitations).

---

## Usage

```sh
ndppd [-d] [-c <config>] [-p <pidfile>] [-v...]
```

| Flag | Description |
|---|---|
| `-c <config>` | Configuration file. Default `/etc/ndppd.conf`. Long form `--config` |
| `-d` | Daemonize, and log to syslog instead of the terminal. Long form `--daemon` |
| `-p <pidfile>` | Write a pidfile at this location |
| `-v` | Increase verbosity. Repeat for more — `-v -v -v` is the useful level when something is wrong |

A systemd unit is shipped as `ndppd.service`.

ndppd must run as root, or at least with `CAP_NET_RAW` and `CAP_NET_ADMIN`.

---

## Configuration

Block syntax. Comments are `#` to end of line, or `/* ... */`.
`ndppd.conf-dist` is a complete annotated example, and `ndppd.conf(5)` has
the reference.

```nginx
# /etc/ndppd.conf

route-ttl   30000   # ms between reloads of /proc/net/ipv6_route
address-ttl 30000   # ms between reloads of /proc/net/if_inet6

proxy eth0 {        # the interface solicitations arrive on

    router yes      # set the Router flag in advertisements        (default yes)
    promiscuous no  # see the note in Limitations — you likely
                    # want this set to yes                         (default no)
    timeout 500     # ms to wait for an advertisement from the
                    # target before giving up on it                (default 500)
    ttl 30000       # ms an entry stays cached, valid or invalid    (default 30000)
    deadtime 30000  # ms a failed entry stays cached before it
                    # is retried                               (default = ttl)
    retries 3       # solicitations before declaring unreachable    (default 3)
    keepalive yes   # re-solicit before an entry expires           (default yes)
    autowire no     # add host routes from received advertisements  (default no)

    rule 2001:db8::/48 {
        auto        # — or: iface <if>, or: static. Exactly one.
        autovia no  # route via the advertising host rather than
                    # the interface; 'iface' rules only            (default no)
    }
}
```

### Choosing a rule mode

This is the decision people most often get wrong.

**`auto`** — look the target up in `/proc/net/ipv6_route` and solicit on
whichever interface the route points at. Use this unless you have a reason
not to.

**`iface <name>`** — always solicit on this interface. Use it when the
routing table will not tell the truth, or when you want `autowire` or
`autovia`, which only work here.

**`static`** — answer immediately, without soliciting anything. ndppd will
answer for *every* address in the prefix whether or not anything is there,
so a `static /64` claims eighteen quintillion addresses on your provider's
link. Correct only when you know exactly what is behind you; wrong, and
quietly so, the rest of the time. ndppd warns at startup if you use
`static` with a prefix of /120 or shorter.

> **Specifying no mode at all means `static`.** That is a compatibility
> behaviour kept from before 0.2.2, and it is almost never what someone
> leaving the mode out actually wanted. Always state the mode.

---

## Examples

### A delegated prefix behind a LAN

```nginx
proxy eth0 {
    promiscuous yes

    rule 2001:db8:1234:5600::/56 {
        auto
    }
}
```

### A bridge, with host routes injected from advertisements

```nginx
proxy eth0 {
    promiscuous yes
    autowire yes

    rule 2001:db8::/48 {
        iface br0
        autovia yes
    }
}
```

`autowire` adds a host route when an advertisement arrives on `br0` and
removes it when the entry expires. It applies to `iface` rules only — with
`auto` and `static`, the routes are expected to exist already.

---

## Upgrading to 1.0

1.0 is on [`main`][main]. It is a rewrite, not a continuation, and the
configuration file changed with it:

These are the nearest 1.0 equivalents, not exact translations — the
session state machine was rewritten, so the timers do not map one to one:

| 0.2.x | Nearest 1.0 equivalent |
|---|---|
| `timeout` | `retrans-time` |
| `retries` | `retrans-limit` |
| `ttl`, `deadtime` | `valid-ttl`, `invalid-ttl` |
| `promiscuous` | always on, no keyword |
| `route-ttl`, `address-ttl` | gone — routes are tracked over Netlink |
| `autovia` | gone |
| `autowire` | per-rule rather than per-proxy, with an optional `table` |
| `rule` modes `auto` / `iface` / `static` | unchanged in meaning |

1.0 **rejects** an unknown keyword rather than ignoring it, so a 0.2.x file
will not load — you will get a parse error naming a line and column. Start
from [1.0's README][mainreadme] rather than adapting this one.

---

## Reporting bugs

Open an issue. For this branch, please confirm the problem is a crash or
memory error — anything else is likely to be closed with a pointer to 1.0,
not because the report is wrong but because this branch is not where such
things get fixed.

A `-v -v -v` log and the output of `ip -6 route` and `ip -6 addr` are
almost always what gets asked for first.

---

## Credits and license

ndppd is by Daniel Adolfsson <daniel@ashen.se>.

GNU General Public License v3 or later.
Copyright © 2011–2026 Daniel Adolfsson.

The historical 0.2.5 plain-text documentation is preserved as
[`README`](README) alongside this file.
