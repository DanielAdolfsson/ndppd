# ndppd — NDP Proxy Daemon

**ndppd** proxies IPv6 Neighbor Discovery between interfaces, so a prefix
routed on-link to your gateway is reachable by the machines actually
holding those addresses behind it.

This is the `1.0-devel` branch: a ground-up C99 rewrite with a corrected
session state machine, promiscuous-mode packet capture and strict RFC 4861
compliance. The 0.2.x C++ implementation lives on `master`.

## Status

**1.0-beta1.** Running in production, and under active work again.

The rewrite sat untouched from June 2020 until 2026, when **[totoCZ][toto]**
took it into production behind a Juniper switch, found everything that was
wrong with it, and fixed it — ten commits covering promiscuous reception,
the solicited-node multicast MAC, unicast NUD probes without a source
link-layer option, four separate RFC 4861 compliance bugs in the NS/NA
path, two more in the BSD packet path, the session state machine's handling
of STALE and of late-arriving routes, and a fork-time bug that silently
left the daemon unable to see the packets it exists to answer. That work is
[#93][pr93], and it is why this branch is worth finishing rather than
abandoning.

It has since gained a test suite — 228 unit and 55 integration assertions —
and the fixes that suite turned up. See [test/README.md](test/README.md).

What is not yet done is listed under [Limitations](#limitations). If you
are deploying this, read that section first.

[toto]: https://github.com/totoCZ
[pr93]: https://github.com/DanielAdolfsson/ndppd/pull/93

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

### Why not the kernel's `proxy_ndp`

| | Kernel `proxy_ndp` | 0.2.x | This rewrite |
|---|---|---|---|
| Prefix rules | ❌ one entry per address | ✅ | ✅ |
| Probes before replying | ❌ replies blindly | ✅ | ✅ |
| Sees unicast NUD probes | ❌ multicast only | ❌ all-multicast socket | ✅ promiscuous |
| Routing table integration | ❌ | ✅ Netlink / AF_ROUTE | ✅ |
| RFC 4861 conformance | partial | ⚠️ DAD and STALE bugs | ✅ |

**The unicast NUD problem.** Once a neighbor entry exists, the upstream
router refreshes it with a unicast NS sent straight to the proxy's MAC —
multicast is not involved. Neither the kernel proxy nor 0.2.x saw those
frames, so the entry went STALE and then FAILED every twenty or thirty
minutes under sustained traffic, and recovered only when something put the
link back into multicast. This is also why "it works while tcpdump is
running" is such a common report: tcpdump sets promiscuous mode as a side
effect. ndppd sets it on purpose.

---

## Limitations

Most "ndppd isn't working" reports are one of these. None of them is a bug.

- **It does not route.** ndppd answers discovery; moving packets afterwards
  is the kernel's job and needs a route and
  `net.ipv6.conf.all.forwarding=1`. ndppd will not set either for you.
- **It does not send router advertisements.** Downstream machines still
  need an RA daemon, or static addressing.
- **It is not a substitute for the kernel's neighbour table on its own
  host.** ndppd reads packets from an `AF_PACKET` socket, which does not
  see discovery the local stack generates for local delivery.
- **Ethernet only.** The packet path assumes a link-layer header and a
  hardware address, so `tun`, `wg` and other point-to-point devices do not
  work. ([#72][i72])
- **MLD snooping will defeat it.** A snooping switch forwards
  solicited-node multicast only to ports that have reported interest, and
  ndppd does not report interest in the addresses it proxies for.
  ([#55][i55])
- **Interfaces must exist at startup.** ndppd exits if a configured
  interface is missing, which at boot is a race against Docker and libvirt
  bridges. ([#79][i79])

[i55]: https://github.com/DanielAdolfsson/ndppd/issues/55
[i72]: https://github.com/DanielAdolfsson/ndppd/issues/72
[i79]: https://github.com/DanielAdolfsson/ndppd/issues/79

---

## Building

```sh
make && sudo make install
```

The man pages are built with [Asciidoctor][adoc]; `make ndppd` builds only
the binary if you would rather not install it.

On FreeBSD and other BSDs the Makefile needs GNU make — `gmake`. The base
system's `make` reports *"Need an operator"* on the first line.

[adoc]: https://asciidoctor.org

---

## Usage

```sh
ndppd -c /etc/ndppd.conf [-d] [-v...] [-p pidfile] [--syslog] [--netns <name>]
```

| Flag | Description |
|---|---|
| `-c /path` | Configuration file |
| `-d` | Daemonize |
| `-p /path` | PID file, held under an exclusive `flock` so a second instance refuses to start |
| `--syslog` | Log to syslog even in the foreground |
| `-v`, `-vv` | Debug, then trace. The default is info |
| `--netns <name>` | *(Linux)* Enter a named network namespace before binding anything |

ndppd logs with `printf`, so with stdout redirected to a file the C library
buffers it. Use `stdbuf -oL` if you want to watch the log live.

A systemd unit is shipped as `ndppd.service`; edit its `ExecStart` to point
at your configuration file.

---

## Configuration

Block syntax. Comments are `#` to end of line, or `/* ... */`.
`ndppd.conf-dist` is a complete annotated example.

```nginx
# /etc/ndppd.conf

valid-ttl   30000   # ms to keep a VALID session after the last NA from the target
invalid-ttl 10000   # ms to cache a failed session — absorbs NS floods
retrans-time 1000   # ms between outgoing NS probes
retrans-limit   3   # probes before giving up
keepalive      no   # yes = keep probing STALE sessions with no upstream NS

proxy eth0 {        # the interface solicitations arrive on
    router no       # set the Router flag in NAs — yes if the proxied
                    # targets are themselves routers, e.g. downstream CPE
    target <mac>    # advertise this MAC instead of eth0's, for every rule

    rule 2001:db8::/48 {
        auto        # — or: iface <if>, or: static. Exactly one.
        table 254   # routing table to consult (Linux only)
        autowire    # add a /128 host route while the session lives (iface only)
        target <mac>        # per-rule MAC override
        rewrite fd00::/48   # solicit a different prefix than the one advertised
    }
}
```

### Choosing a rule mode

This is the decision people most often get wrong.

**`auto`** — find the downstream interface in the routing table. Use this
unless you have a reason not to. It survives an interface being renamed,
and it picks up a route that appears after ndppd started, which is what
makes it right for containers and VMs that come and go.

**`iface <name>`** — always solicit on this interface. Use it when the
routing table will not tell the truth, or when you want `autowire`.

**`static`** — answer immediately, without soliciting anything. ndppd will
answer for *every* address in the prefix whether or not anything is there,
so a `static /64` claims eighteen quintillion addresses on your provider's
link. Correct only when you know what is behind you and want to skip the
probe round-trip; wrong, and quietly so, the rest of the time.

### `rewrite`

Advertise one prefix upstream while soliciting a different one downstream —
a public prefix in front of ULAs:

```nginx
proxy eth0 {
    rule 2001:db8:a::/48 {
        iface eth1
        rewrite fd00::/48
    }
}
```

A solicitation for `2001:db8:a::1` probes `fd00::1` on `eth1`, and the
public address is what goes back upstream. The internal address is never
advertised. ndppd rewrites the *discovery* only — translating the traffic
afterwards is still yours to arrange.

---

## Session state machine

One session per (target, proxy) pair. The STALE timeout is fixed at 30 s.

```
 [new NS] ──────────────────► INCOMPLETE ──── NA received ───► VALID
                                   │                              │
                          retrans-limit                        valid-ttl
                            exceeded │                            │
                                     ▼                            ▼
                                  INVALID ◄──── 30 s ────── STALE
                                     │
                               invalid-ttl
                                     │
                                     ▼
                                 (deleted)
```

- **INCOMPLETE** — probing downstream, retransmitting every `retrans-time`
  up to `retrans-limit` times. Upstream solicitations are queued, not
  answered: an answer here would be a claim ndppd cannot back up.
- **VALID** — upstream solicitations are answered immediately. An
  unsolicited NA from the target extends the lifetime (§7.2.5).
- **STALE** — reachability is unknown (§7.3.3), so a fresh solicitation
  triggers a new probe rather than an immediate answer. The retransmit
  interval doubles every `retrans-limit` probes.
- **INVALID** — queued subscribers are kept, so a late NA still satisfies
  all of them. In `auto` mode an incoming NS re-checks the routing table,
  which is what lets a container that starts after the first solicitation
  still be reached.

A **static** session has no downstream target to confirm, so none of this
applies to it: it answers from configuration in any state, and ages out
only to stop the table growing for every address ever solicited.

---

## Examples

### A delegated prefix behind a LAN

```nginx
proxy wan0 {
    rule 2001:db8:1234:5600::/56 {
        auto
    }
}
```

### Containers, with per-host route injection

```nginx
proxy eth0 {
    rule 2001:db8::/48 {
        iface br0
        autowire
        table 100
    }
}
```

`autowire` adds a `/128` through `br0` for as long as the session lives and
removes it when the session expires.

---

## Tests

```sh
make check
```

228 unit assertions and 55 integration assertions, both layers emitting
TAP 13. The integration suite runs a real daemon across three network
namespaces and needs no root. [test/README.md](test/README.md) has the
detail.

---

## Credits

ndppd is by Daniel Adolfsson <daniel@ashen.se>.

The 1.0 rewrite owes its existence as a usable program to
**[totoCZ][toto]**, who deployed it, diagnosed why it did not work, and
sent back the fixes that make it work — see [#93][pr93] and
[#92][i92]. Several of them are the kind of bug that only a real network
finds: a multicast MAC that is wrong by one byte, a socket membership
dropped by the wrong process at fork, an NA that is correct in every
respect except the one flag that would have let a neighbour cache believe
it.

[i92]: https://github.com/DanielAdolfsson/ndppd/issues/92

---

## License

GNU General Public License v3 or later.
Copyright © 2011–2026 Daniel Adolfsson <daniel@ashen.se>
