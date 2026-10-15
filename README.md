# ndppd — NDP Proxy Daemon

**ndppd** proxies IPv6 Neighbor Discovery between interfaces so delegated prefixes are reachable across a gateway. Ground-up C99 rewrite with a corrected session state machine, promiscuous-mode packet capture, and strict RFC 4861 compliance.

---

## Why not the kernel or the original ndppd?

| | Kernel `proxy_ndp` | Original ndppd | This rewrite |
|---|---|---|---|
| Prefix rules | ❌ per-address only | ✅ | ✅ |
| Probes before replying | ❌ replies blindly | ✅ | ✅ |
| Sees unicast NUD probes | ❌ multicast only | ❌ all-multicast socket | ✅ promiscuous |
| Routing table integration | ❌ | ✅ Netlink / AF_ROUTE | ✅ |
| RFC 4861 compliant | partial | ⚠️ DAD, STALE bugs | ✅ |

**The unicast NUD problem**: once a neighbor entry is established, NUD refreshes it with unicast NS sent directly to the proxy's MAC — bypassing multicast entirely. Neither the kernel proxy nor the original ndppd ever saw these frames. The upstream neighbor cache goes STALE → FAILED every 20–30 minutes under sustained traffic. This rewrite runs in promiscuous mode and captures all frames.

---

## Install

```sh
make && make install
```

Man pages require Asciidoctor.

---

## Usage

```sh
ndppd -c /etc/ndppd.conf [-dv] [-p pidfile] [--syslog] [--netns <name>]
```

| Flag | Description |
|---|---|
| `-c /path` | Config file (always required) |
| `-d` | Daemonize |
| `-p /path` | Pidfile, flock-locked to prevent duplicates |
| `--syslog` | Force syslog in the foreground |
| `-v` / `-vv` | Debug / trace logging |
| `--netns <name>` | *(Linux)* Enter named netns before starting |

---

## Configuration

Block syntax. Comments: `#` or `/* */`.

```nginx
# /etc/ndppd.conf

valid-ttl   30000   # ms to keep a VALID session after last NA from target
invalid-ttl 10000   # ms to cache a failed session (absorbs NS floods)
retrans-time  1000  # ms between outgoing NS probes
retrans-limit    3  # probes before giving up
keepalive      no   # yes = keep probing STALE sessions without upstream NS

proxy eth0 {
    router no       # set Router flag in NAs (yes if proxied targets are routers, e.g. downstream CPE)
    target <mac>    # override advertised MAC for all rules (optional)

    rule 2001:db8::/48 {
        auto        # resolve via routing table — or: iface <if>, or: static
        table 254   # routing table to use (Linux only)
        autowire    # add /128 host route on VALID, remove on expiry (iface only)
        target <mac>             # per-rule MAC override (optional)
        rewrite fd00::/48        # rewrite target before forwarding (optional)
    }
}
```

Each rule requires exactly one of `auto`, `iface <if>`, or `static`.

---

## Session state machine

One session per (target, proxy) pair. STALE timeout is hardcoded at 30 s.

```
 [new NS] ──────────────────► INCOMPLETE ──── NA received ───► VALID
                                   │                              │
                          retrans_limit                       valid-ttl
                           exceeded  │                            │
                                     ▼                            ▼
                                  INVALID ◄──── 30 s ────── STALE
                                     │
                               invalid-ttl
                                     │
                                     ▼
                                 (deleted)
```

- **INCOMPLETE** — probing downstream; retransmits every `retrans-time` up to `retrans-limit` times.
- **VALID** — upstream NS answered immediately with a solicited NA.
- **STALE** — re-probes on fresh upstream NS; retransmit interval doubles every `retrans-limit` probes (capped at 2²⁰ × `retrans-time`).
- **INVALID** — keeps queued subscribers; a late NA still satisfies them all. In `auto` mode, re-checks the routing table on each incoming NS so a route appearing after initial failure is picked up automatically.

---

## Examples

### Delegated prefix to a LAN

```nginx
proxy wan0 {
    rule 2001:db8:1234:5600::/56 {
        auto
    }
}
```

### Containers with per-host route injection

```nginx
proxy eth0 {
    rule 2001:db8::/48 {
        iface br0
        autowire
        table 100
    }
}
```

### Public-to-internal prefix rewrite

NS for `2001:db8:a::1` probes `fd00::1` on `eth1`; the public address is advertised upstream.

```nginx
proxy eth0 {
    rule 2001:db8:a::/48 {
        iface eth1
        rewrite fd00::/48
    }
}
```

---

## Systemd

```sh
systemctl enable --now ndppd
```

Unit file at `ndppd.service`. Edit `ExecStart` to add `-c /etc/ndppd.conf`.

---

## License

GNU General Public License v3 or later.  
Copyright (C) 2011–2019 Daniel Adolfsson <daniel@ashen.se>
