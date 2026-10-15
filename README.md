# ndppd — NDP Proxy Daemon

`ndppd` answers IPv6 Neighbor Solicitation messages on behalf of addresses
that live somewhere else, so a prefix your provider puts *on-link* can
actually be routed to containers, VMs or a downstream network behind your
host.

---

## Project status

**The 0.2.x line on `master` is the supported version of ndppd.** It is what
distributions ship, what is running in production, and where fixes and
releases will happen from here on.

**The `1.0-devel` rewrite is discontinued.** It was started in 2019 as a
ground-up C99 replacement and last received a commit in June 2020. It never
reached a state anyone could run in production, it no longer compiles with a
current toolchain, and keeping it nominally alive has had a real cost: for
six years the README told people the version they were running was obsolete
and its replacement was not ready, which is a bad answer to give anyone.

The branch stays in the repository for reference and for anyone who wants to
pick ideas out of it — several are good, and some of them will be ported —
but it is not the future of this project and no further work will go into
it. If you are running ndppd, run `master`.

This repository is maintained on a best-effort basis. Issues and pull
requests are welcome; review may be slow.

---

## What problem it solves

Before anything can send you an IPv6 packet, it has to learn your link-layer
address. It does that by multicasting a Neighbor Solicitation — "who has
`2001:db8::1`?" — and waiting for the owner to answer with a Neighbor
Advertisement (RFC 4861).

That works when the address is configured on a machine attached to the link.
It does not work when your provider routes a prefix *on-link* to a segment,
and you want to use that prefix on containers or VMs behind your host. The
provider's router solicits for an address, nothing on the link claims it, and
the traffic is dropped — even though you have a perfectly good route for it
one hop further in.

Linux can proxy neighbor discovery itself:

```sh
sysctl -w net.ipv6.conf.all.proxy_ndp=1
ip -6 neigh add proxy 2001:db8::1 dev eth0
```

but only one address at a time, it cannot list what it is proxying, and it
answers blindly — it will claim an address whether or not anything is
actually there.

`ndppd` listens for solicitations on an interface, decides from your rules
whether the target is one it should answer for, optionally checks that the
target really exists by soliciting it on an internal interface, and only then
advertises. Rules are written as prefixes, so one line covers a whole `/64`.

---

## Install

No dependencies beyond a C++ compiler and `make`.

```sh
make
sudo make install
```

Installs `ndppd` to `/usr/local/sbin` and the man pages `ndppd(1)` and
`ndppd.conf(5)`. Override with `PREFIX=`, `DESTDIR=`, `SBINDIR=`, `MANDIR=`.

Most distributions package ndppd already — check there first.

---

## Getting started

A complete, working configuration. Your provider routes `2001:db8:1000::/48`
on-link to `eth0`; your containers live on `br0` behind it.

`/etc/ndppd.conf`:

```
proxy eth0 {
    router yes

    rule 2001:db8:1000:1::/64 {
        iface br0
    }
}
```

ndppd does not configure routing for you. You also need:

```sh
sysctl -w net.ipv6.conf.all.forwarding=1
```

and the prefix actually configured on `br0`, with your containers using the
host as their default route.

Then:

```sh
ndppd -c /etc/ndppd.conf -d -p /run/ndppd.pid
```

or `systemctl enable --now ndppd` using the shipped `ndppd.service`.

To watch what it is doing, run it in the foreground with `-vvv`.

---

## Choosing a rule mode

Every rule needs exactly one of `iface`, `static` or `auto`. This is the
decision people most often get wrong, so:

### `iface <interface>` — recommended

```
rule 2001:db8:1000:1::/64 {
    iface br0
}
```

When a solicitation arrives for an address in the prefix, ndppd solicits that
address on `br0` and answers upstream only if something replies. Correct
behaviour by construction: ndppd never claims an address that is not there,
so an address you have not assigned yet stays unreachable instead of becoming
a black hole.

Use this unless you have a specific reason not to.

### `static` — answer immediately

```
rule 2001:db8:1000:1::/64 {
    static
}
```

Answers every solicitation in the prefix without checking anything. No
resolution latency, and it works when the target cannot answer for itself.

The cost is that ndppd now claims **every** address in the prefix. Anything
in it that does not exist becomes a black hole rather than an immediate
"unreachable", and on a shared segment a prefix wider than you actually own
means claiming other people's addresses. ndppd warns on startup if you use
`static` with a prefix shorter than `/120`.

### `auto` — resolve through the routing table

```
rule 2001:db8:1000::/48 {
    auto
}
```

Looks the target up in the kernel routing table and solicits on whichever
interface comes back, so you do not have to name interfaces in the config.

**`auto` does not currently work.** Two separate defects stop it from ever
completing a session — see [Known issues](#known-issues). Use `iface` rules
instead; they do the same job with the interface named explicitly.

---

## Configuration reference

See `ndppd.conf(5)` for the full description. In brief:

### Global

| Option | Default | Meaning |
| ------ | ------- | ------- |
| `route-ttl` | `30000` | How often (ms) to re-read `/proc/net/ipv6_route` |
| `address-ttl` | `30000` | How often (ms) to re-read local addresses |

### `proxy <interface> { … }`

The interface to listen for solicitations on — the one facing your provider.

| Option | Default | Meaning |
| ------ | ------- | ------- |
| `router` | `yes` | Set the Router flag in advertisements |
| `timeout` | `500` | How long (ms) to wait for a target to answer |
| `ttl` | `30000` | How long (ms) to cache a resolved session |
| `deadtime` | = `ttl` | How long (ms) to cache a session that never resolved |
| `retries` | `3` | Solicitations to send before giving up on a target |
| `keepalive` | `yes` | Re-solicit a session before it expires |
| `autowire` | `no` | Add a host route for a resolved target, remove it on expiry |
| `promiscuous` | `no` | Put the interface in promiscuous mode |

`promiscuous` is worth knowing about: without it the socket only sees
multicast solicitations. Once an upstream router has an entry for you it
refreshes it with *unicast* solicitations sent straight to your MAC, which
an all-multicast socket never sees. If proxying works and then stops after
twenty or thirty minutes of steady traffic, try `promiscuous yes`.

### `rule <prefix> { … }`

One of `iface <interface>`, `static` or `auto`, plus:

| Option | Default | Meaning |
| ------ | ------- | ------- |
| `autovia` | `no` | With `autowire`, route via the target's own address |

---

## What ndppd does not do

Most "ndppd isn't working" reports turn out to be one of these:

- **It does not route.** It makes your host *claim* an address. Getting the
  packet onward is up to your routing table and
  `net.ipv6.conf.all.forwarding`.
- **It does not enable forwarding.**
- **It does not send Router Advertisements.** Use `radvd` or similar for
  that.
- **It does not configure addresses** on your downstream interface.
- **It only handles Neighbor Solicitation and Advertisement.** Not Router
  Solicitation/Advertisement, not Redirect, not MLD.

---

## Troubleshooting

Start here:

```sh
ndppd -c /etc/ndppd.conf -vvv
```

| What you see | What it means |
| ------------ | ------------- |
| No `handle_solicit` lines at all | Solicitations are not reaching ndppd. Check you are proxying on the interface facing your provider. If they appear and then stop, try `promiscuous yes` — unicast NUD probes do not reach an all-multicast socket. |
| `checking <prefix> against <target>` but no advertisement | Your rule's prefix does not cover the target. |
| `write_advert()` logged, but nothing in `tcpdump` | Known limitation: advertisements go out through an `AF_INET6` socket, so the kernel has to resolve the destination link-layer address first. When it cannot, `sendmsg()` reports success and the packet is silently dropped. See issue [#71](https://github.com/DanielAdolfsson/ndppd/issues/71). |
| `session is now invalid` | The target never answered. With an `iface` rule, check the address really is up on that interface. With `auto`, see [Known issues](#known-issues). |
| `Low prefix length (… <= 120) when using 'static'` | You are claiming a large prefix unconditionally. Usually you want `iface`. |
| Works, then stops after ~20–30 minutes | Almost always the unicast-NUD case above. `promiscuous yes`. |

Still stuck? Open an issue with the `-vvv` output, your config, and
`ip -6 route`, `ip -6 addr` and `sysctl net.ipv6.conf.all.forwarding`.

---

## Known issues

These are reproduced by the test suite and marked `TODO` there, so they are
tracked rather than forgotten. See `test/README.md`.

- **`auto` rules never complete.** Two independent defects: `iface.cc` only
  accepts an advertisement if some rule has a *daughter* interface matching
  the one it arrived on, which an `auto` rule never has; and `route::ifa()`
  returns null once it has cached the interface, so only the first target
  behind a given route ever gets solicited. The second is the root cause of
  issue [#68](https://github.com/DanielAdolfsson/ndppd/issues/68) and
  explains why the failure looks intermittent — the route list is rebuilt
  every `route-ttl` milliseconds, which resets the cache.
- **Advertisements can be silently dropped**
  ([#71](https://github.com/DanielAdolfsson/ndppd/issues/71),
  [#81](https://github.com/DanielAdolfsson/ndppd/issues/81)) — see the
  troubleshooting table above.
- **A trailing slash in a prefix parses as `/0`.** `2001:db8::/` is accepted
  and matches every address on the internet. Check your config for typos.
- **A prefix above `/128` is clamped, not rejected.**

---

## Tests

```sh
make check              # unit + integration
make check-unit         # fast, no network
make check-integration  # a real daemon in network namespaces
```

The integration suite builds a three-namespace topology, runs ndppd in the
middle of it and asserts on what actually reaches the wire. It needs **no
root** — it runs under `unshare -Urn` — and it drives a binary plus a config
file rather than any internal API, so `run.sh --binary <path>` will test any
build.

Full details, and how to add a case, in [`test/README.md`](test/README.md).

---

## Contributing

Bug reports are most useful with the `-vvv` log, the config, and your routing
state. Patches are welcome; please add or update a test under `test/` for
anything that changes behaviour — `make check` should pass before and after.

---

## License

GNU General Public License v3 or later. See [LICENSE](LICENSE).

Copyright (C) 2011-2026 Daniel Adolfsson <daniel@ashen.se>
