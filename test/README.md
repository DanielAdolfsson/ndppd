# Tests

```
make check              # both layers
make check-unit         # 228 assertions; no network, no privileges, no waiting
make check-integration  #  55 assertions; a real daemon on real interfaces
```

Both layers emit [TAP 13](https://testanything.org), so either can be fed
to `prove`, to a CI annotation parser, or read as it stands.

---

## Unit tests — `test/unit/`

The unit binary links the production objects for `addr`, `alloc`, `conf`,
`log`, `proxy`, `rule` and `session`, and substitutes `test/unit/fake.c`
for `iface.c`, `rt.c` and `io.c` — the two places ndppd needs a kernel.

The code under test is therefore the shipped code, while three things
become possible that are not possible against a running daemon:

- **Every emitted NS and NA is recorded** and can be asserted on exactly,
  rather than inferred from whether a ping got through.
- **`nd_current_time` is an ordinary variable.** A VALID session ageing
  into STALE after thirty seconds is tested by assigning to it. The suite
  does not sleep.
- **`nd_iface_send_ns()` tolerates a NULL interface.** A code path that
  segfaults against the real `iface.c` is observable as a recorded send
  with `iface == NULL`, instead of killing the run — which is how the
  static-rule crash is pinned at unit level as well as end to end.

`tap.h` and `tap.c` are 150 lines of C99 and are the entire framework.
ndppd is expected to build with nothing but a compiler, on platforms as old
and as odd as the ones in #67 and #73; a suite that dragged in a test
framework would make that claim untestable exactly where it matters.

What is covered:

| | |
|---|---|
| `test_addr.c` | every prefix length from 0 to 128, against an independent bitwise reference, for `nd_addr_match` and `nd_addr_combine`; netmask round-trips; classification; hashing; link-layer addresses |
| `test_conf.c` | the real `nd_conf_load()` against temporary files — every rule mode, prefix handling, rewrite, target overrides, global bounds, structural errors, and the shipped `ndppd.conf-dist` |
| `test_session.c` | the state machine: INCOMPLETE → VALID → STALE → INVALID → deleted, subscriber queueing, retransmission limits, auto-mode route resolution, rewrite, autowire, and both lookup tables |
| `test_alloc.c` | the slab allocator: distinct blocks, free-list reuse, size bucketing |

`addr.c` gets the heaviest treatment because it is where a mistake is both
easiest to make and hardest to see: two hand-written tables of 32-bit
masks, one per byte order, and a rule that matches one bit too many still
looks plausible in a config file and in a log line. The reference
implementation is deliberately written in a different style from the
implementation — if both were written the same way they would share the
same bug.

`NDPPD_TEST_SRCDIR` lets a test find `ndppd.conf-dist` regardless of where
the binary is run from.

---

## Integration tests — `test/integration/`

```
     ns:up                    ns:rt                   ns:down
  2001:db8::1/48    ====   2001:db8::2/48    ====  2001:db8:0:1::2/64
   (upstream)              2001:db8:0:1::1/64          (target)
                              [ ndppd ]
```

`up` believes the whole `/48` is on-link, so reaching anything downstream
means soliciting on the link and waiting for someone to claim the address.
Nobody does — that is ndppd's job. This is the situation every ndppd
deployment is in: a provider that routes a prefix on-link rather than to a
next hop.

### It runs on Linux and on FreeBSD

ndppd supports both, so the suite does too — and the *same* cases run on
both. Everything that needs a kernel's own vocabulary for "a separate
network stack" lives in a backend behind a fixed contract:

| | Linux | FreeBSD |
| --- | --- | --- |
| separate stack | network namespace (`unshare -n`) | VNET jail (`jail -c vnet persist`) |
| cable | `veth` pair | `epair` |
| move an end | `ip link set X netns PID` | `ifconfig X vnet <jail>` |
| run a command there | `nsenter -t PID -n` | `jexec <jail>` |
| forwarding | `/proc/sys/net/ipv6/conf/all/forwarding` | `sysctl net.inet6.ip6.forwarding` |
| raw frames (`ndtool.py`) | `AF_PACKET` socket | `/dev/bpf` |

The contract is documented at the top of `lib/topology.sh`; the backends
are `lib/topology-linux.sh` and `lib/topology-freebsd.sh`. No case file
names an interface type, a namespace mechanism or a tool, which is what
keeps them identical across platforms. Both backends must also deliver the
interfaces under the same names — a case writes `rt0` and `rt1` into the
ndppd config it generates.

Two traps are worth knowing about, because both would otherwise look like
an ndppd bug rather than a harness bug:

- **`ping -W` is seconds on Linux and milliseconds on FreeBSD.** Cases say
  `assert_reachable`, which calls `topo_ping <ns> <count> <seconds> <addr>`;
  the backend converts. A shared flag string would make every FreeBSD
  reachability assertion fail.
- **FreeBSD tears the epairs down before the jails.** Destroying a VNET
  jail that still owns interfaces has a history of panicking the host.

### Root: not on Linux, necessarily on FreeBSD

On Linux the whole harness runs under `unshare -Urn`. A user namespace
grants `CAP_NET_ADMIN` inside its own network namespace, which covers veth
pairs, addressing, promiscuous mode, the forwarding sysctl, `AF_PACKET` and
`CAP_NET_RAW`. Extra namespaces are made by parking a child in its own
netns and moving a veth end in by PID — `ip netns` would want a bind mount
under `/run/netns` and would reintroduce the root requirement.

FreeBSD has no unprivileged equivalent: VNET jails and `epair` are root
operations. The FreeBSD backend therefore requires root and says so, which
is why the FreeBSD CI job runs in a disposable VM. Run it anywhere else at
your own risk — it creates and destroys interfaces and jails.

Where the host cannot support the suite — unprivileged user namespaces
disabled, no root on FreeBSD, no VIMAGE in the kernel, a `ping` that does
not take these flags — it reports `1..0 # SKIP` with the reason rather
than failing.

Beyond the base system, FreeBSD needs `bash` and `python3` from packages
(`pkg install -y gmake bash python3`), and the Makefile is GNU make, so
build with `gmake`.

### It tests a binary, not an API

A case drives `ndppd` plus a config file and asserts on observable
behaviour. Nothing in `test/integration/` touches ndppd's internals, so
`run.sh --binary <path>` will test any build — which makes it usable as a
conformance target, not just a regression net for this tree.

Most cases first assert the target is **unreachable without ndppd**, so the
suite cannot quietly stop testing anything.

### `lib/ndtool.py`

Three of ndppd's behaviours cannot be reached with `ping` and `ip`, so
there is a small stdlib-only packet tool for them:

- **The Ethernet destination of an outgoing solicitation.** A wrong
  solicited-node MAC still reaches a veth peer, because the peer's IPv6
  stack accepts the frame on the strength of the IPv6 destination alone —
  there is no hardware filter in the path. On a real bridge it is dropped.
  The only way to see it here is to look at the frame, which is what
  `080-solicited-node-mac.sh` does.
- **A unicast NUD solicitation that omits the source link-layer option**,
  as RFC 4861 §7.7.3 says it should. Linux always includes it, so the peer
  kernel cannot produce this packet.
- **Solicitations ndppd is required to discard** — multicast target, hop
  limit below 255 — which no cooperating kernel will emit.

### Cases

| | |
|---|---|
| `010-iface-rule` | the common case: solicit downstream, answer upstream only after the target replies |
| `020-static-rule` | answers without probing, and probes nothing |
| `030-auto-rule` | resolves the downstream interface from the routing table |
| `040-unmatched-target` | answers only for configured prefixes |
| `050-rewrite` | solicits the internal address, advertises the public one, never leaks the internal one |
| `060-daemonize` | `-d` and `-p`: the child survives with its promiscuous membership intact, and a second instance refuses the pidfile |
| `070-static-rule-longevity` | a static rule under sustained traffic, past its `valid-ttl` |
| `080-solicited-node-mac` | the Ethernet destination is `33:33:ff:..`, not `33:33:fe:..` |
| `090-unicast-nud` | a unicast NS with no SLLAO gets a *solicited* NA, unicast back to the prober |
| `100-rfc-validation` | hop limit ≠ 255 and multicast targets are discarded, and a discard does not break the next good packet |
| `110-config-path` | the configuration path used when `-c` is absent is absolute, and `ndppd(8)` names it |

Several of these are regression tests for specific fixes in #93, and they
discriminate: reverting the solicited-node MAC computation to its pre-#93
form turns `080` red with
`got 33:33:fe:00:ab:cd`.

---

## Known failures

None. Every assertion enforces.

The suite shipped with six unit assertions and one integration assertion
reported under TAP's `TODO` directive — bugs it reproduced but that were
fixed separately, so they were tracked without turning CI red. Each was
paired with an assertion on *current* behaviour, so a bug could not change
shape while it was open: when the fix landed, that assertion started
failing, which was the reminder to delete the `todo` line.

If you add one, follow the same pattern. `todo("reason")` before `ok_todo`
in the unit suite, `todo "reason"` before the assertion in an integration
case.
