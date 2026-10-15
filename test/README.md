# ndppd test suite

Two layers, both run by `make check`:

| Layer | Target | What it covers | Privileges |
| ----- | ------ | -------------- | ---------- |
| Unit | `make check-unit` | Pure functions: address parsing and prefix matching, the config parser, the routing-table reader, the reference-counted pointer | none |
| Integration | `make check-integration` | A real `ndppd` binary proxying real neighbor discovery between real interfaces | **none** — unprivileged namespaces |

Both emit [TAP 13](https://testanything.org), so they compose with `prove`,
CI annotators and anything else that speaks TAP.

```sh
make check              # everything
make check-unit         # fast; no network
make check-integration  # ~1 minute

./test/unit/ndppd-unit-tests --list       # list unit tests
./test/unit/ndppd-unit-tests address_parses_prefixes
./test/integration/run.sh --list          # list integration cases
./test/integration/run.sh 010-iface-rule
```

## Unit tests

`test/unit/` builds a binary from the project's own object files — every
`src/*.o` except `ndppd.o`, which holds `main()` — plus the test
translation units. No mocking framework, no test framework dependency:
`tap.h` is 160 lines of C++03 and nothing else is required.

Fixtures live in `test/unit/fixtures/`. `route::load()` takes a path, so
the routing-table parser is tested against a checked-in
`/proc/net/ipv6_route` sample rather than whatever the build machine
happens to have in its routing table.

One of the config tests parses the shipped `ndppd.conf-dist`. If the parser
and the example ever disagree, CI finds out before a user does.

## Integration tests

`test/integration/run.sh` builds this topology and runs the daemon in the
middle of it:

```
     ns:up                    ns:rt                   ns:down
  2001:db8::1/48    ====   2001:db8::2/48    ====  2001:db8:0:1::2/64
   (upstream)              2001:db8:0:1::1/64          (target)
                              [ ndppd ]
```

`up` believes the whole `2001:db8::/48` is on-link, so reaching anything
downstream means solicitating for it on the link and waiting for somebody to
claim the address. Nobody does — that is ndppd's job. This is the situation
every ndppd deployment is in: a provider that routes a prefix on-link rather
than to a next hop.

Each case asserts that the downstream host is **unreachable before ndppd
starts**, which keeps the suite honest: if the topology ever starts working
on its own, every other assertion in the file is meaningless.

### It does not need root

The whole harness runs under `unshare -Urn`. A user namespace grants
`CAP_NET_ADMIN` inside its own network namespace, which covers everything
ndppd needs: veth pairs, bridges, addressing, promiscuous mode, the
forwarding sysctl and `AF_PACKET` sockets.

Extra namespaces are made by parking a child process in its own netns and
moving one end of a veth into it by PID. `ip netns` would need a bind mount
under `/run/netns` and so would reintroduce the root requirement this
harness exists to avoid.

If unprivileged user namespaces are disabled on the host — some
distributions and container runtimes do that — the suite reports
`1..0 # SKIP` with the reason rather than failing.

### It tests a binary, not an API

A case drives `ndppd` plus a configuration file and asserts on observable
behaviour: reachability, and what the daemon says it did. Nothing in
`test/integration/` references ndppd's internals.

That is deliberate. `run.sh --binary <path>` will test *any* build, which
makes the suite usable as a conformance target rather than only as a
regression net for this tree.

## Writing a case

Drop a file in `test/integration/cases/`. It runs in its own user and
network namespace, so it cannot disturb its neighbours, and everything it
creates is reclaimed when it exits.

```sh
#!/bin/bash
# One or two sentences on what this case establishes and why it matters.
set -u
. "$LIB/topology.sh"
. "$LIB/assert.sh"

topo_up

assert_unreachable up "$TOPO_DOWN_HOST" "unreachable before ndppd starts"

topo_ndppd_start "
proxy rt0 {
    rule 2001:db8:0:1::/64 {
        iface rt1
    }
}"

assert_reachable up "$TOPO_DOWN_HOST" "ndppd makes the target reachable"
assert_log_matches "write_advert" "ndppd advertised the target"

assert_summary
```

Available: `topo_up`, `topo_ns <up|rt|down> <cmd...>`, `topo_ndppd_start`,
`topo_ndppd_stop`, `topo_add_down_addr`, `topo_logfile`,
`assert_reachable`, `assert_unreachable`, `assert_log_matches`,
`assert_log_not_matches`, `assert_exit`, `todo`, `diag`.

## Known bugs are tracked, not hidden

Several tests describe behaviour that is wrong today. Rather than delete
them or let the suite go red, they are marked with TAP's `TODO` directive:
the assertion runs and is reported, but does not fail the build.

```sh
todo "route::ifa() returns null once _ifa is cached; see src/route.cc"
assert_log_not_matches "_ifaces.size\(\) = 0" \
    "every target behind a route gets an interface to solicit on"
```

Each one is paired with an assertion pinning the *current* behaviour, so a
bug cannot quietly change shape while it is open. When the bug is fixed,
delete the `todo` line — and the test starts enforcing the fix.

Currently marked TODO:

| Where | Bug |
| ----- | --- |
| `040-auto-rule` | `auto` rules never match the advertisement relevance check in `iface.cc`, so every advertisement for them is discarded (arrived with the autowire series, commit `a008fad`; not present in 0.2.5) |
| `050-route-interface-cache` | `route::ifa()` returns null once the interface is cached, so only the first target behind a route resolves — the root cause of issue #68, present since 0.2.2 |
| `test_address` | `2001:db8::/` parses as `/0`, turning a trailing-slash typo into a rule matching every address on the internet |
| `test_address` | a prefix above 128 is silently clamped instead of rejected |
| `test_ptr` | `ptr<T>::reset()` does not release its reference (currently unused, so latent) |

A TODO assertion that starts passing is reported as
`ok N - ... # TODO ...`, which is TAP's way of saying the bug appears to be
fixed and the marker should come off.
