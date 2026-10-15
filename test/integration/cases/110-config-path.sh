#!/usr/bin/env bash
# The configuration path ndppd uses when -c is not given.
#
# ndppd.service passes no -c, and systemd runs a service with its working
# directory at /. The compiled-in default used to be the relative path
# "../ndppd.conf", so the shipped unit looked for /ndppd.conf and the
# daemon exited -- while ndppd(8) and README.md both documented
# /etc/ndppd.conf.
#
# The default is built from SYSCONFDIR, so a packager who moves it moves
# the documentation's claim with it. This case asserts the binary under
# test and its own man page agree, whatever that path is.
set -u
. "$LIB/topology.sh"
. "$LIB/assert.sh"

topo_up

# Run from a directory where no relative path could accidentally resolve.
out="$(cd / && topo_ns rt "$NDPPD_BINARY" 2>&1 | head -5)"

case "$out" in
    *'Loading configuration "/'*)
        _result 0 "the default configuration path is absolute" ;;
    *)
        _result 1 "the default configuration path is absolute"
        diag "  ndppd said: $out" ;;
esac

path="$(printf '%s\n' "$out" | sed -n 's/.*Loading configuration "\([^"]*\)".*/\1/p' | head -1)"
diag "default configuration path: ${path:-unknown}"

# Whatever it is, the man page has to name it.
if [ -n "$path" ] && grep -Fq -- "$path" "$SRCDIR/ndppd.8.adoc"; then
    _result 0 "ndppd(8) documents that path"
else
    _result 1 "ndppd(8) documents that path"
    diag "  ndppd.8.adoc does not mention $path"
fi

assert_summary
