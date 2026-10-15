// ndppd - NDP Proxy Daemon
// Copyright (C) 2026  Daniel Adolfsson <daniel@ashen.se>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//
// Tests for ndppd::address (src/address.cc).
//
// address is what turns a line in ndppd.conf into the prefix comparison
// that decides whether ndppd answers a solicitation. A defect here either
// silently stops answering or -- worse -- answers for addresses it should
// not. It is also the prime suspect for issue #67 (addresses printed
// scrambled on 32-bit ARM), which is why the round-trip cases below are
// worth running under the cross-compiled CI jobs.

#include "tap.h"
#include "ndppd.h"

using namespace ndppd;

static address A(const char* s)
{
    address a;
    a.parse_string(s);
    return a;
}

TEST(address_default_is_empty)
{
    address a;
    tap::ok(a.is_empty(), "default-constructed address is empty");
    tap::is_str(a.to_string(), "::", "default-constructed address prints as ::");
    tap::is(a.prefix(), 128, "default-constructed address has a /128 mask");
}

TEST(address_parses_plain_addresses)
{
    address a;
    tap::ok(a.parse_string("2001:db8::1"), "parses a plain address");
    tap::is_str(a.to_string(), "2001:db8::1", "round-trips a plain address");
    tap::is(a.prefix(), 128, "a plain address is implicitly /128");

    tap::ok(a.parse_string("::1"), "parses the loopback address");
    tap::is_str(a.to_string(), "::1", "round-trips the loopback address");

    tap::ok(a.parse_string("fe80::1"), "parses a link-local address");
    tap::ok(a.parse_string("ff02::1"), "parses a multicast address");
}

TEST(address_parses_prefixes)
{
    address a;
    tap::ok(a.parse_string("2001:db8::/32"), "parses an address with a prefix");
    tap::is(a.prefix(), 32, "prefix length is recorded");
    tap::is_str(a.to_string(), "2001:db8::/32", "round-trips address with prefix");

    tap::ok(a.parse_string("2001:db8::/64"), "parses a /64");
    tap::is(a.prefix(), 64, "/64 recorded");

    tap::ok(a.parse_string("2001:db8::/0"), "parses a /0");
    tap::is(a.prefix(), 0, "/0 recorded");
}

TEST(address_to_string_omits_slash_128)
{
    // Deliberate: a host address reads better without the redundant /128,
    // and the daemon's debug output relies on it.
    tap::is_str(A("2001:db8::1/128").to_string(), "2001:db8::1",
                "to_string() omits an explicit /128");
}

TEST(address_prefix_round_trips_at_every_boundary)
{
    // Byte and word boundaries are where netmask builders break.
    static const int pf[] = { 0, 1, 7, 8, 9, 31, 32, 33, 63, 64, 65, 95, 96,
                              120, 127, 128 };

    for (size_t i = 0; i < sizeof(pf) / sizeof(pf[0]); i++) {
        address a("2001:db8::");
        a.prefix(pf[i]);
        std::ostringstream d;
        d << "prefix(" << pf[i] << ") round-trips through prefix()";
        tap::is(a.prefix(), pf[i], d.str());
    }
}

TEST(address_rejects_garbage)
{
    address a;
    tap::ok(!a.parse_string("garbage"), "rejects a non-address");
    tap::ok(!a.parse_string(""), "rejects an empty string");
    tap::ok(!a.parse_string("2001:db8::1/xyz"), "rejects a non-numeric prefix");
    tap::ok(!a.parse_string("12345::"), "rejects an over-long hextet");
}

TEST(address_tolerates_surrounding_whitespace)
{
    address a;
    tap::ok(a.parse_string("  2001:db8::1  "), "tolerates surrounding whitespace");
    tap::is_str(a.to_string(), "2001:db8::1", "whitespace is not part of the address");

    tap::ok(a.parse_string("2001:db8::1 /32"), "tolerates whitespace before the prefix");
    tap::is(a.prefix(), 32, "prefix after whitespace is applied");
}

TEST(address_matching_is_prefix_based)
{
    address net("2001:db8::/32");
    tap::ok(net == A("2001:db8:1::1"), "a /32 matches an address inside it");
    tap::ok(net == A("2001:db8::"), "a /32 matches its own network address");
    tap::ok(net != A("2001:db9::1"), "a /32 does not match an address outside it");

    address host("2001:db8::1");
    tap::ok(host == A("2001:db8::1"), "a /128 matches itself");
    tap::ok(host != A("2001:db8::2"), "a /128 does not match a neighbour");
}

TEST(address_matching_is_asymmetric_by_design)
{
    // operator== masks with the *left* operand's netmask only. This is what
    // makes `rule->addr() == taddr` mean "does this rule cover this target",
    // so it is load-bearing rather than accidental -- but it does mean
    // address is not a value type with a symmetric equality, and comparisons
    // must always be written prefix-on-the-left.
    address net("2001:db8::/32");
    address host("2001:db8:1::1");

    tap::ok(net == host, "prefix == host is true when the host is covered");
    tap::ok(!(host == net), "host == prefix is false: equality is asymmetric");
}

TEST(address_classifies_unicast_and_multicast)
{
    tap::ok(A("ff02::1").is_multicast(), "ff02::1 is multicast");
    tap::ok(!A("ff02::1").is_unicast(), "ff02::1 is not unicast");
    tap::ok(A("2001:db8::1").is_unicast(), "a global address is unicast");
    tap::ok(!A("2001:db8::1").is_multicast(), "a global address is not multicast");
    tap::ok(A("fe80::1").is_unicast(), "a link-local address is unicast");

    address unspec("::");
    tap::ok(!unspec.is_unicast(), ":: is not unicast");
    tap::ok(!unspec.is_multicast(), ":: is not multicast");
    tap::ok(unspec.is_empty(), ":: with a /128 mask is 'empty'");
}

TEST(address_reset_restores_the_empty_state)
{
    address a("2001:db8::/32");
    tap::ok(!a.is_empty(), "a parsed prefix is not empty");
    a.reset();
    tap::ok(a.is_empty(), "reset() returns the address to the empty state");
    tap::is(a.prefix(), 128, "reset() restores the all-ones mask");
}

TEST(address_trailing_slash_is_accepted_as_slash_zero)
{
    // KNOWN BUG: "2001:db8::/" parses successfully and yields /0, because
    // parse_string() runs atoi() over an empty prefix string. A trailing
    // slash is an easy typo in ndppd.conf, and /0 means "every address on
    // the internet" -- so this turns a typo into a rule that answers
    // solicitations for everything. It should be rejected.
    address a;
    bool parsed = a.parse_string("2001:db8::/");

    tap::todo("trailing slash should be rejected, not treated as /0");
    tap::ok(!parsed, "a trailing slash with no digits is rejected");

    // Document what it actually does today, so the behaviour cannot change
    // unnoticed while the bug is still open.
    tap::ok(parsed && a.prefix() == 0,
            "current behaviour: a trailing slash is parsed as /0");
}

TEST(address_out_of_range_prefix_is_clamped)
{
    // KNOWN BUG: parse_string() accepts up to four prefix digits and passes
    // them to prefix(), which clamps anything >= 128. "2001:db8::/999" is
    // therefore silently read as /128 rather than reported as a config
    // error.
    address a;
    bool parsed = a.parse_string("2001:db8::/999");

    tap::todo("a prefix above 128 should be rejected, not clamped");
    tap::ok(!parsed, "an out-of-range prefix is rejected");

    tap::ok(parsed && a.prefix() == 128,
            "current behaviour: an out-of-range prefix is clamped to /128");
}
