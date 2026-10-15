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
// Tests for ndppd::route (src/route.cc).
//
// route is how a rule in `auto` mode decides which interface to solicit on.
// It parses /proc/net/ipv6_route by fixed byte offsets, which makes it both
// fragile and -- because route::load() takes a path -- easy to test against
// a checked-in fixture rather than whatever the build machine happens to
// have in its routing table.

#include "tap.h"
#include "ndppd.h"
// ndppd.h does not pull in route.h.
#include "route.h"

#include <string>

using namespace ndppd;

namespace {

std::string fixture()
{
    return std::string(NDPPD_TEST_SRCDIR) + "/test/unit/fixtures/ipv6_route";
}

address A(const char* s)
{
    address a;
    a.parse_string(s);
    return a;
}

} // namespace

TEST(route_hexdec_decodes_hex_pairs)
{
    unsigned char buf[4];

    tap::is((int)route::hexdec("deadbeef", buf, 4), 4, "decodes four byte pairs");
    tap::is((int)buf[0], 0xde, "first byte decoded");
    tap::is((int)buf[1], 0xad, "second byte decoded");
    tap::is((int)buf[2], 0xbe, "third byte decoded");
    tap::is((int)buf[3], 0xef, "fourth byte decoded");
}

TEST(route_hexdec_is_case_insensitive)
{
    unsigned char lower[2], upper[2];
    route::hexdec("abcd", lower, 2);
    route::hexdec("ABCD", upper, 2);
    tap::is((int)lower[0], (int)upper[0], "upper and lower case decode alike (byte 0)");
    tap::is((int)lower[1], (int)upper[1], "upper and lower case decode alike (byte 1)");
}

TEST(route_hexdec_stops_at_the_first_non_hex_pair)
{
    unsigned char buf[8];
    tap::is((int)route::hexdec("dead!!!!", buf, 8), 2,
            "stops at the first pair that is not hex");
    tap::is((int)route::hexdec("zz", buf, 8), 0,
            "decodes nothing when the very first pair is not hex");
}

TEST(route_hexdec_honours_the_size_limit)
{
    unsigned char buf[2];
    tap::is((int)route::hexdec("deadbeef", buf, 2), 2,
            "never writes more bytes than it was given room for");
}

TEST(route_token_extracts_the_first_word)
{
    tap::is_str(route::token("eth0"), "eth0", "reads a bare word");
    tap::is_str(route::token("      eth0"), "eth0", "skips leading whitespace");
    tap::is_str(route::token("  eth0  rest"), "eth0", "stops at the next whitespace");
    tap::is_str(route::token(""), "", "an empty string yields an empty token");
    tap::is_str(route::token("     "), "", "whitespace only yields an empty token");
}

TEST(route_load_parses_the_routing_table)
{
    route::load(fixture());

    ptr<route> rt = route::find(A("2001:db8:0:1::5"));
    if (!tap::ok(!rt.is_null(), "a covered address resolves to a route"))
        return;

    tap::is_str(rt->ifname(), "rt1", "the most specific route wins");
    tap::is(rt->addr().prefix(), 64, "the route keeps its prefix length");
    tap::is_str(rt->addr().to_string(), "2001:db8:0:1::/64",
                "the route destination is decoded correctly");
}

TEST(route_load_distinguishes_between_routes)
{
    route::load(fixture());

    ptr<route> a = route::find(A("2001:db8:0:1::5"));
    ptr<route> b = route::find(A("2001:db8:0:2::5"));

    if (a.is_null() || b.is_null()) {
        tap::ok(false, "both addresses resolve to routes");
        return;
    }

    tap::is_str(a->ifname(), "rt1", "the first prefix resolves to its own interface");
    tap::is_str(b->ifname(), "rt2", "the second prefix resolves to its own interface");
}

TEST(route_load_falls_back_to_the_covering_prefix)
{
    route::load(fixture());

    // 2001:db8:0:9:: is inside the /48 but outside both /64s.
    ptr<route> rt = route::find(A("2001:db8:0:9::1"));
    if (!tap::ok(!rt.is_null(), "an address covered only by the /48 resolves"))
        return;
    tap::is_str(rt->ifname(), "rt0", "it falls back to the /48's interface");
}

TEST(route_load_skips_malformed_lines)
{
    // The fixture contains one truncated line and one whose destination
    // field is not hex. Neither should become a route, and neither should
    // stop the rest of the file from being parsed.
    route::load(fixture());

    ptr<route> rt = route::find(A("fe80::1"));
    if (!tap::ok(!rt.is_null(), "routes after the malformed lines still parse"))
        return;
    tap::is_str(rt->ifname(), "rt0", "the link-local route survives");
}

TEST(route_load_handles_a_missing_file)
{
    // A missing /proc/net/ipv6_route must not take the daemon down; it is
    // reloaded on a timer and a transient failure has to be survivable.
    route::load("/nonexistent/ndppd/ipv6_route");
    tap::ok(true, "loading a missing routing table does not throw");

    // Reload the fixture so the shared static route list is left in a known
    // state for whichever test runs next.
    route::load(fixture());
}

TEST(route_find_returns_null_when_nothing_matches)
{
    // The fixture deliberately ends with a ::/0 default route, so this test
    // uses a table without one.
    route::load("/nonexistent/ndppd/ipv6_route");
    tap::ok(route::find(A("2001:db8::1")).is_null(),
            "find() returns null when the table holds no match");
    route::load(fixture());
}

TEST(route_default_route_matches_anything)
{
    route::load(fixture());
    ptr<route> rt = route::find(A("2600::1"));
    if (!tap::ok(!rt.is_null(), "an address outside every prefix hits the default route"))
        return;
    tap::is_str(rt->ifname(), "rt0", "the default route's interface is returned");
}
