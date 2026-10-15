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
// Tests for ndppd::conf (src/conf.cc), the ndppd.conf parser.
//
// Every deployment of ndppd starts by feeding this parser a file written by
// hand, so its tolerance for mistakes is part of the user interface. These
// tests pin down the syntax that is actually accepted -- including the
// shipped ndppd.conf-dist, which has no other protection against drifting
// out of sync with the parser.

#include "tap.h"
#include "ndppd.h"

#include <cstdio>
#include <cstdlib>
#include <string>
#include <unistd.h>

using namespace ndppd;

namespace {

// Writes text to a temporary file and returns its path. The file is removed
// when the process exits, which is good enough for a test binary.
class tmpconf {
public:
    tmpconf(const std::string& text)
    {
        char tmpl[] = "/tmp/ndppd-test-conf-XXXXXX";
        int fd = mkstemp(tmpl);
        if (fd < 0) {
            _path = "";
            return;
        }
        _path = tmpl;
        if (write(fd, text.data(), text.size()) != (ssize_t)text.size())
            _path = "";
        close(fd);
    }

    ~tmpconf()
    {
        if (!_path.empty())
            unlink(_path.c_str());
    }

    const std::string& path() const { return _path; }

private:
    std::string _path;
};

ptr<conf> parse(const std::string& text)
{
    tmpconf t(text);
    return conf::load(t.path());
}

} // namespace

TEST(conf_parses_a_simple_key_and_value)
{
    ptr<conf> c = parse("route-ttl 30000\n");
    if (!tap::ok(!c.is_null(), "a simple key/value file parses"))
        return;

    ptr<conf> v = c->find("route-ttl");
    tap::ok(!v.is_null(), "the key is present");
    tap::is(v->as_int(), 30000, "the value is read as an integer");
    tap::is_str(v->as_str(), "30000", "the value is also available as a string");
}

TEST(conf_parses_nested_blocks)
{
    ptr<conf> c = parse(
        "proxy eth0 {\n"
        "    router yes\n"
        "    rule 2001:db8::/64 {\n"
        "        static\n"
        "    }\n"
        "}\n");

    if (!tap::ok(!c.is_null(), "a nested configuration parses"))
        return;

    ptr<conf> proxy = c->find("proxy");
    if (!tap::ok(!proxy.is_null(), "the proxy block is found"))
        return;

    tap::is_str(proxy->as_str(), "eth0", "the proxy block keeps its value");
    tap::ok(proxy->is_block(), "the proxy entry is a block");
    tap::ok(proxy->find("router")->as_bool(), "a key inside the block is readable");

    ptr<conf> rule = proxy->find("rule");
    if (!tap::ok(!rule.is_null(), "the nested rule block is found"))
        return;

    tap::is_str(rule->as_str(), "2001:db8::/64", "the rule keeps its address");
    tap::ok(!rule->find("static").is_null(), "a valueless key inside the rule is present");
}

TEST(conf_supports_every_comment_style)
{
    ptr<conf> c = parse(
        "# a hash comment\n"
        "// a C++ comment\n"
        "/* a C comment\n"
        "   spanning lines */\n"
        "ttl 1234 # trailing hash comment\n");

    if (!tap::ok(!c.is_null(), "a file using every comment style parses"))
        return;

    tap::is(c->find("ttl")->as_int(), 1234, "comments do not disturb the value");
}

TEST(conf_accepts_an_equals_sign)
{
    ptr<conf> c = parse("ttl = 500\n");
    if (!tap::ok(!c.is_null(), "key = value parses"))
        return;
    tap::is(c->find("ttl")->as_int(), 500, "the value after '=' is read");
}

TEST(conf_accepts_quoted_values)
{
    ptr<conf> c = parse("name \"eth0 with spaces\"\n");
    if (!tap::ok(!c.is_null(), "a double-quoted value parses"))
        return;
    tap::is_str(c->find("name")->as_str(), "eth0 with spaces",
                "quotes are stripped and spaces preserved");

    ptr<conf> c2 = parse("name 'single quoted'\n");
    if (!tap::ok(!c2.is_null(), "a single-quoted value parses"))
        return;
    tap::is_str(c2->find("name")->as_str(), "single quoted",
                "single quotes work the same way");
}

TEST(conf_keeps_every_repeated_key)
{
    // ndppd.conf relies on this: a proxy may hold many rules, and a file may
    // hold many proxies.
    ptr<conf> c = parse(
        "proxy eth0 { router yes }\n"
        "proxy eth1 { router no }\n");

    if (!tap::ok(!c.is_null(), "repeated keys parse"))
        return;

    std::vector<ptr<conf> > all = c->find_all("proxy");
    tap::is((int)all.size(), 2, "find_all() returns every proxy block");

    tap::ok(!c->find("proxy", 0).is_null(), "the first proxy is reachable by index");
    tap::ok(!c->find("proxy", 1).is_null(), "the second proxy is reachable by index");
}

TEST(conf_reads_booleans)
{
    ptr<conf> c = parse("a yes\nb true\nc no\nd false\ne banana\n");
    if (!tap::ok(!c.is_null(), "a file of booleans parses"))
        return;

    tap::ok(c->find("a")->as_bool(), "'yes' is true");
    tap::ok(c->find("b")->as_bool(), "'true' is true");
    tap::ok(!c->find("c")->as_bool(), "'no' is false");
    tap::ok(!c->find("d")->as_bool(), "'false' is false");

    // Anything unrecognised is false rather than an error. Worth knowing:
    // a typo in a boolean silently turns the option off.
    tap::ok(!c->find("e")->as_bool(), "an unrecognised boolean reads as false");
}

TEST(conf_reports_a_missing_key_as_null)
{
    ptr<conf> c = parse("ttl 1\n");
    if (!tap::ok(!c.is_null(), "file parses"))
        return;
    tap::ok(c->find("nonexistent").is_null(), "a missing key yields a null ptr");
}

TEST(conf_rejects_a_missing_file)
{
    ptr<conf> c = conf::load("/nonexistent/ndppd/does-not-exist.conf");
    tap::ok(c.is_null(), "loading a missing file yields a null ptr");
}

TEST(conf_rejects_an_unbalanced_block)
{
    ptr<conf> c = parse("proxy eth0 {\n    router yes\n");
    tap::ok(c.is_null(), "an unclosed block is rejected");
}

TEST(conf_shipped_example_parses)
{
    // ndppd.conf-dist is what users copy to /etc/ndppd.conf. If the parser
    // and the example ever disagree, the first person to find out should be
    // CI and not a user.
    std::string path = std::string(NDPPD_TEST_SRCDIR) + "/ndppd.conf-dist";
    ptr<conf> c = conf::load(path);

    if (!tap::ok(!c.is_null(), "the shipped ndppd.conf-dist parses"))
        return;

    ptr<conf> proxy = c->find("proxy");
    if (!tap::ok(!proxy.is_null(), "ndppd.conf-dist defines a proxy"))
        return;

    tap::ok(proxy->is_block(), "the example proxy is a block");
    tap::ok(!proxy->find("rule").is_null(), "the example proxy defines a rule");
    tap::is(c->find("route-ttl")->as_int(), 30000,
            "the example route-ttl is read correctly");
}
