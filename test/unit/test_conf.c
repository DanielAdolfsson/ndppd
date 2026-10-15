/*
 * This file is part of ndppd.
 *
 * Copyright (C) 2011-2026  Daniel Adolfsson <daniel@ashen.se>
 *
 * ndppd is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * ndppd is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with ndppd.  If not, see <https://www.gnu.org/licenses/>.
 */

/*
 * The configuration parser is the part of ndppd every user touches, and
 * roughly half of the open tracker is really a configuration question.  A
 * parser that accepts a typo and silently means something else is therefore
 * a bug with the same severity as a dropped packet -- `rule 2001:db8::/`
 * quietly becoming a rule that matches the entire internet is the shape of
 * failure these tests exist to catch.
 *
 * Each case writes a config to a temporary file and loads it through the
 * real nd_conf_load(), then inspects the proxy list the parser built.
 * Proxies accumulate in a static list with no teardown, so every case uses
 * its own interface name.
 */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fake.h"
#include "ndppd.h"
#include "tap.h"

extern int nd_conf_invalid_ttl;
extern int nd_conf_valid_ttl;
extern int nd_conf_stale_ttl;
extern int nd_conf_retrans_limit;
extern int nd_conf_retrans_time;
extern bool nd_conf_keepalive;

static char ndL_conf_path[] = "/tmp/ndppd-test-conf-XXXXXX";
static bool ndL_conf_path_ready;

/* Loads `text` as a configuration and returns whether the parser accepted
 * it.  Errors are expected in the negative cases, so the log is silenced
 * for the duration unless the suite is being run verbosely. */
/* `table` selects a routing table, and src/conf.c only offers the key on
   Linux -- FreeBSD has FIBs rather than rtnetlink tables. Config text that
   needs the key has to vary with it, or the whole load fails there for a
   reason the test is not about. */
#ifdef __linux__
#    define TABLE_LINE "        table 100\n"
#else
#    define TABLE_LINE ""
#endif

static bool load(const char *text)
{
    if (!ndL_conf_path_ready) {
        int fd = mkstemp(ndL_conf_path);
        if (fd < 0) {
            perror("mkstemp");
            exit(1);
        }
        close(fd);
        ndL_conf_path_ready = true;
    }

    FILE *fp = fopen(ndL_conf_path, "w");
    if (!fp) {
        perror("fopen");
        exit(1);
    }
    fputs(text, fp);
    fclose(fp);

    /* Most cases below are negative, and ndppd logs a parse error for each
     * one on stdout -- the same stream TAP is written to.  Mute it for the
     * duration of the load so the output stays machine-readable, unless the
     * suite was run with -v. */
    if (nd_opt_verbosity == ND_LOG_TRACE)
        return nd_conf_load(ndL_conf_path);

    fflush(stdout);

    int saved = dup(STDOUT_FILENO);
    int devnull = open("/dev/null", O_WRONLY);

    if (saved >= 0 && devnull >= 0)
        dup2(devnull, STDOUT_FILENO);

    bool result = nd_conf_load(ndL_conf_path);

    fflush(stdout);

    if (saved >= 0) {
        dup2(saved, STDOUT_FILENO);
        close(saved);
    }

    if (devnull >= 0)
        close(devnull);

    return result;
}

static void cleanup(void)
{
    if (ndL_conf_path_ready)
        unlink(ndL_conf_path);
}

/* The parser prepends each rule, so proxy->rules is in reverse source
 * order.  Tests index by source order to stay readable. */
static nd_rule_t *rule_at(nd_proxy_t *proxy, int index)
{
    int count = 0;
    ND_LL_COUNT(proxy->rules, count, next);

    int want = count - 1 - index;
    if (want < 0)
        return NULL;

    nd_rule_t *rule = proxy->rules;
    for (int i = 0; rule && i < want; i++)
        rule = rule->next;

    return rule;
}

void test_conf(void)
{
    tap_begin("conf");

    atexit(cleanup);

    /* --- a complete, ordinary configuration ----------------------------- */

    {
        ok(load("proxy ut0 {\n"
                "    router yes\n"
                "    rule 2001:db8:1234:5600::/56 {\n"
                "        auto\n"
                "    }\n"
                "}\n"),
           "a minimal auto configuration parses");

        nd_proxy_t *proxy = nd_proxy_find("ut0");
        ok(proxy != NULL, "the proxy was created");

        if (proxy) {
            ok(proxy->router, "router yes was applied");

            nd_rule_t *rule = rule_at(proxy, 0);
            ok(rule != NULL, "the rule was created");

            if (rule) {
                ok_str(nd_ntoa(&rule->addr), "2001:db8:1234:5600::", "the rule address was parsed");
                ok_int(rule->prefix, 56, "the rule prefix was parsed");
                ok_int(rule->mode, ND_MODE_AUTO, "the rule mode is auto");
                ok(!rule->autowire, "autowire defaults to off");
#ifdef __linux__
                ok_int(rule->table, 254, "the routing table defaults to 254 (main)");
#endif
            }
        }
    }

    /* --- every rule mode ------------------------------------------------- */

    {
        ok(load("proxy ut1 {\n"
                "    rule 2001:db8:0:1::/64 {\n"
                "        iface ut1d\n"
                "    }\n"
                "    rule 2001:db8:0:2::/64 {\n"
                "        static\n"
                "    }\n"
                "    rule 2001:db8:0:3::/64 {\n"
                "        auto\n"
                "    }\n"
                "}\n"),
           "iface, static and auto rules parse together");

        nd_proxy_t *proxy = nd_proxy_find("ut1");
        ok(proxy != NULL, "the proxy was created");

        if (proxy) {
            int count = 0;
            ND_LL_COUNT(proxy->rules, count, next);
            ok_int(count, 3, "all three rules were kept");

            nd_rule_t *r0 = rule_at(proxy, 0);
            nd_rule_t *r1 = rule_at(proxy, 1);
            nd_rule_t *r2 = rule_at(proxy, 2);

            if (r0 && r1 && r2) {
                ok_int(r0->mode, ND_MODE_IFACE, "the first rule is an iface rule");
                ok_str(r0->ifname, "ut1d", "the iface rule remembered its interface");
                ok_int(r1->mode, ND_MODE_STATIC, "the second rule is static");
                ok_int(r2->mode, ND_MODE_AUTO, "the third rule is auto");
            }
        }
    }

    /* --- prefix handling -------------------------------------------------- */

    {
        ok(load("proxy ut2 {\n"
                "    rule 2001:db8::1 {\n"
                "        static\n"
                "    }\n"
                "}\n"),
           "a rule with no prefix parses");

        nd_proxy_t *proxy = nd_proxy_find("ut2");
        nd_rule_t *rule = proxy ? rule_at(proxy, 0) : NULL;

        ok(rule != NULL, "the rule was created");
        if (rule)
            ok_int(rule->prefix, 128, "a rule with no prefix means /128, not /0");
    }

    /* A trailing slash with no number is a typo, and in 0.2.x it parsed as
     * /0 -- a rule matching every address on the internet.  The 1.0 parser
     * must reject it. */
    ok(!load("proxy ut3 {\n"
             "    rule 2001:db8::/ {\n"
             "        static\n"
             "    }\n"
             "}\n"),
       "a rule with a trailing slash and no prefix is rejected");

    ok(!load("proxy ut4 {\n"
             "    rule 2001:db8::/129 {\n"
             "        static\n"
             "    }\n"
             "}\n"),
       "a prefix above /128 is rejected, not clamped");

    ok(!load("proxy ut5 {\n"
             "    rule 2001:db8::/-1 {\n"
             "        static\n"
             "    }\n"
             "}\n"),
       "a negative prefix is rejected");

    ok(!load("proxy ut6 {\n"
             "    rule not:an:address::/64 {\n"
             "        static\n"
             "    }\n"
             "}\n"),
       "a malformed address is rejected");

    /* --- mode is mandatory and exclusive ---------------------------------- */

    ok(!load("proxy ut7 {\n"
             "    rule 2001:db8::/64 {\n"
             "    }\n"
             "}\n"),
       "a rule with no mode is rejected");

    ok(!load("proxy ut8 {\n"
             "    rule 2001:db8::/64 {\n"
             "        static\n"
             "        auto\n"
             "    }\n"
             "}\n"),
       "static and auto together are rejected");

    ok(!load("proxy ut9 {\n"
             "    rule 2001:db8::/64 {\n"
             "        auto\n"
             "        iface eth0\n"
             "    }\n"
             "}\n"),
       "auto and iface together are rejected");

    /* --- autowire is only meaningful with iface --------------------------- */

    ok(!load("proxy ut10 {\n"
             "    rule 2001:db8::/64 {\n"
             "        auto\n"
             "        autowire yes\n"
             "    }\n"
             "}\n"),
       "autowire with auto is rejected");

    ok(!load("proxy ut11 {\n"
             "    rule 2001:db8::/64 {\n"
             "        static\n"
             "        autowire yes\n"
             "    }\n"
             "}\n"),
       "autowire with static is rejected");

    {
        ok(load("proxy ut12 {\n"
                "    rule 2001:db8::/64 {\n"
                "        iface ut12d\n"
                "        autowire yes\n" TABLE_LINE
                "    }\n"
                "}\n"),
           "autowire with iface is accepted");

        nd_proxy_t *proxy = nd_proxy_find("ut12");
        nd_rule_t *rule = proxy ? rule_at(proxy, 0) : NULL;

        if (rule) {
            ok(rule->autowire, "autowire was applied");
#ifndef __FreeBSD__
            ok_int(rule->table, 100, "an explicit routing table was applied");
#endif
        }
    }

    /* --- rewrite ----------------------------------------------------------- */

    {
        ok(load("proxy ut13 {\n"
                "    rule 2001:db8:a::/48 {\n"
                "        iface ut13d\n"
                "        rewrite fd00::/48\n"
                "    }\n"
                "}\n"),
           "a rewrite rule parses");

        nd_proxy_t *proxy = nd_proxy_find("ut13");
        nd_rule_t *rule = proxy ? rule_at(proxy, 0) : NULL;

        if (rule) {
            ok_str(nd_ntoa(&rule->rewrite_tgt), "fd00::", "the rewrite prefix was parsed");
            ok_int(rule->rewrite_pflen, 48, "the rewrite prefix length was parsed");
        }
    }

    {
        ok(load("proxy ut14 {\n"
                "    rule 2001:db8:a::/48 {\n"
                "        iface ut14d\n"
                "        rewrite fd00::1\n"
                "    }\n"
                "}\n"),
           "a rewrite with no prefix parses");

        nd_proxy_t *proxy = nd_proxy_find("ut14");
        nd_rule_t *rule = proxy ? rule_at(proxy, 0) : NULL;

        if (rule)
            ok_int(rule->rewrite_pflen, 128, "a rewrite with no prefix means /128");
    }

    /* --- link-layer target overrides ---------------------------------------- */

    {
        ok(load("proxy ut15 {\n"
                "    target 02:00:00:00:00:aa\n"
                "    rule 2001:db8::/64 {\n"
                "        static\n"
                "    }\n"
                "    rule 2001:db8:1::/64 {\n"
                "        static\n"
                "        target 02:00:00:00:00:bb\n"
                "    }\n"
                "}\n"),
           "proxy-level and rule-level target overrides parse");

        nd_proxy_t *proxy = nd_proxy_find("ut15");

        if (proxy) {
            nd_lladdr_t want_proxy = fake_lladdr("02:00:00:00:00:aa");
            nd_lladdr_t want_rule = fake_lladdr("02:00:00:00:00:bb");

            ok(nd_lladdr_eq(&proxy->target, &want_proxy), "the proxy target was parsed");

            nd_rule_t *r0 = rule_at(proxy, 0);
            nd_rule_t *r1 = rule_at(proxy, 1);

            /* A rule with no target of its own inherits the proxy's, which
             * is how `target` at proxy scope is documented to behave. */
            if (r0)
                ok(nd_lladdr_eq(&r0->target, &want_proxy), "a rule inherits the proxy target");
            if (r1)
                ok(nd_lladdr_eq(&r1->target, &want_rule), "a rule target overrides the proxy target");
        }
    }

    ok(!load("proxy ut16 {\n"
             "    rule 2001:db8::/64 {\n"
             "        static\n"
             "        target not-a-mac\n"
             "    }\n"
             "}\n"),
       "a malformed link-layer address is rejected");

    /* --- global settings ------------------------------------------------------ */

    {
        int old_valid = nd_conf_valid_ttl, old_invalid = nd_conf_invalid_ttl;
        int old_limit = nd_conf_retrans_limit, old_time = nd_conf_retrans_time;
        bool old_keepalive = nd_conf_keepalive;

        ok(load("valid-ttl 20000\n"
                "invalid-ttl 5000\n"
                "retrans-limit 5\n"
                "retrans-time 2000\n"
                "keepalive yes\n"),
           "global settings parse outside any proxy block");

        ok_int(nd_conf_valid_ttl, 20000, "valid-ttl was applied");
        ok_int(nd_conf_invalid_ttl, 5000, "invalid-ttl was applied");
        ok_int(nd_conf_retrans_limit, 5, "retrans-limit was applied");
        ok_int(nd_conf_retrans_time, 2000, "retrans-time was applied");
        ok(nd_conf_keepalive, "keepalive was applied");

        /* Out-of-range values are rejected rather than clamped, so a
         * mistyped TTL cannot silently become something else. */
        ok(!load("valid-ttl 5000\n"), "valid-ttl below its 10000 minimum is rejected");
        ok(!load("invalid-ttl 999\n"), "invalid-ttl below its 1000 minimum is rejected");
        ok(!load("retrans-limit 11\n"), "retrans-limit above its maximum of 10 is rejected");
        ok(!load("retrans-time 60001\n"), "retrans-time above its maximum is rejected");

        /* retrans-limit 0 is in range, and the STALE backoff takes it
         * modulo -- guarding that division is what the merged #93 fixed. */
        ok(load("retrans-limit 0\n"), "retrans-limit 0 is accepted");

        nd_conf_valid_ttl = old_valid;
        nd_conf_invalid_ttl = old_invalid;
        nd_conf_retrans_limit = old_limit;
        nd_conf_retrans_time = old_time;
        nd_conf_keepalive = old_keepalive;
    }

    /* `renew` was listed in the table with min 0 and max 0, so the only
     * value it accepted was the one it already had -- and nothing read it.
     * It is gone; if it ever comes back it needs bounds that permit a
     * value, and this assertion is the reminder. */
    ok(!load("renew 5000\n"), "renew is not a recognised option");

    /* `stale-ttl` has a variable and a default but no entry in the parser
     * table at all, so the 30s STALE timeout cannot be configured. */
    ok(!load("stale-ttl 10000\n"), "stale-ttl is not a recognised option");

    /* --- comments and whitespace ----------------------------------------------- */

    {
        ok(load("# a leading comment\n"
                "\n"
                "valid-ttl 30000   # trailing comment\n"
                "\n"
                "proxy ut17 {\n"
                "    # a comment inside a block\n"
                "    rule 2001:db8::/64 {\n"
                "        static   # and inside a rule\n"
                "    }\n"
                "}\n"),
           "# comments and blank lines are ignored");

        ok(nd_proxy_find("ut17") != NULL, "the proxy after a comment was still created");
    }

    /* README.md documents C-style comments, so the parser has to have
     * them. They may span lines, which means ndL_skip() consumes them
     * rather than leaving them to the caller's end-of-line handling. */
    {
        ok(load("/* a C-style comment */\n"
                "valid-ttl 30000\n"),
           "a C-style comment is accepted");

        ok(load("/* a comment\n"
                "   spanning\n"
                "   several lines */\n"
                "valid-ttl 30000\n"),
           "a C-style comment may span lines");

        ok(load("proxy ut21 { /* inline */\n"
                "    rule 2001:db8::/64 { /* here too */\n"
                "        static\n"
                "    }\n"
                "}\n"),
           "a C-style comment is accepted inside a block");

        ok(nd_proxy_find("ut21") != NULL, "the surrounding configuration still parsed");

        /* An unterminated comment swallows the rest of the file, so the
         * block it was opened in never closes. */
        ok(!load("proxy ut22 {\n"
                 "    /* unterminated\n"
                 "    rule 2001:db8::/64 {\n"
                 "        static\n"
                 "    }\n"
                 "}\n"),
           "an unterminated C-style comment is an error, not a silent truncation");
    }

    /* --- structural errors ------------------------------------------------------ */

    ok(!load("proxy ut18 {\n"
             "    rule 2001:db8::/64 {\n"
             "        static\n"
             "    }\n"),
       "an unterminated proxy block is rejected");

    ok(!load("}\n"), "a stray closing brace is rejected");

    ok(!load("not-a-key yes\n"), "an unknown key is rejected");

    ok(!load("proxy ut19 {\n"
             "    router yes\n"
             "    rule 2001:db8::/64 {\n"
             "        static\n"
             "    }\n"
             "    valid-ttl 30000\n"
             "}\n"),
       "a global key inside a proxy block is rejected");

    ok(!load("proxy {\n"
             "}\n"),
       "a proxy with no interface name is rejected");

    /* A second proxy for an interface that already has one is a
     * configuration mistake, not a merge. */
    {
        ok(load("proxy ut20 {\n"
                "    rule 2001:db8::/64 {\n"
                "        static\n"
                "    }\n"
                "}\n"),
           "the first proxy for an interface is accepted");

        ok(!load("proxy ut20 {\n"
                 "    rule 2001:db8:1::/64 {\n"
                 "        static\n"
                 "    }\n"
                 "}\n"),
           "a duplicate proxy for the same interface is rejected");
    }

    /* --- the shipped example --------------------------------------------------- */

    /* ndppd.conf-dist is what a new user copies.  Parsing it here means the
     * documented example and the parser cannot drift apart silently. */
    {
        char path[512];
        snprintf(path, sizeof(path), "%s/ndppd.conf-dist", NDPPD_TEST_SRCDIR);

        FILE *fp = fopen(path, "r");

        if (!fp) {
            tap_diag("  cannot open %s -- skipping", path);
        } else {
            char buf[8192];
            size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
            buf[n] = 0;
            fclose(fp);

            /* The shipped file names a real interface; rename it so the
             * proxy list does not collide with the cases above. */
            char *p;
            while ((p = strstr(buf, "proxy eth0")) != NULL)
                memcpy(p, "proxy dist", 10);

            ok(load(buf), "the shipped ndppd.conf-dist parses");

            /* It used to document three keys the parser does not have --
             * `retransmit-limit`, `retransmit-time` and `renew` -- all
             * commented out, so a user only found out by uncommenting the
             * line the file told them to uncomment. */
            ok(strstr(buf, "retransmit-limit") == NULL,
               "ndppd.conf-dist does not document a retransmit-limit key");
            ok(strstr(buf, "retransmit-time") == NULL,
               "ndppd.conf-dist does not document a retransmit-time key");
            ok(strstr(buf, "renew") == NULL,
               "ndppd.conf-dist does not document the removed renew key");
        }
    }
}
