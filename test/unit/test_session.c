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
 * session.c is the part of ndppd that decides whether to answer a
 * solicitation, and it is where the behaviour users actually complain about
 * lives: #75 ("proxy stops working after some time") and #68 are both
 * state-machine reports.
 *
 * The integration suite can only see the outcome -- a ping goes through or
 * it does not.  These tests link session.c against test/unit/fake.c
 * instead of iface.c and rt.c, which makes the whole state machine
 * observable and, more usefully, makes time an ordinary variable.  A VALID
 * session ageing into STALE after 30 seconds is tested by assigning to
 * nd_current_time, not by waiting.
 *
 * Sessions live in a static hash table with no teardown, so every case uses
 * its own target address.
 */
#include <string.h>

#include "fake.h"
#include "ndppd.h"
#include "tap.h"

extern int nd_conf_invalid_ttl;
extern int nd_conf_valid_ttl;
extern int nd_conf_stale_ttl;
extern int nd_conf_retrans_limit;
extern int nd_conf_retrans_time;
extern bool nd_conf_keepalive;

/* A proxy and a rule built by hand, bypassing the config parser so that a
 * failure here cannot be a parser failure in disguise. */
static nd_proxy_t ndL_proxy;
static nd_rule_t ndL_rule;

static nd_rule_t *rule_for(nd_mode_t mode, const char *prefix, int pflen)
{
    ndL_proxy = (nd_proxy_t){ 0 };
    strcpy(ndL_proxy.ifname, "up0");
    ndL_proxy.iface = &fake_iface_up;
    ndL_proxy.router = false;

    ndL_rule = (nd_rule_t){ 0 };
    ndL_rule.proxy = &ndL_proxy;
    ndL_rule.addr = fake_addr(prefix);
    ndL_rule.prefix = pflen;
    ndL_rule.mode = mode;
    ndL_rule.table = 254;
    ndL_rule.iface = mode == ND_MODE_IFACE ? &fake_iface_down : NULL;

    return &ndL_rule;
}

/* Advance the clock and let the daemon's periodic tick run.  ndppd.c calls
 * nd_session_update_all() roughly every 100 ms; `steps` ticks of `ms` each
 * reproduces that without sleeping.
 *
 * An INVALID session that outlives invalid-ttl is freed by the tick that
 * notices, so this stops one tick short of that -- otherwise every caller
 * would be holding a dangling pointer.  Use advance_to_deletion() when the
 * teardown is the thing being tested. */
static void advance(nd_session_t *session, long ms, int steps)
{
    for (int i = 0; i < steps; i++) {
        if (session->state == ND_STATE_INVALID &&
            nd_current_time + ms - session->state_time >= nd_conf_invalid_ttl)
            return;

        nd_current_time += ms;
        nd_session_update(session);
    }
}

/* Runs the session all the way to the tick that frees it.  `session` is a
 * dangling pointer on return and must not be touched again. */
static void advance_to_deletion(nd_session_t *session, long ms, int max_steps)
{
    for (int i = 0; i < max_steps; i++) {
        bool last = session->state == ND_STATE_INVALID &&
                    nd_current_time + ms - session->state_time >= nd_conf_invalid_ttl;

        nd_current_time += ms;
        nd_session_update(session);

        if (last)
            return;
    }
}

/* Upstream keeps using the address: a solicitation arrives, then the daemon
 * ticks.  This is the ordinary steady state of a working proxy, and it is
 * different from advance() in one way that matters -- ins_time stays
 * current, which is what makes session.c decide a session is worth
 * re-probing as it ages out of VALID. */
static void advance_with_traffic(nd_session_t *session, const nd_addr_t *src, const nd_lladdr_t *src_ll, //
                                 long ms, int steps)
{
    for (int i = 0; i < steps; i++) {
        if (session->state == ND_STATE_INVALID &&
            nd_current_time + ms - session->state_time >= nd_conf_invalid_ttl)
            return;

        nd_current_time += ms;
        nd_session_handle_ns(session, src, src_ll);
        nd_session_update(session);
    }
}

void test_session(void)
{
    tap_begin("session");

    const nd_addr_t src = fake_addr("2001:db8::1");
    const nd_lladdr_t src_ll = fake_lladdr("02:00:00:00:00:99");

    /* --- iface mode: probe downstream, answer only once the target replies --- */

    {
        fake_reset();
        nd_rule_t *rule = rule_for(ND_MODE_IFACE, "2001:db8:0:10::", 64);
        nd_addr_t tgt = fake_addr("2001:db8:0:10::2");

        nd_session_t *s = nd_session_create(rule, &tgt);

        ok_int(s->state, ND_STATE_INCOMPLETE, "an iface session starts INCOMPLETE");
        ok_int(fake_ns_count, 1, "creating the session sends one solicitation");
        ok(fake_ns_count && fake_ns[0].iface == &fake_iface_down,
           "the solicitation goes out the downstream interface");
        ok(fake_ns_count && nd_addr_eq(&fake_ns[0].tgt, &tgt), "the solicitation asks for the target");
        ok_int(fake_na_count, 0, "nothing is advertised before the target has answered");

        /* An upstream solicitation while INCOMPLETE must be queued, not
         * answered -- answering here is a claim ndppd cannot back up. */
        nd_session_handle_ns(s, &src, &src_ll);
        ok_int(fake_na_count, 0, "an upstream NS while INCOMPLETE is queued, not answered");

        /* The target replies. */
        nd_session_handle_na(s);

        ok_int(s->state, ND_STATE_VALID, "an advertisement from the target makes the session VALID");
        ok_int(fake_na_count, 1, "the queued subscriber is answered");

        if (fake_na_count) {
            ok(nd_addr_eq(&fake_na[0].dst, &src), "the advertisement goes to the original requester");
            ok(nd_lladdr_eq(&fake_na[0].dst_ll, &src_ll), "...at the MAC it solicited from");
            ok(nd_addr_eq(&fake_na[0].tgt, &tgt), "...and advertises the target");
            ok(fake_na[0].iface == &fake_iface_up, "...on the upstream interface");
            ok(!fake_na[0].has_tgt_ll, "with no target override, ndppd advertises its own MAC");
        }

        /* Once VALID, a further solicitation is answered straight away. */
        int before = fake_na_count;
        nd_session_handle_ns(s, &src, &src_ll);
        ok_int(fake_na_count, before + 1, "a VALID session answers the next NS immediately");
    }

    /* --- duplicate subscribers are not queued twice ------------------------- */

    {
        fake_reset();
        nd_rule_t *rule = rule_for(ND_MODE_IFACE, "2001:db8:0:11::", 64);
        nd_addr_t tgt = fake_addr("2001:db8:0:11::2");

        nd_session_t *s = nd_session_create(rule, &tgt);

        /* A host that retransmits its solicitation must not be answered
         * once per retransmission when the target eventually replies. */
        for (int i = 0; i < 5; i++)
            nd_session_handle_ns(s, &src, &src_ll);

        nd_session_handle_na(s);
        ok_int(fake_na_count, 1, "five identical solicitations produce one advertisement");

        /* Distinct requesters are distinct subscribers, though. */
        fake_reset();
        rule = rule_for(ND_MODE_IFACE, "2001:db8:0:12::", 64);
        tgt = fake_addr("2001:db8:0:12::2");
        s = nd_session_create(rule, &tgt);

        nd_addr_t src2 = fake_addr("2001:db8::7");
        nd_lladdr_t src2_ll = fake_lladdr("02:00:00:00:00:77");

        nd_session_handle_ns(s, &src, &src_ll);
        nd_session_handle_ns(s, &src2, &src2_ll);
        nd_session_handle_na(s);

        ok_int(fake_na_count, 2, "two different requesters each get an advertisement");
    }

    /* --- INCOMPLETE gives up after retrans-limit probes ---------------------- */

    {
        fake_reset();
        nd_conf_retrans_limit = 3;
        nd_conf_retrans_time = 1000;

        nd_rule_t *rule = rule_for(ND_MODE_IFACE, "2001:db8:0:13::", 64);
        nd_addr_t tgt = fake_addr("2001:db8:0:13::2");

        nd_session_t *s = nd_session_create(rule, &tgt);
        ok_int(fake_ns_count, 1, "the first probe goes out on creation");

        /* Nothing answers.  Each retrans-time the daemon probes again,
         * until retrans-limit is exceeded. */
        advance(s, 1000, 3);

        ok_int(s->state, ND_STATE_INVALID, "INCOMPLETE becomes INVALID once retrans-limit is exceeded");
        ok_int(fake_ns_count, 3, "exactly retrans-limit solicitations were sent");

        /* An INVALID session must stop answering but keep its subscribers,
         * so a late advertisement still satisfies them. */
        ok_int(fake_na_count, 0, "an INVALID session has advertised nothing");

        nd_session_handle_ns(s, &src, &src_ll);
        ok_int(fake_na_count, 0, "an INVALID session does not answer a solicitation");

        nd_session_handle_na(s);
        ok_int(s->state, ND_STATE_VALID, "a late advertisement rescues an INVALID session");
        ok_int(fake_na_count, 1, "...and the queued subscriber is answered");
    }

    /* --- probing does not continue forever ----------------------------------- */

    {
        fake_reset();
        nd_conf_retrans_limit = 3;
        nd_conf_retrans_time = 1000;
        nd_conf_invalid_ttl = 10000;

        nd_rule_t *rule = rule_for(ND_MODE_IFACE, "2001:db8:0:14::", 64);
        nd_addr_t tgt = fake_addr("2001:db8:0:14::2");

        nd_session_t *s = nd_session_create(rule, &tgt);

        /* Run well past the point of giving up. If the limit were not
         * enforced this would emit a probe per tick forever, which is the
         * shape of a solicitation storm against a dead target. */
        advance(s, 1000, 8);

        ok(fake_ns_count <= 3, "no further probes after the session went INVALID (sent %d)", fake_ns_count);
    }

    /* --- VALID ages into STALE, and a gratuitous NA defers that --------------- */

    {
        fake_reset();
        nd_conf_valid_ttl = 30000;
        nd_conf_stale_ttl = 30000;
        nd_conf_keepalive = false;

        nd_rule_t *rule = rule_for(ND_MODE_IFACE, "2001:db8:0:15::", 64);
        nd_addr_t tgt = fake_addr("2001:db8:0:15::2");

        nd_session_t *s = nd_session_create(rule, &tgt);
        nd_session_handle_na(s);
        ok_int(s->state, ND_STATE_VALID, "the session is VALID");

        /* Not yet. */
        advance(s, 10000, 2);
        ok_int(s->state, ND_STATE_VALID, "still VALID before valid-ttl has elapsed");

        /* A gratuitous advertisement from the target is proof it is still
         * there, and must push the expiry back (RFC 4861 7.2.5). */
        nd_session_handle_na(s);
        advance(s, 10000, 2);
        ok_int(s->state, ND_STATE_VALID, "a gratuitous NA from the target extends the VALID lifetime");

        /* With nothing further from the target it ages out.  The last NA
         * reset state_time, so valid-ttl is reached one tick after the two
         * above -- step singly, or the session runs straight on through
         * STALE and into INVALID and the transition under test is missed. */
        advance(s, 10000, 1);
        ok_int(s->state, ND_STATE_STALE, "VALID becomes STALE once valid-ttl elapses with no NA");
    }

    /* --- STALE does not answer on reachability it cannot confirm -------------- */

    {
        fake_reset();
        nd_conf_valid_ttl = 30000;
        nd_conf_stale_ttl = 30000;
        nd_conf_retrans_time = 1000;
        nd_conf_keepalive = false;

        nd_rule_t *rule = rule_for(ND_MODE_IFACE, "2001:db8:0:16::", 64);
        nd_addr_t tgt = fake_addr("2001:db8:0:16::2");

        nd_session_t *s = nd_session_create(rule, &tgt);
        nd_session_handle_na(s);

        /* Age it into STALE without any upstream interest, so the VALID
         * handler does not probe on the way out. */
        s->ins_time = nd_current_time - nd_conf_valid_ttl - 1;
        advance(s, 10000, 4);
        ok_int(s->state, ND_STATE_STALE, "the session is STALE");

        int na_before = fake_na_count;
        int ns_before = fake_ns_count;

        nd_current_time += nd_conf_retrans_time;
        nd_session_handle_ns(s, &src, &src_ll);

        /* RFC 4861 7.3.3: STALE means reachability is unknown.  Answering
         * with an OVERRIDE advertisement would overwrite a working entry in
         * the requester's cache with one ndppd cannot stand behind. */
        ok_int(fake_na_count, na_before, "a STALE session does not answer immediately");
        ok(fake_ns_count > ns_before, "a STALE session probes the target instead");

        /* The requester is queued, and answered when the target replies. */
        nd_session_handle_na(s);
        ok_int(s->state, ND_STATE_VALID, "the reply returns the session to VALID");
        ok_int(fake_na_count, na_before + 1, "...and the waiting requester is answered");
    }

    /* --- STALE eventually becomes INVALID ------------------------------------- */

    {
        fake_reset();
        nd_conf_valid_ttl = 30000;
        nd_conf_stale_ttl = 30000;
        nd_conf_keepalive = false;

        nd_rule_t *rule = rule_for(ND_MODE_IFACE, "2001:db8:0:17::", 64);
        nd_addr_t tgt = fake_addr("2001:db8:0:17::2");

        nd_session_t *s = nd_session_create(rule, &tgt);
        nd_session_handle_na(s);

        s->ins_time = nd_current_time - nd_conf_valid_ttl - 1;
        advance(s, 10000, 4);
        ok_int(s->state, ND_STATE_STALE, "the session is STALE");

        advance(s, 10000, 4);
        ok_int(s->state, ND_STATE_INVALID, "STALE becomes INVALID once stale-ttl elapses");
    }

    /* --- retrans-limit 0 must not divide by zero ------------------------------ */

    {
        fake_reset();
        nd_conf_retrans_limit = 0;
        nd_conf_retrans_time = 1000;
        nd_conf_valid_ttl = 30000;
        nd_conf_stale_ttl = 30000;
        nd_conf_keepalive = true;

        nd_rule_t *rule = rule_for(ND_MODE_IFACE, "2001:db8:0:18::", 64);
        nd_addr_t tgt = fake_addr("2001:db8:0:18::2");

        nd_session_t *s = nd_session_create(rule, &tgt);
        nd_session_handle_na(s);

        /* The STALE backoff takes ons_count modulo retrans-limit. The
         * config permits 0, and before #93 that was a division by zero. */
        advance(s, 10000, 10);

        ok(s->state == ND_STATE_STALE || s->state == ND_STATE_INVALID,
           "retrans-limit 0 drives the state machine without dividing by zero");

        nd_conf_retrans_limit = 3;
        nd_conf_keepalive = false;
    }

    /* --- static mode ----------------------------------------------------------- */

    {
        fake_reset();
        nd_rule_t *rule = rule_for(ND_MODE_STATIC, "2001:db8:0:19::", 64);
        nd_addr_t tgt = fake_addr("2001:db8:0:19::2");

        nd_session_t *s = nd_session_create(rule, &tgt);

        ok_int(s->state, ND_STATE_VALID, "a static session is VALID immediately");
        ok_int(fake_ns_count, 0, "a static session solicits nothing");
        ok(s->iface == NULL, "a static session has no downstream interface");

        nd_session_handle_ns(s, &src, &src_ll);
        ok_int(fake_na_count, 1, "a static session answers the first solicitation");

        if (fake_na_count)
            ok(fake_na[0].iface == &fake_iface_up, "the advertisement goes out the proxy interface");
    }

    /* A static session has no downstream interface, but nd_session_update()
     * does not know that: when VALID ages into STALE it calls
     * nd_iface_send_ns(session->iface, ...) unconditionally.  Against the
     * real iface.c that reads iface->lladdr off a NULL pointer and the
     * daemon dies -- roughly valid-ttl after a static rule last saw
     * traffic, which is to say under exactly the load it is meant to carry.
     *
     * The fake records the call instead of dereferencing, so the bug shows
     * up here as a solicitation sent on no interface at all. */
    {
        fake_reset();
        nd_conf_valid_ttl = 30000;
        nd_conf_keepalive = false;

        nd_rule_t *rule = rule_for(ND_MODE_STATIC, "2001:db8:0:20::", 64);
        nd_addr_t tgt = fake_addr("2001:db8:0:20::2");

        nd_session_t *s = nd_session_create(rule, &tgt);

        /* Upstream keeps using the address, so ins_time stays recent -- and
         * a recent ins_time is exactly what makes nd_session_update()
         * decide the session is worth re-probing when VALID ages out. */
        advance_with_traffic(s, &src, &src_ll, 1000, 40);

        int null_iface_ns = 0;
        for (int i = 0; i < fake_ns_count; i++)
            if (fake_ns[i].iface == NULL)
                null_iface_ns++;

        todo("static sessions probe on a NULL interface; segfaults against real iface.c (see plan/)");
        ok_todo(null_iface_ns == 0, "a static session never solicits on a NULL interface");

        /* Pinned alongside it: an assertion on *current* behaviour, so the
         * bug cannot quietly change shape while it is open.  When it is
         * fixed this one starts failing, which is the reminder to delete
         * the todo above and turn it into an enforcing assertion. */
        ok(null_iface_ns > 0,
           "current behaviour: %d solicitation(s) attempted on a NULL interface", null_iface_ns);

        /* Against the real iface.c the first of those reads iface->lladdr
         * off a NULL pointer.  It is reached here after forty seconds of
         * ordinary upstream traffic against a static rule. */
        ok(s->state == ND_STATE_STALE || s->state == ND_STATE_INVALID,
           "the static session did age out of VALID, which is what triggers it");
    }

    /* --- auto mode ------------------------------------------------------------- */

    {
        fake_reset();
        fake_route("2001:db8:0:21::/64", FAKE_IF_DOWN_INDEX, 254);

        nd_rule_t *rule = rule_for(ND_MODE_AUTO, "2001:db8:0:21::", 64);
        nd_addr_t tgt = fake_addr("2001:db8:0:21::2");

        nd_session_t *s = nd_session_create(rule, &tgt);

        ok_int(s->state, ND_STATE_INCOMPLETE, "an auto session with a route starts INCOMPLETE");
        ok(s->iface == &fake_iface_down, "the route's output interface was adopted");
        ok_int(fake_ns_count, 1, "the target is solicited on that interface");

        nd_session_handle_na(s);
        ok_int(s->state, ND_STATE_VALID, "the session becomes VALID when the target replies");
    }

    /* An auto rule whose route points back out the proxy interface would
     * make ndppd solicit a target on the same link it is proxying for,
     * answering its own solicitation. */
    {
        fake_reset();
        fake_route("2001:db8:0:22::/64", FAKE_IF_UP_INDEX, 254);

        nd_rule_t *rule = rule_for(ND_MODE_AUTO, "2001:db8:0:22::", 64);
        nd_addr_t tgt = fake_addr("2001:db8:0:22::2");

        nd_session_t *s = nd_session_create(rule, &tgt);

        ok_int(s->state, ND_STATE_INVALID, "an auto route back out the proxy interface is refused");
        ok_int(fake_ns_count, 0, "...and nothing is solicited");
    }

    /* The #93 fix: a container that starts after the first solicitation
     * arrives.  The session is created INVALID because no route exists yet,
     * and before the fix it stayed that way until invalid-ttl without ever
     * re-checking -- long after the requester gave up. */
    {
        fake_reset();
        nd_rule_t *rule = rule_for(ND_MODE_AUTO, "2001:db8:0:23::", 64);
        nd_addr_t tgt = fake_addr("2001:db8:0:23::2");

        nd_session_t *s = nd_session_create(rule, &tgt);

        ok_int(s->state, ND_STATE_INVALID, "an auto session with no route starts INVALID");
        ok_int(fake_ns_count, 0, "nothing is solicited while there is no route");

        /* The route appears. */
        fake_route("2001:db8:0:23::/64", FAKE_IF_DOWN_INDEX, 254);

        nd_session_handle_ns(s, &src, &src_ll);

        ok_int(s->state, ND_STATE_INCOMPLETE, "the next NS re-checks the table and starts probing");
        ok_int(fake_ns_count, 1, "...and the target is finally solicited");

        nd_session_handle_na(s);
        ok_int(s->state, ND_STATE_VALID, "the session completes");
        ok_int(fake_na_count, 1, "the requester that was waiting is answered");
    }

    /* --- rewrite ---------------------------------------------------------------- */

    {
        fake_reset();
        nd_rule_t *rule = rule_for(ND_MODE_IFACE, "2001:db8:a::", 48);
        rule->rewrite_tgt = fake_addr("fd00::");
        rule->rewrite_pflen = 48;

        nd_addr_t tgt = fake_addr("2001:db8:a::1");
        nd_session_t *s = nd_session_create(rule, &tgt);

        nd_addr_t want = fake_addr("fd00::1");

        ok(nd_addr_eq(&s->tgt, &tgt), "the session keeps the public target");
        ok(nd_addr_eq(&s->tgt_r, &want), "...and a rewritten target of fd00::1");
        ok(fake_ns_count && nd_addr_eq(&fake_ns[0].tgt, &want), "the downstream solicitation asks for fd00::1");

        nd_session_handle_na(s);
        nd_session_handle_ns(s, &src, &src_ll);

        /* Upstream must never learn the internal address. */
        bool leaked = false;
        for (int i = 0; i < fake_na_count; i++)
            if (nd_addr_eq(&fake_na[i].tgt, &want))
                leaked = true;

        ok(!leaked, "the rewritten address is never advertised upstream");
        ok(fake_na_count && nd_addr_eq(&fake_na[fake_na_count - 1].tgt, &tgt),
           "the public address is what gets advertised");
    }

    /* --- target MAC override ------------------------------------------------------ */

    {
        fake_reset();
        nd_rule_t *rule = rule_for(ND_MODE_STATIC, "2001:db8:0:24::", 64);
        rule->target = fake_lladdr("02:00:00:00:00:ab");

        nd_addr_t tgt = fake_addr("2001:db8:0:24::2");
        nd_session_t *s = nd_session_create(rule, &tgt);

        nd_session_handle_ns(s, &src, &src_ll);

        ok_int(fake_na_count, 1, "the session advertised");

        if (fake_na_count) {
            nd_lladdr_t want = fake_lladdr("02:00:00:00:00:ab");
            ok(fake_na[0].has_tgt_ll, "a rule target makes ndppd advertise an explicit MAC");
            ok(nd_lladdr_eq(&fake_na[0].tgt_ll, &want), "...and it is the configured one");
        }
    }

    /* --- the router flag ------------------------------------------------------------ */

    {
        fake_reset();
        nd_rule_t *rule = rule_for(ND_MODE_STATIC, "2001:db8:0:25::", 64);
        rule->proxy->router = true;

        nd_addr_t tgt = fake_addr("2001:db8:0:25::2");
        nd_session_t *s = nd_session_create(rule, &tgt);
        nd_session_handle_ns(s, &src, &src_ll);

        ok(fake_na_count && fake_na[0].router, "router yes sets the Router flag on advertisements");
    }

    /* --- DAD and solicitations with no source link-layer address ---------------------- */

    {
        fake_reset();
        nd_rule_t *rule = rule_for(ND_MODE_STATIC, "2001:db8:0:26::", 64);
        nd_addr_t tgt = fake_addr("2001:db8:0:26::2");

        nd_session_t *s = nd_session_create(rule, &tgt);

        /* Duplicate address detection: the source is :: and there is no
         * SLLAO to answer to, so the advertisement goes to all-nodes. */
        nd_addr_t unspec = fake_addr("::");
        nd_session_handle_ns(s, &unspec, NULL);

        ok_int(fake_na_count, 1, "a DAD solicitation is answered");

        if (fake_na_count) {
            nd_addr_t allnodes = fake_addr("ff02::1");
            nd_lladdr_t allnodes_ll = fake_lladdr("33:33:00:00:00:01");

            ok(nd_addr_eq(&fake_na[0].dst, &allnodes), "the DAD reply goes to ff02::1");
            ok(nd_lladdr_eq(&fake_na[0].dst_ll, &allnodes_ll), "...at 33:33:00:00:00:01");
        }
    }

    /* A solicitation that cannot be answered must not crash on the NULL
     * link-layer address, and must not queue a subscriber it could never
     * reach. */
    {
        fake_reset();
        nd_rule_t *rule = rule_for(ND_MODE_IFACE, "2001:db8:0:27::", 64);
        nd_addr_t tgt = fake_addr("2001:db8:0:27::2");

        nd_session_t *s = nd_session_create(rule, &tgt);

        nd_addr_t unspec = fake_addr("::");
        nd_session_handle_ns(s, &unspec, NULL);

        ok_int(fake_na_count, 0, "an INCOMPLETE session does not answer a DAD solicitation");

        nd_session_handle_na(s);
        ok_int(fake_na_count, 0, "...and queued nothing that it could not address");
    }

    /* --- autowire ------------------------------------------------------------------- */

    {
        fake_reset();
        nd_rule_t *rule = rule_for(ND_MODE_IFACE, "2001:db8:0:28::", 64);
        rule->autowire = true;
        rule->table = 100;

        nd_addr_t tgt = fake_addr("2001:db8:0:28::2");
        nd_session_t *s = nd_session_create(rule, &tgt);

        ok_int(fake_route_op_count, 0, "autowire adds no route while the session is INCOMPLETE");

        nd_session_handle_na(s);

        ok_int(fake_route_op_count, 1, "a route is added when the session becomes VALID");

        if (fake_route_op_count) {
            ok(fake_route_ops[0].added, "the operation is an addition");
            ok(nd_addr_eq(&fake_route_ops[0].dst, &tgt), "the route is for the target");
            ok_int(fake_route_ops[0].pflen, 128, "...as a host route");
            ok_int(fake_route_ops[0].oif, FAKE_IF_DOWN_INDEX, "...out the downstream interface");
            ok_int(fake_route_ops[0].table, 100, "...in the configured table");
        }

        /* Let it expire all the way to deletion and the route must come
         * back out again, or a dead container keeps a route forever. */
        nd_conf_valid_ttl = 30000;
        nd_conf_stale_ttl = 30000;
        nd_conf_invalid_ttl = 10000;
        nd_conf_keepalive = false;

        s->ins_time = nd_current_time - nd_conf_valid_ttl - 1;
        advance_to_deletion(s, 10000, 32);
        s = NULL;

        bool removed = false;
        for (int i = 0; i < fake_route_op_count; i++)
            if (!fake_route_ops[i].added && nd_addr_eq(&fake_route_ops[i].dst, &tgt))
                removed = true;

        ok(removed, "the autowired route is removed when the session expires");
    }

    /* --- session lookup ---------------------------------------------------------------- */

    {
        fake_reset();
        nd_rule_t *rule = rule_for(ND_MODE_IFACE, "2001:db8:0:29::", 64);
        nd_addr_t tgt = fake_addr("2001:db8:0:29::2");

        nd_session_t *s = nd_session_create(rule, &tgt);

        ok(nd_session_find(&tgt, &ndL_proxy) == s, "a session is found by target and proxy");

        nd_addr_t other = fake_addr("2001:db8:0:29::3");
        ok(nd_session_find(&other, &ndL_proxy) == NULL, "a different target finds no session");

        /* The reverse table is how an incoming advertisement is matched
         * back to the session that solicited it. */
        ok(nd_session_find_r(&tgt, &fake_iface_down) == s, "a session is found by rewritten target and interface");
        ok(nd_session_find_r(&tgt, &fake_iface_up) == NULL, "...but not from the wrong interface");
    }

    /* Rewritten sessions must be reachable from the rewritten address on
     * the reverse lookup, or the advertisement that comes back from the
     * real host is dropped as unsolicited. */
    {
        fake_reset();
        nd_rule_t *rule = rule_for(ND_MODE_IFACE, "2001:db8:b::", 48);
        rule->rewrite_tgt = fake_addr("fd00::");
        rule->rewrite_pflen = 48;

        nd_addr_t tgt = fake_addr("2001:db8:b::5");
        nd_addr_t rewritten = fake_addr("fd00::5");

        nd_session_t *s = nd_session_create(rule, &tgt);

        ok(nd_session_find(&tgt, &ndL_proxy) == s, "a rewritten session is found by its public address");
        ok(nd_session_find_r(&rewritten, &fake_iface_down) == s,
           "...and by its rewritten address on the reverse lookup");
    }

    nd_conf_retrans_limit = 3;
    nd_conf_retrans_time = 1000;
    nd_conf_valid_ttl = 30000;
    nd_conf_invalid_ttl = 10000;
    nd_conf_keepalive = false;
}
