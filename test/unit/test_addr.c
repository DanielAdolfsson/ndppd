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
 * addr.c is where a mistake is both easiest to make and hardest to notice:
 * the prefix helpers are written against a byte-order-dependent table of
 * 32-bit masks, and a rule that matches one bit too many or too few still
 * looks plausible in a config file and in a log line.  #67 is an
 * endianness report against exactly this code.
 *
 * So rather than spot-checking a handful of prefixes, the tests below check
 * every prefix length from 0 to 128 against an independent byte-at-a-time
 * reference.  The reference is deliberately written in a different style
 * from the implementation -- if both were written the same way they would
 * share the same bug.
 */
#include <string.h>

#include "fake.h"
#include "ndppd.h"
#include "tap.h"

/* Independent reference: does the first `pflen` bits of a and b agree? */
static bool ref_match(const nd_addr_t *a, const nd_addr_t *b, unsigned pflen)
{
    for (unsigned bit = 0; bit < pflen; bit++) {
        unsigned byte = bit / 8;
        unsigned mask = 0x80u >> (bit % 8);

        if ((a->u8[byte] & mask) != (b->u8[byte] & mask))
            return false;
    }

    return true;
}

/* Independent reference: first `pflen` bits from a, the rest from b. */
static nd_addr_t ref_combine(const nd_addr_t *a, const nd_addr_t *b, unsigned pflen)
{
    nd_addr_t out;

    for (unsigned bit = 0; bit < 128; bit++) {
        unsigned byte = bit / 8;
        unsigned mask = 0x80u >> (bit % 8);
        const nd_addr_t *src = bit < pflen ? a : b;

        if (bit % 8 == 0)
            out.u8[byte] = 0;

        out.u8[byte] |= src->u8[byte] & mask;
    }

    return out;
}

void test_addr(void)
{
    tap_begin("addr");

    /* --- nd_ntoa / parsing round-trip ---------------------------------- */

    ok_str(nd_ntoa(&(nd_addr_t){ { 0 } }), "::", "nd_ntoa renders the unspecified address");
    ok_str(nd_ntoa(NULL), "(null)", "nd_ntoa tolerates NULL");

    static const char *roundtrip[] = {
        "::",
        "::1",
        "2001:db8::1",
        "2001:db8:0:1::2",
        "fe80::1",
        "ff02::1",
        "ff02::1:ff00:1",
        "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff",
    };

    for (size_t i = 0; i < sizeof(roundtrip) / sizeof(roundtrip[0]); i++) {
        nd_addr_t a = fake_addr(roundtrip[i]);
        ok_str(nd_ntoa(&a), roundtrip[i], "%s round-trips through nd_ntoa", roundtrip[i]);
    }

    /* nd_ntoa rotates three static buffers so it can be used more than once
     * in a single printf.  Several log lines in proxy.c and session.c rely
     * on that; if the rotation broke they would all print the same address. */
    {
        nd_addr_t a = fake_addr("2001:db8::1");
        nd_addr_t b = fake_addr("2001:db8::2");
        nd_addr_t c = fake_addr("2001:db8::3");

        const char *sa = nd_ntoa(&a);
        const char *sb = nd_ntoa(&b);
        const char *sc = nd_ntoa(&c);

        ok(!strcmp(sa, "2001:db8::1") && !strcmp(sb, "2001:db8::2") && !strcmp(sc, "2001:db8::3"),
           "three nd_ntoa results stay valid at once");
    }

    /* --- nd_addr_eq ----------------------------------------------------- */

    {
        nd_addr_t a = fake_addr("2001:db8::1");
        nd_addr_t b = fake_addr("2001:db8::1");
        nd_addr_t c = fake_addr("2001:db8::2");

        ok(nd_addr_eq(&a, &b), "nd_addr_eq is true for equal addresses");
        ok(!nd_addr_eq(&a, &c), "nd_addr_eq is false for different addresses");

        /* A difference in the very last bit must still register. */
        nd_addr_t d = a;
        d.u8[15] ^= 1;
        ok(!nd_addr_eq(&a, &d), "nd_addr_eq notices a difference in the last bit");

        /* ...and so must one in the very first. */
        nd_addr_t e = a;
        e.u8[0] ^= 0x80;
        ok(!nd_addr_eq(&a, &e), "nd_addr_eq notices a difference in the first bit");
    }

    /* --- nd_addr_match against the reference, every prefix length ------- */

    {
        static const char *pairs[][2] = {
            { "2001:db8::1", "2001:db8::2" },
            { "2001:db8:0:1::2", "2001:db8:0:2::2" },
            { "2001:db8::1", "2001:db8::1" },
            { "::", "8000::" },
            { "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "::" },
            { "2001:db8:1234:5600::", "2001:db8:1234:56ff::" },
            { "fe80::1", "fe80::1:0:0:1" },
        };

        int mismatches = 0;

        for (size_t i = 0; i < sizeof(pairs) / sizeof(pairs[0]); i++) {
            nd_addr_t a = fake_addr(pairs[i][0]);
            nd_addr_t b = fake_addr(pairs[i][1]);

            for (unsigned pflen = 0; pflen <= 128; pflen++) {
                if (nd_addr_match(&a, &b, pflen) != ref_match(&a, &b, pflen)) {
                    tap_diag("  nd_addr_match(%s, %s, %u) disagrees with reference", pairs[i][0], pairs[i][1], pflen);
                    mismatches++;
                }
            }
        }

        ok_int(mismatches, 0, "nd_addr_match agrees with a bitwise reference at all 129 prefix lengths");
    }

    /* The boundary cases the table-driven implementation is most likely to
     * get wrong, spelled out so a failure names the prefix. */
    {
        nd_addr_t a = fake_addr("2001:db8::");
        nd_addr_t b = fake_addr("2001:db9::");

        ok(nd_addr_match(&a, &b, 0), "/0 matches everything");
        ok(nd_addr_match(&a, &b, 31), "2001:db8:: and 2001:db9:: share a /31");
        ok(!nd_addr_match(&a, &b, 32), "2001:db8:: and 2001:db9:: differ at /32");
        ok(nd_addr_match(&a, &a, 128), "/128 matches an identical address");
        ok(!nd_addr_match(&a, &b, 128), "/128 does not match a different address");

        /* A prefix longer than an address cannot be satisfied.  conf.c
         * refuses to parse one, so this is defence in depth rather than a
         * reachable path -- but nd_addr_match is also called with values
         * from the kernel's routing table. */
        ok(!nd_addr_match(&a, &a, 129), "a prefix longer than 128 never matches");
    }

    /* 32-bit word boundaries: the implementation walks u32[] words, so the
     * three interior boundaries are where an off-by-one would hide. */
    {
        nd_addr_t base = fake_addr("::");

        for (unsigned boundary = 32; boundary <= 96; boundary += 32) {
            nd_addr_t other = base;
            other.u8[boundary / 8] = 0x80; /* flip the first bit past the boundary */

            ok(nd_addr_match(&base, &other, boundary), "/%u matches when only the next bit differs", boundary);
            ok(!nd_addr_match(&base, &other, boundary + 1), "/%u does not", boundary + 1);
        }
    }

    /* --- nd_addr_combine ------------------------------------------------ */

    {
        /* This is what a `rewrite` rule does: keep the rewrite prefix and
         * graft the original target's host bits onto it. */
        nd_addr_t pfx = fake_addr("fd00::");
        nd_addr_t tgt = fake_addr("2001:db8:a::1");
        nd_addr_t out;

        nd_addr_combine(&pfx, &tgt, 48, &out);
        ok_str(nd_ntoa(&out), "fd00::1", "rewrite fd00::/48 maps 2001:db8:a::1 to fd00::1");

        nd_addr_combine(&pfx, &tgt, 0, &out);
        ok(nd_addr_eq(&out, &tgt), "combining at /0 yields the target unchanged");

        nd_addr_combine(&pfx, &tgt, 128, &out);
        ok(nd_addr_eq(&out, &pfx), "combining at /128 yields the prefix unchanged");

        /* Anything above /128 is clamped rather than read off the end of
         * the mask table. */
        nd_addr_combine(&pfx, &tgt, 200, &out);
        ok(nd_addr_eq(&out, &pfx), "combining above /128 is clamped, not out of bounds");
    }

    {
        static const char *pairs[][2] = {
            { "fd00::", "2001:db8:a::1" },
            { "2001:db8:ffff::", "::1234:5678:9abc:def0" },
            { "::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff" },
        };

        int mismatches = 0;

        for (size_t i = 0; i < sizeof(pairs) / sizeof(pairs[0]); i++) {
            nd_addr_t a = fake_addr(pairs[i][0]);
            nd_addr_t b = fake_addr(pairs[i][1]);

            for (unsigned pflen = 0; pflen <= 128; pflen++) {
                nd_addr_t got;
                nd_addr_combine(&a, &b, pflen, &got);
                nd_addr_t want = ref_combine(&a, &b, pflen);

                if (!nd_addr_eq(&got, &want)) {
                    tap_diag("  nd_addr_combine(%s, %s, %u) = %s, reference says %s", //
                             pairs[i][0], pairs[i][1], pflen, nd_ntoa(&got), nd_ntoa(&want));
                    mismatches++;
                }
            }
        }

        ok_int(mismatches, 0, "nd_addr_combine agrees with a bitwise reference at all 129 prefix lengths");
    }

    /* --- netmask conversion --------------------------------------------- */

    {
        int mismatches = 0;

        for (unsigned pflen = 0; pflen <= 128; pflen++) {
            nd_addr_t mask;
            nd_mask_from_pflen(pflen, &mask);

            if ((unsigned)nd_mask_to_pflen(&mask) != pflen) {
                tap_diag("  /%u round-tripped to /%d", pflen, nd_mask_to_pflen(&mask));
                mismatches++;
            }
        }

        ok_int(mismatches, 0, "nd_mask_from_pflen and nd_mask_to_pflen round-trip at all 129 prefix lengths");

        /* The mask must be contiguous high bits, not merely the right
         * popcount -- nd_mask_to_pflen only counts bits, so it would happily
         * round-trip a scattered mask. */
        nd_addr_t mask;
        nd_mask_from_pflen(64, &mask);
        ok_str(nd_ntoa(&mask), "ffff:ffff:ffff:ffff::", "/64 is ffff:ffff:ffff:ffff::");

        nd_mask_from_pflen(56, &mask);
        ok_str(nd_ntoa(&mask), "ffff:ffff:ffff:ff00::", "/56 is ffff:ffff:ffff:ff00::");

        nd_mask_from_pflen(0, &mask);
        ok(nd_addr_is_unspecified(&mask), "/0 is the all-zero mask");

        nd_mask_from_pflen(128, &mask);
        ok_str(nd_ntoa(&mask), "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "/128 is all ones");
    }

    /* --- classification -------------------------------------------------- */

    {
        nd_addr_t unspec = fake_addr("::");
        nd_addr_t loop = fake_addr("::1");
        nd_addr_t mcast = fake_addr("ff02::1");
        nd_addr_t solic = fake_addr("ff02::1:ff00:1");
        nd_addr_t ll = fake_addr("fe80::1");
        nd_addr_t gua = fake_addr("2001:db8::1");

        ok(nd_addr_is_unspecified(&unspec), ":: is unspecified");
        ok(!nd_addr_is_unspecified(&loop), "::1 is not unspecified");
        ok(!nd_addr_is_unspecified(&gua), "a global address is not unspecified");

        ok(nd_addr_is_multicast(&mcast), "ff02::1 is multicast");
        ok(nd_addr_is_multicast(&solic), "a solicited-node address is multicast");
        ok(!nd_addr_is_multicast(&ll), "fe80::1 is not multicast");
        ok(!nd_addr_is_multicast(&gua), "a global address is not multicast");
        ok(!nd_addr_is_multicast(&unspec), ":: is not multicast");
    }

    /* --- hashing --------------------------------------------------------- */

    {
        /* The session table buckets on this hash.  Equal addresses must
         * land in the same bucket, or a session is never found again. */
        nd_addr_t a = fake_addr("2001:db8:0:1::2");
        nd_addr_t b = fake_addr("2001:db8:0:1::2");

        ok_int(nd_addr_hash(&a), nd_addr_hash(&b), "equal addresses hash equal");

        /* Addresses that differ only in the low bits -- which is what a
         * prefix full of hosts looks like -- must not all collide. */
        unsigned collisions = 0;
        nd_addr_t base = fake_addr("2001:db8:0:1::");
        uint32_t first = 0;

        for (unsigned i = 1; i <= 64; i++) {
            nd_addr_t h = base;
            h.u8[15] = (uint8_t)i;
            uint32_t hash = nd_addr_hash(&h);

            if (i == 1)
                first = hash;
            else if (hash == first)
                collisions++;
        }

        ok_int(collisions, 0, "64 hosts in one /64 do not all hash to the same bucket");
    }

    /* --- link-layer addresses -------------------------------------------- */

    {
        nd_lladdr_t a = fake_lladdr("02:00:00:00:00:01");
        nd_lladdr_t b = fake_lladdr("02:00:00:00:00:01");
        nd_lladdr_t c = fake_lladdr("02:00:00:00:00:02");
        nd_lladdr_t zero = { { 0, 0, 0, 0, 0, 0 } };

        ok(nd_lladdr_eq(&a, &b), "nd_lladdr_eq is true for equal addresses");
        ok(!nd_lladdr_eq(&a, &c), "nd_lladdr_eq is false for different addresses");

        ok(nd_lladdr_is_unspecified(&zero), "the all-zero MAC is unspecified");
        ok(!nd_lladdr_is_unspecified(&a), "a real MAC is not unspecified");

        /* An unspecified rule target is how session.c decides whether to
         * advertise an overridden MAC, so every byte has to count. */
        for (int i = 0; i < 6; i++) {
            nd_lladdr_t one = zero;
            one.u8[i] = 1;
            ok(!nd_lladdr_is_unspecified(&one), "a MAC with only byte %d set is not unspecified", i);
        }

        ok_str(nd_ll_ntoa(&a), "2:0:0:0:0:1", "nd_ll_ntoa renders a MAC");
        ok_str(nd_ll_ntoa(NULL), "(null)", "nd_ll_ntoa tolerates NULL");
    }
}
