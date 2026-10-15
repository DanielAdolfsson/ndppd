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
// Tests for ptr<T>/weak_ptr<T> (src/ptr.h).
//
// ndppd's object lifetimes all run through this hand-rolled reference
// counter, so a defect here surfaces as a use-after-free somewhere else
// entirely. It is also one of the few parts of the daemon with no I/O at
// all, which makes it cheap to pin down.

#include "tap.h"
#include "ndppd.h"

using namespace ndppd;

namespace {

int g_live = 0;

struct probe {
    int tag;
    probe(int t = 0) : tag(t) { g_live++; }
    ~probe() { g_live--; }
};

} // namespace

TEST(ptr_default_is_null)
{
    ptr<probe> p;
    tap::ok(p.is_null(), "default-constructed ptr is null");
    tap::ok(!p, "default-constructed ptr is falsy");
}

TEST(ptr_holds_and_frees)
{
    g_live = 0;
    {
        ptr<probe> p(new probe(7));
        tap::ok(!p.is_null(), "ptr holding an object is not null");
        tap::ok(!!p, "ptr holding an object is truthy");
        tap::is(p->tag, 7, "operator-> reaches the object");
        tap::is((*p).tag, 7, "operator* reaches the object");
        tap::is(g_live, 1, "exactly one object is live inside scope");
    }
    tap::is(g_live, 0, "object is freed when the last strong ref goes away");
}

TEST(ptr_shares_ownership)
{
    g_live = 0;
    {
        ptr<probe> a(new probe(1));
        {
            ptr<probe> b(a);
            tap::is(g_live, 1, "copying a ptr does not copy the object");
            tap::ok(a == b, "copies compare equal");
        }
        tap::is(g_live, 1, "object survives while another strong ref remains");
    }
    tap::is(g_live, 0, "object is freed once every strong ref is gone");
}

TEST(ptr_assignment_releases_previous)
{
    g_live = 0;
    {
        ptr<probe> p(new probe(1));
        tap::is(g_live, 1, "first object live");
        p = ptr<probe>(new probe(2));
        tap::is(g_live, 1, "assigning a new object releases the previous one");
        tap::is(p->tag, 2, "ptr now refers to the new object");
    }
    tap::is(g_live, 0, "all objects freed");
}

TEST(ptr_distinct_objects_compare_unequal)
{
    ptr<probe> a(new probe(1));
    ptr<probe> b(new probe(1));
    tap::ok(a != b, "two ptrs to distinct objects compare unequal");
}

TEST(weak_ptr_does_not_keep_object_alive)
{
    g_live = 0;
    weak_ptr<probe> w;
    {
        ptr<probe> s(new probe(3));
        w = s;
        tap::ok(!w.is_null(), "weak ref is valid while a strong ref exists");
        tap::is(g_live, 1, "object live");
    }
    tap::is(g_live, 0, "strong ref going away frees the object");
    tap::ok(w.is_null(), "weak ref reports null once the object is gone");
}

TEST(ptr_deref_of_null_throws)
{
    ptr<probe> p;
    bool threw = false;
    try {
        p->tag = 1;
    } catch (invalid_pointer* e) {
        threw = true;
        delete e;
    } catch (...) {
        threw = true;
    }
    tap::ok(threw, "dereferencing a null ptr throws invalid_pointer");
}

TEST(ptr_reset_releases)
{
    g_live = 0;
    ptr<probe> p(new probe(1));
    tap::is(g_live, 1, "object live before reset");
    p.reset();

    // KNOWN BUG: ptr<T>::reset() does not release the current reference.
    // reset() forwards to acquire(void*), which returns early when handed a
    // null pointer -- before it ever calls release(). The same early return
    // makes `p = (T *)0` a no-op. Nothing in ndppd calls either today
    // (src/session.cc's .reset() calls are on address, not ptr), so this is
    // a trap for future code rather than a live leak. Drop the two todo()
    // calls below once acquire(void*) releases first.
    tap::todo("ptr<T>::reset() does not release; see acquire(void*) in src/ptr.h");
    tap::is(g_live, 0, "reset() releases the object");
    tap::todo("ptr<T>::reset() does not release; see acquire(void*) in src/ptr.h");
    tap::ok(p.is_null(), "ptr is null after reset()");
}
