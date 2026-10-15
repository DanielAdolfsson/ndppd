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
// A minimal TAP 13 (https://testanything.org) producer.
//
// Deliberately dependency-free and C++03-compatible: ndppd is expected to
// build with nothing but a C++ compiler on platforms as old as the ones in
// issues #67 and #91, and the tests must not be the reason that stops being
// true.
#pragma once

#include <cstdio>
#include <cstdlib>
#include <sstream>
#include <string>
#include <vector>

namespace tap {

typedef void (*test_fn)();

struct test_case {
    const char* name;
    test_fn fn;
};

// Function-local statics, so registration order never depends on static
// initialisation order across translation units.
inline std::vector<test_case>& tests()
{
    static std::vector<test_case> v;
    return v;
}

inline int& counter()    { static int n = 0; return n; }
inline int& failures()   { static int n = 0; return n; }

// When non-empty, the next assertion is reported with a TAP "# TODO"
// directive: it is allowed to fail without failing the run. Used to pin
// down known bugs so they are documented and tracked rather than silently
// tolerated. Remove the todo() call when the bug is fixed and the test will
// start enforcing the correct behaviour.
inline std::string& todo_reason() { static std::string s; return s; }

inline void todo(const std::string& reason) { todo_reason() = reason; }

struct registrar {
    registrar(const char* name, test_fn fn)
    {
        test_case tc;
        tc.name = name;
        tc.fn = fn;
        tests().push_back(tc);
    }
};

inline void diag(const std::string& msg)
{
    std::printf("# %s\n", msg.c_str());
}

inline bool ok(bool cond, const std::string& desc)
{
    int n = ++counter();
    std::string reason = todo_reason();
    todo_reason().clear();

    if (cond) {
        if (reason.empty())
            std::printf("ok %d - %s\n", n, desc.c_str());
        else
            // Passing a TODO means the bug is fixed; say so loudly.
            std::printf("ok %d - %s # TODO %s\n", n, desc.c_str(), reason.c_str());
    } else {
        if (reason.empty()) {
            std::printf("not ok %d - %s\n", n, desc.c_str());
            failures()++;
        } else {
            std::printf("not ok %d - %s # TODO %s\n", n, desc.c_str(), reason.c_str());
        }
    }

    std::fflush(stdout);
    return cond;
}

template <typename T>
inline std::string str_of(const T& v)
{
    std::ostringstream ss;
    ss << v;
    return ss.str();
}

template <typename A, typename B>
inline bool is(const A& got, const B& expected, const std::string& desc)
{
    bool pass = (got == expected);
    bool had_todo = !todo_reason().empty();
    ok(pass, desc);
    if (!pass && !had_todo) {
        diag("  got:      " + str_of(got));
        diag("  expected: " + str_of(expected));
    }
    return pass;
}

// std::string vs const char* needs a nudge in C++03.
inline bool is_str(const std::string& got, const std::string& expected, const std::string& desc)
{
    return is<std::string, std::string>(got, expected, desc);
}

inline int run(int argc, char** argv)
{
    std::string only;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--list") {
            for (size_t j = 0; j < tests().size(); j++)
                std::printf("%s\n", tests()[j].name);
            return 0;
        }
        only = a;
    }

    std::printf("TAP version 13\n");

    for (size_t i = 0; i < tests().size(); i++) {
        if (!only.empty() && only != tests()[i].name)
            continue;
        std::printf("# Subtest: %s\n", tests()[i].name);
        tests()[i].fn();
    }

    std::printf("1..%d\n", counter());

    if (failures()) {
        std::printf("# FAILED %d of %d\n", failures(), counter());
        return 1;
    }

    std::printf("# passed %d\n", counter());
    return 0;
}

} // namespace tap

// Defines and registers a test. Body follows the macro.
#define TEST(name)                                                             \
    static void name();                                                        \
    static tap::registrar tap_registrar_##name(#name, name);                   \
    static void name()
