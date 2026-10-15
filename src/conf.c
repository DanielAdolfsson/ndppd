/*
 * This file is part of ndppd.
 *
 * Copyright (C) 2011-2019  Daniel Adolfsson <daniel@ashen.se>
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
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#ifdef __linux__
#    include <netinet/ether.h>
#else
#    include <sys/types.h>

#    include <net/ethernet.h>
#endif
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "ndppd.h"

int nd_conf_invalid_ttl = 10000;
int nd_conf_valid_ttl = 30000;
int nd_conf_stale_ttl = 30000;
int nd_conf_renew = 5000;
int nd_conf_retrans_limit = 3;
int nd_conf_retrans_time = 1000;
bool nd_conf_keepalive = false;

typedef struct {
    const char *data;
    size_t offset;
    size_t length;
    int line;
    int column;
} ndL_state_t;

typedef struct ndL_cfinfo ndL_cfinfo_t;

typedef bool (*ndL_cfcb_t)(ndL_state_t *, const ndL_cfinfo_t *, void *);

struct ndL_cfinfo {
    const char *key;
    int scope;
    int type;
    uintptr_t offset;
    int min;
    int max;
    ndL_cfcb_t cb;
};

//! Scopes.
enum { NDL_DEFAULT, NDL_PROXY, NDL_RULE };

//! Configuration types.
enum { NDL_NONE, NDL_INT, NDL_BOOL, NDL_ADDR, NDL_NAME, NDL_LLADDR };

static bool ndL_parse_rule(ndL_state_t *state, ndL_cfinfo_t *info, nd_proxy_t *proxy);
static bool ndL_parse_rewrite(ndL_state_t *state, ndL_cfinfo_t *info, nd_rule_t *rule);
static bool ndL_parse_proxy(ndL_state_t *state, ND_UNUSED ndL_cfinfo_t *u1, ND_UNUSED void *u2);
static bool ndL_parse_mode(ndL_state_t *state, ndL_cfinfo_t *info, nd_rule_t *rule);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wincompatible-pointer-types"
#pragma GCC diagnostic ignored "-Wint-conversion"
static const ndL_cfinfo_t ndL_cfinfo_table[] = {
    { "proxy", NDL_DEFAULT, NDL_NONE, 0, 0, 0, ndL_parse_proxy },
    { "rule", NDL_PROXY, NDL_NONE, 0, 0, 0, ndL_parse_rule },
    { "rewrite", NDL_RULE, NDL_NONE, 0, 0, 0, ndL_parse_rewrite },
    { "invalid-ttl", NDL_DEFAULT, NDL_INT, &nd_conf_invalid_ttl, 1000, 3600000, NULL },
    { "valid-ttl", NDL_DEFAULT, NDL_INT, &nd_conf_valid_ttl, 10000, 3600000, NULL },
    { "renew", NDL_DEFAULT, NDL_INT, &nd_conf_renew, 0, 0, NULL },
    { "retrans-limit", NDL_DEFAULT, NDL_INT, &nd_conf_retrans_limit, 0, 10, NULL },
    { "retrans-time", NDL_DEFAULT, NDL_INT, &nd_conf_retrans_time, 0, 60000, NULL },
    { "keepalive", NDL_DEFAULT, NDL_BOOL, &nd_conf_keepalive, 0, 0, NULL },
    { "router", NDL_PROXY, NDL_BOOL, offsetof(nd_proxy_t, router), 0, 0, NULL },
    { "auto", NDL_RULE, NDL_NONE, 0, 0, 0, ndL_parse_mode },
    { "static", NDL_RULE, NDL_NONE, 0, 0, 0, ndL_parse_mode },
    { "autowire", NDL_RULE, NDL_BOOL, offsetof(nd_rule_t, autowire), 0, 0, NULL },
    { "iface", NDL_RULE, NDL_NONE, 0, 0, 0, ndL_parse_mode },
    { "target", NDL_PROXY, NDL_LLADDR, offsetof(nd_proxy_t, target), 0, 0, NULL },
    { "target", NDL_RULE, NDL_LLADDR, offsetof(nd_rule_t, target), 0, 0, NULL },
#ifndef __FreeBSD__
    { "table", NDL_RULE, NDL_INT, offsetof(nd_rule_t, table), 0, 255, NULL },
#endif
    { 0 },
};
#pragma GCC diagnostic pop

static void ndL_error(const ndL_state_t *state, const char *fmt, ...)
{
    char buf[512];
    va_list va;

    va_start(va, fmt);
    vsnprintf(buf, sizeof(buf), fmt, va);
    va_end(va);

    nd_log_error("(at line %d column %d) %s", state->line, state->column, buf);
}

static bool ndL_eof(ndL_state_t *state)
{
    return state->offset >= state->length;
}

static void ndL_skip(ndL_state_t *state)
{
    bool comment = false;

    while (state->offset < state->length) {
        char c = state->data[state->offset];

        if (c == '#')
            comment = true;

        if (c == '\n' || (!comment && !isspace(c)))
            break;

        state->offset++;
        state->column++;
    }
}

static char ndL_accept(ndL_state_t *state, char *valid)
{
    if (state->offset >= state->length) {
        return false;
    }

    char c = state->data[state->offset];

    if (!strchr(valid, c))
        return 0;

    state->offset++;

    if (c == '\n') {
        state->column = 1;
        state->line++;
    } else {
        state->column++;
    }

    return c;
}

static bool ndL_accept_int(ndL_state_t *state, int *ptr, int min, int max)
{
    ndL_state_t tmp = *state;

    char buf[64];
    int i = 0;

    while (i < 64 && tmp.offset < tmp.length) {
        char c = tmp.data[tmp.offset];

        if (!isdigit(c) && c != '-')
            break;

        buf[i++] = c;
        tmp.offset++;
        tmp.column++;
    }

    if (i == 64 || tmp.offset == state->offset)
        return false;

    buf[i] = 0;

    char *endptr;

    long value = strtoll(buf, &endptr, 10);

    if (*endptr || value > max || value < min)
        return false;

    *ptr = (int)value;

    *state = tmp;
    return true;
}

static bool ndL_accept_addr(ndL_state_t *state, nd_addr_t *addr)
{
    ndL_state_t tmp = *state;

    char buf[64];
    int i = 0;

    while (i < 64 && tmp.offset < tmp.length) {
        char c = tmp.data[tmp.offset];

        if (!isxdigit(c) && c != '.' && c != ':')
            break;

        buf[i++] = c;
        tmp.offset++;
        tmp.column++;
    }

    if (i == 64 || tmp.offset == state->offset)
        return false;

    buf[i] = 0;

    if (inet_pton(AF_INET6, buf, addr) != 1) {
        ndL_error(state, "Invalid IPv6 address \"%s\"", buf);
        return false;
    }

    *state = tmp;
    return true;
}

static bool ndL_accept_lladdr(ndL_state_t *state, nd_lladdr_t *out)
{
    ndL_state_t tmp = *state;

    char buf[64];
    int i = 0;

    while (i < 64 && tmp.offset < tmp.length) {
        char c = tmp.data[tmp.offset];

        if (!isxdigit(c) && c != ':')
            break;

        buf[i++] = c;
        tmp.offset++;
        tmp.column++;
    }

    if (i == 64 || tmp.offset == state->offset)
        return false;

    buf[i] = 0;

    struct ether_addr *addr = ether_aton(buf);

    if (addr == NULL) {
        ndL_error(state, "Invalid link-layer address \"%s\"", buf);
        return false;
    }

    *out = *(nd_lladdr_t *)addr;
    *state = tmp;
    return true;
}

static bool ndL_accept_name(ndL_state_t *state, char *str, size_t size)
{
    static const char *valid = "$-_.";
    ndL_state_t tmp = *state;

    while (size > 0 && tmp.offset < tmp.length) {
        char c = tmp.data[tmp.offset];

        if ((tmp.offset == state->offset && !isalpha(c)) ||
            (tmp.offset > state->offset && !isalnum(c) && !strchr(valid, c))) {
            break;
        }

        *str++ = c;
        tmp.offset++;
        tmp.column++;
    }

    if (!size || tmp.offset == state->offset)
        return false;

    *str = 0;
    *state = tmp;
    return true;
}

static bool ndL_accept_bool(ndL_state_t *state, bool *value)
{
    char buf[16];
    ndL_state_t tmp = *state;

    if (!ndL_accept_name(&tmp, buf, sizeof(buf)) || !strcmp(buf, "yes") || !strcmp(buf, "true"))
        *value = true;
    else if (!strcmp(buf, "no") || !strcmp(buf, "false"))
        *value = false;
    else
        return false;

    *state = tmp;
    return true;
}

static bool ndL_parse_block(ndL_state_t *state, int scope, void *ptr);

static bool ndL_parse_rule(ndL_state_t *state, ND_UNUSED ndL_cfinfo_t *info, nd_proxy_t *proxy)
{
    nd_rule_t *rule = nd_rule_create(proxy);

    if (!ndL_accept_addr(state, &rule->addr)) {
        ndL_error(state, "Expected IPv6 address");
        return false;
    }

    if (ndL_accept(state, "/")) {
        if (!ndL_accept_int(state, &rule->prefix, 0, 128)) {
            ndL_error(state, "Expected prefix");
            return false;
        }
    } else {
        rule->prefix = 128;
    }

#ifdef __linux__
    rule->table = 254;
#else
    rule->table = 0;
#endif

    if (!ndL_parse_block(state, NDL_RULE, rule))
        return false;

    if (rule->mode == ND_MODE_UNKNOWN) {
        ndL_error(state, "\"static\", \"auto\", or \"iface\" need to be specified");
        return false;
    }

    if (rule->autowire && rule->mode != ND_MODE_IFACE) {
        ndL_error(state, "\"autowire\" may only be used in combination with \"iface\"");
        return false;
    }

    return true;
}

static bool ndL_parse_rewrite(ndL_state_t *state, ND_UNUSED ndL_cfinfo_t *info, nd_rule_t *rule)
{
    if (!ndL_accept_addr(state, &rule->rewrite_tgt))
        return false;

    if (ndL_accept(state, "/")) {
        if (!ndL_accept_int(state, &rule->rewrite_pflen, 0, 128)) {
            ndL_error(state, "Expected prefix");
            return false;
        }
    } else {
        rule->rewrite_pflen = 128;
    }

    return true;
}

static bool ndL_parse_proxy(ndL_state_t *state, ND_UNUSED ndL_cfinfo_t *u1, ND_UNUSED void *u2)
{
    char ifname[IF_NAMESIZE];

    if (!ndL_accept_name(state, ifname, sizeof(ifname))) {
        ndL_error(state, "Expected interface name");
        return false;
    }

    nd_proxy_t *proxy = nd_proxy_create(ifname);

    if (proxy == NULL)
        return false;

    return ndL_parse_block(state, NDL_PROXY, proxy);
}

static bool ndL_parse_mode(ndL_state_t *state, ndL_cfinfo_t *info, nd_rule_t *rule)
{
    if (rule->mode != ND_MODE_UNKNOWN) {
        ndL_error(state, "\"static\", \"auto\" and \"iface\" are mutually exclusive");
        return false;
    }

    if (!strcmp(info->key, "auto")) {
        rule->mode = ND_MODE_AUTO;
    } else if (!strcmp(info->key, "static")) {
        rule->mode = ND_MODE_STATIC;
    } else {
        if (!ndL_accept_name(state, rule->ifname, sizeof(rule->ifname))) {
            ndL_error(state, "Expected interface name");
            return false;
        }

        rule->mode = ND_MODE_IFACE;
    }

    return true;
}

static bool ndL_parse_block(ndL_state_t *state, int scope, void *ptr)
{
    ndL_skip(state);

    if (scope != NDL_DEFAULT && !ndL_accept(state, "{")) {
        ndL_error(state, "Expected start-of-block '{'");
        return false;
    }

    uint32_t bits = 0;

    for (;;) {
        ndL_skip(state);

        switch (ndL_accept(state, "\n}")) {
        case '}':
            if (scope == NDL_DEFAULT) {
                ndL_error(state, "Unexpected end-of-block");
                return false;
            }
            return true;

        case '\n':
            continue;
        }

        if (ndL_eof(state)) {
            if (scope != NDL_DEFAULT) {
                ndL_error(state, "Expected end-of-block '}'");
                return false;
            }

            return true;
        }

        char key[32];
        if (!ndL_accept_name(state, key, sizeof(key))) {
            nd_log_error("Expected key");
            return false;
        }

        ndL_skip(state);

        bool found = false;

        for (int i = 0; !found && ndL_cfinfo_table[i].key; i++) {
            if (ndL_cfinfo_table[i].scope != scope)
                continue;

            if (strcmp(key, ndL_cfinfo_table[i].key) != 0)
                continue;

            bits |= 1 << i;
            found = true;

            const ndL_cfinfo_t *t = &ndL_cfinfo_table[i];
            const ndL_state_t state_before_value = *state;

            switch (t->type) {
            case NDL_NONE:
                break;

            case NDL_BOOL:
                if (!ndL_accept_bool(state, (bool *)(ptr + t->offset))) {
                    ndL_error(&state_before_value, "Expected boolean value");
                    return false;
                }
                break;

            case NDL_INT:
                if (!ndL_accept_int(state, (int *)(ptr + t->offset), t->min, t->max)) {
                    ndL_error(&state_before_value, "Expected an integer");
                    return false;
                }
                break;

            case NDL_ADDR:
                if (!ndL_accept_addr(state, (nd_addr_t *)(ptr + t->offset))) {
                    ndL_error(&state_before_value, "Expected an IPv6 address");
                    return false;
                }
                break;

            case NDL_NAME:
                if (!ndL_accept_name(state, (char *)(ptr + t->offset), t->max)) {
                    ndL_error(&state_before_value, "Expected identifier");
                    return false;
                }
                break;

            case NDL_LLADDR:
                if (!ndL_accept_lladdr(state, (nd_lladdr_t *)(ptr + t->offset))) {
                    ndL_error(&state_before_value, "Expected a link-layer address");
                    return false;
                }
                break;
            }

            if (t->cb) {
                ndL_skip(state);

                if (!t->cb(state, &ndL_cfinfo_table[i], ptr))
                    return false;
            }

            ndL_skip(state);

            if (!ndL_eof(state) && state->data[state->offset] != '}' && state->data[state->offset] != '\n') {
                ndL_error(state, "Expected newline, end-of-block, or end-of-line");
                return false;
            }
        }

        if (!found) {
            ndL_error(state, "Invalid configuration");
            return false;
        }
    }
}

bool nd_conf_load(const char *path)
{
    FILE *fp = fopen(path, "r");

    if (fp == NULL) {
        nd_log_error("Failed to load configuration: %s", strerror(errno));
        return NULL;
    }

    struct stat stat;

    if (fstat(fileno(fp), &stat) < 0) {
        nd_log_error("Failed to determine size: %s", strerror(errno));
        fclose(fp);
        return NULL;
    }

    char *buf = (char *)malloc(stat.st_size);

    if (buf == NULL) {
        nd_log_error("Failed to allocate buffer: %s", strerror(errno));
        fclose(fp);
        return NULL;
    }

    bool result = false;

    if (fread(buf, stat.st_size, 1, fp) != 1) {
        nd_log_error("Failed to read config: %s", strerror(errno));
    } else {
        ndL_state_t state = { .data = buf, .offset = 0, .length = stat.st_size, .column = 0, .line = 1 };

        // FIXME: Validate configuration

        result = ndL_parse_block(&state, NDL_DEFAULT, NULL);
    }

    fclose(fp);
    free(buf);
    return result;
}
