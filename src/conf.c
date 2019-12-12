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
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifndef INT_MAX
#    define INT_MAX __INT_MAX__
#endif

#ifndef INT_MIN
#    define INT_MIN (-INT_MAX - 1)
#endif

#include "ndppd.h"
#include "proxy.h"
#include "rule.h"

int nd_conf_invalid_ttl = 10000;
int nd_conf_valid_ttl = 30000;
int nd_conf_stale_ttl = 30000;
int nd_conf_renew = 5000;
int nd_conf_retrans_limit = 3;
int nd_conf_retrans_time = 1000;
bool nd_conf_keepalive = false;

typedef struct
{
    const char *data;
    size_t offset;
    size_t length;
    int line;
    int column;
} ndL_state_t;

typedef bool (*ndL_cfcb_t)(ndL_state_t *state, void *ptr);

typedef struct
{
    const char *key;
    int scope;
    int type;
    uintptr_t offset;
    int min;
    int max;
    ndL_cfcb_t cb;
} ndL_cfinfo_t;

/* Scopes. */
enum
{
    NDL_DEFAULT,
    NDL_PROXY,
    NDL_ROUTE
};

/* Configuration types. */
enum
{
    NDL_NONE,
    NDL_INT,
    NDL_BOOL,
    NDL_ADDR
};

/* Character classes. */
enum
{
    NDL_ALPHA = 256, /* [a-zA-Z] */
    NDL_ALNUM,       /* [a-zA-Z0-9] */
    NDL_DIGIT,       /* [0-9] */
    NDL_EALNM,       /* [a-zA-Z0-9_-] */
    NDL_SPACE,       /* [\s] */
    NDL_SNONL,       /* [^\S\n] */
    NDL_XNONL,       /* [^\n] */
    NDL_IPV6X,       /* [A-Fa-f0-9:] */
};

static bool ndL_parse_rule(ndL_state_t *state, nd_proxy_t *proxy);
static bool ndL_parse_proxy(ndL_state_t *state, void *unused);

static const ndL_cfinfo_t ndL_cfinfo_table[] = {
    { "proxy", NDL_DEFAULT, NDL_NONE, 0, 0, 0, (ndL_cfcb_t)ndL_parse_proxy },
    { "rule", NDL_PROXY, NDL_NONE, 0, 0, 0, (ndL_cfcb_t)ndL_parse_rule },
    { "invalid-ttl", NDL_DEFAULT, NDL_INT, (uintptr_t)&nd_conf_invalid_ttl, 1000, 3600000, NULL },
    { "valid-ttl", NDL_DEFAULT, NDL_INT, (uintptr_t)&nd_conf_valid_ttl, 10000, 3600000, NULL },
    { "renew", NDL_DEFAULT, NDL_INT, (uintptr_t)&nd_conf_renew, 0, 0, NULL },
    { "retrans-limit", NDL_DEFAULT, NDL_INT, (uintptr_t)&nd_conf_retrans_limit, 0, 10, NULL },
    { "retrans-time", NDL_DEFAULT, NDL_INT, (uintptr_t)&nd_conf_retrans_time, 0, 60000, NULL },
    { "keepalive", NDL_DEFAULT, NDL_BOOL, (uintptr_t)&nd_conf_keepalive, 0, 0, NULL },
    { "router", NDL_PROXY, NDL_BOOL, offsetof(nd_proxy_t, router), 0, 0, NULL },
    { "auto", NDL_ROUTE, NDL_BOOL, offsetof(nd_rule_t, is_auto), 0, 0, NULL },
    { "promisc", NDL_PROXY, NDL_BOOL, offsetof(nd_proxy_t, promisc), 0, 0, NULL },
    { NULL, 0, 0, 0, 0, 0, NULL },
};

static void ndL_error(const ndL_state_t *state, const char *fmt, ...)
{
    char buf[512];
    va_list va;

    va_start(va, fmt);
    vsnprintf(buf, sizeof(buf), fmt, va);
    va_end(va);

    nd_log_error("%s at line %d column %d", buf, state->line, state->column);
}

static char ndL_accept_one(ndL_state_t *state, int cl)
{
    if (state->offset >= state->length)
        return 0;

    char ch = state->data[state->offset];

    bool result;

    switch (cl)
    {
    case 0:
        result = true;
        break;

    case NDL_ALPHA:
        result = isalpha(ch);
        break;

    case NDL_ALNUM:
        result = isalnum(ch);
        break;

    case NDL_DIGIT:
        result = isdigit(ch);
        break;

    case NDL_EALNM:
        result = isalnum(ch) || ch == '_' || ch == '-';
        break;

    case NDL_SPACE:
        result = isspace(ch);
        break;

    case NDL_SNONL:
        result = isspace(ch) && ch != '\n';
        break;

    case NDL_XNONL:
        result = ch != '\n';
        break;

    case NDL_IPV6X:
        result = isxdigit(ch) || ch == ':';
        break;

    default:
        result = (cl >= 0 && cl < 256) && (unsigned char)ch == cl;
        break;
    }

    if (!result)
        return false;

    if (ch == '\n')
    {
        state->line++;
        state->column = 1;
    }
    else
    {
        state->column++;
    }

    state->offset++;

    return ch;
}

static bool ndL_accept_all(ndL_state_t *state, int cl, char *buf, size_t buflen)
{
    ndL_state_t tmp = *state;

    for (size_t i = 0; !buf || i < buflen; i++)
    {
        char ch = ndL_accept_one(&tmp, cl);

        if (buf)
            buf[i] = ch;

        if (!ch)
        {
            if (i > 0)
            {
                *state = tmp;
                return true;
            }

            break;
        }
    }

    return false;
}

static bool ndL_accept(ndL_state_t *state, const char *str, int except_cl)
{
    ndL_state_t tmp = *state;

    while (*str && ndL_accept_one(&tmp, *str))
        str++;

    if (*str)
        return false;

    if (except_cl && ndL_accept_one(&tmp, except_cl))
        return false;

    *state = tmp;
    return true;
}

static bool ndL_accept_bool(ndL_state_t *state, bool *value)
{
    if (ndL_accept(state, "yes", NDL_EALNM) || ndL_accept(state, "true", NDL_EALNM))
        *value = true;
    else if (ndL_accept(state, "no", NDL_EALNM) || ndL_accept(state, "false", NDL_EALNM))
        *value = false;
    else
    {
        /* For accurate reporting of location. */
        ndL_state_t tmp = *state;
        if (ndL_accept_one(&tmp, NDL_XNONL) != 0)
            return false;

        *value = true;
    }

    return true;
}

static bool ndL_accept_int(ndL_state_t *state, int *value)
{
    ndL_state_t tmp = *state;

    int n = ndL_accept_one(&tmp, '-') ? -1 : 1;

    char buf[32];

    if (!ndL_accept_all(&tmp, NDL_DIGIT, buf, sizeof(buf)))
        return false;

    /* Trailing [A-Za-z0-9_-] are invalid. */
    if (ndL_accept_one(&tmp, NDL_EALNM))
        return false;

    long longval = strtoll(buf, NULL, 10) * n;

    if (longval < INT_MIN || longval > INT_MAX)
        return false;

    *value = (int)longval;
    *state = tmp;
    return true;
}

static bool ndL_eof(ndL_state_t *state)
{
    return state->offset >= state->length;
}

static void ndL_skip(ndL_state_t *state, bool skip_newline)
{
    for (;;)
    {
        ndL_accept_all(state, skip_newline ? NDL_SPACE : NDL_SNONL, NULL, 0);

        if (ndL_accept(state, "#", 0))
        {
            ndL_accept_all(state, NDL_XNONL, NULL, 0);
        }
        else if (ndL_accept(state, "/*", 0))
        {
            for (;;)
            {
                if (ndL_eof(state))
                {
                    ndL_error(state, "Expected end-of-comment before end-of-file");
                    break;
                }

                if (ndL_accept(state, "*/", 0))
                    break;

                ndL_accept_one(state, 0);
            }
        }
        else
        {
            break;
        }
    }
}

static bool ndL_accept_addr(ndL_state_t *state, nd_addr_t *addr)
{
    ndL_state_t tmp = *state;

    char buf[64];

    for (size_t i = 0; i < sizeof(buf); i++)
    {
        if (!(buf[i] = ndL_accept_one(&tmp, NDL_IPV6X)))
        {
            if (i == 0)
                return false;

            /* Make sure we don't have a trailing [A-Za-z0-9-_]. */
            if (ndL_accept_one(&tmp, NDL_EALNM))
                return false;

            if (inet_pton(AF_INET6, buf, addr) != 1)
            {
                ndL_error(state, "Invalid IPv6 address \"%s\"", buf);
                return false;
            }

            *state = tmp;
            return true;
        }
    }

    return false;
}

static bool ndL_parse_block(ndL_state_t *state, int scope, void *ptr);

static bool ndL_parse_rule(ndL_state_t *state, nd_proxy_t *proxy)
{
    nd_rule_t *rule = nd_rule_create(proxy);

    if (!ndL_accept_addr(state, &rule->addr))
    {
        ndL_error(state, "Expected IPv6 address");
        return false;
    }

    if (ndL_accept(state, "/", 0))
    {
        /* Just for accurate logging if there is an error. */
        ndL_state_t tmp = *state;

        if (!ndL_accept_int(state, &rule->prefix))
        {
            ndL_error(state, "Expected prefix");
            return false;
        }

        if (rule->prefix < 0 || rule->prefix > 128)
        {
            ndL_error(&tmp, "Invalid prefix (%d)", rule->prefix);
            return false;
        }
    }
    else
    {
        rule->prefix = 128;
    }

    return ndL_parse_block(state, NDL_ROUTE, rule);
}

static bool ndL_parse_proxy(ndL_state_t *state, __attribute__((unused)) void *unused)
{
    char ifname[IF_NAMESIZE];

    if (!ndL_accept_all(state, NDL_EALNM, ifname, sizeof(ifname)))
    {
        ndL_error(state, "Expected interface name");
        return false;
    }

    nd_proxy_t *proxy = nd_proxy_create(ifname);

    if (proxy == NULL)
        return false;

    return ndL_parse_block(state, NDL_PROXY, proxy);
}

static bool ndL_parse_block(ndL_state_t *state, int scope, void *ptr)
{
    ndL_skip(state, false);

    if (scope != NDL_DEFAULT && !ndL_accept_one(state, '{'))
    {
        ndL_error(state, "Expected start-of-block '{'");
        return false;
    }

    for (;;)
    {
        ndL_skip(state, true);

        if (scope != NDL_DEFAULT && ndL_accept_one(state, '}'))
            return true;

        if (ndL_eof(state))
        {
            if (scope != NDL_DEFAULT)
            {
                ndL_error(state, "Expected end-of-block '}'");
                return false;
            }

            return true;
        }

        bool found = false;

        for (int i = 0; !found && ndL_cfinfo_table[i].key; i++)
        {
            if (ndL_cfinfo_table[i].scope != scope)
                continue;

            if (!ndL_accept(state, ndL_cfinfo_table[i].key, NDL_EALNM))
                continue;

            ndL_skip(state, false);

            found = true;

            const ndL_cfinfo_t *t = &ndL_cfinfo_table[i];
            const ndL_state_t saved_state = *state;

            switch (ndL_cfinfo_table[i].type)
            {
            case NDL_NONE:
                break;

            case NDL_BOOL:
                if (!ndL_accept_bool(state, (bool *)(ptr + t->offset)))
                {
                    ndL_error(&saved_state, "Expected boolean value");
                    return false;
                }
                break;

            case NDL_INT:
                if (!ndL_accept_int(state, (int *)(ptr + t->offset)))
                {
                    ndL_error(&saved_state, "Expected an integer");
                    return false;
                }
                if (*(int *)(ptr + t->offset) < t->min || *(int *)(ptr + t->offset) > t->max)
                {
                    ndL_error(&saved_state, "Invalid range; must be between %d and %d", t->min, t->max);
                    return false;
                }
                break;

            case NDL_ADDR:
                if (!ndL_accept_addr(state, (nd_addr_t *)(ptr + t->offset)))
                {
                    ndL_error(&saved_state, "Expected an IPv6 address");
                    return false;
                }
                break;
            }

            if (t->cb)
            {
                ndL_skip(state, false);

                if (!t->cb(state, ptr))
                    return false;
            }

            ndL_skip(state, false);

            if (!ndL_eof(state) && !ndL_accept_one(state, '\n'))
            {
                ndL_error(state, "Expected newline");
                return false;
            }
        }

        if (!found)
        {
            ndL_error(state, "Invalid configuration");
            return false;
        }
    }
}

bool nd_conf_load(const char *path)
{
    FILE *fp = fopen(path, "r");

    if (fp == NULL)
    {
        nd_log_error("Failed to load configuration: %s", strerror(errno));
        return NULL;
    }

    struct stat stat;

    if (fstat(fileno(fp), &stat) < 0)
    {
        nd_log_error("Failed to determine size: %s", strerror(errno));
        fclose(fp);
        return NULL;
    }

    char *buf = (char *)malloc(stat.st_size);

    if (buf == NULL)
    {
        nd_log_error("Failed to allocate buffer: %s", strerror(errno));
        fclose(fp);
        return NULL;
    }

    bool result = false;

    if (fread(buf, stat.st_size, 1, fp) != 1)
    {
        nd_log_error("Failed to read config: %s", strerror(errno));
    }
    else
    {
        ndL_state_t state = { .data = buf, .offset = 0, .length = stat.st_size, .column = 0, .line = 1 };

        /* TODO: Validate configuration. */

        result = ndL_parse_block(&state, NDL_DEFAULT, NULL);
    }

    fclose(fp);
    free(buf);
    return result;
}
