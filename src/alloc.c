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
#include <stdlib.h>
#include <string.h>

#ifndef NDPPD_ALLOC_SIZE
#    define NDPPD_ALLOC_SIZE 16384
#endif

#ifndef NDPPD_MAX_ALLOC
#    define NDPPD_MAX_ALLOC 128
#endif

#include "ndppd.h"

typedef struct ndL_chunk ndL_chunk_t;
typedef struct ndL_obj ndL_obj_t;

struct ndL_chunk {
    ndL_chunk_t *next;
    size_t free;
    size_t size;
};

struct ndL_obj {
    ndL_obj_t *next;
};

static ndL_chunk_t *ndL_chunks;
static size_t ndL_alloc_size = NDPPD_ALLOC_SIZE;
static ndL_obj_t *ndL_free_objects[NDPPD_MAX_ALLOC >> 3];

char *nd_strdup(const char *str)
{
    size_t len = strlen(str);
    char *buf = (char *)nd_alloc(len + 1);
    strcpy(buf, str);
    return buf;
}

void nd_free(void *ptr, size_t size)
{
    if (size == 0 || size > NDPPD_MAX_ALLOC) {
        abort();
    }

    size = (size + 7U) & ~7U;

    unsigned int bucket = (size >> 3) - 1;
    ND_LL_PREPEND(ndL_free_objects[bucket], (ndL_obj_t *)ptr, next);
}

void *nd_alloc(size_t size)
{
    if (size == 0 || size > NDPPD_MAX_ALLOC) {
        abort();
    }

    /* To keep everything properly aligned, we'll make sure it's multiple of 8. */
    size = (size + 7U) & ~7U;

    /* See if we can reuse an object. */

    unsigned int bucket = (size >> 3) - 1;
    ndL_obj_t *obj = ndL_free_objects[bucket];

    if (obj) {
        ND_LL_DELETE(ndL_free_objects[bucket], obj, next);
        return obj;
    }

    /* See if we have any chunks with enough space left. */

    for (ndL_chunk_t *chunk = ndL_chunks; chunk; chunk = chunk->next) {
        if (chunk->free >= size) {
            void *ptr = (void *)chunk + chunk->size - chunk->free;
            chunk->free -= size;
            return ptr;
        }
    }

    ndL_chunk_t *chunk = (ndL_chunk_t *)malloc(ndL_alloc_size);

    // This should never happen.
    if (chunk == NULL) {
        abort();
    }

    *chunk = (ndL_chunk_t){
        .next = ndL_chunks,
        .size = ndL_alloc_size,
        .free = ndL_alloc_size - ((sizeof(ndL_chunk_t) + 7U) & ~7U),
    };

    ndL_chunks = chunk;

    ndL_alloc_size *= 2;

    void *ptr = (void *)chunk + chunk->size - chunk->free;
    chunk->free -= size;
    return ptr;
}

void nd_alloc_cleanup()
{
    ND_LL_FOREACH_S (ndL_chunks, chunk, tmp, next) {
        free(chunk);
    }
}
