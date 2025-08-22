/****************************************************************************
**
** SPDX-License-Identifier: BSD-2-Clause-Patent
**
** SPDX-FileCopyrightText: Copyright (c) 2023 SoftAtHome
**
** Redistribution and use in source and binary forms, with or without modification,
** are permitted provided that the following conditions are met:
**
** 1. Redistributions of source code must retain the above copyright notice,
** this list of conditions and the following disclaimer.
**
** 2. Redistributions in binary form must reproduce the above copyright notice,
** this list of conditions and the following disclaimer in the documentation
** and/or other materials provided with the distribution.
**
** Subject to the terms and conditions of this license, each copyright holder
** and contributor hereby grants to those receiving rights under this license
** a perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable
** (except for failure to satisfy the conditions of this license) patent license
** to make, have made, use, offer to sell, sell, import, and otherwise transfer
** this software, where such license applies only to those patent claims, already
** acquired or hereafter acquired, licensable by such copyright holder or contributor
** that are necessarily infringed by:
**
** (a) their Contribution(s) (the licensed copyrights of copyright holders and
** non-copyrightable additions of contributors, in source or binary form) alone;
** or
**
** (b) combination of their Contribution(s) with the work of authorship to which
** such Contribution(s) was added by such copyright holder or contributor, if,
** at the time the Contribution is added, such addition causes such combination
** to be necessarily infringed. The patent license shall not apply to any other
** combinations which include the Contribution.
**
** Except as expressly stated above, no rights or licenses from any copyright
** holder or contributor is granted under this license, whether expressly, by
** implication, estoppel or otherwise.
**
** DISCLAIMER
**
** THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
** AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
** IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
** ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE
** LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
** DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
** SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
** CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
** OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
** USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
**
****************************************************************************/

#include <stdlib.h>
#include <string.h>

#include <amxc/amxc_hash.h>
#include <amxc/amxc_htable.h>
#include <amxc/amxc_macros.h>

/**
   @file
   @brief
   Ambiorix hash table API implementation
 */

static void amxc_htable_insert_it(amxc_htable_t* const htable,
                                  amxc_htable_it_t* const it) {
    unsigned int index = 0;
    amxc_array_it_t* ait = NULL;

    amxc_htable_it_take(it);
    index = amxc_htable_key2index(htable, it->key);
    ait = amxc_array_get_at(&htable->table, index);
    // insert item
    if((ait != NULL) && (ait->data != NULL)) {
        it->next = (amxc_htable_it_t*) ait->data;
    }
    amxc_array_it_set_data(ait, it);
    it->ait = ait;
    htable->items++;
}

static int amxc_htable_grow(amxc_htable_t* const htable, size_t hint) {
    int retval = -1;
    size_t capacity = htable->table.items;
    amxc_array_it_t* temp = htable->table.buffer;
    size_t start_bucket = htable->table.first_used;
    size_t end_bucket = htable->table.last_used;

    htable->table.buffer = NULL;
    htable->table.first_used = 0;
    htable->table.last_used = 0;
    htable->table.items = 0;
    htable->items = 0;

    when_null(temp, exit);

    if(hint != 0) {
        retval = amxc_array_grow(&htable->table, capacity + hint);
    } else {
        retval = amxc_array_grow(&htable->table, capacity > 1024 ? capacity + 1024 : 2 * capacity);
    }
    when_failed(retval, exit);

    for(size_t i = start_bucket; i <= end_bucket; i++) {
        amxc_htable_it_t* hit = (amxc_htable_it_t*) temp[i].data;
        amxc_htable_it_t* next = NULL;
        if(hit == NULL) {
            continue;
        }
        hit->ait = NULL;
        next = hit->next;
        hit->next = NULL;
        amxc_htable_insert_it(htable, hit);
        while(next) {
            hit = next;
            hit->ait = NULL;
            next = hit->next;
            hit->next = NULL;
            amxc_htable_insert_it(htable, hit);
        }
    }
    free(temp);

exit:
    return retval;
}

static void amxc_htable_it_delete_func(amxc_array_it_t* const it) {
    amxc_htable_t* htable = (amxc_htable_t*) it->array;
    amxc_htable_it_t* current = (amxc_htable_it_t*) it->data;

    while(current != NULL) {
        amxc_htable_it_t* next = current->next;
        char* key = current->key;
        current->key = NULL;
        amxc_htable_it_take(current);
        if(htable->it_del != NULL) {
            htable->it_del(key, current);
        }
        free(key);
        current = next;
    }
}

int amxc_htable_new(amxc_htable_t** htable, const size_t reserve) {
    int retval = -1;
    when_null(htable, exit);

    *htable = (amxc_htable_t*) calloc(1, sizeof(amxc_htable_t));
    when_null(*htable, exit);

    retval = amxc_htable_init(*htable, reserve);
    if(retval == -1) {
        free(*htable);
        *htable = NULL;
    }

exit:
    return retval;
}

static int amxc_htable_cmp_keys(amxc_array_it_t* it1, amxc_array_it_t* it2) {
    const char* key1 = (const char*) amxc_array_it_get_data(it1);
    const char* key2 = (const char*) amxc_array_it_get_data(it2);
    return strcmp(key1 == NULL? "":key1, key2 == NULL? "":key2);
}


void amxc_htable_delete(amxc_htable_t** htable, amxc_htable_it_delete_t func) {
    when_null(htable, exit);
    when_null(*htable, exit);

    (*htable)->it_del = func;
    amxc_array_clean(&(*htable)->table, amxc_htable_it_delete_func);
    free(*htable);
    *htable = NULL;

exit:
    return;
}

int amxc_htable_init(amxc_htable_t* const htable, const size_t reserve) {
    int retval = -1;
    when_null(htable, exit);

    htable->items = 0;
    htable->hfunc = amxc_BKDR_hash;

    when_failed(amxc_array_init(&htable->table, reserve != 0 ? reserve : 64), exit);

    retval = 0;

exit:
    return retval;
}

void amxc_htable_clean(amxc_htable_t* const htable, amxc_htable_it_delete_t func) {
    when_null(htable, exit);

    htable->it_del = func;
    amxc_array_clean(&htable->table, amxc_htable_it_delete_func);
    htable->items = 0;

exit:
    return;
}

void amxc_htable_set_hash_func(amxc_htable_t* const htable,
                               amxc_htable_hash_func_t func) {
    when_null(htable, exit);

    if(func != NULL) {
        htable->hfunc = func;
    } else {
        htable->hfunc = amxc_BKDR_hash;
    }

exit:
    return;
}

unsigned int amxc_htable_key2index(const amxc_htable_t* const htable,
                                   const char* const key) {
    unsigned int hash = AMXC_HTABLE_RANGE;
    when_null(htable, exit);
    when_true(htable->table.items == 0, exit);

    hash = htable->hfunc(key, strlen(key)) % htable->table.items;

exit:
    return hash;
}

int amxc_htable_insert(amxc_htable_t* const htable,
                       const char* const key,
                       amxc_htable_it_t* const it) {
    int retval = -1;

    when_null(htable, exit);
    when_null(key, exit);
    when_true(*key == 0, exit);
    when_null(it, exit);

    // remove the iterator first
    amxc_htable_it_take(it);
    // no side effects here, strcmp does not modify the content of the string
    // for performance reasons the pointer check is done first
    if((it->key != NULL) && (strcmp(it->key, key) != 0)) {
        free(it->key);
        it->key = NULL;
    }

    if((htable->table.items == 0) ||
       (((htable->items + 1) * 100) / htable->table.items >= 75)) {
        // time to grow the table
        when_failed(amxc_htable_grow(htable, 0), exit);
    }

    // update htable iterator
    if(it->key == NULL) {
        size_t length = strlen(key);
        it->key = (char*) calloc(length + 1, sizeof(char));
        when_null(it->key, exit);
        memcpy(it->key, key, length);
    }

    amxc_htable_insert_it(htable, it);

    retval = 0;

exit:
    return retval;
}

amxc_htable_it_t* amxc_htable_get(const amxc_htable_t* const htable,
                                  const char* const key) {
    amxc_htable_it_t* it = NULL;
    unsigned int index = 0;
    amxc_array_it_t* ait = NULL;

    when_null(htable, exit);
    when_null(key, exit);
    when_true(*key == 0, exit);

    when_true(htable->table.items == 0, exit);

    index = amxc_htable_key2index(htable, key);
    // the index is always in array bounderies.
    // the following line is always returning a valid array iterator pointer
    ait = amxc_array_get_at(&htable->table, index);

    it = ait == NULL? NULL:(amxc_htable_it_t*) ait->data;
    while(it != NULL && strcmp(key, it->key) != 0) {
        it = it->next;
    }

exit:
    return it;
}

amxc_htable_it_t* amxc_htable_take(amxc_htable_t* const htable,
                                   const char* const key) {
    amxc_htable_it_t* it = amxc_htable_get(htable, key);
    if(it != NULL) {
        amxc_htable_it_take(it);
    }
    return it;
}

amxc_htable_it_t* amxc_htable_get_first(const amxc_htable_t* const htable) {
    amxc_htable_it_t* it = NULL;
    amxc_array_it_t* ait = NULL;
    when_null(htable, exit);

    ait = amxc_array_get_first(&htable->table);
    when_null(ait, exit);
    it = (amxc_htable_it_t*) ait->data;

exit:
    return it;
}

amxc_htable_it_t* amxc_htable_get_last(const amxc_htable_t* const htable) {
    amxc_htable_it_t* it = NULL;
    amxc_array_it_t* ait = NULL;
    when_null(htable, exit);

    ait = amxc_array_get_last(&htable->table);
    when_null(ait, exit);
    it = (amxc_htable_it_t*) ait->data;

exit:
    return it;
}

amxc_array_t* amxc_htable_get_sorted_keys(const amxc_htable_t* const htable) {
    amxc_array_t* keys = NULL;
    uint32_t size = 0;
    uint32_t index = 0;
    when_null(htable, exit);

    size = amxc_htable_size(htable);
    when_true(size == 0, exit);

    amxc_array_new(&keys, size);
    when_null(keys, exit);

    amxc_htable_for_each(it, htable) {
        const char* key = amxc_htable_it_get_key(it);
        amxc_array_set_data_at(keys, index, (void*) key);
        index++;
    }

    amxc_array_sort(keys, amxc_htable_cmp_keys);

exit:
    return keys;
}

int amxc_htable_move(amxc_htable_t* const dest, amxc_htable_t* const src) {
    int retval = -1;
    size_t needed_items = 0;
    size_t needed_cap = 0;
    size_t dest_cap = 0;

    when_null(dest, exit);
    when_null(src, exit);

    needed_items = amxc_htable_size(src) + amxc_htable_size(dest);
    needed_cap = ((needed_items + 1) * 100) / 75;
    dest_cap = amxc_htable_capacity(dest);

    retval = 0;
    if(dest_cap < needed_cap) {
        retval = amxc_htable_grow(dest, needed_cap - dest_cap);
    }
    when_failed(retval, exit);

    amxc_htable_for_each(it, src) {
        amxc_htable_insert_it(dest, it);
    }

    retval = 0;

exit:
    return retval;
}