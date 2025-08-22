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

#include <stdio.h>

#include <stdlib.h>
#include <setjmp.h>
#include <stdarg.h>
#include <cmocka.h>
#include <amxc/amxc_hash.h>
#include <amxc/amxc_htable.h>

#include "test_amxc_htable.h"

#include <amxc/amxc_macros.h>
static unsigned int deletes = 0;
static amxc_htable_t* htable = NULL;
static amxc_htable_it_t it[2000];

static void amxc_htable_setup(void) {
    assert_int_equal(amxc_htable_new(&htable, 0), 0);

    for(int i = 0; i < 30; i++) {
        assert_int_equal(amxc_htable_it_init(&it[i]), 0);
    }
}

static void amxc_htable_teardown(void) {
    amxc_htable_delete(&htable, NULL);
}

static void amxc_delete_it_func(const char* key, amxc_htable_it_t* it) {
    assert_ptr_not_equal(it, NULL);
    assert_ptr_not_equal((char*) key, NULL);
    assert_ptr_equal(it->key, NULL);
    assert_ptr_equal(it->ait, NULL);
    assert_ptr_equal(it->next, NULL);
    deletes++;
}

void amxc_htable_new_delete_null_check(UNUSED void** state) {
    amxc_htable_setup();
    // passing NULL pointers should not lead to segfault
    assert_int_equal(amxc_htable_new(NULL, 0), -1);
    amxc_htable_delete(NULL, NULL);
    amxc_htable_teardown();
}

void amxc_htable_new_delete_check(UNUSED void** state) {
    amxc_htable_setup();
    amxc_htable_t* htable = NULL;
    assert_int_equal(amxc_htable_new(&htable, 0), 0);
    assert_ptr_not_equal(htable, NULL);
    assert_ptr_not_equal(htable->hfunc, NULL);
    assert_ptr_not_equal(htable->table.buffer, NULL);
    assert_int_equal(htable->items, 0);
    assert_int_equal(amxc_array_capacity(&htable->table), 64);

    amxc_htable_delete(&htable, NULL);
    assert_ptr_equal(htable, NULL);
    amxc_htable_teardown();
}

void amxc_htable_delete_func_check(UNUSED void** state) {
    amxc_htable_setup();
    char key[10] = "";

    for(int i = 0; i < 30; i++) {
        sprintf(key, "key%d", i);
        assert_int_equal(amxc_htable_insert(htable, key, &it[i]), 0);
    }

    amxc_htable_delete(&htable, amxc_delete_it_func);
    assert_int_equal(deletes, 30);
    amxc_htable_teardown();
}

void amxc_htable_init_clean_null_check(UNUSED void** state) {
    amxc_htable_setup();
    // passing NULL pointers should not lead to segfault
    assert_int_equal(amxc_htable_init(NULL, 0), -1);
    amxc_htable_clean(NULL, NULL);
    amxc_htable_teardown();
}

void amxc_htable_init_clean_check(UNUSED void** state) {
    amxc_htable_setup();
    amxc_htable_t htable;

    assert_int_equal(amxc_htable_init(&htable, 0), 0);
    assert_ptr_not_equal(htable.table.buffer, NULL);
    assert_ptr_not_equal(htable.hfunc, NULL);
    assert_int_equal(htable.items, 0);
    assert_int_equal(amxc_array_capacity(&htable.table), 64);

    amxc_htable_clean(&htable, NULL);
    assert_ptr_equal(htable.table.buffer, NULL);
    assert_ptr_not_equal(htable.hfunc, NULL);
    assert_int_equal(htable.items, 0);
    assert_int_equal(amxc_array_capacity(&htable.table), 0);
    amxc_htable_teardown();
}

void amxc_htable_init_reserve_check(UNUSED void** state) {
    amxc_htable_setup();
    amxc_htable_t htable;

    assert_int_equal(amxc_htable_init(&htable, 32), 0);
    assert_ptr_not_equal(htable.table.buffer, NULL);
    assert_ptr_not_equal(htable.hfunc, NULL);
    assert_int_equal(htable.items, 0);
    assert_int_equal(amxc_array_capacity(&htable.table), 32);
    amxc_htable_clean(&htable, NULL);

    assert_int_equal(amxc_htable_init(&htable, 66), 0);
    assert_ptr_not_equal(htable.table.buffer, NULL);
    assert_ptr_not_equal(htable.hfunc, NULL);
    assert_int_equal(htable.items, 0);
    assert_int_equal(amxc_array_capacity(&htable.table), 66);
    amxc_htable_clean(&htable, NULL);
    amxc_htable_teardown();
}

void amxc_htable_set_hash_func_check(UNUSED void** state) {
    amxc_htable_setup();
    // should not segfault
    amxc_htable_set_hash_func(NULL, NULL);

    // check for default hash function
    assert_ptr_equal(htable->hfunc, amxc_BKDR_hash);

    // change hash function
    amxc_htable_set_hash_func(htable, amxc_DJB_hash);
    assert_ptr_equal(htable->hfunc, amxc_DJB_hash);

    // reset to default hash function
    amxc_htable_set_hash_func(htable, NULL);
    assert_ptr_equal(htable->hfunc, amxc_BKDR_hash);
    amxc_htable_teardown();
}

void amxc_htable_key2index_null_check(UNUSED void** state) {
    amxc_htable_setup();
    // should not segfault
    assert_int_equal(amxc_htable_key2index(NULL, NULL), AMXC_HTABLE_RANGE);
    assert_int_equal(amxc_htable_key2index(NULL, "data"), AMXC_HTABLE_RANGE);

    // delete the hash table buffer
    amxc_htable_clean(htable, NULL);
    assert_int_equal(amxc_htable_key2index(htable, "data"), AMXC_HTABLE_RANGE);
    amxc_htable_teardown();
}

void amxc_htable_key2index_check(UNUSED void** state) {
    amxc_htable_setup();
    // should not segfault
    assert_int_equal(amxc_htable_key2index(htable, "Key1"), 18);
    assert_int_equal(amxc_htable_key2index(htable, "Key2"), 19);
    amxc_htable_teardown();
}

void amxc_htable_insert_null_check(UNUSED void** state) {
    amxc_htable_setup();
    assert_int_equal(amxc_htable_insert(NULL, NULL, NULL), -1);

    assert_int_equal(amxc_htable_insert(htable, NULL, NULL), -1);
    assert_int_equal(htable->items, 0);

    assert_int_equal(amxc_htable_insert(htable, "", NULL), -1);
    assert_int_equal(htable->items, 0);

    assert_int_equal(amxc_htable_insert(htable, "TestKey", NULL), -1);
    assert_int_equal(htable->items, 0);

    assert_int_equal(amxc_htable_insert(htable, NULL, &it[0]), -1);
    assert_int_equal(htable->items, 0);
    amxc_htable_teardown();
}

void amxc_htable_insert_check(UNUSED void** state) {
    amxc_htable_setup();
    assert_int_equal(amxc_htable_insert(htable, "TestKey", &it[0]), 0);
    assert_ptr_not_equal(it[0].ait, NULL);
    assert_ptr_equal(it[0].ait->array, &htable->table);
    assert_string_equal(it[0].key, "TestKey");
    // it is the first item, so the next pointer should be 0
    assert_ptr_equal(it[0].next, NULL);
    assert_int_equal(htable->items, 1);
    amxc_htable_teardown();
}

void amxc_htable_insert_same_key_check(UNUSED void** state) {
    amxc_htable_setup();
    assert_int_equal(amxc_htable_insert(htable, "TestKey", &it[0]), 0);
    assert_ptr_not_equal(it[0].ait, NULL);
    assert_ptr_equal(it[0].ait->array, &htable->table);
    assert_string_equal(it[0].key, "TestKey");
    // it is the first item, so the next pointer should be 0
    assert_ptr_equal(it[0].next, NULL);
    assert_int_equal(htable->items, 1);

    assert_int_equal(amxc_htable_insert(htable, "TestKey", &it[1]), 0);
    assert_ptr_not_equal(it[1].ait, NULL);
    assert_ptr_equal(it[1].ait->array, &htable->table);
    assert_string_equal(it[1].key, "TestKey");
    // it is the second item with same key, so the next pointer should be set to it[0]
    assert_ptr_equal(it[1].next, &it[0]);

    // same position
    assert_ptr_equal(it[0].ait, it[1].ait);
    assert_int_equal(htable->items, 2);
    amxc_htable_teardown();
}

void amxc_htable_insert_same_it_check(UNUSED void** state) {
    amxc_htable_setup();
    assert_int_equal(amxc_htable_insert(htable, "TestKey", &it[0]), 0);

    assert_int_equal(amxc_htable_insert(htable, "AnotherKey", &it[0]), 0);
    assert_ptr_not_equal(it[0].ait, NULL);
    assert_string_equal(it[0].key, "AnotherKey");
    assert_int_equal(htable->items, 1);

    assert_int_equal(amxc_htable_insert(htable, "AnotherKey", &it[0]), 0);
    assert_ptr_not_equal(it[0].ait, NULL);
    assert_string_equal(it[0].key, "AnotherKey");
    assert_int_equal(htable->items, 1);
    amxc_htable_teardown();
}

void amxc_htable_insert_grow_check(UNUSED void** state) {
    amxc_htable_setup();
    amxc_htable_delete(&htable, NULL);

    char key[10];
    assert_int_equal(amxc_htable_new(&htable, 8), 0);
    for(int i = 0; i < 30; i++) {
        sprintf(key, "key%d", i);
        assert_int_equal(amxc_htable_insert(htable, key, &it[i]), 0);
        assert_ptr_not_equal(it[i].ait, NULL);
        assert_string_equal(it[i].key, key);
        assert_int_equal(htable->items, i + 1);
        if(i == 6) {
            assert_int_equal(amxc_htable_capacity(htable), 16);
        }
        if(i == 12) {
            assert_int_equal(amxc_htable_capacity(htable), 32);
        }
    }

    assert_int_equal(amxc_htable_capacity(htable), 64);
    amxc_htable_teardown();
}

void amxc_htable_insert_grow_big_check(UNUSED void** state) {
    amxc_htable_setup();
    amxc_htable_delete(&htable, NULL);

    char key[10];
    assert_int_equal(amxc_htable_new(&htable, 1025), 0);
    for(int i = 0; i < 2000; i++) {
        sprintf(key, "key%d", i);
        assert_int_equal(amxc_htable_insert(htable, key, &it[i]), 0);
        assert_ptr_not_equal(it[i].ait, NULL);
        assert_string_equal(it[i].key, key);
        assert_int_equal(htable->items, i + 1);
    }

    assert_int_equal(amxc_htable_capacity(htable), 1025 + 1024 + 1024);
    amxc_htable_teardown();
}

void amxc_htable_is_empty_null_check(UNUSED void** state) {
    amxc_htable_setup();
    assert_int_equal(amxc_htable_is_empty(NULL), true);
    amxc_htable_teardown();
}

void amxc_htable_is_empty_check(UNUSED void** state) {
    amxc_htable_setup();
    assert_int_equal(amxc_htable_is_empty(htable), true);

    amxc_htable_insert(htable, "Key1", &it[0]);
    assert_int_equal(amxc_htable_is_empty(htable), false);

    amxc_htable_teardown();
}

void amxc_htable_size_null_check(UNUSED void** state) {
    amxc_htable_setup();
    assert_int_equal(amxc_htable_size(NULL), 0);
    amxc_htable_teardown();
}

void amxc_htable_size_check(UNUSED void** state) {
    amxc_htable_setup();
    assert_int_equal(amxc_htable_size(htable), 0);

    amxc_htable_insert(htable, "Key1", &it[0]);
    assert_int_equal(amxc_htable_size(htable), 1);

    amxc_htable_insert(htable, "Key1", &it[0]);
    assert_int_equal(amxc_htable_size(htable), 1);

    amxc_htable_insert(htable, "Key2", &it[1]);
    assert_int_equal(amxc_htable_size(htable), 2);
    amxc_htable_teardown();
}

void amxc_htable_capacity_null_check(UNUSED void** state) {
    amxc_htable_setup();
    assert_int_equal(amxc_htable_capacity(NULL), 0);
    amxc_htable_teardown();
}

void amxc_htable_capacity_check(UNUSED void** state) {
    amxc_htable_setup();
    amxc_htable_delete(&htable, NULL);

    assert_int_equal(amxc_htable_new(&htable, 8), 0);
    assert_int_equal(amxc_htable_capacity(htable), 8);

    assert_int_equal(amxc_htable_insert(htable, "key0", &it[0]), 0);
    assert_int_equal(amxc_htable_insert(htable, "key1", &it[1]), 0);
    assert_int_equal(amxc_htable_insert(htable, "key2", &it[2]), 0);
    assert_int_equal(amxc_htable_insert(htable, "key3", &it[3]), 0);
    assert_int_equal(amxc_htable_insert(htable, "key4", &it[4]), 0);
    assert_int_equal(amxc_htable_insert(htable, "key5", &it[5]), 0);
    assert_int_equal(amxc_htable_capacity(htable), 16);
    amxc_htable_teardown();
}

void amxc_htable_get_null_check(UNUSED void** state) {
    amxc_htable_setup();
    assert_ptr_equal(amxc_htable_get(NULL, NULL), NULL);

    assert_ptr_equal(amxc_htable_get(htable, NULL), NULL);
    assert_ptr_equal(amxc_htable_get(htable, ""), NULL);
    amxc_htable_teardown();
}

void amxc_htable_get_check(UNUSED void** state) {
    amxc_htable_setup();
    amxc_htable_insert(htable, "Key1", &it[0]);
    amxc_htable_insert(htable, "Key2", &it[1]);
    amxc_htable_insert(htable, "Key3", &it[2]);
    amxc_htable_insert(htable, "Key4", &it[3]);
    amxc_htable_insert(htable, "Key5", &it[4]);

    assert_ptr_equal(amxc_htable_get(htable, "Key3"), &it[2]);
    assert_string_equal(it[2].key, "Key3");
    assert_ptr_not_equal(it[2].ait, NULL);

    assert_ptr_equal(amxc_htable_get(htable, "Key1"), &it[0]);
    assert_string_equal(it[0].key, "Key1");
    assert_ptr_not_equal(it[0].ait, NULL);

    assert_ptr_equal(amxc_htable_get(htable, "Key4"), &it[3]);
    assert_string_equal(it[3].key, "Key4");
    assert_ptr_not_equal(it[3].ait, NULL);

    assert_ptr_equal(amxc_htable_get(htable, "Key2"), &it[1]);
    assert_string_equal(it[1].key, "Key2");
    assert_ptr_not_equal(it[1].ait, NULL);

    assert_ptr_equal(amxc_htable_get(htable, "Key5"), &it[4]);
    assert_string_equal(it[4].key, "Key5");
    assert_ptr_not_equal(it[4].ait, NULL);

    assert_ptr_equal(amxc_htable_get(htable, "Dummy"), NULL);

    // clean the table
    amxc_htable_clean(htable, NULL);
    assert_ptr_equal(amxc_htable_get(htable, "Dummy"), NULL);
    amxc_htable_teardown();
}

void amxc_htable_get_chained_check(UNUSED void** state) {
    amxc_htable_setup();
    amxc_htable_insert(htable, "Key1", &it[0]);
    amxc_htable_insert(htable, "Key610", &it[1]);

    assert_ptr_equal(amxc_htable_get(htable, "Key610"), &it[1]);
    assert_string_equal(it[1].key, "Key610");
    assert_ptr_not_equal(it[1].ait, NULL);
    assert_ptr_equal(it[1].next, &it[0]);

    assert_ptr_equal(amxc_htable_get(htable, "Key1"), &it[0]);
    assert_string_equal(it[0].key, "Key1");
    assert_ptr_not_equal(it[0].ait, NULL);
    amxc_htable_teardown();
}

void amxc_htable_get_first_null_check(UNUSED void** state) {
    amxc_htable_setup();
    assert_ptr_equal(amxc_htable_get_first(NULL), NULL);

    assert_ptr_equal(amxc_htable_get_first(htable), NULL);
    amxc_htable_teardown();
}

void amxc_htable_get_first_check(UNUSED void** state) {
    amxc_htable_setup();
    amxc_htable_insert(htable, "Key1", &it[0]);

    assert_ptr_equal(amxc_htable_get_first(htable), &it[0]);
    assert_string_equal(it[0].key, "Key1");
    assert_ptr_not_equal(it[0].ait, NULL);

    // clean the table
    amxc_htable_clean(htable, NULL);
    assert_ptr_equal(amxc_htable_get_first(htable), NULL);
    amxc_htable_teardown();
}

void amxc_htable_get_last_null_check(UNUSED void** state) {
    amxc_htable_setup();
    assert_ptr_equal(amxc_htable_get_last(NULL), NULL);

    assert_ptr_equal(amxc_htable_get_last(htable), NULL);
    amxc_htable_teardown();
}

void amxc_htable_get_last_check(UNUSED void** state) {
    amxc_htable_setup();
    amxc_htable_insert(htable, "Key1", &it[0]);

    assert_ptr_equal(amxc_htable_get_last(htable), &it[0]);
    assert_string_equal(it[0].key, "Key1");
    assert_ptr_not_equal(it[0].ait, NULL);

    // clean the table
    amxc_htable_clean(htable, NULL);
    assert_ptr_equal(amxc_htable_get_last(htable), NULL);
    amxc_htable_teardown();
}

void amxc_htable_take_null_check(UNUSED void** state) {
    amxc_htable_setup();
    assert_ptr_equal(amxc_htable_take(NULL, NULL), NULL);

    assert_ptr_equal(amxc_htable_take(htable, NULL), NULL);
    assert_ptr_equal(amxc_htable_take(htable, ""), NULL);
    amxc_htable_teardown();
}

void amxc_htable_take_check(UNUSED void** state) {
    amxc_htable_setup();
    amxc_htable_insert(htable, "Key1", &it[0]);
    amxc_htable_insert(htable, "Key2", &it[1]);
    amxc_htable_insert(htable, "Key3", &it[2]);
    amxc_htable_insert(htable, "Key4", &it[3]);
    amxc_htable_insert(htable, "Key5", &it[4]);

    assert_ptr_equal(amxc_htable_take(htable, "Key3"), &it[2]);
    assert_string_equal(it[2].key, "Key3");
    assert_ptr_equal(it[2].ait, NULL);
    assert_int_equal(htable->items, 4);

    assert_ptr_equal(amxc_htable_take(htable, "Key1"), &it[0]);
    assert_string_equal(it[0].key, "Key1");
    assert_ptr_equal(it[0].ait, NULL);
    assert_int_equal(htable->items, 3);

    assert_ptr_equal(amxc_htable_take(htable, "Key4"), &it[3]);
    assert_string_equal(it[3].key, "Key4");
    assert_ptr_equal(it[3].ait, NULL);
    assert_int_equal(htable->items, 2);

    assert_ptr_equal(amxc_htable_take(htable, "Key2"), &it[1]);
    assert_string_equal(it[1].key, "Key2");
    assert_ptr_equal(it[1].ait, NULL);
    assert_int_equal(htable->items, 1);

    assert_ptr_equal(amxc_htable_take(htable, "Key5"), &it[4]);
    assert_string_equal(it[4].key, "Key5");
    assert_ptr_equal(it[4].ait, NULL);
    assert_int_equal(htable->items, 0);

    amxc_htable_it_clean(&it[0], NULL);
    amxc_htable_it_clean(&it[1], NULL);
    amxc_htable_it_clean(&it[2], NULL);
    amxc_htable_it_clean(&it[3], NULL);
    amxc_htable_it_clean(&it[4], NULL);
    amxc_htable_teardown();
}

void amxc_htable_take_chained_check(UNUSED void** state) {
    amxc_htable_setup();
    amxc_htable_insert(htable, "Key1", &it[0]);
    amxc_htable_insert(htable, "Key610", &it[1]);

    assert_ptr_equal(amxc_htable_take(htable, "Key610"), &it[1]);
    assert_string_equal(it[1].key, "Key610");
    assert_ptr_equal(it[1].ait, NULL);
    assert_ptr_equal(it[1].next, NULL);
    assert_int_equal(htable->items, 1);

    assert_ptr_equal(amxc_htable_take(htable, "Key1"), &it[0]);
    assert_string_equal(it[0].key, "Key1");
    assert_ptr_equal(it[0].ait, NULL);
    assert_int_equal(htable->items, 0);

    assert_ptr_equal(amxc_htable_take(htable, "Dummy"), NULL);

    amxc_htable_it_clean(&it[0], NULL);
    amxc_htable_it_clean(&it[1], NULL);
    amxc_htable_teardown();
}

void amxc_htable_take_first_null_check(UNUSED void** state) {
    amxc_htable_setup();
    assert_ptr_equal(amxc_htable_take_first(NULL), NULL);

    assert_ptr_equal(amxc_htable_take_first(htable), NULL);
    amxc_htable_teardown();
}

void amxc_htable_take_first_check(UNUSED void** state) {
    amxc_htable_setup();
    amxc_htable_insert(htable, "Key1", &it[0]);

    assert_ptr_equal(amxc_htable_take_first(htable), &it[0]);
    assert_string_equal(it[0].key, "Key1");
    assert_ptr_equal(it[0].ait, NULL);

    amxc_htable_it_clean(&it[0], NULL);

    // clean the table
    amxc_htable_clean(htable, NULL);
    assert_ptr_equal(amxc_htable_take_first(htable), NULL);
    amxc_htable_teardown();
}

void amxc_htable_contains_null_check(UNUSED void** state) {
    amxc_htable_setup();
    assert_int_equal(amxc_htable_contains(NULL, NULL), false);

    assert_int_equal(amxc_htable_contains(htable, NULL), false);
    assert_int_equal(amxc_htable_contains(htable, ""), false);
    amxc_htable_teardown();
}

void amxc_htable_contains_check(UNUSED void** state) {
    amxc_htable_setup();
    amxc_htable_insert(htable, "Key1", &it[0]);
    amxc_htable_insert(htable, "Key2", &it[1]);

    assert_int_equal(amxc_htable_contains(htable, "Key1"), true);
    assert_int_equal(amxc_htable_contains(htable, "Key2"), true);
    assert_int_equal(amxc_htable_contains(htable, "Key3"), false);
    amxc_htable_teardown();
}

void amxc_htable_it_get_next_null_check(UNUSED void** state) {
    amxc_htable_setup();
    assert_ptr_equal(amxc_htable_it_get_next(NULL), NULL);
    assert_ptr_equal(amxc_htable_it_get_next(&it[0]), NULL);
    amxc_htable_teardown();
}

void amxc_htable_it_get_next_check(UNUSED void** state) {
    amxc_htable_setup();
    amxc_htable_insert(htable, "Key1", &it[0]);
    amxc_htable_insert(htable, "Key2", &it[1]);
    amxc_htable_insert(htable, "Key3", &it[2]);
    amxc_htable_insert(htable, "Key4", &it[3]);
    amxc_htable_insert(htable, "Key5", &it[4]);

    unsigned int count = 0;
    amxc_htable_it_t* it = amxc_htable_get_first(htable);
    while(it) {
        it = amxc_htable_it_get_next(it);
        count++;
    }

    assert_int_equal(count, 5);
    amxc_htable_teardown();
}

void amxc_htable_it_get_next_chained_check(UNUSED void** state) {
    amxc_htable_setup();
    amxc_htable_insert(htable, "Key", &it[0]);
    amxc_htable_insert(htable, "Key", &it[1]);
    amxc_htable_insert(htable, "Key", &it[2]);
    amxc_htable_insert(htable, "Key", &it[3]);
    amxc_htable_insert(htable, "Key", &it[4]);

    amxc_array_it_t* ait = it[0].ait;
    unsigned int count = 0;
    amxc_htable_it_t* it = amxc_htable_get_first(htable);
    while(it) {
        assert_ptr_equal(it->ait, ait);
        it = amxc_htable_it_get_next(it);
        count++;
    }

    assert_int_equal(count, 5);
    amxc_htable_teardown();
}

void amxc_htable_it_get_next_key_null_check(UNUSED void** state) {
    amxc_htable_setup();
    assert_ptr_equal(amxc_htable_it_get_next_key(NULL), NULL);
    assert_ptr_equal(amxc_htable_it_get_next_key(&it[0]), NULL);
    amxc_htable_teardown();
}

void amxc_htable_it_get_next_key_check(UNUSED void** state) {
    amxc_htable_setup();
    amxc_htable_insert(htable, "Key1", &it[0]);
    amxc_htable_insert(htable, "Key2", &it[1]);
    amxc_htable_insert(htable, "Key3", &it[2]);
    amxc_htable_insert(htable, "Key4", &it[3]);
    amxc_htable_insert(htable, "Key5", &it[4]);
    amxc_htable_insert(htable, "Key610", &it[11]);
    amxc_htable_insert(htable, "Key1", &it[5]);
    amxc_htable_insert(htable, "Key2", &it[6]);
    amxc_htable_insert(htable, "Key3", &it[7]);
    amxc_htable_insert(htable, "Key1", &it[8]);
    amxc_htable_insert(htable, "Key2", &it[9]);
    amxc_htable_insert(htable, "Key3", &it[10]);

    unsigned int count = 0;
    amxc_array_it_t* ait = it[0].ait;
    amxc_htable_it_t* iter = amxc_htable_get(htable, "Key1");
    while(iter) {
        assert_ptr_equal(iter->ait, ait);
        iter = amxc_htable_it_get_next_key(iter);
        count++;
    }

    assert_int_equal(count, 3);

    count = 0;
    ait = it[2].ait;
    iter = amxc_htable_get(htable, "Key3");
    while(iter) {
        assert_ptr_equal(iter->ait, ait);
        iter = amxc_htable_it_get_next_key(iter);
        count++;
    }

    assert_int_equal(count, 3);

    count = 0;
    iter = amxc_htable_get(htable, "Key4");
    while(iter) {
        iter = amxc_htable_it_get_next_key(iter);
        count++;
    }

    assert_int_equal(count, 1);
    amxc_htable_teardown();
}

void amxc_htable_it_get_previous_null_check(UNUSED void** state) {
    amxc_htable_setup();
    assert_ptr_equal(amxc_htable_it_get_previous(NULL), NULL);
    assert_ptr_equal(amxc_htable_it_get_previous(&it[0]), NULL);
    amxc_htable_teardown();
}

void amxc_htable_it_get_previous_check(UNUSED void** state) {
    amxc_htable_setup();
    amxc_htable_insert(htable, "Key1", &it[0]);
    amxc_htable_insert(htable, "Key2", &it[1]);
    amxc_htable_insert(htable, "Key3", &it[2]);
    amxc_htable_insert(htable, "Key4", &it[3]);
    amxc_htable_insert(htable, "Key5", &it[4]);

    unsigned int count = 0;
    amxc_htable_it_t* it = amxc_htable_get_last(htable);
    while(it) {
        it = amxc_htable_it_get_previous(it);
        count++;
    }

    assert_int_equal(count, 5);
    amxc_htable_teardown();
}

void amxc_htable_it_get_previous_chained_check(UNUSED void** state) {
    amxc_htable_setup();
    amxc_htable_insert(htable, "Key", &it[0]);
    amxc_htable_insert(htable, "Key", &it[1]);
    amxc_htable_insert(htable, "Key", &it[2]);
    amxc_htable_insert(htable, "Key", &it[3]);
    amxc_htable_insert(htable, "Key", &it[4]);

    amxc_array_it_t* ait = it[0].ait;
    unsigned int count = 0;
    amxc_htable_it_t* it = amxc_htable_get_last(htable);
    while(it) {
        assert_ptr_equal(it->ait, ait);
        it = amxc_htable_it_get_previous(it);
        count++;
    }

    assert_int_equal(count, 5);
    amxc_htable_teardown();
}

void amxc_htable_it_get_previous_key_null_check(UNUSED void** state) {
    amxc_htable_setup();
    assert_ptr_equal(amxc_htable_it_get_previous(NULL), NULL);
    assert_ptr_equal(amxc_htable_it_get_previous(&it[0]), NULL);
    amxc_htable_teardown();
}

void amxc_htable_it_get_previous_key_check(UNUSED void** state) {
    amxc_htable_setup();
    amxc_htable_insert(htable, "Key1", &it[0]);
    amxc_htable_insert(htable, "Key2", &it[1]);
    amxc_htable_insert(htable, "Key3", &it[2]);
    amxc_htable_insert(htable, "Key4", &it[3]);
    amxc_htable_insert(htable, "Key5", &it[4]);
    amxc_htable_insert(htable, "Key610", &it[11]);
    amxc_htable_insert(htable, "Key1", &it[5]);
    amxc_htable_insert(htable, "Key2", &it[6]);
    amxc_htable_insert(htable, "Key3", &it[7]);
    amxc_htable_insert(htable, "Key1", &it[8]);
    amxc_htable_insert(htable, "Key2", &it[9]);
    amxc_htable_insert(htable, "Key3", &it[10]);

    unsigned int count = 0;
    amxc_array_it_t* ait = it[0].ait;
    amxc_htable_it_t* iter = amxc_htable_get(htable, "Key1");
    while(iter) {
        assert_ptr_equal(iter->ait, ait);
        iter = amxc_htable_it_get_previous_key(iter);
        count++;
    }

    assert_int_equal(count, 3);

    count = 0;
    ait = it[2].ait;
    iter = amxc_htable_get(htable, "Key3");
    while(iter) {
        assert_ptr_equal(iter->ait, ait);
        iter = amxc_htable_it_get_previous_key(iter);
        count++;
    }

    assert_int_equal(count, 3);

    count = 0;
    iter = amxc_htable_get(htable, "Key4");
    while(iter) {
        iter = amxc_htable_it_get_previous_key(iter);
        count++;
    }

    assert_int_equal(count, 1);
    amxc_htable_teardown();
}

void amxc_htable_it_take_null_check(UNUSED void** state) {
    amxc_htable_setup();
    amxc_htable_it_take(NULL);
    amxc_htable_it_take(&it[0]);
    amxc_htable_teardown();
}

void amxc_htable_it_take_check(UNUSED void** state) {
    amxc_htable_setup();
    amxc_htable_insert(htable, "Key1", &it[0]);
    amxc_htable_insert(htable, "Key2", &it[1]);
    amxc_htable_insert(htable, "Key3", &it[2]);
    amxc_htable_insert(htable, "Key4", &it[3]);
    amxc_htable_insert(htable, "Key5", &it[4]);

    amxc_htable_it_take(&it[3]);
    assert_int_equal(amxc_htable_size(htable), 4);
    assert_string_equal(it[3].key, "Key4");
    assert_ptr_equal(it[3].ait, NULL);
    assert_ptr_equal(it[3].next, NULL);

    amxc_htable_it_take(&it[4]);
    assert_int_equal(amxc_htable_size(htable), 3);
    assert_string_equal(it[4].key, "Key5");
    assert_ptr_equal(it[4].ait, NULL);
    assert_ptr_equal(it[4].next, NULL);

    amxc_htable_it_clean(&it[3], NULL);
    amxc_htable_it_clean(&it[4], NULL);
    amxc_htable_teardown();
}

void amxc_htable_it_take_chained_check(UNUSED void** state) {
    amxc_htable_setup();
    amxc_htable_insert(htable, "Key", &it[0]);
    amxc_htable_insert(htable, "Key", &it[1]);
    amxc_htable_insert(htable, "Key", &it[2]);
    amxc_htable_insert(htable, "Key", &it[3]);
    amxc_htable_insert(htable, "Key", &it[4]);

    amxc_htable_it_take(&it[2]);
    assert_int_equal(amxc_htable_size(htable), 4);
    assert_string_equal(it[2].key, "Key");
    assert_ptr_equal(it[2].ait, NULL);
    assert_ptr_equal(it[2].next, NULL);

    amxc_htable_it_take(&it[0]);
    assert_int_equal(amxc_htable_size(htable), 3);
    assert_string_equal(it[0].key, "Key");
    assert_ptr_equal(it[0].ait, NULL);
    assert_ptr_equal(it[0].next, NULL);

    amxc_htable_it_take(&it[4]);
    assert_int_equal(amxc_htable_size(htable), 2);
    assert_string_equal(it[4].key, "Key");
    assert_ptr_equal(it[4].ait, NULL);
    assert_ptr_equal(it[4].next, NULL);

    amxc_htable_it_clean(&it[0], NULL);
    amxc_htable_it_clean(&it[2], NULL);
    amxc_htable_it_clean(&it[4], NULL);
    amxc_htable_teardown();
}

void amxc_htable_it_get_key_check(UNUSED void** state) {
    amxc_htable_setup();
    assert_ptr_equal((void*) amxc_htable_it_get_key(NULL), NULL);
    assert_ptr_equal((void*) amxc_htable_it_get_key(&it[0]), NULL);

    amxc_htable_insert(htable, "SomeKey", &it[0]);
    assert_string_equal(amxc_htable_it_get_key(&it[0]), "SomeKey");
    amxc_htable_take(htable, "SomeKey");
    assert_string_equal(amxc_htable_it_get_key(&it[0]), "SomeKey");

    amxc_htable_it_clean(&it[0], NULL);
    amxc_htable_teardown();
}

void amxc_htable_it_init_null_check(UNUSED void** state) {
    amxc_htable_setup();
    amxc_htable_it_init(NULL);
    amxc_htable_teardown();
}

void amxc_htable_it_clean_null_check(UNUSED void** state) {
    amxc_htable_setup();
    amxc_htable_it_clean(NULL, NULL);
    amxc_htable_teardown();
}

void amxc_htable_it_clean_func_check(UNUSED void** state) {
    amxc_htable_setup();
    deletes = 0;
    amxc_htable_insert(htable, "SomeKey", &it[0]);
    assert_string_equal(it[0].key, "SomeKey");
    amxc_htable_it_clean(&it[0], amxc_delete_it_func);
    assert_int_equal(deletes, 1);
    amxc_htable_teardown();
}

void amxc_htable_get_sorted_keys_check(UNUSED void** state) {
    amxc_htable_setup();
    amxc_htable_delete(&htable, NULL);
    amxc_array_t* array = NULL;

    char key[10];
    assert_int_equal(amxc_htable_new(&htable, 1025), 0);
    for(int i = 0; i < 2000; i++) {
        sprintf(key, "key%4d", i);
        assert_int_equal(amxc_htable_insert(htable, key, &it[i]), 0);
        assert_ptr_not_equal(it[i].ait, NULL);
        assert_string_equal(it[i].key, key);
        assert_int_equal(htable->items, i + 1);
    }

    assert_int_equal(amxc_htable_capacity(htable), 1025 + 1024 + 1024);
    array = amxc_htable_get_sorted_keys(htable);
    assert_non_null(array);
    assert_int_equal(amxc_array_size(array), 2000);

    for(int i = 0; i < 2000; i++) {
        const char* ak = (const char*) amxc_array_get_data_at(array, i);
        sprintf(key, "key%4d", i);
        assert_string_equal(ak, key);
    }

    amxc_array_delete(&array, NULL);
    amxc_htable_clean(htable, NULL);

    array = amxc_htable_get_sorted_keys(htable);
    assert_null(array);
    array = amxc_htable_get_sorted_keys(NULL);
    assert_null(array);

    amxc_htable_teardown();
}

void amxc_htable_move_check(UNUSED void** state) {
    amxc_htable_setup();
    amxc_htable_delete(&htable, NULL);

    amxc_htable_t dest;
    amxc_htable_init(&dest, 0);

    char key[10];
    assert_int_equal(amxc_htable_new(&htable, 1025), 0);
    for(int i = 0; i < 2000; i++) {
        sprintf(key, "key%4d", i);
        assert_int_equal(amxc_htable_insert(htable, key, &it[i]), 0);
        assert_ptr_not_equal(it[i].ait, NULL);
        assert_string_equal(it[i].key, key);
        assert_int_equal(htable->items, i + 1);
    }

    for(int i = 0; i < 2000; i++) {
        sprintf(key, "key%4d", i);
        assert_true(amxc_htable_contains(htable, key));
        assert_ptr_equal(amxc_htable_get(htable, key), &it[i]);
    }

    assert_int_equal(amxc_htable_move(&dest, htable), 0);
    assert_int_equal(amxc_htable_size(&dest), 2000);
    assert_true(amxc_htable_is_empty(htable));

    for(int i = 0; i < 2000; i++) {
        sprintf(key, "key%4d", i);
        assert_true(amxc_htable_contains(&dest, key));
        assert_ptr_equal(amxc_htable_get(&dest, key), &it[i]);
    }

    assert_int_equal(amxc_htable_move(htable, &dest), 0);

    assert_int_not_equal(amxc_htable_move(NULL, htable), 0);
    assert_int_not_equal(amxc_htable_move(&dest, NULL), 0);

    amxc_htable_clean(&dest, NULL);
    amxc_htable_teardown();
}

void amxc_htable_check_null_ptr(UNUSED void** state) {
    htable = (amxc_htable_t*) calloc(1, sizeof(amxc_htable_t));
    assert_non_null(htable);
    assert_int_not_equal(amxc_htable_insert(htable, "Key", &it[0]), 0);
    assert_int_equal(amxc_htable_init(htable, 10), 0);
    assert_int_equal(amxc_htable_insert(htable, "Key", &it[0]), 0);
    amxc_htable_delete(&htable, NULL);
}
