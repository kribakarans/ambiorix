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

#include <sys/time.h>
#include <sys/resource.h>

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <inttypes.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <cmocka.h>

#include <amxc/amxc_variant.h>
#include <amxc_variant_priv.h>

#include "test_variant_list.h"

#include <amxc/amxc_macros.h>
void test_variant_llist_get_index(UNUSED void** state) {
    amxc_var_t var;
    amxc_var_t string;
    amxc_var_t* key_part = NULL;
    const amxc_var_t* key_part_const = NULL;

    amxc_var_init(&var);
    amxc_var_init(&string);
    amxc_var_set(cstring_t, &string, "Hello,world,and,anyone,else,in,the,universe");
    assert_int_equal(amxc_var_convert(&var, &string, AMXC_VAR_ID_LIST), 0);
    assert_int_equal(amxc_var_type_of(&var), AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_llist_size(&var.data.vl), 8);

    key_part = amxc_var_get_index(&var, 6, AMXC_VAR_FLAG_COPY);
    assert_ptr_not_equal(key_part, NULL);
    assert_int_equal(amxc_var_type_of(key_part), AMXC_VAR_ID_CSTRING);
    assert_ptr_equal(key_part->lit.llist, NULL);
    assert_string_equal(key_part->data.s, "the");
    amxc_var_delete(&key_part);
    assert_ptr_equal(key_part, NULL);

    key_part_const = amxc_var_get_index(&var, 5, AMXC_VAR_FLAG_DEFAULT);
    assert_ptr_not_equal(key_part_const, NULL);
    assert_int_equal(amxc_var_type_of(key_part_const), AMXC_VAR_ID_CSTRING);
    assert_ptr_not_equal(key_part_const->lit.llist, NULL);
    assert_string_equal(key_part_const->data.s, "in");

    key_part = amxc_var_get_index(&var, 99, AMXC_VAR_FLAG_COPY);
    assert_ptr_equal(key_part, NULL);

    amxc_var_set_type(&var, AMXC_VAR_ID_BOOL);
    key_part = amxc_var_get_index(&var, 6, AMXC_VAR_FLAG_COPY);
    assert_ptr_equal(key_part, NULL);

    amxc_var_clean(&string);
    amxc_var_clean(&var);
}

void test_variant_llist_set_index(UNUSED void** state) {
    amxc_var_t var;
    amxc_var_t string;
    amxc_var_t* key_part = NULL;
    amxc_var_t* key_part_copy = NULL;
    const amxc_var_t* key_part_const = NULL;

    amxc_var_init(&var);
    amxc_var_init(&string);
    amxc_var_set(cstring_t, &string, "Hello,world,and,anyone,else,in,the,universe");
    assert_int_equal(amxc_var_convert(&var, &string, AMXC_VAR_ID_LIST), 0);
    assert_int_equal(amxc_var_type_of(&var), AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_llist_size(&var.data.vl), 8);

    assert_int_equal(amxc_var_new(&key_part), 0);
    amxc_var_set(cstring_t, key_part, "some text");
    assert_int_equal(amxc_var_set_index(&var, 6, key_part, AMXC_VAR_FLAG_COPY | AMXC_VAR_FLAG_UPDATE), 0);
    assert_int_equal(amxc_llist_size(&var.data.vl), 8);
    key_part_copy = amxc_var_get_index(&var, 6, AMXC_VAR_FLAG_COPY);
    assert_ptr_not_equal(key_part_copy, NULL);
    amxc_var_delete(&key_part_copy);

    assert_int_equal(amxc_var_set_index(&var, 6, key_part, AMXC_VAR_FLAG_COPY), 0);
    assert_ptr_equal(key_part->lit.llist, NULL);
    assert_int_equal(amxc_llist_size(&var.data.vl), 9);
    key_part_copy = amxc_var_get_index(&var, 6, AMXC_VAR_FLAG_COPY);
    assert_ptr_not_equal(key_part_copy, NULL);
    assert_ptr_not_equal(key_part_copy, key_part);
    amxc_var_delete(&key_part_copy);
    assert_int_equal(amxc_llist_size(&var.data.vl), 9);
    amxc_var_delete(&key_part);
    assert_int_equal(amxc_llist_size(&var.data.vl), 9);

    assert_int_equal(amxc_var_new(&key_part), 0);
    amxc_var_set(cstring_t, key_part, "some text");
    assert_int_equal(amxc_var_set_index(&var, 5, key_part, AMXC_VAR_FLAG_UPDATE), 0);
    assert_int_equal(amxc_llist_size(&var.data.vl), 9);

    key_part_const = amxc_var_get_index(&var, 5, AMXC_VAR_FLAG_DEFAULT);
    assert_ptr_not_equal(key_part_const, NULL);
    assert_int_equal(amxc_var_type_of(key_part_const), AMXC_VAR_ID_CSTRING);
    assert_string_equal(key_part_const->data.s, "some text");

    assert_int_equal(amxc_var_new(&key_part), 0);
    amxc_var_set(uint64_t, key_part, 123);
    assert_int_equal(amxc_var_set_index(&var, 8, key_part, AMXC_VAR_FLAG_COPY | AMXC_VAR_FLAG_UPDATE), 0);
    assert_int_equal(amxc_llist_size(&var.data.vl), 9);
    amxc_var_delete(&key_part);

    assert_int_equal(amxc_var_new(&key_part), 0);
    amxc_var_set(uint64_t, key_part, 123);
    assert_int_equal(amxc_var_set_index(&var, 0, key_part, AMXC_VAR_FLAG_DEFAULT), 0);
    assert_int_equal(amxc_llist_size(&var.data.vl), 10);
    assert_ptr_equal(amxc_var_get_index(&var, 0, AMXC_VAR_FLAG_DEFAULT), key_part);
    amxc_var_delete(&key_part);

    amxc_var_new(&key_part);
    amxc_var_set(cstring_t, key_part, "more text");
    assert_int_equal(amxc_var_set_index(&var, -1, key_part, AMXC_VAR_FLAG_COPY), 0);
    assert_int_equal(amxc_llist_size(&var.data.vl), 10);
    assert_int_equal(amxc_var_set_index(&var, -1, key_part, AMXC_VAR_FLAG_UPDATE), 0);
    assert_int_equal(amxc_llist_size(&var.data.vl), 11);
    assert_int_equal(amxc_var_set_index(&var, -1, key_part, AMXC_VAR_FLAG_DEFAULT), 0);
    assert_int_equal(amxc_llist_size(&var.data.vl), 11);
    amxc_var_new(&key_part);
    amxc_var_set(cstring_t, key_part, "some text");
    assert_int_equal(amxc_var_set_index(&var, -1, key_part, AMXC_VAR_FLAG_DEFAULT), 0);
    assert_int_equal(amxc_llist_size(&var.data.vl), 12);
    amxc_var_delete(&key_part);
    assert_int_equal(amxc_llist_size(&var.data.vl), 11);

    amxc_var_new(&key_part);
    amxc_var_set(cstring_t, key_part, "some text");
    assert_int_equal(amxc_var_set_index(&var, 2, key_part, AMXC_VAR_FLAG_DEFAULT), 0);
    assert_int_equal(amxc_llist_size(&var.data.vl), 12);
    amxc_var_delete(&key_part);
    assert_int_equal(amxc_llist_size(&var.data.vl), 11);

    key_part = amxc_var_get_index(&var, 8, AMXC_VAR_FLAG_COPY);
    assert_int_equal(amxc_var_type_of(key_part), AMXC_VAR_ID_UINT64);
    assert_int_equal(key_part->data.ui64, 123);

    assert_int_not_equal(amxc_var_set_index(&var, 8, NULL, AMXC_VAR_FLAG_COPY), 0);
    assert_int_not_equal(amxc_var_set_index(&var, 99, key_part, AMXC_VAR_FLAG_COPY), 0);
    assert_int_not_equal(amxc_var_set_index(NULL, 6, key_part, AMXC_VAR_FLAG_COPY), 0);

    assert_int_not_equal(amxc_var_set_index(&var, 8, NULL, AMXC_VAR_FLAG_DEFAULT), 0);
    assert_int_not_equal(amxc_var_set_index(&var, 99, key_part, AMXC_VAR_FLAG_DEFAULT), 0);
    assert_int_not_equal(amxc_var_set_index(NULL, 6, key_part, AMXC_VAR_FLAG_DEFAULT), 0);

    amxc_var_set_type(&var, AMXC_VAR_ID_BOOL);
    assert_int_not_equal(amxc_var_set_index(&var, 6, key_part, AMXC_VAR_FLAG_COPY), 0);

    amxc_var_delete(&key_part);
    amxc_var_clean(&string);
    amxc_var_clean(&var);
}

void test_variant_llist_set_key(UNUSED void** state) {
    amxc_var_t var;
    amxc_var_t string;
    amxc_var_t* key_part = NULL;
    const amxc_var_t* key_part_const = NULL;

    amxc_var_init(&var);
    amxc_var_init(&string);
    amxc_var_set(cstring_t, &string, "Hello,world,and,anyone,else,in,the,universe");
    assert_int_equal(amxc_var_convert(&var, &string, AMXC_VAR_ID_LIST), 0);
    assert_int_equal(amxc_var_type_of(&var), AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_llist_size(&var.data.vl), 8);

    assert_int_equal(amxc_var_new(&key_part), 0);
    amxc_var_set(cstring_t, key_part, "some text");
    assert_int_equal(amxc_var_set_key(&var, "6", key_part, AMXC_VAR_FLAG_COPY | AMXC_VAR_FLAG_UPDATE), 0);
    assert_int_equal(amxc_llist_size(&var.data.vl), 8);

    assert_int_equal(amxc_var_set_key(&var, "5", key_part, AMXC_VAR_FLAG_DEFAULT | AMXC_VAR_FLAG_UPDATE), 0);
    assert_int_equal(amxc_llist_size(&var.data.vl), 8);

    key_part = amxc_var_get_key(&var, "6", AMXC_VAR_FLAG_COPY);
    assert_ptr_not_equal(key_part, NULL);
    assert_int_equal(amxc_var_type_of(key_part), AMXC_VAR_ID_CSTRING);
    assert_string_equal(key_part->data.s, "some text");
    amxc_var_delete(&key_part);

    key_part_const = amxc_var_get_key(&var, "5", AMXC_VAR_FLAG_DEFAULT);
    assert_ptr_not_equal(key_part_const, NULL);
    assert_int_equal(amxc_var_type_of(key_part_const), AMXC_VAR_ID_CSTRING);
    assert_string_equal(key_part_const->data.s, "some text");

    assert_int_equal(amxc_var_new(&key_part), 0);
    amxc_var_set(uint64_t, key_part, 123);
    assert_int_equal(amxc_var_set_key(&var, "8", key_part, AMXC_VAR_FLAG_COPY | AMXC_VAR_FLAG_UPDATE), 0);
    assert_int_equal(amxc_llist_size(&var.data.vl), 9);
    amxc_var_delete(&key_part);

    key_part = amxc_var_get_key(&var, "8", AMXC_VAR_FLAG_COPY);
    assert_int_equal(amxc_var_type_of(key_part), AMXC_VAR_ID_UINT64);
    assert_int_equal(key_part->data.ui64, 123);

    assert_int_not_equal(amxc_var_set_key(&var, "8", NULL, AMXC_VAR_FLAG_COPY), 0);
    assert_int_not_equal(amxc_var_set_key(&var, "99", key_part, AMXC_VAR_FLAG_COPY), 0);
    assert_int_not_equal(amxc_var_set_key(NULL, "6", key_part, AMXC_VAR_FLAG_COPY), 0);

    assert_int_not_equal(amxc_var_set_key(&var, "8", NULL, AMXC_VAR_FLAG_DEFAULT), 0);
    assert_int_not_equal(amxc_var_set_key(&var, "99", key_part, AMXC_VAR_FLAG_DEFAULT), 0);
    assert_int_not_equal(amxc_var_set_key(NULL, "6", key_part, AMXC_VAR_FLAG_DEFAULT), 0);


    amxc_var_set_type(&var, AMXC_VAR_ID_BOOL);
    assert_int_not_equal(amxc_var_set_key(&var, "6", key_part, AMXC_VAR_FLAG_COPY), 0);

    amxc_var_delete(&key_part);
    amxc_var_clean(&string);
    amxc_var_clean(&var);
}