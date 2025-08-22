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

#include "test_variant_htable.h"

#include <amxc/amxc_macros.h>
void test_variant_htable_init(UNUSED void** state) {
    amxc_var_t var;
    amxc_var_t string;

    amxc_var_init(&var);
    amxc_var_init(&string);

    assert_int_equal(amxc_var_set_type(&var, AMXC_VAR_ID_HTABLE), 0);
    amxc_var_clean(&var);

    assert_int_equal(amxc_var_set_type(&string, AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(amxc_var_set_cstring_t(&string, "key:value"), 0);
    assert_int_equal(amxc_var_convert(&var, &string, AMXC_VAR_ID_HTABLE), 0);

    amxc_var_clean(&string);
    amxc_var_clean(&var);
}

void test_variant_htable_copy(UNUSED void** state) {
    amxc_var_t string;
    amxc_var_t var;
    amxc_var_t copy_var;
    amxc_htable_t* htable = NULL;

    assert_int_equal(amxc_var_init(&string), 0);
    assert_int_equal(amxc_var_init(&var), 0);
    assert_int_equal(amxc_var_init(&copy_var), 0);
    assert_int_equal(var.type_id, AMXC_VAR_ID_NULL);
    assert_int_equal(amxc_var_set_type(&string, AMXC_VAR_ID_CSTRING), 0);
    string.data.s = "";

    assert_int_equal(amxc_var_convert(&var, &string, AMXC_VAR_ID_HTABLE), 0);
    assert_int_equal(string.type_id, AMXC_VAR_ID_CSTRING);
    string.data.s = "Key1:Hello,Key2:world,Key3:and,Key4:anyone,Key5:else,Key6:in,Key7:the,Key8:universe";
    assert_int_equal(amxc_var_convert(&var, &string, AMXC_VAR_ID_HTABLE), 0);
    assert_int_equal(amxc_htable_size(&var.data.vm), 8);
    assert_int_equal(amxc_var_copy(&copy_var, &var), 0);
    assert_int_equal(amxc_htable_size(&var.data.vm), 8);

    htable = &copy_var.data.vm;
    amxc_htable_for_each(it, htable) {
        amxc_var_t* item = amxc_var_from_htable_it(it);
        assert_int_equal(item->type_id, AMXC_VAR_ID_CSTRING);
    }

    amxc_var_clean(&var);
    amxc_var_clean(&copy_var);
}

void test_variant_htable_move(UNUSED void** state) {
    amxc_var_t src;
    amxc_var_t dst;

    assert_int_equal(amxc_var_init(&src), 0);
    assert_int_equal(amxc_var_init(&dst), 0);
    amxc_var_set_type(&src, AMXC_VAR_ID_HTABLE);

    amxc_var_add_key(cstring_t, &src, "key1", "item1");
    amxc_var_add_key(cstring_t, &src, "key2", "item2");
    amxc_var_add_key(cstring_t, &src, "key3", "item3");
    amxc_var_add_key(cstring_t, &src, "key4", "item4");
    amxc_var_add_key(cstring_t, &src, "key5", "item5");
    amxc_var_add_key(cstring_t, &src, "key6", "item6");
    amxc_var_add_key(cstring_t, &src, "key7", "item7");
    amxc_var_add_key(cstring_t, &src, "key8", "item8");
    amxc_var_add_key(cstring_t, &src, "key9", "item9");
    amxc_var_add_key(cstring_t, &src, "key10", "item10");

    assert_int_equal(amxc_htable_size(amxc_var_constcast(amxc_htable_t, &src)), 10);
    assert_int_equal(amxc_var_move(&dst, &src), 0);
    assert_true(amxc_var_is_null(&src));
    assert_int_equal(amxc_var_type_of(&dst), AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_htable_size(amxc_var_constcast(amxc_htable_t, &dst)), 10);

    assert_non_null(GET_ARG(&dst, "key5"));
    assert_non_null(GET_ARG(&dst, "key1"));
    assert_non_null(GET_ARG(&dst, "key3"));
    assert_non_null(GET_ARG(&dst, "key7"));
    assert_non_null(GET_ARG(&dst, "key9"));

    amxc_var_clean(&dst);
    amxc_var_clean(&src);
}

void test_variant_htable_convert_to_bool(UNUSED void** state) {
    amxc_var_t string;
    amxc_var_t var;
    amxc_var_t copy_var;

    assert_int_equal(amxc_var_init(&string), 0);
    assert_int_equal(amxc_var_init(&var), 0);
    assert_int_equal(amxc_var_init(&copy_var), 0);
    assert_int_equal(var.type_id, AMXC_VAR_ID_NULL);
    assert_int_equal(amxc_var_set_type(&copy_var, AMXC_VAR_ID_HTABLE), 0);
    assert_int_equal(copy_var.type_id, AMXC_VAR_ID_HTABLE);

    assert_true(amxc_htable_is_empty(&copy_var.data.vm));
    assert_int_equal(amxc_var_convert(&var, &copy_var, AMXC_VAR_ID_BOOL), 0);
    assert_false(var.data.b);

    assert_int_equal(amxc_var_set_type(&string, AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(string.type_id, AMXC_VAR_ID_CSTRING);
    string.data.s = "Key1:Hello,Key2:world,Key3:and,Key4:anyone,Key5:else,Key6:in,Key7:the,Key8:universe";

    assert_int_equal(amxc_var_convert(&var, &string, AMXC_VAR_ID_HTABLE), 0);
    assert_int_equal(amxc_htable_size(&var.data.vm), 8);
    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_BOOL), 0);
    assert_true(copy_var.data.b);

    amxc_var_clean(&var);
    amxc_var_clean(&copy_var);
}

void test_variant_htable_convert_to_integer(UNUSED void** state) {
    amxc_var_t string;
    amxc_var_t var;
    amxc_var_t copy_var;

    assert_int_equal(amxc_var_init(&string), 0);
    assert_int_equal(amxc_var_init(&var), 0);
    assert_int_equal(amxc_var_init(&copy_var), 0);
    assert_int_equal(var.type_id, AMXC_VAR_ID_NULL);
    assert_int_equal(amxc_var_set_type(&copy_var, AMXC_VAR_ID_HTABLE), 0);
    assert_int_equal(copy_var.type_id, AMXC_VAR_ID_HTABLE);

    assert_true(amxc_htable_is_empty(&copy_var.data.vm));
    assert_int_equal(amxc_var_convert(&var, &copy_var, AMXC_VAR_ID_UINT64), 0);
    assert_int_equal(var.data.ui64, 0);

    assert_int_equal(amxc_var_set_type(&string, AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(string.type_id, AMXC_VAR_ID_CSTRING);
    string.data.s = "Key1:Hello,Key2:world,Key3:and,Key4:anyone,Key5:else,Key6:in,Key7:the,Key8:universe";

    assert_int_equal(amxc_var_convert(&var, &string, AMXC_VAR_ID_HTABLE), 0);
    assert_int_equal(amxc_htable_size(&var.data.vm), 8);
    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_UINT64), 0);
    assert_int_equal(copy_var.data.ui64, 8);

    amxc_var_clean(&var);
    amxc_var_clean(&copy_var);
}

void test_variant_htable_convert_to_list(UNUSED void** state) {
    amxc_var_t string;
    amxc_var_t var;
    amxc_var_t copy_var;

    assert_int_equal(amxc_var_init(&string), 0);
    assert_int_equal(amxc_var_init(&var), 0);
    assert_int_equal(amxc_var_init(&copy_var), 0);
    assert_int_equal(var.type_id, AMXC_VAR_ID_NULL);
    assert_int_equal(amxc_var_set_type(&copy_var, AMXC_VAR_ID_HTABLE), 0);
    assert_int_equal(copy_var.type_id, AMXC_VAR_ID_HTABLE);

    assert_true(amxc_htable_is_empty(&copy_var.data.vm));
    assert_int_equal(amxc_var_convert(&var, &copy_var, AMXC_VAR_ID_LIST), 0);
    assert_int_equal(amxc_llist_size(&var.data.vl), 0);
    assert_true(amxc_llist_is_empty(&var.data.vl));

    assert_int_equal(amxc_var_set_type(&string, AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(string.type_id, AMXC_VAR_ID_CSTRING);
    string.data.s = "Key1:Hello,Key2:world,Key3:and,Key4:anyone,Key5:else,Key6:in,Key7:the,Key8:universe";

    assert_int_equal(amxc_var_convert(&var, &string, AMXC_VAR_ID_HTABLE), 0);
    assert_int_equal(var.type_id, AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_htable_size(&var.data.vm), 8);
    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_LIST), 0);
    assert_int_equal(copy_var.type_id, AMXC_VAR_ID_LIST);
    assert_false(amxc_llist_is_empty(&copy_var.data.vl));

    amxc_var_clean(&var);
    amxc_var_clean(&copy_var);
}

void test_variant_htable_convert_to_string(UNUSED void** state) {
    amxc_var_t string;
    amxc_var_t var;
    amxc_var_t copy_var;

    assert_int_equal(amxc_var_init(&string), 0);
    assert_int_equal(amxc_var_init(&var), 0);
    assert_int_equal(amxc_var_init(&copy_var), 0);
    assert_int_equal(var.type_id, AMXC_VAR_ID_NULL);
    assert_int_equal(amxc_var_set_type(&copy_var, AMXC_VAR_ID_HTABLE), 0);
    assert_int_equal(copy_var.type_id, AMXC_VAR_ID_HTABLE);

    assert_true(amxc_htable_is_empty(&copy_var.data.vm));
    assert_int_equal(amxc_var_convert(&var, &copy_var, AMXC_VAR_ID_CSTRING), 0);
    assert_ptr_not_equal(var.data.s, NULL);
    assert_int_equal(strlen(var.data.s), 0);
    assert_int_equal(amxc_var_set_type(&string, AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(string.type_id, AMXC_VAR_ID_CSTRING);
    string.data.s = "Key1:Hello,Key2:world,Key3:and,Key4:anyone,Key5:else,Key6:in,Key7:the,Key8:universe";

    assert_int_equal(amxc_var_convert(&var, &string, AMXC_VAR_ID_HTABLE), 0);
    assert_int_equal(var.type_id, AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_htable_size(&var.data.vm), 8);
    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_CSTRING), 0);
    assert_string_equal(copy_var.data.s, string.data.s);

    amxc_var_clean(&var);
    amxc_var_clean(&copy_var);
}

void test_variant_htable_convert_to_string_should_not_segfault(UNUSED void** state) {
    amxc_var_t htable_var;
    amxc_var_t* str_var = NULL;
    amxc_var_t copy_var;

    assert_int_equal(amxc_var_init(&htable_var), 0);
    assert_int_equal(amxc_var_new(&str_var), 0);
    assert_int_equal(amxc_var_init(&copy_var), 0);

    assert_int_equal(amxc_var_set_type(str_var, AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(str_var->type_id, AMXC_VAR_ID_CSTRING);
    assert_int_equal(amxc_var_set_type(&htable_var, AMXC_VAR_ID_HTABLE), 0);
    assert_int_equal(htable_var.type_id, AMXC_VAR_ID_HTABLE);

    assert_true(amxc_htable_is_empty(&htable_var.data.vm));
    amxc_htable_insert(&htable_var.data.vm, "test", &str_var->hit);

    assert_int_equal(amxc_var_convert(&copy_var, &htable_var, AMXC_VAR_ID_CSTRING), 0);

    amxc_var_clean(&htable_var);
    amxc_var_clean(&copy_var);
}

void test_variant_htable_set_get(UNUSED void** state) {
    amxc_var_t var;
    amxc_var_t* item = NULL;
    amxc_var_t string;
    amxc_htable_t* htable = NULL;
    const amxc_htable_t* consthtable = NULL;

    assert_int_equal(amxc_var_init(&string), 0);
    assert_int_equal(amxc_var_init(&var), 0);

    htable = amxc_var_dyncast(amxc_htable_t, NULL);
    assert_ptr_equal(htable, NULL);

    assert_int_equal(amxc_var_set_type(&var, AMXC_VAR_ID_CUSTOM_BASE), 0);
    htable = amxc_var_dyncast(amxc_htable_t, &var);
    assert_ptr_equal(htable, NULL);
    consthtable = amxc_var_constcast(amxc_htable_t, &var);
    assert_ptr_equal(consthtable, NULL);

    assert_int_equal(amxc_var_set_type(&string, AMXC_VAR_ID_CSTRING), 0);
    string.data.s = "Key1:Hello,Key2:world,Key3:and,Key4:anyone,Key5:else,Key6:in,Key7:the,Key8:universe";
    assert_int_equal(amxc_var_convert(&var, &string, AMXC_VAR_ID_HTABLE), 0);

    htable = amxc_var_dyncast(amxc_htable_t, &var);
    assert_ptr_not_equal(htable, NULL);
    amxc_htable_delete(&htable, variant_htable_it_free);
    consthtable = amxc_var_constcast(amxc_htable_t, &var);
    assert_ptr_not_equal(consthtable, NULL);

    item = amxc_var_get_index(&var, 0, AMXC_VAR_FLAG_DEFAULT);
    assert_non_null(item);
    item = amxc_var_get_index(&var, 7, AMXC_VAR_FLAG_DEFAULT);
    assert_non_null(item);
    item = amxc_var_get_index(&var, 8, AMXC_VAR_FLAG_DEFAULT);
    assert_null(item);
    assert_ptr_not_equal(amxc_var_get_index(&var, 0, AMXC_VAR_FLAG_DEFAULT), amxc_var_get_index(&var, 7, AMXC_VAR_FLAG_DEFAULT));

    amxc_var_clean(&var);
}

void test_variant_htable_compare(UNUSED void** state) {
    amxc_var_t var1;
    amxc_var_t var2;
    amxc_var_t data;
    int result = 0;

    assert_int_equal(amxc_var_init(&var1), 0);
    assert_int_equal(amxc_var_init(&var2), 0);
    assert_int_equal(amxc_var_init(&data), 0);
    assert_int_equal(amxc_var_set_type(&var1, AMXC_VAR_ID_HTABLE), 0);
    assert_int_equal(var1.type_id, AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_var_set_type(&var2, AMXC_VAR_ID_HTABLE), 0);
    assert_int_equal(var2.type_id, AMXC_VAR_ID_HTABLE);

    assert_int_equal(amxc_var_compare(&var1, &var2, &result), 0);
    assert_true(result == 0);

    assert_non_null(amxc_var_add_key(cstring_t, &var1, "cstring_key", "my_value"));
    assert_int_equal(amxc_var_compare(&var1, &var2, &result), 0);
    assert_true(result > 0);
    assert_int_equal(amxc_var_compare(&var2, &var1, &result), 0);
    assert_true(result < 0);

    assert_non_null(amxc_var_add_key(cstring_t, &var2, "cstring_key", "my_value"));
    assert_int_equal(amxc_var_compare(&var1, &var2, &result), 0);
    assert_true(result == 0);

    assert_non_null(amxc_var_add_key(uint32_t, &var1, "uint32_key", 1));
    assert_int_equal(amxc_var_compare(&var1, &var2, &result), 0);
    assert_true(result > 0);

    assert_non_null(amxc_var_add_key(uint32_t, &var2, "uint32_key", 2));
    assert_int_equal(amxc_var_compare(&var1, &var2, &result), 0);
    assert_true(result < 0);

    assert_int_equal(amxc_var_set_type(&var1, AMXC_VAR_ID_HTABLE), 0);
    assert_int_equal(amxc_var_set_type(&var2, AMXC_VAR_ID_HTABLE), 0);
    assert_int_equal(amxc_var_compare(&var1, &var2, &result), 0);
    assert_true(result == 0);

    assert_int_equal(amxc_var_set(cstring_t, &data, "value"), 0);
    assert_int_equal(amxc_var_set_path(&var1, "table_1.2.table_2.my_string", &data,
                                       AMXC_VAR_FLAG_AUTO_ADD | AMXC_VAR_FLAG_COPY), 0);
    assert_int_equal(amxc_var_set_path(&var2, "table_1.2.table_2.my_string", &data,
                                       AMXC_VAR_FLAG_AUTO_ADD | AMXC_VAR_FLAG_COPY), 0);
    assert_int_equal(amxc_var_compare(&var1, &var2, &result), 0);
    assert_true(result == 0);

    assert_int_equal(amxc_var_set_type(&var1, AMXC_VAR_ID_HTABLE), 0);
    assert_int_equal(amxc_var_set_type(&var2, AMXC_VAR_ID_HTABLE), 0);
    assert_int_equal(amxc_var_compare(&var1, &var2, &result), 0);
    assert_true(result == 0);

    assert_non_null(amxc_var_add_key(cstring_t, &var1, "key", "my_value"));
    assert_non_null(amxc_var_add_key(uint32_t, &var2, "key", 2));
    assert_int_equal(amxc_var_compare(&var1, &var2, &result), 0);
    assert_true(result != 0);

    assert_int_equal(amxc_var_compare(&var1, &data, &result), 0);
    assert_true(result != 0);

    amxc_var_clean(&var1);
    amxc_var_clean(&var2);
    amxc_var_clean(&data);
}

void test_variant_htable_add_new(UNUSED void** state) {
    amxc_var_t var;
    amxc_var_t* item = NULL;
    const amxc_htable_t* consttable = NULL;
    const amxc_llist_t* constlist = NULL;
    amxc_htable_t atable;

    assert_int_equal(amxc_htable_init(&atable, 0), 0);

    assert_int_equal(amxc_var_init(&var), 0);
    assert_int_equal(amxc_var_set_type(&var, AMXC_VAR_ID_LIST), 0);

    item = amxc_var_add(amxc_htable_t, &var, NULL);
    assert_ptr_not_equal(item, NULL);
    assert_int_equal(amxc_var_type_of(item), AMXC_VAR_ID_HTABLE);
    consttable = amxc_var_constcast(amxc_htable_t, item);
    assert_int_equal(amxc_htable_size(consttable), 0);

    item = amxc_var_add(amxc_htable_t, &var, &atable);
    assert_ptr_not_equal(item, NULL);
    assert_int_equal(amxc_var_type_of(item), AMXC_VAR_ID_HTABLE);
    consttable = amxc_var_constcast(amxc_htable_t, item);
    assert_int_equal(amxc_htable_size(consttable), 0);

    item = amxc_var_add(amxc_htable_t, NULL, NULL);
    assert_ptr_equal(item, NULL);

    constlist = amxc_var_constcast(amxc_llist_t, &var);
    assert_ptr_not_equal(consttable, NULL);
    assert_int_equal(amxc_llist_size(constlist), 2);

    amxc_htable_clean(&atable, NULL);
    amxc_var_clean(&var);
}

void test_variant_htable_add_new_key(UNUSED void** state) {
    amxc_var_t var;
    amxc_var_t* item = NULL;
    const amxc_htable_t* consttable = NULL;
    amxc_htable_t atable;

    assert_int_equal(amxc_htable_init(&atable, 0), 0);

    assert_int_equal(amxc_var_init(&var), 0);
    assert_int_equal(amxc_var_set_type(&var, AMXC_VAR_ID_HTABLE), 0);

    item = amxc_var_add_key(amxc_htable_t, &var, "key1", NULL);
    assert_ptr_not_equal(item, NULL);
    assert_int_equal(amxc_var_type_of(item), AMXC_VAR_ID_HTABLE);
    consttable = amxc_var_constcast(amxc_htable_t, item);
    assert_int_equal(amxc_htable_size(consttable), 0);

    item = amxc_var_add_key(amxc_htable_t, &var, "key2", &atable);
    assert_ptr_not_equal(item, NULL);
    assert_int_equal(amxc_var_type_of(item), AMXC_VAR_ID_HTABLE);
    consttable = amxc_var_constcast(amxc_htable_t, item);
    assert_int_equal(amxc_htable_size(consttable), 0);

    item = amxc_var_add_key(amxc_htable_t, NULL, "Key3", NULL);
    assert_ptr_equal(item, NULL);

    consttable = amxc_var_constcast(amxc_htable_t, &var);
    assert_ptr_not_equal(consttable, NULL);
    assert_int_equal(amxc_htable_size(consttable), 2);

    amxc_htable_clean(&atable, NULL);
    amxc_var_clean(&var);
}

void test_variant_htable_add_new_key_duplicate(UNUSED void** state) {
    amxc_var_t var;
    amxc_var_t* item = NULL;

    assert_int_equal(amxc_var_init(&var), 0);
    assert_int_equal(amxc_var_set_type(&var, AMXC_VAR_ID_HTABLE), 0);

    item = amxc_var_add_key(uint32_t, &var, "key1", 1);
    assert_ptr_not_equal(item, NULL);
    item = amxc_var_add_key(uint32_t, &var, "key1", 2);
    assert_ptr_equal(item, NULL);

    amxc_var_clean(&var);
}
