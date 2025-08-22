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
void test_variant_list_copy(UNUSED void** state) {
    amxc_var_t string;
    amxc_var_t var;
    amxc_var_t copy_var;
    amxc_llist_t* list = NULL;

    assert_int_equal(amxc_var_init(&string), 0);
    assert_int_equal(amxc_var_init(&var), 0);
    assert_int_equal(amxc_var_init(&copy_var), 0);
    assert_int_equal(var.type_id, AMXC_VAR_ID_NULL);
    assert_int_equal(amxc_var_set_type(&string, AMXC_VAR_ID_CSTRING), 0);
    string.data.s = strdup("");

    assert_int_equal(amxc_var_convert(&var, &string, AMXC_VAR_ID_LIST), 0);
    assert_int_equal(amxc_llist_size(&var.data.vl), 0);
    free(string.data.s);

    assert_int_equal(string.type_id, AMXC_VAR_ID_CSTRING);
    string.data.s = strdup("Hello,world,and,anyone,else,in,the,universe");
    assert_int_equal(amxc_var_convert(&var, &string, AMXC_VAR_ID_LIST), 0);
    assert_int_equal(amxc_llist_size(&var.data.vl), 8);

    assert_int_equal(amxc_var_copy(&copy_var, &var), 0);
    assert_int_equal(amxc_llist_size(&var.data.vl), 8);
    free(string.data.s);

    list = &copy_var.data.vl;
    amxc_llist_for_each(it, list) {
        amxc_var_t* item = amxc_var_from_llist_it(it);
        assert_int_equal(item->type_id, AMXC_VAR_ID_CSTRING);
    }

    amxc_var_clean(&var);
    amxc_var_clean(&copy_var);
}

void test_variant_list_move(UNUSED void** state) {
    amxc_var_t src;
    amxc_var_t dst;

    assert_int_equal(amxc_var_init(&src), 0);
    assert_int_equal(amxc_var_init(&dst), 0);
    amxc_var_set_type(&src, AMXC_VAR_ID_LIST);

    amxc_var_add(cstring_t, &src, "item1");
    amxc_var_add(cstring_t, &src, "item2");
    amxc_var_add(cstring_t, &src, "item3");
    amxc_var_add(cstring_t, &src, "item4");

    assert_int_equal(amxc_llist_size(amxc_var_constcast(amxc_llist_t, &src)), 4);
    assert_int_equal(amxc_var_move(&dst, &src), 0);
    assert_true(amxc_var_is_null(&src));
    assert_int_equal(amxc_var_type_of(&dst), AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_llist_size(amxc_var_constcast(amxc_llist_t, &dst)), 4);

    amxc_var_clean(&dst);
    amxc_var_clean(&src);
}

void test_variant_list_convert_to_bool(UNUSED void** state) {
    amxc_var_t string;
    amxc_var_t var;
    amxc_var_t copy_var;


    assert_int_equal(amxc_var_init(&string), 0);
    assert_int_equal(amxc_var_init(&var), 0);
    assert_int_equal(amxc_var_init(&copy_var), 0);
    assert_int_equal(var.type_id, AMXC_VAR_ID_NULL);
    assert_int_equal(amxc_var_set_type(&copy_var, AMXC_VAR_ID_LIST), 0);
    assert_int_equal(copy_var.type_id, AMXC_VAR_ID_LIST);

    assert_true(amxc_llist_is_empty(&copy_var.data.vl));
    assert_int_equal(amxc_var_convert(&var, &copy_var, AMXC_VAR_ID_BOOL), 0);
    assert_false(var.data.b);

    assert_int_equal(amxc_var_set_type(&string, AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(string.type_id, AMXC_VAR_ID_CSTRING);
    string.data.s = strdup("Hello,world,and,anyone,else,in,the,universe");

    assert_int_equal(amxc_var_convert(&var, &string, AMXC_VAR_ID_LIST), 0);
    assert_int_equal(amxc_llist_size(&var.data.vl), 8);
    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_BOOL), 0);
    assert_true(copy_var.data.b);

    free(string.data.s);
    amxc_var_clean(&var);
    amxc_var_clean(&copy_var);
}

void test_variant_list_convert_to_integer(UNUSED void** state) {
    amxc_var_t string;
    amxc_var_t var;
    amxc_var_t copy_var;

    assert_int_equal(amxc_var_init(&string), 0);
    assert_int_equal(amxc_var_init(&var), 0);
    assert_int_equal(amxc_var_init(&copy_var), 0);
    assert_int_equal(var.type_id, AMXC_VAR_ID_NULL);
    assert_int_equal(amxc_var_set_type(&copy_var, AMXC_VAR_ID_LIST), 0);
    assert_int_equal(copy_var.type_id, AMXC_VAR_ID_LIST);

    assert_true(amxc_llist_is_empty(&copy_var.data.vl));
    assert_int_equal(amxc_var_convert(&var, &copy_var, AMXC_VAR_ID_UINT64), 0);
    assert_int_equal(var.data.ui64, 0);

    assert_int_equal(amxc_var_set_type(&string, AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(string.type_id, AMXC_VAR_ID_CSTRING);
    string.data.s = strdup("Hello,world,and,anyone,else,in,the,universe");

    assert_int_equal(amxc_var_convert(&var, &string, AMXC_VAR_ID_LIST), 0);
    assert_int_equal(amxc_llist_size(&var.data.vl), 8);
    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_UINT64), 0);
    assert_int_equal(copy_var.data.ui64, 8);

    free(string.data.s);
    amxc_var_clean(&var);
    amxc_var_clean(&copy_var);
}

void test_variant_list_convert_to_htable(UNUSED void** state) {
    amxc_var_t string;
    amxc_var_t var;
    amxc_var_t copy_var;

    assert_int_equal(amxc_var_init(&string), 0);
    assert_int_equal(amxc_var_init(&var), 0);
    assert_int_equal(amxc_var_init(&copy_var), 0);
    assert_int_equal(var.type_id, AMXC_VAR_ID_NULL);
    assert_int_equal(amxc_var_set_type(&copy_var, AMXC_VAR_ID_LIST), 0);
    assert_int_equal(copy_var.type_id, AMXC_VAR_ID_LIST);

    assert_true(amxc_llist_is_empty(&copy_var.data.vl));
    assert_int_equal(amxc_var_convert(&var, &copy_var, AMXC_VAR_ID_HTABLE), 0);
    assert_int_equal(amxc_htable_size(&var.data.vm), 0);
    assert_true(amxc_htable_is_empty(&var.data.vm));

    assert_int_equal(amxc_var_set_type(&string, AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(string.type_id, AMXC_VAR_ID_CSTRING);
    string.data.s = strdup("Hello,world,and,anyone,else,in,the,universe");

    assert_int_equal(amxc_var_convert(&var, &string, AMXC_VAR_ID_LIST), 0);
    assert_int_equal(var.type_id, AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_llist_size(&var.data.vl), 8);
    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_HTABLE), 0);
    assert_int_equal(copy_var.type_id, AMXC_VAR_ID_HTABLE);
    assert_false(amxc_htable_is_empty(&copy_var.data.vm));

    free(string.data.s);
    amxc_var_clean(&var);
    amxc_var_clean(&copy_var);
}

void test_variant_list_convert_to_string(UNUSED void** state) {
    amxc_var_t string;
    amxc_var_t var;
    amxc_var_t copy_var;

    assert_int_equal(amxc_var_init(&string), 0);
    assert_int_equal(amxc_var_init(&var), 0);
    assert_int_equal(amxc_var_init(&copy_var), 0);
    assert_int_equal(var.type_id, AMXC_VAR_ID_NULL);
    assert_int_equal(amxc_var_set_type(&copy_var, AMXC_VAR_ID_LIST), 0);
    assert_int_equal(copy_var.type_id, AMXC_VAR_ID_LIST);

    assert_true(amxc_llist_is_empty(&copy_var.data.vl));
    assert_int_equal(amxc_var_convert(&var, &copy_var, AMXC_VAR_ID_CSTRING), 0);
    assert_ptr_equal(var.data.s, NULL);

    assert_int_equal(amxc_var_set_type(&string, AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(string.type_id, AMXC_VAR_ID_CSTRING);
    string.data.s = strdup("Hello,world,and,anyone,else,in,the,universe");

    assert_int_equal(amxc_var_convert(&var, &string, AMXC_VAR_ID_LIST), 0);
    assert_int_equal(var.type_id, AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_llist_size(&var.data.vl), 8);
    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_CSTRING), 0);
    assert_string_equal(copy_var.data.s, "Hello,world,and,anyone,else,in,the,universe");

    assert_int_equal(amxc_var_convert(&var, &string, AMXC_VAR_ID_LIST), 0);
    assert_int_equal(var.type_id, AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_llist_size(&var.data.vl), 8);
    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_CSV_STRING), 0);
    assert_string_equal(copy_var.data.s, "Hello,world,and,anyone,else,in,the,universe");

    assert_int_equal(amxc_var_convert(&var, &string, AMXC_VAR_ID_LIST), 0);
    assert_int_equal(var.type_id, AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_llist_size(&var.data.vl), 8);
    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_SSV_STRING), 0);
    assert_string_equal(copy_var.data.s, "Hello world and anyone else in the universe");

    free(string.data.s);
    amxc_var_clean(&var);
    amxc_var_clean(&copy_var);
}

void test_variant_llist_set_get(UNUSED void** state) {
    amxc_var_t var;
    amxc_var_t string;
    amxc_llist_t* list = NULL;
    const amxc_llist_t* constlist = NULL;

    assert_int_equal(amxc_var_init(&string), 0);
    assert_int_equal(amxc_var_init(&var), 0);

    list = amxc_var_dyncast(amxc_llist_t, NULL);
    assert_ptr_equal(list, NULL);

    assert_int_equal(amxc_var_set_type(&var, AMXC_VAR_ID_CUSTOM_BASE), 0);
    list = amxc_var_dyncast(amxc_llist_t, &var);
    assert_ptr_equal(list, NULL);
    constlist = amxc_var_constcast(amxc_llist_t, &var);
    assert_ptr_equal(constlist, NULL);

    assert_int_equal(amxc_var_set_type(&string, AMXC_VAR_ID_CSTRING), 0);
    string.data.s = strdup("Hello,world,and,anyone,else,in,the,universe");
    assert_int_equal(amxc_var_convert(&var, &string, AMXC_VAR_ID_LIST), 0);

    list = amxc_var_dyncast(amxc_llist_t, &var);
    assert_ptr_not_equal(list, NULL);
    amxc_llist_delete(&list, variant_list_it_free);
    constlist = amxc_var_constcast(amxc_llist_t, &var);
    assert_ptr_not_equal(constlist, NULL);

    free(string.data.s);
    amxc_var_clean(&var);
}

void test_variant_llist_compare(UNUSED void** state) {
    amxc_var_t var1;
    amxc_var_t var2;
    amxc_var_t* list1;
    amxc_var_t* list2;
    int result = 0;

    assert_int_equal(amxc_var_init(&var1), 0);
    assert_int_equal(amxc_var_init(&var2), 0);
    assert_int_equal(amxc_var_set_type(&var1, AMXC_VAR_ID_LIST), 0);
    assert_int_equal(var1.type_id, AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_var_set_type(&var2, AMXC_VAR_ID_LIST), 0);
    assert_int_equal(var2.type_id, AMXC_VAR_ID_LIST);

    assert_int_equal(amxc_var_compare(&var1, &var2, &result), 0);
    assert_true(result == 0);

    assert_non_null(amxc_var_add(cstring_t, &var1, "my_value"));
    assert_int_equal(amxc_var_compare(&var1, &var2, &result), 0);
    assert_true(result > 0);
    assert_int_equal(amxc_var_compare(&var2, &var1, &result), 0);
    assert_true(result < 0);

    assert_non_null(amxc_var_add(cstring_t, &var2, "my_value"));
    assert_int_equal(amxc_var_compare(&var1, &var2, &result), 0);
    assert_true(result == 0);

    assert_non_null(amxc_var_add(uint32_t, &var1, 1));
    assert_int_equal(amxc_var_compare(&var1, &var2, &result), 0);
    assert_true(result > 0);

    assert_non_null(amxc_var_add(uint32_t, &var2, 2));
    assert_int_equal(amxc_var_compare(&var1, &var2, &result), 0);
    assert_true(result < 0);

    assert_int_equal(amxc_var_set_type(&var1, AMXC_VAR_ID_LIST), 0);
    assert_int_equal(amxc_var_set_type(&var2, AMXC_VAR_ID_LIST), 0);
    assert_int_equal(amxc_var_compare(&var1, &var2, &result), 0);
    assert_true(result == 0);

    assert_non_null(amxc_var_add(cstring_t, &var1, "my_value"));
    assert_non_null(amxc_var_add(uint32_t, &var1, 1));
    assert_non_null(amxc_var_add(uint32_t, &var2, 1));
    assert_non_null(amxc_var_add(cstring_t, &var2, "my_value"));
    assert_int_equal(amxc_var_compare(&var1, &var2, &result), 0);
    assert_true(result != 0);

    assert_int_equal(amxc_var_set_type(&var1, AMXC_VAR_ID_LIST), 0);
    assert_int_equal(amxc_var_set_type(&var2, AMXC_VAR_ID_LIST), 0);
    assert_int_equal(amxc_var_compare(&var1, &var2, &result), 0);
    assert_true(result == 0);

    list1 = amxc_var_add(amxc_llist_t, &var1, NULL);
    assert_non_null(list1);
    list2 = amxc_var_add(amxc_llist_t, &var2, NULL);
    assert_non_null(list2);
    assert_int_equal(amxc_var_compare(&var1, &var2, &result), 0);
    assert_true(result == 0);

    assert_non_null(amxc_var_add(cstring_t, list1, "my_value"));
    assert_int_equal(amxc_var_compare(&var1, &var2, &result), 0);
    assert_true(result > 0);

    assert_non_null(amxc_var_add(cstring_t, list2, "my_value"));
    assert_int_equal(amxc_var_compare(&var1, &var2, &result), 0);
    assert_true(result == 0);

    amxc_var_clean(&var1);
    amxc_var_clean(&var2);
}

void test_variant_llist_add_new(UNUSED void** state) {
    amxc_var_t var;
    amxc_var_t* item = NULL;
    const amxc_llist_t* constlist = NULL;
    amxc_llist_t alist;

    assert_int_equal(amxc_llist_init(&alist), 0);

    assert_int_equal(amxc_var_init(&var), 0);
    assert_int_equal(amxc_var_set_type(&var, AMXC_VAR_ID_LIST), 0);

    item = amxc_var_add(amxc_llist_t, &var, NULL);
    assert_ptr_not_equal(item, NULL);
    assert_int_equal(amxc_var_type_of(item), AMXC_VAR_ID_LIST);
    constlist = amxc_var_constcast(amxc_llist_t, item);
    assert_int_equal(amxc_llist_size(constlist), 0);

    item = amxc_var_add(amxc_llist_t, &var, &alist);
    assert_ptr_not_equal(item, NULL);
    assert_int_equal(amxc_var_type_of(item), AMXC_VAR_ID_LIST);
    constlist = amxc_var_constcast(amxc_llist_t, item);
    assert_int_equal(amxc_llist_size(constlist), 0);

    item = amxc_var_add(amxc_llist_t, NULL, NULL);
    assert_ptr_equal(item, NULL);

    constlist = amxc_var_constcast(amxc_llist_t, &var);
    assert_ptr_not_equal(constlist, NULL);
    assert_int_equal(amxc_llist_size(constlist), 2);

    amxc_llist_clean(&alist, NULL);
    amxc_var_clean(&var);
}

void test_variant_llist_add_new_key(UNUSED void** state) {
    amxc_var_t var;
    amxc_var_t* item = NULL;
    const amxc_llist_t* constlist = NULL;
    const amxc_htable_t* consttable = NULL;
    amxc_llist_t alist;

    assert_int_equal(amxc_llist_init(&alist), 0);

    assert_int_equal(amxc_var_init(&var), 0);
    assert_int_equal(amxc_var_set_type(&var, AMXC_VAR_ID_LIST), 0);

    item = amxc_var_add_key(amxc_htable_t, &var, "1", NULL);
    assert_ptr_not_equal(item, NULL);
    assert_int_equal(amxc_var_type_of(item), AMXC_VAR_ID_HTABLE);
    consttable = amxc_var_constcast(amxc_htable_t, item);
    assert_int_equal(amxc_htable_size(consttable), 0);

    item = amxc_var_add_key(amxc_llist_t, &var, "2", &alist);
    assert_ptr_not_equal(item, NULL);
    assert_int_equal(amxc_var_type_of(item), AMXC_VAR_ID_LIST);
    constlist = amxc_var_constcast(amxc_llist_t, item);
    assert_int_equal(amxc_llist_size(constlist), 0);

    item = amxc_var_add_key(cstring_t, NULL, "3", NULL);
    assert_ptr_equal(item, NULL);

    constlist = amxc_var_constcast(amxc_llist_t, &var);
    assert_ptr_not_equal(constlist, NULL);
    assert_int_equal(amxc_llist_size(constlist), 2);

    amxc_llist_clean(&alist, NULL);
    amxc_var_clean(&var);
}

void test_variant_llist_get_path(UNUSED void** state) {
    amxc_var_t var;
    amxc_var_t* item = NULL;

    assert_int_equal(amxc_var_init(&var), 0);
    assert_int_equal(amxc_var_set_type(&var, AMXC_VAR_ID_LIST), 0);

    assert_ptr_not_equal(amxc_var_add(uint32_t, &var, 123), NULL);
    assert_ptr_not_equal(amxc_var_add(cstring_t, &var, "acracadabra"), NULL);
    assert_ptr_not_equal(amxc_var_add(bool, &var, "true"), NULL);

    item = amxc_var_get_path(&var, "0", AMXC_VAR_FLAG_DEFAULT);
    assert_ptr_not_equal(item, NULL);
    assert_int_equal(amxc_var_type_of(item), AMXC_VAR_ID_UINT32);

    item = amxc_var_get_path(&var, "Test", AMXC_VAR_FLAG_DEFAULT);
    assert_true(amxc_var_is_null(item));

    amxc_var_clean(&var);
}
