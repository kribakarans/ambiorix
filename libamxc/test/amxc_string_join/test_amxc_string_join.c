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
#include <stdio.h>
#include <stdarg.h>
#include <stddef.h>
#include <ctype.h>
#include <string.h>
#include <setjmp.h>
#include <cmocka.h>

#include <amxc/amxc_string_split.h>
#include <amxc/amxc_string_join.h>
#include <amxc/amxc_utils.h>

#include "test_amxc_string_join.h"

#include <amxc/amxc_macros.h>
void test_can_join_variant_list_to_string(UNUSED void** state) {
    amxc_var_t var;
    amxc_string_t string;
    amxc_var_t* sub_var = NULL;

    amxc_var_init(&var);
    amxc_string_init(&string, 0);

    amxc_var_set_type(&var, AMXC_VAR_ID_LIST);
    amxc_var_add(cstring_t, &var, "text1");
    amxc_var_add(uint32_t, &var, 123);
    sub_var = amxc_var_add(amxc_llist_t, &var, NULL);
    amxc_var_add(csv_string_t, sub_var, "a,b");
    amxc_var_add(ssv_string_t, sub_var, "a b");

    assert_int_equal(amxc_string_csv_join_var(&string, &var), 0);
    assert_string_equal(amxc_string_get(&string, 0), "text1,123,[a,b,a b]");
    amxc_string_reset(&string);

    assert_int_equal(amxc_string_ssv_join_var(&string, &var), 0);
    assert_string_equal(amxc_string_get(&string, 0), "text1 123 [a,b,a b]");

    amxc_var_clean(&var);
    amxc_string_clean(&string);
}

void test_join_fails_on_wrong_variant_type(UNUSED void** state) {
    amxc_var_t var;
    amxc_string_t string;

    amxc_var_init(&var);
    amxc_string_init(&string, 0);

    amxc_var_set(cstring_t, &var, "text1");
    assert_int_not_equal(amxc_string_csv_join_var(&string, &var), 0);
    assert_true(amxc_string_is_empty(&string));

    amxc_var_set(bool, &var, true);
    assert_int_not_equal(amxc_string_csv_join_var(&string, &var), 0);
    assert_true(amxc_string_is_empty(&string));

    amxc_var_clean(&var);
    amxc_string_clean(&string);
}

void test_join_adds_to_string(UNUSED void** state) {
    amxc_var_t var;
    amxc_string_t string;

    amxc_var_init(&var);
    amxc_string_init(&string, 0);
    amxc_string_appendf(&string, "The list is added after this: ");

    amxc_var_set_type(&var, AMXC_VAR_ID_LIST);
    amxc_var_add(cstring_t, &var, "text1");
    amxc_var_add(uint32_t, &var, 123);
    amxc_var_add(amxc_llist_t, &var, NULL);

    assert_int_equal(amxc_string_csv_join_var(&string, &var), 0);
    assert_string_equal(amxc_string_get(&string, 0), "The list is added after this: text1,123,[]");
    amxc_string_reset(&string);

    amxc_string_appendf(&string, "The list is added after this: ");
    assert_int_equal(amxc_string_ssv_join_var(&string, &var), 0);
    assert_string_equal(amxc_string_get(&string, 0), "The list is added after this: text1 123 []");

    amxc_var_clean(&var);
    amxc_string_clean(&string);
}

void test_split_and_join_to_list_provides_similar_string(UNUSED void** state) {
    amxc_llist_t list;
    amxc_string_t string;

    amxc_llist_init(&list);
    amxc_string_init(&string, 0);
    amxc_string_appendf(&string, "text1,text2,text3,[text4,text5],text6");

    assert_int_equal(amxc_string_split_to_llist(&string, &list, ','), 0);
    amxc_string_clean(&string);
    assert_int_equal(amxc_string_join_llist(&string, &list, ','), 0);
    assert_string_equal(amxc_string_get(&string, 0), "text1,text2,text3,[text4,text5],text6");

    amxc_string_clean(&string);
    assert_int_equal(amxc_string_join_llist(&string, &list, ' '), 0);
    assert_string_equal(amxc_string_get(&string, 0), "text1 text2 text3 [text4,text5] text6");

    amxc_llist_clean(&list, amxc_string_list_it_free);
    amxc_string_clean(&string);
}

void test_join_fails_with_invalid_separators(UNUSED void** state) {
    amxc_llist_t list;
    amxc_string_t string;

    amxc_llist_init(&list);
    amxc_string_init(&string, 0);
    amxc_string_appendf(&string, "text1,text2,text3,[text4,text5],text6");

    assert_int_equal(amxc_string_split_to_llist(&string, &list, ','), 0);
    amxc_string_clean(&string);
    assert_int_not_equal(amxc_string_join_llist(&string, &list, '['), 0);
    assert_true(amxc_string_is_empty(&string));
    assert_int_not_equal(amxc_string_join_llist(&string, &list, ']'), 0);
    assert_true(amxc_string_is_empty(&string));
    assert_int_not_equal(amxc_string_join_llist(&string, &list, 'a'), 0);
    assert_true(amxc_string_is_empty(&string));
    assert_int_not_equal(amxc_string_join_llist(&string, &list, '9'), 0);
    assert_true(amxc_string_is_empty(&string));

    assert_int_equal(amxc_string_join_llist(&string, &list, ':'), 0);
    assert_string_equal(amxc_string_get(&string, 0), "text1:text2:text3:[text4,text5]:text6");

    amxc_llist_clean(&list, amxc_string_list_it_free);
    amxc_string_clean(&string);
}

void test_join_does_input_argument_validation(UNUSED void** state) {
    amxc_llist_t list;
    amxc_var_t var;
    amxc_string_t string;

    amxc_llist_init(&list);
    amxc_var_init(&var);
    amxc_string_init(&string, 0);

    assert_int_not_equal(amxc_string_csv_join_var(NULL, &var), 0);
    assert_int_not_equal(amxc_string_csv_join_var(&string, NULL), 0);
    assert_int_not_equal(amxc_string_ssv_join_var(NULL, &var), 0);
    assert_int_not_equal(amxc_string_ssv_join_var(&string, NULL), 0);

    assert_int_not_equal(amxc_string_join_llist(NULL, &list, '/'), 0);
    assert_int_not_equal(amxc_string_join_llist(&string, NULL, '/'), 0);

    amxc_llist_clean(&list, amxc_string_list_it_free);
    amxc_string_clean(&string);
    amxc_var_clean(&var);
}
