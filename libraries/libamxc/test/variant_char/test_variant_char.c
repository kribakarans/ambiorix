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
#include <string.h>

#include <amxc/amxc_variant.h>
#include <amxc_variant_priv.h>

#include "test_variant_char.h"

#include <amxc/amxc_macros.h>
void test_variant_char_copy(UNUSED void** state) {
    amxc_var_t var;
    amxc_var_t copy_var;

    assert_int_equal(amxc_var_init(&var), 0);
    assert_int_equal(amxc_var_init(&copy_var), 0);
    assert_int_equal(var.type_id, AMXC_VAR_ID_NULL);
    assert_int_equal(amxc_var_set_type(&var, AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(var.type_id, AMXC_VAR_ID_CSTRING);
    var.data.s = "Hello world";

    assert_int_equal(amxc_var_copy(&copy_var, &var), 0);
    assert_string_equal(copy_var.data.s, "Hello world");
    free(copy_var.data.s);
}

void test_variant_char_convert_to_bool(UNUSED void** state) {
    amxc_var_t var;
    amxc_var_t copy_var;


    assert_int_equal(amxc_var_init(&var), 0);
    assert_int_equal(amxc_var_init(&copy_var), 0);
    assert_int_equal(var.type_id, AMXC_VAR_ID_NULL);
    assert_int_equal(amxc_var_set_type(&var, AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(var.type_id, AMXC_VAR_ID_CSTRING);

    var.data.s = NULL;
    assert_int_not_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_BOOL), 0);
    var.data.s = "";
    assert_int_not_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_BOOL), 0);

    var.data.s = "Hello world";
    assert_int_not_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_BOOL), 0);
    var.data.s = "0x10";
    assert_int_not_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_BOOL), 0);

    var.data.s = "true";
    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_BOOL), 0);
    assert_true(copy_var.data.b);

    var.data.s = "false";
    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_BOOL), 0);
    assert_false(copy_var.data.b);

    var.data.s = "yes";
    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_BOOL), 0);
    assert_true(copy_var.data.b);

    var.data.s = "no";
    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_BOOL), 0);
    assert_false(copy_var.data.b);

    var.data.s = "1";
    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_BOOL), 0);
    assert_true(copy_var.data.b);

    var.data.s = "0";
    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_BOOL), 0);
    assert_false(copy_var.data.b);

    var.data.s = "ON";
    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_BOOL), 0);
    assert_true(copy_var.data.b);

    var.data.s = "Off";
    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_BOOL), 0);
    assert_false(copy_var.data.b);

    var.data.s = "   \n\t   true";
    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_BOOL), 0);
    assert_true(copy_var.data.b);
}

void test_variant_char_convert_to_integer(UNUSED void** state) {
    amxc_var_t var;
    amxc_var_t copy_var;


    assert_int_equal(amxc_var_init(&var), 0);
    assert_int_equal(amxc_var_init(&copy_var), 0);
    assert_int_equal(var.type_id, AMXC_VAR_ID_NULL);
    assert_int_equal(amxc_var_set_type(&var, AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(var.type_id, AMXC_VAR_ID_CSTRING);

    var.data.s = NULL;
    assert_int_not_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_INT64), 0);
    var.data.s = "";
    assert_int_not_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_INT64), 0);

    var.data.s = "NULL";
    assert_int_not_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_INT64), 0);
    var.data.s = "\n\t  NULL";
    assert_int_not_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_INT64), 0);
    var.data.s = "Hello World";
    assert_int_not_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_INT64), 0);
    var.data.s = "12345Hello World";
    assert_int_not_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_INT64), 0);
    var.data.s = "     12345     ";
    assert_int_not_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_INT64), 0);

    var.data.s = "12345";
    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_INT64), 0);
    assert_int_equal(copy_var.data.i64, 12345);

    var.data.s = "  +555";
    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_INT64), 0);
    assert_int_equal(copy_var.data.i64, 555);

    var.data.s = "  -987";
    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_INT64), 0);
    assert_int_equal(copy_var.data.i64, -987);

    var.data.s = "92233720368547758081";
    assert_int_not_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_INT64), 0);
    var.data.s = "-92233720368547758081";
    assert_int_not_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_INT64), 0);
}

void test_variant_char_convert_to_uinteger(UNUSED void** state) {
    amxc_var_t var;
    amxc_var_t copy_var;


    assert_int_equal(amxc_var_init(&var), 0);
    assert_int_equal(amxc_var_init(&copy_var), 0);
    assert_int_equal(var.type_id, AMXC_VAR_ID_NULL);
    assert_int_equal(amxc_var_set_type(&var, AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(var.type_id, AMXC_VAR_ID_CSTRING);

    var.data.s = NULL;
    assert_int_not_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_UINT64), 0);
    var.data.s = "";
    assert_int_not_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_UINT64), 0);

    var.data.s = "NULL";
    assert_int_not_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_UINT64), 0);
    var.data.s = "\n\t  NULL";
    assert_int_not_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_UINT64), 0);
    var.data.s = "Hello World";
    assert_int_not_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_UINT64), 0);
    var.data.s = "12345Hello World";
    assert_int_not_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_UINT64), 0);
    var.data.s = "     12345     ";
    assert_int_not_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_UINT64), 0);

    var.data.s = "12345";
    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_UINT64), 0);
    assert_int_equal(copy_var.data.ui64, 12345);

    var.data.s = "  +555";
    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_UINT64), 0);
    assert_int_equal(copy_var.data.ui64, 555);

    var.data.s = "  -987";
    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_UINT64), 0);
    assert_int_equal(copy_var.data.ui64, 987);

    var.data.s = "92233720368547758081";
    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_UINT64), 0);
}

void test_variant_char_convert_to_list(UNUSED void** state) {
    amxc_var_t var;
    amxc_var_t copy_var;
    amxc_llist_it_t* it = NULL;

    assert_int_equal(amxc_var_init(&var), 0);
    assert_int_equal(amxc_var_init(&copy_var), 0);
    assert_int_equal(var.type_id, AMXC_VAR_ID_NULL);
    assert_int_equal(amxc_var_set_type(&var, AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(var.type_id, AMXC_VAR_ID_CSTRING);

    var.data.s = NULL;
    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_LIST), 0);
    assert_int_equal(amxc_var_type_of(&copy_var), AMXC_VAR_ID_LIST);
    var.data.s = strdup("");
    amxc_var_clean(&copy_var);
    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_LIST), 0);
    assert_int_equal(amxc_var_type_of(&copy_var), AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_llist_size(&copy_var.data.vl), 0);
    free(var.data.s);

    var.data.s = strdup("NULL");
    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_LIST), 0);
    assert_int_equal(amxc_llist_size(&copy_var.data.vl), 1);
    it = amxc_llist_get_first(&copy_var.data.vl);
    assert_ptr_not_equal(amxc_var_from_llist_it(it), NULL);
    assert_string_equal(amxc_var_from_llist_it(it)->data.s, "NULL");
    amxc_llist_clean(&copy_var.data.vl, variant_list_it_free);
    free(var.data.s);

    var.data.s = strdup("a,b,c,d,e");
    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_LIST), 0);
    assert_int_equal(amxc_llist_size(&copy_var.data.vl), 5);
    it = amxc_llist_get_first(&copy_var.data.vl);
    assert_ptr_not_equal(amxc_var_from_llist_it(it), NULL);
    assert_string_equal(amxc_var_from_llist_it(it)->data.s, "a");

    it = amxc_llist_it_get_next(it);
    assert_ptr_not_equal(amxc_var_from_llist_it(it), NULL);
    assert_string_equal(amxc_var_from_llist_it(it)->data.s, "b");

    it = amxc_llist_it_get_next(it);
    assert_ptr_not_equal(amxc_var_from_llist_it(it), NULL);
    assert_string_equal(amxc_var_from_llist_it(it)->data.s, "c");

    it = amxc_llist_it_get_next(it);
    assert_ptr_not_equal(amxc_var_from_llist_it(it), NULL);
    assert_string_equal(amxc_var_from_llist_it(it)->data.s, "d");

    it = amxc_llist_it_get_next(it);
    assert_ptr_not_equal(amxc_var_from_llist_it(it), NULL);
    assert_string_equal(amxc_var_from_llist_it(it)->data.s, "e");
    amxc_llist_clean(&copy_var.data.vl, variant_list_it_free);
    free(var.data.s);

    var.data.s = strdup("a , b , c ,   d ,    \t \n         e");
    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_LIST), 0);
    assert_int_equal(amxc_llist_size(&copy_var.data.vl), 5);
    it = amxc_llist_get_first(&copy_var.data.vl);
    assert_ptr_not_equal(amxc_var_from_llist_it(it), NULL);
    assert_string_equal(amxc_var_from_llist_it(it)->data.s, "a");

    it = amxc_llist_it_get_next(it);
    assert_ptr_not_equal(amxc_var_from_llist_it(it), NULL);
    assert_string_equal(amxc_var_from_llist_it(it)->data.s, "b");

    it = amxc_llist_it_get_next(it);
    assert_ptr_not_equal(amxc_var_from_llist_it(it), NULL);
    assert_string_equal(amxc_var_from_llist_it(it)->data.s, "c");

    it = amxc_llist_it_get_next(it);
    assert_ptr_not_equal(amxc_var_from_llist_it(it), NULL);
    assert_string_equal(amxc_var_from_llist_it(it)->data.s, "d");

    it = amxc_llist_it_get_next(it);
    assert_ptr_not_equal(amxc_var_from_llist_it(it), NULL);
    assert_string_equal(amxc_var_from_llist_it(it)->data.s, "e");
    amxc_llist_clean(&copy_var.data.vl, variant_list_it_free);
    free(var.data.s);

    var.data.s = strdup("a,,b,,c,,d, ,e");
    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_LIST), 0);
    assert_int_equal(amxc_llist_size(&copy_var.data.vl), 9);
    it = amxc_llist_get_first(&copy_var.data.vl);
    assert_ptr_not_equal(amxc_var_from_llist_it(it), NULL);
    assert_string_equal(amxc_var_from_llist_it(it)->data.s, "a");

    it = amxc_llist_it_get_next(it);
    assert_ptr_not_equal(amxc_var_from_llist_it(it), NULL);
    assert_string_equal(amxc_var_from_llist_it(it)->data.s, "");

    it = amxc_llist_it_get_next(it);
    assert_ptr_not_equal(amxc_var_from_llist_it(it), NULL);
    assert_string_equal(amxc_var_from_llist_it(it)->data.s, "b");

    it = amxc_llist_it_get_next(it);
    assert_ptr_not_equal(amxc_var_from_llist_it(it), NULL);
    assert_string_equal(amxc_var_from_llist_it(it)->data.s, "");

    it = amxc_llist_it_get_next(it);
    assert_ptr_not_equal(amxc_var_from_llist_it(it), NULL);
    assert_string_equal(amxc_var_from_llist_it(it)->data.s, "c");

    it = amxc_llist_it_get_next(it);
    assert_ptr_not_equal(amxc_var_from_llist_it(it), NULL);
    assert_string_equal(amxc_var_from_llist_it(it)->data.s, "");

    it = amxc_llist_it_get_next(it);
    assert_ptr_not_equal(amxc_var_from_llist_it(it), NULL);
    assert_string_equal(amxc_var_from_llist_it(it)->data.s, "d");

    it = amxc_llist_it_get_next(it);
    assert_ptr_not_equal(amxc_var_from_llist_it(it), NULL);
    assert_string_equal(amxc_var_from_llist_it(it)->data.s, "");

    it = amxc_llist_it_get_next(it);
    assert_ptr_not_equal(amxc_var_from_llist_it(it), NULL);
    assert_string_equal(amxc_var_from_llist_it(it)->data.s, "e");
    free(var.data.s);

    amxc_llist_clean(&copy_var.data.vl, variant_list_it_free);

    amxc_var_clean(&copy_var);
}

void test_variant_ssv_char_convert_to_list(UNUSED void** state) {
    amxc_var_t var;
    amxc_var_t copy_var;
    amxc_llist_it_t* it = NULL;

    assert_int_equal(amxc_var_init(&var), 0);
    assert_int_equal(amxc_var_init(&copy_var), 0);
    assert_int_equal(var.type_id, AMXC_VAR_ID_NULL);
    assert_int_equal(amxc_var_set_type(&var, AMXC_VAR_ID_SSV_STRING), 0);
    assert_int_equal(var.type_id, AMXC_VAR_ID_SSV_STRING);

    var.data.s = NULL;
    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_LIST), 0);
    assert_int_equal(amxc_var_type_of(&copy_var), AMXC_VAR_ID_LIST);
    var.data.s = strdup("");
    amxc_var_clean(&copy_var);
    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_LIST), 0);
    assert_int_equal(amxc_var_type_of(&copy_var), AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_llist_size(&copy_var.data.vl), 0);
    free(var.data.s);

    var.data.s = strdup("NULL");
    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_LIST), 0);
    assert_int_equal(amxc_llist_size(&copy_var.data.vl), 1);
    it = amxc_llist_get_first(&copy_var.data.vl);
    assert_ptr_not_equal(amxc_var_from_llist_it(it), NULL);
    assert_string_equal(amxc_var_from_llist_it(it)->data.s, "NULL");
    amxc_llist_clean(&copy_var.data.vl, variant_list_it_free);
    free(var.data.s);

    var.data.s = strdup("a b c d e");
    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_LIST), 0);
    assert_int_equal(amxc_llist_size(&copy_var.data.vl), 5);
    it = amxc_llist_get_first(&copy_var.data.vl);
    assert_ptr_not_equal(amxc_var_from_llist_it(it), NULL);
    assert_string_equal(amxc_var_from_llist_it(it)->data.s, "a");

    it = amxc_llist_it_get_next(it);
    assert_ptr_not_equal(amxc_var_from_llist_it(it), NULL);
    assert_string_equal(amxc_var_from_llist_it(it)->data.s, "b");

    it = amxc_llist_it_get_next(it);
    assert_ptr_not_equal(amxc_var_from_llist_it(it), NULL);
    assert_string_equal(amxc_var_from_llist_it(it)->data.s, "c");

    it = amxc_llist_it_get_next(it);
    assert_ptr_not_equal(amxc_var_from_llist_it(it), NULL);
    assert_string_equal(amxc_var_from_llist_it(it)->data.s, "d");

    it = amxc_llist_it_get_next(it);
    assert_ptr_not_equal(amxc_var_from_llist_it(it), NULL);
    assert_string_equal(amxc_var_from_llist_it(it)->data.s, "e");
    amxc_llist_clean(&copy_var.data.vl, variant_list_it_free);
    free(var.data.s);

    var.data.s = strdup("a  b  c  d  e");
    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_LIST), 0);
    assert_int_equal(amxc_llist_size(&copy_var.data.vl), 5);
    it = amxc_llist_get_first(&copy_var.data.vl);
    assert_ptr_not_equal(amxc_var_from_llist_it(it), NULL);
    assert_string_equal(amxc_var_from_llist_it(it)->data.s, "a");

    it = amxc_llist_it_get_next(it);
    assert_ptr_not_equal(amxc_var_from_llist_it(it), NULL);
    assert_string_equal(amxc_var_from_llist_it(it)->data.s, "b");

    it = amxc_llist_it_get_next(it);
    assert_ptr_not_equal(amxc_var_from_llist_it(it), NULL);
    assert_string_equal(amxc_var_from_llist_it(it)->data.s, "c");

    it = amxc_llist_it_get_next(it);
    assert_ptr_not_equal(amxc_var_from_llist_it(it), NULL);
    assert_string_equal(amxc_var_from_llist_it(it)->data.s, "d");

    it = amxc_llist_it_get_next(it);
    assert_ptr_not_equal(amxc_var_from_llist_it(it), NULL);
    assert_string_equal(amxc_var_from_llist_it(it)->data.s, "e");

    amxc_llist_clean(&copy_var.data.vl, variant_list_it_free);
    free(var.data.s);

    amxc_var_clean(&copy_var);
}

void test_variant_char_convert_to_htable(UNUSED void** state) {
    amxc_var_t var;
    amxc_var_t copy_var;
    amxc_htable_it_t* it = NULL;

    assert_int_equal(amxc_var_init(&var), 0);
    assert_int_equal(amxc_var_init(&copy_var), 0);
    assert_int_equal(var.type_id, AMXC_VAR_ID_NULL);
    assert_int_equal(amxc_var_set_type(&var, AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(var.type_id, AMXC_VAR_ID_CSTRING);

    var.data.s = NULL;
    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_HTABLE), 0);
    assert_int_equal(amxc_var_type_of(&copy_var), AMXC_VAR_ID_HTABLE);
    var.data.s = "";
    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_HTABLE), 0);
    assert_int_equal(amxc_var_type_of(&copy_var), AMXC_VAR_ID_HTABLE);

    var.data.s = "NULL";
    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_HTABLE), 0);
    assert_int_equal(amxc_htable_size(&copy_var.data.vm), 1);
    it = amxc_htable_get_first(&copy_var.data.vm);
    assert_ptr_not_equal(amxc_var_from_htable_it(it), NULL);
    assert_ptr_equal(amxc_var_from_htable_it(it)->data.s, NULL);
    assert_ptr_not_equal(amxc_htable_it_get_key(it), NULL);
    assert_string_equal(amxc_htable_it_get_key(it), "NULL");

    var.data.s = "key1:a,key2:b,key3:c,key4:d,key5:e";
    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_HTABLE), 0);
    assert_int_equal(amxc_htable_size(&copy_var.data.vm), 5);
    it = amxc_htable_get(&copy_var.data.vm, "key1");
    assert_ptr_not_equal(amxc_var_from_htable_it(it), NULL);
    assert_ptr_not_equal(amxc_var_from_htable_it(it)->data.s, NULL);
    assert_string_equal(amxc_var_from_htable_it(it)->data.s, "a");
    assert_ptr_not_equal(amxc_htable_it_get_key(it), NULL);
    assert_string_equal(amxc_htable_it_get_key(it), "key1");

    it = amxc_htable_get(&copy_var.data.vm, "key2");
    assert_ptr_not_equal(amxc_var_from_htable_it(it), NULL);
    assert_ptr_not_equal(amxc_var_from_htable_it(it)->data.s, NULL);
    assert_string_equal(amxc_var_from_htable_it(it)->data.s, "b");
    assert_ptr_not_equal(amxc_htable_it_get_key(it), NULL);
    assert_string_equal(amxc_htable_it_get_key(it), "key2");

    it = amxc_htable_get(&copy_var.data.vm, "key3");
    assert_ptr_not_equal(amxc_var_from_htable_it(it), NULL);
    assert_ptr_not_equal(amxc_var_from_htable_it(it)->data.s, NULL);
    assert_string_equal(amxc_var_from_htable_it(it)->data.s, "c");
    assert_ptr_not_equal(amxc_htable_it_get_key(it), NULL);
    assert_string_equal(amxc_htable_it_get_key(it), "key3");

    it = amxc_htable_get(&copy_var.data.vm, "key4");
    assert_ptr_not_equal(amxc_var_from_htable_it(it), NULL);
    assert_ptr_not_equal(amxc_var_from_htable_it(it)->data.s, NULL);
    assert_string_equal(amxc_var_from_htable_it(it)->data.s, "d");
    assert_ptr_not_equal(amxc_htable_it_get_key(it), NULL);
    assert_string_equal(amxc_htable_it_get_key(it), "key4");

    it = amxc_htable_get(&copy_var.data.vm, "key5");
    assert_ptr_not_equal(amxc_var_from_htable_it(it), NULL);
    assert_ptr_not_equal(amxc_var_from_htable_it(it)->data.s, NULL);
    assert_string_equal(amxc_var_from_htable_it(it)->data.s, "e");
    assert_ptr_not_equal(amxc_htable_it_get_key(it), NULL);
    assert_string_equal(amxc_htable_it_get_key(it), "key5");

    amxc_var_clean(&copy_var);
}

void test_variant_char_convert_to_double(UNUSED void** state) {
    amxc_var_t var;
    amxc_var_t copy_var;

    assert_int_equal(amxc_var_init(&var), 0);
    assert_int_equal(amxc_var_init(&copy_var), 0);
    assert_int_equal(var.type_id, AMXC_VAR_ID_NULL);
    assert_int_equal(amxc_var_set_type(&var, AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(var.type_id, AMXC_VAR_ID_CSTRING);

    var.data.s = NULL;
    assert_int_not_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_DOUBLE), 0);
    var.data.s = "";
    assert_int_not_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_DOUBLE), 0);

    var.data.s = "NULL";
    assert_int_not_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_DOUBLE), 0);
    var.data.s = "\n\t  NULL";
    assert_int_not_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_DOUBLE), 0);
    var.data.s = "Hello World";
    assert_int_not_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_DOUBLE), 0);
    var.data.s = "12345Hello World";
    assert_int_not_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_DOUBLE), 0);
    var.data.s = "     12345     ";
    assert_int_not_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_DOUBLE), 0);

    var.data.s = "12345";
    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_DOUBLE), 0);
    assert_true(copy_var.data.d == 12345);

    var.data.s = "1e+10";
    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_DOUBLE), 0);
    assert_true(copy_var.data.d == 1e+10);

    var.data.s = "1e-10";
    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_DOUBLE), 0);

    var.data.s = "2.2204460492503131e-400";
    assert_int_not_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_DOUBLE), 0);
}

void test_variant_char_convert_to_float(UNUSED void** state) {
    amxc_var_t var;
    amxc_var_t copy_var;

    assert_int_equal(amxc_var_init(&var), 0);
    assert_int_equal(amxc_var_init(&copy_var), 0);
    assert_int_equal(var.type_id, AMXC_VAR_ID_NULL);
    assert_int_equal(amxc_var_set_type(&var, AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(var.type_id, AMXC_VAR_ID_CSTRING);

    var.data.s = NULL;
    assert_int_not_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_FLOAT), 0);
    var.data.s = "";
    assert_int_not_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_FLOAT), 0);

    var.data.s = "NULL";
    assert_int_not_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_FLOAT), 0);
    var.data.s = "\n\t  NULL";
    assert_int_not_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_FLOAT), 0);
    var.data.s = "Hello World";
    assert_int_not_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_FLOAT), 0);
    var.data.s = "12345Hello World";
    assert_int_not_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_FLOAT), 0);
    var.data.s = "     12345     ";
    assert_int_not_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_FLOAT), 0);

    var.data.s = "12345";
    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_FLOAT), 0);
    assert_true(copy_var.data.f == 12345);

    var.data.s = "1e+10";
    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_FLOAT), 0);

    var.data.s = "2.2204460492503131e-400";
    assert_int_not_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_FLOAT), 0);
}

void test_variant_char_convert_to_ts(UNUSED void** state) {
    amxc_var_t var1;
    amxc_var_t var2;
    char buffer[32] = {};
    amxc_var_t string_with_null_buffer;

    amxc_var_init(&var1);
    amxc_var_init(&var2);
    amxc_var_init(&string_with_null_buffer);

    // Case: normal
    assert_int_equal(amxc_var_set(cstring_t, &var1, "2020-06-19T09:08:16Z"), 0);
    assert_int_equal(amxc_var_convert(&var2, &var1, AMXC_VAR_ID_TIMESTAMP), 0);
    assert_int_equal(var2.type_id, AMXC_VAR_ID_TIMESTAMP);
    amxc_ts_format(amxc_var_constcast(amxc_ts_t, &var2), buffer, sizeof(buffer));
    assert_string_equal("2020-06-19T09:08:16Z", buffer);

    // Case: cannot parse
    assert_int_equal(amxc_var_set(cstring_t, &var1, "THIS IS NOT A TIMESTAMP"), 0);
    assert_int_not_equal(amxc_var_convert(&var2, &var1, AMXC_VAR_ID_TIMESTAMP), 0);

    // Case: empty string
    assert_int_equal(amxc_var_set(cstring_t, &var1, ""), 0);
    assert_int_not_equal(amxc_var_convert(&var2, &var1, AMXC_VAR_ID_TIMESTAMP), 0);

    // Case: string buffer is null
    assert_int_equal(amxc_var_set_type(&string_with_null_buffer, AMXC_VAR_ID_CSTRING), 0);
    assert_int_not_equal(amxc_var_convert(&var2, &string_with_null_buffer, AMXC_VAR_ID_TIMESTAMP), 0);

    amxc_var_clean(&var1);
    amxc_var_clean(&var2);
    amxc_var_clean(&string_with_null_buffer);
}

void test_variant_char_compare(UNUSED void** state) {
    amxc_var_t var1;
    amxc_var_t var2;
    int result = 0;

    assert_int_equal(amxc_var_init(&var1), 0);
    assert_int_equal(amxc_var_init(&var2), 0);
    assert_int_equal(amxc_var_set_type(&var1, AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(amxc_var_set_type(&var2, AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(var1.type_id, AMXC_VAR_ID_CSTRING);
    assert_int_equal(var2.type_id, AMXC_VAR_ID_CSTRING);

    assert_int_equal(amxc_var_compare(&var1, &var2, &result), 0);
    assert_int_equal(result, 0);

    var1.data.s = "Hello world";
    var2.data.s = "Hello world";

    assert_int_equal(amxc_var_compare(&var1, &var2, &result), 0);
    assert_int_equal(result, 0);

    var2.data.s = "Hello europe";
    assert_int_equal(amxc_var_compare(&var2, &var1, &result), 0);
    assert_true(result < 0);

    var2.data.s = "Hello zulu";
    assert_int_equal(amxc_var_compare(&var2, &var1, &result), 0);
    assert_true(result > 0);
}

void test_variant_char_set_get(UNUSED void** state) {
    amxc_var_t var1;
    char* text = NULL;
    const char* consttext = NULL;

    assert_int_equal(amxc_var_init(&var1), 0);
    amxc_var_set_type(&var1, AMXC_VAR_ID_CSTRING);
    assert_string_equal(amxc_var_constcast(cstring_t, &var1), "");
    text = amxc_var_dyncast(cstring_t, &var1);
    assert_string_equal(text, "");
    free(text);

    assert_int_equal(amxc_var_set_cstring_t(&var1, "Hello world"), 0);
    assert_int_equal(var1.type_id, AMXC_VAR_ID_CSTRING);
    assert_string_equal(var1.data.s, "Hello world");

    text = amxc_var_get_cstring_t(&var1);
    assert_ptr_not_equal(text, NULL);
    assert_string_equal(text, "Hello world");
    free(text);

    assert_int_equal(amxc_var_set_csv_string_t(&var1, "Hello world"), 0);
    assert_int_equal(var1.type_id, AMXC_VAR_ID_CSV_STRING);
    text = amxc_var_get_csv_string_t(&var1);
    assert_ptr_not_equal(text, NULL);
    assert_string_equal(text, "Hello world");
    free(text);

    assert_int_equal(amxc_var_set_ssv_string_t(&var1, "Hello world"), 0);
    assert_int_equal(var1.type_id, AMXC_VAR_ID_SSV_STRING);
    text = amxc_var_get_ssv_string_t(&var1);
    assert_ptr_not_equal(text, NULL);
    assert_string_equal(text, "Hello world");
    free(text);

    text = amxc_var_dyncast(cstring_t, &var1);
    assert_ptr_not_equal(text, NULL);
    assert_string_equal(text, "Hello world");
    free(text);
    consttext = amxc_var_constcast(cstring_t, &var1);
    assert_ptr_not_equal(consttext, NULL);
    assert_string_equal(consttext, "Hello world");

    text = amxc_var_dyncast(csv_string_t, &var1);
    assert_ptr_not_equal(text, NULL);
    assert_string_equal(text, "Hello world");
    free(text);
    consttext = amxc_var_constcast(csv_string_t, &var1);
    assert_ptr_not_equal(consttext, NULL);
    assert_string_equal(consttext, "Hello world");

    text = amxc_var_dyncast(ssv_string_t, &var1);
    assert_ptr_not_equal(text, NULL);
    assert_string_equal(text, "Hello world");
    free(text);
    consttext = amxc_var_constcast(ssv_string_t, &var1);
    assert_ptr_not_equal(consttext, NULL);
    assert_string_equal(consttext, "Hello world");

    text = amxc_var_dyncast(cstring_t, NULL);
    assert_ptr_equal(text, NULL);
    text = amxc_var_dyncast(csv_string_t, NULL);
    assert_ptr_equal(text, NULL);
    text = amxc_var_dyncast(ssv_string_t, NULL);
    assert_ptr_equal(text, NULL);

    assert_int_equal(amxc_var_set_type(&var1, AMXC_VAR_ID_CUSTOM_BASE), 0);
    text = amxc_var_dyncast(cstring_t, &var1);
    assert_ptr_equal(text, NULL);
    consttext = amxc_var_constcast(cstring_t, &var1);
    assert_ptr_equal(consttext, NULL);

    consttext = amxc_var_constcast(cstring_t, NULL);
    assert_ptr_equal(consttext, NULL);
    assert_int_equal(amxc_var_set_type(&var1, AMXC_VAR_ID_BOOL), 0);
    consttext = amxc_var_constcast(cstring_t, &var1);
    assert_ptr_equal(consttext, NULL);

    assert_int_not_equal(amxc_var_set_cstring_t(NULL, NULL), 0);
    assert_int_not_equal(amxc_var_set_cstring_t(NULL, "Hello world"), 0);
    assert_int_not_equal(amxc_var_set_cstring_t(&var1, NULL), 0);

    assert_int_not_equal(amxc_var_set_csv_string_t(NULL, NULL), 0);
    assert_int_not_equal(amxc_var_set_csv_string_t(NULL, "Hello world"), 0);
    assert_int_not_equal(amxc_var_set_csv_string_t(&var1, NULL), 0);

    assert_int_not_equal(amxc_var_set_ssv_string_t(NULL, NULL), 0);
    assert_int_not_equal(amxc_var_set_ssv_string_t(NULL, "Hello world"), 0);
    assert_int_not_equal(amxc_var_set_ssv_string_t(&var1, NULL), 0);

    amxc_var_clean(&var1);
}

void test_variant_cstring_add(UNUSED void** state) {
    amxc_var_t var;
    const amxc_llist_t* list = NULL;
    const amxc_htable_t* table = NULL;

    assert_int_equal(amxc_var_init(&var), 0);
    assert_int_equal(amxc_var_set_type(&var, AMXC_VAR_ID_LIST), 0);
    assert_ptr_not_equal(amxc_var_add(cstring_t, &var, "hello"), NULL);
    assert_ptr_not_equal(amxc_var_add(csv_string_t, &var, "world"), NULL);
    assert_ptr_not_equal(amxc_var_add(ssv_string_t, &var, "."), NULL);

    assert_ptr_equal(amxc_var_add(cstring_t, NULL, "hello"), NULL);
    assert_ptr_equal(amxc_var_add(csv_string_t, NULL, "world"), NULL);
    assert_ptr_equal(amxc_var_add(ssv_string_t, NULL, "."), NULL);

    list = amxc_var_constcast(amxc_llist_t, &var);
    assert_int_equal(amxc_llist_size(list), 3);
    amxc_var_clean(&var);

    assert_int_equal(amxc_var_init(&var), 0);
    assert_int_equal(amxc_var_set_type(&var, AMXC_VAR_ID_HTABLE), 0);
    assert_ptr_not_equal(amxc_var_add_key(cstring_t, &var, "B1", "hello"), NULL);
    assert_ptr_not_equal(amxc_var_add_key(csv_string_t, &var, "B2", "world"), NULL);
    assert_ptr_not_equal(amxc_var_add_key(ssv_string_t, &var, "B3", "."), NULL);

    assert_ptr_equal(amxc_var_add_key(cstring_t, NULL, "B1", "hello"), NULL);
    assert_ptr_equal(amxc_var_add_key(csv_string_t, NULL, "B2", "world"), NULL);
    assert_ptr_equal(amxc_var_add_key(ssv_string_t, NULL, "B2", "."), NULL);

    table = amxc_var_constcast(amxc_htable_t, &var);
    assert_int_equal(amxc_htable_size(table), 3);
    amxc_var_clean(&var);
}

void test_variant_char_copy_null(UNUSED void** state) {
    amxc_var_t var1;
    amxc_var_t var2;

    assert_int_equal(amxc_var_init(&var1), 0);
    assert_int_equal(amxc_var_init(&var2), 0);
    assert_int_equal(amxc_var_set_type(&var1, AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(amxc_var_copy(&var2, &var1), 0);

    amxc_var_clean(&var1);
    amxc_var_clean(&var2);
}

void test_variant_char_take_push(UNUSED void** state) {
    amxc_var_t var1;
    char* txt = NULL;

    amxc_var_init(&var1);
    amxc_var_set(cstring_t, &var1, "Hello World.");

    txt = amxc_var_take(cstring_t, &var1);
    assert_ptr_not_equal(txt, NULL);
    assert_int_equal(var1.type_id, AMXC_VAR_ID_NULL);
    assert_ptr_equal(var1.data.s, NULL);
    assert_string_equal(txt, "Hello World.");

    assert_int_equal(amxc_var_push(cstring_t, &var1, txt), 0);
    assert_int_equal(var1.type_id, AMXC_VAR_ID_CSTRING);
    assert_ptr_not_equal(var1.data.s, NULL);
    assert_string_equal(var1.data.s, "Hello World.");

    txt = amxc_var_take(csv_string_t, &var1);
    assert_int_equal(amxc_var_push(csv_string_t, &var1, txt), 0);
    assert_int_equal(var1.type_id, AMXC_VAR_ID_CSV_STRING);
    assert_ptr_not_equal(var1.data.s, NULL);
    assert_string_equal(var1.data.s, "Hello World.");

    txt = amxc_var_take(ssv_string_t, &var1);
    assert_int_equal(amxc_var_push(ssv_string_t, &var1, txt), 0);
    assert_int_equal(var1.type_id, AMXC_VAR_ID_SSV_STRING);
    assert_ptr_not_equal(var1.data.s, NULL);
    assert_string_equal(var1.data.s, "Hello World.");

    assert_ptr_equal(amxc_var_take(csv_string_t, NULL), NULL);
    assert_ptr_equal(amxc_var_take(ssv_string_t, NULL), NULL);
    assert_ptr_equal(amxc_var_take(cstring_t, NULL), NULL);

    amxc_var_clean(&var1);
}

void test_variant_char_move(UNUSED void** state) {
    amxc_var_t src;
    amxc_var_t dst;

    amxc_var_init(&src);
    amxc_var_init(&dst);

    amxc_var_set(cstring_t, &src, "This is a tekst - ... ");
    assert_int_equal(amxc_var_move(&dst, &src), 0);

    amxc_var_clean(&src);
    amxc_var_clean(&dst);
}

void test_variant_char_cast(UNUSED void** state) {
    amxc_var_t test_var;

    amxc_var_init(&test_var);

    amxc_var_set(cstring_t, &test_var, "true");
    assert_int_equal(amxc_var_type_of(&test_var), AMXC_VAR_ID_CSTRING);
    assert_int_equal(amxc_var_cast(&test_var, AMXC_VAR_ID_ANY), 0);
    assert_int_equal(amxc_var_type_of(&test_var), AMXC_VAR_ID_BOOL);
    assert_true(amxc_var_constcast(bool, &test_var));

    amxc_var_set(cstring_t, &test_var, "TRUE");
    assert_int_equal(amxc_var_type_of(&test_var), AMXC_VAR_ID_CSTRING);
    assert_int_equal(amxc_var_cast(&test_var, AMXC_VAR_ID_ANY), 0);
    assert_int_equal(amxc_var_type_of(&test_var), AMXC_VAR_ID_BOOL);
    assert_true(amxc_var_constcast(bool, &test_var));

    amxc_var_set(cstring_t, &test_var, "Yes");
    assert_int_equal(amxc_var_type_of(&test_var), AMXC_VAR_ID_CSTRING);
    assert_int_equal(amxc_var_cast(&test_var, AMXC_VAR_ID_ANY), 0);
    assert_int_equal(amxc_var_type_of(&test_var), AMXC_VAR_ID_BOOL);
    assert_true(amxc_var_constcast(bool, &test_var));

    amxc_var_set(cstring_t, &test_var, "false");
    assert_int_equal(amxc_var_type_of(&test_var), AMXC_VAR_ID_CSTRING);
    assert_int_equal(amxc_var_cast(&test_var, AMXC_VAR_ID_ANY), 0);
    assert_int_equal(amxc_var_type_of(&test_var), AMXC_VAR_ID_BOOL);
    assert_false(amxc_var_constcast(bool, &test_var));

    amxc_var_set(cstring_t, &test_var, "FaLsE");
    assert_int_equal(amxc_var_type_of(&test_var), AMXC_VAR_ID_CSTRING);
    assert_int_equal(amxc_var_cast(&test_var, AMXC_VAR_ID_ANY), 0);
    assert_int_equal(amxc_var_type_of(&test_var), AMXC_VAR_ID_BOOL);
    assert_false(amxc_var_constcast(bool, &test_var));

    amxc_var_set(cstring_t, &test_var, "\n false");
    assert_int_equal(amxc_var_type_of(&test_var), AMXC_VAR_ID_CSTRING);
    assert_int_equal(amxc_var_cast(&test_var, AMXC_VAR_ID_ANY), 0);
    assert_int_equal(amxc_var_type_of(&test_var), AMXC_VAR_ID_BOOL);
    assert_false(amxc_var_constcast(bool, &test_var));

    amxc_var_set(cstring_t, &test_var, "NO");
    assert_int_equal(amxc_var_type_of(&test_var), AMXC_VAR_ID_CSTRING);
    assert_int_equal(amxc_var_cast(&test_var, AMXC_VAR_ID_ANY), 0);
    assert_int_equal(amxc_var_type_of(&test_var), AMXC_VAR_ID_BOOL);
    assert_false(amxc_var_constcast(bool, &test_var));

    amxc_var_set(cstring_t, &test_var, "1970-01-01T00:00:00Z");
    assert_int_equal(amxc_var_type_of(&test_var), AMXC_VAR_ID_CSTRING);
    assert_int_equal(amxc_var_cast(&test_var, AMXC_VAR_ID_ANY), 0);
    assert_int_equal(amxc_var_type_of(&test_var), AMXC_VAR_ID_TIMESTAMP);
    amxc_var_dump(&test_var, STDOUT_FILENO);

    amxc_var_set(cstring_t, &test_var, "-3.141592654");
    assert_int_equal(amxc_var_type_of(&test_var), AMXC_VAR_ID_CSTRING);
    assert_int_equal(amxc_var_cast(&test_var, AMXC_VAR_ID_ANY), 0);
    assert_int_equal(amxc_var_type_of(&test_var), AMXC_VAR_ID_DOUBLE);

    amxc_var_set(cstring_t, &test_var, "3.141592654");
    assert_int_equal(amxc_var_type_of(&test_var), AMXC_VAR_ID_CSTRING);
    assert_int_equal(amxc_var_cast(&test_var, AMXC_VAR_ID_ANY), 0);
    assert_int_equal(amxc_var_type_of(&test_var), AMXC_VAR_ID_DOUBLE);

    amxc_var_set(cstring_t, &test_var, "+3.141592654");
    assert_int_equal(amxc_var_type_of(&test_var), AMXC_VAR_ID_CSTRING);
    assert_int_equal(amxc_var_cast(&test_var, AMXC_VAR_ID_ANY), 0);
    assert_int_equal(amxc_var_type_of(&test_var), AMXC_VAR_ID_DOUBLE);

    amxc_var_set(cstring_t, &test_var, "+1024");
    assert_int_equal(amxc_var_type_of(&test_var), AMXC_VAR_ID_CSTRING);
    assert_int_equal(amxc_var_cast(&test_var, AMXC_VAR_ID_ANY), 0);
    assert_int_equal(amxc_var_type_of(&test_var), AMXC_VAR_ID_INT32);
    assert_int_equal(test_var.data.i32, 1024);

    amxc_var_set(cstring_t, &test_var, "-1024");
    assert_int_equal(amxc_var_type_of(&test_var), AMXC_VAR_ID_CSTRING);
    assert_int_equal(amxc_var_cast(&test_var, AMXC_VAR_ID_ANY), 0);
    assert_int_equal(amxc_var_type_of(&test_var), AMXC_VAR_ID_INT32);
    assert_int_equal(test_var.data.i32, -1024);

    amxc_var_set(cstring_t, &test_var, "1024");
    assert_int_equal(amxc_var_type_of(&test_var), AMXC_VAR_ID_CSTRING);
    assert_int_equal(amxc_var_cast(&test_var, AMXC_VAR_ID_ANY), 0);
    assert_int_equal(amxc_var_type_of(&test_var), AMXC_VAR_ID_UINT32);
    assert_int_equal(test_var.data.ui32, 1024);

    amxc_var_set(cstring_t, &test_var, "+2147483648");
    assert_int_equal(amxc_var_type_of(&test_var), AMXC_VAR_ID_CSTRING);
    assert_int_equal(amxc_var_cast(&test_var, AMXC_VAR_ID_ANY), 0);
    assert_int_equal(amxc_var_type_of(&test_var), AMXC_VAR_ID_INT64);
    assert_int_equal(test_var.data.i64, 2147483648);

    amxc_var_set(cstring_t, &test_var, "-2147483649");
    assert_int_equal(amxc_var_type_of(&test_var), AMXC_VAR_ID_CSTRING);
    assert_int_equal(amxc_var_cast(&test_var, AMXC_VAR_ID_ANY), 0);
    assert_int_equal(amxc_var_type_of(&test_var), AMXC_VAR_ID_INT64);
    assert_int_equal(test_var.data.i64, -2147483649);

    amxc_var_set(cstring_t, &test_var, "4294967296");
    assert_int_equal(amxc_var_type_of(&test_var), AMXC_VAR_ID_CSTRING);
    assert_int_equal(amxc_var_cast(&test_var, AMXC_VAR_ID_ANY), 0);
    assert_int_equal(amxc_var_type_of(&test_var), AMXC_VAR_ID_UINT64);
    assert_int_equal(test_var.data.ui64, 4294967296);

    amxc_var_set(cstring_t, &test_var, " HELLO WORLD ");
    assert_int_equal(amxc_var_type_of(&test_var), AMXC_VAR_ID_CSTRING);
    assert_int_equal(amxc_var_cast(&test_var, AMXC_VAR_ID_ANY), 0);
    assert_int_equal(amxc_var_type_of(&test_var), AMXC_VAR_ID_CSTRING);
    assert_string_equal(test_var.data.s, " HELLO WORLD ");

    amxc_var_set(cstring_t, &test_var, "");
    assert_int_equal(amxc_var_type_of(&test_var), AMXC_VAR_ID_CSTRING);
    assert_int_equal(amxc_var_cast(&test_var, AMXC_VAR_ID_ANY), 0);
    assert_int_equal(amxc_var_type_of(&test_var), AMXC_VAR_ID_CSTRING);
    assert_string_equal(test_var.data.s, "");

    amxc_var_set(csv_string_t, &test_var, "Phonebook.Contact.[FirstName=='ward'].PhoneNumber.*,Phonebook.Contact.");
    assert_int_equal(amxc_var_type_of(&test_var), AMXC_VAR_ID_CSV_STRING);
    assert_int_equal(amxc_var_cast(&test_var, AMXC_VAR_ID_LIST), 0);
    amxc_var_dump(&test_var, STDOUT_FILENO);
    assert_int_equal(amxc_var_type_of(&test_var), AMXC_VAR_ID_LIST);
    assert_string_equal(GETI_CHAR(&test_var, 0), "Phonebook.Contact.[FirstName=='ward'].PhoneNumber.*");
    assert_string_equal(GETI_CHAR(&test_var, 1), "Phonebook.Contact.");

    amxc_var_set(csv_string_t, &test_var, "Phonebook.Contact.[FirstName=='ward'].PhoneNumber.*");
    assert_int_equal(amxc_var_type_of(&test_var), AMXC_VAR_ID_CSV_STRING);
    assert_int_equal(amxc_var_cast(&test_var, AMXC_VAR_ID_LIST), 0);
    amxc_var_dump(&test_var, STDOUT_FILENO);
    assert_int_equal(amxc_var_type_of(&test_var), AMXC_VAR_ID_LIST);
    assert_string_equal(GETI_CHAR(&test_var, 0), "Phonebook.Contact.[FirstName=='ward'].PhoneNumber.*");

    amxc_var_set(csv_string_t, &test_var, "a,[b,c],d");
    assert_int_equal(amxc_var_type_of(&test_var), AMXC_VAR_ID_CSV_STRING);
    assert_int_equal(amxc_var_cast(&test_var, AMXC_VAR_ID_LIST), 0);
    amxc_var_dump(&test_var, STDOUT_FILENO);
    assert_int_equal(amxc_var_type_of(&test_var), AMXC_VAR_ID_LIST);
    assert_string_equal(GETI_CHAR(&test_var, 0), "a");
    assert_int_equal(amxc_var_type_of(GETI_ARG(&test_var, 1)), AMXC_VAR_ID_LIST);
    assert_string_equal(GETP_CHAR(&test_var, "1.0"), "b");
    assert_string_equal(GETP_CHAR(&test_var, "1.1"), "c");
    assert_string_equal(GETI_CHAR(&test_var, 2), "d");

    amxc_var_clean(&test_var);
}