/****************************************************************************
**
** SPDX-License-Identifier: BSD-2-Clause-Patent
**
** SPDX-FileCopyrightText: Copyright (c) 2024 SoftAtHome
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
#include <sys/types.h>
#include <sys/stat.h>

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

#include <amxc/amxc.h>
#include <amxp/amxp_signal.h>
#include <amxd/amxd_dm.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_parameter.h>
#include <amxo/amxo.h>
#include <amxo/amxo_hooks.h>

#include "test_plusequals.h"
#include "../common/testutil.h"

#include <amxc/amxc_macros.h>

static void s_testhelper_plusequals(const char* odl_filename, const char* config_var_name, const amxc_var_t* expected_value) {
    amxd_dm_t dm;
    amxo_parser_t parser;
    amxc_var_t* actual_value = NULL;
    amxd_dm_init(&dm);
    amxo_parser_init(&parser);

    amxo_testutil_load_odl_file(&parser, &dm, odl_filename);

    actual_value = amxo_parser_get_config(&parser, config_var_name);

    amxo_testutil_assert_var_equal(actual_value, expected_value);

    amxo_parser_clean(&parser);
    amxd_dm_clean(&dm);
}

void test_plusequals_normalcase(UNUSED void** state) {
    amxc_var_t expected_value;

    amxc_var_init(&expected_value);
    amxc_var_set_type(&expected_value, AMXC_VAR_ID_LIST);
    amxc_var_add(cstring_t, &expected_value, "foo");
    amxc_var_add(cstring_t, &expected_value, "bar");
    s_testhelper_plusequals("testodl_normalcase.odl", "mylist", &expected_value);

    amxc_var_clean(&expected_value);
}

void test_plusequals_include(UNUSED void** state) {
    amxc_var_t expected_value;

    // Variant containing: ["monday", "tuesday", "wednesday", "thursday"]
    amxc_var_init(&expected_value);
    amxc_var_set_type(&expected_value, AMXC_VAR_ID_LIST);
    amxc_var_add(cstring_t, &expected_value, "monday");
    amxc_var_add(cstring_t, &expected_value, "tuesday");
    amxc_var_add(cstring_t, &expected_value, "wednesday");
    amxc_var_add(cstring_t, &expected_value, "thursday");

    s_testhelper_plusequals("testodl_include.odl", "mylist", &expected_value);

    amxc_var_clean(&expected_value);
}

void test_plusequals_various_types(UNUSED void** state) {
    amxc_var_t expected_list;
    amxc_var_t expected_int;
    amxc_var_t expected_string;
    amxc_var_t* sublist1;
    amxc_var_t* sublist2;

    // variant containing: [ ["sub", "list"], ["different", "sublist"], "2", "hello", true ]
    amxc_var_init(&expected_list);
    amxc_var_set_type(&expected_list, AMXC_VAR_ID_LIST);
    sublist1 = amxc_var_add_new(&expected_list);
    amxc_var_set_type(sublist1, AMXC_VAR_ID_LIST);
    amxc_var_add(cstring_t, sublist1, "sub");
    amxc_var_add(cstring_t, sublist1, "list");
    sublist2 = amxc_var_add_new(&expected_list);
    amxc_var_set_type(sublist2, AMXC_VAR_ID_LIST);
    amxc_var_add(cstring_t, sublist2, "different");
    amxc_var_add(cstring_t, sublist2, "sublist");
    amxc_var_add(int64_t, &expected_list, 2);
    amxc_var_add(cstring_t, &expected_list, "hello");
    amxc_var_add(bool, &expected_list, true);

    // variant containing: 9001
    amxc_var_init(&expected_int);
    amxc_var_set(int64_t, &expected_int, 9001);

    // variant containing: "hello world"
    amxc_var_init(&expected_string);
    amxc_var_set(cstring_t, &expected_string, "hello world");

    s_testhelper_plusequals("testodl_various_types.odl", "mylist", &expected_list);

    s_testhelper_plusequals("testodl_various_types.odl", "myint", &expected_int);

    s_testhelper_plusequals("testodl_various_types.odl", "mystring", &expected_string);

    amxc_var_clean(&expected_list);
    amxc_var_clean(&expected_string);
    amxc_var_clean(&expected_int);
}

void test_plusequals_conversion_error(UNUSED void** state) {
    // "something" cannot be converted to an integer, so this must fail:
    amxo_testutil_assert_odl_error_string(
        "\%config { myvar = 17; }"
        "\%config { myvar += \"something\";}");
}

void test_plusequals_conversion(UNUSED void** state) {
    amxc_var_t expected_int;
    amxc_var_t expected_string;

    amxc_var_init(&expected_int);
    amxc_var_init(&expected_string);
    amxc_var_set_type(&expected_int, AMXC_VAR_ID_INT32);
    amxc_var_set_type(&expected_string, AMXC_VAR_ID_CSTRING);
    amxc_var_set(cstring_t, &expected_string, "hello123");
    amxc_var_set(int32_t, &expected_int, 124);
    s_testhelper_plusequals("testodl_conversion.odl", "myint", &expected_int);
    s_testhelper_plusequals("testodl_conversion.odl", "mystring", &expected_string);

    amxc_var_clean(&expected_int);
    amxc_var_clean(&expected_string);
}

void test_plusequals_on_unsupported_type(UNUSED void** state) {
    amxo_testutil_assert_odl_error_string(
        "\%config { myvar = true; }"
        "\%config { myvar += false;}");
}

void test_plusequals_on_not_defined_before(UNUSED void** state) {
    amxc_var_t expected_string;
    amxc_var_t expected_bool_false;
    amxc_var_t expected_bool_true;

    amxc_var_init(&expected_string);
    amxc_var_set(cstring_t, &expected_string, "adding to something not defined before");
    amxc_var_init(&expected_bool_false);
    amxc_var_set(bool, &expected_bool_false, false);
    amxc_var_init(&expected_bool_true);
    amxc_var_set(bool, &expected_bool_true, true);

    s_testhelper_plusequals("testodl_add_to_undefined.odl", "mystring", &expected_string);
    s_testhelper_plusequals("testodl_add_to_undefined.odl", "mybool_true", &expected_bool_true);
    s_testhelper_plusequals("testodl_add_to_undefined.odl", "mybool_false", &expected_bool_false);

    amxc_var_clean(&expected_string);
    amxc_var_clean(&expected_bool_true);
    amxc_var_clean(&expected_bool_false);
}
