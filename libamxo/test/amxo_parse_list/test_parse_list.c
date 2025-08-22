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

#include "test_parse_list.h"
#include "../common/testutil.h"

#include <stdarg.h> // needed for cmocka
#include <setjmp.h> // needed for cmocka
#include <unistd.h> // needed for cmocka
#include <cmocka.h>

#include <amxc/amxc.h>
#include <amxo/amxo.h>
#include <amxc/amxc_macros.h>

void test_parse_list(UNUSED void** state) {
    amxc_var_t var;
    amxc_var_t* sub_var = NULL;
    amxc_var_t* sub_sub_var = NULL;

    // Variant: [ "foo", "bar" ]
    amxc_var_init(&var);
    amxc_var_set_type(&var, AMXC_VAR_ID_LIST);
    amxc_var_add(cstring_t, &var, "foo");
    amxc_var_add(cstring_t, &var, "bar");
    amxo_testutil_assert_odl_config_string_sets(
        "\%config { mylist = [ \"foo\", \"bar\" ];}",
        "mylist",
        &var);
    amxc_var_clean(&var);

    // Variant: [ 1, 2, 3, 4, 5 ]
    amxc_var_init(&var);
    amxc_var_set_type(&var, AMXC_VAR_ID_LIST);
    amxc_var_add(int64_t, &var, 1);
    amxc_var_add(int64_t, &var, 2);
    amxc_var_add(int64_t, &var, 3);
    amxc_var_add(int64_t, &var, 4);
    amxc_var_add(int64_t, &var, 5);
    amxo_testutil_assert_odl_config_string_sets(
        "\%config { mylist = [ 1, 2, 3, 4, 5 ];}",
        "mylist",
        &var);
    amxc_var_clean(&var);

    // Variant: [ ]
    amxc_var_init(&var);
    amxc_var_set_type(&var, AMXC_VAR_ID_LIST);
    amxo_testutil_assert_odl_config_string_sets(
        "\%config { mylist = [  ];}",
        "mylist",
        &var);
    amxo_testutil_assert_odl_config_string_sets(
        "\%config { mylist = [];}",
        "mylist",
        &var);
    amxc_var_clean(&var);

    // Variant: [ [] ]
    amxc_var_init(&var);
    amxc_var_set_type(&var, AMXC_VAR_ID_LIST);
    sub_var = amxc_var_add_new(&var);
    amxc_var_set_type(sub_var, AMXC_VAR_ID_LIST);
    amxo_testutil_assert_odl_config_string_sets(
        "\%config { mylist = [ [] ];}",
        "mylist",
        &var);
    amxc_var_clean(&var);

    // Variant: [ "test" ]
    amxc_var_init(&var);
    amxc_var_set_type(&var, AMXC_VAR_ID_LIST);
    amxc_var_add(cstring_t, &var, "test");
    amxo_testutil_assert_odl_config_string_sets(
        "\%config { mylist = [ \"test\" ];}",
        "mylist",
        &var);
    amxc_var_clean(&var);

    // Variant: [ [ "test" ] ]
    amxc_var_init(&var);
    amxc_var_set_type(&var, AMXC_VAR_ID_LIST);
    sub_var = amxc_var_add_new(&var);
    amxc_var_set_type(sub_var, AMXC_VAR_ID_LIST);
    amxc_var_add(cstring_t, sub_var, "test");
    amxo_testutil_assert_odl_config_string_sets(
        "\%config { mylist = [ [ \"test\" ] ];}",
        "mylist",
        &var);
    amxc_var_clean(&var);

    // Variant: [ [ [ "hello"] , 1 ], [ true ]]
    amxc_var_init(&var);
    amxc_var_set_type(&var, AMXC_VAR_ID_LIST);
    sub_var = amxc_var_add_new(&var);
    amxc_var_set_type(sub_var, AMXC_VAR_ID_LIST);
    sub_sub_var = amxc_var_add_new(sub_var);
    amxc_var_set_type(sub_sub_var, AMXC_VAR_ID_LIST);
    amxc_var_add(cstring_t, sub_sub_var, "hello");
    amxc_var_add(int64_t, sub_var, 1);
    sub_var = amxc_var_add_new(&var);
    amxc_var_set_type(sub_var, AMXC_VAR_ID_LIST);
    amxc_var_add(bool, sub_var, true);
    amxo_testutil_assert_odl_config_string_sets(
        "\%config { mylist = [ [ \"hello\" ,1 ], [true ]];}",
        "mylist",
        &var);
    amxc_var_clean(&var);
}

void test_parse_list_parse_errors(UNUSED void** state) {
    amxo_testutil_assert_odl_error_string("\%config { mylist = [;}");
    amxo_testutil_assert_odl_error_string("\%config { mylist = [}");
    amxo_testutil_assert_odl_error_string("\%config { mylist = [");
    amxo_testutil_assert_odl_error_string("\%config { mylist = ];}");
    amxo_testutil_assert_odl_error_string("\%config { mylist = [\"hello];}");
    amxo_testutil_assert_odl_error_string("\%config { mylist = ]\"thinking outside the box\"[;}");
}