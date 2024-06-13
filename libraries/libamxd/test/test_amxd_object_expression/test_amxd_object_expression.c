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
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <cmocka.h>
#include <unistd.h>
#include <signal.h>
#include <sys/signalfd.h>
#include <string.h>

#include <amxc/amxc.h>
#include <amxp/amxp_signal.h>
#include <amxp/amxp_slot.h>
#include <amxp/amxp_expression.h>

#include <amxd/amxd_common.h>
#include <amxd/amxd_dm.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_object_expression.h>

#include "test_amxd_object_expression.h"

#include <amxc/amxc_macros.h>
static amxd_dm_t dm;

static void test_build_dm(void) {
    amxd_object_t* object = NULL;
    amxd_object_t* instance = NULL;
    amxd_object_t* child_object = NULL;
    amxd_param_t* param = NULL;
    amxc_var_t data;
    amxc_var_t* str = NULL;
    amxc_var_t* nmbr = NULL;

    amxc_var_init(&data);
    amxc_var_set_type(&data, AMXC_VAR_ID_HTABLE);
    str = amxc_var_add_key(cstring_t, &data, "Param1", "TestData");
    amxc_var_add_key(bool, &data, "Param2", true);
    nmbr = amxc_var_add_key(uint32_t, &data, "Param3", 666);

    assert_int_equal(amxd_dm_init(&dm), 0);

    assert_int_equal(amxd_object_new(&object, amxd_object_singleton, "MyObject"), 0);
    assert_int_equal(amxd_dm_add_root_object(&dm, object), 0);

    assert_int_equal(amxd_object_new(&child_object, amxd_object_singleton, "ChildObject1"), 0);
    assert_int_equal(amxd_object_add_object(object, child_object), 0);

    assert_int_equal(amxd_param_new(&param, "Param1", AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(amxd_object_add_param(child_object, param), 0);
    assert_int_equal(amxd_param_new(&param, "Param2", AMXC_VAR_ID_BOOL), 0);
    assert_int_equal(amxd_object_add_param(child_object, param), 0);
    assert_int_equal(amxd_param_new(&param, "Param3", AMXC_VAR_ID_UINT32), 0);
    assert_int_equal(amxd_object_add_param(child_object, param), 0);
    assert_int_equal(amxd_object_set_params(child_object, &data), 0);

    assert_int_equal(amxd_object_new(&child_object, amxd_object_template, "ChildObject2"), 0);
    assert_int_equal(amxd_object_add_object(object, child_object), 0);

    assert_int_equal(amxd_param_new(&param, "Param1", AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(amxd_object_add_param(child_object, param), 0);
    assert_int_equal(amxd_param_new(&param, "Param2", AMXC_VAR_ID_BOOL), 0);
    assert_int_equal(amxd_object_add_param(child_object, param), 0);
    assert_int_equal(amxd_param_new(&param, "Param3", AMXC_VAR_ID_UINT32), 0);
    assert_int_equal(amxd_object_add_param(child_object, param), 0);

    assert_int_equal(amxd_object_new_instance(&instance, child_object, NULL, 0, NULL), 0);
    assert_int_equal(amxd_object_set_params(instance, &data), 0);

    assert_int_equal(amxd_object_new_instance(&instance, child_object, NULL, 0, NULL), 0);
    amxc_var_set(cstring_t, str, "Hello");
    amxc_var_set(uint32_t, nmbr, 1234);
    assert_int_equal(amxd_object_set_params(instance, &data), 0);

    assert_int_equal(amxd_object_new_instance(&instance, child_object, NULL, 0, NULL), 0);
    amxc_var_set(cstring_t, str, "World");
    amxc_var_set(uint32_t, nmbr, 2020);
    assert_int_equal(amxd_object_set_params(instance, &data), 0);

    assert_int_equal(amxd_object_new_instance(&instance, child_object, NULL, 0, NULL), 0);
    amxc_var_set(cstring_t, str, "Hello");
    amxc_var_set(uint32_t, nmbr, 2020);
    assert_int_equal(amxd_object_set_params(instance, &data), 0);

    amxc_var_clean(&data);
}

int test_object_expression_setup(UNUSED void** state) {
    test_build_dm();
    return 0;
}

int test_object_expression_teardown(UNUSED void** state) {
    amxd_dm_clean(&dm);

    return 0;
}

void test_can_match_object_with_expression(UNUSED void** state) {
    amxd_object_t* object = NULL;
    amxp_expr_t expression;

    assert_int_equal(amxp_expr_init(&expression, "Param1==\"TestData\" && Param3 == 666"), 0);
    object = amxd_dm_findf(&dm, "MyObject.ChildObject1");
    assert_true(amxd_object_matches_expr(object, &expression));

    object = amxd_dm_findf(&dm, "MyObject.ChildObject2.1");
    assert_true(amxd_object_matches_expr(object, &expression));

    object = amxd_dm_findf(&dm, "MyObject.ChildObject2.2");
    assert_false(amxd_object_matches_expr(object, &expression));

    object = amxd_dm_findf(&dm, "MyObject.ChildObject2.3");
    assert_false(amxd_object_matches_expr(object, &expression));

    amxp_expr_clean(&expression);
}

void test_expression_fields_are_retrieved_in_hierarchy(UNUSED void** state) {
    amxd_object_t* object = NULL;
    amxp_expr_t expression;

    object = amxd_dm_findf(&dm, "MyObject");

    assert_int_equal(amxp_expr_init(&expression, "ChildObject1.Param1==\"TestData\" && ChildObject1.Param3 == 666"), 0);
    assert_true(amxd_object_matches_expr(object, &expression));
    amxp_expr_clean(&expression);

    assert_int_equal(amxp_expr_init(&expression, "ChildObject2.1.Param9==\"TestData\" && ChildObject2.1.Param3 == 666"), 0);
    assert_false(amxd_object_matches_expr(object, &expression));
    amxp_expr_clean(&expression);

    assert_int_equal(amxp_expr_init(&expression, "ChildObject2.1.Param1==\"TestData\" && ChildObject2.1.Param3 == 666"), 0);
    object = amxd_dm_findf(&dm, "MyObject.ChildObject2");
    assert_false(amxd_object_matches_expr(object, &expression));
    amxp_expr_clean(&expression);
}

void test_expression_has_matching_instances(UNUSED void** state) {
    amxd_object_t* object = NULL;
    amxp_expr_t expression;

    object = amxd_dm_findf(&dm, "MyObject.ChildObject2");

    assert_int_equal(amxp_expr_init(&expression, "Param1==\"Hello\" && Param3 > 1000"), 0);
    assert_true(amxd_object_has_matching_instances(object, &expression));
    amxp_expr_clean(&expression);
}

void test_api_does_input_arg_validation(UNUSED void** state) {
    amxd_object_t* object = NULL;
    amxp_expr_t expression;
    amxp_expr_t* expr = NULL;
    amxc_var_t data;

    amxc_var_init(&data);

    object = amxd_dm_findf(&dm, "MyObject.ChildObject2");
    assert_int_equal(amxp_expr_init(&expression, "Param1==\"Hello\" && Param3 > 1000"), 0);

    assert_false(amxd_object_matches_expr(object, NULL));
    assert_false(amxd_object_matches_expr(NULL, &expression));

    assert_false(amxd_object_has_matching_instances(object, NULL));
    assert_false(amxd_object_has_matching_instances(NULL, &expression));
    object = amxd_dm_findf(&dm, "MyObject.ChildObject1");
    assert_false(amxd_object_has_matching_instances(object, &expression));

    object = amxd_dm_findf(&dm, "MyObject.ChildObject2");
    assert_int_not_equal(amxd_object_new_key_expr(object, NULL, NULL), 0);
    assert_int_not_equal(amxd_object_new_key_expr(object, NULL, &data), 0);
    assert_int_not_equal(amxd_object_new_key_expr(object, &expr, &data), 0);
    assert_ptr_equal(expr, NULL);

    amxc_var_set_type(&data, AMXC_VAR_ID_HTABLE);
    assert_int_not_equal(amxd_object_new_key_expr(NULL, &expr, &data), 0);
    assert_ptr_equal(expr, NULL);
    object = amxd_dm_findf(&dm, "MyObject.ChildObject1");
    assert_int_not_equal(amxd_object_new_key_expr(object, &expr, &data), 0);
    assert_ptr_equal(expr, NULL);

    amxp_expr_clean(&expression);
    amxc_var_clean(&data);
}

void test_can_iterator_over_all_matching_instances(UNUSED void** state) {
    amxd_object_t* object = NULL;
    amxd_object_t* instance = NULL;
    amxp_expr_t expression;

    assert_int_equal(amxp_expr_init(&expression, "Param1==\"Hello\""), 0);
    object = amxd_dm_findf(&dm, "MyObject.ChildObject2");

    instance = amxd_object_find_instance(object, &expression);
    assert_ptr_not_equal(instance, NULL);
    assert_int_equal(amxd_object_get_index(instance), 2);

    instance = amxd_object_find_next_instance(instance, &expression);
    assert_ptr_not_equal(instance, NULL);
    assert_int_equal(amxd_object_get_index(instance), 4);

    instance = amxd_object_find_next_instance(instance, &expression);
    assert_ptr_equal(instance, NULL);

    instance = amxd_object_find_next_instance(instance, &expression);
    assert_ptr_equal(instance, NULL);

    amxp_expr_clean(&expression);
}

void test_can_start_path_with_dot_in_expr(UNUSED void** state) {
    amxd_object_t* object = NULL;
    amxp_expr_t expression;

    assert_int_equal(amxp_expr_init(&expression, ".ChildObject2.3.Param3==2020"), 0);
    object = amxd_dm_findf(&dm, "MyObject");
    assert_true(amxd_object_matches_expr(object, &expression));
    amxp_expr_clean(&expression);

    assert_int_equal(amxp_expr_init(&expression, ".Param3==2020"), 0);
    assert_false(amxd_object_matches_expr(object, &expression));

    object = amxd_dm_findf(&dm, "MyObject.ChildObject2.3");
    assert_true(amxd_object_matches_expr(object, &expression));

    object = amxd_dm_findf(&dm, "MyObject.ChildObject2");
    assert_ptr_not_equal(amxd_object_find_instance(object, &expression), NULL);

    amxp_expr_clean(&expression);
}