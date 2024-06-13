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

#include <amxc/amxc.h>
#include <amxp/amxp_signal.h>
#include <amxp/amxp_slot.h>

#include <amxd/amxd_common.h>
#include <amxd/amxd_dm.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_parameter.h>
#include <amxd/amxd_function.h>
#include <amxd/amxd_action.h>

#include "test_amxd_object_action.h"

#include <amxc/amxc_macros.h>
static amxd_dm_t dm;

static amxd_action_t expected_reason;
static void* expected_priv;
static amxd_object_t* expected_obj;
static amxd_status_t status;

static uint32_t called = 0;

static amxd_status_t amxd_action_dummy_cb(UNUSED amxd_object_t* const object,
                                          UNUSED amxd_param_t* const param,
                                          UNUSED amxd_action_t reason,
                                          UNUSED const amxc_var_t* const args,
                                          UNUSED amxc_var_t* const retval,
                                          UNUSED void* priv) {
    return amxd_status_unknown_error;
}

static amxd_status_t amxd_action_object_test_cb(amxd_object_t* const object,
                                                amxd_param_t* const param,
                                                amxd_action_t reason,
                                                UNUSED const amxc_var_t* const args,
                                                amxc_var_t* const retval,
                                                void* priv) {
    amxc_var_t* value = NULL;

    assert_ptr_equal(object, expected_obj);
    assert_ptr_equal(param, NULL);
    assert_int_equal(reason, expected_reason);
    assert_ptr_equal(priv, expected_priv);

    if(status == amxd_status_ok) {
        amxc_var_set_type(retval, AMXC_VAR_ID_HTABLE);
        value = amxc_var_add_new_key(retval, "TestParam");
        amxc_var_set(cstring_t, value, "Test Data");
    } else {
        amxc_var_clean(retval);
    }

    called++;
    return status;
}

static amxd_object_t* test_build_dm(void) {
    amxd_object_t* object = NULL;
    amxd_object_t* template = NULL;
    amxd_param_t* param = NULL;

    assert_int_equal(amxd_dm_init(&dm), 0);

    assert_int_equal(amxd_object_new(&template, amxd_object_template, "parent"), 0);
    assert_int_equal(amxd_dm_add_root_object(&dm, template), 0);
    assert_int_equal(amxd_object_new(&object, amxd_object_singleton, "child"), 0);
    assert_int_equal(amxd_object_add_object(template, object), 0);

    assert_int_equal(amxd_param_new(&param, "templ_param", AMXC_VAR_ID_CSTRING), 0);
    amxd_param_set_attr(param, amxd_pattr_template, true);
    assert_int_equal(amxd_object_add_param(template, param), 0);
    assert_int_equal(amxd_param_new(&param, "inst_param", AMXC_VAR_ID_BOOL), 0);
    assert_int_equal(amxd_object_add_param(template, param), 0);
    assert_int_equal(amxd_param_new(&param, "param", AMXC_VAR_ID_UINT32), 0);
    amxd_param_set_attr(param, amxd_pattr_template, true);
    amxd_param_set_attr(param, amxd_pattr_instance, true);
    assert_int_equal(amxd_object_add_param(template, param), 0);

    assert_int_equal(amxd_param_new(&param, "child_param", AMXC_VAR_ID_CSTRING), 0);
    amxd_param_set_attr(param, amxd_pattr_private, true);
    assert_int_equal(amxd_object_add_param(object, param), 0);
    assert_int_equal(amxd_param_new(&param, "child_param2", AMXC_VAR_ID_BOOL), 0);
    assert_int_equal(amxd_object_add_param(object, param), 0);
    assert_int_equal(amxd_param_new(&param, "child_param3", AMXC_VAR_ID_UINT64), 0);
    assert_int_equal(amxd_object_add_param(object, param), 0);

    return template;
}

void test_amxd_object_add_action_cb(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxd_object_t* object = NULL;
    amxd_object_t* instance = NULL;
    amxc_var_t value;

    amxc_var_init(&value);
    template = test_build_dm();
    object = amxd_object_get_child(template, "child");
    assert_int_equal(amxd_object_new_instance(&instance, template, NULL, 0, NULL), 0);
    assert_int_equal(amxd_object_add_action_cb(template, action_object_list, amxd_action_object_test_cb, NULL), 0);
    assert_int_equal(amxd_object_add_action_cb(template, action_object_read, amxd_action_object_test_cb, NULL), 0);
    assert_int_equal(amxd_object_add_action_cb(template, action_object_list, amxd_action_dummy_cb, NULL), 0);
    assert_int_equal(amxd_object_add_action_cb(object, action_object_read, amxd_action_object_test_cb, NULL), 0);

    expected_reason = action_object_read;
    expected_priv = NULL;
    status = amxd_status_ok;
    called = 0;

    expected_obj = template;
    assert_int_equal(amxd_object_get_param(template, "TestParam", &value), status);
    assert_int_equal(amxc_var_type_of(&value), AMXC_VAR_ID_CSTRING);
    assert_string_equal(amxc_var_constcast(cstring_t, &value), "Test Data");

    expected_obj = object;
    assert_int_equal(amxd_object_get_param(object, "TestParam", &value), status);
    assert_int_equal(amxc_var_type_of(&value), AMXC_VAR_ID_CSTRING);
    assert_string_equal(amxc_var_constcast(cstring_t, &value), "Test Data");

    expected_obj = template;
    status = amxd_status_parameter_not_found;
    assert_int_equal(amxd_object_get_param(template, "TestParam", &value), status);

    assert_int_equal(called, 3);

    amxc_var_clean(&value);
    amxd_dm_clean(&dm);
}

void test_amxd_object_add_action_cb_invalid_args(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxd_object_t* instance = NULL;
    amxc_var_t value;

    amxc_var_init(&value);
    template = test_build_dm();
    assert_int_equal(amxd_object_new_instance(&instance, template, NULL, 0, NULL), 0);
    assert_int_not_equal(amxd_object_add_action_cb(NULL, action_object_read, amxd_action_object_test_cb, NULL), 0);
    assert_int_not_equal(amxd_object_add_action_cb(template, action_object_read, NULL, NULL), 0);
    assert_int_equal(amxd_object_add_action_cb(template, action_object_read, amxd_action_object_test_cb, NULL), 0);
    assert_int_not_equal(amxd_object_add_action_cb(template, action_object_read, amxd_action_object_test_cb, NULL), 0);

    amxc_var_clean(&value);
    amxd_dm_clean(&dm);
}

void test_amxd_object_remove_action_cb(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxd_object_t* object = NULL;
    amxd_object_t* instance = NULL;
    amxc_var_t value;

    amxc_var_init(&value);
    template = test_build_dm();
    object = amxd_object_get_child(template, "child");
    assert_int_equal(amxd_object_new_instance(&instance, template, NULL, 0, NULL), 0);
    assert_int_equal(amxd_object_add_action_cb(template, action_object_list, amxd_action_object_test_cb, NULL), 0);
    assert_int_equal(amxd_object_add_action_cb(template, action_object_read, amxd_action_object_test_cb, NULL), 0);
    assert_int_equal(amxd_object_add_action_cb(template, action_object_list, amxd_action_dummy_cb, NULL), 0);
    assert_int_equal(amxd_object_add_action_cb(object, action_object_read, amxd_action_object_test_cb, NULL), 0);

    expected_reason = action_object_read;
    expected_priv = NULL;
    status = amxd_status_ok;
    called = 0;

    expected_obj = template;
    assert_int_equal(amxd_object_get_param(template, "TestParam", &value), status);
    assert_int_equal(amxc_var_type_of(&value), AMXC_VAR_ID_CSTRING);
    assert_string_equal(amxc_var_constcast(cstring_t, &value), "Test Data");

    assert_int_equal(amxd_object_remove_action_cb(template, action_object_read, amxd_action_object_test_cb), 0);
    assert_int_equal(amxd_object_remove_action_cb(template, action_object_list, amxd_action_object_test_cb), 0);
    assert_int_not_equal(amxd_object_get_param(template, "TestParam", &value), 0);

    assert_int_equal(called, 1);

    amxc_var_clean(&value);
    amxd_dm_clean(&dm);
}

void test_amxd_object_remove_action_cb_invalid_args(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxd_object_t* object = NULL;
    amxd_object_t* instance = NULL;
    amxc_var_t value;

    amxc_var_init(&value);
    template = test_build_dm();
    object = amxd_object_get_child(template, "child");
    assert_int_equal(amxd_object_new_instance(&instance, template, NULL, 0, NULL), 0);
    assert_int_equal(amxd_object_add_action_cb(template, action_object_list, amxd_action_object_test_cb, NULL), 0);
    assert_int_equal(amxd_object_add_action_cb(template, action_object_read, amxd_action_object_test_cb, NULL), 0);
    assert_int_equal(amxd_object_add_action_cb(template, action_object_list, amxd_action_dummy_cb, NULL), 0);
    assert_int_equal(amxd_object_add_action_cb(object, action_object_read, amxd_action_object_test_cb, NULL), 0);

    assert_int_not_equal(amxd_object_remove_action_cb(NULL, action_object_read, amxd_action_object_test_cb), 0);
    assert_int_not_equal(amxd_object_remove_action_cb(template, action_object_read, NULL), 0);
    assert_int_equal(amxd_object_remove_action_cb(template, action_object_list, amxd_action_object_test_cb), 0);
    assert_int_not_equal(amxd_object_remove_action_cb(template, action_object_list, amxd_action_object_test_cb), 0);

    amxc_var_clean(&value);
    amxd_dm_clean(&dm);
}

void test_amxd_object_disable_action_cb(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxd_object_t* object = NULL;
    amxd_object_t* instance = NULL;
    amxc_var_t value;

    amxc_var_init(&value);
    template = test_build_dm();
    object = amxd_object_get_child(template, "child");
    assert_int_equal(amxd_object_new_instance(&instance, template, NULL, 0, NULL), 0);
    assert_int_equal(amxd_object_add_action_cb(template, action_object_list, amxd_action_object_test_cb, NULL), 0);
    assert_int_equal(amxd_object_add_action_cb(template, action_object_read, amxd_action_object_test_cb, NULL), 0);
    assert_int_equal(amxd_object_add_action_cb(template, action_object_list, amxd_action_dummy_cb, NULL), 0);
    assert_int_equal(amxd_object_add_action_cb(object, action_object_read, amxd_action_object_test_cb, NULL), 0);

    expected_reason = action_object_read;
    expected_priv = NULL;
    status = amxd_status_ok;
    called = 0;

    expected_obj = template;
    assert_int_equal(amxd_object_get_param(template, "TestParam", &value), status);
    assert_int_equal(amxc_var_type_of(&value), AMXC_VAR_ID_CSTRING);
    assert_string_equal(amxc_var_constcast(cstring_t, &value), "Test Data");

    amxd_object_enable_action_cb(template, action_object_read, amxd_action_object_test_cb, false);
    amxd_object_enable_action_cb(template, action_object_list, amxd_action_object_test_cb, false);
    assert_int_not_equal(amxd_object_get_param(template, "TestParam", &value), 0);

    assert_int_equal(called, 1);

    amxc_var_clean(&value);
    amxd_dm_clean(&dm);
}

void test_amxd_object_action_cb_data(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxc_var_t* data = NULL;

    amxc_var_new(&data);
    template = test_build_dm();
    assert_int_equal(amxd_object_add_action_cb(template, action_object_list, amxd_action_object_test_cb, NULL), 0);

    amxd_object_set_action_cb_data(template, action_object_list, amxd_action_object_test_cb, data);
    amxd_object_set_action_cb_data(NULL, action_object_list, amxd_action_object_test_cb, data);
    amxd_object_set_action_cb_data(template, action_object_read, NULL, data);
    amxd_object_set_action_cb_data(template, action_object_read, amxd_action_object_test_cb, data);

    amxc_var_delete(&data);
    amxd_dm_clean(&dm);
}
