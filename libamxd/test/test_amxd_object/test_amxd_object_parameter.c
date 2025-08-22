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

#include <amxd/amxd_dm.h>
#include <amxd/amxd_action.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_parameter.h>

#include "test_amxd_object.h"

#include <amxc/amxc_macros.h>
static amxd_dm_t dm;

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

void test_amxd_object_add_parameter(UNUSED void** state) {
    amxd_object_t* object = NULL;
    amxd_object_t* templ = NULL;
    amxd_param_t* param = NULL;
    assert_int_equal(amxd_dm_init(&dm), 0);

    assert_int_equal(amxd_object_new(&object, amxd_object_singleton, "parent"), 0);
    assert_int_equal(amxd_dm_add_root_object(&dm, object), 0);

    assert_int_equal(amxd_object_new(&templ, amxd_object_template, "templ"), 0);
    assert_int_equal(amxd_dm_add_root_object(&dm, templ), 0);

    assert_int_equal(amxd_param_new(&param, "test_param", AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(amxd_object_add_param(object, param), 0);

    assert_int_equal(amxd_param_new(&param, "test_param", AMXC_VAR_ID_CSTRING), 0);
    assert_int_not_equal(amxd_object_add_param(object, param), 0);
    amxd_param_delete(&param);

    assert_int_equal(amxd_param_new(&param, "test_param2", AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(amxd_object_add_param(object, param), 0);

    assert_int_equal(amxd_object_set_attr(object, amxd_oattr_locked, true), 0);
    assert_int_equal(amxd_param_new(&param, "test_param3", AMXC_VAR_ID_CSTRING), 0);
    assert_int_not_equal(amxd_object_add_param(object, param), 0);
    amxd_param_delete(&param);

    assert_int_equal(amxd_param_new(&param, "templ_param1", AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(amxd_object_add_param(templ, param), 0);
    assert_int_equal(amxd_param_new(&param, "templ_param2", AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(amxd_param_set_attr(param, amxd_pattr_template, true), 0);
    assert_int_equal(amxd_object_add_param(templ, param), 0);
    assert_int_equal(amxd_param_new(&param, "templ_param3", AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(amxd_param_set_attr(param, amxd_pattr_instance, true), 0);
    assert_int_equal(amxd_object_add_param(templ, param), 0);
    assert_int_equal(amxd_param_new(&param, "templ_param4", AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(amxd_param_set_attr(param, amxd_pattr_instance, true), 0);
    assert_int_equal(amxd_param_set_attr(param, amxd_pattr_template, true), 0);
    assert_int_equal(amxd_object_add_param(templ, param), 0);

    amxd_dm_clean(&dm);
}

void test_amxd_object_add_param_invalid_arg(UNUSED void** state) {
    amxd_object_t* object = NULL;
    amxd_param_t* param = NULL;
    assert_int_equal(amxd_dm_init(&dm), 0);

    assert_int_equal(amxd_object_new(&object, amxd_object_singleton, "parent"), 0);
    assert_int_equal(amxd_dm_add_root_object(&dm, object), 0);

    assert_int_equal(amxd_param_new(&param, "test_func", AMXC_VAR_ID_CSTRING), 0);
    assert_int_not_equal(amxd_object_add_param(NULL, param), 0);
    assert_int_not_equal(amxd_object_add_param(object, NULL), 0);
    assert_int_equal(amxd_object_add_param(object, param), 0);
    assert_int_not_equal(amxd_object_add_param(object, param), 0);

    amxd_dm_clean(&dm);
}

void test_amxd_object_get_parameter(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxd_object_t* object = NULL;
    amxd_object_t* instance = NULL;
    amxd_object_t* instance_object = NULL;

    amxd_param_t* param = NULL;
    assert_int_equal(amxd_dm_init(&dm), 0);

    assert_int_equal(amxd_object_new(&template, amxd_object_template, "parent"), 0);
    assert_int_equal(amxd_dm_add_root_object(&dm, template), 0);
    assert_int_equal(amxd_object_new(&object, amxd_object_singleton, "child"), 0);
    assert_int_equal(amxd_object_add_object(template, object), 0);
    assert_int_equal(amxd_param_new(&param, "templ_param_x", AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(amxd_object_add_param(template, param), 0);
    assert_int_equal(amxd_param_new(&param, "templ_param", AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(amxd_object_add_param(template, param), 0);
    assert_int_equal(amxd_param_new(&param, "child_param", AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(amxd_object_add_param(object, param), 0);

    assert_int_equal(amxd_object_new_instance(&instance, template, NULL, 0, NULL), 0);
    param = amxd_object_get_param_def(instance, "templ_param");
    assert_ptr_not_equal(param, NULL);
    assert_ptr_equal(amxd_param_get_owner(param), instance);

    assert_ptr_equal(amxd_object_get_param_value(instance, "templ_param"), &param->value);
    assert_null(amxd_object_get_param_value(instance, "NotExistingParam"));
    assert_null(amxd_object_get_param_value(NULL, "templ_param"));
    assert_null(amxd_object_get_param_value(instance, ""));
    assert_null(amxd_object_get_param_value(instance, NULL));
    assert_int_equal(amxd_param_new(&param, "new_param", AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(amxd_object_add_param(instance, param), 0);
    assert_non_null(amxd_object_get_param_value(instance, "new_param"));
    assert_true(param->attr.instance);
    assert_int_equal(amxd_param_new(&param, "new_templ_param", AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(amxd_param_set_attr(param, amxd_pattr_template, true), 0);
    assert_int_not_equal(amxd_object_add_param(instance, param), 0);
    assert_int_equal(amxd_param_set_attr(param, amxd_pattr_instance, true), 0);
    assert_int_equal(amxd_object_add_param(instance, param), 0);
    amxd_param_delete(&param);

    param = amxd_object_get_param_def(object, "child_param");
    assert_ptr_not_equal(param, NULL);
    assert_ptr_equal(amxd_param_get_owner(param), object);

    instance_object = amxd_object_get(instance, "child");
    assert_ptr_not_equal(instance_object, NULL);
    assert_ptr_equal(amxd_object_get_parent(instance_object), instance);
    assert_ptr_equal(instance_object->derived_from.llist, &object->derived_objects);
    assert_ptr_equal(instance_object->type, amxd_object_singleton);
    param = amxd_object_get_param_def(instance_object, "child_param");
    assert_ptr_not_equal(param, NULL);
    assert_ptr_equal(amxd_param_get_owner(param), instance_object);

    assert_ptr_equal(amxd_object_get_param_def(NULL, "child_param"), NULL);
    assert_ptr_equal(amxd_object_get_param_def(instance_object, ""), NULL);
    assert_ptr_equal(amxd_object_get_param_def(instance_object, NULL), NULL);
    assert_ptr_equal(amxd_object_get_param_def(amxd_dm_get_root(&dm), "Test"), NULL);

    amxd_dm_clean(&dm);
}

void test_amxd_object_get_parameter_value(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxd_object_t* object = NULL;
    amxd_object_t* instance = NULL;
    amxc_var_t value;

    amxc_var_init(&value);

    template = test_build_dm();
    object = amxd_object_get_child(template, "child");

    assert_int_equal(amxd_object_get_param(template, "templ_param", &value), 0);
    assert_int_equal(amxc_var_type_of(&value), AMXC_VAR_ID_CSTRING);
    assert_int_equal(amxd_object_get_param(template, "inst_param", &value), 0);
    assert_int_equal(amxd_object_get_param(template, "param", &value), 0);
    assert_int_equal(amxc_var_type_of(&value), AMXC_VAR_ID_UINT32);

    assert_int_equal(amxd_object_new_instance(&instance, template, NULL, 0, NULL), 0);
    assert_int_not_equal(amxd_object_get_param(instance, "templ_param", &value), 0);
    assert_int_equal(amxd_object_get_param(instance, "inst_param", &value), 0);
    assert_int_equal(amxc_var_type_of(&value), AMXC_VAR_ID_BOOL);
    assert_int_equal(amxd_object_get_param(instance, "param", &value), 0);
    assert_int_equal(amxc_var_type_of(&value), AMXC_VAR_ID_UINT32);

    assert_int_equal(amxd_object_get_param(object, "child_param", &value), 0);
    assert_int_equal(amxc_var_type_of(&value), AMXC_VAR_ID_CSTRING);
    assert_int_equal(amxd_object_get_param(object, "child_param2", &value), 0);
    assert_int_equal(amxc_var_type_of(&value), AMXC_VAR_ID_BOOL);
    assert_int_equal(amxd_object_get_param(object, "child_param3", &value), 0);
    assert_int_equal(amxc_var_type_of(&value), AMXC_VAR_ID_UINT64);

    object = amxd_object_get_child(instance, "child");
    assert_int_equal(amxd_object_get_param(object, "child_param", &value), 0);
    assert_int_equal(amxc_var_type_of(&value), AMXC_VAR_ID_CSTRING);
    assert_int_equal(amxd_object_get_param(object, "child_param2", &value), 0);
    assert_int_equal(amxc_var_type_of(&value), AMXC_VAR_ID_BOOL);
    assert_int_equal(amxd_object_get_param(object, "child_param3", &value), 0);
    assert_int_equal(amxc_var_type_of(&value), AMXC_VAR_ID_UINT64);

    assert_int_not_equal(amxd_object_get_param(object, "fake_news", &value), 0);
    assert_int_not_equal(amxd_object_get_param(object, NULL, &value), 0);
    assert_int_not_equal(amxd_object_get_param(object, "", &value), 0);
    assert_int_not_equal(amxd_object_get_param(object, "fake_news", NULL), 0);
    assert_int_not_equal(amxd_object_get_param(NULL, "fake_news", &value), 0);

    amxc_var_clean(&value);
    amxd_dm_clean(&dm);
}

void test_amxd_object_get_parameter_value_type(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxd_object_t* object = NULL;
    amxd_object_t* instance = NULL;
    amxd_status_t status = amxd_status_ok;
    char* str_val = NULL;
    uint32_t uint32_val = 0;
    uint64_t uint64_val = 0;
    int32_t int32_val = 0;
    int64_t int64_val = 0;
    bool bool_val = false;
    double double_val = 0;

    template = test_build_dm();
    assert_int_equal(amxd_object_new_instance(&instance, template, NULL, 0, NULL), 0);
    object = amxd_object_get_child(instance, "child");

    amxd_object_set_value(cstring_t, object, "child_param", "1234");
    str_val = amxd_object_get_value(cstring_t, object, "child_param", &status);
    assert_int_equal(status, 0);
    assert_ptr_not_equal(str_val, NULL);
    assert_string_equal(str_val, "1234");
    free(str_val);
    str_val = NULL;

    uint32_val = amxd_object_get_value(uint32_t, object, "child_param", &status);
    assert_int_equal(status, 0);
    assert_int_equal(uint32_val, 1234);
    uint64_val = amxd_object_get_value(uint64_t, object, "child_param", &status);
    assert_int_equal(status, 0);
    assert_int_equal(uint64_val, 1234);
    int32_val = amxd_object_get_value(int32_t, object, "child_param", &status);
    assert_int_equal(status, 0);
    assert_int_equal(int32_val, 1234);
    int64_val = amxd_object_get_value(int64_t, object, "child_param", &status);
    assert_int_equal(int64_val, 1234);
    assert_int_equal(status, 0);
    bool_val = amxd_object_get_value(bool, object, "child_param", &status);
    assert_int_equal(status, 0);
    assert_false(bool_val);
    double_val = amxd_object_get_value(double, object, "child_param", &status);
    assert_int_equal(status, 0);
    assert_true(double_val == 1234);

    uint32_val = amxd_object_get_value(uint32_t, object, "child_param", NULL);
    assert_int_equal(uint32_val, 1234);
    uint64_val = amxd_object_get_value(uint64_t, object, "child_param", NULL);
    assert_int_equal(uint64_val, 1234);
    int32_val = amxd_object_get_value(int32_t, object, "child_param", NULL);
    assert_int_equal(int32_val, 1234);
    int64_val = amxd_object_get_value(int64_t, object, "child_param", NULL);
    assert_int_equal(status, 0);
    bool_val = amxd_object_get_value(bool, object, "child_param", NULL);
    assert_false(bool_val);
    double_val = amxd_object_get_value(double, object, "child_param", NULL);
    assert_true(double_val == 1234);

    str_val = amxd_object_get_value(cstring_t, NULL, "child_param", &status);
    assert_int_not_equal(status, 0);
    uint32_val = amxd_object_get_value(uint32_t, NULL, "child_param", &status);
    assert_int_not_equal(status, 0);
    uint64_val = amxd_object_get_value(uint64_t, NULL, "child_param", &status);
    assert_int_not_equal(status, 0);
    int32_val = amxd_object_get_value(int32_t, NULL, "child_param", &status);
    assert_int_not_equal(status, 0);
    int64_val = amxd_object_get_value(int64_t, NULL, "child_param", &status);
    assert_int_not_equal(status, 0);
    bool_val = amxd_object_get_value(bool, NULL, "child_param", &status);
    assert_int_not_equal(status, 0);
    double_val = amxd_object_get_value(double, NULL, "child_param", &status);
    assert_int_not_equal(status, 0);

    str_val = amxd_object_get_value(cstring_t, object, NULL, &status);
    assert_int_not_equal(status, 0);
    uint32_val = amxd_object_get_value(uint32_t, object, NULL, &status);
    assert_int_not_equal(status, 0);
    uint64_val = amxd_object_get_value(uint64_t, object, NULL, &status);
    assert_int_not_equal(status, 0);
    int32_val = amxd_object_get_value(int32_t, object, NULL, &status);
    assert_int_not_equal(status, 0);
    int64_val = amxd_object_get_value(int64_t, object, NULL, &status);
    assert_int_not_equal(status, 0);
    bool_val = amxd_object_get_value(bool, object, NULL, &status);
    assert_int_not_equal(status, 0);
    double_val = amxd_object_get_value(double, object, NULL, &status);
    assert_int_not_equal(status, 0);

    amxd_dm_clean(&dm);
}

void test_amxd_object_get_parameter_value_with_cb(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxd_object_t* object = NULL;
    amxd_object_t* instance = NULL;
    amxc_var_t value;

    amxc_var_init(&value);

    template = test_build_dm();
    object = amxd_object_get_child(template, "child");
    assert_int_equal(amxd_object_add_action_cb(template, action_object_read, amxd_action_object_read, NULL), 0);
    assert_int_equal(amxd_object_add_action_cb(object, action_object_read, amxd_action_object_read, NULL), 0);

    assert_int_equal(amxd_object_get_param(template, "templ_param", &value), 0);
    assert_int_equal(amxc_var_type_of(&value), AMXC_VAR_ID_CSTRING);
    assert_int_equal(amxd_object_get_param(template, "inst_param", &value), 0);
    assert_int_equal(amxd_object_get_param(template, "param", &value), 0);
    assert_int_equal(amxc_var_type_of(&value), AMXC_VAR_ID_UINT32);

    assert_int_equal(amxd_object_new_instance(&instance, template, NULL, 0, NULL), 0);
    assert_int_not_equal(amxd_object_get_param(instance, "templ_param", &value), 0);
    assert_int_equal(amxd_object_get_param(instance, "inst_param", &value), 0);
    assert_int_equal(amxc_var_type_of(&value), AMXC_VAR_ID_BOOL);
    assert_int_equal(amxd_object_get_param(instance, "param", &value), 0);
    assert_int_equal(amxc_var_type_of(&value), AMXC_VAR_ID_UINT32);

    assert_int_equal(amxd_object_get_param(template, "templ_param", &value), 0);
    assert_int_equal(amxc_var_type_of(&value), AMXC_VAR_ID_CSTRING);
    assert_int_equal(amxd_object_get_param(template, "inst_param", &value), 0);
    assert_int_equal(amxd_object_get_param(template, "param", &value), 0);
    assert_int_equal(amxc_var_type_of(&value), AMXC_VAR_ID_UINT32);

    assert_int_equal(amxd_object_get_param(object, "child_param", &value), 0);
    assert_int_equal(amxc_var_type_of(&value), AMXC_VAR_ID_CSTRING);
    assert_int_equal(amxd_object_get_param(object, "child_param2", &value), 0);
    assert_int_equal(amxc_var_type_of(&value), AMXC_VAR_ID_BOOL);
    assert_int_equal(amxd_object_get_param(object, "child_param3", &value), 0);
    assert_int_equal(amxc_var_type_of(&value), AMXC_VAR_ID_UINT64);

    object = amxd_object_get_child(instance, "child");
    assert_int_equal(amxd_object_get_param(object, "child_param", &value), 0);
    assert_int_equal(amxc_var_type_of(&value), AMXC_VAR_ID_CSTRING);
    assert_int_equal(amxd_object_get_param(object, "child_param2", &value), 0);
    assert_int_equal(amxc_var_type_of(&value), AMXC_VAR_ID_BOOL);
    assert_int_equal(amxd_object_get_param(object, "child_param3", &value), 0);
    assert_int_equal(amxc_var_type_of(&value), AMXC_VAR_ID_UINT64);

    assert_int_not_equal(amxd_object_get_param(object, "fake_news", &value), 0);
    assert_int_not_equal(amxd_object_get_param(object, NULL, &value), 0);
    assert_int_not_equal(amxd_object_get_param(object, "", &value), 0);
    assert_int_not_equal(amxd_object_get_param(object, "fake_news", NULL), 0);
    assert_int_not_equal(amxd_object_get_param(NULL, "fake_news", &value), 0);

    amxc_var_clean(&value);
    amxd_dm_clean(&dm);
}

void test_amxd_object_set_parameter_value(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxd_object_t* object = NULL;
    amxd_object_t* instance = NULL;
    amxc_var_t value;

    amxc_var_init(&value);
    template = test_build_dm();
    object = amxd_object_get_child(template, "child");

    amxc_var_set(uint32_t, &value, 123);
    assert_int_equal(amxd_object_set_param(template, "templ_param", &value), 0);
    amxc_var_clean(&value);
    assert_int_equal(amxd_object_get_param(template, "templ_param", &value), 0);
    assert_int_equal(amxc_var_type_of(&value), AMXC_VAR_ID_CSTRING);
    assert_string_equal(amxc_var_constcast(cstring_t, &value), "123");
    amxc_var_set(uint32_t, &value, 123);
    assert_int_not_equal(amxd_object_set_param(template, "inst_param", &value), 0);
    assert_int_equal(amxd_object_set_param(template, "param", &value), 0);

    assert_int_equal(amxd_object_new_instance(&instance, template, NULL, 0, NULL), 0);
    assert_int_not_equal(amxd_object_set_param(instance, "templ_param", &value), 0);
    assert_int_equal(amxd_object_set_param(instance, "inst_param", &value), 0);
    assert_int_equal(amxd_object_set_param(instance, "param", &value), 0);
    amxc_var_clean(&value);
    assert_int_equal(amxd_object_get_param(instance, "param", &value), 0);
    assert_int_equal(amxc_var_type_of(&value), AMXC_VAR_ID_UINT32);

    assert_int_not_equal(amxd_object_set_param(object, "fake_news", &value), 0);
    assert_int_not_equal(amxd_object_set_param(object, NULL, &value), 0);
    assert_int_not_equal(amxd_object_set_param(object, "", &value), 0);
    assert_int_not_equal(amxd_object_set_param(object, "fake_news", NULL), 0);
    assert_int_not_equal(amxd_object_set_param(NULL, "fake_news", &value), 0);

    amxc_var_clean(&value);
    amxd_dm_clean(&dm);
}

void test_amxd_object_set_parameter_value_type(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxd_object_t* object = NULL;
    amxd_object_t* instance = NULL;
    amxc_var_t value;

    amxc_var_init(&value);
    template = test_build_dm();
    assert_int_equal(amxd_object_new_instance(&instance, template, NULL, 0, NULL), 0);

    object = amxd_object_get_child(instance, "child");
    assert_int_equal(amxd_object_set_value(cstring_t, object, "child_param", "Hello"), 0);
    assert_int_equal(amxd_object_set_value(cstring_t, object, "child_param", ""), 0);
    assert_int_equal(amxd_object_set_value(int32_t, object, "child_param", 1), 0);
    assert_int_equal(amxd_object_set_value(uint32_t, object, "child_param", 2), 0);
    assert_int_equal(amxd_object_set_value(int64_t, object, "child_param", 3), 0);
    assert_int_equal(amxd_object_set_value(uint64_t, object, "child_param", 4), 0);
    assert_int_equal(amxd_object_set_value(bool, object, "child_param", true), 0);
    assert_int_equal(amxd_object_set_value(double, object, "child_param", 3.14), 0);

    assert_int_not_equal(amxd_object_set_value(cstring_t, object, "child_param", NULL), 0);
    assert_int_not_equal(amxd_object_set_value(cstring_t, NULL, "child_param", "Hello"), 0);
    assert_int_not_equal(amxd_object_set_value(int32_t, NULL, "child_param", 1), 0);
    assert_int_not_equal(amxd_object_set_value(uint32_t, NULL, "child_param", 2), 0);
    assert_int_not_equal(amxd_object_set_value(int64_t, NULL, "child_param", 3), 0);
    assert_int_not_equal(amxd_object_set_value(uint64_t, NULL, "child_param", 4), 0);
    assert_int_not_equal(amxd_object_set_value(bool, NULL, "child_param", true), 0);
    assert_int_not_equal(amxd_object_set_value(double, NULL, "child_param", 3.14), 0);

    assert_int_not_equal(amxd_object_set_value(cstring_t, object, "", "Hello"), 0);
    assert_int_not_equal(amxd_object_set_value(int32_t, object, "", 1), 0);
    assert_int_not_equal(amxd_object_set_value(uint32_t, object, "", 2), 0);
    assert_int_not_equal(amxd_object_set_value(int64_t, object, "", 3), 0);
    assert_int_not_equal(amxd_object_set_value(uint64_t, object, "", 4), 0);
    assert_int_not_equal(amxd_object_set_value(bool, object, "", true), 0);
    assert_int_not_equal(amxd_object_set_value(double, object, "", 3.14), 0);

    assert_int_not_equal(amxd_object_set_value(cstring_t, object, NULL, "Hello"), 0);
    assert_int_not_equal(amxd_object_set_value(int32_t, object, NULL, 1), 0);
    assert_int_not_equal(amxd_object_set_value(uint32_t, object, NULL, 2), 0);
    assert_int_not_equal(amxd_object_set_value(int64_t, object, NULL, 3), 0);
    assert_int_not_equal(amxd_object_set_value(uint64_t, object, NULL, 4), 0);
    assert_int_not_equal(amxd_object_set_value(bool, object, NULL, true), 0);
    assert_int_not_equal(amxd_object_set_value(double, object, NULL, 3.14), 0);

    amxc_var_clean(&value);
    amxd_dm_clean(&dm);
}

void test_amxd_object_set_parameters_value(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxd_object_t* object = NULL;
    amxc_var_t values;
    amxc_var_t* value;

    amxc_var_init(&values);
    template = test_build_dm();
    object = amxd_object_get_child(template, "child");

    amxc_var_set_type(&values, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &values, "param", "123");
    amxc_var_add_key(uint32_t, &values, "templ_param", 123);
    assert_int_equal(amxd_object_set_params(template, &values), 0);
    amxc_var_clean(&values);
    assert_int_equal(amxd_object_get_params(template, &values, amxd_dm_access_private), 0);
    value = amxc_var_get_path(&values, "templ_param", AMXC_VAR_FLAG_DEFAULT);
    assert_int_equal(amxc_var_type_of(value), AMXC_VAR_ID_CSTRING);
    assert_string_equal(amxc_var_constcast(cstring_t, value), "123");
    value = amxc_var_get_path(&values, "param", AMXC_VAR_FLAG_DEFAULT);
    assert_int_equal(amxc_var_type_of(value), AMXC_VAR_ID_UINT32);
    assert_int_equal(amxc_var_constcast(uint32_t, value), 123);

    amxc_var_set_type(&values, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &values, "fake_news", "123");
    amxc_var_add_key(uint32_t, &values, "invalid", 123);
    assert_int_not_equal(amxd_object_set_params(object, &values), 0);
    assert_int_not_equal(amxd_object_set_params(object, NULL), 0);
    assert_int_not_equal(amxd_object_set_params(NULL, &values), 0);
    amxc_var_set_type(&values, AMXC_VAR_ID_LIST);
    assert_int_not_equal(amxd_object_set_params(object, &values), 0);

    amxc_var_clean(&values);
    amxd_dm_clean(&dm);
}

void test_amxd_object_set_parameter_value_with_cb(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxd_object_t* object = NULL;
    amxd_object_t* instance = NULL;
    amxc_var_t value;

    amxc_var_init(&value);
    template = test_build_dm();
    object = amxd_object_get_child(template, "child");
    assert_int_equal(amxd_object_add_action_cb(template, action_object_write, amxd_action_object_write, NULL), 0);
    assert_int_equal(amxd_object_add_action_cb(object, action_object_write, amxd_action_object_write, NULL), 0);

    amxc_var_set(uint32_t, &value, 123);
    assert_int_equal(amxd_object_set_param(template, "templ_param", &value), 0);
    amxc_var_clean(&value);
    assert_int_equal(amxd_object_get_param(template, "templ_param", &value), 0);
    assert_int_equal(amxc_var_type_of(&value), AMXC_VAR_ID_CSTRING);
    assert_string_equal(amxc_var_constcast(cstring_t, &value), "123");
    amxc_var_set(uint32_t, &value, 123);
    assert_int_not_equal(amxd_object_set_param(template, "inst_param", &value), 0);
    assert_int_equal(amxd_object_set_param(template, "param", &value), 0);

    assert_int_equal(amxd_object_new_instance(&instance, template, NULL, 0, NULL), 0);
    assert_int_not_equal(amxd_object_set_param(instance, "templ_param", &value), 0);
    assert_int_equal(amxd_object_set_param(instance, "inst_param", &value), 0);
    assert_int_equal(amxd_object_set_param(instance, "param", &value), 0);
    amxc_var_clean(&value);
    assert_int_equal(amxd_object_get_param(instance, "param", &value), 0);
    assert_int_equal(amxc_var_type_of(&value), AMXC_VAR_ID_UINT32);

    assert_int_not_equal(amxd_object_set_param(object, "fake_news", &value), 0);
    assert_int_not_equal(amxd_object_set_param(object, NULL, &value), 0);
    assert_int_not_equal(amxd_object_set_param(object, "", &value), 0);
    assert_int_not_equal(amxd_object_set_param(object, "fake_news", NULL), 0);
    assert_int_not_equal(amxd_object_set_param(NULL, "fake_news", &value), 0);

    amxd_dm_clean(&dm);
}

void test_amxd_object_set_parameters_value_with_cb(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxd_object_t* object = NULL;
    amxc_var_t values;
    amxc_var_t* value;

    amxc_var_init(&values);
    template = test_build_dm();
    object = amxd_object_get_child(template, "child");
    assert_int_equal(amxd_object_add_action_cb(template, action_object_write, amxd_action_object_write, NULL), 0);

    amxc_var_set_type(&values, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &values, "param", "123");
    amxc_var_add_key(uint32_t, &values, "templ_param", 123);
    assert_int_equal(amxd_object_set_params(template, &values), 0);
    amxc_var_clean(&values);
    assert_int_equal(amxd_object_get_params(template, &values, amxd_dm_access_private), 0);
    value = amxc_var_get_path(&values, "templ_param", AMXC_VAR_FLAG_DEFAULT);
    assert_int_equal(amxc_var_type_of(value), AMXC_VAR_ID_CSTRING);
    assert_string_equal(amxc_var_constcast(cstring_t, value), "123");
    value = amxc_var_get_path(&values, "param", AMXC_VAR_FLAG_DEFAULT);
    assert_int_equal(amxc_var_type_of(value), AMXC_VAR_ID_UINT32);
    assert_int_equal(amxc_var_constcast(uint32_t, value), 123);

    amxc_var_set_type(&values, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &values, "fake_news", "123");
    amxc_var_add_key(uint32_t, &values, "invalid", 123);
    assert_int_not_equal(amxd_object_set_params(object, &values), 0);
    assert_int_not_equal(amxd_object_set_params(object, NULL), 0);
    assert_int_not_equal(amxd_object_set_params(NULL, &values), 0);
    amxc_var_set_type(&values, AMXC_VAR_ID_LIST);
    assert_int_not_equal(amxd_object_set_params(object, &values), 0);

    amxc_var_clean(&values);
    amxd_dm_clean(&dm);
}

void test_amxd_object_get_parameters_value(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxd_object_t* object = NULL;
    amxd_object_t* instance = NULL;
    int index = 0;
    amxc_var_t params;

    amxc_var_init(&params);
    template = test_build_dm();
    object = amxd_object_get_child(template, "child");

    assert_int_equal(amxd_object_get_params(template, &params, amxd_dm_access_protected), 0);
    assert_int_equal(amxc_var_type_of(&params), AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_htable_size(amxc_var_constcast(amxc_htable_t, &params)), 3);

    assert_int_equal(amxd_object_new_instance(&instance, template, NULL, 0, NULL), 0);
    assert_int_equal(amxd_object_get_params(template, &params, amxd_dm_access_protected), 0);
    assert_int_equal(amxc_var_type_of(&params), AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_htable_size(amxc_var_constcast(amxc_htable_t, &params)), 3); // 2 template parameters

    assert_int_equal(amxd_object_get_params(instance, &params, amxd_dm_access_protected), 0);
    assert_int_equal(amxc_var_type_of(&params), AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_htable_size(amxc_var_constcast(amxc_htable_t, &params)), 2);

    assert_int_equal(amxd_object_get_params(object, &params, amxd_dm_access_protected), 0);
    assert_int_equal(amxc_var_type_of(&params), AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_htable_size(amxc_var_constcast(amxc_htable_t, &params)), 2);

    assert_int_equal(amxd_object_get_params(object, &params, amxd_dm_access_private), 0);
    assert_int_equal(amxc_var_type_of(&params), AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_htable_size(amxc_var_constcast(amxc_htable_t, &params)), 3);

    object = amxd_object_get_child(instance, "child");
    assert_int_equal(amxd_object_get_params(object, &params, amxd_dm_access_protected), 0);
    assert_int_equal(amxc_var_type_of(&params), AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_htable_size(amxc_var_constcast(amxc_htable_t, &params)), 2);
    index = 0;
    amxc_htable_for_each(it, amxc_var_constcast(amxc_htable_t, &params)) {
        const char* names[2] = { "child_param2", "child_param3" };
        const char* param_name = amxc_htable_it_get_key(it);
        assert_string_equal(param_name, names[index]);
        index++;
    }

    assert_int_equal(amxd_object_get_params(object, &params, amxd_dm_access_private), 0);
    assert_int_equal(amxc_var_type_of(&params), AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_htable_size(amxc_var_constcast(amxc_htable_t, &params)), 3);

    assert_int_not_equal(amxd_object_get_params(NULL, &params, amxd_dm_access_private), 0);
    assert_int_not_equal(amxd_object_get_params(object, NULL, amxd_dm_access_private), 0);

    amxc_var_clean(&params);
    amxd_dm_clean(&dm);
}

void test_amxd_object_get_parameters_value_with_cb(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxd_object_t* object = NULL;
    amxd_object_t* instance = NULL;
    int index = 0;
    amxc_var_t params;

    amxc_var_init(&params);
    template = test_build_dm();
    object = amxd_object_get_child(template, "child");
    assert_int_equal(amxd_object_add_action_cb(template, action_object_read, amxd_action_object_read, NULL), 0);
    assert_int_equal(amxd_object_add_action_cb(object, action_object_read, amxd_action_object_read, NULL), 0);

    assert_int_equal(amxd_object_get_params(template, &params, amxd_dm_access_protected), 0);
    assert_int_equal(amxc_var_type_of(&params), AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_htable_size(amxc_var_constcast(amxc_htable_t, &params)), 3);

    assert_int_equal(amxd_object_new_instance(&instance, template, NULL, 0, NULL), 0);
    assert_int_equal(amxd_object_get_params(template, &params, amxd_dm_access_protected), 0);
    assert_int_equal(amxc_var_type_of(&params), AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_htable_size(amxc_var_constcast(amxc_htable_t, &params)), 3); // 2 template parameters

    assert_int_equal(amxd_object_get_params(instance, &params, amxd_dm_access_protected), 0);
    assert_int_equal(amxc_var_type_of(&params), AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_htable_size(amxc_var_constcast(amxc_htable_t, &params)), 2);

    assert_int_equal(amxd_object_get_params(object, &params, amxd_dm_access_protected), 0);
    assert_int_equal(amxc_var_type_of(&params), AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_htable_size(amxc_var_constcast(amxc_htable_t, &params)), 2);

    assert_int_equal(amxd_object_get_params(object, &params, amxd_dm_access_private), 0);
    assert_int_equal(amxc_var_type_of(&params), AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_htable_size(amxc_var_constcast(amxc_htable_t, &params)), 3);

    object = amxd_object_get_child(instance, "child");
    assert_int_equal(amxd_object_get_params(object, &params, amxd_dm_access_protected), 0);
    assert_int_equal(amxc_var_type_of(&params), AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_htable_size(amxc_var_constcast(amxc_htable_t, &params)), 2);
    index = 0;
    amxc_htable_for_each(it, amxc_var_constcast(amxc_htable_t, &params)) {
        const char* names[2] = { "child_param2", "child_param3" };
        const char* param_name = amxc_htable_it_get_key(it);
        assert_string_equal(param_name, names[index]);
        index++;
    }

    assert_int_equal(amxd_object_get_params(object, &params, amxd_dm_access_private), 0);
    assert_int_equal(amxc_var_type_of(&params), AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_htable_size(amxc_var_constcast(amxc_htable_t, &params)), 3);

    assert_int_not_equal(amxd_object_get_params(NULL, &params, amxd_dm_access_private), 0);
    assert_int_not_equal(amxd_object_get_params(object, NULL, amxd_dm_access_private), 0);

    amxc_var_clean(&params);
    amxd_dm_clean(&dm);
}

void test_amxd_object_list_parameters(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxd_object_t* object = NULL;
    amxd_object_t* instance = NULL;
    int index = 0;
    amxc_var_t plist;

    amxc_var_init(&plist);
    template = test_build_dm();
    object = amxd_object_get_child(template, "child");

    assert_int_equal(amxd_object_list_params(template, &plist, amxd_dm_access_public), 0);
    assert_int_equal(amxc_var_type_of(&plist), AMXC_VAR_ID_LIST);
    index = 0;
    amxc_llist_for_each(it, (amxc_var_constcast(amxc_llist_t, &plist))) {
        const char* names[3] = { "templ_param", "inst_param", "param" };
        amxc_var_t* param_name = amxc_var_from_llist_it(it);
        assert_int_equal(amxc_var_type_of(param_name), AMXC_VAR_ID_CSTRING);
        assert_string_equal(amxc_var_constcast(cstring_t, param_name), names[index]);
        index++;
    }

    assert_int_equal(amxd_object_list_params(template, &plist, amxd_dm_access_protected), 0);
    assert_int_equal(amxc_var_type_of(&plist), AMXC_VAR_ID_LIST);
    index = 0;
    amxc_llist_for_each(it, (amxc_var_constcast(amxc_llist_t, &plist))) {
        const char* names[3] = { "templ_param", "inst_param", "param" };
        amxc_var_t* param_name = amxc_var_from_llist_it(it);
        assert_int_equal(amxc_var_type_of(param_name), AMXC_VAR_ID_CSTRING);
        assert_string_equal(amxc_var_constcast(cstring_t, param_name), names[index]);
        index++;
    }

    assert_int_equal(amxd_object_new_instance(&instance, template, NULL, 0, NULL), 0);
    index = 0;
    assert_int_equal(amxd_object_list_params(instance, &plist, amxd_dm_access_public), 0);
    assert_int_equal(amxc_var_type_of(&plist), AMXC_VAR_ID_LIST);
    amxc_llist_for_each(it, (amxc_var_constcast(amxc_llist_t, &plist))) {
        const char* names[2] = { "inst_param", "param" };
        amxc_var_t* param_name = amxc_var_from_llist_it(it);
        assert_int_equal(amxc_var_type_of(param_name), AMXC_VAR_ID_CSTRING);
        assert_string_equal(amxc_var_constcast(cstring_t, param_name), names[index]);
        index++;
    }

    assert_int_equal(amxd_object_list_params(object, &plist, amxd_dm_access_public), 0);
    assert_int_equal(amxc_var_type_of(&plist), AMXC_VAR_ID_LIST);
    index = 0;
    amxc_llist_for_each(it, (amxc_var_constcast(amxc_llist_t, &plist))) {
        const char* names[2] = { "child_param2", "child_param3" };
        amxc_var_t* param_name = amxc_var_from_llist_it(it);
        assert_int_equal(amxc_var_type_of(param_name), AMXC_VAR_ID_CSTRING);
        assert_string_equal(amxc_var_constcast(cstring_t, param_name), names[index]);
        index++;
    }

    assert_int_equal(amxd_object_list_params(object, &plist, amxd_dm_access_private), 0);
    assert_int_equal(amxc_var_type_of(&plist), AMXC_VAR_ID_LIST);
    index = 0;
    amxc_llist_for_each(it, (amxc_var_constcast(amxc_llist_t, &plist))) {
        const char* names[3] = { "child_param", "child_param2", "child_param3" };
        amxc_var_t* param_name = amxc_var_from_llist_it(it);
        assert_int_equal(amxc_var_type_of(param_name), AMXC_VAR_ID_CSTRING);
        assert_string_equal(amxc_var_constcast(cstring_t, param_name), names[index]);
        index++;
    }

    assert_int_equal(amxd_object_list_params(object, &plist, amxd_dm_access_public), 0);
    assert_int_equal(amxc_var_type_of(&plist), AMXC_VAR_ID_LIST);
    index = 0;
    amxc_llist_for_each(it, (amxc_var_constcast(amxc_llist_t, &plist))) {
        const char* names[2] = { "child_param2", "child_param3" };
        amxc_var_t* param_name = amxc_var_from_llist_it(it);
        assert_int_equal(amxc_var_type_of(param_name), AMXC_VAR_ID_CSTRING);
        assert_string_equal(amxc_var_constcast(cstring_t, param_name), names[index]);
        index++;
    }

    object = amxd_object_get_child(instance, "child");
    assert_int_equal(amxd_object_list_params(object, &plist, amxd_dm_access_private), 0);
    assert_int_equal(amxc_var_type_of(&plist), AMXC_VAR_ID_LIST);
    index = 0;
    amxc_llist_for_each(it, (amxc_var_constcast(amxc_llist_t, &plist))) {
        const char* names[3] = { "child_param", "child_param2", "child_param3" };
        amxc_var_t* param_name = amxc_var_from_llist_it(it);
        assert_int_equal(amxc_var_type_of(param_name), AMXC_VAR_ID_CSTRING);
        assert_string_equal(amxc_var_constcast(cstring_t, param_name), names[index]);
        index++;
    }

    assert_int_not_equal(amxd_object_list_params(object, NULL, amxd_dm_access_private), 0);
    assert_int_not_equal(amxd_object_list_params(NULL, &plist, amxd_dm_access_private), 0);

    amxc_var_clean(&plist);
    amxd_dm_clean(&dm);
}

void test_amxd_object_count_parameters(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxd_object_t* object = NULL;
    amxd_object_t* instance = NULL;

    template = test_build_dm();
    object = amxd_object_get_child(template, "child");

    assert_int_equal(amxd_object_new_instance(&instance, template, NULL, 0, NULL), 0);

    assert_int_equal(amxd_object_get_param_count(template, amxd_dm_access_protected), 3);
    assert_int_equal(amxd_object_get_param_count(instance, amxd_dm_access_protected), 2);
    assert_int_equal(amxd_object_get_param_count(object, amxd_dm_access_protected), 2);
    assert_int_equal(amxd_object_get_param_count(object, amxd_dm_access_private), 3);
    object = amxd_object_get_child(instance, "child");
    assert_ptr_not_equal(object, NULL);
    assert_int_equal(amxd_object_get_param_count(object, amxd_dm_access_protected), 2);
    assert_int_equal(amxd_object_get_param_count(object, amxd_dm_access_private), 3);

    assert_int_equal(amxd_object_get_param_count(NULL, amxd_dm_access_protected), 0);
    assert_int_equal(amxd_object_get_param_count(NULL, amxd_dm_access_private), 0);

    amxd_dm_clean(&dm);
}

void test_amxd_object_count_parameters_with_cb(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxd_object_t* object = NULL;
    amxd_object_t* instance = NULL;

    template = test_build_dm();
    object = amxd_object_get_child(template, "child");
    assert_int_equal(amxd_object_add_action_cb(template, action_object_list, amxd_action_object_list, NULL), 0);
    assert_int_equal(amxd_object_add_action_cb(object, action_object_list, amxd_action_object_list, NULL), 0);

    assert_int_equal(amxd_object_new_instance(&instance, template, NULL, 0, NULL), 0);

    assert_int_equal(amxd_object_get_param_count(template, amxd_dm_access_protected), 3);
    assert_int_equal(amxd_object_get_param_count(instance, amxd_dm_access_protected), 2);
    assert_int_equal(amxd_object_get_param_count(object, amxd_dm_access_protected), 2);
    assert_int_equal(amxd_object_get_param_count(object, amxd_dm_access_private), 3);
    object = amxd_object_get_child(instance, "child");
    assert_ptr_not_equal(object, NULL);
    assert_int_equal(amxd_object_get_param_count(object, amxd_dm_access_protected), 2);
    assert_int_equal(amxd_object_get_param_count(object, amxd_dm_access_private), 3);

    assert_int_equal(amxd_object_get_param_count(NULL, amxd_dm_access_protected), 0);
    assert_int_equal(amxd_object_get_param_count(NULL, amxd_dm_access_private), 0);

    amxd_dm_clean(&dm);
}

void test_amxd_object_get_params_filtered(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxd_object_t* object = NULL;
    amxd_object_t* instance = NULL;
    amxd_param_t* param = NULL;
    amxc_var_t params;
    int rv = 0;
    const amxc_htable_t* ht_params = NULL;

    amxc_var_init(&params);

    template = test_build_dm();
    assert_int_equal(amxd_object_new_instance(&instance, template, NULL, 0, NULL), 0);
    object = amxd_object_findf(template, "1.child.");
    assert_non_null(object);
    param = amxd_object_get_param_def(object, "child_param2");
    assert_non_null(param);
    amxd_param_set_flag(param, "bart");
    assert_true(amxd_param_has_flag(param, "bart"));

    rv = amxd_object_get_params_filtered(object, &params,
                                         "'bart' in flags", amxd_dm_access_private);
    assert_int_equal(rv, 0);
    assert_int_equal(amxc_var_type_of(&params), AMXC_VAR_ID_HTABLE);
    ht_params = amxc_var_constcast(amxc_htable_t, &params);
    assert_int_equal(amxc_htable_size(ht_params), 1);

    amxd_param_unset_flag(param, "bart");
    assert_false(amxd_param_has_flag(param, "bart"));
    rv = amxd_object_get_params_filtered(object, &params,
                                         "'bart' in flags", amxd_dm_access_private);
    assert_int_equal(rv, 0);
    assert_int_equal(amxc_var_type_of(&params), AMXC_VAR_ID_HTABLE);
    ht_params = amxc_var_constcast(amxc_htable_t, &params);
    assert_int_equal(amxc_htable_size(ht_params), 0);

    rv = amxd_object_get_params_filtered(object, &params,
                                         "name starts with 'child'", amxd_dm_access_private);
    assert_int_equal(rv, 0);
    assert_int_equal(amxc_var_type_of(&params), AMXC_VAR_ID_HTABLE);
    amxc_var_dump(&params, STDOUT_FILENO);
    ht_params = amxc_var_constcast(amxc_htable_t, &params);
    assert_int_equal(amxc_htable_size(ht_params), 3);

    rv = amxd_object_get_params_filtered(object, &params,
                                         "attributes.private == true", amxd_dm_access_private);
    assert_int_equal(rv, 0);
    assert_int_equal(amxc_var_type_of(&params), AMXC_VAR_ID_HTABLE);
    ht_params = amxc_var_constcast(amxc_htable_t, &params);
    assert_int_equal(amxc_htable_size(ht_params), 1);

    rv = amxd_object_get_params_filtered(object, &params, NULL, amxd_dm_access_private);
    assert_int_equal(rv, 0);
    assert_int_equal(amxc_var_type_of(&params), AMXC_VAR_ID_HTABLE);
    ht_params = amxc_var_constcast(amxc_htable_t, &params);
    assert_int_equal(amxc_htable_size(ht_params), 3);

    rv = amxd_object_get_params_filtered(object, &params, "", amxd_dm_access_private);
    assert_int_equal(rv, 0);
    assert_int_equal(amxc_var_type_of(&params), AMXC_VAR_ID_HTABLE);
    ht_params = amxc_var_constcast(amxc_htable_t, &params);
    assert_int_equal(amxc_htable_size(ht_params), 3);

    rv = amxd_object_get_params_filtered(object, &params, "", amxd_dm_access_public);
    assert_int_equal(rv, 0);
    assert_int_equal(amxc_var_type_of(&params), AMXC_VAR_ID_HTABLE);
    ht_params = amxc_var_constcast(amxc_htable_t, &params);
    assert_int_equal(amxc_htable_size(ht_params), 2);

    amxc_var_clean(&params);
    amxd_dm_clean(&dm);
}

void test_amxd_object_get_params_invalid_expr_filter(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxd_object_t* object = NULL;
    amxd_object_t* instance = NULL;
    amxc_var_t params;
    int rv = 0;

    amxc_var_init(&params);

    template = test_build_dm();
    assert_int_equal(amxd_object_new_instance(&instance, template, NULL, 0, NULL), 0);
    object = amxd_object_findf(template, "1.child.");
    assert_non_null(object);

    rv = amxd_object_get_params_filtered(object, &params, "protocol > 100", amxd_dm_access_private);
    assert_int_not_equal(rv, 0);
    assert_int_equal(amxc_var_type_of(&params), AMXC_VAR_ID_NULL);

    rv = amxd_object_get_params_filtered(object, &params, "name <> 100", amxd_dm_access_private);
    assert_int_not_equal(rv, 0);
    assert_int_equal(amxc_var_type_of(&params), AMXC_VAR_ID_NULL);

    rv = amxd_object_get_params_filtered(NULL, &params, NULL, amxd_dm_access_private);
    assert_int_not_equal(rv, 0);
    assert_int_equal(amxc_var_type_of(&params), AMXC_VAR_ID_NULL);

    rv = amxd_object_get_params_filtered(object, NULL, NULL, amxd_dm_access_private);
    assert_int_not_equal(rv, 0);
    assert_int_equal(amxc_var_type_of(&params), AMXC_VAR_ID_NULL);

    amxc_var_clean(&params);
    amxd_dm_clean(&dm);
}

void test_amxd_object_parameter_flags(UNUSED void** state) {
    amxd_object_t* object = NULL;
    amxd_param_t* param = NULL;

    assert_int_equal(amxd_object_new(&object, amxd_object_template, "test_object"), 0);
    assert_int_equal(amxd_param_new(&param, "test_param", AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(amxd_object_add_param(object, param), 0);

    amxd_param_set_flag(param, "test_flag");
    assert_true(amxd_param_has_flag(param, "test_flag"));
    amxd_param_unset_flag(param, "test_flag");
    assert_false(amxd_param_has_flag(param, "test_flag"));

    amxd_param_set_flag(NULL, "test_flag");
    amxd_param_set_flag(param, NULL);
    amxd_param_set_flag(param, "");

    assert_false(amxd_param_has_flag(NULL, "test_flag"));
    assert_false(amxd_param_has_flag(param, NULL));
    assert_false(amxd_param_has_flag(param, ""));

    amxd_param_unset_flag(NULL, "test_flag");
    amxd_param_unset_flag(param, NULL);
    amxd_param_unset_flag(param, "");

    amxd_object_delete(&object);
}

void test_amxd_object_set(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxd_object_t* instance = NULL;
    amxd_object_t* object = NULL;
    amxd_status_t status = amxd_status_ok;

    char* txt = NULL;
    amxc_ts_t ts;
    amxc_ts_t* tsp = NULL;

    amxc_ts_now(&ts);

    template = test_build_dm();
    assert_int_equal(amxd_object_new_instance(&instance, template, NULL, 0, NULL), 0);
    object = amxd_object_findf(instance, "child.");

    assert_int_equal(amxd_object_set_value(csv_string_t, object, "child_param", "a,b,c"), 0);
    assert_int_equal(amxd_object_set_value(ssv_string_t, object, "child_param", "a b c"), 0);
    assert_int_equal(amxd_object_set_value(int8_t, object, "child_param", 1), 0);
    assert_int_equal(amxd_object_set_value(uint8_t, object, "child_param", 2), 0);
    assert_int_equal(amxd_object_set_value(int16_t, object, "child_param", 3), 0);
    assert_int_equal(amxd_object_set_value(uint16_t, object, "child_param", 4), 0);
    assert_int_equal(amxd_object_set_value(amxc_ts_t, object, "child_param", &ts), 0);

    txt = amxd_object_get_value(cstring_t, object, "child_param", &status);
    tsp = amxd_object_get_value(amxc_ts_t, object, "child_param", &status);

    free(txt);
    free(tsp);
    amxd_dm_clean(&dm);
}

void test_amxd_object_get_helpers(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxd_object_t* instance = NULL;
    amxd_object_t* object = NULL;
    amxd_status_t status = amxd_status_ok;
    amxc_ts_t ts;

    amxc_ts_now(&ts);

    template = test_build_dm();
    assert_int_equal(amxd_object_new_instance(&instance, template, NULL, 0, NULL), 0);
    object = amxd_object_findf(instance, "child.");

    assert_int_equal(amxd_object_set_value(cstring_t, object, "child_param", "10"), 0);

    assert_int_equal(amxd_object_get_value(int8_t, object, "child_param", &status), 10);
    assert_int_equal(amxd_object_get_value(uint8_t, object, "child_param", &status), 10);
    assert_int_equal(amxd_object_get_value(int16_t, object, "child_param", &status), 10);
    assert_int_equal(amxd_object_get_value(uint16_t, object, "child_param", &status), 10);

    amxd_dm_clean(&dm);
}
