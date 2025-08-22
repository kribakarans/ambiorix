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
#include <stdio.h>

#include <amxc/amxc.h>
#include <amxp/amxp_signal.h>
#include <amxp/amxp_slot.h>
#include <amxp/amxp_expression.h>

#include <amxd/amxd_common.h>
#include <amxd/amxd_transaction.h>
#include <amxd/amxd_dm.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_object_expression.h>
#include <amxd/amxd_action.h>

#include "test_amxd_key_parameter.h"

#include <amxc/amxc_macros.h>
static amxd_dm_t dm;

static amxd_status_t amxd_param_cleanup_data(amxd_object_t* const object,
                                             amxd_param_t* const param,
                                             amxd_action_t reason,
                                             UNUSED const amxc_var_t* const args,
                                             UNUSED amxc_var_t* const retval,
                                             void* priv) {
    amxd_status_t status = amxd_status_ok;
    amxc_var_t* data = (amxc_var_t*) priv;

    if((reason != action_object_destroy) &&
       ( reason != action_param_destroy)) {
        status = amxd_status_function_not_implemented;
        goto exit;
    }

    // action private data must not be removed when the action is used
    // on derived objects.
    // only remove action data when the action is owned by the object or
    // parameter on which the action is called.
    if(reason == action_object_destroy) {
        if(amxd_object_has_action_cb(object, reason, amxd_param_cleanup_data)) {
            amxc_var_delete(&data);
            amxd_object_set_action_cb_data(object, reason, amxd_param_cleanup_data, NULL);
        }
    } else {
        if(amxd_param_has_action_cb(param, reason, amxd_param_cleanup_data)) {
            amxc_var_delete(&data);
            amxd_param_set_action_cb_data(param, reason, amxd_param_cleanup_data, NULL);
        }
    }

exit:
    return status;
}


static void test_build_dm(void) {
    amxd_object_t* object = NULL;
    amxd_object_t* child_object = NULL;
    amxd_param_t* param = NULL;
    amxc_var_t value;
    amxc_var_t* enum_data = NULL;

    amxc_var_init(&value);
    amxc_var_set(cstring_t, &value, "TestValue");

    amxc_var_new(&enum_data);
    amxc_var_set_type(enum_data, AMXC_VAR_ID_LIST);
    amxc_var_add(cstring_t, enum_data, "UDP");
    amxc_var_add(cstring_t, enum_data, "TCP");

    assert_int_equal(amxd_dm_init(&dm), 0);

    assert_int_equal(amxd_object_new(&object, amxd_object_singleton, "MyObject"), 0);
    assert_int_equal(amxd_param_new(&param, "Param1", AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(amxd_param_set_value(param, &value), 0);
    assert_int_equal(amxd_object_add_param(object, param), 0);
    assert_int_equal(amxd_dm_add_root_object(&dm, object), 0);

    assert_int_equal(amxd_object_new(&child_object, amxd_object_template, "ChildObject"), 0);
    assert_int_equal(amxd_object_add_object(object, child_object), 0);
    assert_int_equal(amxd_param_new(&param, "Param1", AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(amxd_param_set_attr(param, amxd_pattr_key, true), 0);
    assert_int_equal(amxd_object_add_param(child_object, param), 0);
    assert_int_equal(amxd_param_new(&param, "Param2", AMXC_VAR_ID_BOOL), 0);
    assert_int_equal(amxd_object_add_param(child_object, param), 0);
    assert_int_equal(amxd_param_new(&param, "Param3", AMXC_VAR_ID_UINT32), 0);
    assert_int_equal(amxd_object_add_param(child_object, param), 0);

    assert_int_equal(amxd_object_new(&child_object, amxd_object_template, "KeyValidateObject"), 0);
    assert_int_equal(amxd_object_add_object(object, child_object), 0);
    assert_int_equal(amxd_param_new(&param, "Param1", AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(amxd_param_set_attr(param, amxd_pattr_key, true), 0);
    assert_int_equal(amxd_param_set_attr(param, amxd_pattr_mutable, true), 0);
    assert_int_equal(amxd_param_add_action_cb(param, action_param_validate, amxd_action_param_check_enum, enum_data), 0);
    assert_int_equal(amxd_param_add_action_cb(param, action_param_destroy, amxd_param_cleanup_data, enum_data), 0);
    assert_int_equal(amxd_object_add_param(child_object, param), 0);

    assert_int_equal(amxd_object_new(&child_object, amxd_object_template, "UKeyObject"), 0);
    assert_int_equal(amxd_object_add_object(object, child_object), 0);
    assert_int_equal(amxd_param_new(&param, "UKey1", AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(amxd_param_set_attr(param, amxd_pattr_key, true), 0);
    assert_int_equal(amxd_param_set_attr(param, amxd_pattr_unique, true), 0);
    assert_int_equal(amxd_object_add_param(child_object, param), 0);
    assert_int_equal(amxd_param_new(&param, "UKey2", AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(amxd_param_set_attr(param, amxd_pattr_key, true), 0);
    assert_int_equal(amxd_param_set_attr(param, amxd_pattr_unique, true), 0);
    assert_int_equal(amxd_object_add_param(child_object, param), 0);
    assert_int_equal(amxd_param_new(&param, "KeyParam1", AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(amxd_param_set_attr(param, amxd_pattr_key, true), 0);
    assert_int_equal(amxd_object_add_param(child_object, param), 0);
    assert_int_equal(amxd_param_new(&param, "KeyParam2", AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(amxd_param_set_attr(param, amxd_pattr_key, true), 0);
    assert_int_equal(amxd_object_add_param(child_object, param), 0);
    assert_int_equal(amxd_param_new(&param, "Param1", AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(amxd_object_add_param(child_object, param), 0);
    assert_int_equal(amxd_param_new(&param, "Param2", AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(amxd_object_add_param(child_object, param), 0);

    assert_int_equal(amxd_object_new(&child_object, amxd_object_template, "AliasObject"), 0);
    assert_int_equal(amxd_object_add_object(object, child_object), 0);
    assert_int_equal(amxd_param_new(&param, "Alias", AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(amxd_param_set_attr(param, amxd_pattr_key, true), 0);
    assert_int_equal(amxd_param_set_attr(param, amxd_pattr_unique, true), 0);
    assert_int_equal(amxd_object_add_param(child_object, param), 0);
    assert_int_equal(amxd_param_new(&param, "Param1", AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(amxd_object_add_param(child_object, param), 0);

    assert_int_equal(amxd_object_new(&child_object, amxd_object_template, "FakeAliasObject"), 0);
    assert_int_equal(amxd_object_add_object(object, child_object), 0);
    assert_int_equal(amxd_param_new(&param, "Alias", AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(amxd_object_add_param(child_object, param), 0);
    assert_int_equal(amxd_param_new(&param, "Param1", AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(amxd_object_add_param(child_object, param), 0);

    assert_int_equal(amxd_object_new(&child_object, amxd_object_singleton, "TestSingleton"), 0);
    assert_int_equal(amxd_param_new(&param, "Param1", AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(amxd_object_add_param(child_object, param), 0);
    assert_int_equal(amxd_object_add_object(object, child_object), 0);

    assert_int_equal(amxd_object_new(&child_object, amxd_object_mib, "TestMib"), 0);
    assert_int_equal(amxd_param_new(&param, "Param1", AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(amxd_object_add_param(child_object, param), 0);
    assert_int_equal(amxd_dm_store_mib(&dm, child_object), 0);

    amxc_var_clean(&value);
}

int test_key_parameter_setup(UNUSED void** state) {
    test_build_dm();
    return 0;
}

int test_key_parameter_teardown(UNUSED void** state) {
    amxd_dm_clean(&dm);

    return 0;
}

void test_key_flag_is_set(UNUSED void** state) {
    amxd_object_t* object = amxd_dm_findf(&dm, "MyObject.ChildObject");
    amxd_param_t* param = amxd_object_get_param_def(object, "Param1");

    assert_true(amxd_param_is_attr_set(param, amxd_pattr_key));
}

void test_can_add_key_param_if_no_instances_exist(UNUSED void** state) {
    amxd_object_t* object = NULL;
    amxd_param_t* param = NULL;

    object = amxd_dm_findf(&dm, "MyObject.ChildObject");
    assert_int_equal(amxd_param_new(&param, "ParamExtra", AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(amxd_param_set_attr(param, amxd_pattr_key, true), 0);
    assert_int_equal(amxd_object_add_param(object, param), 0);
}

void test_key_parameters_must_be_set(UNUSED void** state) {
    amxd_trans_t transaction;
    amxd_object_t* object = NULL;

    amxd_trans_init(&transaction);
    amxd_trans_select_pathf(&transaction, "MyObject.ChildObject");
    amxd_trans_add_inst(&transaction, 1, NULL);
    assert_int_not_equal(amxd_trans_apply(&transaction, &dm), 0);
    object = amxd_dm_findf(&dm, "MyObject.ChildObject.1");
    assert_ptr_equal(object, NULL);

    amxd_trans_clean(&transaction);
    amxd_trans_select_pathf(&transaction, "MyObject.ChildObject");
    amxd_trans_add_inst(&transaction, 1, NULL);
    amxd_trans_set_value(cstring_t, &transaction, "Param1", "TheKeyValue");
    assert_int_not_equal(amxd_trans_apply(&transaction, &dm), 0);
    object = amxd_dm_findf(&dm, "MyObject.ChildObject.1");
    assert_ptr_equal(object, NULL);

    amxd_trans_clean(&transaction);
    amxd_trans_select_pathf(&transaction, "MyObject.ChildObject");
    amxd_trans_add_inst(&transaction, 1, NULL);
    amxd_trans_set_value(cstring_t, &transaction, "Param1", "TheKeyValue");
    amxd_trans_set_value(cstring_t, &transaction, "ParamExtra", "TheKeyValue");
    assert_int_equal(amxd_trans_apply(&transaction, &dm), 0);
    object = amxd_dm_findf(&dm, "MyObject.ChildObject.1");
    assert_ptr_not_equal(object, NULL);

    amxd_trans_clean(&transaction);
}

void test_key_parameters_must_be_unique(UNUSED void** state) {
    amxd_trans_t transaction;
    amxd_object_t* object = NULL;

    amxd_trans_init(&transaction);
    amxd_trans_select_pathf(&transaction, "MyObject.ChildObject");
    amxd_trans_add_inst(&transaction, 2, NULL);
    amxd_trans_set_value(cstring_t, &transaction, "Param1", "TheKeyValue");
    amxd_trans_set_value(cstring_t, &transaction, "ParamExtra", "TheKeyValue");
    assert_int_not_equal(amxd_trans_apply(&transaction, &dm), 0);
    object = amxd_dm_findf(&dm, "MyObject.ChildObject.2");
    assert_ptr_equal(object, NULL);

    amxd_trans_clean(&transaction);
    amxd_trans_select_pathf(&transaction, "MyObject.ChildObject");
    amxd_trans_add_inst(&transaction, 2, NULL);
    amxd_trans_set_value(cstring_t, &transaction, "Param1", "OtherValue");
    amxd_trans_set_value(cstring_t, &transaction, "ParamExtra", "TheKeyValue");
    assert_int_equal(amxd_trans_apply(&transaction, &dm), 0);
    object = amxd_dm_findf(&dm, "MyObject.ChildObject.2");
    assert_ptr_not_equal(object, NULL);

    amxd_trans_clean(&transaction);
}

void test_can_not_add_key_params_if_instances_exist(UNUSED void** state) {
    amxd_object_t* object = NULL;
    amxd_param_t* param = NULL;

    object = amxd_dm_findf(&dm, "MyObject.ChildObject");
    assert_int_equal(amxd_param_new(&param, "ParamExtra2", AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(amxd_param_set_attr(param, amxd_pattr_key, true), 0);
    assert_int_not_equal(amxd_object_add_param(object, param), 0);

    assert_ptr_equal(amxd_param_get_owner(param), NULL);
    assert_ptr_equal(amxd_object_get_param_def(object, "ParamExtra2"), NULL);

    amxd_param_delete(&param);
}

void test_can_not_unset_key_attr(UNUSED void** state) {
    amxd_object_t* object = NULL;
    amxd_param_t* param = NULL;

    object = amxd_dm_findf(&dm, "MyObject.ChildObject");
    param = amxd_object_get_param_def(object, "ParamExtra");
    assert_int_not_equal(amxd_param_set_attr(param, amxd_pattr_key, false), 0);

    object = amxd_dm_findf(&dm, "MyObject.ChildObject.1");
    param = amxd_object_get_param_def(object, "ParamExtra");
    assert_int_not_equal(amxd_param_set_attr(param, amxd_pattr_key, false), 0);
}

void test_can_not_delete_key_parameter(UNUSED void** state) {
    amxd_object_t* object = NULL;
    amxd_param_t* param = NULL;

    object = amxd_dm_findf(&dm, "MyObject.ChildObject");
    param = amxd_object_get_param_def(object, "ParamExtra");
    assert_int_not_equal(amxd_param_delete(&param), 0);
    param = amxd_object_get_param_def(object, "ParamExtra");
    assert_ptr_not_equal(param, NULL);

    object = amxd_dm_findf(&dm, "MyObject.ChildObject.1");
    param = amxd_object_get_param_def(object, "ParamExtra");
    assert_int_not_equal(amxd_param_delete(&param), 0);
    param = amxd_object_get_param_def(object, "ParamExtra");
    assert_ptr_not_equal(param, NULL);
}

void test_can_not_add_key_param_to(UNUSED void** state) {
    amxd_object_t* object = NULL;
    amxd_param_t* param = NULL;

    assert_int_equal(amxd_param_new(&param, "TestParam", AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(amxd_param_set_attr(param, amxd_pattr_key, true), 0);

    // singleton
    object = amxd_dm_findf(&dm, "MyObject.TestSingleton");
    assert_ptr_not_equal(object, NULL);
    assert_int_not_equal(amxd_object_add_param(object, param), 0);
    assert_ptr_equal(amxd_object_get_param_def(object, "TestParam"), NULL);
    assert_ptr_equal(amxd_param_get_owner(param), NULL);

    // mib
    object = amxd_dm_get_mib(&dm, "TestMib");
    assert_ptr_not_equal(object, NULL);
    assert_int_not_equal(amxd_object_add_param(object, param), 0);
    assert_ptr_equal(amxd_object_get_param_def(object, "TestParam"), NULL);
    assert_ptr_equal(amxd_param_get_owner(param), NULL);

    // instance
    object = amxd_dm_findf(&dm, "MyObject.ChildObject.1");
    assert_ptr_not_equal(object, NULL);
    assert_int_not_equal(amxd_object_add_param(object, param), 0);
    assert_ptr_equal(amxd_object_get_param_def(object, "TestParam"), NULL);
    assert_ptr_equal(amxd_param_get_owner(param), NULL);

    amxd_param_delete(&param);
}

void test_can_not_set_key_attr_on_params_of(UNUSED void** state) {
    amxd_object_t* object = NULL;
    amxd_param_t* param = NULL;

    // singleton
    object = amxd_dm_findf(&dm, "MyObject.TestSingleton");
    assert_ptr_not_equal(object, NULL);
    param = amxd_object_get_param_def(object, "Param1");
    assert_ptr_not_equal(param, NULL);
    assert_int_not_equal(amxd_param_set_attr(param, amxd_pattr_key, true), 0);

    // mib
    object = amxd_dm_get_mib(&dm, "TestMib");
    assert_ptr_not_equal(object, NULL);
    param = amxd_object_get_param_def(object, "Param1");
    assert_ptr_not_equal(param, NULL);
    assert_int_not_equal(amxd_param_set_attr(param, amxd_pattr_key, true), 0);

    // instance
    object = amxd_dm_findf(&dm, "MyObject.ChildObject.1");
    assert_ptr_not_equal(object, NULL);
    param = amxd_object_get_param_def(object, "Param2");
    assert_ptr_not_equal(param, NULL);
    assert_int_not_equal(amxd_param_set_attr(param, amxd_pattr_key, true), 0);

    // template with instances
    object = amxd_dm_findf(&dm, "MyObject.ChildObject");
    assert_ptr_not_equal(object, NULL);
    param = amxd_object_get_param_def(object, "Param2");
    assert_ptr_not_equal(param, NULL);
    assert_int_not_equal(amxd_param_set_attr(param, amxd_pattr_key, true), 0);
}

void test_object_has_key_parameters(UNUSED void** state) {
    amxd_object_t* object = NULL;

    object = amxd_dm_findf(&dm, "MyObject.TestSingleton");
    assert_ptr_not_equal(object, NULL);
    assert_false(amxd_object_has_keys(object));

    object = amxd_dm_get_mib(&dm, "TestMib");
    assert_ptr_not_equal(object, NULL);
    assert_false(amxd_object_has_keys(object));

    object = amxd_dm_findf(&dm, "MyObject.ChildObject.1");
    assert_ptr_not_equal(object, NULL);
    assert_true(amxd_object_has_keys(object));

    object = amxd_dm_findf(&dm, "MyObject.ChildObject");
    assert_ptr_not_equal(object, NULL);
    assert_true(amxd_object_has_keys(object));
}

void test_key_parameter_values_are_immutable(UNUSED void** state) {
    amxd_object_t* object = NULL;

    object = amxd_dm_findf(&dm, "MyObject.ChildObject.1");
    assert_ptr_not_equal(object, NULL);
    assert_true(amxd_object_has_keys(object));

    assert_int_not_equal(amxd_object_set_value(cstring_t, object, "ParamExtra", "MyNewValue"), 0);
    assert_int_not_equal(amxd_object_set_value(cstring_t, object, "Param1", "MyNewValue"), 0);
    assert_int_equal(amxd_object_set_value(uint32_t, object, "Param3", 500), 0);
}

void test_can_build_key_expression(UNUSED void** state) {
    amxc_var_t key_params;
    amxp_expr_t* expr = NULL;
    amxd_object_t* object = NULL;

    amxc_var_init(&key_params);
    object = amxd_dm_findf(&dm, "MyObject.ChildObject");

    amxc_var_set_type(&key_params, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &key_params, "Param1", "test");
    amxc_var_add_key(cstring_t, &key_params, "ParamExtra", "test");
    assert_int_equal(amxd_object_new_key_expr(object, &expr, &key_params), 0);
    assert_ptr_not_equal(expr, NULL);
    assert_false(amxd_object_has_matching_instances(object, expr));

    amxp_expr_delete(&expr);
    amxc_var_clean(&key_params);

    amxc_var_set_type(&key_params, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &key_params, "Param1", "TheKeyValue");
    amxc_var_add_key(cstring_t, &key_params, "ParamExtra", "TheKeyValue");
    assert_int_equal(amxd_object_new_key_expr(object, &expr, &key_params), 0);
    assert_ptr_not_equal(expr, NULL);
    assert_true(amxd_object_has_matching_instances(object, expr));

    amxp_expr_delete(&expr);
    amxc_var_clean(&key_params);
}

void test_amxd_object_add_instance_verifies_keys(UNUSED void** state) {
    amxd_object_t* object = NULL;
    amxd_object_t* instance = NULL;
    amxc_var_t key_params;
    amxc_var_t* param1 = NULL;
    amxc_var_t* paramextra = NULL;

    amxc_var_init(&key_params);
    amxc_var_set_type(&key_params, AMXC_VAR_ID_HTABLE);
    param1 = amxc_var_add_key(cstring_t, &key_params, "Param1", "TheKeyValue");
    paramextra = amxc_var_add_key(cstring_t, &key_params, "ParamExtra", "TheKeyValue");

    object = amxd_dm_findf(&dm, "MyObject.ChildObject");
    assert_int_not_equal(amxd_object_add_instance(&instance, object, NULL, 0, &key_params), 0);
    assert_ptr_equal(instance, NULL);

    amxc_var_set(cstring_t, param1, "Unique");
    assert_int_equal(amxd_object_add_instance(&instance, object, NULL, 0, &key_params), 0);
    assert_ptr_not_equal(instance, NULL);

    amxc_var_set(cstring_t, paramextra, "Unique");
    assert_int_equal(amxd_object_add_instance(NULL, object, NULL, 0, &key_params), 0);

    amxc_var_clean(&key_params);
}

void test_can_check_object_has_key_parameters(UNUSED void** state) {
    amxd_object_t* object = NULL;

    object = amxd_dm_findf(&dm, "MyObject.ChildObject");
    assert_true(amxd_object_has_keys(object));

    object = amxd_dm_findf(&dm, "MyObject.TestSingleton");
    assert_false(amxd_object_has_keys(object));

    object = amxd_dm_findf(&dm, "MyObject.ChildObject.1");
    assert_true(amxd_object_has_keys(object));

    assert_false(amxd_object_has_keys(NULL));
}

void test_can_create_instance_with_unique_keys(UNUSED void** state) {
    amxd_object_t* object = NULL;
    amxc_var_t key_params;
    amxd_object_t* instance = NULL;
    amxc_var_t* uk1 = NULL;
    amxc_var_t* uk2 = NULL;
    amxc_var_t* k1 = NULL;
    amxc_var_t* k2 = NULL;
    amxc_var_t* p1 = NULL;

    amxc_var_init(&key_params);
    amxc_var_set_type(&key_params, AMXC_VAR_ID_HTABLE);

    object = amxd_dm_findf(&dm, "MyObject.UKeyObject");
    assert_true(amxd_object_has_keys(object));

    uk1 = amxc_var_add_key(cstring_t, &key_params, "UKey1", "U1");
    uk2 = amxc_var_add_key(cstring_t, &key_params, "UKey2", "U2");
    k1 = amxc_var_add_key(cstring_t, &key_params, "KeyParam1", "U3");
    k2 = amxc_var_add_key(cstring_t, &key_params, "KeyParam2", "U4");
    p1 = amxc_var_add_key(cstring_t, &key_params, "Param1", "*");
    amxc_var_add_key(cstring_t, &key_params, "Param2", "]");

    assert_int_equal(amxd_object_add_instance(&instance, object, NULL, 0, &key_params), 0);
    assert_non_null(instance);
    assert_int_not_equal(amxd_object_add_instance(&instance, object, NULL, 0, &key_params), 0);

    amxc_var_set(cstring_t, uk1, "U2");
    amxc_var_set(cstring_t, uk2, "U1");
    amxc_var_set(cstring_t, k1, "U4");
    amxc_var_set(cstring_t, k2, "U3");
    amxc_var_set(cstring_t, p1, "[");
    assert_int_equal(amxd_object_add_instance(&instance, object, NULL, 0, &key_params), 0);
    assert_non_null(instance);

    amxc_var_set(cstring_t, uk1, "U9");
    amxc_var_set(cstring_t, uk2, "U9");
    amxc_var_set(cstring_t, k1, "U4");
    amxc_var_set(cstring_t, k2, "U2");
    amxc_var_set(cstring_t, p1, "[.*]");
    assert_int_equal(amxd_object_add_instance(&instance, object, NULL, 0, &key_params), 0);
    assert_non_null(instance);

    amxc_var_clean(&key_params);
}

void test_can_find_object_with_keys(UNUSED void** state) {
    amxd_object_t* object = amxd_dm_findf(&dm, "MyObject.UKeyObject.[UKey1=='U2']");
    assert_non_null(object);

    object = amxd_dm_findf(&dm, "MyObject.UKeyObject.[UKey2=='U2']");
    assert_non_null(object);

    object = amxd_dm_findf(&dm, "MyObject.UKeyObject.[KeyParam1=='U3'&&KeyParam2=='U4']");
    assert_non_null(object);

    object = amxd_dm_findf(&dm, "MyObject.UKeyObject.[KeyParam1=='U4'&&KeyParam2=='U3']");
    assert_non_null(object);

    object = amxd_dm_findf(&dm, "MyObject.UKeyObject.[Param1=='*']");
    assert_non_null(object);

    object = amxd_dm_findf(&dm, "MyObject.UKeyObject.[Param1=='[']");
    assert_non_null(object);

    object = amxd_dm_findf(&dm, "MyObject.UKeyObject.[Param1=='[.*]']");
    assert_non_null(object);
}

void test_find_fails_with_invalid_expression_part(UNUSED void** state) {
    amxd_object_t* object = amxd_dm_findf(&dm, "MyObject.UKeyObject.[UKey1!>'U2\']");
    assert_null(object);
    assert_int_equal(amxd_dm_get_status(&dm), amxd_status_invalid_path);

    object = amxd_dm_findf(&dm, "MyObject.UKeyObject.[]");
    assert_null(object);
    assert_int_equal(amxd_dm_get_status(&dm), amxd_status_invalid_path);

    object = amxd_dm_findf(&dm, "MyObject.UKeyObject.*");
    assert_null(object);
    assert_int_equal(amxd_dm_get_status(&dm), amxd_status_invalid_path);

    object = amxd_dm_findf(&dm, "MyObject.UKeyObject.[NotExisiting>400]");
    assert_null(object);
    assert_int_equal(amxd_dm_get_status(&dm), amxd_status_invalid_path);

    object = amxd_dm_findf(&dm, "MyObject.UKeyObject.[UKey2==100");
    assert_null(object);
    assert_int_equal(amxd_dm_get_status(&dm), amxd_status_invalid_path);

    object = amxd_dm_findf(&dm, "MyObject.UKeyObject.[KeyParam1=='U4']");
    assert_null(object);
    assert_int_equal(amxd_dm_get_status(&dm), amxd_status_duplicate);

    object = amxd_dm_findf(&dm, "MyObject.UKeyObject.[UKey1=='Z999']");
    assert_null(object);
    assert_int_equal(amxd_dm_get_status(&dm), amxd_status_ok);

    object = amxd_dm_findf(&dm, "MyObject.UKeyObject.[2A]");
    assert_null(object);
    assert_int_equal(amxd_dm_get_status(&dm), amxd_status_invalid_path);

    object = amxd_dm_findf(&dm, "MyObject.[2A]");
    assert_null(object);
    assert_int_equal(amxd_dm_get_status(&dm), amxd_status_invalid_path);

    object = amxd_dm_findf(&dm, "MyObject.[Param1==\"TestValue\"]");
    assert_null(object);
    assert_int_equal(amxd_dm_get_status(&dm), amxd_status_invalid_path);

    object = amxd_dm_findf(&dm, "MyObject.UKeyObject.[Param2==']']");
    assert_null(object);
    assert_int_equal(amxd_dm_get_status(&dm), amxd_status_duplicate);
}

void test_find_fails_with_wildcard(UNUSED void** state) {
    amxd_object_t* object = NULL;

    object = amxd_dm_findf(&dm, "MyObject.UKeyObject.*");
    assert_null(object);
    assert_int_equal(amxd_dm_get_status(&dm), amxd_status_invalid_path);
}

void test_can_create_instance_with_alias(UNUSED void** state) {
    amxd_object_t* object = NULL;
    amxd_object_t* instance = NULL;
    char* text = NULL;
    amxc_var_t key_params;

    amxc_var_init(&key_params);
    amxc_var_set_type(&key_params, AMXC_VAR_ID_HTABLE);

    object = amxd_dm_findf(&dm, "MyObject.AliasObject");
    assert_true(amxd_object_has_keys(object));

    assert_int_equal(amxd_object_new_instance(&instance, object, "SillyName", 0, NULL), 0);
    assert_non_null(instance);
    assert_string_equal(amxd_object_get_name(instance, AMXD_OBJECT_NAMED), "SillyName");
    text = amxd_object_get_value(cstring_t, instance, "Alias", NULL);
    assert_non_null(text);
    assert_string_equal(text, "SillyName");
    free(text);

    assert_int_equal(amxd_object_new_instance(&instance, object, NULL, 0, NULL), 0);
    assert_non_null(instance);
    assert_string_equal(amxd_object_get_name(instance, AMXD_OBJECT_NAMED), "cpe-AliasObject-2");
    text = amxd_object_get_value(cstring_t, instance, "Alias", NULL);
    assert_non_null(text);
    assert_string_equal(text, "cpe-AliasObject-2");
    free(text);

    amxc_var_add_key(cstring_t, &key_params, "Alias", "T&T-%CPE");
    assert_int_equal(amxd_object_add_instance(&instance, object, NULL, 0, &key_params), 0);
    assert_non_null(instance);
    assert_string_equal(amxd_object_get_name(instance, AMXD_OBJECT_NAMED), "T&T-%CPE");
    text = amxd_object_get_value(cstring_t, instance, "Alias", NULL);
    assert_non_null(text);
    assert_string_equal(text, "T&T-%CPE");
    free(text);

    amxc_var_clean(&key_params);
}

void test_can_create_instance_with_non_key_alias(UNUSED void** state) {
    amxd_object_t* object = NULL;
    amxd_object_t* instance = NULL;
    char* text = NULL;
    amxc_var_t key_params;

    amxc_var_init(&key_params);
    amxc_var_set_type(&key_params, AMXC_VAR_ID_HTABLE);

    object = amxd_dm_findf(&dm, "MyObject.FakeAliasObject");
    assert_false(amxd_object_has_keys(object));

    assert_int_equal(amxd_object_new_instance(&instance, object, "SillyName", 0, NULL), 0);
    assert_non_null(instance);
    assert_string_equal(amxd_object_get_name(instance, AMXD_OBJECT_NAMED), "SillyName");
    text = amxd_object_get_value(cstring_t, instance, "Alias", NULL);
    assert_string_equal(text, "");
    free(text);

    assert_int_equal(amxd_object_new_instance(&instance, object, NULL, 0, NULL), 0);
    assert_non_null(instance);
    assert_string_equal(amxd_object_get_name(instance, AMXD_OBJECT_NAMED), "2");
    text = amxd_object_get_value(cstring_t, instance, "Alias", NULL);
    assert_string_equal(text, "");
    free(text);

    amxc_var_add_key(cstring_t, &key_params, "Alias", "SillyName");
    assert_int_equal(amxd_object_add_instance(&instance, object, NULL, 0, &key_params), 0);
    assert_non_null(instance);
    assert_string_equal(amxd_object_get_name(instance, AMXD_OBJECT_NAMED), "3");
    text = amxd_object_get_value(cstring_t, instance, "Alias", NULL);
    assert_non_null(text);
    assert_string_equal(text, "SillyName");
    free(text);

    amxc_var_clean(&key_params);
}

void test_creation_fails_when_alias_value_is_wrong_type(UNUSED void** state) {
    amxd_object_t* object = NULL;
    amxd_object_t* instance = NULL;
    amxc_var_t key_params;
    amxc_var_t* alias = NULL;

    amxc_var_init(&key_params);
    amxc_var_set_type(&key_params, AMXC_VAR_ID_HTABLE);

    object = amxd_dm_findf(&dm, "MyObject.AliasObject");
    assert_true(amxd_object_has_keys(object));

    alias = amxc_var_add_key(bool, &key_params, "Alias", true);
    assert_int_not_equal(amxd_object_add_instance(&instance, object, NULL, 0, &key_params), 0);
    assert_null(instance);

    amxc_var_set(ssv_string_t, alias, "YAA");
    assert_int_equal(amxd_object_add_instance(&instance, object, NULL, 0, &key_params), 0);

    amxc_var_set(uint32_t, alias, 1024);
    assert_int_not_equal(amxd_object_add_instance(&instance, object, NULL, 0, &key_params), 0);
    assert_null(instance);

    amxc_var_set(csv_string_t, alias, "YAA2");
    assert_int_equal(amxd_object_add_instance(&instance, object, NULL, 0, &key_params), 0);

    amxc_var_clean(&key_params);
}

void test_creation_fails_when_alias_starts_with_number(UNUSED void** state) {
    amxd_object_t* object = NULL;
    amxd_object_t* instance = NULL;

    amxc_var_t key_params;

    amxc_var_init(&key_params);
    amxc_var_set_type(&key_params, AMXC_VAR_ID_HTABLE);

    object = amxd_dm_findf(&dm, "MyObject.AliasObject");
    assert_true(amxd_object_has_keys(object));

    assert_int_not_equal(amxd_object_new_instance(&instance, object, "2nd-SillyName", 0, NULL), 0);
    assert_null(instance);

    amxc_var_add_key(cstring_t, &key_params, "Alias", "3th-SillyName");
    assert_int_not_equal(amxd_object_add_instance(&instance, object, NULL, 0, &key_params), 0);
    assert_null(instance);

    amxc_var_clean(&key_params);
}

void test_can_find_instances_with_alias(UNUSED void** state) {
    amxd_object_t* object = NULL;
    amxd_object_t* instance = NULL;
    amxd_object_t* finstance = NULL;
    char* text = NULL;

    object = amxd_dm_findf(&dm, "MyObject.AliasObject");
    assert_true(amxd_object_has_keys(object));

    assert_int_equal(amxd_object_new_instance(&instance, object, "Unique.Alias.Name", 0, NULL), 0);
    assert_non_null(instance);
    assert_string_equal(amxd_object_get_name(instance, AMXD_OBJECT_NAMED), "Unique.Alias.Name");
    text = amxd_object_get_value(cstring_t, instance, "Alias", NULL);
    assert_non_null(text);
    assert_string_equal(text, "Unique.Alias.Name");
    free(text);

    finstance = amxd_dm_findf(&dm, "MyObject.AliasObject.Unique.Alias.Name");
    assert_null(finstance);

    finstance = amxd_dm_findf(&dm, "MyObject.AliasObject.\"Unique.Alias.Name\"");
    assert_null(finstance);

    finstance = amxd_dm_findf(&dm, "MyObject.AliasObject.'Unique.Alias.Name'");
    assert_null(finstance);

    finstance = amxd_dm_findf(&dm, "MyObject.AliasObject.[Unique.Alias.Name]");
    assert_non_null(finstance);
    assert_ptr_equal(finstance, instance);

    finstance = amxd_dm_findf(&dm, "MyObject.AliasObject.[Alias == 'Unique.Alias.Name']");
    assert_non_null(finstance);
    assert_ptr_equal(finstance, instance);
}

void test_can_create_instances_with_keys_that_has_validation(UNUSED void** state) {
    amxd_trans_t transaction;
    amxd_object_t* object = NULL;

    amxd_trans_init(&transaction);
    amxd_trans_select_pathf(&transaction, "MyObject.KeyValidateObject");
    amxd_trans_add_inst(&transaction, 1, NULL);
    amxd_trans_set_value(cstring_t, &transaction, "Param1", "UDP");
    assert_int_equal(amxd_trans_apply(&transaction, &dm), 0);
    object = amxd_dm_findf(&dm, "MyObject.KeyValidateObject.1");
    assert_non_null(object);

    amxd_trans_clean(&transaction);
}

void test_can_change_mutable_key(UNUSED void** state) {
    amxd_trans_t transaction;
    amxd_object_t* object = NULL;

    amxd_trans_init(&transaction);
    amxd_trans_select_pathf(&transaction, "MyObject.KeyValidateObject.1.");
    amxd_trans_set_value(cstring_t, &transaction, "Param1", "TCP");
    assert_int_equal(amxd_trans_apply(&transaction, &dm), 0);
    object = amxd_dm_findf(&dm, "MyObject.KeyValidateObject.1");
    assert_non_null(object);

    amxd_trans_clean(&transaction);
}

void test_adding_duplicate_fails(UNUSED void** state) {
    amxd_trans_t transaction;
    amxd_object_t* object = NULL;

    amxd_trans_init(&transaction);
    amxd_trans_select_pathf(&transaction, "MyObject.KeyValidateObject");
    amxd_trans_add_inst(&transaction, 2, NULL);
    amxd_trans_set_value(cstring_t, &transaction, "Param1", "TCP");
    assert_int_not_equal(amxd_trans_apply(&transaction, &dm), 0);
    object = amxd_dm_findf(&dm, "MyObject.KeyValidateObject.2.");
    assert_null(object);

    amxd_trans_clean(&transaction);
}

void test_changing_mutable_key_fails_if_duplicate(UNUSED void** state) {
    amxd_trans_t transaction;
    amxd_object_t* object = NULL;

    amxd_trans_init(&transaction);
    amxd_trans_select_pathf(&transaction, "MyObject.KeyValidateObject");
    amxd_trans_add_inst(&transaction, 2, NULL);
    amxd_trans_set_value(cstring_t, &transaction, "Param1", "UDP");
    assert_int_equal(amxd_trans_apply(&transaction, &dm), 0);
    object = amxd_dm_findf(&dm, "MyObject.KeyValidateObject.2.");
    assert_non_null(object);
    amxd_trans_clean(&transaction);

    amxd_trans_init(&transaction);
    amxd_trans_select_pathf(&transaction, "MyObject.KeyValidateObject.1.");
    amxd_trans_set_value(cstring_t, &transaction, "Param1", "UDP");
    assert_int_not_equal(amxd_trans_apply(&transaction, &dm), 0);
    object = amxd_dm_findf(&dm, "MyObject.KeyValidateObject.1");
    assert_non_null(object);
    amxd_trans_clean(&transaction);

    amxd_trans_init(&transaction);
    amxd_trans_select_pathf(&transaction, "MyObject.KeyValidateObject.2.");
    amxd_trans_set_value(cstring_t, &transaction, "Param1", "TCP");
    assert_int_not_equal(amxd_trans_apply(&transaction, &dm), 0);
    object = amxd_dm_findf(&dm, "MyObject.KeyValidateObject.2");
    assert_non_null(object);

    amxd_trans_clean(&transaction);

}
