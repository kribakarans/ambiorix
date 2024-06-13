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
#include <amxd/amxd_action.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_transaction.h>
#include <amxd/amxd_parameter.h>
#include <amxd/amxd_function.h>

#include "test_amxd_default_functions.h"

void test_amxd_get_function_all(UNUSED void** state) {
    amxd_object_t* object = NULL;
    amxd_object_t* template = NULL;
    amxd_object_t* instance = NULL;
    amxc_var_t retval;
    amxc_var_t args;
    amxc_var_t* value = NULL;
    amxc_var_t* obj_params = NULL;

    amxc_var_init(&args);
    amxc_var_init(&retval);

    template = test_build_dm();
    object = amxd_object_get_child(template, "child");
    assert_int_equal(amxd_object_new_instance(&instance, template, "Instance1", 0, NULL), 0);
    assert_int_equal(amxd_object_new_instance(&instance, template, "Instance2", 0, NULL), 0);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(uint32_t, &args, "depth", 1);
    amxc_var_add_key(uint32_t, &args, "access", amxd_dm_access_public);
    assert_int_equal(amxd_object_invoke_function(template, "_get", &args, &retval), 0);
    assert_int_equal(amxc_var_type_of(&retval), AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_htable_size(amxc_var_constcast(amxc_htable_t, &retval)), 2);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(uint32_t, &args, "depth", 1);
    amxc_var_add_key(uint32_t, &args, "access", amxd_dm_access_protected);
    assert_int_equal(amxd_object_invoke_function(template, "_get", &args, &retval), 0);
    assert_int_equal(amxc_var_type_of(&retval), AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_htable_size(amxc_var_constcast(amxc_htable_t, &retval)), 3);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxd_object_invoke_function(instance, "_get", &args, &retval), 0);
    assert_int_equal(amxc_var_type_of(&retval), AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_htable_size(amxc_var_constcast(amxc_htable_t, &retval)), 1);
    obj_params = amxc_var_get_key(&retval, "parent.2.", AMXC_VAR_FLAG_DEFAULT);
    assert_int_equal(amxc_var_type_of(obj_params), AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_htable_size(amxc_var_constcast(amxc_htable_t, obj_params)), 3);
    value = amxc_var_get_path(obj_params, "inst_param", AMXC_VAR_FLAG_DEFAULT);
    assert_ptr_not_equal(value, NULL);
    value = amxc_var_get_path(obj_params, "param", AMXC_VAR_FLAG_DEFAULT);
    assert_ptr_not_equal(value, NULL);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    assert_int_not_equal(amxd_object_invoke_function(object, "_get", &args, &retval), 0);
    amxc_var_dump(&retval, STDOUT_FILENO);

    object = amxd_object_get_child(instance, "child");
    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxd_object_invoke_function(object, "_get", &args, &retval), 0);
    assert_int_equal(amxc_htable_size(amxc_var_constcast(amxc_htable_t, &retval)), 1); // 1 object
    obj_params = amxc_var_get_key(&retval, "parent.2.child.", AMXC_VAR_FLAG_DEFAULT);
    assert_int_equal(amxc_var_type_of(obj_params), AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_htable_size(amxc_var_constcast(amxc_htable_t, obj_params)), 2); // 2 parameters
    value = amxc_var_get_path(obj_params, "child_param2", AMXC_VAR_FLAG_DEFAULT);
    assert_ptr_not_equal(value, NULL);
    value = amxc_var_get_path(obj_params, "child_param3", AMXC_VAR_FLAG_DEFAULT);
    assert_ptr_not_equal(value, NULL);
    value = amxc_var_get_path(obj_params, "child_param", AMXC_VAR_FLAG_DEFAULT);
    assert_ptr_equal(value, NULL);

    amxc_var_clean(&args);
    amxc_var_clean(&retval);
    test_clean_dm();
}

void test_amxd_get_function_filtered(UNUSED void** state) {
    amxd_object_t* object = NULL;
    amxd_object_t* template = NULL;
    amxd_object_t* instance = NULL;
    amxc_var_t retval;
    amxc_var_t args;
    amxc_var_t* value = NULL;
    amxc_var_t* params = NULL;
    amxc_var_t* obj_params = NULL;

    amxc_var_init(&args);
    amxc_var_init(&retval);

    template = test_build_dm();
    assert_int_equal(amxd_object_new_instance(&instance, template, "Instance1", 0, NULL), 0);
    assert_int_equal(amxd_object_new_instance(&instance, template, "Instance2", 0, NULL), 0);
    object = amxd_object_get_child(instance, "child");

    assert_int_equal(amxd_object_new_instance(&instance, template, "test.dot.", 0, NULL), 0);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    params = amxc_var_add_key(amxc_llist_t, &args, "parameters", NULL);
    amxc_var_add(cstring_t, params, "param");
    amxc_var_add_key(uint32_t, &args, "depth", 1);
    assert_int_not_equal(amxd_object_invoke_function(template, "_get", &args, &retval), 0);
    assert_int_equal(amxc_var_type_of(&retval), AMXC_VAR_ID_NULL);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    params = amxc_var_add_key(amxc_llist_t, &args, "parameters", NULL);
    amxc_var_add(cstring_t, params, "child_param2");
    assert_int_equal(amxd_object_invoke_function(object, "_get", &args, &retval), 0);
    assert_int_equal(amxc_var_type_of(&retval), AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_htable_size(amxc_var_constcast(amxc_htable_t, &retval)), 1); // 1 object
    obj_params = amxc_var_get_key(&retval, "parent.2.child.", AMXC_VAR_FLAG_DEFAULT);
    assert_int_equal(amxc_var_type_of(obj_params), AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_htable_size(amxc_var_constcast(amxc_htable_t, obj_params)), 1); // 1 parameter
    value = amxc_var_get_path(obj_params, "child_param2", AMXC_VAR_FLAG_DEFAULT);
    assert_ptr_not_equal(value, NULL);
    value = amxc_var_get_path(obj_params, "child_param3", AMXC_VAR_FLAG_DEFAULT);
    assert_ptr_equal(value, NULL);
    value = amxc_var_get_path(obj_params, "child_param", AMXC_VAR_FLAG_DEFAULT);
    assert_ptr_equal(value, NULL);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    params = amxc_var_add_key(amxc_llist_t, &args, "parameters", NULL);
    amxc_var_add(cstring_t, params, "inst_param");
    assert_int_equal(amxd_object_invoke_function(instance, "_get", &args, &retval), 0);
    assert_int_equal(amxc_var_type_of(&retval), AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_htable_size(amxc_var_constcast(amxc_htable_t, &retval)), 1); // 1 object
    obj_params = amxc_var_get_key(&retval, "parent.3.", AMXC_VAR_FLAG_DEFAULT);
    assert_int_equal(amxc_var_type_of(obj_params), AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_htable_size(amxc_var_constcast(amxc_htable_t, obj_params)), 1); // 0 parameters
    value = amxc_var_get_path(obj_params, "inst_param", AMXC_VAR_FLAG_DEFAULT);
    assert_ptr_not_equal(value, NULL);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    params = amxc_var_add_key(amxc_llist_t, &args, "parameters", NULL);
    amxc_var_add(cstring_t, params, "Alias");
    assert_int_equal(amxd_object_invoke_function(instance, "_get", &args, &retval), 0);
    amxc_var_dump(&retval, STDOUT_FILENO);

    object = amxd_object_findf(template, ".[Alias == 'test.dot.'].");
    assert_non_null(object);
    object = amxd_object_findf(template, ".[test.dot.].");
    assert_non_null(object);
    object = amxd_object_findf(template, ".test.dot.");
    assert_null(object);

    amxc_var_clean(&args);
    amxc_var_clean(&retval);
    test_clean_dm();
}

void test_amxd_get_function_filtered_invalid(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxd_object_t* instance = NULL;
    amxc_var_t retval;
    amxc_var_t args;
    amxc_var_t* params = NULL;

    amxc_var_init(&args);
    amxc_var_init(&retval);

    template = test_build_dm();
    assert_int_equal(amxd_object_new_instance(&instance, template, "Instance1", 0, NULL), 0);
    assert_int_equal(amxd_object_new_instance(&instance, template, "Instance2", 0, NULL), 0);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    params = amxc_var_add_key(amxc_llist_t, &args, "parameters", NULL);
    amxc_var_add(uint32_t, params, 1234);
    assert_int_not_equal(amxd_object_invoke_function(template, "_get", &args, &retval), 0);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    params = amxc_var_add_key(amxc_llist_t, &args, "parameters", NULL);
    amxc_var_add(cstring_t, params, "invalid_name");
    assert_int_not_equal(amxd_object_invoke_function(template, "_get", &args, &retval), 0);

    amxc_var_clean(&args);
    amxc_var_clean(&retval);
    test_clean_dm();
}

void test_amxd_get_function_path(UNUSED void** state) {
    amxd_object_t* parent = NULL;
    amxc_var_t retval;
    amxc_var_t args;
    amxd_trans_t trans;
    amxd_dm_t* dm = NULL;

    amxc_var_init(&args);
    amxc_var_init(&retval);
    amxd_trans_init(&trans);

    parent = test_build_dm();
    dm = amxd_object_get_dm(parent);
    amxd_trans_set_attr(&trans, amxd_tattr_change_priv, true);
    amxd_trans_select_pathf(&trans, "parent");
    amxd_trans_add_inst(&trans, 0, NULL);
    amxd_trans_select_pathf(&trans, ".child");
    amxd_trans_set_value(cstring_t, &trans, "child_param", "Test1");
    amxd_trans_set_value(cstring_t, &trans, "child_param2", "true");
    amxd_trans_set_value(cstring_t, &trans, "child_param3", "1111");
    amxd_trans_select_pathf(&trans, "parent");
    amxd_trans_add_inst(&trans, 0, NULL);
    amxd_trans_select_pathf(&trans, ".child");
    amxd_trans_set_value(cstring_t, &trans, "child_param", "Test2");
    amxd_trans_set_value(cstring_t, &trans, "child_param2", "false");
    amxd_trans_set_value(cstring_t, &trans, "child_param3", "1111");
    assert_int_equal(amxd_trans_apply(&trans, dm), 0);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &args, "rel_path", "[child.child_param2 == true].");
    assert_int_equal(amxd_object_invoke_function(parent, "_get", &args, &retval), 0);
    assert_int_equal(amxc_var_type_of(&retval), AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_htable_size(amxc_var_constcast(amxc_htable_t, &retval)), 1); // 1 object

    amxc_var_add_key(cstring_t, &args, "rel_path", "[child.child_param3 > 100].");
    assert_int_equal(amxd_object_invoke_function(parent, "_get", &args, &retval), 0);
    assert_int_equal(amxc_var_type_of(&retval), AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_htable_size(amxc_var_constcast(amxc_htable_t, &retval)), 2); // 2 objects

    amxc_var_add_key(cstring_t, &args, "rel_path", "[child.child_param3 > 100]");
    assert_int_not_equal(amxd_object_invoke_function(parent, "_get", &args, &retval), 0);
    assert_int_equal(amxc_var_type_of(&retval), AMXC_VAR_ID_NULL);

    amxc_var_add_key(cstring_t, &args, "rel_path", "[child.child_param3 < 100].");
    assert_int_equal(amxd_object_invoke_function(parent, "_get", &args, &retval), amxd_status_ok);
    assert_int_equal(amxc_var_type_of(&retval), AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_htable_size(amxc_var_constcast(amxc_htable_t, &retval)), 0);

    amxc_var_add_key(cstring_t, &args, "rel_path", "1.");
    assert_int_equal(amxd_object_invoke_function(parent, "_get", &args, &retval), 0);
    assert_int_equal(amxc_var_type_of(&retval), AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_htable_size(amxc_var_constcast(amxc_htable_t, &retval)), 1); // 1 objects

    amxc_var_add_key(cstring_t, &args, "rel_path", "1");
    assert_int_not_equal(amxd_object_invoke_function(parent, "_get", &args, &retval), 0);
    amxc_var_dump(&retval, STDOUT_FILENO);
    assert_int_equal(amxc_var_type_of(&retval), AMXC_VAR_ID_NULL);

    amxc_var_add_key(cstring_t, &args, "rel_path", "1.child.child_param3");
    assert_int_equal(amxd_object_invoke_function(parent, "_get", &args, &retval), 0);
    assert_int_equal(amxc_var_type_of(&retval), AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_htable_size(amxc_var_constcast(amxc_htable_t, &retval)), 1); // 1 objects

    amxc_var_clean(&args);
    amxc_var_clean(&retval);
    amxd_trans_clean(&trans);
    test_clean_dm();
}

void test_amxd_get_function_with_cb(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxd_object_t* instance = NULL;
    amxc_var_t retval;
    amxc_var_t args;
    amxc_var_t* value = NULL;
    amxc_var_t* obj_params = NULL;

    amxc_var_init(&args);
    amxc_var_init(&retval);

    template = test_build_dm();
    assert_int_equal(amxd_object_add_action_cb(template, action_object_read, amxd_action_object_read, NULL), 0);
    assert_int_equal(amxd_object_new_instance(&instance, template, "Instance1", 0, NULL), 0);
    assert_int_equal(amxd_object_new_instance(&instance, template, "Instance2", 0, NULL), 0);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(uint32_t, &args, "depth", 1);
    amxc_var_add_key(uint32_t, &args, "access", amxd_dm_access_public);
    assert_int_equal(amxd_object_invoke_function(template, "_get", &args, &retval), 0);
    assert_int_equal(amxc_var_type_of(&retval), AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_htable_size(amxc_var_constcast(amxc_htable_t, &retval)), 2);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(uint32_t, &args, "depth", 1);
    amxc_var_add_key(uint32_t, &args, "access", amxd_dm_access_protected);
    assert_int_equal(amxd_object_invoke_function(template, "_get", &args, &retval), 0);
    assert_int_equal(amxc_var_type_of(&retval), AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_htable_size(amxc_var_constcast(amxc_htable_t, &retval)), 3);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxd_object_invoke_function(instance, "_get", &args, &retval), 0);
    assert_int_equal(amxc_var_type_of(&retval), AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_htable_size(amxc_var_constcast(amxc_htable_t, &retval)), 1);
    obj_params = amxc_var_get_key(&retval, "parent.2.", AMXC_VAR_FLAG_DEFAULT);
    assert_int_equal(amxc_var_type_of(obj_params), AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_htable_size(amxc_var_constcast(amxc_htable_t, obj_params)), 3);
    value = amxc_var_get_path(obj_params, "inst_param", AMXC_VAR_FLAG_DEFAULT);
    assert_ptr_not_equal(value, NULL);
    value = amxc_var_get_path(obj_params, "param", AMXC_VAR_FLAG_DEFAULT);
    assert_ptr_not_equal(value, NULL);

    amxc_var_clean(&args);
    amxc_var_clean(&retval);
    test_clean_dm();
}

void test_amxd_get_function_recursive_singleton(UNUSED void** state) {
    amxd_object_t* root = test_build_dm2();
    amxc_var_t args;
    amxc_var_t retval;
    amxc_var_t* var_obj = NULL;
    amxc_var_t* var_sub_obj = NULL;

    amxc_var_init(&args);
    amxc_var_init(&retval);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(int32_t, &args, "depth", INT32_MAX);
    assert_int_equal(amxd_object_invoke_function(root, "_get", &args, &retval), 0);
    amxc_var_dump(&retval, STDOUT_FILENO);

    var_obj = amxc_var_get_key(&retval, "MyRoot.", AMXC_VAR_FLAG_DEFAULT);
    assert_int_equal(amxc_var_type_of(var_obj), AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_htable_size(amxc_var_constcast(amxc_htable_t, var_obj)), 3); // 3 parameters

    var_sub_obj = amxc_var_get_key(&retval, "MyRoot.MyChild.1.", AMXC_VAR_FLAG_DEFAULT);
    assert_int_equal(amxc_var_type_of(var_sub_obj), AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_htable_size(amxc_var_constcast(amxc_htable_t, var_sub_obj)), 4);
    var_sub_obj = amxc_var_get_key(&retval, "MyRoot.MyChild.1.SubChild.", AMXC_VAR_FLAG_DEFAULT);
    assert_int_equal(amxc_var_type_of(var_sub_obj), AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_htable_size(amxc_var_constcast(amxc_htable_t, var_sub_obj)), 3);
    var_sub_obj = amxc_var_get_key(&retval, "MyRoot.MyChild.1.SubChild.SubTemplate.1.", AMXC_VAR_FLAG_DEFAULT);
    assert_int_equal(amxc_var_type_of(var_sub_obj), AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_htable_size(amxc_var_constcast(amxc_htable_t, var_sub_obj)), 3);

    amxc_var_clean(&args);
    amxc_var_clean(&retval);
    test_clean_dm();
}

void test_amxd_get_function_recursive_template(UNUSED void** state) {
    amxd_object_t* root = test_build_dm2();
    amxc_var_t args;
    amxc_var_t retval;
    amxc_var_t* var_obj = NULL;
    amxc_var_t* var_sub_obj = NULL;

    amxc_var_init(&args);
    amxc_var_init(&retval);

    root = amxd_object_get_child(root, "MyChild");
    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(int32_t, &args, "depth", INT32_MAX);
    assert_int_equal(amxd_object_invoke_function(root, "_get", &args, &retval), 0);
    assert_int_equal(amxc_var_type_of(&retval), AMXC_VAR_ID_HTABLE);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(int32_t, &args, "depth", INT32_MAX);
    amxc_var_add_key(cstring_t, &args, "rel_path", "*.");
    assert_int_equal(amxd_object_invoke_function(root, "_get", &args, &retval), 0);

    amxc_var_dump(&retval, STDOUT_FILENO);

    var_obj = amxc_var_get_key(&retval, "MyRoot.MyChild.1.", AMXC_VAR_FLAG_DEFAULT);
    assert_int_equal(amxc_var_type_of(var_obj), AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_htable_size(amxc_var_constcast(amxc_htable_t, var_obj)), 4);

    var_sub_obj = amxc_var_get_key(&retval, "MyRoot.MyChild.1.SubChild.", AMXC_VAR_FLAG_DEFAULT);
    assert_int_equal(amxc_var_type_of(var_sub_obj), AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_htable_size(amxc_var_constcast(amxc_htable_t, var_sub_obj)), 3);
    var_sub_obj = amxc_var_get_key(&retval, "MyRoot.MyChild.1.SubChild.SubTemplate.1.", AMXC_VAR_FLAG_DEFAULT);
    assert_int_equal(amxc_var_type_of(var_sub_obj), AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_htable_size(amxc_var_constcast(amxc_htable_t, var_sub_obj)), 3);

    amxc_var_clean(&args);
    amxc_var_clean(&retval);
    test_clean_dm();
}