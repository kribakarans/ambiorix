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
#include <setjmp.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <cmocka.h>

#include <amxc/amxc.h>
#include <amxp/amxp_signal.h>
#include <amxp/amxp_slot.h>
#include <amxp/amxp_timer.h>

#include <amxd/amxd_dm.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_object_event.h>
#include <amxd/amxd_transaction.h>

#include "test_amxd_function_get_supported.h"

#include <amxc/amxc_macros.h>
static amxd_dm_t dm;

int test_function_get_supported_setup(UNUSED void** state) {
    amxd_object_t* root = NULL;
    amxd_object_t* singleton = NULL;
    amxd_object_t* template = NULL;
    amxd_object_t* instance = NULL;
    amxd_param_t* param = NULL;
    amxd_function_t* func = NULL;
    amxc_var_t def_val;

    assert_int_equal(amxd_dm_init(&dm), 0);
    amxc_var_init(&def_val);

    // object Main
    assert_int_equal(amxd_object_new(&root, amxd_object_singleton, "Main"), 0);
    assert_int_equal(amxd_dm_add_root_object(&dm, root), 0);

    // %read-only object Main.Template[]
    assert_int_equal(amxd_object_new(&template, amxd_object_template, "Template"), 0);
    amxd_object_set_attr(template, amxd_oattr_read_only, true);
    assert_int_equal(amxd_object_add_object(root, template), 0);
    // string param1
    assert_int_equal(amxd_param_new(&param, "param1", AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(amxd_object_add_param(template, param), 0);
    // %read-only uint32 param2
    assert_int_equal(amxd_param_new(&param, "param2", AMXC_VAR_ID_UINT32), 0);
    amxd_param_set_attr(param, amxd_pattr_read_only, true);
    assert_int_equal(amxd_object_add_param(template, param), 0);
    // %key string param3
    assert_int_equal(amxd_param_new(&param, "param3", AMXC_VAR_ID_CSTRING), 0);
    amxd_param_set_attr(param, amxd_pattr_key, true);
    assert_int_equal(amxd_object_add_param(template, param), 0);
    // htable func1(%mandatory %in string arg1, %in uint32 arg2 = 10)
    assert_int_equal(amxd_function_new(&func, "func1", AMXC_VAR_ID_HTABLE, NULL), 0);
    assert_int_equal(amxd_function_new_arg(func, "arg1", AMXC_VAR_ID_CSTRING, NULL), 0);
    amxc_var_set(uint32_t, &def_val, 10);
    assert_int_equal(amxd_function_new_arg(func, "arg2", AMXC_VAR_ID_UINT32, &def_val), 0);
    assert_int_equal(amxd_object_add_function(template, func), 0);

    assert_int_equal(amxd_object_add_event(template, "MyEvent!"), 0);

    assert_int_equal(amxd_object_new(&singleton, amxd_object_singleton, "SubObject"), 0);
    amxd_object_set_attr(singleton, amxd_oattr_persistent, true);
    assert_int_equal(amxd_object_add_object(template, singleton), 0);
    assert_int_equal(amxd_param_new(&param, "param1", AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(amxd_object_add_param(singleton, param), 0);

    assert_int_equal(amxd_object_new(&singleton, amxd_object_singleton, "PrivateSubObject"), 0);
    amxd_object_set_attr(singleton, amxd_oattr_private, true);
    assert_int_equal(amxd_object_add_object(template, singleton), 0);
    assert_int_equal(amxd_param_new(&param, "param1", AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(amxd_object_add_param(singleton, param), 0);

    assert_int_equal(amxd_object_new(&singleton, amxd_object_singleton, "ProtectedSubObject"), 0);
    amxd_object_set_attr(singleton, amxd_oattr_protected, true);
    assert_int_equal(amxd_object_add_object(template, singleton), 0);
    assert_int_equal(amxd_param_new(&param, "param1", AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(amxd_object_add_param(singleton, param), 0);

    // %persistent object Main.Singleton
    assert_int_equal(amxd_object_new(&singleton, amxd_object_singleton, "Singleton"), 0);
    amxd_object_set_attr(singleton, amxd_oattr_persistent, true);
    assert_int_equal(amxd_object_add_object(root, singleton), 0);
    // string param1
    assert_int_equal(amxd_param_new(&param, "param1", AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(amxd_object_add_param(singleton, param), 0);
    // %read-only uint32 param2
    assert_int_equal(amxd_param_new(&param, "param2", AMXC_VAR_ID_UINT32), 0);
    amxd_param_set_attr(param, amxd_pattr_read_only, true);
    amxd_param_set_attr(param, amxd_pattr_variable, true);
    assert_int_equal(amxd_object_add_param(singleton, param), 0);
    // htable func1(%mandatory %in string arg1, %in uint32 arg2 = 10)
    assert_int_equal(amxd_function_new(&func, "func1", AMXC_VAR_ID_HTABLE, NULL), 0);
    assert_int_equal(amxd_function_new_arg(func, "arg1", AMXC_VAR_ID_CSTRING, NULL), 0);
    amxc_var_set(uint32_t, &def_val, 10);
    assert_int_equal(amxd_function_new_arg(func, "arg2", AMXC_VAR_ID_UINT32, &def_val), 0);
    assert_int_equal(amxd_object_add_function(singleton, func), 0);

    amxc_var_set_type(&def_val, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &def_val, "param3", "Key1");
    assert_int_equal(amxd_object_add_instance(&instance, template, "Instance1", 0, &def_val), 0);
    amxc_var_set_type(&def_val, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &def_val, "param3", "Key2");
    assert_int_equal(amxd_object_add_instance(&instance, template, "Instance2", 0, &def_val), 0);

    amxc_var_clean(&def_val);
    return 0;
}

int test_function_get_supported_teardown(UNUSED void** state) {
    amxd_dm_clean(&dm);

    return 0;
}

void test_amxd_can_get_supported_singleton_object(UNUSED void** state) {
    amxd_object_t* singleton = NULL;
    amxc_var_t retval;
    amxc_var_t args;

    amxc_var_init(&args);
    amxc_var_init(&retval);

    singleton = amxd_dm_findf(&dm, "Main.Singleton");
    assert_non_null(singleton);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxd_object_invoke_function(singleton, "_get_supported", &args, &retval), 0);

    assert_non_null(GET_ARG(&retval, "Main.Singleton."));
    amxc_var_dump(&retval, STDOUT_FILENO);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(bool, &args, "parameters", true);
    assert_int_equal(amxd_object_invoke_function(singleton, "_get_supported", &args, &retval), 0);
    assert_non_null(GET_ARG(&retval, "Main.Singleton."));
    assert_non_null(GETP_ARG(&retval, "'Main.Singleton.'.supported_params.0.value_change"));
    assert_int_equal(GETP_UINT32(&retval, "'Main.Singleton.'.supported_params.0.value_change"), 1);
    assert_non_null(GETP_ARG(&retval, "'Main.Singleton.'.supported_params.0.access"));
    assert_int_equal(GETP_UINT32(&retval, "'Main.Singleton.'.supported_params.0.access"), 1);
    assert_non_null(GETP_ARG(&retval, "'Main.Singleton.'.supported_params.0.type"));
    assert_int_equal(GETP_UINT32(&retval, "'Main.Singleton.'.supported_params.0.type"), 1);
    assert_non_null(GETP_ARG(&retval, "'Main.Singleton.'.supported_params.1.value_change"));
    assert_int_equal(GETP_UINT32(&retval, "'Main.Singleton.'.supported_params.1.value_change"), 2);
    assert_non_null(GETP_ARG(&retval, "'Main.Singleton.'.supported_params.1.access"));
    assert_int_equal(GETP_UINT32(&retval, "'Main.Singleton.'.supported_params.1.access"), 0);
    assert_non_null(GETP_ARG(&retval, "'Main.Singleton.'.supported_params.1.type"));
    assert_int_equal(GETP_UINT32(&retval, "'Main.Singleton.'.supported_params.1.type"), 8);
    amxc_var_dump(&retval, STDOUT_FILENO);

    amxc_var_clean(&retval);
    amxc_var_clean(&args);
}

void test_amxd_can_get_supported_template_object(UNUSED void** state) {
    amxd_object_t* templ = NULL;
    amxc_var_t retval;
    amxc_var_t args;

    amxc_var_init(&args);
    amxc_var_init(&retval);

    templ = amxd_dm_findf(&dm, "Main.Template");
    assert_non_null(templ);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxd_object_invoke_function(templ, "_get_supported", &args, &retval), 0);

    amxc_var_dump(&retval, STDOUT_FILENO);
    assert_non_null(GET_ARG(&retval, "Main.Template.{i}."));
    assert_true(GETP_BOOL(&retval, "'Main.Template.{i}.'.is_multi_instance"));
    assert_int_equal(GETP_INT32(&retval, "'Main.Template.{i}.'.supported_params.2.access"), 0);
    assert_non_null(GET_ARG(&retval, "Main.Template.{i}.SubObject."));
    assert_false(GETP_BOOL(&retval, "'Main.Template.{i}.SubObject'.is_multi_instance"));

    amxc_var_clean(&retval);
    amxc_var_clean(&args);
}

void test_amxd_get_supported_instance_object_succeeds(UNUSED void** state) {
    amxd_object_t* inst = NULL;
    amxc_var_t retval;
    amxc_var_t args;

    amxc_var_init(&args);
    amxc_var_init(&retval);

    inst = amxd_dm_findf(&dm, "Main.Template.1.");
    assert_non_null(inst);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxd_object_invoke_function(inst, "_get_supported", &args, &retval), 0);
    amxc_var_dump(&retval, STDOUT_FILENO);

    inst = amxd_dm_findf(&dm, "Main.Template.1.SubObject");
    assert_non_null(inst);

    assert_int_equal(amxd_object_invoke_function(inst, "_get_supported", &args, &retval), 0);
    amxc_var_dump(&retval, STDOUT_FILENO);

    amxc_var_clean(&retval);
    amxc_var_clean(&args);
}

void test_amxd_can_get_supported_template_object_parameters(UNUSED void** state) {
    amxd_object_t* templ = NULL;
    amxc_var_t retval;
    amxc_var_t args;

    amxc_var_init(&args);
    amxc_var_init(&retval);

    templ = amxd_dm_findf(&dm, "Main.Template");
    assert_non_null(templ);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(bool, &args, "first_level_only", false);
    amxc_var_add_key(bool, &args, "parameters", true);
    assert_int_equal(amxd_object_invoke_function(templ, "_get_supported", &args, &retval), 0);

    amxc_var_dump(&retval, STDOUT_FILENO);
    assert_non_null(GETP_ARG(&retval, "'Main.Template.{i}.'.supported_params.0.param_name"));
    assert_string_equal(GETP_CHAR(&retval, "'Main.Template.{i}.'.supported_params.0.param_name"), "param1");
    assert_non_null(GETP_ARG(&retval, "'Main.Template.{i}.'.supported_params.0.type"));
    assert_int_equal(GETP_UINT32(&retval, "'Main.Template.{i}.'.supported_params.0.type"), AMXC_VAR_ID_CSTRING);
    assert_non_null(GETP_ARG(&retval, "'Main.Template.{i}.'.supported_params.1.param_name"));
    assert_string_equal(GETP_CHAR(&retval, "'Main.Template.{i}.'.supported_params.1.param_name"), "param2");
    assert_non_null(GETP_ARG(&retval, "'Main.Template.{i}.'.supported_params.1.type"));
    assert_int_equal(GETP_UINT32(&retval, "'Main.Template.{i}.'.supported_params.1.type"), AMXC_VAR_ID_UINT32);
    assert_non_null(GETP_ARG(&retval, "'Main.Template.{i}.SubObject.'.supported_params.0.param_name"));
    assert_string_equal(GETP_CHAR(&retval, "'Main.Template.{i}.SubObject.'.supported_params.0.param_name"), "param1");
    assert_non_null(GETP_ARG(&retval, "'Main.Template.{i}.SubObject.'.supported_params.0.type"));
    assert_int_equal(GETP_UINT32(&retval, "'Main.Template.{i}.SubObject.'.supported_params.0.type"), AMXC_VAR_ID_CSTRING);
    assert_non_null(GETP_ARG(&retval, "'Main.Template.{i}.ProtectedSubObject.'.supported_params.0.type"));
    assert_int_equal(GETP_UINT32(&retval, "'Main.Template.{i}.ProtectedSubObject.'.supported_params.0.type"), AMXC_VAR_ID_CSTRING);

    amxc_var_clean(&retval);
    amxc_var_clean(&args);
}

void test_amxd_can_get_supported_template_object_parameters_public_access(UNUSED void** state) {
    amxd_object_t* templ = NULL;
    amxc_var_t retval;
    amxc_var_t args;

    amxc_var_init(&args);
    amxc_var_init(&retval);

    templ = amxd_dm_findf(&dm, "Main.Template");
    assert_non_null(templ);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(bool, &args, "first_level_only", false);
    amxc_var_add_key(bool, &args, "parameters", true);
    amxc_var_add_key(uint32_t, &args, "access", amxd_dm_access_public);
    assert_int_equal(amxd_object_invoke_function(templ, "_get_supported", &args, &retval), 0);

    amxc_var_dump(&retval, STDOUT_FILENO);
    assert_non_null(GETP_ARG(&retval, "'Main.Template.{i}.'.supported_params.0.param_name"));
    assert_string_equal(GETP_CHAR(&retval, "'Main.Template.{i}.'.supported_params.0.param_name"), "param1");
    assert_non_null(GETP_ARG(&retval, "'Main.Template.{i}.'.supported_params.0.type"));
    assert_int_equal(GETP_UINT32(&retval, "'Main.Template.{i}.'.supported_params.0.type"), AMXC_VAR_ID_CSTRING);
    assert_non_null(GETP_ARG(&retval, "'Main.Template.{i}.'.supported_params.1.param_name"));
    assert_string_equal(GETP_CHAR(&retval, "'Main.Template.{i}.'.supported_params.1.param_name"), "param2");
    assert_non_null(GETP_ARG(&retval, "'Main.Template.{i}.'.supported_params.1.type"));
    assert_int_equal(GETP_UINT32(&retval, "'Main.Template.{i}.'.supported_params.1.type"), AMXC_VAR_ID_UINT32);
    assert_non_null(GETP_ARG(&retval, "'Main.Template.{i}.SubObject.'.supported_params.0.param_name"));
    assert_string_equal(GETP_CHAR(&retval, "'Main.Template.{i}.SubObject.'.supported_params.0.param_name"), "param1");
    assert_non_null(GETP_ARG(&retval, "'Main.Template.{i}.SubObject.'.supported_params.0.type"));
    assert_int_equal(GETP_UINT32(&retval, "'Main.Template.{i}.SubObject.'.supported_params.0.type"), AMXC_VAR_ID_CSTRING);
    assert_null(GETP_ARG(&retval, "'Main.Template.{i}.ProtectedSubObject.'.supported_params.0.type"));

    amxc_var_clean(&retval);
    amxc_var_clean(&args);
}

void test_amxd_can_get_supported_template_object_parameters_first_level(UNUSED void** state) {
    amxd_object_t* templ = NULL;
    amxc_var_t retval;
    amxc_var_t args;

    amxc_var_init(&args);
    amxc_var_init(&retval);

    templ = amxd_dm_findf(&dm, "Main.Template");
    assert_non_null(templ);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(bool, &args, "first_level_only", true);
    amxc_var_add_key(bool, &args, "parameters", true);
    assert_int_equal(amxd_object_invoke_function(templ, "_get_supported", &args, &retval), 0);

    amxc_var_dump(&retval, STDOUT_FILENO);
    assert_non_null(GETP_ARG(&retval, "'Main.Template.{i}.'.supported_params.0.param_name"));
    assert_string_equal(GETP_CHAR(&retval, "'Main.Template.{i}.'.supported_params.0.param_name"), "param1");
    assert_non_null(GETP_ARG(&retval, "'Main.Template.{i}.'.supported_params.0.type"));
    assert_int_equal(GETP_UINT32(&retval, "'Main.Template.{i}.'.supported_params.0.type"), AMXC_VAR_ID_CSTRING);
    assert_non_null(GETP_ARG(&retval, "'Main.Template.{i}.'.supported_params.1.param_name"));
    assert_string_equal(GETP_CHAR(&retval, "'Main.Template.{i}.'.supported_params.1.param_name"), "param2");
    assert_non_null(GETP_ARG(&retval, "'Main.Template.{i}.'.supported_params.1.type"));
    assert_int_equal(GETP_UINT32(&retval, "'Main.Template.{i}.'.supported_params.1.type"), AMXC_VAR_ID_UINT32);
    assert_non_null(GETP_ARG(&retval, "'Main.Template.{i}.SubObject.'"));
    assert_null(GETP_ARG(&retval, "'Main.Template.{i}.SubObject.'.supported_params"));

    amxc_var_clean(&retval);
    amxc_var_clean(&args);
}

void test_amxd_can_get_supported_template_object_events(UNUSED void** state) {
    amxd_object_t* templ = NULL;
    amxc_var_t retval;
    amxc_var_t args;

    amxc_var_init(&args);
    amxc_var_init(&retval);

    templ = amxd_dm_findf(&dm, "Main.Template");
    assert_non_null(templ);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(bool, &args, "first_level_only", false);
    amxc_var_add_key(bool, &args, "events", true);
    assert_int_equal(amxd_object_invoke_function(templ, "_get_supported", &args, &retval), 0);

    amxc_var_dump(&retval, STDOUT_FILENO);
    assert_non_null(GETP_ARG(&retval, "'Main.Template.{i}.'.supported_events.'MyEvent!'"));

    amxc_var_clean(&retval);
    amxc_var_clean(&args);
}

void test_amxd_get_supported_can_use_rel_path(UNUSED void** state) {
    amxd_object_t* root = NULL;
    amxc_var_t retval;
    amxc_var_t args;

    amxc_var_init(&args);
    amxc_var_init(&retval);

    root = amxd_dm_findf(&dm, "Main.");
    assert_non_null(root);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &args, "rel_path", "Singleton.");
    assert_int_equal(amxd_object_invoke_function(root, "_get_supported", &args, &retval), 0);

    amxc_var_clean(&retval);
    amxc_var_clean(&args);
}

void test_amxd_get_supported_fails_with_invalid_rel_path(UNUSED void** state) {
    amxd_object_t* root = NULL;
    amxc_var_t retval;
    amxc_var_t args;

    amxc_var_init(&args);
    amxc_var_init(&retval);

    root = amxd_dm_findf(&dm, "Main.");
    assert_non_null(root);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &args, "rel_path", "NotExisting.Object.");
    assert_int_not_equal(amxd_object_invoke_function(root, "_get_supported", &args, &retval), 0);

    amxc_var_clean(&retval);
    amxc_var_clean(&args);
}


void test_amxd_get_supported_can_use_to_high_access(UNUSED void** state) {
    amxd_object_t* singleton = NULL;
    amxc_var_t retval;
    amxc_var_t args;

    amxc_var_init(&args);
    amxc_var_init(&retval);

    singleton = amxd_dm_findf(&dm, "Main.Singleton.");
    assert_non_null(singleton);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(uint32_t, &args, "access", 100);
    assert_int_equal(amxd_object_invoke_function(singleton, "_get_supported", &args, &retval), 0);
    amxc_var_dump(&retval, STDOUT_FILENO);

    amxc_var_clean(&retval);
    amxc_var_clean(&args);
}