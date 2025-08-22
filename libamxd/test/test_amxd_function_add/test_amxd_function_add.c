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

#include "test_amxd_function_add.h"

#include <amxc/amxc_macros.h>
static amxd_dm_t dm;

int test_function_add_setup(UNUSED void** state) {
    amxd_object_t* root = NULL;
    amxd_object_t* singleton = NULL;
    amxd_object_t* template = NULL;
    amxd_object_t* template2 = NULL;
    amxd_object_t* instance = NULL;
    amxd_param_t* param = NULL;
    amxd_function_t* func = NULL;
    amxc_var_t def_val;
    amxc_var_t* param3_val = NULL;

    assert_int_equal(amxd_dm_init(&dm), 0);
    amxc_var_init(&def_val);

    // object Main
    assert_int_equal(amxd_object_new(&root, amxd_object_singleton, "Main"), 0);
    assert_int_equal(amxd_dm_add_root_object(&dm, root), 0);

    // %persistent object Main.Template[]
    assert_int_equal(amxd_object_new(&template, amxd_object_template, "Template"), 0);
    amxd_object_set_attr(template, amxd_oattr_persistent, true);
    assert_int_equal(amxd_object_add_object(root, template), 0);
    // string param1
    assert_int_equal(amxd_param_new(&param, "param1", AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(amxd_object_add_param(template, param), 0);
    // %read-only uint32 param2
    assert_int_equal(amxd_param_new(&param, "param2", AMXC_VAR_ID_UINT32), 0);
    amxd_param_set_attr(param, amxd_pattr_read_only, true);
    assert_int_equal(amxd_object_add_param(template, param), 0);
    // %unique uint32 param3
    assert_int_equal(amxd_param_new(&param, "param3", AMXC_VAR_ID_UINT32), 0);
    amxd_param_set_attr(param, amxd_pattr_unique, true);
    assert_int_equal(amxd_object_add_param(template, param), 0);
    // htable func1(%mandatory %in string arg1, %in uint32 arg2 = 10)
    assert_int_equal(amxd_function_new(&func, "func1", AMXC_VAR_ID_HTABLE, NULL), 0);
    assert_int_equal(amxd_function_new_arg(func, "arg1", AMXC_VAR_ID_CSTRING, NULL), 0);
    amxc_var_set(uint32_t, &def_val, 10);
    assert_int_equal(amxd_function_new_arg(func, "arg2", AMXC_VAR_ID_UINT32, &def_val), 0);
    assert_int_equal(amxd_object_add_function(template, func), 0);

    // %persistent object Main.Template[].SubTemplate[]
    assert_int_equal(amxd_object_new(&template2, amxd_object_template, "SubTemplate"), 0);
    amxd_object_set_attr(template2, amxd_oattr_persistent, true);
    assert_int_equal(amxd_object_add_object(template, template2), 0);
    // string param1
    assert_int_equal(amxd_param_new(&param, "param1", AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(amxd_object_add_param(template2, param), 0);

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
    assert_int_equal(amxd_object_add_param(singleton, param), 0);
    // htable func1(%mandatory %in string arg1, %in uint32 arg2 = 10)
    assert_int_equal(amxd_function_new(&func, "func1", AMXC_VAR_ID_HTABLE, NULL), 0);
    assert_int_equal(amxd_function_new_arg(func, "arg1", AMXC_VAR_ID_CSTRING, NULL), 0);
    amxc_var_set(uint32_t, &def_val, 10);
    assert_int_equal(amxd_function_new_arg(func, "arg2", AMXC_VAR_ID_UINT32, &def_val), 0);
    assert_int_equal(amxd_object_add_function(singleton, func), 0);

    amxc_var_set_type(&def_val, AMXC_VAR_ID_HTABLE);
    param3_val = amxc_var_add_key(uint32_t, &def_val, "param3", 1);
    assert_int_equal(amxd_object_add_instance(&instance, template, "Instance1", 0, &def_val), 0);
    amxc_var_set(uint32_t, param3_val, 2);
    assert_int_equal(amxd_object_add_instance(&instance, template, "Instance2", 0, &def_val), 0);

    amxc_var_clean(&def_val);
    return 0;
}

int test_function_add_teardown(UNUSED void** state) {
    amxd_dm_clean(&dm);

    return 0;
}

void test_amxd_can_add_instance_object(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxc_var_t retval;
    amxc_var_t args;

    amxc_var_init(&args);
    amxc_var_init(&retval);

    template = amxd_dm_findf(&dm, "Main.Template");
    assert_non_null(template);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxd_object_invoke_function(template, "_add", &args, &retval), 0);

    assert_non_null(GET_ARG(&retval, "index"));
    assert_non_null(GET_ARG(&retval, "name"));

    amxc_var_clean(&retval);
    amxc_var_clean(&args);
}

void test_amxd_add_can_use_rel_path(UNUSED void** state) {
    amxd_object_t* root = NULL;
    amxc_var_t retval;
    amxc_var_t args;
    amxc_var_t* params = NULL;

    amxc_var_init(&args);
    amxc_var_init(&retval);

    root = amxd_dm_findf(&dm, "Main.");
    assert_non_null(root);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &args, "rel_path", "Template.");
    params = amxc_var_add_key(amxc_htable_t, &args, "parameters", NULL);
    amxc_var_add_key(uint32_t, params, "param3", 3);
    assert_int_equal(amxd_object_invoke_function(root, "_add", &args, &retval), 0);

    amxc_var_dump(&retval, STDOUT_FILENO);
    assert_int_equal(amxc_var_type_of(&retval), AMXC_VAR_ID_HTABLE);

    amxc_var_clean(&retval);
    amxc_var_clean(&args);
}

void test_amxd_add_fails_with_invalid_rel_path(UNUSED void** state) {
    amxd_object_t* root = NULL;
    amxc_var_t retval;
    amxc_var_t args;

    amxc_var_init(&args);
    amxc_var_init(&retval);

    root = amxd_dm_findf(&dm, "Main.");
    assert_non_null(root);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &args, "rel_path", "NotExisting.Object.");
    assert_int_not_equal(amxd_object_invoke_function(root, "_add", &args, &retval), 0);

    amxc_var_clean(&retval);
    amxc_var_clean(&args);
}


void test_amxd_add_can_use_to_high_access(UNUSED void** state) {
    amxd_object_t* singleton = NULL;
    amxc_var_t retval;
    amxc_var_t args;
    amxc_var_t* params = NULL;

    amxc_var_init(&args);
    amxc_var_init(&retval);

    singleton = amxd_dm_findf(&dm, "Main.Template.");
    assert_non_null(singleton);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(uint32_t, &args, "access", 100);
    params = amxc_var_add_key(amxc_htable_t, &args, "parameters", NULL);
    amxc_var_add_key(uint32_t, params, "param3", 4);
    assert_int_equal(amxd_object_invoke_function(singleton, "_add", &args, &retval), 0);

    amxc_var_clean(&retval);
    amxc_var_clean(&args);
}

void test_amxd_add_fails_on_singleton(UNUSED void** state) {
    amxd_object_t* object = NULL;
    amxc_var_t retval;
    amxc_var_t args;

    amxc_var_init(&args);
    amxc_var_init(&retval);

    object = amxd_dm_findf(&dm, "Main.Singleton");
    assert_non_null(object);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    assert_int_not_equal(amxd_object_invoke_function(object, "_add", &args, &retval), 0);

    object = amxd_dm_findf(&dm, "Main.");
    amxc_var_add_key(cstring_t, &args, "rel_path", "Singleton.");
    assert_int_not_equal(amxd_object_invoke_function(object, "_add", &args, &retval), 0);

    amxc_var_clean(&retval);
    amxc_var_clean(&args);
}

void test_amxd_add_fails_when_unique_param_is_not_unique(UNUSED void** state) {
    amxd_object_t* root = NULL;
    amxc_var_t retval;
    amxc_var_t args;
    amxc_var_t* params = NULL;

    amxc_var_init(&args);
    amxc_var_init(&retval);

    root = amxd_dm_findf(&dm, "Main.");
    assert_non_null(root);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &args, "rel_path", "Template.");
    params = amxc_var_add_key(amxc_htable_t, &args, "parameters", NULL);
    amxc_var_add_key(uint32_t, params, "param3", 3);
    assert_int_not_equal(amxd_object_invoke_function(root, "_add", &args, &retval), 0);

    amxc_var_clean(&retval);
    amxc_var_clean(&args);
}

void test_amxd_can_add_instances_using_wildcard(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxc_var_t retval;
    amxc_var_t args;

    amxc_var_init(&args);
    amxc_var_init(&retval);

    template = amxd_dm_findf(&dm, "Main.Template");
    assert_non_null(template);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &args, "rel_path", "*.SubTemplate.");
    assert_int_equal(amxd_object_invoke_function(template, "_add", &args, &retval), 0);
    amxc_var_dump(&retval, STDOUT_FILENO);

    assert_int_equal(amxc_var_type_of(&retval), AMXC_VAR_ID_LIST);
    assert_string_equal(GETP_CHAR(&retval, "0.path"), "Main.Template.1.SubTemplate.1.");
    assert_string_equal(GETP_CHAR(&retval, "1.path"), "Main.Template.2.SubTemplate.1.");
    assert_string_equal(GETP_CHAR(&retval, "2.path"), "Main.Template.3.SubTemplate.1.");
    assert_string_equal(GETP_CHAR(&retval, "3.path"), "Main.Template.4.SubTemplate.1.");

    amxc_var_clean(&retval);
    amxc_var_clean(&args);
}

void test_amxd_can_add_instances_using_searchpath(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxc_var_t retval;
    amxc_var_t args;

    amxc_var_init(&args);
    amxc_var_init(&retval);

    template = amxd_dm_findf(&dm, "Main.Template");
    assert_non_null(template);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &args, "rel_path", "[param3 == 4].SubTemplate.");
    assert_int_equal(amxd_object_invoke_function(template, "_add", &args, &retval), 0);
    amxc_var_dump(&retval, STDOUT_FILENO);

    assert_int_equal(amxc_var_type_of(&retval), AMXC_VAR_ID_LIST);
    assert_string_equal(GETP_CHAR(&retval, "0.path"), "Main.Template.5.SubTemplate.2.");

    amxc_var_clean(&retval);
    amxc_var_clean(&args);
}