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

#include "test_amxd_function_del.h"

#include <amxc/amxc_macros.h>
static amxd_dm_t dm;

int test_function_del_setup(UNUSED void** state) {
    amxd_object_t* root = NULL;
    amxd_object_t* singleton = NULL;
    amxd_object_t* template = NULL;
    amxd_object_t* sub = NULL;
    amxd_object_t* instance = NULL;
    amxd_param_t* param = NULL;
    amxd_function_t* func = NULL;
    amxc_var_t def_val;

    assert_int_equal(amxd_dm_init(&dm), 0);
    amxc_var_init(&def_val);

    // object Main
    assert_int_equal(amxd_object_new(&root, amxd_object_singleton, "Main"), 0);
    assert_int_equal(amxd_dm_add_root_object(&dm, root), 0);

    // %persistent object Main.Template[]
    assert_int_equal(amxd_object_new(&template, amxd_object_template, "Template"), 0);
    amxd_object_set_attr(template, amxd_oattr_persistent, true);
    assert_int_equal(amxd_object_add_object(root, template), 0);
    // %unique %key string Alias
    assert_int_equal(amxd_param_new(&param, "Alias", AMXC_VAR_ID_CSTRING), 0);
    amxd_param_set_attr(param, amxd_pattr_key, true);
    amxd_param_set_attr(param, amxd_pattr_unique, true);
    assert_int_equal(amxd_object_add_param(template, param), 0);
    // string param1
    assert_int_equal(amxd_param_new(&param, "param1", AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(amxd_object_add_param(template, param), 0);
    // %read-only uint32 param2
    assert_int_equal(amxd_param_new(&param, "param2", AMXC_VAR_ID_UINT32), 0);
    amxd_param_set_attr(param, amxd_pattr_read_only, true);
    assert_int_equal(amxd_object_add_param(template, param), 0);
    // htable func1(%mandatory %in string arg1, %in uint32 arg2 = 10)
    assert_int_equal(amxd_function_new(&func, "func1", AMXC_VAR_ID_HTABLE, NULL), 0);
    assert_int_equal(amxd_function_new_arg(func, "arg1", AMXC_VAR_ID_CSTRING, NULL), 0);
    amxc_var_set(uint32_t, &def_val, 10);
    assert_int_equal(amxd_function_new_arg(func, "arg2", AMXC_VAR_ID_UINT32, &def_val), 0);
    assert_int_equal(amxd_object_add_function(template, func), 0);

    // object Main.Template[].Sub[]
    assert_int_equal(amxd_object_new(&sub, amxd_object_template, "Sub"), 0);
    assert_int_equal(amxd_object_add_object(template, sub), 0);
    // %unique %key string Alias
    assert_int_equal(amxd_param_new(&param, "Alias", AMXC_VAR_ID_CSTRING), 0);
    amxd_param_set_attr(param, amxd_pattr_key, true);
    amxd_param_set_attr(param, amxd_pattr_unique, true);
    assert_int_equal(amxd_object_add_param(sub, param), 0);

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

    assert_int_equal(amxd_object_add_instance(&instance, template, "Instance1", 0, NULL), 0);
    assert_int_equal(amxd_object_add_instance(&instance, template, "Instance2", 0, NULL), 0);
    assert_int_equal(amxd_object_add_instance(&instance, template, "Test1", 0, NULL), 0);
    assert_int_equal(amxd_object_add_instance(&instance, template, "Test2", 0, NULL), 0);
    assert_int_equal(amxd_object_add_instance(&instance, template, "Test3", 0, NULL), 0);
    assert_int_equal(amxd_object_add_instance(&instance, template, "YAI1", 0, NULL), 0);
    assert_int_equal(amxd_object_add_instance(&instance, template, "YAI2", 0, NULL), 0);
    assert_int_equal(amxd_object_add_instance(&instance, template, "YAI3", 0, NULL), 0);
    template = amxd_object_findf(instance, "Sub");
    assert_int_equal(amxd_object_add_instance(&instance, template, "SUBINST", 0, NULL), 0);

    amxc_var_clean(&def_val);
    return 0;
}

int test_function_del_teardown(UNUSED void** state) {
    amxd_dm_clean(&dm);

    return 0;
}

void test_amxd_can_del_instance_object(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxd_object_t* object = NULL;
    amxc_var_t retval;
    amxc_var_t args;

    amxc_var_init(&args);
    amxc_var_init(&retval);

    template = amxd_dm_findf(&dm, "Main.Template.");
    assert_non_null(template);
    object = amxd_dm_findf(&dm, "Main.Template.1");
    assert_non_null(object);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxd_object_invoke_function(object, "_del", &args, &retval), 0);
    assert_int_equal(amxd_object_get_instance_count(template), 7);

    assert_int_equal(amxc_var_type_of(&retval), AMXC_VAR_ID_LIST);

    amxc_var_clean(&retval);
    amxc_var_clean(&args);
}

void test_amxd_del_can_use_rel_path(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxd_object_t* root = NULL;
    amxc_var_t retval;
    amxc_var_t args;

    amxc_var_init(&args);
    amxc_var_init(&retval);

    root = amxd_dm_findf(&dm, "Main.");
    assert_non_null(root);
    template = amxd_dm_findf(&dm, "Main.Template.");
    assert_non_null(template);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &args, "rel_path", "Template.2.");
    assert_int_equal(amxd_object_invoke_function(root, "_del", &args, &retval), 0);
    assert_int_equal(amxd_object_get_instance_count(template), 6);

    root = amxd_dm_findf(&dm, "Main.Template.");
    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(uint32_t, &args, "index", 3); // index should be ignored
    amxc_var_add_key(cstring_t, &args, "rel_path", "[Alias == 'YAI1' || Alias == 'YAI2'].");
    assert_int_equal(amxd_object_invoke_function(root, "_del", &args, &retval), 0);
    assert_int_equal(amxd_object_get_instance_count(template), 4);

    amxc_var_dump(&retval, STDOUT_FILENO);
    assert_string_equal(GETI_CHAR(&retval, 0), "Main.Template.6.");
    assert_string_equal(GETI_CHAR(&retval, 1), "Main.Template.6.Sub.");
    assert_string_equal(GETI_CHAR(&retval, 2), "Main.Template.7.");
    assert_string_equal(GETI_CHAR(&retval, 3), "Main.Template.7.Sub.");

    amxc_var_clean(&retval);
    amxc_var_clean(&args);
}

void test_amxd_del_fails_with_invalid_rel_path(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxd_object_t* root = NULL;
    amxc_var_t retval;
    amxc_var_t args;

    amxc_var_init(&args);
    amxc_var_init(&retval);

    root = amxd_dm_findf(&dm, "Main.");
    assert_non_null(root);
    template = amxd_dm_findf(&dm, "Main.Template.");
    assert_non_null(template);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &args, "rel_path", "NotExisting.Object.");
    assert_int_not_equal(amxd_object_invoke_function(root, "_del", &args, &retval), 0);
    assert_int_equal(amxd_object_get_instance_count(template), 4);
    amxc_var_clean(&retval);
    amxc_var_clean(&args);
}


void test_amxd_del_can_use_to_high_access(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxc_var_t retval;
    amxc_var_t args;

    amxc_var_init(&args);
    amxc_var_init(&retval);

    template = amxd_dm_findf(&dm, "Main.Template.");
    assert_non_null(template);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(uint32_t, &args, "access", 100);
    amxc_var_add_key(cstring_t, &args, "name", "Test1");
    assert_int_equal(amxd_object_invoke_function(template, "_del", &args, &retval), 0);
    assert_int_equal(amxd_object_get_instance_count(template), 3);

    amxc_var_clean(&retval);
    amxc_var_clean(&args);
}

void test_amxd_del_fails_on_singleton(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxd_object_t* object = NULL;
    amxc_var_t retval;
    amxc_var_t args;

    amxc_var_init(&args);
    amxc_var_init(&retval);

    object = amxd_dm_findf(&dm, "Main.Singleton");
    assert_non_null(object);
    template = amxd_dm_findf(&dm, "Main.Template.");
    assert_non_null(template);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    assert_int_not_equal(amxd_object_invoke_function(object, "_del", &args, &retval), 0);

    object = amxd_dm_findf(&dm, "Main.");
    amxc_var_add_key(cstring_t, &args, "rel_path", "Singleton.");
    assert_int_not_equal(amxd_object_invoke_function(object, "_del", &args, &retval), 0);
    assert_int_equal(amxd_object_get_instance_count(template), 3);

    amxc_var_clean(&retval);
    amxc_var_clean(&args);
}

void test_amxd_can_delete_on_index_with_rel_path(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxd_object_t* root = NULL;
    amxc_var_t retval;
    amxc_var_t args;

    amxc_var_init(&args);
    amxc_var_init(&retval);

    root = amxd_dm_findf(&dm, "Main.");
    assert_non_null(root);
    template = amxd_dm_findf(&dm, "Main.Template.");
    assert_non_null(template);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &args, "rel_path", "Template.");
    amxc_var_add_key(uint32_t, &args, "index", 4);
    assert_int_equal(amxd_object_invoke_function(root, "_del", &args, &retval), 0);
    assert_int_equal(amxd_object_get_instance_count(template), 2);

    amxc_var_dump(&retval, STDOUT_FILENO);
    assert_string_equal(GETI_CHAR(&retval, 0), "Main.Template.4.");
    assert_string_equal(GETI_CHAR(&retval, 1), "Main.Template.4.Sub.");

    amxc_var_clean(&retval);
    amxc_var_clean(&args);
}

void test_amxd_can_delete_on_name_with_rel_path(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxd_object_t* root = NULL;
    amxc_var_t retval;
    amxc_var_t args;

    amxc_var_init(&args);
    amxc_var_init(&retval);

    root = amxd_dm_findf(&dm, "Main.");
    assert_non_null(root);
    template = amxd_dm_findf(&dm, "Main.Template.");
    assert_non_null(template);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &args, "rel_path", "Template.");
    amxc_var_add_key(cstring_t, &args, "name", "Test3");
    assert_int_equal(amxd_object_invoke_function(root, "_del", &args, &retval), 0);
    assert_int_equal(amxd_object_get_instance_count(template), 1);

    amxc_var_dump(&retval, STDOUT_FILENO);
    assert_string_equal(GETI_CHAR(&retval, 0), "Main.Template.5.");
    assert_string_equal(GETI_CHAR(&retval, 1), "Main.Template.5.Sub.");

    amxc_var_clean(&retval);
    amxc_var_clean(&args);
}

void test_amxd_delete_key_path_returns_index_path(UNUSED void** state) {
    amxd_object_t* root = NULL;
    amxc_var_t retval;
    amxc_var_t args;

    amxc_var_init(&args);
    amxc_var_init(&retval);

    root = amxd_dm_findf(&dm, "Main.");
    assert_non_null(root);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &args, "rel_path", "Template.YAI3.Sub.SUBINST.");
    assert_int_equal(amxd_object_invoke_function(root, "_del", &args, &retval), 0);

    amxc_var_dump(&retval, STDOUT_FILENO);
    assert_string_equal(GETI_CHAR(&retval, 0), "Main.Template.8.Sub.1.");

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &args, "rel_path", "Template.YAI3.");
    assert_int_equal(amxd_object_invoke_function(root, "_del", &args, &retval), 0);

    amxc_var_dump(&retval, STDOUT_FILENO);
    assert_string_equal(GETI_CHAR(&retval, 0), "Main.Template.8.");
    assert_string_equal(GETI_CHAR(&retval, 1), "Main.Template.8.Sub.");

    amxc_var_clean(&retval);
    amxc_var_clean(&args);
}