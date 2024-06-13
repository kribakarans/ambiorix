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
#include <amxd/amxd_object.h>
#include <amxd/amxd_function.h>

#include "test_amxd_object.h"

#include <amxc/amxc_macros.h>
static amxd_dm_t dm;
static int count1 = 0;
static int count2 = 0;
static uint64_t call_id = 0;

static amxd_status_t test_func(amxd_object_t* object,
                               amxd_function_t* func,
                               amxc_var_t* args,
                               amxc_var_t* ret) {
    assert_ptr_not_equal(object, NULL);
    assert_ptr_not_equal(func, NULL);
    assert_ptr_not_equal(args, NULL);
    assert_ptr_not_equal(ret, NULL);
    assert_int_equal(amxc_var_type_of(args), AMXC_VAR_ID_HTABLE);

    count1++;

    return 0;
}

static amxd_status_t test_func2(amxd_object_t* object,
                                amxd_function_t* func,
                                amxc_var_t* args,
                                amxc_var_t* ret) {
    assert_ptr_not_equal(object, NULL);
    assert_ptr_not_equal(func, NULL);
    assert_ptr_not_equal(args, NULL);
    assert_ptr_not_equal(ret, NULL);
    assert_int_equal(amxc_var_type_of(args), AMXC_VAR_ID_HTABLE);

    count2++;

    return 0;
}

static amxd_status_t test_deferred_func(amxd_object_t* object,
                                        amxd_function_t* func,
                                        amxc_var_t* args,
                                        amxc_var_t* ret) {
    assert_ptr_not_equal(object, NULL);
    assert_ptr_not_equal(func, NULL);
    assert_ptr_not_equal(args, NULL);
    assert_ptr_not_equal(ret, NULL);
    assert_int_equal(amxc_var_type_of(args), AMXC_VAR_ID_HTABLE);

    call_id = 0;
    assert_int_not_equal(amxd_function_defer(NULL, &call_id, ret, NULL, NULL), 0);
    assert_int_equal(call_id, 0);
    assert_int_not_equal(amxd_function_defer(func, &call_id, NULL, NULL, NULL), 0);
    assert_int_equal(call_id, 0);
    assert_int_not_equal(amxd_function_defer(func, NULL, ret, NULL, NULL), 0);

    assert_int_equal(amxd_function_defer(func, &call_id, ret, NULL, NULL), 0);

    return amxd_status_deferred;
}

static amxd_status_t test_deferred_func_invalid(amxd_object_t* object,
                                                amxd_function_t* func,
                                                amxc_var_t* args,
                                                amxc_var_t* ret) {
    assert_ptr_not_equal(object, NULL);
    assert_ptr_not_equal(func, NULL);
    assert_ptr_not_equal(args, NULL);
    assert_ptr_not_equal(ret, NULL);
    assert_int_equal(amxc_var_type_of(args), AMXC_VAR_ID_HTABLE);

    return amxd_status_deferred;
}

static void test_deferred_cancel(UNUSED uint64_t id, void* const priv) {
    assert_non_null(priv);
    assert_ptr_equal(priv, &dm);
}

static void test_deferred_done(UNUSED const amxc_var_t* const data, void* const priv) {
    assert_non_null(priv);
    assert_ptr_equal(priv, &dm);
}

static amxd_status_t test_deferred_func_cancel(amxd_object_t* object,
                                               amxd_function_t* func,
                                               amxc_var_t* args,
                                               amxc_var_t* ret) {
    assert_ptr_not_equal(object, NULL);
    assert_ptr_not_equal(func, NULL);
    assert_ptr_not_equal(args, NULL);
    assert_ptr_not_equal(ret, NULL);
    assert_int_equal(amxc_var_type_of(args), AMXC_VAR_ID_HTABLE);

    amxd_function_defer(func, &call_id, ret, test_deferred_cancel, &dm);

    return amxd_status_deferred;
}

void test_amxd_object_add_function(UNUSED void** state) {
    amxd_object_t* object = NULL;
    amxd_function_t* function = NULL;
    assert_int_equal(amxd_dm_init(&dm), 0);

    assert_int_equal(amxd_object_new(&object, amxd_object_singleton, "parent"), 0);
    assert_int_equal(amxd_dm_add_root_object(&dm, object), 0);

    assert_int_equal(amxd_function_new(&function, "test_func", AMXC_VAR_ID_CSTRING, test_func), 0);
    assert_int_equal(amxd_object_add_function(object, function), 0);

    assert_int_equal(amxd_function_new(&function, "test_func", AMXC_VAR_ID_CSTRING, test_func), 0);
    assert_int_not_equal(amxd_object_add_function(object, function), 0);
    amxd_function_delete(&function);

    assert_int_equal(amxd_function_new(&function, "test_func2", AMXC_VAR_ID_CSTRING, test_func), 0);
    assert_int_equal(amxd_object_add_function(object, function), 0);

    assert_int_equal(amxd_object_set_attr(object, amxd_oattr_locked, true), 0);
    assert_int_equal(amxd_function_new(&function, "test_func3", AMXC_VAR_ID_CSTRING, test_func), 0);
    assert_int_not_equal(amxd_object_add_function(object, function), 0);
    amxd_function_delete(&function);

    amxd_dm_clean(&dm);
}

void test_amxd_object_add_function_invalid_arg(UNUSED void** state) {
    amxd_object_t* object = NULL;
    amxd_function_t* function = NULL;
    assert_int_equal(amxd_dm_init(&dm), 0);

    assert_int_equal(amxd_object_new(&object, amxd_object_singleton, "parent"), 0);
    assert_int_equal(amxd_dm_add_root_object(&dm, object), 0);

    assert_int_equal(amxd_function_new(&function, "test_func", AMXC_VAR_ID_CSTRING, test_func), 0);
    assert_int_not_equal(amxd_object_add_function(NULL, function), 0);
    assert_int_not_equal(amxd_object_add_function(object, NULL), 0);
    assert_int_equal(amxd_object_add_function(object, function), 0);
    assert_int_not_equal(amxd_object_add_function(object, function), 0);

    amxd_dm_clean(&dm);
}

void test_amxd_object_change_function(UNUSED void** state) {
    amxd_object_t* object = NULL;
    amxd_object_t* instance = NULL;
    amxd_function_t* function = NULL;
    amxd_function_t* function_inst = NULL;
    assert_int_equal(amxd_dm_init(&dm), 0);

    assert_int_equal(amxd_object_new(&object, amxd_object_template, "parent"), 0);
    assert_int_equal(amxd_dm_add_root_object(&dm, object), 0);

    assert_int_equal(amxd_function_new(&function, "test_func", AMXC_VAR_ID_CSTRING, test_func), 0);
    assert_int_equal(amxd_object_add_function(object, function), 0);

    assert_int_equal(amxd_object_change_function(object, "test_func", test_func2), 0);
    assert_int_equal(amxd_object_change_function(object, "test_func", test_func), 0);

    assert_int_equal(amxd_object_new_instance(&instance, object, NULL, 0, NULL), 0);
    function_inst = amxd_object_get_function(instance, "test_func");
    assert_ptr_not_equal(function_inst, NULL);
    assert_ptr_equal(function_inst->impl, test_func);
    assert_ptr_equal(function_inst, function);

    assert_int_equal(amxd_object_change_function(instance, "test_func", test_func2), 0);
    function_inst = amxd_object_get_function(instance, "test_func");
    assert_ptr_not_equal(function_inst, NULL);
    assert_ptr_equal(function_inst->impl, test_func2);
    assert_ptr_not_equal(function_inst, function);

    amxd_dm_clean(&dm);
}

void test_amxd_object_change_function_invalid_args(UNUSED void** state) {
    amxd_object_t* object = NULL;
    amxd_function_t* function = NULL;
    assert_int_equal(amxd_dm_init(&dm), 0);

    assert_int_equal(amxd_object_new(&object, amxd_object_template, "parent"), 0);
    assert_int_equal(amxd_dm_add_root_object(&dm, object), 0);

    assert_int_equal(amxd_function_new(&function, "test_func", AMXC_VAR_ID_CSTRING, test_func), 0);
    assert_int_equal(amxd_object_add_function(object, function), 0);

    assert_int_not_equal(amxd_object_change_function(NULL, "test_func", test_func2), 0);
    assert_int_not_equal(amxd_object_change_function(object, "test_func2", test_func2), 0);
    assert_int_not_equal(amxd_object_change_function(object, NULL, test_func2), 0);
    assert_int_not_equal(amxd_object_change_function(object, "", test_func2), 0);
    assert_int_equal(amxd_object_change_function(object, "test_func", NULL), 0);

    amxd_dm_clean(&dm);
}

void test_amxd_object_get_function(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxd_object_t* object = NULL;
    amxd_object_t* instance = NULL;
    amxd_object_t* instance_object = NULL;

    amxd_function_t* function = NULL;
    assert_int_equal(amxd_dm_init(&dm), 0);

    assert_int_equal(amxd_object_new(&template, amxd_object_template, "parent"), 0);
    assert_int_equal(amxd_dm_add_root_object(&dm, template), 0);
    assert_int_equal(amxd_object_new(&object, amxd_object_singleton, "child"), 0);
    assert_int_equal(amxd_object_add_object(template, object), 0);
    assert_int_equal(amxd_function_new(&function, "templ_func", AMXC_VAR_ID_CSTRING, test_func), 0);
    assert_int_equal(amxd_object_add_function(template, function), 0);
    assert_int_equal(amxd_function_new(&function, "child_func", AMXC_VAR_ID_CSTRING, test_func2), 0);
    assert_int_equal(amxd_object_add_function(object, function), 0);

    assert_int_equal(amxd_object_new_instance(&instance, template, NULL, 0, NULL), 0);
    function = amxd_object_get_function(instance, "templ_func");
    assert_ptr_not_equal(function, NULL);
    assert_ptr_equal(amxd_function_get_owner(function), template);

    function = amxd_object_get_function(object, "child_func");
    assert_ptr_not_equal(function, NULL);
    assert_ptr_equal(amxd_function_get_owner(function), object);

    instance_object = amxd_object_get(instance, "child");
    assert_ptr_not_equal(instance_object, NULL);
    assert_ptr_equal(amxd_object_get_parent(instance_object), instance);
    assert_ptr_equal(instance_object->derived_from.llist, &object->derived_objects);
    assert_ptr_equal(instance_object->type, amxd_object_singleton);
    function = amxd_object_get_function(instance_object, "child_func");
    assert_ptr_not_equal(function, NULL);
    assert_ptr_equal(amxd_function_get_owner(function), object);

    assert_int_equal(amxd_object_change_function(instance_object, "child_func", test_func), 0);
    function = amxd_object_get_function(instance_object, "child_func");
    assert_ptr_not_equal(function, NULL);
    assert_ptr_equal(amxd_function_get_owner(function), instance_object);

    amxd_dm_clean(&dm);
}

void test_amxd_object_get_function_invalid_args(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxd_object_t* object = NULL;
    amxd_object_t* instance = NULL;

    amxd_function_t* function = NULL;
    assert_int_equal(amxd_dm_init(&dm), 0);

    assert_int_equal(amxd_object_new(&template, amxd_object_template, "parent"), 0);
    assert_int_equal(amxd_dm_add_root_object(&dm, template), 0);
    assert_int_equal(amxd_object_new(&object, amxd_object_singleton, "child"), 0);
    assert_int_equal(amxd_object_add_object(template, object), 0);
    assert_int_equal(amxd_function_new(&function, "templ_func", AMXC_VAR_ID_CSTRING, test_func), 0);
    assert_int_equal(amxd_object_add_function(template, function), 0);
    assert_int_equal(amxd_function_new(&function, "child_func", AMXC_VAR_ID_CSTRING, test_func2), 0);
    assert_int_equal(amxd_object_add_function(object, function), 0);

    assert_int_equal(amxd_object_new_instance(&instance, template, NULL, 0, NULL), 0);
    function = amxd_object_get_function(instance, "templ_func");
    assert_ptr_not_equal(function, NULL);
    assert_ptr_equal(amxd_function_get_owner(function), template);

    function = amxd_object_get_function(NULL, "templ_func");
    assert_ptr_equal(function, NULL);
    function = amxd_object_get_function(instance, "");
    assert_ptr_equal(function, NULL);
    function = amxd_object_get_function(instance, NULL);
    assert_ptr_equal(function, NULL);
    function = amxd_object_get_function(instance, "afunc");
    assert_ptr_equal(function, NULL);
    function = amxd_object_get_function(amxd_dm_get_root(&dm), "afunc");
    assert_ptr_equal(function, NULL);

    amxd_dm_clean(&dm);
}

void test_amxd_object_get_functions(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxd_object_t* object = NULL;
    amxd_object_t* instance = NULL;
    amxd_object_t* instance_object = NULL;
    amxc_var_t functions;
    const amxc_llist_t* func_list = NULL;

    amxd_function_t* function = NULL;
    amxc_var_init(&functions);

    assert_int_equal(amxd_dm_init(&dm), 0);

    assert_int_equal(amxd_object_new(&template, amxd_object_template, "parent"), 0);
    assert_int_equal(amxd_dm_add_root_object(&dm, template), 0);
    assert_int_equal(amxd_object_new(&object, amxd_object_singleton, "child"), 0);
    assert_int_equal(amxd_object_add_object(template, object), 0);

    assert_int_equal(amxd_function_new(&function, "templ_func", AMXC_VAR_ID_CSTRING, test_func), 0);
    assert_int_equal(amxd_object_add_function(template, function), 0);
    assert_int_equal(amxd_function_new(&function, "templ_func2", AMXC_VAR_ID_CSTRING, test_func), 0);
    assert_int_equal(amxd_function_set_attr(function, amxd_fattr_template, true), 0);
    assert_int_equal(amxd_object_add_function(template, function), 0);
    assert_int_equal(amxd_function_new(&function, "templ_func3", AMXC_VAR_ID_CSTRING, test_func), 0);
    assert_int_equal(amxd_function_set_attr(function, amxd_fattr_private, true), 0);
    assert_int_equal(amxd_object_add_function(template, function), 0);

    assert_int_equal(amxd_function_new(&function, "child_func", AMXC_VAR_ID_CSTRING, test_func), 0);
    assert_int_equal(amxd_object_add_function(object, function), 0);
    assert_int_equal(amxd_function_new(&function, "child_func2", AMXC_VAR_ID_CSTRING, test_func2), 0);
    assert_int_equal(amxd_object_add_function(object, function), 0);
    assert_int_equal(amxd_function_new(&function, "child_func3", AMXC_VAR_ID_CSTRING, test_func2), 0);
    assert_int_equal(amxd_function_set_attr(function, amxd_fattr_private, true), 0);
    assert_int_equal(amxd_object_add_function(object, function), 0);

    assert_int_equal(amxd_object_new_instance(&instance, template, NULL, 0, NULL), 0);
    function = amxd_object_get_function(instance, "templ_func");
    assert_ptr_not_equal(function, NULL);
    assert_ptr_equal(amxd_function_get_owner(function), template);

    instance_object = amxd_object_get(instance, "child");
    assert_int_equal(amxd_object_change_function(instance_object, "child_func", test_func), 0);
    assert_int_equal(amxd_object_list_functions(instance_object, &functions, amxd_dm_access_private), 0);
    assert_int_equal(amxc_var_type_of(&functions), AMXC_VAR_ID_LIST);
    func_list = amxc_var_constcast(amxc_llist_t, &functions);
    assert_int_equal(amxc_llist_size(func_list), 3 + INSTANCE_DEFAULT_FUNCS);
    assert_int_equal(amxd_object_list_functions(instance_object, &functions, amxd_dm_access_protected), 0);
    assert_int_equal(amxc_var_type_of(&functions), AMXC_VAR_ID_LIST);
    func_list = amxc_var_constcast(amxc_llist_t, &functions);
    assert_int_equal(amxc_llist_size(func_list), 2 + INSTANCE_DEFAULT_FUNCS);
    amxc_var_clean(&functions);

    assert_int_equal(amxd_object_list_functions(instance, &functions, amxd_dm_access_private), 0);
    amxc_var_dump(&functions, STDOUT_FILENO);
    func_list = amxc_var_constcast(amxc_llist_t, &functions);
    assert_int_equal(amxc_llist_size(func_list), 2 + INSTANCE_DEFAULT_FUNCS);
    assert_int_equal(amxd_object_list_functions(instance, &functions, amxd_dm_access_protected), 0);
    func_list = amxc_var_constcast(amxc_llist_t, &functions);
    assert_int_equal(amxc_llist_size(func_list), 1 + INSTANCE_DEFAULT_FUNCS);
    amxc_var_clean(&functions);

    assert_int_not_equal(amxd_object_list_functions(instance, NULL, 0), 0);
    assert_int_not_equal(amxd_object_list_functions(NULL, &functions, 0), 0);

    amxd_dm_clean(&dm);
}

void test_amxd_object_invoke_function(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxd_object_t* object = NULL;
    amxd_object_t* instance = NULL;
    amxd_function_t* function = NULL;

    amxc_var_t args;
    amxc_var_t ret;

    amxc_var_init(&args);
    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_init(&ret);

    assert_int_equal(amxd_dm_init(&dm), 0);

    assert_int_equal(amxd_object_new(&template, amxd_object_template, "parent"), 0);
    assert_int_equal(amxd_dm_add_root_object(&dm, template), 0);
    assert_int_equal(amxd_object_new(&object, amxd_object_singleton, "child"), 0);
    assert_int_equal(amxd_object_add_object(template, object), 0);

    assert_int_equal(amxd_function_new(&function, "templ_func", AMXC_VAR_ID_CSTRING, test_func), 0);
    amxd_function_set_attr(function, amxd_fattr_template, true);
    assert_int_equal(amxd_object_add_function(template, function), 0);
    assert_int_equal(amxd_function_new(&function, "inst_func", AMXC_VAR_ID_CSTRING, test_func), 0);
    assert_int_equal(amxd_object_add_function(template, function), 0);
    assert_int_equal(amxd_function_new(&function, "inst_func2", AMXC_VAR_ID_CSTRING, NULL), 0);
    assert_int_equal(amxd_object_add_function(template, function), 0);
    assert_int_equal(amxd_function_new(&function, "child_func", AMXC_VAR_ID_CSTRING, test_func), 0);
    assert_int_equal(amxd_object_add_function(object, function), 0);
    assert_int_equal(amxd_function_new(&function, "child_func2", AMXC_VAR_ID_CSTRING, test_func2), 0);
    assert_int_equal(amxd_object_add_function(object, function), 0);
    assert_int_equal(amxd_object_new_instance(&instance, template, NULL, 0, NULL), 0);

    assert_int_equal(amxd_object_invoke_function(template, "templ_func", &args, &ret), 0);
    assert_int_equal(count1, 1);
    assert_int_equal(amxd_object_invoke_function(instance, "inst_func", &args, &ret), 0);
    assert_int_equal(count1, 2);
    assert_int_not_equal(amxd_object_invoke_function(instance, "templ_func", &args, &ret), 0);
    assert_int_equal(count1, 2);
    assert_int_not_equal(amxd_object_invoke_function(template, "inst_func", &args, &ret), 0);
    assert_int_equal(count1, 2);
    assert_int_not_equal(amxd_object_invoke_function(instance, "inst_func2", &args, &ret), 0);
    assert_int_equal(count1, 2);

    assert_int_equal(amxd_object_invoke_function(object, "child_func", &args, &ret), 0);
    assert_int_equal(count1, 3);
    assert_int_not_equal(amxd_object_invoke_function(template, "child_func", &args, &ret), 0);
    assert_int_equal(count1, 3);
    assert_int_equal(amxd_object_invoke_function(object, "child_func2", &args, &ret), 0);
    assert_int_equal(count1, 3);
    assert_int_equal(count2, 1);

    assert_int_not_equal(amxd_object_invoke_function(NULL, "child_func", &args, &ret), 0);
    assert_int_not_equal(amxd_object_invoke_function(object, "", &args, &ret), 0);
    assert_int_not_equal(amxd_object_invoke_function(object, NULL, &args, &ret), 0);
    assert_int_not_equal(amxd_object_invoke_function(object, "child_func", NULL, &ret), 0);
    assert_int_not_equal(amxd_object_invoke_function(object, "child_func", &args, NULL), 0);
    amxc_var_set_type(&args, AMXC_VAR_ID_LIST);
    assert_int_not_equal(amxd_object_invoke_function(object, "child_func", &args, &ret), 0);

    amxc_var_clean(&args);
    amxc_var_clean(&ret);
    amxd_dm_clean(&dm);
}

void test_amxd_object_deferred_function_no_callbacks(UNUSED void** state) {
    amxd_object_t* object = NULL;
    amxd_function_t* function = NULL;
    uint64_t local_call_id = 0;

    amxc_var_t args;
    amxc_var_t ret;

    amxc_var_init(&args);
    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_init(&ret);

    assert_int_equal(amxd_dm_init(&dm), 0);

    assert_int_equal(amxd_object_new(&object, amxd_object_singleton, "child"), 0);
    assert_int_equal(amxd_dm_add_root_object(&dm, object), 0);
    assert_int_equal(amxd_function_new(&function, "deferred_func", AMXC_VAR_ID_CSTRING, test_deferred_func), 0);
    assert_int_equal(amxd_object_add_function(object, function), 0);
    assert_int_equal(amxd_function_new(&function, "deferred_func_invalid", AMXC_VAR_ID_CSTRING, test_deferred_func_invalid), 0);
    assert_int_equal(amxd_object_add_function(object, function), 0);

    while(amxp_signal_read() == 0) {
    }

    assert_int_equal(amxd_object_invoke_function(object, "deferred_func", &args, &ret), amxd_status_deferred);
    local_call_id = amxc_var_constcast(uint64_t, &ret);
    assert_int_equal(local_call_id, call_id);

    while(amxp_signal_read() == 0) {
    }

    amxd_function_deferred_remove(local_call_id);
    while(amxp_signal_read() == 0) {
    }
    amxd_function_deferred_remove(local_call_id);
    while(amxp_signal_read() == 0) {
    }

    amxc_var_clean(&ret);
    assert_int_equal(amxd_object_invoke_function(object, "deferred_func", &args, &ret), amxd_status_deferred);
    local_call_id = amxc_var_constcast(uint64_t, &ret);
    assert_int_equal(local_call_id, call_id);
    amxd_function_deferred_remove(local_call_id);
    while(amxp_signal_read() == 0) {
    }

    amxc_var_clean(&ret);
    assert_int_equal(amxd_object_invoke_function(object, "deferred_func", &args, &ret), amxd_status_deferred);
    local_call_id = amxc_var_constcast(uint64_t, &ret);
    assert_int_equal(local_call_id, call_id);
    amxd_function_deferred_done(local_call_id, amxd_status_ok, NULL, NULL);
    while(amxp_signal_read() == 0) {
    }

    amxc_var_clean(&ret);
    assert_int_equal(amxd_object_invoke_function(object, "deferred_func", &args, &ret), amxd_status_deferred);
    local_call_id = amxc_var_constcast(uint64_t, &ret);
    amxc_var_set(bool, &ret, true);
    assert_int_equal(amxd_function_deferred_done(local_call_id, amxd_status_ok, &args, &ret), 0);
    assert_int_not_equal(amxd_function_deferred_done(local_call_id, amxd_status_ok, &args, &ret), 0);
    while(amxp_signal_read() == 0) {
    }

    amxc_var_clean(&ret);
    assert_int_equal(amxd_object_invoke_function(object, "deferred_func", &args, &ret), amxd_status_deferred);
    local_call_id = amxc_var_constcast(uint64_t, &ret);
    assert_int_equal(local_call_id, call_id);
    amxc_var_clean(&ret);
    assert_int_equal(amxd_object_invoke_function(object, "deferred_func", &args, &ret), amxd_status_deferred);
    local_call_id = amxc_var_constcast(uint64_t, &ret);
    assert_int_equal(local_call_id, call_id);

    amxc_var_clean(&ret);
    assert_int_not_equal(amxd_object_invoke_function(object, "deferred_func_invalid", &args, &ret), amxd_status_deferred);

    amxc_var_clean(&args);
    amxc_var_clean(&ret);
    amxd_dm_clean(&dm);
}

void test_amxd_object_deferred_function_cancel_callback(UNUSED void** state) {
    amxd_object_t* object = NULL;
    amxd_function_t* function = NULL;
    uint64_t local_call_id = 0;

    amxc_var_t args;
    amxc_var_t ret;

    amxc_var_init(&args);
    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_init(&ret);

    assert_int_equal(amxd_dm_init(&dm), 0);

    assert_int_equal(amxd_object_new(&object, amxd_object_singleton, "child"), 0);
    assert_int_equal(amxd_dm_add_root_object(&dm, object), 0);
    assert_int_equal(amxd_function_new(&function, "deferred_func", AMXC_VAR_ID_CSTRING, test_deferred_func_cancel), 0);
    assert_int_equal(amxd_object_add_function(object, function), 0);

    assert_int_equal(amxd_object_invoke_function(object, "deferred_func", &args, &ret), amxd_status_deferred);
    local_call_id = amxc_var_constcast(uint64_t, &ret);
    assert_int_equal(local_call_id, call_id);
    assert_ptr_equal(amxd_function_deferred_get_priv(local_call_id), &dm);
    assert_null(amxd_function_deferred_get_priv(local_call_id + 1));
    while(amxp_signal_read() == 0) {
    }

    amxd_function_deferred_remove(local_call_id);
    assert_null(amxd_function_deferred_get_priv(local_call_id));
    while(amxp_signal_read() == 0) {
    }

    assert_int_equal(amxd_object_invoke_function(object, "deferred_func", &args, &ret), amxd_status_deferred);
    local_call_id = amxc_var_constcast(uint64_t, &ret);
    assert_int_equal(local_call_id, call_id);
    amxd_function_deferred_remove(local_call_id);
    while(amxp_signal_read() == 0) {
    }

    assert_int_equal(amxd_object_invoke_function(object, "deferred_func", &args, &ret), amxd_status_deferred);
    local_call_id = amxc_var_constcast(uint64_t, &ret);
    amxd_function_deferred_done(local_call_id, amxd_status_ok, NULL, NULL);
    while(amxp_signal_read() == 0) {
    }

    assert_int_equal(amxd_object_invoke_function(object, "deferred_func", &args, &ret), amxd_status_deferred);
    local_call_id = amxc_var_constcast(uint64_t, &ret);
    amxc_var_set(bool, &ret, true);
    assert_int_equal(amxd_function_deferred_done(local_call_id, amxd_status_ok, &args, &ret), 0);
    assert_int_not_equal(amxd_function_deferred_done(local_call_id, amxd_status_ok, &args, &ret), 0);
    while(amxp_signal_read() == 0) {
    }

    assert_int_equal(amxd_object_invoke_function(object, "deferred_func", &args, &ret), amxd_status_deferred);
    local_call_id = amxc_var_constcast(uint64_t, &ret);
    assert_int_equal(amxd_object_invoke_function(object, "deferred_func", &args, &ret), amxd_status_deferred);
    local_call_id = amxc_var_constcast(uint64_t, &ret);
    assert_int_equal(local_call_id, call_id);

    amxc_var_clean(&args);
    amxc_var_clean(&ret);
    amxd_dm_clean(&dm);
}

void test_amxd_object_deferred_function_done_callback(UNUSED void** state) {
    amxd_object_t* object = NULL;
    amxd_function_t* function = NULL;
    uint64_t local_call_id = 0;

    amxc_var_t args;
    amxc_var_t ret;

    amxc_var_init(&args);
    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_init(&ret);

    assert_int_equal(amxd_dm_init(&dm), 0);

    assert_int_equal(amxd_object_new(&object, amxd_object_singleton, "child"), 0);
    assert_int_equal(amxd_dm_add_root_object(&dm, object), 0);
    assert_int_equal(amxd_function_new(&function, "deferred_func", AMXC_VAR_ID_CSTRING, test_deferred_func), 0);
    assert_int_equal(amxd_object_add_function(object, function), 0);

    while(amxp_signal_read() == 0) {
    }

    assert_int_equal(amxd_object_invoke_function(object, "deferred_func", &args, &ret), amxd_status_deferred);
    local_call_id = amxc_var_constcast(uint64_t, &ret);
    assert_int_equal(local_call_id, call_id);
    assert_int_equal(amxd_function_set_deferred_cb(local_call_id, test_deferred_done, &dm), 0);

    while(amxp_signal_read() == 0) {
    }

    amxd_function_deferred_remove(local_call_id);
    while(amxp_signal_read() == 0) {
    }
    amxd_function_deferred_remove(local_call_id);
    while(amxp_signal_read() == 0) {
    }

    assert_int_equal(amxd_object_invoke_function(object, "deferred_func", &args, &ret), amxd_status_deferred);
    local_call_id = amxc_var_constcast(uint64_t, &ret);
    assert_int_equal(local_call_id, call_id);
    assert_int_equal(amxd_function_set_deferred_cb(local_call_id, test_deferred_done, &dm), 0);
    while(amxp_signal_read() == 0) {
    }

    assert_int_equal(amxd_object_invoke_function(object, "deferred_func", &args, &ret), amxd_status_deferred);
    local_call_id = amxc_var_constcast(uint64_t, &ret);
    assert_int_equal(local_call_id, call_id);
    assert_int_equal(amxd_function_set_deferred_cb(local_call_id, test_deferred_done, &dm), 0);
    amxd_function_deferred_done(local_call_id, amxd_status_ok, NULL, NULL);
    while(amxp_signal_read() == 0) {
    }

    assert_int_equal(amxd_object_invoke_function(object, "deferred_func", &args, &ret), amxd_status_deferred);
    local_call_id = amxc_var_constcast(uint64_t, &ret);
    amxc_var_set(bool, &ret, true);
    assert_int_equal(amxd_function_set_deferred_cb(local_call_id, test_deferred_done, &dm), 0);
    assert_int_equal(amxd_function_deferred_done(local_call_id, amxd_status_ok, &args, &ret), 0);
    assert_int_not_equal(amxd_function_deferred_done(local_call_id, amxd_status_ok, &args, &ret), 0);
    assert_int_not_equal(amxd_function_set_deferred_cb(local_call_id, test_deferred_done, &dm), 0);
    while(amxp_signal_read() == 0) {
    }

    assert_int_equal(amxd_object_invoke_function(object, "deferred_func", &args, &ret), amxd_status_deferred);
    local_call_id = amxc_var_constcast(uint64_t, &ret);
    assert_int_equal(local_call_id, call_id);
    assert_int_equal(amxd_function_set_deferred_cb(local_call_id, test_deferred_done, &dm), 0);
    assert_int_equal(amxd_object_invoke_function(object, "deferred_func", &args, &ret), amxd_status_deferred);
    local_call_id = amxc_var_constcast(uint64_t, &ret);
    assert_int_equal(local_call_id, call_id);
    assert_int_equal(amxd_function_set_deferred_cb(local_call_id, test_deferred_done, &dm), 0);

    amxc_var_clean(&args);
    amxc_var_clean(&ret);
    amxd_dm_clean(&dm);
}


void test_amxd_object_count_functions(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxd_object_t* object = NULL;
    amxd_object_t* instance = NULL;
    amxd_function_t* function = NULL;

    amxc_var_t args;
    amxc_var_t ret;

    amxc_var_init(&args);
    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_init(&ret);

    assert_int_equal(amxd_dm_init(&dm), 0);

    assert_int_equal(amxd_object_new(&template, amxd_object_template, "parent"), 0);
    assert_int_equal(amxd_dm_add_root_object(&dm, template), 0);
    assert_int_equal(amxd_object_new(&object, amxd_object_singleton, "child"), 0);
    assert_int_equal(amxd_object_add_object(template, object), 0);

    assert_int_equal(amxd_function_new(&function, "templ_func", AMXC_VAR_ID_CSTRING, test_func), 0);
    amxd_function_set_attr(function, amxd_fattr_template, true);
    assert_int_equal(amxd_object_add_function(template, function), 0);
    assert_int_equal(amxd_function_new(&function, "inst_func", AMXC_VAR_ID_CSTRING, test_func), 0);
    assert_int_equal(amxd_object_add_function(template, function), 0);
    assert_int_equal(amxd_function_new(&function, "inst_func2", AMXC_VAR_ID_CSTRING, NULL), 0);
    assert_int_equal(amxd_object_add_function(template, function), 0);

    assert_int_equal(amxd_function_new(&function, "child_func", AMXC_VAR_ID_CSTRING, test_func), 0);
    assert_int_equal(amxd_object_add_function(object, function), 0);
    assert_int_equal(amxd_function_new(&function, "child_func2", AMXC_VAR_ID_CSTRING, test_func2), 0);
    assert_int_equal(amxd_object_add_function(object, function), 0);

    assert_int_equal(amxd_object_new_instance(&instance, template, NULL, 0, NULL), 0);

    assert_int_equal(amxd_object_get_function_count(template, amxd_dm_access_private), 3 + TEMPLATE_DEFAULT_FUNCS);
    assert_int_equal(amxd_object_get_function_count(template, amxd_dm_access_protected), 3 + TEMPLATE_DEFAULT_FUNCS);
    assert_int_equal(amxd_object_get_function_count(instance, amxd_dm_access_protected), 2 + INSTANCE_DEFAULT_FUNCS);
    assert_int_equal(amxd_object_get_function_count(object, amxd_dm_access_protected), 2 + SINGELTON_DEFAULT_FUNCS);

    assert_int_equal(amxd_object_get_function_count(NULL, amxd_dm_access_protected), 0);

    amxc_var_clean(&args);
    amxc_var_clean(&ret);
    amxd_dm_clean(&dm);
}
