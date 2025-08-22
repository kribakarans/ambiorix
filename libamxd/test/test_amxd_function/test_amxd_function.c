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
#include <amxd/amxd_function.h>

#include "test_amxd_function.h"

#include <amxc/amxc_macros.h>
static amxd_status_t test_func(amxd_object_t* object,
                               amxd_function_t* func,
                               amxc_var_t* args,
                               amxc_var_t* ret) {
    assert_ptr_not_equal(object, NULL);
    assert_ptr_not_equal(func, NULL);
    assert_ptr_not_equal(args, NULL);
    assert_ptr_not_equal(ret, NULL);
    assert_int_equal(amxc_var_type_of(args), AMXC_VAR_ID_HTABLE);

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

    return 0;
}

static amxd_status_t test_func3(amxd_object_t* object,
                                amxd_function_t* func,
                                amxc_var_t* args,
                                amxc_var_t* ret) {
    assert_ptr_not_equal(object, NULL);
    assert_ptr_not_equal(func, NULL);
    assert_ptr_not_equal(args, NULL);
    assert_ptr_not_equal(ret, NULL);
    assert_int_equal(amxc_var_type_of(args), AMXC_VAR_ID_HTABLE);

    return amxd_function_call_base(func, object, args, ret);
}

void test_amxd_function_new_delete(UNUSED void** state) {
    amxd_function_t* function = NULL;

    assert_int_equal(amxd_function_new(&function, "test_func", AMXC_VAR_ID_ANY, test_func), 0);
    assert_ptr_not_equal(function, NULL);
    assert_ptr_equal(function->impl, test_func);
    assert_int_equal(function->ret_type, AMXC_VAR_ID_ANY);
    assert_string_equal(function->name, "test_func");
    assert_int_equal(function->attr.instance, 0);
    assert_int_equal(function->attr.priv, 0);
    assert_int_equal(function->attr.templ, 0);

    amxd_function_delete(&function);
    assert_ptr_equal(function, NULL);
    amxd_function_delete(&function);


    assert_int_equal(amxd_function_new(&function, "test_func", AMXC_VAR_ID_CSTRING, test_func), 0);
    amxd_function_delete(&function);
    assert_ptr_equal(function, NULL);
}

void test_amxd_function_new_delete_invalid_args(UNUSED void** state) {
    amxd_function_t* function = NULL;

    assert_int_equal(amxd_function_new(&function, "test_func", AMXC_VAR_ID_CSTRING, NULL), 0);
    assert_ptr_not_equal(function, NULL);
    amxd_function_delete(&function);

    assert_int_not_equal(amxd_function_new(&function, "test_func", AMXC_VAR_ID_CUSTOM_BASE + 100, test_func), 0);
    assert_ptr_equal(function, NULL);

    assert_int_not_equal(amxd_function_new(NULL, "test_func", AMXC_VAR_ID_CSTRING, test_func), 0);
    assert_ptr_equal(function, NULL);

    assert_int_not_equal(amxd_function_new(&function, "123", AMXC_VAR_ID_CSTRING, test_func), 0);
    assert_ptr_equal(function, NULL);
    assert_int_not_equal(amxd_function_new(&function, "test@func", AMXC_VAR_ID_CSTRING, test_func), 0);
    assert_ptr_equal(function, NULL);
    assert_int_not_equal(amxd_function_new(&function, "", AMXC_VAR_ID_CSTRING, test_func), 0);
    assert_ptr_equal(function, NULL);
    assert_int_not_equal(amxd_function_new(&function, NULL, AMXC_VAR_ID_CSTRING, test_func), 0);
    assert_ptr_equal(function, NULL);

    amxd_function_delete(&function);
}

void test_amxd_function_copy(UNUSED void** state) {
    amxd_function_t* function = NULL;
    amxd_function_t* cfunction = NULL;

    assert_int_equal(amxd_function_new(&function, "test_func", AMXC_VAR_ID_CSTRING, test_func), 0);
    assert_int_equal(amxd_function_copy(&cfunction, function), 0);
    assert_ptr_equal(cfunction->impl, test_func);
    assert_int_equal(cfunction->ret_type, AMXC_VAR_ID_CSTRING);
    assert_string_equal(cfunction->name, "test_func");
    assert_int_equal(cfunction->attr.instance, 0);
    assert_int_equal(cfunction->attr.priv, 0);
    assert_int_equal(cfunction->attr.templ, 0);
    amxd_function_delete(&function);
    amxd_function_delete(&cfunction);
}

void test_amxd_function_copy_with_args(UNUSED void** state) {
    amxd_function_t* function = NULL;
    amxd_function_t* cfunction = NULL;

    assert_int_equal(amxd_function_new(&function, "test_func", AMXC_VAR_ID_CSTRING, test_func), 0);
    assert_int_equal(amxd_function_new_arg(function, "arg1", AMXC_VAR_ID_UINT32, NULL), 0);
    assert_int_equal(amxd_function_new_arg(function, "arg2", AMXC_VAR_ID_UINT32, NULL), 0);
    assert_int_equal(amxd_function_copy(&cfunction, function), 0);
    assert_int_equal(amxc_llist_size(&cfunction->args), 2);
    amxd_function_delete(&function);
    amxd_function_delete(&cfunction);
}

void test_amxd_function_copy_with_attributes(UNUSED void** state) {
    amxd_function_t* function = NULL;
    amxd_function_t* cfunction = NULL;

    assert_int_equal(amxd_function_new(&function, "test_func", AMXC_VAR_ID_CSTRING, test_func), 0);
    assert_int_equal(amxd_function_new_arg(function, "arg1", AMXC_VAR_ID_UINT32, NULL), 0);
    assert_int_equal(amxd_function_new_arg(function, "arg2", AMXC_VAR_ID_UINT32, NULL), 0);
    amxd_function_set_attr(function, amxd_fattr_private, true);
    assert_int_equal(amxd_function_copy(&cfunction, function), 0);
    assert_int_equal(cfunction->attr.priv, 1);
    assert_int_equal(amxc_llist_size(&cfunction->args), 2);
    amxd_function_delete(&function);
    amxd_function_delete(&cfunction);
}

void test_amxd_function_copy_invalid(UNUSED void** state) {
    amxd_function_t* function = NULL;
    amxd_function_t* cfunction = NULL;

    assert_int_equal(amxd_function_new(&function, "test_func", AMXC_VAR_ID_CSTRING, test_func), 0);
    assert_int_equal(amxd_function_new_arg(function, "arg1", AMXC_VAR_ID_UINT32, NULL), 0);
    assert_int_equal(amxd_function_new_arg(function, "arg2", AMXC_VAR_ID_UINT32, NULL), 0);
    amxd_function_set_attr(function, amxd_fattr_private, true);

    assert_int_not_equal(amxd_function_copy(NULL, function), 0);
    assert_int_not_equal(amxd_function_copy(&cfunction, NULL), 0);
    assert_ptr_equal(cfunction, NULL);

    amxd_function_delete(&function);
    amxd_function_delete(&function);
}

void test_amxd_function_get_owner_invalid(UNUSED void** state) {
    amxd_function_t* function = NULL;

    assert_int_equal(amxd_function_new(&function, "templ_func", AMXC_VAR_ID_CSTRING, test_func), 0);
    assert_ptr_equal(amxd_function_get_owner(NULL), NULL);
    assert_ptr_equal(amxd_function_get_owner(function), NULL);

    amxd_function_delete(&function);
}

void test_amxd_function_get_base(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxd_object_t* object = NULL;
    amxd_object_t* instance = NULL;
    amxd_object_t* instance_object = NULL;
    amxd_function_t* function = NULL;
    amxd_function_t* base_function = NULL;
    amxd_dm_t dm;

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
    base_function = amxd_function_get_base(function);
    assert_ptr_not_equal(function, base_function);
    assert_ptr_equal(amxd_function_get_owner(base_function), object);
    assert_ptr_equal(amxd_function_get_owner(function), instance_object);

    function = amxd_object_get_function(instance, "templ_func");
    base_function = amxd_function_get_base(function);
    assert_ptr_equal(base_function, NULL);
    assert_ptr_not_equal(function, NULL);
    assert_ptr_equal(amxd_function_get_owner(function), template);

    assert_int_equal(amxd_object_change_function(instance, "templ_func", test_func2), 0);
    function = amxd_object_get_function(instance, "templ_func");
    base_function = amxd_function_get_base(function);
    assert_ptr_not_equal(base_function, NULL);
    assert_ptr_not_equal(function, NULL);
    assert_ptr_not_equal(function, base_function);
    assert_ptr_equal(amxd_function_get_owner(function), instance);
    assert_ptr_equal(amxd_function_get_owner(base_function), template);

    amxd_dm_clean(&dm);
}

void test_amxd_function_get_base_invalid(UNUSED void** state) {
    amxd_function_t* function = NULL;
    amxd_object_t* object = NULL;

    assert_int_equal(amxd_object_new(&object, amxd_object_singleton, "child"), 0);
    assert_int_equal(amxd_function_new(&function, "templ_func", AMXC_VAR_ID_CSTRING, test_func), 0);
    assert_int_equal(amxd_object_add_function(object, function), 0);

    amxc_llist_it_take(&object->derived_from);

    assert_ptr_equal(amxd_function_get_base(NULL), NULL);
    assert_ptr_equal(amxd_function_get_base(function), NULL);

    amxd_function_delete(&function);
    amxd_object_delete(&object);
}

void test_amxd_can_call_base(UNUSED void** state) {
    amxd_dm_t dm;
    amxd_function_t* function = NULL;
    amxd_object_t* object = NULL;
    amxd_object_t* base_object = NULL;
    amxc_var_t args;
    amxc_var_t ret;

    amxc_var_init(&args);
    amxc_var_init(&ret);

    assert_int_equal(amxd_dm_init(&dm), 0);

    assert_int_equal(amxd_object_new(&object, amxd_object_singleton, "child"), 0);
    assert_int_equal(amxd_dm_add_root_object(&dm, object), 0);
    assert_int_equal(amxd_function_new(&function, "_get", AMXC_VAR_ID_CSTRING, test_func3), 0);
    assert_int_equal(amxd_object_add_function(object, function), 0);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxd_object_invoke_function(object, "_get", &args, &ret), 0);

    base_object = amxd_object_get_base(object);
    function = amxd_object_get_function(base_object, "_get");
    assert_int_equal(amxd_function_set_impl(function, NULL), 0);
    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    assert_int_not_equal(amxd_object_invoke_function(object, "_get()", &args, &ret), 0);

    function = amxd_object_get_function(object, "_set");
    assert_non_null(function);

    assert_int_equal(amxd_function_set_impl(function, test_func3), 0);
    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    assert_int_not_equal(amxd_object_invoke_function(object, "_set()", &args, &ret), 0);

    amxc_var_clean(&args);
    amxc_var_clean(&ret);
    amxd_dm_clean(&dm);
}

void test_amxd_function_get_name_invalid(UNUSED void** state) {
    assert_ptr_equal(amxd_function_get_name(NULL), NULL);
}

void test_amxd_function_attributes(UNUSED void** state) {
    amxd_function_t* function = NULL;

    assert_int_equal(amxd_function_new(&function, "templ_func", AMXC_VAR_ID_CSTRING, test_func), 0);
    assert_false(amxd_function_is_attr_set(function, amxd_fattr_template));
    assert_false(amxd_function_is_attr_set(function, amxd_fattr_instance));
    assert_false(amxd_function_is_attr_set(function, amxd_fattr_private));

    assert_int_equal(amxd_function_set_attr(function, amxd_fattr_template, true), 0);
    assert_true(amxd_function_is_attr_set(function, amxd_fattr_template));
    assert_int_equal(amxd_function_set_attr(function, amxd_fattr_template, false), 0);
    assert_false(amxd_function_is_attr_set(function, amxd_fattr_template));

    assert_int_equal(amxd_function_set_attr(function, amxd_fattr_instance, true), 0);
    assert_true(amxd_function_is_attr_set(function, amxd_fattr_instance));
    assert_int_equal(amxd_function_set_attr(function, amxd_fattr_instance, false), 0);
    assert_false(amxd_function_is_attr_set(function, amxd_fattr_instance));

    assert_int_equal(amxd_function_set_attr(function, amxd_fattr_private, true), 0);
    assert_true(amxd_function_is_attr_set(function, amxd_fattr_private));
    assert_int_equal(amxd_function_set_attr(function, amxd_fattr_private, false), 0);
    assert_false(amxd_function_is_attr_set(function, amxd_fattr_private));

    assert_int_not_equal(amxd_function_set_attr(NULL, amxd_fattr_private, true), 0);
    assert_false(amxd_function_is_attr_set(NULL, amxd_fattr_private));

    assert_int_equal(amxd_function_set_attrs(function, SET_BIT(amxd_fattr_template) |
                                             SET_BIT(amxd_fattr_instance) |
                                             SET_BIT(amxd_fattr_private) |
                                             SET_BIT(amxd_fattr_async), false), 0);
    assert_false(amxd_function_is_attr_set(function, amxd_fattr_template));
    assert_false(amxd_function_is_attr_set(function, amxd_fattr_instance));
    assert_false(amxd_function_is_attr_set(function, amxd_fattr_private));
    assert_false(amxd_function_is_attr_set(function, amxd_fattr_async));

    assert_int_equal(amxd_function_set_attrs(function, SET_BIT(amxd_fattr_template) |
                                             SET_BIT(amxd_fattr_instance) |
                                             SET_BIT(amxd_fattr_private) |
                                             SET_BIT(amxd_fattr_async), true), 0);
    assert_true(amxd_function_is_attr_set(function, amxd_fattr_template));
    assert_true(amxd_function_is_attr_set(function, amxd_fattr_instance));
    assert_true(amxd_function_is_attr_set(function, amxd_fattr_private));
    assert_true(amxd_function_is_attr_set(function, amxd_fattr_async));

    assert_int_equal(amxd_function_set_attrs(function, SET_BIT(amxd_fattr_template) |
                                             SET_BIT(amxd_fattr_instance) |
                                             SET_BIT(amxd_fattr_private), false), 0);
    assert_false(amxd_function_is_attr_set(function, amxd_fattr_template));
    assert_false(amxd_function_is_attr_set(function, amxd_fattr_instance));
    assert_false(amxd_function_is_attr_set(function, amxd_fattr_private));

    assert_int_not_equal(amxd_function_set_attrs(function, SET_BIT(amxd_fattr_template) |
                                                 SET_BIT(amxd_fattr_instance) |
                                                 SET_BIT(amxd_fattr_private) |
                                                 SET_BIT(5), false), 0);
    assert_int_not_equal(amxd_function_set_attrs(NULL, SET_BIT(amxd_fattr_template) |
                                                 SET_BIT(amxd_fattr_instance) |
                                                 SET_BIT(amxd_fattr_private), true), 0);

    amxd_function_delete(&function);
}

void test_amxd_function_are_args_valid(UNUSED void** state) {
    amxd_function_t* function = NULL;
    amxd_object_t* object = NULL;

    amxc_var_t def_val;
    amxc_var_t args;
    amxc_var_t ret;
    amxc_var_init(&def_val);
    amxc_var_init(&args);
    amxc_var_init(&ret);
    amxc_var_set(uint32_t, &def_val, 10);

    assert_int_equal(amxd_object_new(&object, amxd_object_singleton, "test_object"), 0);

    assert_int_equal(amxd_function_new(&function, "my_func", AMXC_VAR_ID_CSTRING, test_func), 0);
    assert_int_equal(amxd_function_new_arg(function, "arg1", AMXC_VAR_ID_UINT32, NULL), 0);
    amxd_function_arg_set_attr(function, "arg1", amxd_aattr_mandatory, true);
    amxd_function_arg_set_attr(function, "arg1", amxd_aattr_in, true);
    assert_int_equal(amxd_function_new_arg(function, "arg2", AMXC_VAR_ID_UINT32, &def_val), 0);
    amxd_function_arg_set_attr(function, "arg2", amxd_aattr_strict, true);
    amxd_function_arg_set_attr(function, "arg2", amxd_aattr_in, true);
    amxc_var_set(cstring_t, &def_val, "Hello");
    assert_int_equal(amxd_function_new_arg(function, "arg3", AMXC_VAR_ID_CSTRING, &def_val), 0);
    amxd_function_arg_set_attr(function, "arg3", amxd_aattr_in, true);
    assert_int_equal(amxd_function_new_arg(function, "arg4", AMXC_VAR_ID_BOOL, NULL), 0);
    amxd_function_arg_set_attr(function, "arg4", amxd_aattr_out, true);
    amxd_function_arg_set_attr(function, "arg4", amxd_aattr_in, false);

    assert_int_equal(amxd_object_add_function(object, function), 0);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &args, "arg1", "0xFF");
    amxc_var_add_key(uint32_t, &args, "arg2", 123);
    amxc_var_add_key(cstring_t, &args, "arg3", "test test");
    assert_int_equal(amxd_object_invoke_function(object, "my_func", &args, &ret), 0);
    amxc_var_clean(&args);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &args, "arg1", "0xFF");
    amxc_var_add_key(bool, &args, "arg2", true);
    amxc_var_add_key(cstring_t, &args, "arg3", "test test");
    assert_int_not_equal(amxd_object_invoke_function(object, "my_func", &args, &ret), 0);
    amxc_var_clean(&args);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &args, "arg1", "0xFF");
    amxc_var_add_key(uint32_t, &args, "arg2", 999);
    assert_int_equal(amxd_object_invoke_function(object, "my_func", &args, &ret), 0);
    amxc_var_clean(&args);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(uint32_t, &args, "arg2", 999);
    assert_int_not_equal(amxd_object_invoke_function(object, "my_func", &args, &ret), 0);
    amxc_var_clean(&args);

    amxc_var_set_type(&args, AMXC_VAR_ID_LIST);
    amxc_var_add(cstring_t, &args, "0xFF");
    amxc_var_add(uint32_t, &args, 123);
    amxc_var_add(cstring_t, &args, "test test");
    assert_int_not_equal(amxd_object_invoke_function(object, "my_func", &args, &ret), 0);
    amxc_var_clean(&args);

    amxd_function_delete(&function);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxd_function_new(&function, "my_func", AMXC_VAR_ID_CSTRING, test_func), 0);
    assert_int_equal(amxd_object_add_function(object, function), 0);

    amxc_var_add_key(cstring_t, &args, "arg1", "0xFF");
    amxc_var_add_key(uint32_t, &args, "arg2", 123);
    amxc_var_add_key(cstring_t, &args, "arg3", "test test");
    assert_int_equal(amxd_object_invoke_function(object, "my_func", &args, &ret), 0);
    amxc_var_clean(&args);

    assert_int_equal(amxd_function_new(&function, "my_func", AMXC_VAR_ID_CSTRING, test_func), 0);
    assert_int_equal(amxd_function_new_arg(function, "arg1", AMXC_VAR_ID_ANY, NULL), 0);
    assert_int_not_equal(amxd_function_arg_set_attr(function, "arg1", amxd_aattr_strict, true), 0);
    assert_int_not_equal(amxd_function_arg_set_attrs(function, "arg1", SET_BIT(amxd_aattr_strict), true), 0);
    assert_int_not_equal(amxd_function_new_arg(function, "arg2", AMXC_VAR_ID_CUSTOM_BASE + 20, NULL), 0);
    amxd_function_delete(&function);

    amxd_object_delete(&object);
    amxc_var_clean(&def_val);
}

void test_amxd_function_flags(UNUSED void** state) {
    amxd_function_t* function = NULL;
    amxd_object_t* object = NULL;

    amxc_var_t def_val;
    amxc_var_t args;
    amxc_var_t ret;
    amxc_var_init(&def_val);
    amxc_var_init(&args);
    amxc_var_init(&ret);
    amxc_var_set(uint32_t, &def_val, 10);

    assert_int_equal(amxd_object_new(&object, amxd_object_singleton, "test_object"), 0);

    assert_int_equal(amxd_function_new(&function, "my_func", AMXC_VAR_ID_CSTRING, test_func), 0);
    assert_int_equal(amxd_function_new_arg(function, "arg1", AMXC_VAR_ID_UINT32, NULL), 0);
    amxd_function_arg_set_attr(function, "arg1", amxd_aattr_mandatory, true);
    amxd_function_arg_set_attr(function, "arg1", amxd_aattr_in, true);
    assert_int_equal(amxd_function_new_arg(function, "arg2", AMXC_VAR_ID_UINT32, &def_val), 0);
    amxd_function_arg_set_attr(function, "arg2", amxd_aattr_strict, true);
    amxd_function_arg_set_attr(function, "arg2", amxd_aattr_in, true);
    amxc_var_set(cstring_t, &def_val, "Hello");
    assert_int_equal(amxd_function_new_arg(function, "arg3", AMXC_VAR_ID_CSTRING, &def_val), 0);
    amxd_function_arg_set_attr(function, "arg3", amxd_aattr_in, true);
    assert_int_equal(amxd_function_new_arg(function, "arg4", AMXC_VAR_ID_BOOL, NULL), 0);
    amxd_function_arg_set_attr(function, "arg4", amxd_aattr_out, true);
    amxd_function_arg_set_attr(function, "arg4", amxd_aattr_in, false);

    assert_int_equal(amxd_object_add_function(object, function), 0);

    amxd_function_set_flag(function, "async");
    assert_true(amxd_function_has_flag(function, "async"));
    assert_false(amxd_function_has_flag(function, "storage"));

    assert_int_equal(amxd_function_describe(function, &ret), 0);
    assert_non_null(GETP_ARG(&ret, "flags.0"));

    amxd_function_unset_flag(function, "async");
    assert_false(amxd_function_has_flag(function, "async"));

    amxc_var_clean(&args);
    amxc_var_clean(&ret);
    amxd_object_delete(&object);
    amxc_var_clean(&def_val);
}
