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

#include "test_amxd_parameter.h"

#include <amxc/amxc_macros.h>
void test_amxd_parameter_new_delete(UNUSED void** state) {
    amxd_param_t* param = NULL;

    assert_int_equal(amxd_param_new(&param, "Param1", AMXC_VAR_ID_CSTRING), 0);
    assert_ptr_not_equal(param, NULL);
    assert_int_equal(amxc_var_type_of(&param->value), AMXC_VAR_ID_CSTRING);
    assert_int_equal(param->attr.templ, 0);
    assert_int_equal(param->attr.instance, 0);
    assert_int_equal(param->attr.priv, 0);
    assert_int_equal(param->attr.read_only, 0);
    assert_int_equal(param->attr.persistent, 0);
    assert_int_equal(param->attr.variable, 0);

    amxd_param_delete(&param);
    assert_ptr_equal(param, NULL);
    amxd_param_delete(&param);

    assert_int_equal(amxd_param_new(&param, "Param1", AMXC_VAR_ID_CSTRING), 0);
    assert_ptr_not_equal(param, NULL);
    amxd_param_delete(&param);
    amxd_param_delete(NULL);
    assert_ptr_equal(param, NULL);
}

void test_amxd_parameter_new_delete_invalid_args(UNUSED void** state) {
    amxd_param_t* param = NULL;

    assert_int_equal(amxd_param_new(&param, "Param1", AMXC_VAR_ID_CSTRING), 0);
    assert_ptr_not_equal(param, NULL);
    amxd_param_delete(&param);

    assert_int_not_equal(amxd_param_new(&param, "Param1", AMXC_VAR_ID_CUSTOM_BASE + 100), 0);
    assert_ptr_equal(param, NULL);

    assert_int_not_equal(amxd_param_new(NULL, "Param1", AMXC_VAR_ID_CSTRING), 0);
    assert_ptr_equal(param, NULL);

    assert_int_not_equal(amxd_param_new(&param, "123", AMXC_VAR_ID_CSTRING), 0);
    assert_ptr_equal(param, NULL);
    assert_int_not_equal(amxd_param_new(&param, "MyParam@test", AMXC_VAR_ID_CSTRING), 0);
    assert_ptr_equal(param, NULL);
    assert_int_not_equal(amxd_param_new(&param, "", AMXC_VAR_ID_CSTRING), 0);
    assert_ptr_equal(param, NULL);
    assert_int_not_equal(amxd_param_new(&param, NULL, AMXC_VAR_ID_CSTRING), 0);
    assert_ptr_equal(param, NULL);

    amxd_param_delete(&param);
}

void test_amxd_parameter_copy(UNUSED void** state) {
    amxd_param_t* param = NULL;
    amxd_param_t* cparam = NULL;

    assert_int_equal(amxd_param_new(&param, "Param1", AMXC_VAR_ID_BOOL), 0);
    assert_int_equal(amxd_param_copy(&cparam, param), 0);
    assert_int_equal(amxc_var_type_of(&cparam->value), AMXC_VAR_ID_BOOL);
    assert_string_equal(cparam->name, "Param1");
    assert_int_equal(cparam->attr.templ, 0);
    assert_int_equal(cparam->attr.instance, 0);
    assert_int_equal(cparam->attr.priv, 0);
    assert_int_equal(cparam->attr.read_only, 0);
    assert_int_equal(cparam->attr.persistent, 0);
    assert_int_equal(cparam->attr.variable, 0);
    amxd_param_delete(&cparam);

    amxd_param_set_flag(param, "TestFlag");
    assert_int_equal(amxd_param_copy(&cparam, param), 0);
    assert_true(amxd_param_has_flag(cparam, "TestFlag"));

    amxd_param_delete(&cparam);
    amxd_param_delete(&param);
}

void test_amxd_parameter_copy_invalid(UNUSED void** state) {
    amxd_param_t* param = NULL;
    amxd_param_t* cparam = NULL;

    assert_int_equal(amxd_param_new(&param, "Param1", AMXC_VAR_ID_BOOL), 0);
    assert_int_not_equal(amxd_param_copy(NULL, param), 0);
    assert_int_not_equal(amxd_param_copy(&cparam, NULL), 0);

    amxd_param_delete(&param);
    amxd_param_delete(&cparam);
}

void test_amxd_parameter_owner(UNUSED void** state) {
    amxd_object_t* object1 = NULL;
    amxd_object_t* object2 = NULL;
    amxd_param_t* param1 = NULL;
    amxd_param_t* param2 = NULL;

    assert_int_equal(amxd_object_new(&object1, amxd_object_singleton, "obj1"), 0);
    assert_int_equal(amxd_object_new(&object2, amxd_object_singleton, "obj2"), 0);
    assert_int_equal(amxd_param_new(&param1, "param", AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(amxd_param_new(&param2, "param", AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(amxd_object_add_param(object1, param1), 0);
    assert_int_not_equal(amxd_object_add_param(object2, param1), 0);

    assert_ptr_equal(amxd_param_get_owner(param1), object1);
    assert_ptr_equal(amxd_param_get_owner(param2), NULL);
    assert_ptr_equal(amxd_param_get_owner(NULL), NULL);

    amxd_object_delete(&object1);
    amxd_object_delete(&object2);
    amxd_param_delete(&param2);
}

void test_amxd_parameter_name(UNUSED void** state) {
    amxd_param_t* param1 = NULL;
    assert_int_equal(amxd_param_new(&param1, "param", AMXC_VAR_ID_CSTRING), 0);
    assert_string_equal(amxd_param_get_name(param1), "param");
    assert_ptr_equal(amxd_param_get_name(NULL), NULL);

    amxd_param_delete(&param1);
}

void test_amxd_param_attributes(UNUSED void** state) {
    amxd_param_t* param = NULL;

    assert_int_equal(amxd_param_new(&param, "templ_func", AMXC_VAR_ID_CSTRING), 0);
    assert_false(amxd_param_is_attr_set(param, amxd_pattr_template));
    assert_false(amxd_param_is_attr_set(param, amxd_pattr_instance));
    assert_false(amxd_param_is_attr_set(param, amxd_pattr_private));
    assert_false(amxd_param_is_attr_set(param, amxd_pattr_read_only));
    assert_false(amxd_param_is_attr_set(param, amxd_pattr_variable));
    assert_false(amxd_param_is_attr_set(param, amxd_pattr_persistent));

    assert_int_equal(amxd_param_set_attr(param, amxd_pattr_template, true), 0);
    assert_true(amxd_param_is_attr_set(param, amxd_pattr_template));
    assert_int_equal(amxd_param_set_attr(param, amxd_pattr_template, false), 0);
    assert_false(amxd_param_is_attr_set(param, amxd_pattr_template));

    assert_int_equal(amxd_param_set_attr(param, amxd_pattr_instance, true), 0);
    assert_true(amxd_param_is_attr_set(param, amxd_pattr_instance));
    assert_int_equal(amxd_param_set_attr(param, amxd_pattr_instance, false), 0);
    assert_false(amxd_param_is_attr_set(param, amxd_pattr_instance));

    assert_int_equal(amxd_param_set_attr(param, amxd_pattr_private, true), 0);
    assert_true(amxd_param_is_attr_set(param, amxd_pattr_private));
    assert_int_equal(amxd_param_set_attr(param, amxd_pattr_private, false), 0);
    assert_false(amxd_param_is_attr_set(param, amxd_pattr_private));

    assert_int_equal(amxd_param_set_attr(param, amxd_pattr_read_only, true), 0);
    assert_true(amxd_param_is_attr_set(param, amxd_pattr_read_only));
    assert_int_equal(amxd_param_set_attr(param, amxd_pattr_read_only, false), 0);
    assert_false(amxd_param_is_attr_set(param, amxd_pattr_read_only));

    assert_int_equal(amxd_param_set_attr(param, amxd_pattr_variable, true), 0);
    assert_true(amxd_param_is_attr_set(param, amxd_pattr_variable));
    assert_int_equal(amxd_param_set_attr(param, amxd_pattr_variable, false), 0);
    assert_false(amxd_param_is_attr_set(param, amxd_pattr_variable));

    assert_int_equal(amxd_param_set_attr(param, amxd_pattr_persistent, true), 0);
    assert_true(amxd_param_is_attr_set(param, amxd_pattr_persistent));
    assert_int_equal(amxd_param_set_attr(param, amxd_pattr_persistent, false), 0);
    assert_false(amxd_param_is_attr_set(param, amxd_pattr_persistent));


    assert_int_not_equal(amxd_param_set_attr(NULL, amxd_pattr_persistent, true), 0);
    assert_false(amxd_param_is_attr_set(NULL, amxd_pattr_persistent));

    assert_int_equal(amxd_param_set_attrs(param, SET_BIT(amxd_pattr_template) |
                                          SET_BIT(amxd_pattr_instance) |
                                          SET_BIT(amxd_pattr_private) |
                                          SET_BIT(amxd_pattr_read_only) |
                                          SET_BIT(amxd_pattr_variable) |
                                          SET_BIT(amxd_pattr_persistent), false), 0);
    assert_false(amxd_param_is_attr_set(param, amxd_pattr_template));
    assert_false(amxd_param_is_attr_set(param, amxd_pattr_instance));
    assert_false(amxd_param_is_attr_set(param, amxd_pattr_private));
    assert_false(amxd_param_is_attr_set(param, amxd_pattr_read_only));
    assert_false(amxd_param_is_attr_set(param, amxd_pattr_variable));
    assert_false(amxd_param_is_attr_set(param, amxd_pattr_persistent));

    assert_int_equal(amxd_param_set_attrs(param, SET_BIT(amxd_pattr_template) |
                                          SET_BIT(amxd_pattr_instance) |
                                          SET_BIT(amxd_pattr_private) |
                                          SET_BIT(amxd_pattr_read_only) |
                                          SET_BIT(amxd_pattr_variable) |
                                          SET_BIT(amxd_pattr_persistent), true), 0);
    assert_true(amxd_param_is_attr_set(param, amxd_pattr_template));
    assert_true(amxd_param_is_attr_set(param, amxd_pattr_instance));
    assert_true(amxd_param_is_attr_set(param, amxd_pattr_private));
    assert_true(amxd_param_is_attr_set(param, amxd_pattr_read_only));
    assert_true(amxd_param_is_attr_set(param, amxd_pattr_variable));
    assert_true(amxd_param_is_attr_set(param, amxd_pattr_persistent));

    assert_int_equal(amxd_param_set_attrs(param, SET_BIT(amxd_pattr_template) |
                                          SET_BIT(amxd_pattr_instance) |
                                          SET_BIT(amxd_pattr_private) |
                                          SET_BIT(amxd_pattr_read_only) |
                                          SET_BIT(amxd_pattr_variable) |
                                          SET_BIT(amxd_pattr_persistent), false), 0);
    assert_false(amxd_param_is_attr_set(param, amxd_pattr_template));
    assert_false(amxd_param_is_attr_set(param, amxd_pattr_instance));
    assert_false(amxd_param_is_attr_set(param, amxd_pattr_private));
    assert_false(amxd_param_is_attr_set(param, amxd_pattr_read_only));
    assert_false(amxd_param_is_attr_set(param, amxd_pattr_variable));
    assert_false(amxd_param_is_attr_set(param, amxd_pattr_persistent));

    assert_int_not_equal(amxd_param_set_attrs(param, SET_BIT(amxd_pattr_template) |
                                              SET_BIT(amxd_pattr_instance) |
                                              SET_BIT(amxd_pattr_private) |
                                              SET_BIT((amxd_pattr_max + 1)), false), 0);
    assert_int_not_equal(amxd_param_set_attrs(NULL, SET_BIT(amxd_pattr_template) |
                                              SET_BIT(amxd_pattr_instance) |
                                              SET_BIT(amxd_pattr_private), true), 0);

    amxd_param_delete(&param);
}

void test_amxd_param_get_value(UNUSED void** state) {
    amxd_param_t* param = NULL;
    amxc_var_t value;

    amxc_var_init(&value);
    assert_int_equal(amxd_param_new(&param, "Param1", AMXC_VAR_ID_CSTRING), 0);
    assert_ptr_not_equal(param, NULL);

    assert_int_equal(amxd_param_get_value(param, &value), 0);
    assert_int_not_equal(amxd_param_get_value(param, NULL), 0);
    assert_int_not_equal(amxd_param_get_value(NULL, &value), 0);

    amxd_param_delete(&param);
}

void test_amxd_param_set_value(UNUSED void** state) {
    amxd_param_t* param = NULL;
    amxc_var_t value;

    amxc_var_init(&value);
    amxc_var_set(cstring_t, &value, "ABCD");

    assert_int_equal(amxd_param_new(&param, "Param1", AMXC_VAR_ID_CSTRING), 0);
    assert_ptr_not_equal(param, NULL);

    assert_int_equal(amxd_param_set_value(param, &value), 0);
    assert_int_not_equal(amxd_param_set_value(param, NULL), 0);
    assert_int_not_equal(amxd_param_set_value(NULL, &value), 0);

    amxd_param_delete(&param);
    amxc_var_clean(&value);
}

void test_amxd_param_validate(UNUSED void** state) {
    amxd_param_t* param = NULL;
    amxc_var_t value;

    amxc_var_init(&value);
    amxc_var_set(cstring_t, &value, "ABCD");

    assert_int_equal(amxd_param_new(&param, "Param1", AMXC_VAR_ID_CSTRING), 0);
    assert_ptr_not_equal(param, NULL);

    assert_int_equal(amxd_param_validate(param, &value), 0);
    assert_int_not_equal(amxd_param_validate(param, NULL), 0);
    assert_int_not_equal(amxd_param_validate(NULL, &value), 0);

    amxd_param_delete(&param);
    amxc_var_clean(&value);
}

void test_amxd_param_delete(UNUSED void** state) {
    amxd_param_t* param = NULL;

    assert_int_equal(amxd_param_new(&param, "Param1", AMXC_VAR_ID_CSTRING), 0);
    assert_ptr_not_equal(param, NULL);

    amxd_param_delete(&param);
    assert_ptr_equal(param, NULL);
    amxd_param_delete(&param);

    amxd_param_delete(NULL);

    amxd_param_delete(&param);
}

void test_amxd_param_describe(UNUSED void** state) {
    amxd_param_t* param = NULL;
    amxc_var_t value;

    amxc_var_init(&value);

    assert_int_equal(amxd_param_new(&param, "Param1", AMXC_VAR_ID_CSTRING), 0);
    assert_ptr_not_equal(param, NULL);

    assert_int_equal(amxd_param_describe(param, &value), 0);
    assert_int_equal(amxc_var_type_of(&value), AMXC_VAR_ID_HTABLE);
    assert_ptr_not_equal(amxc_var_get_key(&value, "name", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_key(&value, "type_name", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_key(&value, "type_id", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_key(&value, "attributes", AMXC_VAR_FLAG_DEFAULT), NULL);

    assert_int_not_equal(amxd_param_describe(param, NULL), 0);
    assert_int_not_equal(amxd_param_describe(NULL, &value), 0);

    amxc_var_clean(&value);
    amxd_param_delete(&param);
}

void test_amxd_param_type(UNUSED void** state) {
    amxd_param_t* param = NULL;

    assert_int_equal(amxd_param_new(&param, "Param1", AMXC_VAR_ID_CSTRING), 0);
    assert_ptr_not_equal(param, NULL);
    assert_int_equal(amxd_param_get_type(param), AMXC_VAR_ID_CSTRING);
    amxd_param_delete(&param);

    assert_int_not_equal(amxd_param_new(&param, "Param1", AMXC_VAR_ID_ANY), 0);
    assert_ptr_equal(param, NULL);

    assert_int_not_equal(amxd_param_new(&param, "Param1", AMXC_VAR_ID_LIST), 0);
    assert_ptr_equal(param, NULL);

    assert_int_not_equal(amxd_param_new(&param, "Param1", AMXC_VAR_ID_HTABLE), 0);
    assert_ptr_equal(param, NULL);

    assert_int_not_equal(amxd_param_new(&param, "Param1", AMXC_VAR_ID_CUSTOM_BASE), 0);
    assert_ptr_equal(param, NULL);

    assert_int_not_equal(amxd_param_new(&param, "Param1", AMXC_VAR_ID_CUSTOM_BASE + 100), 0);
    assert_ptr_equal(param, NULL);

    assert_int_equal(amxd_param_new(&param, "Param1", AMXC_VAR_ID_BOOL), 0);
    assert_ptr_not_equal(param, NULL);
    assert_int_equal(amxd_param_get_type(param), AMXC_VAR_ID_BOOL);
    amxd_param_delete(&param);

    amxd_param_delete(&param);
}
