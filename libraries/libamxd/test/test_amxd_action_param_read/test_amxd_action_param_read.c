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
#include <amxd/amxd_transaction.h>

#include "test_amxd_action_param_read.h"

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
    assert_int_equal(amxd_param_new(&param, "inst_param", AMXC_VAR_ID_CSTRING), 0);
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

void test_amxd_param_read(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxd_object_t* instance = NULL;
    amxd_param_t* param = NULL;
    amxc_var_t retval;

    amxc_var_init(&retval);

    template = test_build_dm();
    assert_int_equal(amxd_object_new_instance(&instance, template, NULL, 0, NULL), 0);

    param = amxd_object_get_param_def(template, "templ_param");
    assert_int_equal(amxd_action_param_read(NULL, param, action_param_read, NULL, &retval, NULL), 0);
    assert_int_equal(amxc_var_type_of(&retval), amxd_param_get_type(param));
    param = amxd_object_get_param_def(template, "param");
    assert_int_equal(amxd_action_param_read(NULL, param, action_param_read, NULL, &retval, NULL), 0);
    assert_int_equal(amxc_var_type_of(&retval), amxd_param_get_type(param));
    param = amxd_object_get_param_def(instance, "param");
    assert_int_equal(amxd_action_param_read(NULL, param, action_param_read, NULL, &retval, NULL), 0);
    assert_int_equal(amxc_var_type_of(&retval), amxd_param_get_type(param));
    param = amxd_object_get_param_def(instance, "inst_param");
    assert_int_equal(amxd_action_param_read(NULL, param, action_param_read, NULL, &retval, NULL), 0);
    assert_int_equal(amxc_var_type_of(&retval), amxd_param_get_type(param));

    param = amxd_object_get_param_def(template, "templ_param");
    assert_int_not_equal(amxd_action_param_read(NULL, NULL, action_param_read, NULL, &retval, NULL), 0);
    assert_int_not_equal(amxd_action_param_read(NULL, param, action_object_list, NULL, &retval, NULL), 0);
    assert_int_not_equal(amxd_action_param_read(NULL, param, action_param_read, NULL, NULL, NULL), 0);
    assert_int_equal(amxd_action_param_read(NULL, param, action_param_read, NULL, &retval, NULL), 0);

    amxc_var_clean(&retval);
    amxd_dm_clean(&dm);
}

void test_amxd_param_read_with_cb(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxd_object_t* instance = NULL;
    amxd_param_t* param = NULL;
    amxc_var_t retval;

    amxc_var_init(&retval);

    template = test_build_dm();
    assert_int_equal(amxd_object_new_instance(&instance, template, NULL, 0, NULL), 0);
    param = amxd_object_get_param_def(template, "templ_param");
    assert_int_equal(amxd_param_add_action_cb(param, action_param_read, amxd_action_param_read, NULL), 0);

    assert_int_equal(amxd_dm_invoke_action(NULL, param, action_param_read, NULL, &retval), 0);
    assert_int_equal(amxc_var_type_of(&retval), amxd_param_get_type(param));
    param = amxd_object_get_param_def(template, "param");
    assert_int_equal(amxd_dm_invoke_action(NULL, param, action_param_read, NULL, &retval), 0);
    assert_int_equal(amxc_var_type_of(&retval), amxd_param_get_type(param));
    param = amxd_object_get_param_def(instance, "param");
    assert_int_equal(amxd_dm_invoke_action(NULL, param, action_param_read, NULL, &retval), 0);
    assert_int_equal(amxc_var_type_of(&retval), amxd_param_get_type(param));
    param = amxd_object_get_param_def(instance, "inst_param");
    assert_int_equal(amxd_dm_invoke_action(NULL, param, action_param_read, NULL, &retval), 0);
    assert_int_equal(amxc_var_type_of(&retval), amxd_param_get_type(param));

    param = amxd_object_get_param_def(template, "templ_param");
    assert_int_not_equal(amxd_dm_invoke_action(NULL, NULL, action_param_read, NULL, &retval), 0);
    assert_int_not_equal(amxd_dm_invoke_action(NULL, param, action_object_list, NULL, &retval), 0);
    assert_int_not_equal(amxd_dm_invoke_action(NULL, param, action_param_read, NULL, NULL), 0);
    assert_int_equal(amxd_dm_invoke_action(NULL, param, action_param_read, NULL, &retval), 0);

    amxc_var_clean(&retval);
    amxd_dm_clean(&dm);
}

void test_amxd_param_read_hidden(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxd_object_t* instance = NULL;
    amxd_param_t* param = NULL;
    amxd_trans_t trans;
    amxc_var_t retval;
    amxc_var_t args;

    amxc_var_init(&retval);
    amxc_var_init(&args);
    amxd_trans_init(&trans);

    template = test_build_dm();
    param = amxd_object_get_param_def(template, "inst_param");
    assert_int_equal(amxd_param_add_action_cb(param, action_param_read, amxd_action_param_read_hidden_value, NULL), 0);

    assert_int_equal(amxd_object_new_instance(&instance, template, NULL, 0, NULL), 0);

    amxd_trans_select_object(&trans, instance);
    amxd_trans_set_value(cstring_t, &trans, "inst_param", "TEST");
    assert_int_equal(amxd_trans_apply(&trans, &dm), 0);

    param = amxd_object_get_param_def(instance, "inst_param");

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(uint32_t, &args, "access", amxd_dm_access_public);
    assert_int_equal(amxd_dm_invoke_action(instance, param, action_param_read, &args, &retval), 0);
    assert_int_equal(amxc_var_type_of(&retval), AMXC_VAR_ID_CSTRING);
    assert_string_equal(amxc_var_constcast(cstring_t, &retval), "");

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(uint32_t, &args, "access", amxd_dm_access_protected);
    assert_int_equal(amxd_dm_invoke_action(instance, param, action_param_read, &args, &retval), 0);
    amxc_var_dump(&retval, STDOUT_FILENO);
    assert_int_equal(amxc_var_type_of(&retval), AMXC_VAR_ID_CSTRING);
    assert_string_equal(amxc_var_constcast(cstring_t, &retval), "TEST");

    assert_int_not_equal(amxd_action_param_read_hidden_value(NULL, NULL, action_param_read, NULL, &retval, NULL), 0);
    assert_int_not_equal(amxd_action_param_read_hidden_value(NULL, param, action_object_list, NULL, &retval, NULL), 0);
    assert_int_not_equal(amxd_action_param_read_hidden_value(NULL, param, action_param_read, NULL, NULL, NULL), 0);
    assert_int_equal(amxd_action_param_read_hidden_value(NULL, param, action_param_read, NULL, &retval, NULL), 0);

    amxc_var_clean(&retval);
    amxc_var_clean(&args);
    amxd_trans_clean(&trans);
    amxd_dm_clean(&dm);
}

void test_amxd_param_read_empty_string(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxd_status_t status = amxd_status_ok;

    template = test_build_dm();
    assert_int_equal(amxd_object_set_value(cstring_t, template, "templ_param", ""), amxd_status_ok);
    char* foo = amxd_object_get_value(cstring_t,
                                      template,
                                      "templ_param",
                                      &status);

    assert_int_equal(status, amxd_status_ok);
    assert_non_null(foo);

    free(foo);
    amxd_dm_clean(&dm);
}