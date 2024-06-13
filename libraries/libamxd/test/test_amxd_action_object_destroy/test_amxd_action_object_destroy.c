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

#include <amxd/amxd_common.h>
#include <amxd/amxd_dm.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_parameter.h>
#include <amxd/amxd_function.h>
#include <amxd/amxd_action.h>
#include <amxd/amxd_transaction.h>

#include "test_amxd_action_object_destroy.h"

#include <amxc/amxc_macros.h>
static amxd_dm_t dm;
static int counter = 0;

static amxd_status_t amxd_action_dummy_cb(UNUSED amxd_object_t* const object,
                                          UNUSED amxd_param_t* const param,
                                          UNUSED amxd_action_t reason,
                                          UNUSED const amxc_var_t* const args,
                                          UNUSED amxc_var_t* const retval,
                                          UNUSED void* priv) {
    counter++;
    assert_true(counter < 100);

    return amxd_status_unknown_error;
}

static amxd_object_t* test_build_dm(void) {
    amxd_object_t* object = NULL;
    amxd_object_t* template = NULL;
    amxd_object_t* child_templ = NULL;

    amxd_param_t* param = NULL;

    assert_int_equal(amxd_dm_init(&dm), 0);

    assert_int_equal(amxd_object_new(&template, amxd_object_template, "parent"), 0);
    assert_int_equal(amxd_object_add_action_cb(template, action_object_destroy, amxd_action_dummy_cb, NULL), 0);
    assert_int_equal(amxd_dm_add_root_object(&dm, template), 0);
    assert_int_equal(amxd_object_new(&object, amxd_object_singleton, "child"), 0);
    assert_int_equal(amxd_object_add_object(template, object), 0);
    assert_int_equal(amxd_object_new(&child_templ, amxd_object_template, "child_template"), 0);
    assert_int_equal(amxd_object_add_object(object, child_templ), 0);


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
    counter = 0;

    return template;
}

void test_amxd_object_destroy_action_can_not_fail(UNUSED void** state) {
    amxd_object_t* template = NULL;

    template = test_build_dm();
    assert_int_equal(amxd_dm_invoke_action(template, NULL, action_object_destroy, NULL, NULL), 0);
    amxd_dm_clean(&dm);
}

void test_amxd_object_delete(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxd_object_t* instance = NULL;

    template = test_build_dm();

    assert_int_equal(amxd_object_new_instance(&instance, template, NULL, 1, NULL), 0);
    assert_ptr_not_equal(instance, NULL);

    assert_int_equal(amxd_action_object_destroy(instance, NULL, action_object_destroy, NULL, NULL, NULL), 0);
    instance = amxd_object_get_instance(template, NULL, 1);
    assert_ptr_not_equal(instance, NULL);
    amxd_object_delete(&instance);

    assert_int_equal(amxd_object_new_instance(&instance, template, NULL, 1, NULL), 0);
    assert_ptr_not_equal(instance, NULL);

    amxd_object_delete(&instance);
    assert_ptr_equal(instance, NULL);

    amxd_object_delete(&instance);
    amxd_object_delete(NULL);

    assert_int_equal(amxd_action_object_destroy(NULL, NULL, action_object_destroy, NULL, NULL, NULL), 0);
    assert_int_not_equal(amxd_action_object_destroy(template, NULL, action_object_read, NULL, NULL, NULL), 0);

    amxd_dm_clean(&dm);
}

void test_amxd_object_delete_with_cb(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxd_object_t* instance = NULL;

    template = test_build_dm();
    amxd_object_add_action_cb(template, action_object_destroy, amxd_action_object_destroy, NULL);
    assert_int_equal(amxd_object_new_instance(&instance, template, NULL, 1, NULL), 0);
    assert_ptr_not_equal(instance, NULL);

    amxd_object_delete(&instance);
    assert_ptr_equal(instance, NULL);

    amxd_object_delete(&instance);
    amxd_object_delete(NULL);

    amxd_dm_clean(&dm);
}

static amxd_status_t check_callback_order(amxd_object_t* const object,
                                          UNUSED amxd_param_t* const param,
                                          UNUSED amxd_action_t reason,
                                          UNUSED const amxc_var_t* const args,
                                          UNUSED amxc_var_t* const retval,
                                          UNUSED void* priv) {
    char* path = amxd_object_get_path(object, 0);
    printf("Destroy object %s\n", path);
    check_expected(path);
    free(path);
    return amxd_status_ok;
}

void test_amxd_object_destroy_cb_order(UNUSED void** state) {
    amxd_object_t* object = NULL;
    amxd_trans_t transaction;

    object = test_build_dm();

    amxd_object_add_action_cb(object, action_object_destroy, check_callback_order, NULL);
    object = amxd_object_findf(object, "child");
    amxd_object_add_action_cb(object, action_object_destroy, check_callback_order, NULL);
    object = amxd_object_findf(object, "child_template");
    amxd_object_add_action_cb(object, action_object_destroy, check_callback_order, NULL);

    amxd_trans_init(&transaction);
    amxd_trans_select_pathf(&transaction, "parent");
    amxd_trans_add_inst(&transaction, 0, NULL);
    amxd_trans_select_pathf(&transaction, ".child.child_template");
    amxd_trans_add_inst(&transaction, 0, NULL);
    assert_int_equal(amxd_trans_apply(&transaction, &dm), 0);
    amxd_trans_clean(&transaction);

    object = amxd_dm_findf(&dm, "parent.1.");
    assert_non_null(object);
    object = amxd_dm_findf(&dm, "parent.");

    expect_string(check_callback_order, path, "parent.1.child.child_template.1");
    expect_string(check_callback_order, path, "parent.1.child.child_template");
    expect_string(check_callback_order, path, "parent.1.child");
    expect_string(check_callback_order, path, "parent.1");

    amxd_trans_init(&transaction);
    amxd_trans_select_object(&transaction, object);
    amxd_trans_del_inst(&transaction, 1, NULL);
    assert_int_equal(amxd_trans_apply(&transaction, &dm), 0);
    amxd_trans_clean(&transaction);

    expect_string(check_callback_order, path, "parent.child.child_template");
    expect_string(check_callback_order, path, "parent.child");
    expect_string(check_callback_order, path, "parent");

    amxd_dm_clean(&dm);
}

void test_amxd_object_destroy_root(UNUSED void** state) {
    static amxd_dm_t dm;
    amxd_object_t* root = NULL;

    // GIVEN a datamodel with a destroy handler on the root object
    assert_int_equal(amxd_dm_init(&dm), 0);
    root = amxd_dm_get_root(&dm);
    amxd_object_add_action_cb(root, action_object_destroy, check_callback_order, NULL);

    // EXPECT the destroy callbacks will be called
    expect_value(check_callback_order, path, NULL);

    // WHEN cleaning the datamodel
    amxd_dm_clean(&dm);
}
