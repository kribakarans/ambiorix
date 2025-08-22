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
#include <string.h>
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

#include "test_amxd_issue_105.h"

#include <amxc/amxc_macros.h>
static amxd_dm_t dm;
static amxc_var_t validation_data;

int test_amxd_setup(UNUSED void** state) {
    amxd_object_t* root = NULL;
    amxd_object_t* template = NULL;
    amxd_param_t* param = NULL;

    assert_int_equal(amxd_dm_init(&dm), 0);
    amxc_var_init(&validation_data);
    amxc_var_set(uint32_t, &validation_data, 5);

    assert_int_equal(amxd_object_new(&root, amxd_object_singleton, "MyRoot"), 0);
    assert_int_equal(amxd_dm_add_root_object(&dm, root), 0);

    assert_int_equal(amxd_object_new(&template, amxd_object_template, "MultiInstanceObject"), 0);
    assert_int_equal(amxd_object_add_object(root, template), 0);
    assert_int_equal(amxd_param_new(&param, "TheKey", AMXC_VAR_ID_CSTRING), 0);
    amxd_param_set_attr(param, amxd_pattr_key, true);
    amxd_param_set_attr(param, amxd_pattr_unique, true);
    amxd_param_add_action_cb(param, action_param_validate, amxd_action_param_check_minimum, &validation_data);
    assert_int_equal(amxd_object_add_param(template, param), 0);

    assert_int_equal(amxd_param_new(&param, "OtherParameter", AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(amxd_object_add_param(template, param), 0);
    return 0;
}

int test_amxd_teardown(UNUSED void** state) {
    amxd_dm_clean(&dm);
    amxc_var_clean(&validation_data);
    return 0;
}

void test_amxd_add_instance_invalid(UNUSED void** state) {
    amxd_trans_t transaction;

    assert_int_equal(amxd_trans_init(&transaction), 0);
    assert_int_equal(amxd_trans_select_pathf(&transaction, "MyRoot.MultiInstanceObject"), 0);
    assert_int_equal(amxd_trans_add_inst(&transaction, 0, NULL), 0);
    amxd_trans_set_value(cstring_t, &transaction, "TheKey", "");
    amxd_trans_set_value(cstring_t, &transaction, "OtherParameter", "Test");
    assert_int_not_equal(amxd_trans_apply(&transaction, &dm), 0);
    amxd_trans_clean(&transaction);

    assert_int_equal(amxd_trans_init(&transaction), 0);
    assert_int_equal(amxd_trans_select_pathf(&transaction, "MyRoot.MultiInstanceObject"), 0);
    assert_int_equal(amxd_trans_add_inst(&transaction, 0, NULL), 0);
    amxd_trans_set_value(cstring_t, &transaction, "TheKey", "123");
    amxd_trans_set_value(cstring_t, &transaction, "OtherParameter", "Test");
    assert_int_not_equal(amxd_trans_apply(&transaction, &dm), 0);
    amxd_trans_clean(&transaction);
}

void test_amxd_add_instance_valid(UNUSED void** state) {
    amxd_trans_t transaction;

    assert_int_equal(amxd_trans_init(&transaction), 0);
    assert_int_equal(amxd_trans_select_pathf(&transaction, "MyRoot.MultiInstanceObject"), 0);
    assert_int_equal(amxd_trans_add_inst(&transaction, 0, NULL), 0);
    amxd_trans_set_value(cstring_t, &transaction, "TheKey", "abcde");
    amxd_trans_set_value(cstring_t, &transaction, "OtherParameter", "Test");
    assert_int_equal(amxd_trans_apply(&transaction, &dm), 0);
    amxd_trans_clean(&transaction);

    assert_int_equal(amxd_trans_init(&transaction), 0);
    assert_int_equal(amxd_trans_select_pathf(&transaction, "MyRoot.MultiInstanceObject"), 0);
    assert_int_equal(amxd_trans_add_inst(&transaction, 0, NULL), 0);
    amxd_trans_set_value(cstring_t, &transaction, "TheKey", "12345");
    amxd_trans_set_value(cstring_t, &transaction, "OtherParameter", "Test");
    assert_int_equal(amxd_trans_apply(&transaction, &dm), 0);
    amxd_trans_clean(&transaction);
}
