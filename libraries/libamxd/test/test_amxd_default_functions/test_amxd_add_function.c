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
#include <amxd/amxd_parameter.h>
#include <amxd/amxd_function.h>

#include "test_amxd_default_functions.h"

void test_amxd_add_function(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxd_object_t* instance = NULL;
    amxc_var_t retval;
    amxc_var_t args;
    amxc_var_t* params = NULL;
    amxd_status_t status = amxd_status_ok;
    uint32_t int_value = 0;

    amxc_var_init(&args);
    amxc_var_init(&retval);

    template = test_build_dm();

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxd_object_invoke_function(template, "_add", &args, &retval), 0);
    assert_int_equal(amxc_var_type_of(&retval), AMXC_VAR_ID_HTABLE);
    assert_ptr_not_equal(amxc_var_get_key(&retval, "index", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_key(&retval, "name", AMXC_VAR_FLAG_DEFAULT), NULL);
    instance = amxd_object_get_instance(template, NULL, 1);
    assert_ptr_not_equal(instance, NULL);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    params = amxc_var_add_key(amxc_htable_t, &args, "parameters", NULL);
    amxc_var_add_key(bool, params, "inst_param", "Test Data");
    amxc_var_add_key(uint32_t, params, "param", 666);
    amxc_var_add_key(uint32_t, &args, "index", 3);
    assert_int_equal(amxd_object_invoke_function(template, "_add", &args, &retval), 0);
    instance = amxd_object_get_instance(template, NULL, 3);
    assert_ptr_not_equal(instance, NULL);
    int_value = amxd_object_get_value(uint32_t, instance, "param", &status);
    assert_int_equal(status, amxd_status_ok);
    assert_int_equal(int_value, 666);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    params = amxc_var_add_key(amxc_htable_t, &args, "parameters", NULL);
    amxc_var_add_key(bool, params, "inst_param", "Test Data");
    amxc_var_add_key(uint32_t, params, "param", 666);
    amxc_var_add_key(uint32_t, &args, "index", 3);
    assert_int_not_equal(amxd_object_invoke_function(template, "_add", &args, &retval), 0);
    assert_int_equal(amxd_object_get_instance_count(template), 2);

    amxc_var_clean(&args);
    amxc_var_clean(&retval);
    test_clean_dm();
}

void test_amxd_add_function_with_cb(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxd_object_t* instance = NULL;
    amxc_var_t retval;
    amxc_var_t args;
    amxc_var_t* params = NULL;
    amxd_status_t status = amxd_status_ok;
    uint32_t int_value = 0;

    amxc_var_init(&args);
    amxc_var_init(&retval);

    template = test_build_dm();
    assert_int_equal(amxd_object_add_action_cb(template, action_object_add_inst, amxd_action_object_add_inst, NULL), 0);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxd_object_invoke_function(template, "_add", &args, &retval), 0);
    assert_int_equal(amxc_var_type_of(&retval), AMXC_VAR_ID_HTABLE);
    assert_ptr_not_equal(amxc_var_get_key(&retval, "index", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_key(&retval, "name", AMXC_VAR_FLAG_DEFAULT), NULL);
    instance = amxd_object_get_instance(template, NULL, 1);
    assert_ptr_not_equal(instance, NULL);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    params = amxc_var_add_key(amxc_htable_t, &args, "parameters", NULL);
    amxc_var_add_key(bool, params, "inst_param", "Test Data");
    amxc_var_add_key(uint32_t, params, "param", 666);
    amxc_var_add_key(uint32_t, &args, "index", 3);
    assert_int_equal(amxd_object_invoke_function(template, "_add", &args, &retval), 0);
    instance = amxd_object_get_instance(template, NULL, 3);
    assert_ptr_not_equal(instance, NULL);
    int_value = amxd_object_get_value(uint32_t, instance, "param", &status);
    assert_int_equal(status, amxd_status_ok);
    assert_int_equal(int_value, 666);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    params = amxc_var_add_key(amxc_htable_t, &args, "parameters", NULL);
    amxc_var_add_key(bool, params, "inst_param", "Test Data");
    amxc_var_add_key(uint32_t, params, "param", 666);
    amxc_var_add_key(uint32_t, &args, "index", 3);
    assert_int_not_equal(amxd_object_invoke_function(template, "_add", &args, &retval), 0);
    assert_int_equal(amxd_object_get_instance_count(template), 2);

    amxc_var_clean(&args);
    amxc_var_clean(&retval);
    test_clean_dm();
}