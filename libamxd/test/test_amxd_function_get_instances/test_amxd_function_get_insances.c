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

#include "test_amxd_function_get_instances.h"

#include <amxc/amxc_macros.h>
static amxd_dm_t dm;

int test_function_get_instances_setup(UNUSED void** state) {
    amxd_object_t* root = NULL;
    amxd_object_t* singleton = NULL;
    amxd_object_t* template = NULL;
    amxd_object_t* instance = NULL;
    amxd_param_t* param = NULL;
    amxc_var_t keys;

    assert_int_equal(amxd_dm_init(&dm), 0);
    amxc_var_init(&keys);

    // object Main
    assert_int_equal(amxd_object_new(&root, amxd_object_singleton, "Main"), 0);
    assert_int_equal(amxd_dm_add_root_object(&dm, root), 0);

    // %read-only object Main.Template[]
    assert_int_equal(amxd_object_new(&template, amxd_object_template, "Template"), 0);
    amxd_object_set_attr(template, amxd_oattr_read_only, true);
    assert_int_equal(amxd_object_add_object(root, template), 0);
    // string param1
    assert_int_equal(amxd_param_new(&param, "param1", AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(amxd_param_set_attr(param, amxd_pattr_key, true), 0);
    assert_int_equal(amxd_object_add_param(template, param), 0);
    // %key uint32 param2
    assert_int_equal(amxd_param_new(&param, "param2", AMXC_VAR_ID_UINT32), 0);
    assert_int_equal(amxd_param_set_attr(param, amxd_pattr_key, true), 0);
    assert_int_equal(amxd_object_add_param(template, param), 0);
    // uint32 param3
    assert_int_equal(amxd_param_new(&param, "param3", AMXC_VAR_ID_UINT32), 0);
    assert_int_equal(amxd_object_add_param(template, param), 0);

    assert_int_equal(amxd_object_new(&singleton, amxd_object_singleton, "SubObject"), 0);
    amxd_object_set_attr(singleton, amxd_oattr_persistent, true);
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
    assert_int_equal(amxd_object_add_param(singleton, param), 0);

    amxc_var_set_type(&keys, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &keys, "param1", "test1");
    amxc_var_add_key(uint32_t, &keys, "param2", 1);
    amxc_var_add_key(uint32_t, &keys, "param3", 1);
    assert_int_equal(amxd_object_add_instance(&instance, template, "Instance1", 0, &keys), 0);
    amxc_var_set_type(&keys, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &keys, "param1", "test2");
    amxc_var_add_key(uint32_t, &keys, "param2", 2);
    amxc_var_add_key(uint32_t, &keys, "param3", 1);
    assert_int_equal(amxd_object_add_instance(&instance, template, "Instance2", 0, &keys), 0);

    amxc_var_clean(&keys);
    return 0;
}

int test_function_get_instances_teardown(UNUSED void** state) {
    amxd_dm_clean(&dm);

    return 0;
}

void test_amxd_can_get_instances(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxc_var_t retval;
    amxc_var_t args;

    amxc_var_init(&args);
    amxc_var_init(&retval);

    template = amxd_dm_findf(&dm, "Main.Template");
    assert_non_null(template);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxd_object_invoke_function(template, "_get_instances", &args, &retval), 0);
    amxc_var_dump(&retval, STDOUT_FILENO);

    assert_non_null(GET_ARG(&retval, "Main.Template.1."));
    assert_non_null(GET_ARG(&retval, "Main.Template.2."));

    amxc_var_clean(&retval);
    amxc_var_clean(&args);
}

void test_amxd_get_instances_fails_on_none_template(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxc_var_t retval;
    amxc_var_t args;

    amxc_var_init(&args);
    amxc_var_init(&retval);

    template = amxd_dm_findf(&dm, "Main.");
    assert_non_null(template);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    assert_int_not_equal(amxd_object_invoke_function(template, "_get_instances", &args, &retval), 0);
    amxc_var_dump(&retval, STDOUT_FILENO);

    template = amxd_dm_findf(&dm, "Main.Singleton.");
    assert_non_null(template);
    assert_int_not_equal(amxd_object_invoke_function(template, "_get_instances", &args, &retval), 0);
    amxc_var_dump(&retval, STDOUT_FILENO);

    amxc_var_clean(&retval);
    amxc_var_clean(&args);
}

void test_amxd_get_instances_fails_with_parameter_path(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxc_var_t retval;
    amxc_var_t args;

    amxc_var_init(&args);
    amxc_var_init(&retval);

    template = amxd_dm_findf(&dm, "Main.Template.");
    assert_non_null(template);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &args, "rel_path", "param3");
    assert_int_not_equal(amxd_object_invoke_function(template, "_get_instances", &args, &retval), 0);
    amxc_var_dump(&retval, STDOUT_FILENO);

    amxc_var_clean(&retval);
    amxc_var_clean(&args);
}