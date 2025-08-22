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

void test_amxd_root_has_get_function(UNUSED void** state) {
    amxd_dm_t dm;
    amxd_object_t* root = NULL;
    amxd_object_t* object = NULL;
    amxd_function_t* func = NULL;
    amxc_var_t args;
    amxc_var_t ret;

    amxc_var_init(&args);
    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_init(&ret);

    amxd_dm_init(&dm);
    assert_int_equal(amxd_object_new(&object, amxd_object_singleton, "MyRoot"), 0);
    assert_int_equal(amxd_dm_add_root_object(&dm, object), 0);

    root = amxd_dm_get_root(&dm);
    assert_non_null(root);

    func = amxd_object_get_function(root, "_get");
    assert_non_null(func);

    amxc_var_add_key(cstring_t, &args, "rel_path", "MyRoot.");
    assert_int_equal(amxd_object_invoke_function(root, "_get", &args, &ret), amxd_status_ok);

    amxc_var_dump(&ret, STDOUT_FILENO);

    amxc_var_clean(&args);
    amxc_var_clean(&ret);
    amxd_dm_clean(&dm);
}

void test_amxd_root_has_exec_function(UNUSED void** state) {
    amxd_dm_t dm;
    amxd_object_t* root = NULL;
    amxd_object_t* object = NULL;
    amxd_function_t* func = NULL;
    amxc_var_t args;
    amxc_var_t ret;

    amxc_var_init(&args);
    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_init(&ret);

    amxd_dm_init(&dm);
    assert_int_equal(amxd_object_new(&object, amxd_object_singleton, "MyRoot"), 0);
    assert_int_equal(amxd_dm_add_root_object(&dm, object), 0);

    root = amxd_dm_get_root(&dm);
    assert_non_null(root);

    func = amxd_object_get_function(root, "_get");
    assert_non_null(func);

    amxc_var_add_key(cstring_t, &args, "rel_path", "MyRoot.");
    amxc_var_add_key(cstring_t, &args, "method", "_get");
    assert_int_equal(amxd_object_invoke_function(root, "_exec", &args, &ret), amxd_status_ok);

    amxc_var_dump(&ret, STDOUT_FILENO);

    amxc_var_clean(&args);
    amxc_var_clean(&ret);
    amxd_dm_clean(&dm);
}

void test_amxd_exec_function_fails_when_rel_path_does_not_exists(UNUSED void** state) {
    amxd_dm_t dm;
    amxd_object_t* root = NULL;
    amxd_object_t* object = NULL;
    amxd_function_t* func = NULL;
    amxc_var_t args;
    amxc_var_t* method_args = NULL;
    amxc_var_t ret;

    amxc_var_init(&args);
    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_init(&ret);

    amxd_dm_init(&dm);
    assert_int_equal(amxd_object_new(&object, amxd_object_singleton, "MyRoot"), 0);
    assert_int_equal(amxd_dm_add_root_object(&dm, object), 0);

    root = amxd_dm_get_root(&dm);
    assert_non_null(root);

    func = amxd_object_get_function(root, "_get");
    assert_non_null(func);

    amxc_var_add_key(cstring_t, &args, "rel_path", "Does.Not.Exists.");
    amxc_var_add_key(cstring_t, &args, "method", "_get");
    assert_int_not_equal(amxd_object_invoke_function(root, "_exec", &args, &ret), amxd_status_ok);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &args, "rel_path", "MyRoot.");
    amxc_var_add_key(cstring_t, &args, "method", "_get");
    method_args = amxc_var_add_key(amxc_htable_t, &args, "args", NULL);
    amxc_var_add_key(uint32_t, method_args, "depth", 0);
    assert_int_equal(amxd_object_invoke_function(root, "_exec", &args, &ret), amxd_status_ok);
    amxc_var_dump(&ret, STDOUT_FILENO);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &args, "method", "_get");
    method_args = amxc_var_add_key(amxc_htable_t, &args, "args", NULL);
    amxc_var_add_key(uint32_t, method_args, "depth", 0);
    assert_int_not_equal(amxd_object_invoke_function(root, "_exec", &args, &ret), amxd_status_ok);

    amxc_var_clean(&args);
    amxc_var_clean(&ret);
    amxd_dm_clean(&dm);
}