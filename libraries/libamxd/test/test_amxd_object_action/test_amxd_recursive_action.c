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

#include "amxd_priv.h"
#include "amxd_object_priv.h"
#include "test_amxd_object_action.h"

#include <amxc/amxc_macros.h>
static amxd_dm_t dm;
static amxd_object_t* test_parent = NULL;

static amxd_status_t amxd_action_dummy_write_cb(amxd_object_t* const object,
                                                UNUSED amxd_param_t* const param,
                                                UNUSED amxd_action_t reason,
                                                UNUSED const amxc_var_t* const args,
                                                UNUSED amxc_var_t* const retval,
                                                UNUSED void* priv) {
    amxd_object_t* child = amxd_object_get_child(object, "child");
    assert_ptr_not_equal(child, NULL);
    amxd_status_t status = amxd_object_set_value(cstring_t, child, "param", "Hello world");
    assert_int_not_equal(status, 0);

    return status;
}

static amxd_status_t amxd_action_dummy_cb(amxd_object_t* object,
                                          UNUSED amxd_param_t* const param,
                                          amxd_action_t reason,
                                          const amxc_var_t* const args,
                                          UNUSED amxc_var_t* const retval,
                                          UNUSED void* priv) {
    amxd_object_t* child = amxd_object_findf(object, "1.subtempl");
    assert_ptr_not_equal(child, NULL);
    amxd_status_t status = amxd_dm_invoke_action(child, NULL, reason, args, NULL);
    assert_int_equal(status, 0);

    return status;
}

static amxd_status_t amxd_action_invalid_cb(amxd_object_t* object,
                                            UNUSED amxd_param_t* const param,
                                            amxd_action_t reason,
                                            const amxc_var_t* const args,
                                            UNUSED amxc_var_t* const retval,
                                            UNUSED void* priv) {
    amxd_object_t* parent = amxd_object_get_parent(amxd_object_get_parent(object));
    if(parent == NULL) {
        parent = test_parent;
    }
    assert_ptr_not_equal(parent, NULL);
    amxd_status_t status = amxd_dm_invoke_action(parent, NULL, reason, args, NULL);
    assert_int_not_equal(status, 0);

    return status;
}

void test_amxd_object_recursive_set(UNUSED void** state) {
    amxd_object_t* object = NULL;
    amxd_object_t* child = NULL;
    amxd_param_t* param = NULL;

    assert_int_equal(amxd_dm_init(&dm), 0);

    assert_int_equal(amxd_object_new(&object, amxd_object_singleton, "parent"), 0);
    assert_int_equal(amxd_dm_add_root_object(&dm, object), 0);
    assert_int_equal(amxd_object_new(&child, amxd_object_singleton, "child"), 0);
    assert_int_equal(amxd_object_add_object(object, child), 0);
    assert_int_equal(amxd_param_new(&param, "param", AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(amxd_object_add_param(child, param), 0);
    assert_int_equal(amxd_object_add_action_cb(object, action_object_write, amxd_action_dummy_write_cb, NULL), 0);

    assert_int_not_equal(amxd_object_set_value(cstring_t, object, "dummy", "dummy value"), 0);

    amxd_dm_clean(&dm);
}

void test_amxd_object_recursive_del_inst_valid(UNUSED void** state) {
    amxd_object_t* child = NULL;
    amxd_object_t* template = NULL;
    amxd_object_t* instance = NULL;
    amxc_var_t args;

    amxc_var_init(&args);

    assert_int_equal(amxd_dm_init(&dm), 0);

    assert_int_equal(amxd_object_new(&template, amxd_object_template, "parent"), 0);
    assert_int_equal(amxd_dm_add_root_object(&dm, template), 0);
    assert_int_equal(amxd_object_new(&child, amxd_object_template, "subtempl"), 0);
    assert_int_equal(amxd_object_add_object(template, child), 0);
    assert_int_equal(amxd_object_add_action_cb(template, action_object_del_inst, amxd_action_dummy_cb, NULL), 0);

    assert_int_equal(amxd_object_new_instance(&instance, template, NULL, 1, NULL), 0);
    template = amxd_object_get_child(instance, "subtempl");
    assert_int_equal(amxd_object_new_instance(&instance, template, NULL, 1, NULL), 0);

    template = amxd_dm_findf(&dm, "parent");
    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(uint32_t, &args, "index", 1);
    assert_int_equal(amxd_dm_invoke_action(template, NULL, action_object_del_inst, &args, NULL), 0);
    instance = amxd_object_findf(template, "1");
    assert_non_null(instance);
    assert_int_equal(amxd_dm_invoke_action(instance, NULL, action_object_destroy, NULL, NULL), 0);
    assert_null(amxd_object_findf(template, "1"));

    amxc_var_clean(&args);
    amxd_dm_clean(&dm);
}

void test_amxd_object_recursive_del_inst_invalid(UNUSED void** state) {
    amxd_object_t* child = NULL;
    amxd_object_t* template = NULL;
    amxd_object_t* instance = NULL;
    amxc_var_t args;

    amxc_var_init(&args);

    assert_int_equal(amxd_dm_init(&dm), 0);

    assert_int_equal(amxd_object_new(&template, amxd_object_template, "parent"), 0);
    assert_int_equal(amxd_dm_add_root_object(&dm, template), 0);
    assert_int_equal(amxd_object_new(&child, amxd_object_template, "subtempl"), 0);
    assert_int_equal(amxd_object_add_object(template, child), 0);
    assert_int_equal(amxd_object_add_action_cb(child, action_object_del_inst, amxd_action_invalid_cb, NULL), 0);

    assert_int_equal(amxd_object_new_instance(&instance, template, NULL, 1, NULL), 0);
    template = amxd_object_get_child(instance, "subtempl");
    assert_int_equal(amxd_object_new_instance(&instance, template, NULL, 1, NULL), 0);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(uint32_t, &args, "index", 1);
    assert_int_not_equal(amxd_dm_invoke_action(template, NULL, action_object_del_inst, &args, NULL), 0);
    assert_non_null(amxd_object_findf(template, "1."));

    amxc_var_clean(&args);
    amxd_dm_clean(&dm);
}

void test_amxd_object_recursive_destroy_valid(UNUSED void** state) {
    amxd_object_t* child = NULL;
    amxd_object_t* template = NULL;
    amxd_object_t* instance = NULL;
    amxc_var_t args;

    amxc_var_init(&args);

    assert_int_equal(amxd_dm_init(&dm), 0);

    assert_int_equal(amxd_object_new(&template, amxd_object_template, "parent"), 0);
    assert_int_equal(amxd_dm_add_root_object(&dm, template), 0);
    assert_int_equal(amxd_object_new(&child, amxd_object_template, "subtempl"), 0);
    assert_int_equal(amxd_object_add_object(template, child), 0);
    assert_int_equal(amxd_object_add_action_cb(template, action_object_del_inst, amxd_action_dummy_cb, NULL), 0);

    assert_int_equal(amxd_object_new_instance(&instance, template, NULL, 1, NULL), 0);
    template = amxd_object_get_child(instance, "subtempl");
    assert_int_equal(amxd_object_new_instance(&instance, template, NULL, 1, NULL), 0);

    template = amxd_dm_findf(&dm, "parent");
    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(uint32_t, &args, "index", 1);
    assert_int_equal(amxd_dm_invoke_action(template, NULL, action_object_destroy, &args, NULL), 0);
    assert_null(amxd_dm_findf(&dm, "parent"));

    amxc_var_clean(&args);
    amxd_dm_clean(&dm);
}

void test_amxd_object_recursive_destroy_invalid(UNUSED void** state) {
    amxd_object_t* child = NULL;
    amxd_object_t* template = NULL;
    amxd_object_t* instance = NULL;
    amxc_var_t args;

    amxc_var_init(&args);

    assert_int_equal(amxd_dm_init(&dm), 0);

    assert_int_equal(amxd_object_new(&template, amxd_object_template, "parent"), 0);
    assert_int_equal(amxd_dm_add_root_object(&dm, template), 0);
    assert_int_equal(amxd_object_new(&child, amxd_object_template, "subtempl"), 0);
    assert_int_equal(amxd_object_add_object(template, child), 0);
    assert_int_equal(amxd_object_add_action_cb(child, action_object_destroy, amxd_action_invalid_cb, NULL), 0);
    assert_int_equal(amxd_object_new(&test_parent, amxd_object_singleton, "test_parent"), 0);
    assert_int_equal(amxd_dm_add_root_object(&dm, test_parent), 0);

    assert_int_equal(amxd_object_new_instance(&instance, template, NULL, 1, NULL), 0);
    template = amxd_object_get_child(instance, "subtempl");
    assert_int_equal(amxd_object_new_instance(&instance, template, NULL, 1, NULL), 0);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(uint32_t, &args, "index", 1);
    assert_int_equal(amxd_dm_invoke_action(template, NULL, action_object_destroy, &args, NULL), 0);
    assert_null(amxd_dm_findf(&dm, "parent.1.subtempl."));

    amxc_var_clean(&args);
    amxd_dm_clean(&dm);
}
