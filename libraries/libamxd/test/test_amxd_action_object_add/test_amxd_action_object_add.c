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

#include "test_amxd_action_object_add.h"

#include <amxc/amxc_macros.h>
static amxd_dm_t dm;

static amxd_status_t test_cleanup_data(amxd_object_t* const object,
                                       amxd_param_t* const param,
                                       amxd_action_t reason,
                                       UNUSED const amxc_var_t* const args,
                                       UNUSED amxc_var_t* const retval,
                                       void* priv) {
    amxd_status_t status = amxd_status_ok;
    amxc_var_t* data = (amxc_var_t*) priv;

    if((reason != action_object_destroy) &&
       ( reason != action_param_destroy)) {
        status = amxd_status_function_not_implemented;
        goto exit;
    }

    // action private data must not be removed when the action is used
    // on derivced objects.
    // only remove action data when the action is owned by the object or
    // parameter on which the action is called.
    if(reason == action_object_destroy) {
        if(amxd_object_has_action_cb(object, reason, test_cleanup_data)) {
            amxc_var_delete(&data);
            amxd_object_set_action_cb_data(object, reason, test_cleanup_data, NULL);
        }
    } else {
        if(amxd_param_has_action_cb(param, reason, test_cleanup_data)) {
            amxc_var_delete(&data);
            amxd_param_set_action_cb_data(param, reason, test_cleanup_data, NULL);
        }
    }

exit:
    return status;
}

static amxd_object_t* test_build_dm(void) {
    amxd_object_t* object = NULL;
    amxd_object_t* template = NULL;
    amxd_param_t* param = NULL;
    amxc_var_t* data = NULL;
    amxc_var_t* max = NULL;
    amxc_var_t* max_param = NULL;

    amxc_var_new(&data);
    amxc_var_new(&max);
    amxc_var_new(&max_param);
    amxc_var_set(int64_t, data, 10);
    amxc_var_set(int32_t, max, 3);
    amxc_var_set(cstring_t, max_param, "MyRoot.Max");

    assert_int_equal(amxd_dm_init(&dm), 0);

    assert_int_equal(amxd_object_new(&object, amxd_object_singleton, "MyRoot"), 0);
    assert_int_equal(amxd_param_new(&param, "Max", AMXC_VAR_ID_UINT32), 0);
    assert_int_equal(amxd_object_add_param(object, param), 0);
    amxc_var_set(uint32_t, &param->value, 2);
    assert_int_equal(amxd_dm_add_root_object(&dm, object), 0);

    assert_int_equal(amxd_object_new(&template, amxd_object_template, "MyTemplate"), 0);
    amxd_object_add_action_cb(template, action_object_add_inst, amxd_action_object_add_inst, (void*) max);
    amxd_object_add_action_cb(template, action_object_destroy, test_cleanup_data, (void*) max);
    assert_int_equal(amxd_object_add_object(object, template), 0);
    assert_int_equal(amxd_param_new(&param, "param", AMXC_VAR_ID_UINT32), 0);
    amxd_param_add_action_cb(param, action_param_validate, amxd_action_param_check_minimum, (void*) data);
    amxd_param_add_action_cb(param, action_param_destroy, test_cleanup_data, data);
    assert_int_equal(amxd_object_add_param(template, param), 0);
    assert_int_equal(amxd_param_new(&param, "uparam", AMXC_VAR_ID_UINT32), 0);
    assert_int_equal(amxd_param_set_attr(param, amxd_pattr_unique, true), 0);
    assert_int_equal(amxd_object_add_param(template, param), 0);

    assert_int_equal(amxd_object_new(&template, amxd_object_template, "MyTemplate2"), 0);
    amxd_object_add_action_cb(template, action_object_add_inst, amxd_action_object_add_inst, (void*) max_param);
    amxd_object_add_action_cb(template, action_object_destroy, test_cleanup_data, (void*) max_param);
    assert_int_equal(amxd_object_add_object(object, template), 0);

    assert_int_equal(amxd_object_new(&template, amxd_object_template, "parent"), 0);
    assert_int_equal(amxd_dm_add_root_object(&dm, template), 0);
    assert_int_equal(amxd_object_new(&object, amxd_object_singleton, "child"), 0);
    assert_int_equal(amxd_object_add_object(template, object), 0);

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

    return template;
}

static amxd_status_t misbehaving_add_instance_action(amxd_object_t* object,
                                                     UNUSED amxd_param_t* param,
                                                     amxd_action_t reason,
                                                     UNUSED const amxc_var_t* const args,
                                                     UNUSED amxc_var_t* const retval,
                                                     UNUSED void* priv) {

    amxd_status_t status = amxd_status_unknown_error;
    if(!object) {
        goto exit;
    }

    if(reason != action_object_add_inst) {
        status = amxd_status_function_not_implemented;
        goto exit;
    }

    status = amxd_status_ok;

exit:
    return status;
}

void test_amxd_object_add(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxd_object_t* instance = NULL;
    amxc_var_t retval;
    amxc_var_t args;
    amxc_var_t* params = NULL;

    amxc_var_init(&args);
    amxc_var_init(&retval);

    template = test_build_dm();

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxd_action_object_add_inst(template, NULL, action_object_add_inst, &args, &retval, NULL), 0);
    assert_int_equal(amxc_var_type_of(&retval), AMXC_VAR_ID_HTABLE);
    assert_ptr_not_equal(amxc_var_get_key(&retval, "index", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_key(&retval, "name", AMXC_VAR_FLAG_DEFAULT), NULL);
    instance = amxd_object_get_instance(template, NULL, amxc_var_constcast(uint32_t, amxc_var_get_key(&retval, "index", AMXC_VAR_FLAG_DEFAULT)));
    assert_ptr_not_equal(instance, NULL);

    amxc_var_clean(&retval);
    assert_int_equal(amxd_action_object_add_inst(template, NULL, action_object_add_inst, &args, &retval, NULL), 0);
    instance = amxd_object_get_instance(template, NULL, amxc_var_constcast(uint32_t, amxc_var_get_key(&retval, "index", AMXC_VAR_FLAG_DEFAULT)));
    assert_ptr_not_equal(instance, NULL);

    amxc_var_clean(&retval);
    assert_int_equal(amxd_action_object_add_inst(template, NULL, action_object_add_inst, NULL, &retval, NULL), 0);
    instance = amxd_object_get_instance(template, NULL, amxc_var_constcast(uint32_t, amxc_var_get_key(&retval, "index", AMXC_VAR_FLAG_DEFAULT)));
    assert_ptr_not_equal(instance, NULL);

    assert_int_not_equal(amxd_action_object_add_inst(template, NULL, action_object_add_inst, NULL, NULL, NULL), 0);
    assert_int_not_equal(amxd_action_object_add_inst(NULL, NULL, action_object_add_inst, NULL, &retval, NULL), 0);
    assert_int_not_equal(amxd_action_object_add_inst(template, NULL, action_object_read, NULL, &retval, NULL), 0);
    assert_int_not_equal(amxd_action_object_add_inst(template, NULL, action_object_write, NULL, &retval, NULL), 0);

    amxc_var_clean(&retval);
    assert_int_equal(amxd_action_object_add_inst(template, NULL, action_object_add_inst, &args, &retval, NULL), 0);
    assert_int_equal(amxc_var_type_of(&retval), AMXC_VAR_ID_HTABLE);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    params = amxc_var_add_key(amxc_htable_t, &args, "parameters", NULL);
    amxc_var_add_key(bool, params, "inst_param", true);
    amxc_var_add_key(uint32_t, params, "param", 666);
    amxc_var_add_key(uint32_t, &args, "index", 99);
    amxc_var_add_key(cstring_t, &args, "name", "MyTestInst");
    amxc_var_add_key(bool, &args, "set_priv", false);
    amxc_var_clean(&retval);
    assert_int_equal(amxd_action_object_add_inst(template, NULL, action_object_add_inst, &args, &retval, NULL), 0);
    instance = amxd_object_get_instance(template, "MyTestInst", 0);
    assert_ptr_not_equal(instance, NULL);
    assert_int_equal(amxd_object_get_value(uint32_t, instance, "param", NULL), 666);
    assert_true(amxd_object_get_value(bool, instance, "inst_param", NULL));

    amxd_object_set_attr(template, amxd_oattr_read_only, false);
    amxd_object_set_attr(template, amxd_oattr_private, true);
    amxc_var_clean(&retval);
    assert_int_not_equal(amxd_action_object_add_inst(template, NULL, action_object_add_inst, &args, &retval, NULL), 0);
    assert_int_equal(amxc_var_type_of(&retval), AMXC_VAR_ID_NULL);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    params = amxc_var_add_key(amxc_htable_t, &args, "parameters", NULL);
    amxc_var_add_key(bool, params, "inst_param", true);
    amxc_var_add_key(uint32_t, params, "param", 666);
    amxc_var_add_key(uint32_t, &args, "index", 99);
    amxc_var_add_key(cstring_t, &args, "name", "MyTestInst");
    amxc_var_add_key(uint32_t, &args, "access", amxd_dm_access_private);
    amxc_var_clean(&retval);
    assert_int_not_equal(amxd_action_object_add_inst(template, NULL, action_object_add_inst, &args, &retval, NULL), 0);
    instance = amxd_object_get_instance(template, "MyTestInst", 0);
    assert_ptr_not_equal(instance, NULL);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    params = amxc_var_add_key(amxc_htable_t, &args, "parameters", NULL);
    amxc_var_add_key(bool, params, "inst_param", true);
    amxc_var_add_key(uint32_t, params, "param", 666);
    amxc_var_add_key(uint32_t, &args, "index", 101);
    amxc_var_add_key(cstring_t, &args, "name", "MyTestInst2");
    amxc_var_add_key(uint32_t, &args, "access", amxd_dm_access_private);
    amxc_var_clean(&retval);
    assert_int_equal(amxd_action_object_add_inst(template, NULL, action_object_add_inst, &args, &retval, NULL), 0);
    instance = amxd_object_get_instance(template, "MyTestInst2", 0);
    assert_ptr_not_equal(instance, NULL);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    params = amxc_var_add_key(amxc_htable_t, &args, "parameters", NULL);
    amxc_var_add_key(cstring_t, params, "inst_param", "text");
    amxc_var_add_key(uint32_t, params, "param", 666);
    amxc_var_add_key(uint32_t, &args, "index", 102);
    amxc_var_add_key(cstring_t, &args, "name", "MyTestInst3");
    amxc_var_add_key(uint32_t, &args, "access", amxd_dm_access_private);
    amxc_var_add_key(bool, &args, "set_read_only", false);
    amxc_var_clean(&retval);
    assert_int_not_equal(amxd_action_object_add_inst(template, NULL, action_object_add_inst, &args, &retval, NULL), 0);
    instance = amxd_object_get_instance(template, "MyTestInst3", 0);
    assert_ptr_equal(instance, NULL);

    amxc_var_clean(&args);
    amxc_var_clean(&retval);
    amxd_dm_clean(&dm);
}

void test_does_not_segfault_when_add_inst_action_is_misbehaving(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxd_trans_t transaction;

    template = test_build_dm();
    amxd_object_add_action_cb(template, action_object_add_inst, misbehaving_add_instance_action, NULL);

    amxd_trans_init(&transaction);
    amxd_trans_select_object(&transaction, template);
    amxd_trans_add_inst(&transaction, 0, NULL);
    assert_int_not_equal(amxd_trans_apply(&transaction, &dm), 0);

    amxd_trans_clean(&transaction);
    amxd_dm_clean(&dm);
}

void test_instance_add_fails_when_invalid_values_provided(UNUSED void** state) {
    amxd_trans_t transaction;
    amxd_object_t* object = NULL;

    test_build_dm();

    amxd_trans_init(&transaction);
    amxd_trans_select_pathf(&transaction, "MyRoot.MyTemplate");
    amxd_trans_add_inst(&transaction, 0, NULL);
    amxd_trans_set_value(uint32_t, &transaction, "param", 11);
    amxd_trans_set_value(uint32_t, &transaction, "uparam", 11);
    assert_int_equal(amxd_trans_apply(&transaction, &dm), 0);
    object = amxd_dm_findf(&dm, "MyRoot.MyTemplate.1.");
    assert_non_null(object);
    amxd_trans_clean(&transaction);

    amxd_trans_init(&transaction);
    amxd_trans_select_pathf(&transaction, "MyRoot.MyTemplate");
    amxd_trans_add_inst(&transaction, 0, NULL);
    amxd_trans_set_value(uint32_t, &transaction, "param", 1);
    amxd_trans_set_value(uint32_t, &transaction, "uparam", 1);
    assert_int_not_equal(amxd_trans_apply(&transaction, &dm), 0);
    object = amxd_dm_findf(&dm, "MyRoot.MyTemplate.2.");
    assert_null(object);
    amxd_trans_clean(&transaction);

    amxd_trans_init(&transaction);
    amxd_trans_select_pathf(&transaction, "MyRoot.MyTemplate");
    amxd_trans_add_inst(&transaction, 0, NULL);
    amxd_trans_set_value(uint32_t, &transaction, "param", 20);
    amxd_trans_set_value(uint32_t, &transaction, "uparam", 1);
    assert_int_equal(amxd_trans_apply(&transaction, &dm), 0);
    object = amxd_dm_findf(&dm, "MyRoot.MyTemplate.3.");
    assert_non_null(object);
    amxd_trans_clean(&transaction);

    amxd_trans_init(&transaction);
    amxd_trans_select_pathf(&transaction, "MyRoot.MyTemplate");
    amxd_trans_add_inst(&transaction, 0, NULL);
    amxd_trans_set_value(uint32_t, &transaction, "param", 20);
    amxd_trans_set_value(uint32_t, &transaction, "uparam", 1);
    assert_int_not_equal(amxd_trans_apply(&transaction, &dm), 0);
    object = amxd_dm_findf(&dm, "MyRoot.MyTemplate.4.");
    assert_null(object);

    amxd_trans_clean(&transaction);
    amxd_dm_clean(&dm);
}

void test_instance_add_fails_when_max_instances_reached(UNUSED void** state) {
    amxd_trans_t transaction;

    test_build_dm();

    amxd_trans_init(&transaction);
    amxd_trans_select_pathf(&transaction, "MyRoot.MyTemplate");
    amxd_trans_add_inst(&transaction, 0, NULL);
    amxd_trans_set_value(uint32_t, &transaction, "uparam", 1);
    amxd_trans_select_pathf(&transaction, ".^");
    amxd_trans_add_inst(&transaction, 0, NULL);
    amxd_trans_set_value(uint32_t, &transaction, "uparam", 2);
    amxd_trans_select_pathf(&transaction, ".^");
    amxd_trans_add_inst(&transaction, 0, NULL);
    amxd_trans_set_value(uint32_t, &transaction, "uparam", 3);
    assert_int_equal(amxd_trans_apply(&transaction, &dm), 0);
    amxd_trans_clean(&transaction);

    amxd_trans_init(&transaction);
    amxd_trans_select_pathf(&transaction, "MyRoot.MyTemplate");
    amxd_trans_add_inst(&transaction, 0, NULL);
    amxd_trans_set_value(uint32_t, &transaction, "uparam", 4);
    assert_int_not_equal(amxd_trans_apply(&transaction, &dm), 0);

    amxd_trans_clean(&transaction);
    amxd_dm_clean(&dm);
}

void test_instance_add_fails_when_max_instances_reached_with_param_ref(UNUSED void** state) {
    amxd_trans_t transaction;

    test_build_dm();

    amxd_trans_init(&transaction);
    amxd_trans_select_pathf(&transaction, "MyRoot.MyTemplate2");
    amxd_trans_add_inst(&transaction, 0, NULL);
    amxd_trans_select_pathf(&transaction, ".^");
    amxd_trans_add_inst(&transaction, 0, NULL);
    assert_int_equal(amxd_trans_apply(&transaction, &dm), 0);
    amxd_trans_clean(&transaction);

    amxd_trans_init(&transaction);
    amxd_trans_select_pathf(&transaction, "MyRoot.MyTemplate2");
    amxd_trans_add_inst(&transaction, 0, NULL);
    assert_int_not_equal(amxd_trans_apply(&transaction, &dm), 0);

    amxd_trans_clean(&transaction);
    amxd_dm_clean(&dm);
}

void test_instance_index_overflow(UNUSED void** state) {
    amxd_trans_t transaction;
    amxd_object_t* instance = 0;

    test_build_dm();

    amxd_trans_init(&transaction);
    amxd_trans_select_pathf(&transaction, "MyRoot.");
    amxd_trans_set_value(uint32_t, &transaction, "Max", 5);
    amxd_trans_select_pathf(&transaction, "MyRoot.MyTemplate2");
    amxd_trans_add_inst(&transaction, UINT32_MAX, NULL);
    amxd_trans_select_pathf(&transaction, ".^");
    amxd_trans_add_inst(&transaction, 0, NULL);
    assert_int_equal(amxd_trans_apply(&transaction, &dm), 0);
    amxd_trans_clean(&transaction);

    instance = amxd_dm_findf(&dm, "MyRoot.MyTemplate2.%u", UINT32_MAX);
    assert_non_null(instance);
    instance = amxd_dm_findf(&dm, "MyRoot.MyTemplate2.1");
    assert_non_null(instance);

    amxd_trans_init(&transaction);
    amxd_trans_select_pathf(&transaction, "MyRoot.MyTemplate2");
    amxd_trans_add_inst(&transaction, UINT32_MAX - 1, NULL);
    amxd_trans_select_pathf(&transaction, ".^");
    amxd_trans_add_inst(&transaction, 0, NULL);
    assert_int_equal(amxd_trans_apply(&transaction, &dm), 0);

    instance = amxd_dm_findf(&dm, "MyRoot.MyTemplate2.%u", UINT32_MAX - 1);
    assert_non_null(instance);
    instance = amxd_dm_findf(&dm, "MyRoot.MyTemplate2.2");
    assert_non_null(instance);

    amxd_trans_clean(&transaction);
    amxd_dm_clean(&dm);
}