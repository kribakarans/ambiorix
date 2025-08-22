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

#include "test_amxd_action_object_add_86.h"

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
    // on derived objects.
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

static amxd_status_t test_add_inst1(amxd_object_t* const object,
                                    amxd_param_t* const param,
                                    amxd_action_t reason,
                                    const amxc_var_t* const args,
                                    amxc_var_t* const retval,
                                    void* priv) {
    return amxd_action_object_add_inst(object, param, reason, args, retval, priv);
}

static amxd_status_t test_add_inst2(amxd_object_t* const object,
                                    amxd_param_t* const param,
                                    amxd_action_t reason,
                                    const amxc_var_t* const args,
                                    amxc_var_t* const retval,
                                    void* priv) {
    return amxd_action_object_add_inst(object, param, reason, args, retval, priv);
}

static amxd_object_t* test_build_dm(void) {
    amxd_object_t* object = NULL;
    amxd_object_t* template = NULL;
    amxd_param_t* param = NULL;
    amxc_var_t* max = NULL;

    amxc_var_new(&max);
    amxc_var_set(int32_t, max, 3);

    assert_int_equal(amxd_dm_init(&dm), 0);

    assert_int_equal(amxd_object_new(&object, amxd_object_singleton, "MyRoot"), 0);
    assert_int_equal(amxd_param_new(&param, "Max", AMXC_VAR_ID_UINT32), 0);
    assert_int_equal(amxd_object_add_param(object, param), 0);
    amxc_var_set(uint32_t, &param->value, 2);
    assert_int_equal(amxd_dm_add_root_object(&dm, object), 0);

    assert_int_equal(amxd_object_new(&template, amxd_object_template, "MyTemplate"), 0);
    amxd_object_add_action_cb(template, action_object_add_inst, test_add_inst1, NULL);
    amxd_object_add_action_cb(template, action_object_add_inst, test_add_inst2, (void*) max);
    amxd_object_add_action_cb(template, action_object_destroy, test_cleanup_data, (void*) max);
    assert_int_equal(amxd_object_add_object(object, template), 0);
    assert_int_equal(amxd_param_new(&param, "param", AMXC_VAR_ID_UINT32), 0);
    assert_int_equal(amxd_object_add_param(template, param), 0);

    return template;
}

void test_amxd_object_add_inst_only_adds_one_instance(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxd_trans_t transaction;

    template = test_build_dm();

    assert_int_equal(amxd_object_get_instance_count(template), 0);

    amxd_trans_init(&transaction);
    amxd_trans_select_object(&transaction, template);
    amxd_trans_add_inst(&transaction, 0, NULL);
    assert_int_equal(amxd_trans_apply(&transaction, &dm), 0);

    assert_int_equal(amxd_object_get_instance_count(template), 1);

    amxd_trans_clean(&transaction);
    amxd_dm_clean(&dm);
}

void test_amxd_object_add_inst_max_check(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxd_trans_t transaction;

    template = test_build_dm();

    assert_int_equal(amxd_object_get_instance_count(template), 0);

    amxd_trans_init(&transaction);
    amxd_trans_select_object(&transaction, template);
    amxd_trans_add_inst(&transaction, 0, NULL);
    amxd_trans_select_object(&transaction, template);
    amxd_trans_add_inst(&transaction, 0, NULL);
    amxd_trans_select_object(&transaction, template);
    amxd_trans_add_inst(&transaction, 0, NULL);
    assert_int_equal(amxd_trans_apply(&transaction, &dm), 0);
    amxd_trans_clean(&transaction);

    assert_int_equal(amxd_object_get_instance_count(template), 3);

    amxd_trans_init(&transaction);
    amxd_trans_select_object(&transaction, template);
    amxd_trans_add_inst(&transaction, 0, NULL);
    assert_int_not_equal(amxd_trans_apply(&transaction, &dm), 0);
    amxd_trans_clean(&transaction);

    amxd_dm_clean(&dm);
}