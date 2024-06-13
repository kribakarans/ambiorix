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
#include <string.h>

#include <amxc/amxc.h>
#include <amxp/amxp_signal.h>
#include <amxp/amxp_slot.h>

#include <amxd/amxd_common.h>
#include <amxd/amxd_dm.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_object_event.h>
#include <amxd/amxd_parameter.h>
#include <amxd/amxd_function.h>
#include <amxd/amxd_action.h>
#include <amxd/amxd_mib.h>
#include <amxd/amxd_transaction.h>

#include <amxd_priv.h>

#include "test_amxd_mib.h"

#include <amxc/amxc_macros.h>
static amxd_dm_t dm;

static void test_event_handler(const char* const sig_name,
                               UNUSED const amxc_var_t* const data,
                               void* const priv) {
    int* counter = (int*) priv;

    if(strcmp(sig_name, "dm:mib-added") == 0) {
        (*counter)++;
    }

    if(strcmp(sig_name, "dm:mib-removed") == 0) {
        (*counter)--;
    }
}

static amxd_status_t test_mib_cleanup_data(amxd_object_t* const object,
                                           amxd_param_t* const param,
                                           amxd_action_t reason,
                                           UNUSED const amxc_var_t* const args,
                                           UNUSED amxc_var_t* const retval,
                                           void* priv) {
    amxd_status_t status = amxd_status_ok;
    amxc_var_t* data = (amxc_var_t*) priv;

    // action private data must not be removed when the action is used
    // on derivced objects.
    // only remove action data when the action is owned by the object or
    // parameter on which the action is called.
    if(reason == action_object_destroy) {
        if(amxd_object_has_action_cb(object, reason, test_mib_cleanup_data)) {
            amxc_var_delete(&data);
            amxd_object_set_action_cb_data(object, reason, test_mib_cleanup_data, NULL);
        }
    } else {
        if(amxd_param_has_action_cb(param, reason, test_mib_cleanup_data)) {
            amxc_var_delete(&data);
            amxd_param_set_action_cb_data(param, reason, test_mib_cleanup_data, NULL);
        }
    }

    return status;
}

static amxd_object_t* test_build_dm(void) {
    amxd_object_t* object = NULL;
    amxd_param_t* param = NULL;
    amxd_function_t* func = NULL;
    amxd_object_t* templ_obj = NULL;

    assert_int_equal(amxd_dm_init(&dm), 0);

    assert_int_equal(amxd_object_new(&object, amxd_object_singleton, "TestObject"), 0);
    assert_int_equal(amxd_dm_add_root_object(&dm, object), 0);

    assert_int_equal(amxd_param_new(&param, "Param1", AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(amxd_object_add_param(object, param), 0);
    assert_int_equal(amxd_param_new(&param, "Param2", AMXC_VAR_ID_BOOL), 0);
    assert_int_equal(amxd_object_add_param(object, param), 0);
    amxd_function_new(&func, "Func1", AMXC_VAR_ID_CSTRING, NULL);
    assert_int_equal(amxd_object_add_function(object, func), 0);

    assert_int_equal(amxd_object_new(&templ_obj, amxd_object_template, "TemplObject"), 0);
    assert_int_equal(amxd_param_new(&param, "Param1", AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(amxd_object_add_param(templ_obj, param), 0);
    amxd_function_new(&func, "Func1", AMXC_VAR_ID_CSTRING, NULL);
    assert_int_equal(amxd_object_add_function(templ_obj, func), 0);
    assert_int_equal(amxd_object_add_object(object, templ_obj), 0);

    return object;
}

void test_can_define_and_store_mib(UNUSED void** state) {
    amxd_object_t* mib = NULL;
    amxd_object_t* fetch_mib = NULL;
    amxd_object_t* object = NULL;
    amxd_param_t* param = NULL;

    test_build_dm();

    assert_int_equal(amxd_mib_new(&mib, "TestMib"), 0);
    assert_ptr_not_equal(mib, NULL);
    assert_int_equal(amxd_object_get_type(mib), amxd_object_mib);
    assert_int_equal(amxd_param_new(&param, "MibParam1", AMXC_VAR_ID_UINT32), 0);
    assert_int_equal(amxd_object_add_param(mib, param), 0);
    assert_int_equal(amxd_dm_store_mib(&dm, mib), 0);
    fetch_mib = amxd_dm_get_mib(&dm, "TestMib");
    assert_ptr_not_equal(fetch_mib, NULL);
    assert_ptr_equal(fetch_mib, mib);

    assert_int_equal(amxd_mib_new(&mib, "TestMib"), 0);
    assert_int_not_equal(amxd_dm_store_mib(&dm, mib), 0);
    amxd_mib_delete(&mib);

    assert_int_equal(amxd_mib_new(&mib, "TestMib2"), 0);
    assert_ptr_not_equal(mib, NULL);
    assert_int_equal(amxd_object_get_type(mib), amxd_object_mib);

    assert_int_not_equal(amxd_dm_store_mib(NULL, mib), 0);
    assert_int_not_equal(amxd_dm_store_mib(&dm, NULL), 0);
    assert_int_equal(amxd_object_new(&object, amxd_object_singleton, "NotAMib"), 0);
    assert_int_not_equal(amxd_dm_store_mib(&dm, object), 0);

    assert_ptr_equal(amxd_dm_get_mib(&dm, "NotStoredMib"), NULL);
    assert_ptr_equal(amxd_dm_get_mib(NULL, "TestMib"), NULL);
    assert_ptr_equal(amxd_dm_get_mib(&dm, ""), NULL);
    assert_ptr_equal(amxd_dm_get_mib(&dm, NULL), NULL);

    assert_int_equal(amxd_dm_store_mib(&dm, mib), 0);
    fetch_mib = amxd_dm_get_mib(&dm, "TestMib2");
    assert_ptr_not_equal(fetch_mib, NULL);
    assert_ptr_equal(fetch_mib, mib);

    amxd_object_delete(&mib);
    amxd_object_delete(&object);
    amxd_dm_clean(&dm);
}

static int count_objects(UNUSED amxd_object_t* templ, UNUSED amxd_object_t* obj, void* priv) {
    int* count = (int*) priv;
    *count = *count + 1;
    return 1;
}

void test_can_add_remove_mib_to_from_object(UNUSED void** state) {
    amxd_object_t* mib = NULL;
    amxd_object_t* object = NULL;
    amxd_object_t* mibobject = NULL;
    amxd_object_t* child = NULL;
    amxd_param_t* param = NULL;
    amxd_function_t* func = NULL;

    object = test_build_dm();

    assert_int_equal(amxd_mib_new(&mib, "TestMib"), 0);
    assert_ptr_not_equal(mib, NULL);
    assert_int_equal(amxd_object_get_type(mib), amxd_object_mib);
    assert_int_equal(amxd_param_new(&param, "MibParam1", AMXC_VAR_ID_UINT32), 0);
    assert_int_equal(amxd_object_add_param(mib, param), 0);
    assert_int_equal(amxd_function_new(&func, "MibFunc1", AMXC_VAR_ID_NULL, NULL), 0);
    assert_int_equal(amxd_object_add_function(mib, func), 0);
    assert_int_equal(amxd_object_new(&child, amxd_object_singleton, "MibObject"), 0);
    assert_int_equal(amxd_object_add_object(mib, child), 0);

    assert_int_equal(amxd_dm_store_mib(&dm, mib), 0);

    assert_int_equal(amxd_object_add_mib(object, "TestMib"), 0);
    assert_true(amxd_object_has_mib(object, "TestMib"));
    assert_ptr_not_equal(amxd_object_get_param_def(object, "MibParam1"), NULL);
    assert_ptr_not_equal(amxd_object_get_function(object, "MibFunc1"), NULL);
    assert_ptr_not_equal(amxd_object_get_child(object, "MibObject"), NULL);
    assert_int_not_equal(amxd_object_add_mib(object, "TestMib"), 0);
    assert_true(amxd_object_has_mib(object, "TestMib"));

    int count = 0;
    amxd_object_for_all(object, "MibObject", count_objects, &count);
    assert_int_equal(count, 1);

    assert_int_equal(amxd_object_remove_mib(object, "TestMib"), 0);
    assert_false(amxd_object_has_mib(object, "TestMib"));
    assert_ptr_equal(amxd_object_get_param_def(object, "MibParam1"), NULL);
    assert_ptr_equal(amxd_object_get_function(object, "MibFunc1"), NULL);
    assert_ptr_equal(amxd_object_get_child(object, "MibObject"), NULL);
    assert_int_equal(amxd_object_remove_mib(object, "TestMib"), 0);

    assert_int_equal(amxd_object_add_mib(object, "TestMib"), 0);
    assert_int_not_equal(amxd_object_add_mib(object, "TestMib"), 0);
    func = amxd_object_get_function(object, "MibFunc1");
    amxd_function_delete(&func);
    param = amxd_object_get_param_def(object, "MibParam1");
    amxd_param_delete(&param);
    mibobject = amxd_object_get_child(object, "MibObject");
    amxd_object_delete(&mibobject);
    assert_int_equal(amxd_object_remove_mib(object, "TestMib"), 0);

    amxd_dm_clean(&dm);
}

void test_can_add_remove_mib_to_from_object2(UNUSED void** state) {
    amxd_object_t* mib = NULL;
    amxd_object_t* object = NULL;
    amxd_object_t* mibobject = NULL;
    amxd_object_t* template = NULL;
    amxd_object_t* template2 = NULL;
    amxd_object_t* child = NULL;
    amxd_object_t* child2 = NULL;
    amxd_object_t* child3 = NULL;
    amxd_param_t* param = NULL;
    amxd_param_t* instParam = NULL;
    amxd_function_t* func = NULL;

    object = test_build_dm();

    assert_int_equal(amxd_mib_new(&mib, "TestMib"), 0);
    assert_ptr_not_equal(mib, NULL);
    assert_int_equal(amxd_object_get_type(mib), amxd_object_mib);
    assert_int_equal(amxd_param_new(&param, "MibParam1", AMXC_VAR_ID_UINT32), 0);
    assert_int_equal(amxd_object_add_param(mib, param), 0);
    assert_int_equal(amxd_function_new(&func, "MibFunc1", AMXC_VAR_ID_NULL, NULL), 0);
    assert_int_equal(amxd_object_add_function(mib, func), 0);
    assert_int_equal(amxd_object_new(&template, amxd_object_template, "MibObject"), 0);
    assert_int_equal(amxd_object_add_object(mib, template), 0);
    assert_int_equal(amxd_param_new(&instParam, "InstParam1", AMXC_VAR_ID_UINT32), 0);
    assert_int_equal(amxd_object_add_param(template, instParam), 0);

    assert_int_equal(amxd_dm_store_mib(&dm, mib), 0);

    assert_int_equal(amxd_object_new(&template2, amxd_object_template, "Templ"), 0);
    assert_int_equal(amxd_object_add_object(object, template2), 0);
    assert_int_equal(amxd_object_new_instance(&child2, amxd_object_get_child(object, "Templ"), "TestInst1", 0, NULL), 0);
    assert_int_equal(amxd_object_new_instance(&child3, amxd_object_get_child(object, "Templ"), "TestInst2", 0, NULL), 0);

    assert_int_equal(amxd_object_add_mib(child2, "TestMib"), 0);
    assert_true(amxd_object_has_mib(child2, "TestMib"));
    assert_ptr_not_equal(amxd_object_get_param_def(child2, "MibParam1"), NULL);
    assert_ptr_not_equal(amxd_object_get_function(child2, "MibFunc1"), NULL);
    assert_ptr_not_equal(amxd_object_get_child(child2, "MibObject"), NULL);
    assert_int_not_equal(amxd_object_add_mib(child2, "TestMib"), 0);
    assert_true(amxd_object_has_mib(child2, "TestMib"));

    assert_int_equal(amxd_object_new_instance(&child, amxd_object_get_child(child2, "MibObject"), "MibInst1", 0, NULL), 0);

    int count = 0;
    amxd_object_for_all(object, "Templ.*.MibObject.[InstParam1==0].", count_objects, &count);
    assert_int_equal(count, 1);

    assert_int_equal(amxd_object_remove_mib(child2, "TestMib"), 0);
    assert_false(amxd_object_has_mib(child2, "TestMib"));
    assert_ptr_equal(amxd_object_get_param_def(child2, "MibParam1"), NULL);
    assert_ptr_equal(amxd_object_get_function(child2, "MibFunc1"), NULL);
    assert_ptr_equal(amxd_object_get_child(child2, "MibObject"), NULL);
    assert_int_equal(amxd_object_remove_mib(child2, "TestMib"), 0);

    assert_int_equal(amxd_object_add_mib(child2, "TestMib"), 0);
    assert_int_not_equal(amxd_object_add_mib(child2, "TestMib"), 0);
    func = amxd_object_get_function(child2, "MibFunc1");
    amxd_function_delete(&func);
    param = amxd_object_get_param_def(child2, "MibParam1");
    amxd_param_delete(&param);
    mibobject = amxd_object_get_child(child2, "MibObject");
    amxd_object_delete(&mibobject);
    assert_int_equal(amxd_object_remove_mib(child2, "TestMib"), 0);

    amxd_dm_clean(&dm);
}

void test_can_add_multiple_mibs(UNUSED void** state) {
    amxd_object_t* mib = NULL;
    amxd_object_t* object = NULL;
    amxd_param_t* param = NULL;

    object = test_build_dm();

    assert_int_equal(amxd_mib_new(&mib, "TestMib1"), 0);
    assert_ptr_not_equal(mib, NULL);
    assert_int_equal(amxd_object_get_type(mib), amxd_object_mib);
    assert_int_equal(amxd_param_new(&param, "MibParam1", AMXC_VAR_ID_UINT32), 0);
    assert_int_equal(amxd_object_add_param(mib, param), 0);
    assert_int_equal(amxd_dm_store_mib(&dm, mib), 0);

    assert_int_equal(amxd_mib_new(&mib, "TestMib2"), 0);
    assert_ptr_not_equal(mib, NULL);
    assert_int_equal(amxd_object_get_type(mib), amxd_object_mib);
    assert_int_equal(amxd_param_new(&param, "MibParam2", AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(amxd_object_add_param(mib, param), 0);
    assert_int_equal(amxd_dm_store_mib(&dm, mib), 0);

    assert_int_equal(amxd_object_add_mib(object, "TestMib1"), 0);
    assert_int_equal(amxd_object_add_mib(object, "TestMib2"), 0);
    assert_true(amxd_object_has_mib(object, "TestMib1"));
    assert_true(amxd_object_has_mib(object, "TestMib2"));
    assert_false(amxd_object_has_mib(object, "NotExisting"));
    assert_ptr_not_equal(amxd_object_get_param_def(object, "MibParam1"), NULL);
    assert_ptr_not_equal(amxd_object_get_param_def(object, "MibParam2"), NULL);

    assert_int_equal(amxd_object_remove_mib(object, "TestMib1"), 0);
    assert_false(amxd_object_has_mib(object, "TestMib1"));
    assert_true(amxd_object_has_mib(object, "TestMib2"));
    assert_false(amxd_object_has_mib(object, "NotExisting"));
    assert_ptr_equal(amxd_object_get_param_def(object, "MibParam1"), NULL);
    assert_ptr_not_equal(amxd_object_get_param_def(object, "MibParam2"), NULL);

    assert_int_equal(amxd_object_add_mib(object, "TestMib1"), 0);
    assert_true(amxd_object_has_mib(object, "TestMib1"));
    assert_true(amxd_object_has_mib(object, "TestMib2"));
    assert_false(amxd_object_has_mib(object, "NotExisting"));
    assert_ptr_not_equal(amxd_object_get_param_def(object, "MibParam1"), NULL);
    assert_ptr_not_equal(amxd_object_get_param_def(object, "MibParam2"), NULL);

    assert_int_equal(amxd_object_remove_mib(object, "TestMib2"), 0);
    assert_true(amxd_object_has_mib(object, "TestMib1"));
    assert_false(amxd_object_has_mib(object, "TestMib2"));
    assert_false(amxd_object_has_mib(object, "NotExisting"));
    assert_ptr_not_equal(amxd_object_get_param_def(object, "MibParam1"), NULL);
    assert_ptr_equal(amxd_object_get_param_def(object, "MibParam2"), NULL);

    assert_int_not_equal(amxd_object_add_mib(object, "NotExisting"), 0);

    amxd_dm_clean(&dm);
}

void test_add_mib_fails_when_duplicates(UNUSED void** state) {
    amxd_object_t* mib = NULL;
    amxd_object_t* object = NULL;
    amxd_param_t* param = NULL;

    object = test_build_dm();

    assert_int_equal(amxd_mib_new(&mib, "TestMib1"), 0);
    assert_ptr_not_equal(mib, NULL);
    assert_int_equal(amxd_object_get_type(mib), amxd_object_mib);
    assert_int_equal(amxd_param_new(&param, "Param1", AMXC_VAR_ID_UINT32), 0);
    assert_int_equal(amxd_object_add_param(mib, param), 0);
    assert_int_equal(amxd_dm_store_mib(&dm, mib), 0);

    assert_int_not_equal(amxd_object_add_mib(object, "TestMib1"), 0);
    assert_false(amxd_object_has_mib(object, "TestMib1"));
    assert_ptr_not_equal(amxd_object_get_param_def(object, "Param1"), NULL);

    amxd_dm_clean(&dm);
}

void test_add_mib_fails_when_object_not_in_dm(UNUSED void** state) {
    amxd_object_t* mib = NULL;
    amxd_object_t* object = NULL;
    amxd_param_t* param = NULL;

    assert_int_equal(amxd_dm_init(&dm), 0);

    assert_int_equal(amxd_object_new(&object, amxd_object_singleton, "TestObject"), 0);

    assert_int_equal(amxd_mib_new(&mib, "TestMib1"), 0);
    assert_ptr_not_equal(mib, NULL);
    assert_int_equal(amxd_object_get_type(mib), amxd_object_mib);
    assert_int_equal(amxd_param_new(&param, "Param1", AMXC_VAR_ID_UINT32), 0);
    assert_int_equal(amxd_object_add_param(mib, param), 0);
    assert_int_equal(amxd_dm_store_mib(&dm, mib), 0);

    assert_int_not_equal(amxd_object_add_mib(object, "TestMib1"), 0);
    assert_false(amxd_object_has_mib(object, "TestMib1"));
    assert_ptr_equal(amxd_object_get_param_def(object, "Param1"), NULL);

    amxd_object_delete(&object);
    amxd_dm_clean(&dm);
}

void test_functions_check_input_args(UNUSED void** state) {
    amxd_object_t* mib = NULL;
    amxd_object_t* object = NULL;

    assert_int_not_equal(amxd_mib_new(NULL, "TestMib1"), 0);
    assert_int_not_equal(amxd_mib_new(&mib, ""), 0);
    assert_int_not_equal(amxd_mib_new(&mib, "12345"), 0);
    assert_int_not_equal(amxd_mib_new(&mib, "A.b,%t"), 0);
    assert_int_not_equal(amxd_mib_new(&mib, NULL), 0);

    object = test_build_dm();
    assert_false(amxd_object_has_mib(NULL, "TestMib1"));
    assert_false(amxd_object_has_mib(object, ""));
    assert_false(amxd_object_has_mib(object, NULL));

    assert_int_not_equal(amxd_object_add_mib(object, NULL), 0);
    assert_int_not_equal(amxd_object_add_mib(object, ""), 0);
    assert_int_not_equal(amxd_object_add_mib(NULL, ""), 0);

    assert_int_not_equal(amxd_object_remove_mib(object, NULL), 0);
    assert_int_not_equal(amxd_object_remove_mib(object, ""), 0);
    assert_int_not_equal(amxd_object_remove_mib(NULL, ""), 0);

    amxd_dm_clean(&dm);
}

void test_get_root_of_mib_is_null(UNUSED void** state) {
    amxd_object_t* mib = NULL;
    amxd_object_t* mib_object = NULL;
    amxd_param_t* param = NULL;

    test_build_dm();

    assert_int_equal(amxd_mib_new(&mib, "TestMib"), 0);
    assert_ptr_not_equal(mib, NULL);
    assert_int_equal(amxd_object_get_type(mib), amxd_object_mib);
    assert_int_equal(amxd_param_new(&param, "MibParam1", AMXC_VAR_ID_UINT32), 0);
    assert_int_equal(amxd_object_add_param(mib, param), 0);
    assert_int_equal(amxd_object_new(&mib_object, amxd_object_singleton, "MibChild"), 0);
    assert_int_equal(amxd_object_add_object(mib, mib_object), 0);
    assert_int_equal(amxd_dm_store_mib(&dm, mib), 0);

    assert_ptr_equal(amxd_object_get_root(mib), NULL);

    amxd_dm_clean(&dm);
}

void test_set_attrs_on_mib_fails(UNUSED void** state) {
    amxd_object_t* mib = NULL;
    amxd_object_t* mib_object = NULL;
    amxd_param_t* param = NULL;

    test_build_dm();

    assert_int_equal(amxd_mib_new(&mib, "TestMib"), 0);
    assert_ptr_not_equal(mib, NULL);
    assert_int_equal(amxd_object_get_type(mib), amxd_object_mib);
    assert_int_equal(amxd_param_new(&param, "MibParam1", AMXC_VAR_ID_UINT32), 0);
    assert_int_equal(amxd_object_add_param(mib, param), 0);
    assert_int_equal(amxd_object_new(&mib_object, amxd_object_singleton, "MibChild"), 0);
    assert_int_equal(amxd_object_add_object(mib, mib_object), 0);
    assert_int_equal(amxd_dm_store_mib(&dm, mib), 0);

    assert_int_not_equal(amxd_object_set_attr(mib, amxd_oattr_read_only, true), 0);
    assert_int_equal(amxd_object_set_attr(mib_object, amxd_oattr_read_only, true), 0);

    amxd_dm_clean(&dm);
}

void test_add_mib_to_object_fails_when_leads_to_function_duplicate(UNUSED void** state) {
    amxd_object_t* mib = NULL;
    amxd_object_t* mib_object = NULL;
    amxd_object_t* object = NULL;
    amxd_param_t* param = NULL;
    amxd_function_t* func = NULL;

    object = test_build_dm();

    assert_int_equal(amxd_mib_new(&mib, "TestMib"), 0);
    assert_ptr_not_equal(mib, NULL);
    assert_int_equal(amxd_object_get_type(mib), amxd_object_mib);
    assert_int_equal(amxd_param_new(&param, "MibParam1", AMXC_VAR_ID_UINT32), 0);
    assert_int_equal(amxd_object_add_param(mib, param), 0);
    assert_int_equal(amxd_object_new(&mib_object, amxd_object_singleton, "MibChild"), 0);
    assert_int_equal(amxd_object_add_object(mib, mib_object), 0);
    amxd_function_new(&func, "Func1", AMXC_VAR_ID_CSTRING, NULL);
    assert_int_equal(amxd_object_add_function(mib, func), 0);
    assert_int_equal(amxd_dm_store_mib(&dm, mib), 0);

    assert_int_not_equal(amxd_object_add_mib(object, "TestMib"), 0);

    amxd_dm_clean(&dm);
}

void test_add_mib_can_override_function(UNUSED void** state) {
    amxd_object_t* mib = NULL;
    amxd_object_t* object = NULL;
    amxd_object_t* instance = NULL;
    amxd_function_t* func = NULL;

    test_build_dm();

    object = amxd_dm_findf(&dm, "TestObject.TemplObject");
    assert_ptr_not_equal(object, NULL);
    assert_int_equal(amxd_object_new_instance(&instance, object, NULL, 0, NULL), 0);

    assert_int_equal(amxd_mib_new(&mib, "TestMib"), 0);
    assert_ptr_not_equal(mib, NULL);
    assert_int_equal(amxd_object_get_type(mib), amxd_object_mib);
    amxd_function_new(&func, "Func1", AMXC_VAR_ID_CSTRING, NULL);
    assert_int_equal(amxd_object_add_function(mib, func), 0);
    assert_int_equal(amxd_dm_store_mib(&dm, mib), 0);

    assert_int_equal(amxd_object_add_mib(instance, "TestMib"), 0);

    amxd_dm_clean(&dm);
}

void test_add_mib_function_inherits_argument_attrs(UNUSED void** state) {
    amxd_object_t* mib = NULL;
    amxd_object_t* object = NULL;
    amxd_object_t* instance = NULL;
    amxd_function_t* func = NULL;
    amxc_var_t def_val;

    amxc_var_init(&def_val);
    amxc_var_set(bool, &def_val, true);

    test_build_dm();

    object = amxd_dm_findf(&dm, "TestObject.TemplObject");
    assert_ptr_not_equal(object, NULL);
    assert_int_equal(amxd_object_new_instance(&instance, object, NULL, 0, NULL), 0);

    assert_int_equal(amxd_mib_new(&mib, "TestMib"), 0);
    assert_ptr_not_equal(mib, NULL);
    assert_int_equal(amxd_object_get_type(mib), amxd_object_mib);
    amxd_function_new(&func, "Func1", AMXC_VAR_ID_CSTRING, NULL);
    assert_int_equal(amxd_function_new_arg(func, "parameters", AMXC_VAR_ID_BOOL, &def_val), 0);
    amxd_function_arg_set_attr(func, "parameters", amxd_aattr_in, true);
    amxd_function_arg_set_attr(func, "parameters", amxd_aattr_out, true);
    amxd_function_arg_set_attr(func, "parameters", amxd_aattr_mandatory, true);
    amxd_function_arg_set_attr(func, "parameters", amxd_aattr_strict, true);
    assert_int_equal(amxd_object_add_function(mib, func), 0);
    assert_int_equal(amxd_dm_store_mib(&dm, mib), 0);

    assert_int_equal(amxd_object_add_mib(instance, "TestMib"), 0);

    func = amxd_object_get_function(instance, "Func1");
    assert_non_null(func);

    assert_true(amxd_function_arg_is_attr_set(func, "parameters", amxd_aattr_in));
    assert_true(amxd_function_arg_is_attr_set(func, "parameters", amxd_aattr_out));
    assert_true(amxd_function_arg_is_attr_set(func, "parameters", amxd_aattr_mandatory));
    assert_true(amxd_function_arg_is_attr_set(func, "parameters", amxd_aattr_strict));

    amxd_dm_clean(&dm);
}


void test_add_mib_to_instance(UNUSED void** state) {
    amxd_object_t* mib = NULL;
    amxd_object_t* object = NULL;
    amxd_object_t* instance = NULL;
    amxd_param_t* param = NULL;
    amxc_var_t* data = NULL;
    amxd_function_t* func = NULL;

    amxc_var_new(&data);
    amxc_var_set(uint32_t, data, 0);
    test_build_dm();

    object = amxd_dm_findf(&dm, "TestObject.TemplObject");
    assert_ptr_not_equal(object, NULL);
    assert_int_equal(amxd_object_new_instance(&instance, object, NULL, 0, NULL), 0);

    assert_int_equal(amxd_mib_new(&mib, "TestMib1"), 0);
    assert_ptr_not_equal(mib, NULL);
    assert_int_equal(amxd_object_get_type(mib), amxd_object_mib);
    assert_int_equal(amxd_param_new(&param, "MibParam1", AMXC_VAR_ID_UINT32), 0);
    assert_int_equal(amxd_object_add_param(mib, param), 0);
    assert_int_equal(amxd_param_new(&param, "MibParamB", AMXC_VAR_ID_UINT32), 0);
    assert_int_equal(amxd_param_add_action_cb(param, action_param_validate, amxd_action_param_check_minimum, data), 0);
    assert_int_equal(amxd_param_add_action_cb(param, action_param_destroy, test_mib_cleanup_data, data), 0);
    assert_int_equal(amxd_object_add_param(mib, param), 0);
    amxd_function_new(&func, "Func1", AMXC_VAR_ID_CSTRING, NULL);
    amxd_function_set_attr(func, amxd_fattr_template, true);
    assert_int_equal(amxd_object_add_function(mib, func), 0);
    amxd_function_new(&func, "Func2", AMXC_VAR_ID_CSTRING, NULL);
    amxd_function_set_attr(func, amxd_fattr_instance, true);
    assert_int_equal(amxd_object_add_function(mib, func), 0);
    assert_int_equal(amxd_dm_store_mib(&dm, mib), 0);

    assert_int_equal(amxd_mib_new(&mib, "TestMib2"), 0);
    assert_ptr_not_equal(mib, NULL);
    assert_int_equal(amxd_object_get_type(mib), amxd_object_mib);
    assert_int_equal(amxd_param_new(&param, "MibParam2", AMXC_VAR_ID_UINT32), 0);
    assert_int_equal(amxd_param_set_attr(param, amxd_pattr_template, true), 0);
    assert_int_equal(amxd_object_add_param(mib, param), 0);
    assert_int_equal(amxd_dm_store_mib(&dm, mib), 0);

    assert_int_equal(amxd_object_add_mib(instance, "TestMib1"), 0);
    param = amxd_object_get_param_def(instance, "MibParam1");
    assert_non_null(param);

    assert_int_equal(amxd_object_add_mib(instance, "TestMib2"), 0);
    param = amxd_object_get_param_def(instance, "MibParam2");
    assert_null(param);

    amxd_dm_clean(&dm);
}

void test_add_mib_using_transaction(UNUSED void** state) {
    amxd_object_t* mib = NULL;
    amxd_param_t* param = NULL;
    amxd_object_t* object = NULL;
    amxd_trans_t transaction;

    test_build_dm();

    assert_int_equal(amxd_mib_new(&mib, "TestMib1"), 0);
    assert_ptr_not_equal(mib, NULL);
    assert_int_equal(amxd_object_get_type(mib), amxd_object_mib);
    assert_int_equal(amxd_param_new(&param, "MibParam1", AMXC_VAR_ID_UINT32), 0);
    assert_int_equal(amxd_object_add_param(mib, param), 0);
    assert_int_equal(amxd_param_new(&param, "MibParamB", AMXC_VAR_ID_UINT32), 0);
    assert_int_equal(amxd_object_add_param(mib, param), 0);
    assert_int_equal(amxd_dm_store_mib(&dm, mib), 0);

    assert_int_equal(amxd_trans_init(&transaction), 0);
    assert_int_equal(amxd_trans_select_pathf(&transaction, "TestObject.TemplObject."), 0);
    assert_int_equal(amxd_trans_add_inst(&transaction, 0, NULL), 0);
    assert_int_equal(amxd_trans_add_mib(&transaction, "TestMib1"), 0);
    assert_int_equal(amxd_trans_set_value(cstring_t, &transaction, "Param1", "Test"), 0);
    amxd_trans_dump(&transaction, STDOUT_FILENO, false);
    assert_int_equal(amxd_trans_apply(&transaction, &dm), 0);

    object = amxd_dm_findf(&dm, "TestObject.TemplObject.1.");
    assert_non_null(object);
    param = amxd_object_get_param_def(object, "MibParam1");
    assert_non_null(param);

    amxd_trans_clean(&transaction);

    assert_int_equal(amxd_trans_init(&transaction), 0);
    amxd_trans_select_pathf(&transaction, "TestObject.TemplObject.1.");
    assert_int_equal(amxd_trans_set_value(uint32_t, &transaction, "MibParam1", 102), 0);
    assert_int_equal(amxd_trans_add_mib(&transaction, "TestMib1"), 0);
    amxd_trans_dump(&transaction, STDOUT_FILENO, true);
    assert_int_equal(amxd_trans_apply(&transaction, &dm), 0);

    amxd_trans_clean(&transaction);
    amxd_dm_clean(&dm);
}

void test_add_mib_to_template(UNUSED void** state) {
    amxd_object_t* mib = NULL;
    amxd_object_t* object = NULL;
    amxd_object_t* instance = NULL;
    amxd_param_t* param = NULL;
    amxd_function_t* func = NULL;

    test_build_dm();

    object = amxd_dm_findf(&dm, "TestObject.TemplObject");
    assert_ptr_not_equal(object, NULL);

    assert_int_equal(amxd_mib_new(&mib, "TestMib1"), 0);
    assert_ptr_not_equal(mib, NULL);
    assert_int_equal(amxd_object_get_type(mib), amxd_object_mib);
    assert_int_equal(amxd_param_new(&param, "MibParam1", AMXC_VAR_ID_UINT32), 0);
    assert_int_equal(amxd_object_add_param(mib, param), 0);

    amxd_function_new(&func, "Func2", AMXC_VAR_ID_CSTRING, NULL);
    amxd_function_set_attr(func, amxd_fattr_instance, true);
    assert_int_equal(amxd_object_add_function(mib, func), 0);
    assert_int_equal(amxd_dm_store_mib(&dm, mib), 0);

    assert_int_equal(amxd_object_add_mib(object, "TestMib1"), 0);
    param = amxd_object_get_param_def(object, "MibParam1");
    assert_non_null(param);

    assert_int_equal(amxd_object_new_instance(&instance, object, NULL, 0, NULL), 0);
    param = amxd_object_get_param_def(instance, "MibParam1");
    assert_non_null(param);

    amxd_dm_clean(&dm);
}

void test_mib_not_removed_when_not_added(UNUSED void** state) {
    amxd_object_t* mib = NULL;
    amxd_object_t* object = NULL;
    amxd_param_t* param = NULL;

    object = test_build_dm();

    assert_int_equal(amxd_mib_new(&mib, "TestMib"), 0);
    assert_ptr_not_equal(mib, NULL);
    assert_int_equal(amxd_object_get_type(mib), amxd_object_mib);
    assert_int_equal(amxd_param_new(&param, "MibParam1", AMXC_VAR_ID_UINT32), 0);
    assert_int_equal(amxd_object_add_param(mib, param), 0);
    assert_int_equal(amxd_dm_store_mib(&dm, mib), 0);

    assert_int_equal(amxd_mib_new(&mib, "TestMib2"), 0);
    assert_ptr_not_equal(mib, NULL);
    assert_int_equal(amxd_object_get_type(mib), amxd_object_mib);
    assert_int_equal(amxd_param_new(&param, "MibParam1", AMXC_VAR_ID_UINT32), 0);
    assert_int_equal(amxd_object_add_param(mib, param), 0);
    assert_int_equal(amxd_dm_store_mib(&dm, mib), 0);

    assert_int_equal(amxd_object_add_mib(object, "TestMib"), 0);
    assert_true(amxd_object_has_mib(object, "TestMib"));
    assert_ptr_not_equal(amxd_object_get_param_def(object, "MibParam1"), NULL);

    assert_false(amxd_object_has_mib(object, "TestMib2"));
    assert_int_equal(amxd_object_remove_mib(object, "TestMib2"), 0);
    assert_ptr_not_equal(amxd_object_get_param_def(object, "MibParam1"), NULL);

    amxd_dm_clean(&dm);
}

void test_mib_events(UNUSED void** state) {
    amxd_object_t* mib = NULL;
    amxd_object_t* object = NULL;
    amxd_object_t* instance = NULL;
    amxd_param_t* param = NULL;
    int counter = 0;

    test_build_dm();

    amxp_slot_connect_filtered(&dm.sigmngr, "dm:mib-*", NULL, test_event_handler, &counter);

    object = amxd_dm_findf(&dm, "TestObject.TemplObject");
    assert_ptr_not_equal(object, NULL);
    assert_int_equal(amxd_object_new_instance(&instance, object, NULL, 0, NULL), 0);

    assert_int_equal(amxd_mib_new(&mib, "TestMib1"), 0);
    assert_ptr_not_equal(mib, NULL);
    assert_int_equal(amxd_object_get_type(mib), amxd_object_mib);
    assert_int_equal(amxd_param_new(&param, "MibParam1", AMXC_VAR_ID_UINT32), 0);
    assert_int_equal(amxd_object_add_param(mib, param), 0);
    assert_int_equal(amxd_dm_store_mib(&dm, mib), 0);

    assert_int_equal(amxd_object_add_mib(instance, "TestMib1"), 0);
    while(amxp_signal_read() == 0) {
    }
    assert_int_equal(counter, 1);

    assert_int_equal(amxd_object_remove_mib(instance, "TestMib1"), 0);
    while(amxp_signal_read() == 0) {
    }
    assert_int_equal(counter, 0);

    amxd_dm_clean(&dm);
}

void test_can_fetch_dm_from_mib(UNUSED void** state) {
    amxd_object_t* mib = NULL;
    amxd_param_t* param = NULL;
    amxd_object_t* object = NULL;

    test_build_dm();

    assert_int_equal(amxd_mib_new(&mib, "TestMib1"), 0);
    assert_ptr_not_equal(mib, NULL);
    assert_int_equal(amxd_object_get_type(mib), amxd_object_mib);
    assert_int_equal(amxd_param_new(&param, "MibParam1", AMXC_VAR_ID_UINT32), 0);
    assert_int_equal(amxd_object_add_param(mib, param), 0);
    assert_int_equal(amxd_object_new(&object, amxd_object_singleton, "MibSubObject"), 0);
    assert_int_equal(amxd_object_add_object(mib, object), 0);

    assert_null(amxd_object_get_dm(mib));

    assert_int_equal(amxd_dm_store_mib(&dm, mib), 0);

    assert_ptr_equal(&dm, amxd_object_get_dm(mib));
    assert_ptr_equal(&dm, amxd_object_get_dm(object));

    amxd_dm_clean(&dm);
}

void test_can_declare_event_in_mib(UNUSED void** state) {
    amxd_object_t* mib = NULL;
    amxd_param_t* param = NULL;
    amxd_object_t* object = NULL;
    amxd_object_t* instance = NULL;
    amxc_var_t* event = NULL;

    test_build_dm();

    object = amxd_dm_findf(&dm, "TestObject.TemplObject");
    assert_ptr_not_equal(object, NULL);
    assert_int_equal(amxd_object_new_instance(&instance, object, NULL, 0, NULL), 0);

    assert_int_equal(amxd_mib_new(&mib, "TestMib1"), 0);
    assert_ptr_not_equal(mib, NULL);
    assert_int_equal(amxd_object_get_type(mib), amxd_object_mib);
    assert_int_equal(amxd_param_new(&param, "MibParam1", AMXC_VAR_ID_UINT32), 0);
    assert_int_equal(amxd_object_add_param(mib, param), 0);
    assert_int_equal(amxd_object_new(&object, amxd_object_singleton, "MibSubObject"), 0);
    assert_int_equal(amxd_object_add_object(mib, object), 0);

    assert_null(amxd_object_get_dm(mib));

    assert_int_equal(amxd_dm_store_mib(&dm, mib), 0);
    assert_int_equal(amxd_object_add_event_ext(mib, "Event1!", NULL), 0);
    assert_int_equal(amxd_object_add_event_ext(object, "Event2!", NULL), 0);

    assert_int_equal(amxd_object_add_mib(instance, "TestMib1"), 0);
    event = amxd_object_new_event_data(instance, "Event1!");
    assert_non_null(event);
    free(event);
    object = amxd_object_findf(instance, "MibSubObject");
    assert_non_null(object);
    event = amxd_object_new_event_data(object, "Event2!");
    assert_non_null(event);
    free(event);

    assert_int_equal(amxd_object_remove_mib(instance, "TestMib1"), 0);
    event = amxd_object_new_event_data(instance, "Event1!");
    assert_null(event);

    amxd_dm_clean(&dm);
}

void test_add_mib_object_can_be_read_using_name_path(UNUSED void** state) {
    amxd_object_t* mib = NULL;
    amxd_object_t* object = NULL;
    amxd_param_t* param = NULL;
    amxd_object_t* instance = NULL;
    amxc_var_t ret;
    amxc_var_t args;

    amxc_var_init(&ret);
    amxc_var_init(&args);

    object = test_build_dm();

    assert_int_equal(amxd_mib_new(&mib, "TestMib1"), 0);
    assert_ptr_not_equal(mib, NULL);
    assert_int_equal(amxd_object_get_type(mib), amxd_object_mib);
    assert_int_equal(amxd_param_new(&param, "MParam1", AMXC_VAR_ID_UINT32), 0);
    assert_int_equal(amxd_object_add_param(mib, param), 0);
    assert_int_equal(amxd_object_new(&object, amxd_object_singleton, "TestObj"), 0);
    assert_int_equal(amxd_param_new(&param, "MParam1", AMXC_VAR_ID_UINT32), 0);
    assert_int_equal(amxd_object_add_param(object, param), 0);
    assert_int_equal(amxd_object_add_object(mib, object), 0);
    assert_int_equal(amxd_dm_store_mib(&dm, mib), 0);

    object = amxd_dm_findf(&dm, "TestObject.TemplObject");
    assert_ptr_not_equal(object, NULL);
    assert_int_equal(amxd_object_new_instance(&instance, object, "TestInstance", 0, NULL), 0);
    assert_int_equal(amxd_object_add_mib(instance, "TestMib1"), 0);
    assert_true(amxd_object_has_mib(instance, "TestMib1"));
    assert_ptr_not_equal(amxd_object_get_param_def(object, "Param1"), NULL);

    object = amxd_dm_findf(&dm, "TestObject.");
    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &args, "rel_path", "TemplObject.TestInstance.TestObj.");
    assert_int_equal(amxd_object_invoke_function(object, "_get", &args, &ret), 0);

    amxd_dm_clean(&dm);

    amxc_var_clean(&ret);
    amxc_var_clean(&args);
}

void test_object_get_mibs(UNUSED void** state) {
    amxd_object_t* mib = NULL;
    amxd_object_t* object = NULL;
    char* mib_names = NULL;

    object = test_build_dm();

    assert_int_equal(amxd_mib_new(&mib, "TestMib"), 0);
    assert_ptr_not_equal(mib, NULL);
    assert_int_equal(amxd_object_get_type(mib), amxd_object_mib);
    assert_int_equal(amxd_dm_store_mib(&dm, mib), 0);

    assert_int_equal(amxd_mib_new(&mib, "TestMib2"), 0);
    assert_ptr_not_equal(mib, NULL);
    assert_int_equal(amxd_object_get_type(mib), amxd_object_mib);
    assert_int_equal(amxd_dm_store_mib(&dm, mib), 0);

    mib_names = amxd_object_get_mibs(object);
    assert_null(mib_names);

    assert_int_equal(amxd_object_add_mib(object, "TestMib"), 0);
    assert_true(amxd_object_has_mib(object, "TestMib"));

    mib_names = amxd_object_get_mibs(object);
    assert_non_null(mib_names);
    assert_string_equal(mib_names, "TestMib");
    free(mib_names);

    assert_int_equal(amxd_object_add_mib(object, "TestMib2"), 0);
    assert_true(amxd_object_has_mib(object, "TestMib2"));

    mib_names = amxd_object_get_mibs(object);
    assert_non_null(mib_names);
    assert_string_equal(mib_names, "TestMib TestMib2");
    free(mib_names);

    assert_int_equal(amxd_object_remove_mib(object, "TestMib"), 0);
    assert_false(amxd_object_has_mib(object, "TestMib"));

    mib_names = amxd_object_get_mibs(object);
    assert_non_null(mib_names);
    assert_string_equal(mib_names, "TestMib2");
    free(mib_names);

    assert_int_equal(amxd_object_remove_mib(object, "TestMib2"), 0);
    assert_false(amxd_object_has_mib(object, "TestMib2"));

    mib_names = amxd_object_get_mibs(object);
    assert_null(mib_names);

    amxd_dm_clean(&dm);
}


