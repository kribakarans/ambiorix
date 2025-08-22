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

#include "test_amxd_transaction.h"

#include <amxc/amxc_macros.h>
static amxd_dm_t dm;

static char* validate = "VALIDATE";
static char* delinst = "DELINST";
static char* addinst = "ADDINST";

static amxd_status_t amxd_action_test_validate(amxd_object_t* const object,
                                               amxd_param_t* const param,
                                               amxd_action_t reason,
                                               const amxc_var_t* const args,
                                               amxc_var_t* const retval,
                                               void* priv) {

    assert_int_equal(reason, action_object_validate);
    assert_ptr_not_equal(object, NULL);
    assert_ptr_equal(param, NULL);
    assert_ptr_equal(args, NULL);
    assert_ptr_equal(retval, NULL);
    assert_ptr_equal(priv, validate);

    bool enabled = amxd_object_get_value(bool, object, "Enable", NULL);
    uint32_t length = amxd_object_get_value(uint32_t, object, "Length", NULL);
    char* text = amxd_object_get_value(cstring_t, object, "Text", NULL);
    amxd_status_t status = amxd_status_ok;

    if(enabled) {
        if(text && (strlen(text) > length)) {
            status = amxd_status_invalid_value;
        }
    } else {
        if(text && (strcmp(text, "INVALID") == 0)) {
            status = amxd_status_invalid_value;
        }
    }

    free(text);
    return status;
}

static amxd_status_t amxd_action_test_del_inst(amxd_object_t* const object,
                                               amxd_param_t* const param,
                                               amxd_action_t reason,
                                               const amxc_var_t* const args,
                                               amxc_var_t* const retval,
                                               void* priv) {
    assert_int_equal(reason, action_object_del_inst);
    assert_ptr_not_equal(object, NULL);
    assert_int_equal(amxd_object_get_type(object), amxd_object_template);
    assert_ptr_equal(param, NULL);
    assert_ptr_not_equal(args, NULL);
    assert_int_equal(amxc_var_type_of(args), AMXC_VAR_ID_HTABLE);
    assert_ptr_not_equal(retval, NULL);
    assert_ptr_equal(priv, delinst);

    uint32_t index = 0;
    char* key = NULL;
    amxc_var_t* temp = NULL;
    amxd_object_t* inst = NULL;
    bool sticky = false;
    amxd_status_t status = amxd_status_ok;

    temp = amxc_var_get_key(args, "index", AMXC_VAR_FLAG_DEFAULT);
    index = amxc_var_is_null(temp) ? 0 : amxc_var_dyncast(uint32_t, temp);
    temp = amxc_var_get_key(args, "name", AMXC_VAR_FLAG_DEFAULT);
    key = amxc_var_is_null(temp) ? NULL : amxc_var_dyncast(cstring_t, temp);

    inst = amxd_object_get_instance(object, key, index);
    if(inst == NULL) {
        status = amxd_status_object_not_found;
    } else {
        sticky = amxd_object_get_value(bool, inst, "Sticky", NULL);
        if(sticky) {
            status = amxd_status_invalid_action;
        }
    }

    free(key);
    return status;
}

static amxd_status_t amxd_action_test_add_inst(amxd_object_t* const object,
                                               amxd_param_t* const param,
                                               amxd_action_t reason,
                                               const amxc_var_t* const args,
                                               amxc_var_t* const retval,
                                               void* priv) {
    assert_int_equal(reason, action_object_add_inst);
    assert_ptr_not_equal(object, NULL);
    assert_int_equal(amxd_object_get_type(object), amxd_object_template);
    assert_ptr_equal(param, NULL);
    assert_ptr_not_equal(args, NULL);
    assert_int_equal(amxc_var_type_of(args), AMXC_VAR_ID_HTABLE);
    assert_ptr_not_equal(retval, NULL);
    assert_ptr_equal(priv, addinst);

    char* key = NULL;
    amxc_var_t* temp = NULL;
    amxd_status_t status = amxd_status_ok;

    temp = amxc_var_get_key(args, "name", AMXC_VAR_FLAG_DEFAULT);
    key = amxc_var_is_null(temp) ? NULL : amxc_var_dyncast(cstring_t, temp);

    if((key != NULL) && (strcmp(key, "INVALID") == 0)) {
        status = amxd_status_invalid_name;
    } else {
        status = amxd_action_object_add_inst(object, param, reason, args, retval, NULL);
    }

    free(key);
    return status;
}

void test_build_dm(void) {
    amxd_object_t* object = NULL;
    amxd_object_t* template = NULL;
    amxd_param_t* param = NULL;

    assert_int_equal(amxd_dm_init(&dm), 0);

    assert_int_equal(amxd_object_new(&object, amxd_object_singleton, "Top1"), 0);
    assert_int_equal(amxd_dm_add_root_object(&dm, object), 0);
    assert_int_equal(amxd_param_new(&param, "Enable", AMXC_VAR_ID_BOOL), 0);
    assert_int_equal(amxd_object_add_param(object, param), 0);
    assert_int_equal(amxd_param_new(&param, "Length", AMXC_VAR_ID_UINT32), 0);
    assert_int_equal(amxd_object_add_param(object, param), 0);
    assert_int_equal(amxd_param_new(&param, "Text", AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(amxd_object_add_param(object, param), 0);
    assert_int_equal(amxd_param_new(&param, "ROText", AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(amxd_param_set_attr(param, amxd_pattr_read_only, true), 0);
    assert_int_equal(amxd_object_add_param(object, param), 0);
    assert_int_equal(amxd_object_add_action_cb(object, action_object_validate, amxd_action_test_validate, validate), 0);

    assert_int_equal(amxd_object_new(&object, amxd_object_singleton, "Top2"), 0);
    assert_int_equal(amxd_param_new(&param, "TextA", AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(amxd_object_add_param(object, param), 0);
    assert_int_equal(amxd_param_new(&param, "TextB", AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(amxd_object_add_param(object, param), 0);
    assert_int_equal(amxd_dm_add_root_object(&dm, object), 0);

    assert_int_equal(amxd_object_new(&template, amxd_object_template, "TObject"), 0);
    assert_int_equal(amxd_object_add_object(object, template), 0);
    assert_int_equal(amxd_param_new(&param, "Sticky", AMXC_VAR_ID_BOOL), 0);
    assert_int_equal(amxd_object_add_param(template, param), 0);
    assert_int_equal(amxd_param_new(&param, "Text", AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(amxd_object_add_param(template, param), 0);
    assert_int_equal(amxd_object_add_action_cb(template, action_object_del_inst, amxd_action_test_del_inst, delinst), 0);
    assert_int_equal(amxd_object_add_action_cb(template, action_object_add_inst, amxd_action_test_add_inst, addinst), 0);
    assert_int_equal(amxd_object_new(&object, amxd_object_singleton, "TChild"), 0);
    assert_int_equal(amxd_object_add_object(template, object), 0);
    assert_int_equal(amxd_param_new(&param, "Text", AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(amxd_object_add_param(object, param), 0);
    assert_int_equal(amxd_object_add_action_cb(object, action_object_validate, amxd_action_test_validate, validate), 0);
    assert_int_equal(amxd_object_new(&object, amxd_object_template, "TemplateChild"), 0);
    assert_int_equal(amxd_object_add_object(template, object), 0);

    assert_int_equal(amxd_object_new(&object, amxd_object_mib, "MObject"), 0);
    assert_int_equal(amxd_param_new(&param, "Extra", AMXC_VAR_ID_BOOL), 0);
    assert_int_equal(amxd_object_add_param(object, param), 0);
    assert_int_equal(amxd_param_new(&param, "Number", AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(amxd_object_add_param(object, param), 0);
    assert_int_equal(amxd_dm_store_mib(&dm, object), 0);
}

amxd_dm_t* test_get_dm(void) {
    return &dm;
}

void test_clean_dm(void) {
    amxd_dm_clean(&dm);
}

void test_amxd_transaction_new_delete(UNUSED void** state) {
    amxd_trans_t* transaction = NULL;

    assert_int_equal(amxd_trans_new(&transaction), 0);
    assert_ptr_not_equal(transaction, NULL);

    amxd_trans_delete(&transaction);
    assert_ptr_equal(transaction, NULL);

    amxd_trans_delete(&transaction);
    amxd_trans_delete(NULL);
    assert_int_not_equal(amxd_trans_new(NULL), 0);
}

void test_amxd_transaction_init_clean(UNUSED void** state) {
    amxd_trans_t transaction;

    assert_int_equal(amxd_trans_init(&transaction), 0);
    amxd_trans_clean(&transaction);

    amxd_trans_clean(NULL);
    assert_int_not_equal(amxd_trans_init(NULL), 0);
}

void test_amxd_transaction_add_action(UNUSED void** state) {
    amxd_trans_t transaction;
    amxd_object_t* inst = NULL;
    amxd_object_t* obj = NULL;
    test_build_dm();

    assert_int_equal(amxd_trans_init(&transaction), 0);
    assert_int_equal(amxd_trans_select_pathf(&transaction, "Top2.TObject"), 0);
    assert_int_equal(amxd_trans_add_action(&transaction, action_object_add_inst, NULL), 0);
    assert_int_equal(amxd_trans_apply(&transaction, test_get_dm()), 0);
    amxd_trans_clean(&transaction);

    inst = amxd_dm_findf(test_get_dm(), "Top2.TObject.1");
    assert_ptr_not_equal(inst, NULL);

    assert_int_equal(amxd_trans_select_pathf(&transaction, "Top2.TObject"), 0);
    assert_int_not_equal(amxd_trans_add_action(NULL, action_object_add_inst, NULL), 0);
    assert_int_not_equal(amxd_trans_add_action(&transaction, action_object_read, NULL), 0);
    assert_int_not_equal(amxd_trans_add_action(&transaction, action_object_validate, NULL), 0);
    assert_int_not_equal(amxd_trans_add_action(&transaction, action_object_list, NULL), 0);
    assert_int_not_equal(amxd_trans_apply(&transaction, test_get_dm()), 0);
    amxd_trans_clean(&transaction);

    obj = amxd_dm_findf(test_get_dm(), "Top2.TObject");
    assert_ptr_not_equal(obj, NULL);
    assert_int_equal(amxd_object_get_instance_count(obj), 1);

    test_clean_dm();
}

void test_amxd_transaction_add_action_signed_index(UNUSED void** state) {
    amxd_trans_t transaction;
    amxd_object_t* inst = NULL;
    amxd_object_t* obj = NULL;
    amxc_var_t args;
    test_build_dm();

    amxc_var_init(&args);
    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);

    assert_int_equal(amxd_trans_init(&transaction), 0);
    assert_int_equal(amxd_trans_select_pathf(&transaction, "Top2.TObject"), 0);
    assert_int_equal(amxd_trans_add_action(&transaction, action_object_add_inst, NULL), 0);
    assert_int_equal(amxd_trans_apply(&transaction, test_get_dm()), 0);
    amxd_trans_clean(&transaction);

    inst = amxd_dm_findf(test_get_dm(), "Top2.TObject.1");
    assert_ptr_not_equal(inst, NULL);

    amxc_var_add_key(int32_t, &args, "index", 1);
    assert_int_equal(amxd_trans_select_pathf(&transaction, "Top2.TObject"), 0);
    assert_int_equal(amxd_trans_add_action(&transaction, action_object_del_inst, &args), 0);
    assert_int_equal(amxd_trans_apply(&transaction, test_get_dm()), 0);
    amxd_trans_clean(&transaction);

    obj = amxd_dm_findf(test_get_dm(), "Top2.TObject");
    assert_ptr_not_equal(obj, NULL);
    assert_int_equal(amxd_object_get_instance_count(obj), 0);

    test_clean_dm();
    amxc_var_clean(&args);
}

void test_amxd_transaction_select(UNUSED void** state) {
    amxd_trans_t transaction;
    amxd_object_t* obj = NULL;
    test_build_dm();

    assert_int_equal(amxd_trans_init(&transaction), 0);
    assert_int_equal(amxd_trans_select_pathf(&transaction, "Top2.TObject"), 0);
    assert_int_equal(amxd_trans_select_pathf(&transaction, ".^"), 0);
    assert_int_equal(amxd_trans_select_pathf(&transaction, ".TObject"), 0);
    assert_int_equal(amxd_trans_select_pathf(&transaction, "Top1"), 0);
    obj = amxd_dm_findf(test_get_dm(), "Top2.TObject");
    assert_int_equal(amxd_trans_select_object(&transaction, obj), 0);
    assert_int_equal(amxd_trans_apply(&transaction, test_get_dm()), 0);
    amxd_trans_clean(&transaction);

    assert_int_not_equal(amxd_trans_select_pathf(NULL, "Top2.TObject"), 0);
    assert_int_not_equal(amxd_trans_select_object(NULL, obj), 0);
    assert_int_not_equal(amxd_trans_select_pathf(&transaction, NULL), 0);
    assert_int_not_equal(amxd_trans_select_pathf(&transaction, "%s", ""), 0);
    assert_int_not_equal(amxd_trans_select_object(&transaction, NULL), 0);
    assert_int_not_equal(amxd_trans_apply(&transaction, test_get_dm()), 0);
    amxd_trans_clean(&transaction);

    test_clean_dm();
}

void test_amxd_transaction_set_param(UNUSED void** state) {
    amxd_trans_t transaction;
    amxd_object_t* obj = NULL;
    char* text = NULL;
    amxd_status_t status = amxd_status_ok;

    test_build_dm();

    assert_int_equal(amxd_trans_init(&transaction), 0);
    assert_int_equal(amxd_trans_set_attr(&transaction, amxd_tattr_change_ro, true), 0);
    assert_int_equal(amxd_trans_set_attr(&transaction, amxd_tattr_change_pub, true), 0);
    assert_int_equal(amxd_trans_set_attr(&transaction, amxd_tattr_change_pub, false), 0);
    assert_int_equal(amxd_trans_set_attr(&transaction, amxd_tattr_change_prot, true), 0);
    assert_int_equal(amxd_trans_set_attr(&transaction, amxd_tattr_change_prot, false), 0);
    assert_int_equal(amxd_trans_select_pathf(&transaction, "Top1"), 0);
    assert_int_equal(amxd_trans_set_value(cstring_t, &transaction, "Text", "Hello world"), 0);
    assert_int_equal(amxd_trans_set_value(bool, &transaction, "Enable", true), 0);
    assert_int_equal(amxd_trans_set_value(int32_t, &transaction, "Length", 64), 0);
    assert_int_equal(amxd_trans_set_value(cstring_t, &transaction, "ROText", "Hello world"), 0);
    amxd_trans_dump(&transaction, STDOUT_FILENO, false);
    assert_int_equal(amxd_trans_apply(&transaction, test_get_dm()), 0);
    amxd_trans_clean(&transaction);

    obj = amxd_dm_findf(test_get_dm(), "Top1");
    text = amxd_object_get_value(cstring_t, obj, "Text", &status);
    assert_int_equal(status, amxd_status_ok);
    assert_ptr_not_equal(text, NULL);
    assert_string_equal(text, "Hello world");
    free(text);
    assert_true(amxd_object_get_value(bool, obj, "Enable", &status));
    assert_int_equal(status, amxd_status_ok);
    assert_int_equal(amxd_object_get_value(uint32_t, obj, "Length", &status), 64);
    assert_int_equal(status, amxd_status_ok);
    text = amxd_object_get_value(cstring_t, obj, "ROText", &status);
    assert_int_equal(status, amxd_status_ok);
    assert_ptr_not_equal(text, NULL);
    assert_string_equal(text, "Hello world");
    free(text);

    assert_int_equal(amxd_trans_select_pathf(&transaction, "Top1"), 0);
    assert_int_not_equal(amxd_trans_set_value(cstring_t, NULL, "Text", "Hello world"), 0);
    assert_int_not_equal(amxd_trans_set_value(cstring_t, &transaction, NULL, "Hello world"), 0);
    assert_int_not_equal(amxd_trans_set_value(cstring_t, &transaction, "", "Hello world"), 0);
    assert_int_not_equal(amxd_trans_set_param(&transaction, "Text", NULL), 0);
    assert_int_not_equal(amxd_trans_apply(&transaction, test_get_dm()), 0);
    amxd_trans_clean(&transaction);

    assert_int_equal(amxd_trans_select_pathf(&transaction, "Top1"), 0);
    assert_int_equal(amxd_trans_set_value(cstring_t, &transaction, "Text", "Hello Universe"), 0);
    assert_int_equal(amxd_trans_set_value(int32_t, &transaction, "Length", 5), 0);
    assert_int_not_equal(amxd_trans_apply(&transaction, test_get_dm()), 0);
    amxd_trans_clean(&transaction);

    text = amxd_object_get_value(cstring_t, obj, "Text", &status);
    assert_int_equal(status, amxd_status_ok);
    assert_ptr_not_equal(text, NULL);
    assert_string_equal(text, "Hello world");
    assert_true(amxd_object_get_value(bool, obj, "Enable", &status));
    assert_int_equal(status, amxd_status_ok);
    assert_int_equal(amxd_object_get_value(uint32_t, obj, "Length", &status), 64);
    assert_int_equal(status, amxd_status_ok);
    free(text);

    test_clean_dm();
}

void test_amxd_transaction_add_inst(UNUSED void** state) {
    amxd_trans_t transaction;
    amxd_object_t* obj = NULL;
    char* text = NULL;
    amxd_status_t status = amxd_status_ok;

    test_build_dm();

    assert_int_equal(amxd_trans_init(&transaction), 0);
    assert_int_equal(amxd_trans_select_pathf(&transaction, "Top2.TObject"), 0);
    assert_int_equal(amxd_trans_add_inst(&transaction, 99, "Inst1"), 0);
    amxd_trans_set_value(cstring_t, &transaction, "Text", "InInst1");
    assert_int_equal(amxd_trans_select_pathf(&transaction, ".^"), 0);
    assert_int_equal(amxd_trans_add_inst(&transaction, 100, "Inst2"), 0);
    amxd_trans_set_value(cstring_t, &transaction, "Text", "InInst2");

    amxd_trans_dump(&transaction, STDOUT_FILENO, false);
    assert_int_equal(amxd_trans_apply(&transaction, test_get_dm()), 0);

    amxd_trans_clean(&transaction);

    obj = amxd_dm_findf(test_get_dm(), "Top2.TObject");
    assert_int_equal(amxd_object_get_instance_count(obj), 2);

    obj = amxd_dm_findf(test_get_dm(), "Top2.TObject.Inst1");
    assert_ptr_not_equal(obj, NULL);
    text = amxd_object_get_value(cstring_t, obj, "Text", &status);
    assert_int_equal(status, amxd_status_ok);
    assert_ptr_not_equal(text, NULL);
    assert_string_equal(text, "InInst1");
    free(text);

    obj = amxd_dm_findf(test_get_dm(), "Top2.TObject.100");
    assert_ptr_not_equal(obj, NULL);
    text = amxd_object_get_value(cstring_t, obj, "Text", &status);
    assert_int_equal(status, amxd_status_ok);
    assert_ptr_not_equal(text, NULL);
    assert_string_equal(text, "InInst2");
    free(text);

    assert_int_equal(amxd_trans_select_pathf(&transaction, "Top2.TObject.100"), 0);
    amxd_trans_set_value(cstring_t, &transaction, "Text", "Changed");
    assert_int_equal(amxd_trans_select_pathf(&transaction, ".^"), 0);
    assert_int_equal(amxd_trans_add_inst(&transaction, 0, "INVALID"), 0);
    amxd_trans_set_value(cstring_t, &transaction, "Text", "Test");

    amxd_trans_dump(&transaction, STDOUT_FILENO, false);
    assert_int_not_equal(amxd_trans_apply(&transaction, test_get_dm()), 0);
    amxd_trans_clean(&transaction);

    obj = amxd_dm_findf(test_get_dm(), "Top2.TObject.100");
    assert_ptr_not_equal(obj, NULL);
    text = amxd_object_get_value(cstring_t, obj, "Text", &status);
    assert_int_equal(status, amxd_status_ok);
    assert_ptr_not_equal(text, NULL);
    assert_string_equal(text, "InInst2");
    free(text);

    assert_int_equal(amxd_trans_select_pathf(&transaction, "Top2.TObject"), 0);
    assert_int_equal(amxd_trans_add_inst(&transaction, 101, NULL), 0);
    assert_int_equal(amxd_trans_select_pathf(&transaction, ".^"), 0);
    assert_int_equal(amxd_trans_add_inst(&transaction, 0, NULL), 0);
    assert_int_equal(amxd_trans_select_pathf(&transaction, ".TChild"), 0);
    amxd_trans_set_value(cstring_t, &transaction, "Text", "INVALID");

    amxd_trans_dump(&transaction, STDOUT_FILENO, false);
    assert_int_not_equal(amxd_trans_apply(&transaction, test_get_dm()), 0);
    amxd_trans_clean(&transaction);

    obj = amxd_dm_findf(test_get_dm(), "Top2.TObject");
    assert_int_equal(amxd_object_get_instance_count(obj), 2);
    obj = amxd_dm_findf(test_get_dm(), "Top2.TObject.101");
    assert_ptr_equal(obj, NULL);

    assert_int_equal(amxd_trans_select_pathf(&transaction, "Top2.TObject.100"), 0);
    assert_int_not_equal(amxd_trans_add_inst(NULL, 0, "Name"), 0);
    assert_int_equal(amxd_trans_add_inst(&transaction, 0, NULL), 0);
    amxd_trans_clean(&transaction);

    test_clean_dm();
}

void test_amxd_transaction_del_inst(UNUSED void** state) {
    amxd_trans_t transaction;
    amxd_object_t* obj = NULL;
    char* text = NULL;
    amxd_status_t status = amxd_status_ok;

    test_build_dm();

    assert_int_equal(amxd_trans_init(&transaction), 0);
    assert_int_equal(amxd_trans_select_pathf(&transaction, "Top1"), 0);
    amxd_trans_set_value(cstring_t, &transaction, "Text", "AcraCadabra");
    assert_int_equal(amxd_trans_select_pathf(&transaction, "Top2.TObject"), 0);
    assert_int_equal(amxd_trans_add_inst(&transaction, 99, "Inst1"), 0);
    amxd_trans_set_value(cstring_t, &transaction, "Text", "InInst1");
    amxd_trans_set_value(bool, &transaction, "Sticky", true);
    assert_int_equal(amxd_trans_select_pathf(&transaction, ".^"), 0);
    assert_int_equal(amxd_trans_add_inst(&transaction, 100, "Inst2"), 0);
    amxd_trans_set_value(cstring_t, &transaction, "Text", "InInst2");
    assert_int_equal(amxd_trans_select_pathf(&transaction, ".TemplateChild"), 0);
    assert_int_equal(amxd_trans_add_inst(&transaction, 1, NULL), 0);

    amxd_trans_dump(&transaction, STDOUT_FILENO, false);
    assert_int_equal(amxd_trans_apply(&transaction, test_get_dm()), 0);
    amxd_trans_clean(&transaction);

    obj = amxd_dm_findf(test_get_dm(), "Top2.TObject");
    assert_int_equal(amxd_object_get_instance_count(obj), 2);
    obj = amxd_dm_findf(test_get_dm(), "Top2.TObject.99");
    assert_true(amxd_object_get_value(bool, obj, "Sticky", NULL));
    assert_ptr_equal(amxd_dm_findf(test_get_dm(), "Top2.TObject.Inst1"), obj);

    assert_int_equal(amxd_trans_select_pathf(&transaction, "Top1"), 0);
    amxd_trans_set_value(cstring_t, &transaction, "Text", "Hello World");
    assert_int_equal(amxd_trans_select_pathf(&transaction, "Top2.TObject.100.TemplateChild."), 0);
    assert_int_equal(amxd_trans_del_inst(&transaction, 1, NULL), 0);
    assert_int_equal(amxd_trans_select_pathf(&transaction, "Top2.TObject"), 0);
    assert_int_equal(amxd_trans_del_inst(&transaction, 0, "Inst1"), 0);
    assert_int_equal(amxd_trans_del_inst(&transaction, 100, NULL), 0);
    assert_int_equal(amxd_trans_del_inst(&transaction, 100, NULL), 0);
    assert_int_equal(amxd_trans_select_pathf(&transaction, "Top2.TObject.100.TemplateChild."), 0);
    assert_int_equal(amxd_trans_del_inst(&transaction, 1, NULL), 0);

    amxd_trans_dump(&transaction, STDOUT_FILENO, false);
    assert_int_not_equal(amxd_trans_apply(&transaction, test_get_dm()), 0);
    amxd_trans_clean(&transaction);

    obj = amxd_dm_findf(test_get_dm(), "Top2.TObject");
    assert_int_equal(amxd_object_get_instance_count(obj), 2);

    obj = amxd_dm_findf(test_get_dm(), "Top1");
    text = amxd_object_get_value(cstring_t, obj, "Text", &status);
    assert_string_equal(text, "AcraCadabra");
    free(text);

    assert_int_equal(amxd_trans_select_pathf(&transaction, "Top2.TObject"), 0);
    assert_int_not_equal(amxd_trans_del_inst(NULL, 99, NULL), 0);
    assert_int_not_equal(amxd_trans_del_inst(&transaction, 0, NULL), 0);
    amxd_trans_clean(&transaction);

    assert_int_equal(amxd_trans_select_pathf(&transaction, "Top1"), 0);
    amxd_trans_set_value(cstring_t, &transaction, "Text", "Hello World");
    assert_int_equal(amxd_trans_select_pathf(&transaction, "Top2.TObject.Inst1"), 0);
    amxd_trans_set_value(bool, &transaction, "Sticky", false);
    assert_int_equal(amxd_trans_select_pathf(&transaction, ".^"), 0);
    assert_int_equal(amxd_trans_del_inst(&transaction, 99, NULL), 0);
    assert_int_equal(amxd_trans_del_inst(&transaction, 0, "Inst2"), 0);
    amxd_trans_dump(&transaction, STDOUT_FILENO, false);
    assert_int_equal(amxd_trans_apply(&transaction, test_get_dm()), 0);
    amxd_trans_clean(&transaction);

    obj = amxd_dm_findf(test_get_dm(), "Top2.TObject");
    assert_int_equal(amxd_object_get_instance_count(obj), 0);

    obj = amxd_dm_findf(test_get_dm(), "Top1");
    text = amxd_object_get_value(cstring_t, obj, "Text", &status);
    assert_string_equal(text, "Hello World");
    free(text);

    test_clean_dm();
}

void test_amxd_transaction_apply(UNUSED void** state) {
    amxd_trans_t transaction;
    amxd_object_t* inst = NULL;
    amxd_object_t* obj = NULL;
    amxd_status_t status = amxd_status_ok;
    char* text = NULL;
    test_build_dm();

    assert_int_equal(amxd_trans_init(&transaction), 0);
    amxd_trans_select_pathf(&transaction, "Top1");
    amxd_trans_set_value(cstring_t, &transaction, "Text", "Hello world");
    amxd_trans_set_value(cstring_t, &transaction, "Length", "1234");
    amxd_trans_select_pathf(&transaction, "Top2.TObject");
    amxd_trans_add_inst(&transaction, 1, "TestInst");
    amxd_trans_set_value(cstring_t, &transaction, "Text", "Hi");
    amxd_trans_select_pathf(&transaction, ".^");
    amxd_trans_add_inst(&transaction, 0, NULL);
    amxd_trans_set_value(cstring_t, &transaction, "Text", "Hi Back");
    amxd_trans_select_pathf(&transaction, ".TChild");
    amxd_trans_set_value(cstring_t, &transaction, "Text", "Sub Hi");
    amxd_trans_select_pathf(&transaction, ".^.^");
    amxd_trans_add_inst(&transaction, 0, NULL);
    amxd_trans_set_value(cstring_t, &transaction, "Text", "Hi Back Again");
    amxd_trans_set_value(cstring_t, &transaction, "TChild.Text", "Sub Hi Again");

    amxd_trans_dump(&transaction, STDOUT_FILENO, false);
    assert_int_equal(amxd_trans_apply(&transaction, test_get_dm()), 0);

    amxd_trans_clean(&transaction);

    obj = amxd_dm_findf(test_get_dm(), "Top2.TObject");
    assert_int_equal(amxd_object_get_instance_count(obj), 3);

    inst = amxd_dm_findf(test_get_dm(), "Top2.TObject.1");
    assert_ptr_not_equal(inst, NULL);
    text = amxd_object_get_value(cstring_t, inst, "Text", &status);
    assert_int_equal(status, amxd_status_ok);
    assert_ptr_not_equal(text, NULL);
    assert_string_equal(text, "Hi");
    free(text);

    inst = amxd_dm_findf(test_get_dm(), "Top2.TObject.2");
    assert_ptr_not_equal(inst, NULL);
    text = amxd_object_get_value(cstring_t, inst, "Text", &status);
    assert_int_equal(status, amxd_status_ok);
    assert_ptr_not_equal(text, NULL);
    assert_string_equal(text, "Hi Back");
    free(text);

    obj = amxd_object_get_child(inst, "TChild");
    assert_ptr_not_equal(obj, NULL);
    text = amxd_object_get_value(cstring_t, obj, "Text", &status);
    assert_int_equal(status, amxd_status_ok);
    assert_ptr_not_equal(text, NULL);
    assert_string_equal(text, "Sub Hi");
    free(text);

    amxd_trans_select_pathf(&transaction, "Top2.TObject");
    amxd_trans_del_inst(&transaction, 0, "TestInst");
    amxd_trans_select_pathf(&transaction, ".2");
    amxd_trans_set_value(cstring_t, &transaction, "Text", "Yahoo");
    amxd_trans_dump(&transaction, STDOUT_FILENO, false);
    amxd_trans_dump(&transaction, STDOUT_FILENO, true);
    assert_int_equal(amxd_trans_apply(&transaction, test_get_dm()), 0);
    amxd_trans_clean(&transaction);

    obj = amxd_dm_findf(test_get_dm(), "Top2.TObject");
    assert_int_equal(amxd_object_get_instance_count(obj), 2);
    inst = amxd_dm_findf(test_get_dm(), "Top2.TObject.2");
    assert_ptr_not_equal(inst, NULL);
    text = amxd_object_get_value(cstring_t, inst, "Text", &status);
    assert_int_equal(status, amxd_status_ok);
    assert_ptr_not_equal(text, NULL);
    assert_string_equal(text, "Yahoo");
    free(text);

    assert_int_not_equal(amxd_trans_apply(NULL, test_get_dm()), 0);
    assert_int_not_equal(amxd_trans_apply(&transaction, NULL), 0);

    test_clean_dm();
}

void test_amxd_transaction_on_null_object(UNUSED void** state) {
    amxd_trans_t transaction;
    amxc_var_t var;

    amxc_var_init(&var);
    amxc_var_set(cstring_t, &var, "Hello");

    test_build_dm();

    assert_int_equal(amxd_trans_init(&transaction), 0);
    amxd_trans_select_object(&transaction, NULL);
    amxd_trans_set_param(&transaction, "ExternalIPAddress", &var);
    assert_int_not_equal(amxd_trans_apply(&transaction, test_get_dm()), 0);
    amxd_trans_clean(&transaction);

    assert_int_equal(amxd_trans_init(&transaction), 0);
    amxd_trans_set_param(&transaction, "ExternalIPAddress", &var);
    assert_int_not_equal(amxd_trans_apply(&transaction, test_get_dm()), 0);
    amxd_trans_clean(&transaction);

    test_clean_dm();

    amxc_var_clean(&var);
}

void test_amxd_transaction_can_add_mib(UNUSED void** state) {
    amxd_trans_t transaction;

    test_build_dm();

    assert_int_equal(amxd_trans_init(&transaction), 0);
    amxd_trans_select_pathf(&transaction, "Top2.TObject");
    amxd_trans_add_mib(&transaction, "MObject");
    assert_int_equal(amxd_trans_apply(&transaction, test_get_dm()), 0);
    amxd_trans_clean(&transaction);

    test_clean_dm();
}

static void test_check_changed_event(UNUSED const char* const sig_name,
                                     const amxc_var_t* const data,
                                     UNUSED void* const priv) {
    amxd_dm_t* dm = test_get_dm();
    const char* path = NULL;
    amxd_object_t* object = NULL;
    amxc_var_dump(data, STDOUT_FILENO);

    assert_string_equal(GET_CHAR(data, "path"), "Top2.");
    assert_non_null(GETP_ARG(data, "parameters.TextA"));
    assert_non_null(GETP_ARG(data, "parameters.TextB"));

    path = amxd_dm_signal_get_path(dm, data);
    assert_string_equal(path, "Top2.");

    amxd_dm_signal_get_path(NULL, data);
    amxd_dm_signal_get_path(dm, NULL);

    object = amxd_dm_signal_get_object(dm, data);
    assert_non_null(object);

    amxd_dm_signal_get_object(NULL, data);
    amxd_dm_signal_get_object(dm, NULL);
}

void test_amxd_transaction_changed_event(UNUSED void** state) {
    amxd_trans_t transaction;
    amxd_dm_t* dm = NULL;

    test_build_dm();

    dm = test_get_dm();
    while(amxp_signal_read() == 0) {
    }

    assert_int_equal(amxp_slot_connect(&dm->sigmngr,
                                       "dm:object-changed",
                                       NULL,
                                       test_check_changed_event,
                                       NULL), 0);
    assert_int_equal(amxd_trans_init(&transaction), 0);
    amxd_trans_select_pathf(&transaction, "Top2.");
    amxd_trans_set_value(cstring_t, &transaction, "TextA", "Test1");
    amxd_trans_select_pathf(&transaction, ".TObject.");
    amxd_trans_add_inst(&transaction, 0, NULL);
    amxd_trans_set_value(cstring_t, &transaction, "Text", "Test");
    amxd_trans_select_pathf(&transaction, ".^.^.");
    amxd_trans_set_value(cstring_t, &transaction, "TextB", "Test2");

    assert_int_equal(amxd_trans_apply(&transaction, test_get_dm()), 0);

    amxd_trans_clean(&transaction);

    while(amxp_signal_read() == 0) {
    }

    test_clean_dm();
}

void test_amxd_transaction_revert(UNUSED void** state) {
    amxd_trans_t transaction;
    amxd_dm_t* dm = NULL;
    amxd_object_t* object = NULL;
    amxc_var_t value;

    test_build_dm();
    amxc_var_init(&value);

    dm = test_get_dm();
    while(amxp_signal_read() == 0) {
    }

    assert_int_equal(amxd_trans_init(&transaction), 0);
    amxd_trans_select_pathf(&transaction, "Top2.");
    amxd_trans_set_value(cstring_t, &transaction, "TextA", "Test1");
    amxd_trans_select_pathf(&transaction, ".TObject.");
    amxd_trans_add_inst(&transaction, 0, NULL);
    amxd_trans_set_value(cstring_t, &transaction, "Text", "Test");
    amxd_trans_select_pathf(&transaction, ".^.^.");
    amxd_trans_set_value(cstring_t, &transaction, "TextB", "Test2");

    assert_int_equal(amxd_trans_apply(&transaction, test_get_dm()), 0);

    amxd_trans_clean(&transaction);

    while(amxp_signal_read() == 0) {
    }

    assert_int_equal(amxd_trans_init(&transaction), 0);
    amxd_trans_select_pathf(&transaction, "Top2.");
    amxd_trans_set_value(cstring_t, &transaction, "TextA", "Test10");
    amxd_trans_select_pathf(&transaction, ".TObject.");
    amxd_trans_add_inst(&transaction, 0, NULL);
    amxd_trans_set_value(cstring_t, &transaction, "Text", "Test10");
    amxd_trans_select_pathf(&transaction, ".^.^.");
    amxd_trans_set_value(cstring_t, &transaction, "ERROR", "Test2");

    assert_int_not_equal(amxd_trans_apply(&transaction, test_get_dm()), 0);

    object = amxd_dm_findf(dm, "Top2.");
    amxd_object_get_param(object, "TextA", &value);
    assert_string_equal(GET_CHAR(&value, NULL), "Test1");

    amxd_trans_clean(&transaction);

    amxc_var_clean(&value);
    test_clean_dm();
}
