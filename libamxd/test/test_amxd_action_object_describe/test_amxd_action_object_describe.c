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
#include <amxd/amxd_object_event.h>

#include "test_amxd_action_object_describe.h"

#include <amxc/amxc_macros.h>
static amxd_dm_t dm;

static amxd_object_t* test_build_dm(void) {
    amxd_object_t* object = NULL;
    amxd_object_t* template = NULL;
    amxd_param_t* param = NULL;
    amxc_var_t* data = NULL;
    amxc_var_t* sub_data = NULL;

    amxc_var_new(&data);
    amxc_var_set_type(data, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, data, "Text", "Hello World");
    amxc_var_add_key(uint32_t, data, "Number", 100);
    sub_data = amxc_var_add_key(amxc_htable_t, data, "Sub", NULL);
    amxc_var_add_key(cstring_t, sub_data, "Text", "Hello Universe");
    amxc_var_add_key(bool, sub_data, "Boolean", true);

    assert_int_equal(amxd_dm_init(&dm), 0);

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
    assert_int_equal(amxd_object_add_event(template, "MyEvent1!"), 0);
    assert_int_equal(amxd_object_add_event_ext(template, "MyEvent2!", data), 0);

    assert_int_equal(amxd_param_new(&param, "child_param", AMXC_VAR_ID_CSTRING), 0);
    amxd_param_set_attr(param, amxd_pattr_private, true);
    assert_int_equal(amxd_object_add_param(object, param), 0);
    assert_int_equal(amxd_param_new(&param, "child_param2", AMXC_VAR_ID_BOOL), 0);
    assert_int_equal(amxd_object_add_param(object, param), 0);
    assert_int_equal(amxd_param_new(&param, "child_param3", AMXC_VAR_ID_UINT64), 0);
    assert_int_equal(amxd_object_add_param(object, param), 0);

    assert_int_equal(amxd_object_new(&object, amxd_object_singleton, "PChild"), 0);
    assert_int_equal(amxd_object_set_attr(object, amxd_oattr_protected, true), 0);
    assert_int_equal(amxd_object_add_object(template, object), 0);

    return template;
}

void test_amxd_object_describe(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxd_object_t* instance = NULL;
    amxc_var_t retval;
    amxc_var_t args;

    amxc_var_init(&retval);
    amxc_var_init(&args);

    template = test_build_dm();
    assert_int_equal(amxd_object_new_instance(&instance, template, NULL, 0, NULL), 0);
    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(uint32_t, &args, "access", amxd_dm_access_public);
    assert_int_equal(amxd_action_object_describe(template, NULL, action_object_describe, &args, &retval, NULL), 0);
    assert_int_equal(amxc_var_type_of(&retval), AMXC_VAR_ID_HTABLE);
    amxc_var_dump(&retval, STDOUT_FILENO);

    assert_ptr_not_equal(amxc_var_get_path(&retval, "name", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "attributes.private", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "attributes.read-only", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "attributes.persistent", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "attributes.persistent", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "type_name", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "type_id", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "path", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "object", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_equal(amxc_var_get_path(&retval, "index", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "parameters.templ_param", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "parameters.templ_param.attributes", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "parameters.templ_param.attributes.private", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "parameters.templ_param.attributes.instance", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "parameters.templ_param.attributes.template", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "parameters.templ_param.attributes.read-only", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "parameters.templ_param.attributes.volatile", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "parameters.templ_param.attributes.persistent", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "parameters.templ_param.name", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "parameters.templ_param.value", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "parameters.templ_param.type_name", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "parameters.templ_param.type_id", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "parameters.templ_param", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "parameters.param.attributes", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "parameters.param.attributes.private", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "parameters.param.attributes.instance", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "parameters.param.attributes.template", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "parameters.param.attributes.read-only", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "parameters.param.attributes.volatile", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "parameters.param.attributes.persistent", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "parameters.param.name", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "parameters.param.value", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "parameters.param.type_name", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "parameters.param.type_id", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "events.'MyEvent1!'", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "events.'MyEvent2!'", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_equal(amxc_var_get_path(&retval, "objects", AMXC_VAR_FLAG_DEFAULT), NULL);

    amxc_var_clean(&retval);
    assert_int_equal(amxd_action_object_describe(instance, NULL, action_object_describe, NULL, &retval, NULL), 0);
    assert_int_equal(amxc_var_type_of(&retval), AMXC_VAR_ID_HTABLE);
    amxc_var_dump(&retval, STDOUT_FILENO);

    assert_ptr_not_equal(amxc_var_get_path(&retval, "name", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "attributes.private", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "attributes.read-only", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "attributes.persistent", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "attributes.persistent", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "type_name", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "type_id", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "path", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "object", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "index", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "parameters.inst_param", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "parameters.inst_param.attributes", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "parameters.inst_param.attributes.private", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "parameters.inst_param.attributes.instance", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "parameters.inst_param.attributes.template", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "parameters.inst_param.attributes.read-only", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "parameters.inst_param.attributes.volatile", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "parameters.inst_param.attributes.persistent", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "parameters.inst_param.name", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "parameters.inst_param.value", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "parameters.inst_param.type_name", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "parameters.inst_param.type_id", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "parameters.inst_param", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "parameters.param.attributes", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "parameters.param.attributes.private", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "parameters.param.attributes.instance", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "parameters.param.attributes.template", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "parameters.param.attributes.read-only", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "parameters.param.attributes.volatile", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "parameters.param.attributes.persistent", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "parameters.param.name", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "parameters.param.value", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "parameters.param.type_name", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "parameters.param.type_id", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "events.'MyEvent1!'", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "events.'MyEvent2!'", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "objects'", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "objects.0", AMXC_VAR_FLAG_DEFAULT), NULL);

    assert_int_not_equal(amxd_action_object_describe(NULL, NULL, action_object_describe, NULL, &retval, NULL), 0);
    assert_int_not_equal(amxd_action_object_describe(template, NULL, action_object_describe, NULL, NULL, NULL), 0);
    assert_int_not_equal(amxd_action_object_describe(template, NULL, action_object_read, NULL, &retval, NULL), 0);

    amxc_var_clean(&retval);
    assert_int_equal(amxd_object_describe(template, &retval, AMXD_OBJECT_ALL, amxd_dm_access_protected), 0);
    assert_int_equal(amxc_var_type_of(&retval), AMXC_VAR_ID_HTABLE);

    assert_int_not_equal(amxd_object_describe(NULL, &retval, AMXD_OBJECT_ALL, amxd_dm_access_protected), 0);
    assert_int_not_equal(amxd_object_describe(template, NULL, AMXD_OBJECT_ALL, amxd_dm_access_protected), 0);

    amxc_var_clean(&retval);
    amxc_var_clean(&args);
    amxd_dm_clean(&dm);
}

void test_amxd_object_describe_params(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxd_object_t* instance = NULL;
    amxc_var_t retval;

    amxc_var_init(&retval);

    template = test_build_dm();
    assert_int_equal(amxd_object_new_instance(&instance, template, NULL, 0, NULL), 0);

    assert_int_equal(amxd_object_describe_params(template, &retval, amxd_dm_access_protected), 0);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "templ_param", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "templ_param.attributes", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "templ_param.attributes.private", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "templ_param.attributes.instance", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "templ_param.attributes.template", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "templ_param.attributes.read-only", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "templ_param.attributes.volatile", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "templ_param.attributes.persistent", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "templ_param.name", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "templ_param.value", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "templ_param.type_name", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "templ_param.type_id", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "templ_param", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "param.attributes", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "param.attributes.private", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "param.attributes.instance", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "param.attributes.template", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "param.attributes.read-only", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "param.attributes.volatile", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "param.attributes.persistent", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "param.name", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "param.value", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "param.type_name", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "param.type_id", AMXC_VAR_FLAG_DEFAULT), NULL);

    assert_int_equal(amxd_object_describe_params(instance, &retval, amxd_dm_access_protected), 0);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "inst_param", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "inst_param.attributes", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "inst_param.attributes.private", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "inst_param.attributes.instance", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "inst_param.attributes.template", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "inst_param.attributes.read-only", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "inst_param.attributes.volatile", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "inst_param.attributes.persistent", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "inst_param.name", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "inst_param.value", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "inst_param.type_name", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "inst_param.type_id", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "inst_param", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "param.attributes", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "param.attributes.private", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "param.attributes.instance", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "param.attributes.template", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "param.attributes.read-only", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "param.attributes.volatile", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "param.attributes.persistent", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "param.name", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "param.value", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "param.type_name", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "param.type_id", AMXC_VAR_FLAG_DEFAULT), NULL);

    assert_int_not_equal(amxd_object_describe_params(NULL, &retval, amxd_dm_access_protected), 0);
    assert_int_not_equal(amxd_object_describe_params(instance, NULL, amxd_dm_access_protected), 0);

    amxc_var_clean(&retval);
    amxd_dm_clean(&dm);
}

void test_amxd_object_describe_functions(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxd_object_t* instance = NULL;
    amxc_var_t retval;
    amxc_var_t args;

    amxc_var_init(&retval);
    amxc_var_init(&args);

    template = test_build_dm();
    assert_int_equal(amxd_object_new_instance(&instance, template, NULL, 0, NULL), 0);
    assert_int_equal(amxd_object_new_instance(&instance, template, NULL, 0, NULL), 0);
    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(uint32_t, &args, "access", amxd_dm_access_protected);

    assert_int_equal(amxd_object_describe_functions(template, &retval, amxd_dm_access_protected), 0);

    assert_ptr_not_equal(amxc_var_get_path(&retval, "_get", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "_get.attributes", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "_get.attributes.private", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "_get.attributes.instance", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "_get.attributes.template", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "_get.name", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "_get.type_name", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "_get.type_id", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "_get.arguments", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "_get.arguments.0", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "_get.arguments.0.attributes", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "_get.arguments.0.attributes.out", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "_get.arguments.0.attributes.in", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "_get.arguments.0.attributes.mandatory", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "_get.arguments.0.attributes.strict", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "_get.arguments.0.name", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "_get.arguments.0.type_id", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "_get.arguments.0.type_name", AMXC_VAR_FLAG_DEFAULT), NULL);

    assert_ptr_not_equal(amxc_var_get_path(&retval, "_set", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "_set.attributes", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "_set.attributes.private", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "_set.attributes.instance", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "_set.attributes.template", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "_set.name", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "_set.type_name", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "_set.type_id", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "_set.arguments", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "_set.arguments.0", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "_set.arguments.0.attributes", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "_set.arguments.0.attributes.out", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "_set.arguments.0.attributes.in", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "_set.arguments.0.attributes.mandatory", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "_set.arguments.0.attributes.strict", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "_set.arguments.0.name", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "_set.arguments.0.type_id", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "_set.arguments.0.type_name", AMXC_VAR_FLAG_DEFAULT), NULL);

    assert_int_not_equal(amxd_object_describe_functions(NULL, &retval, amxd_dm_access_protected), 0);
    assert_int_not_equal(amxd_object_describe_functions(instance, NULL, amxd_dm_access_protected), 0);

    amxc_var_clean(&args);
    amxc_var_clean(&retval);
    amxd_dm_clean(&dm);
}

void test_amxd_object_describe_events(UNUSED void** state) {
    amxd_object_t* template = NULL;
    amxd_object_t* instance = NULL;
    amxc_var_t retval;

    amxc_var_init(&retval);

    template = test_build_dm();
    assert_int_equal(amxd_object_new_instance(&instance, template, NULL, 0, NULL), 0);

    assert_int_equal(amxd_object_describe_events(template, &retval, amxd_dm_access_protected), 0);
    amxc_var_dump(&retval, STDOUT_FILENO);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "MyEvent1!", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_equal(amxc_var_get_path(&retval, "'MyEvent1!'.0", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "MyEvent2!", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "'MyEvent2!'.0", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "'MyEvent2!'.1", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "'MyEvent2!'.2", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "'MyEvent2!'.3", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_equal(amxc_var_get_path(&retval, "'MyEvent2!'.4", AMXC_VAR_FLAG_DEFAULT), NULL);

    assert_int_equal(amxd_object_describe_events(instance, &retval, amxd_dm_access_protected), 0);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "MyEvent1!", AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_ptr_not_equal(amxc_var_get_path(&retval, "MyEvent2!", AMXC_VAR_FLAG_DEFAULT), NULL);

    assert_int_not_equal(amxd_object_describe_events(NULL, &retval, amxd_dm_access_protected), 0);
    assert_int_not_equal(amxd_object_describe_events(instance, NULL, amxd_dm_access_protected), 0);

    amxc_var_clean(&retval);
    amxd_dm_clean(&dm);
}
