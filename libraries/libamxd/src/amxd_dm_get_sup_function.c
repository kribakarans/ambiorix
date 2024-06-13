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

#include <string.h>
#include <stdlib.h>

#include "amxd_priv.h"

#include <amxd/amxd_dm.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_path.h>
#include <amxd/amxd_dm_functions.h>
#include <amxd/amxd_transaction.h>

#include "amxd_priv.h"
#include "amxd_assert.h"
#include "amxd_object_priv.h"
#include "amxd_dm_priv.h"

static void amxd_describe_object_usp(amxc_var_t* object_data,
                                     amxc_var_t* retval) {
    uint32_t access = 1;
    uint32_t obj_type = GET_UINT32(object_data, "type_id");
    amxc_var_t* attrs = GET_ARG(object_data, "attributes");

    if(GET_BOOL(attrs, "read-only")) {
        access = 0;
    }
    amxc_var_add_key(bool, retval, "is_multi_instance", obj_type == amxd_object_template);
    if(obj_type == amxd_object_template) {
        amxc_var_add_key(uint32_t, retval, "access", access);
    }
}

static void amxd_describe_param_usp(amxc_var_t* param_data,
                                    amxc_var_t* retval) {
    amxc_var_t* attrs = GET_ARG(param_data, "attributes");
    amxc_var_t* name = GET_ARG(param_data, "name");
    uint32_t param_type = GET_UINT32(param_data, "type_id");

    amxc_var_set_key(retval, "param_name", name, AMXC_VAR_FLAG_DEFAULT);
    if(GET_BOOL(attrs, "read-only") || (GET_BOOL(attrs, "key") && !GET_BOOL(attrs, "mutable"))) {
        amxc_var_add_key(uint32_t, retval, "access", 0);
    } else {
        amxc_var_add_key(uint32_t, retval, "access", 1);
    }
    amxc_var_add_key(uint32_t, retval, "type", param_type);
    amxc_var_add_key(uint32_t, retval, "value_change", GET_BOOL(attrs, "volatile")? 2:1);

    amxc_var_delete(&attrs);
}

static void amxd_describe_func_usp(amxc_var_t* func_data,
                                   amxc_var_t* retval) {
    amxc_string_t* name = amxc_var_take(amxc_string_t, GET_ARG(func_data, "name"));
    amxc_var_t* args = GET_ARG(func_data, "arguments");
    amxc_var_t* out_args = NULL;
    amxc_var_t* in_args = NULL;

    amxc_string_append(name, "()", 2);
    amxc_var_add_key(uint32_t, retval, "command_type",
                     GETP_BOOL(func_data, "attributes.asynchronous")? 2:1);
    amxc_var_add_key(cstring_t, retval, "command_name", amxc_string_get(name, 0));
    out_args = amxc_var_add_key(amxc_llist_t, retval, "output_arg_names", NULL);
    in_args = amxc_var_add_key(amxc_llist_t, retval, "input_arg_names", NULL);
    amxc_var_for_each(arg, args) {
        amxc_var_t* arg_attrs = GET_ARG(arg, "attributes");
        if(GET_BOOL(arg_attrs, "out")) {
            amxc_var_add(cstring_t, out_args, GET_CHAR(arg, "name"));
        }
        if(GET_BOOL(arg_attrs, "in")) {
            amxc_var_add(cstring_t, in_args, GET_CHAR(arg, "name"));
        }
    }
    amxc_string_delete(&name);
}

static void amxd_get_supported_add_data(amxd_object_t* const object,
                                        amxc_var_t* data,
                                        get_supported_args_t* sup) {
    uint32_t flags = 0;
    amxc_var_t object_data;

    amxc_var_init(&object_data);
    flags = AMXD_TEMPLATE_INFO;
    if(sup->params) {
        flags |= AMXD_OBJECT_PARAM;
    }
    if(sup->functions) {
        flags |= AMXD_OBJECT_FUNC | AMXD_OBJECT_NO_BASE;
    }
    if(sup->events) {
        flags |= AMXD_OBJECT_EVENT;
    }
    amxd_object_describe(object, &object_data, flags, sup->access);

    amxd_describe_object_usp(&object_data, data);
    if(sup->params) {
        const amxc_var_t* params = GET_ARG(&object_data, "parameters");
        amxc_var_t* usp_params
            = amxc_var_add_key(amxc_llist_t, data, "supported_params", NULL);
        amxc_var_for_each(param, params) {
            amxc_var_t* usp_param = amxc_var_add(amxc_htable_t, usp_params, NULL);
            amxd_describe_param_usp(param, usp_param);
        }
    }

    if(sup->functions) {
        const amxc_var_t* funcs = GET_ARG(&object_data, "functions");
        amxc_var_t* usp_funcs
            = amxc_var_add_key(amxc_llist_t, data, "supported_commands", NULL);
        amxc_var_for_each(func, funcs) {
            amxc_var_t* usp_func = amxc_var_add(amxc_htable_t, usp_funcs, NULL);
            amxd_describe_func_usp(func, usp_func);
        }
    }

    if(sup->events) {
        const amxc_var_t* events = GET_ARG(&object_data, "events");
        amxc_var_t* usp_events
            = amxc_var_add_key(amxc_llist_t, data, "supported_events", NULL);
        amxc_var_copy(usp_events, events);
    }

    amxc_var_clean(&object_data);
}

static bool amxd_get_supported_filter(amxd_object_t* const object,
                                      UNUSED int32_t depth,
                                      UNUSED void* priv) {
    get_supported_args_t* sup = (get_supported_args_t*) priv;

    if(amxd_object_get_type(object) == amxd_object_instance) {
        return false;
    }
    if(amxd_object_is_attr_set(object, amxd_oattr_private)) {
        return false;
    }
    if(amxd_object_is_attr_set(object, amxd_oattr_protected) &&
       (sup->access == amxd_dm_access_public)) {
        return false;
    }
    return true;
}

static void amxd_get_supported_impl(amxd_object_t* const object,
                                    int32_t depth,
                                    void* priv) {
    get_supported_args_t* sup = (get_supported_args_t*) priv;
    char* sup_path = amxd_object_get_path(object,
                                          AMXD_OBJECT_TERMINATE |
                                          AMXD_OBJECT_SUPPORTED);
    amxc_var_t* data = amxc_var_add_key(amxc_htable_t, sup->ret, sup_path, NULL);
    if(sup->first_lvl && (depth == 0)) {
        sup->functions = false;
        sup->params = false;
        sup->events = false;
    }
    amxd_get_supported_add_data(object, data, sup);
    free(sup_path);
}

static amxd_status_t amxd_get_supported(amxd_object_t* object,
                                        get_supported_args_t* sup) {
    amxd_status_t status = amxd_status_invalid_path;

    amxc_var_set_type(sup->ret, AMXC_VAR_ID_HTABLE);
    amxd_object_hierarchy_walk(object,
                               amxd_direction_down,
                               amxd_get_supported_filter,
                               amxd_get_supported_impl,
                               sup->first_lvl ? 1 : INT32_MAX,
                               sup);

    status = amxd_status_ok;

    return status;
}

amxd_status_t amxd_object_func_get_supported(amxd_object_t* object,
                                             UNUSED amxd_function_t* func,
                                             amxc_var_t* args,
                                             amxc_var_t* ret) {
    amxd_status_t retval = amxd_status_unknown_error;
    amxc_var_t* var_rel_path = GET_ARG(args, "rel_path");
    const char* rel_path = GET_CHAR(var_rel_path, NULL);

    get_supported_args_t sup;
    sup.functions = GET_BOOL(args, "functions");
    sup.params = GET_BOOL(args, "parameters");
    sup.events = GET_BOOL(args, "events");
    sup.first_lvl = GET_BOOL(args, "first_level_only");
    sup.access = (amxd_dm_access_t) GET_UINT32(args, "access");
    sup.ret = ret;

    amxc_var_take_it(var_rel_path);
    if((rel_path != NULL) && (*rel_path != 0)) {
        amxd_path_t path;
        char* obj_path = NULL;

        amxd_path_init(&path, rel_path);
        obj_path = amxd_path_get_supported_path(&path);
        if(obj_path != NULL) {
            object = amxd_object_findf(object, "%s", obj_path);
        }
        free(obj_path);
        amxd_path_clean(&path);
        when_null_status(object, exit, retval = amxd_status_object_not_found);
    } else {
        char* obj_path = NULL;

        obj_path = amxd_object_get_path(object, AMXD_OBJECT_TERMINATE | AMXD_OBJECT_SUPPORTED);
        object = amxd_dm_findf(amxd_object_get_dm(object), "%s", obj_path);
        free(obj_path);
        when_null_status(object, exit, retval = amxd_status_object_not_found);
    }

    retval = amxd_get_supported(object, &sup);

exit:
    amxc_var_delete(&var_rel_path);
    return retval;
}
