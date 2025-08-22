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

#include "amxd_priv.h"

#include <amxd/amxd_dm.h>
#include <amxd/amxd_action.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_path.h>

#include "amxd_assert.h"

static amxd_status_t amxd_can_set_parameter(const amxd_object_t* const object,
                                            const amxd_param_t* const param,
                                            bool set_read_only,
                                            amxd_dm_access_t access) {
    amxd_status_t status = amxd_status_ok;

    when_true_status(amxd_param_is_attr_set(param, amxd_pattr_private) &&
                     access != amxd_dm_access_private,
                     exit,
                     status = amxd_status_parameter_not_found);
    when_true_status(object->type == amxd_object_instance &&
                     !amxd_param_is_attr_set(param, amxd_pattr_instance),
                     exit,
                     status = amxd_status_parameter_not_found);
    when_true_status(object->type == amxd_object_template &&
                     !amxd_param_is_attr_set(param, amxd_pattr_template),
                     exit,
                     status = amxd_status_parameter_not_found);
    when_true_status(amxd_param_is_attr_set(param, amxd_pattr_read_only) &&
                     !set_read_only,
                     exit,
                     status = amxd_status_read_only);

exit:
    return status;
}

static amxc_var_t* amxd_set_action_get_result(const amxd_object_t* object, amxc_var_t* retval) {
    char* path = amxd_object_get_path(object, AMXD_OBJECT_TERMINATE | AMXD_OBJECT_INDEXED);
    amxc_var_t* result = GET_ARG(retval, path);

    if(result == NULL) {
        result = amxc_var_add_new_key(retval, path);
        amxc_var_set_type(result, AMXC_VAR_ID_HTABLE);
        result = amxc_var_add_key(amxc_htable_t, result, "parameters", NULL);
    } else {
        result = GET_ARG(result, "parameters");
    }

    free(path);
    return result;
}

static void amxd_set_action_add_error(amxc_var_t* result,
                                      const char* name,
                                      bool required,
                                      amxd_status_t status) {
    result = amxc_var_add_key(amxc_htable_t, result, name, NULL);
    amxc_var_add_key(uint32_t, result, "error_code", status);
    amxc_var_add_key(bool, result, "required", required);
}

static void amxd_set_action_add_result(amxc_var_t* result,
                                       const char* name,
                                       uint32_t type,
                                       amxc_var_t* value) {
    result = amxc_var_add_new_key(result, name);
    amxc_var_copy(result, value);
    amxc_var_cast(result, type);
}

static amxd_status_t amxd_action_set_value(amxd_object_t* object,
                                           amxd_dm_access_t access,
                                           const char* name,
                                           amxc_var_t* value,
                                           bool ro,
                                           bool required,
                                           amxc_var_t* ret) {
    amxc_var_t* obj_result = NULL;
    amxd_param_t* param = NULL;
    amxd_status_t status = amxd_status_unknown_error;

    param = amxd_object_get_param_def(object, name);
    if(param == NULL) {
        obj_result = amxd_set_action_get_result(object, ret);
        amxd_set_action_add_error(obj_result, name, required, amxd_status_parameter_not_found);
        status = amxd_status_parameter_not_found;
        goto exit;
    }
    object = amxd_param_get_owner(param);
    obj_result = amxd_set_action_get_result(object, ret);

    status = amxd_can_set_parameter(object, param, ro, access);
    if(status != amxd_status_ok) {
        amxd_set_action_add_error(obj_result, name, required, status);
        goto exit;
    }

    status = amxd_param_set_value(param, value);
    if(status != amxd_status_ok) {
        amxd_set_action_add_error(obj_result, name, required, status);
        goto exit;
    }

    amxd_set_action_add_result(obj_result, amxd_param_get_name(param), amxd_param_get_type(param), value);

exit:
    return status;
}

bool PRIVATE amxd_param_is_unique(amxd_object_t* const templ,
                                  amxd_object_t* const current,
                                  amxd_param_t* const param,
                                  const amxc_var_t* const value) {
    bool unique = true;
    if(amxd_param_is_attr_set(param, amxd_pattr_unique) &&
       !amxd_param_is_attr_set(param, amxd_pattr_key)) {
        const char* pname = amxd_param_get_name(param);
        char* v = amxc_var_dyncast(cstring_t, value);
        amxd_object_t* instance = amxd_object_findf(templ, "[%s == '%s']", pname, v);
        free(v);
        if((instance != NULL) && (instance != current)) {
            unique = false;
        }

    }

    return unique;
}

amxd_status_t PRIVATE amxd_action_set_values(amxd_object_t* const object,
                                             amxd_dm_access_t access,
                                             bool ro,
                                             const amxc_var_t* values,
                                             amxc_var_t* ret,
                                             bool required) {
    amxd_status_t status = amxd_status_ok;

    amxc_var_for_each(value, values) {
        const char* name = amxc_var_key(value);
        amxd_status_t ps = amxd_status_ok;
        if(amxc_var_type_of(value) == AMXC_VAR_ID_HTABLE) {
            amxd_object_t* instance = NULL;
            when_true_status(amxd_object_get_type(object) != amxd_object_template,
                             exit,
                             status = amxd_status_object_not_found);
            instance = amxd_object_get_instance(object, name, 0);
            when_null_status(instance, exit, status = amxd_status_object_not_found);
            ps = amxd_action_set_values(instance, access, ro, value, ret, required);
            if(ps != amxd_status_ok) {
                status = ps;
            }
        } else {
            ps = amxd_action_set_value(object, access, name, value, ro, required, ret);
            if(ps != amxd_status_ok) {
                status = ps;
            }
        }
    }

exit:
    return status;
}

amxd_status_t amxd_action_object_write(amxd_object_t* const object,
                                       UNUSED amxd_param_t* const p,
                                       amxd_action_t reason,
                                       const amxc_var_t* const args,
                                       amxc_var_t* const retval,
                                       UNUSED void* priv) {
    amxd_status_t status = amxd_status_unknown_error;
    amxc_var_t* params = NULL;
    amxd_dm_access_t access = amxd_dm_access_public;
    bool set_read_only = false;

    when_null(object, exit);
    when_null_status(args, exit, status = amxd_status_invalid_function_argument);
    when_true_status(reason != action_object_write,
                     exit,
                     status = amxd_status_function_not_implemented);

    when_true_status(amxc_var_type_of(args) != AMXC_VAR_ID_HTABLE,
                     exit,
                     status = amxd_status_invalid_function_argument);

    amxc_var_set_type(retval, AMXC_VAR_ID_HTABLE);
    access = (amxd_dm_access_t) amxc_var_dyncast(uint32_t, GET_ARG(args, "access"));
    set_read_only = GET_BOOL(args, "set_read_only");

    if(amxd_action_verify_access(object, access)) {
        params = amxc_var_get_key(args, "parameters", AMXC_VAR_FLAG_DEFAULT);
        if(params != NULL) {
            when_true_status(amxc_var_type_of(params) != AMXC_VAR_ID_HTABLE,
                             exit,
                             status = amxd_status_invalid_function_argument);
            status = amxd_action_set_values(object, access, set_read_only, params, retval, true);
            when_failed(status, exit);
        }
        params = amxc_var_get_key(args, "oparameters", AMXC_VAR_FLAG_DEFAULT);
        if(params != NULL) {
            when_true_status(amxc_var_type_of(params) != AMXC_VAR_ID_HTABLE,
                             exit,
                             status = amxd_status_invalid_function_argument);
            amxd_action_set_values(object, access, set_read_only, params, retval, false);
        }
        status = amxd_status_ok;
    } else {
        status = amxd_status_object_not_found;
    }

exit:
    return status;
}

amxd_status_t amxd_object_set_params(amxd_object_t* const object,
                                     amxc_var_t* const values) {

    amxd_status_t status = amxd_status_unknown_error;
    amxc_var_t args;

    amxc_var_init(&args);
    when_null(object, exit);
    when_true(amxc_var_is_null(values) ||
              amxc_var_type_of(values) != AMXC_VAR_ID_HTABLE,
              exit);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_set_key(&args, "parameters", values, AMXC_VAR_FLAG_COPY);
    amxc_var_add_key(uint32_t, &args, "access", amxd_dm_access_private);
    amxc_var_add_key(bool, &args, "set_read_only", true);
    status = amxd_dm_invoke_action(object,
                                   NULL,
                                   action_object_write,
                                   &args,
                                   NULL);

exit:
    amxc_var_clean(&args);
    return status;
}
