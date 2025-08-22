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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdlib.h>
#include <string.h>

#include "amxd_priv.h"

#include <amxd/amxd_dm.h>
#include <amxd/amxd_action.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_object_expression.h>

#include "amxd_priv.h"
#include "amxd_object_priv.h"
#include "amxd_assert.h"

static void amxd_action_add_inst_build_retval(amxd_object_t* instance,
                                              amxc_var_t* retval) {
    uint32_t index = amxd_object_get_index(instance);
    const char* name = amxd_object_get_name(instance, AMXD_OBJECT_NAMED);
    char* object = amxd_object_get_path(instance, AMXD_OBJECT_NAMED | AMXD_OBJECT_TERMINATE);
    char* path = amxd_object_get_path(instance, AMXD_OBJECT_INDEXED | AMXD_OBJECT_TERMINATE);
    amxc_var_t* parameters = NULL;
    const amxc_htable_t* ht_parameters = NULL;

    /* build the return value of the add instance action
       the return value is a variant containing a htable
       the variant contains this structure:
       {
            index      : <the new index>,
            name       : <the new name>,
            path       : <the full absolute path with indeces>
            object     : <the full absolute path with names>,
            parameters : <a hash table containig all key parameters and the values>
            {
                <KEY_PARAM1> : <KEY_PARAM1_VALUE>,
                <KEY_PARAM2> : <KEY_PARAM2_VALUE>,
                ...
                <KEY_PARAMn> : <KEY_PARAMn_VALUE>
            }
        }
     */
    amxc_var_set_type(retval, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(uint32_t, retval, "index", index);
    amxc_var_add_key(cstring_t, retval, "name", name);
    amxc_var_add_key(cstring_t, retval, "path", path);
    amxc_var_add_key(cstring_t, retval, "object", object);
    parameters = amxc_var_add_key(amxc_htable_t, retval, "parameters", NULL);

    /* Fetch the description of all parameters in the object and filter out
       the key parameters.

       The parameters variant (which is an htable) will contain all parameters
       after the call to amxd_object_describe_params.
       Each element will have as the key the name of the parameter and the value
       is a hash table containing all meta data of the parameter, including the
       attributes.

       The returned description for each parameter has this format
       <PARAM_NAME>   :
       {
            attributes :
            {
                instance   : <true or false>,
                read-only  : <true or false>,
                volatile   : <true or false>,
                counter    : <true or false>,
                unique     : <true or false>,
                private    : <true or false>,
                template   : <true or false>,
                protected  : <true or false>,
                key        : <true or false>,
                persistent : <true or false>
            },
            value      : <PARAM_VALUE>,
            name       : <PARAM_NAME>,
            type_name  : <PARAM_TYPE_NAME>,
            type_id    : <PARAM_TYPE_ID>
       }
       All parameters for which the "key" attribute is not set are deleted from
       the parameters hash table (using amxc_var_delete)

       All parameters for which the "key" attribute is set are updated.
           - the value of the parameter is taken from the description (field value)
           - the value of the parameter is updated (this will remove the description)
     */
    amxd_object_describe_params(instance, parameters, amxd_dm_access_private);
    ht_parameters = amxc_var_constcast(amxc_htable_t, parameters);
    amxc_htable_for_each(it, ht_parameters) {
        const char* param_name = amxc_htable_it_get_key(it);
        amxc_var_t* param_description = amxc_var_from_htable_it(it);
        bool is_key = GETP_BOOL(param_description, "attributes.key");
        if(is_key) {
            amxc_var_t* param_value = amxc_var_take_key(param_description, "value");
            amxc_var_set_key(parameters, param_name, param_value, AMXC_VAR_FLAG_UPDATE);
        } else {
            amxc_var_delete(&param_description);
        }
    }
    free(path);
    free(object);
}

static amxd_status_t amxd_instance_validate_keys(amxd_object_t* instance) {
    amxd_status_t status = amxd_status_ok;

    amxd_object_for_each(parameter, it, instance) {
        amxd_param_t* param = amxc_container_of(it, amxd_param_t, it);
        if(IS_BIT_SET(amxd_param_get_attrs(param), amxd_pattr_key)) {
            amxc_var_t value;
            amxc_var_init(&value);
            amxd_param_get_value(param, &value);
            status = amxd_param_validate(param, &value);
            amxc_var_clean(&value);
            when_failed(status, exit);
        }
    }

exit:
    return status;
}

static amxd_status_t amxd_action_add_inst(amxd_object_t* const templ,
                                          const char* name,
                                          uint32_t index,
                                          amxc_var_t* params,
                                          amxd_dm_access_t access,
                                          bool set_ro,
                                          amxc_var_t* retval) {
    amxd_status_t status = amxd_status_unknown_error;
    amxc_var_t templ_params;
    amxd_object_t* instance = NULL;
    amxp_expr_t* expr = NULL;

    amxc_var_init(&templ_params);
    when_true_status(amxd_object_get_type(templ) != amxd_object_template,
                     exit,
                     status = amxd_status_invalid_type);
    when_true_status(amxd_object_is_attr_set(templ, amxd_oattr_private) &&
                     access != amxd_dm_access_private,
                     exit,
                     status = amxd_status_invalid_action);
    when_true_status(amxd_object_is_attr_set(templ, amxd_oattr_read_only) &&
                     !set_ro,
                     exit,
                     status = amxd_status_invalid_action);

    status = amxd_object_new_instance(&instance, templ, name, index, params);
    when_failed(status, exit);

    status = amxd_action_set_values(instance, access, true, params, retval, true);
    if(status != amxd_status_ok) {
        amxd_object_delete(&instance);
        goto exit;
    }

    status = amxd_instance_validate_keys(instance);
    if(status != amxd_status_ok) {
        amxd_object_delete(&instance);
        goto exit;
    }

    amxd_action_add_inst_build_retval(instance, retval);

exit:
    amxc_var_clean(&templ_params);
    amxp_expr_delete(&expr);
    return status;
}

static bool amxd_action_add_inst_is_created(amxd_object_t* const object,
                                            amxc_var_t* data) {
    bool retval = false;

    when_false(amxc_var_type_of(data) == AMXC_VAR_ID_HTABLE, exit);
    when_null(GET_ARG(data, "index"), exit);
    when_null(amxd_object_get_instance(object, NULL, GET_UINT32(data, "index")), exit);

    retval = true;

exit:
    return retval;
}

amxd_status_t amxd_action_object_add_inst(amxd_object_t* const object,
                                          UNUSED amxd_param_t* const p,
                                          amxd_action_t reason,
                                          const amxc_var_t* const args,
                                          amxc_var_t* const retval,
                                          void* priv) {
    amxd_status_t status = amxd_status_unknown_error;
    amxc_var_t* params = NULL;
    amxc_var_t* max = (amxc_var_t*) priv;
    uint32_t index = 0;
    char* key = NULL;
    amxd_dm_access_t access = amxd_dm_access_public;
    bool set_ro = false;
    bool is_created = false;

    when_null(object, exit);
    when_null(retval, exit);
    when_true_status(reason != action_object_add_inst,
                     exit,
                     status = amxd_status_function_not_implemented);

    is_created = amxd_action_add_inst_is_created(object, retval);

    if(max != NULL) {
        uint32_t instances = amxd_object_get_instance_count(object);
        int64_t max_inst = 0;
        instances = is_created ? instances - 1 : instances;
        if(amxc_var_type_of(max) == AMXC_VAR_ID_CSTRING) {
            amxc_var_t* ref_value = amxd_resolve_param_ref(object, max);
            max = ref_value == NULL ? max : ref_value;
        }
        max_inst = amxc_var_dyncast(int64_t, max);
        if((max_inst > 0) && ((int64_t) instances >= max_inst)) {
            status = amxd_status_invalid_value;
            goto exit;
        }
    }

    if(is_created) {
        status = amxd_status_ok;
        goto exit;
    }

    index = GET_UINT32(args, "index");
    key = amxc_var_dyncast(cstring_t, GET_ARG(args, "name"));
    params = GET_ARG(args, "parameters");
    access = (amxd_dm_access_t) GET_UINT32(args, "access");
    set_ro = GET_BOOL(args, "set_read_only");

    when_true_status(!amxd_action_verify_access(object, access),
                     exit,
                     status = amxd_status_object_not_found);

    status = amxd_action_add_inst(object, key, index, params, access, set_ro, retval);

exit:
    free(key);
    return status;
}

amxd_status_t amxd_object_add_instance(amxd_object_t** instance,
                                       amxd_object_t* templ,
                                       const char* name,
                                       uint32_t index,
                                       amxc_var_t* values) {
    amxd_status_t status = amxd_status_unknown_error;
    amxc_var_t args;
    amxc_var_t* var_index = NULL;
    amxc_var_t retval;

    amxc_var_init(&args);
    amxc_var_init(&retval);
    when_null(templ, exit);

    if(instance != NULL) {
        *instance = NULL;
    }

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_set_key(&args, "parameters", values, AMXC_VAR_FLAG_COPY);
    amxc_var_add_key(uint32_t, &args, "access", amxd_dm_access_private);
    amxc_var_add_key(bool, &args, "set_read_only", true);
    amxc_var_add_key(uint32_t, &args, "index", index);
    amxc_var_add_key(cstring_t, &args, "name", name);

    status = amxd_dm_invoke_action(templ,
                                   NULL,
                                   action_object_add_inst,
                                   &args,
                                   &retval);
    when_failed(status, exit);

    var_index = amxc_var_get_path(&retval, "index", AMXC_VAR_FLAG_DEFAULT);
    index = amxc_var_dyncast(uint32_t, var_index);

    if(instance != NULL) {
        *instance = amxd_object_get_instance(templ, NULL, index);
    }

exit:
    amxc_var_clean(&args);
    amxc_var_clean(&retval);
    return status;
}
