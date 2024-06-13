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

#include "amxd_assert.h"
#include "amxd_object_priv.h"
#include "amxd_dm_priv.h"

typedef struct _amxd_get {
    amxc_var_t* response;
    amxc_var_t* args;
    bool key_path;
    bool template_only;
    bool include_templates;
    amxd_status_t status;
    bool has_params;
} amxd_get_t;

static bool amxd_get_filter(amxd_object_t* const object,
                            UNUSED int32_t depth,
                            void* priv) {
    amxd_object_t* parent = NULL;
    amxd_get_t* data = (amxd_get_t*) priv;

    if(amxd_object_get_type(object) == amxd_object_instance) {
        return true;
    }
    parent = amxd_object_get_parent(object);
    if((amxd_object_get_type(parent) == amxd_object_template) &&
       !data->include_templates) {
        return false;
    }
    return true;
}

static void amxd_get_subobject(amxd_object_t* const object,
                               UNUSED int32_t depth,
                               void* priv) {
    amxd_get_t* data = (amxd_get_t*) priv;
    amxc_var_t* sub_obj = NULL;
    char* path = NULL;
    amxd_dm_access_t access = (amxd_dm_access_t) GET_UINT32(data->args, "access");
    uint32_t flags = data->key_path ? AMXD_OBJECT_NAMED : AMXD_OBJECT_INDEXED;

    when_true(amxd_object_get_type(object) == amxd_object_template &&
              access == amxd_dm_access_public, exit);
    when_true(data->template_only && amxd_object_get_type(object) != amxd_object_instance, exit);
    when_false(amxd_action_can_access_object(amxd_object_get_attrs(object), access), exit);
    path = amxd_object_get_path(object, AMXD_OBJECT_TERMINATE | flags);
    sub_obj = amxc_var_add_key(amxc_htable_t, data->response, path, NULL);
    if(amxd_object_get_type(object) == amxd_object_template) {
        if(data->has_params) {
            amxc_var_delete(&sub_obj);
        }
        when_false(data->include_templates, exit);
    }

    data->status = amxd_dm_invoke_action(object, NULL, action_object_read, data->args, sub_obj);
    if(data->status != amxd_status_ok) {
        amxc_var_delete(&sub_obj);
        if(data->status == amxd_status_object_not_found) {
            // when not found an empty set can be returned.
            // it is also possible that the object is not accessible (protected/private)
            // and there for should not be added to the result list, but it should
            // not result in an error.
            data->status = amxd_status_ok;
        }
    }

exit:
    free(path);
}

static amxd_status_t amxd_get_fill_response(amxd_dm_t* dm,
                                            bool key_path,
                                            bool template_only,
                                            amxc_llist_t* paths,
                                            amxc_var_t* args,
                                            amxc_var_t* ret) {
    int32_t depth = amxc_var_dyncast(int32_t, GET_ARG(args, "depth"));
    amxc_var_t* params = GET_ARG(args, "parameters");
    bool has_params = !amxc_llist_is_empty(amxc_var_constcast(amxc_llist_t, params));
    amxd_dm_access_t access = (amxd_dm_access_t) GET_UINT32(args, "access");

    amxd_get_t data = {
        .response = ret,
        .args = args,
        .key_path = key_path,
        .template_only = template_only,
        .include_templates = GET_BOOL(args, "templates"),
        .status = amxd_status_ok,
        .has_params = has_params
    };

    if(depth < 0) {
        depth = INT32_MAX;
    }

    amxc_llist_for_each(it, paths) {
        amxd_object_t* object = NULL;
        amxc_string_t* real_path = amxc_string_from_llist_it(it);
        const char* str_rp = NULL;

        str_rp = amxc_string_get(real_path, 0);
        object = amxd_dm_findf(dm, "%s", str_rp);

        if(template_only && (amxd_object_get_type(object) != amxd_object_template) &&
           !data.include_templates) {
            data.status = amxd_status_invalid_path;
            break;
        }

        if(data.include_templates) {
            // go up in hierarchy until highest template object is found
            amxd_object_t* highest = object;
            amxd_object_t* parent = amxd_object_get_parent(object);
            while(parent != NULL) {
                if(amxd_object_get_type(parent) == amxd_object_template) {
                    highest = parent;
                }
                parent = amxd_object_get_parent(parent);
            }
            object = highest;
        }

        if(!amxd_action_verify_access(object, access)) {
            data.status = amxd_status_invalid_path;
            break;
        }

        if((amxd_object_get_type(object) == amxd_object_template)) {
            if(has_params) {
                data.status = amxd_status_parameter_not_found;
                break;
            }
            if(depth == 0) {
                depth = 1;
            }
        }

        amxd_object_hierarchy_walk(object,
                                   amxd_direction_down,
                                   amxd_get_filter,
                                   amxd_get_subobject,
                                   depth,
                                   &data);
    }

    return data.status;
}

amxd_status_t amxd_object_func_get(amxd_object_t* object,
                                   UNUSED amxd_function_t* func,
                                   amxc_var_t* args,
                                   amxc_var_t* ret) {
    amxd_status_t retval = amxd_status_unknown_error;
    amxd_dm_t* dm = amxd_object_get_dm(object);
    amxc_var_t* var_rel_path = GET_ARG(args, "rel_path");
    const char* rel_path = GET_CHAR(var_rel_path, NULL);
    amxc_var_t* params = GET_ARG(args, "parameters");
    amxd_path_t path;
    const char* object_path = NULL;
    const char* parameter = NULL;
    amxc_llist_t paths;

    amxc_llist_init(&paths);
    amxd_def_funcs_remove_args(args);

    retval = amxd_path_init(&path, rel_path);
    when_failed(retval, exit);

    parameter = amxd_path_get_param(&path);
    object_path = amxd_path_get(&path, AMXD_OBJECT_TERMINATE);
    if((parameter != NULL) && (parameter[0] != 0)) {
        if(params == NULL) {
            params = amxc_var_add_key(amxc_llist_t, args, "parameters", NULL);
        }
        amxc_var_add(cstring_t, params, parameter);
    }

    amxc_var_set_type(ret, AMXC_VAR_ID_HTABLE);
    retval = amxd_object_resolve_pathf(object, &paths, "%s", object_path);
    when_failed(retval, exit);
    amxc_var_take_it(var_rel_path);
    retval = amxd_get_fill_response(dm, false, false, &paths, args, ret);

    if(retval == amxd_status_ok) {
        const amxc_htable_t* hresult = amxc_var_constcast(amxc_htable_t, ret);
        if(amxc_htable_is_empty(hresult)) {
            if(!amxd_path_is_search_path(&path)) {
                object = amxd_object_findf(object, "%s", object_path);
                if((object == NULL) || (amxd_object_get_type(object) != amxd_object_template)) {
                    retval = amxd_status_invalid_path;
                }
            } else {
                if(!amxd_object_is_supported(object, rel_path)) {
                    retval = amxd_status_invalid_path;
                }
            }
        }
    } else {
        if(retval == amxd_status_parameter_not_found) {
            const amxc_htable_t* hresult = amxc_var_constcast(amxc_htable_t, ret);
            if((hresult != NULL) && !amxc_htable_is_empty(hresult)) {
                retval = amxd_status_ok;
            }
        }
    }

exit:
    if(retval != amxd_status_ok) {
        amxc_var_clean(ret);
    }
    amxc_var_delete(&var_rel_path);
    amxd_path_clean(&path);
    amxc_llist_clean(&paths, amxc_string_list_it_free);
    return retval;
}

amxd_status_t amxd_object_func_get_instances(amxd_object_t* object,
                                             UNUSED amxd_function_t* func,
                                             amxc_var_t* args,
                                             amxc_var_t* ret) {
    amxd_status_t retval = amxd_status_unknown_error;
    amxd_dm_t* dm = amxd_object_get_dm(object);
    amxc_var_t* var_rel_path = GET_ARG(args, "rel_path");
    const char* rel_path = GET_CHAR(var_rel_path, NULL);
    amxd_path_t path;
    const char* object_path = NULL;
    amxc_llist_t paths;
    amxc_var_t* attrs = NULL;

    amxc_llist_init(&paths);
    amxd_def_funcs_remove_args(args);

    retval = amxd_path_init(&path, rel_path);
    when_failed(retval, exit);
    if(!amxd_object_is_supported(object, rel_path)) {
        retval = amxd_status_invalid_path;
        goto exit;
    }

    if(amxd_path_get_param(&path) != NULL) {
        retval = amxd_status_invalid_path;
        goto exit;
    }

    object_path = amxd_path_get(&path, AMXD_OBJECT_TERMINATE);

    amxc_var_set_type(ret, AMXC_VAR_ID_HTABLE);
    retval = amxd_object_resolve_pathf(object, &paths, "%s", object_path);
    when_failed(retval, exit);
    attrs = amxc_var_add_key(uint32_t, args, "attributes", SET_BIT(amxd_pattr_key));
    amxc_var_take_it(var_rel_path);
    retval = amxd_get_fill_response(dm, false, true, &paths, args, ret);

exit:
    if(retval != amxd_status_ok) {
        amxc_var_clean(ret);
    }
    amxc_var_delete(&attrs);
    amxc_var_delete(&var_rel_path);
    amxd_path_clean(&path);
    amxc_llist_clean(&paths, amxc_string_list_it_free);
    return retval;
}
