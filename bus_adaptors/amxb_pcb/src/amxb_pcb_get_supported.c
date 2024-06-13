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

#include "amxb_pcb.h"
#include <yajl/yajl_gen.h>
#include <amxj/amxj_variant.h>

typedef struct _supported_paths {
    amxc_htable_it_t hit;
    char* supported_path;
} supported_path_t;

typedef struct _supported_data {
    amxc_htable_t objects;
    uint32_t flags;
} supported_data_t;

static void amxb_pcb_del_sup_path(UNUSED const char* key,
                                  amxc_htable_it_t* it) {
    supported_path_t* sup_path = amxc_htable_it_get_data(it, supported_path_t, hit);
    free(sup_path->supported_path);
    free(sup_path);
}

static void amxb_pcb_describe_param_usp(object_t* pcb_object,
                                        amxc_var_t* retval) {
    parameter_t* param = NULL;
    amxc_var_t* params = amxc_var_add_key(amxc_llist_t,
                                          retval,
                                          "supported_params",
                                          NULL);

    object_for_each_parameter(param, pcb_object) {
        const char* param_name = parameter_name(param);
        uint32_t attr = parameter_attributes(param);
        parameter_type_t type = parameter_type(param);
        amxc_var_t* usp_param = amxc_var_add(amxc_htable_t, params, NULL);
        if((attr & PARAMETER_ATTR_EVENT) != 0) {
            amxc_var_delete(&usp_param);
            continue;
        }
        amxc_var_add_key(cstring_t, usp_param, "param_name", param_name);
        if(((attr & parameter_attr_read_only) == parameter_attr_read_only) ||
           ((attr & parameter_attr_key) == parameter_attr_key)) {
            amxc_var_add_key(uint32_t, usp_param, "access", 0);
        } else {
            amxc_var_add_key(uint32_t, usp_param, "access", 1);
        }
        amxc_var_add_key(uint32_t, usp_param, "type", amxb_var_type_from_pcb_arg_type(type));
        amxc_var_add_key(uint32_t, usp_param, "value_change",
                         (attr & (parameter_attr_volatile | parameter_attr_volatile_handler)) != 0? 2:1);
    }
    if(amxc_llist_is_empty(&params->data.vl)) {
        amxc_var_delete(&params);
    }
}

static void amxb_pcb_describe_event_usp(object_t* pcb_object,
                                        amxc_var_t* retval) {
    parameter_t* param = NULL;
    amxc_var_t* params = amxc_var_add_key(amxc_htable_t,
                                          retval,
                                          "supported_events",
                                          NULL);

    object_for_each_parameter(param, pcb_object) {
        amxc_var_t* event_data = NULL;
        const char* param_name = parameter_name(param);
        uint32_t attr = parameter_attributes(param);
        const variant_t* value = parameter_getValue(param);
        if((attr & PARAMETER_ATTR_EVENT) == 0) {
            continue;
        }
        amxc_var_new(&event_data);
        amxc_var_set(jstring_t, event_data, variant_da_char(value));
        amxc_var_cast(event_data, AMXC_VAR_ID_ANY);
        amxc_var_set_key(params, param_name, event_data, AMXC_VAR_FLAG_DEFAULT);
    }
    if(amxc_llist_is_empty(&params->data.vl)) {
        amxc_var_delete(&params);
    }
}

static void amxb_pcb_describe_func_usp(object_t* pcb_object,
                                       amxc_var_t* retval) {
    function_t* func = NULL;
    amxc_var_t* funcs = amxc_var_add_key(amxc_llist_t,
                                         retval,
                                         "supported_commands",
                                         NULL);
    amxc_string_t func_name;
    amxc_string_init(&func_name, 0);

    object_for_each_function(func, pcb_object) {
        function_argument_t* arg = NULL;
        amxc_var_t* out_args = NULL;
        amxc_var_t* in_args = NULL;
        const char* name = function_name(func);
        amxc_var_t* usp_func = NULL;

        usp_func = amxc_var_add(amxc_htable_t, funcs, NULL);

        amxc_string_setf(&func_name, "%s()", name);
        amxc_var_add_key(cstring_t,
                         usp_func,
                         "command_name",
                         amxc_string_get(&func_name, 0));

        amxc_var_add_key(uint32_t, usp_func, "command_type",
                         (function_attributes(func) & function_attr_async) != 0? 2:1);

        out_args = amxc_var_add_key(amxc_llist_t, usp_func, "output_arg_names", NULL);
        in_args = amxc_var_add_key(amxc_llist_t, usp_func, "input_arg_names", NULL);
        for(arg = function_firstArgument(func); arg; arg = function_nextArgument(arg)) {
            argument_attribute_t arg_attrs = argument_attributes(arg);
            const char* arg_name = argument_name(arg);
            if(arg_attrs & argument_attr_out) {
                amxc_var_add(cstring_t, out_args, arg_name);
            }
            if(arg_attrs & argument_attr_in) {
                amxc_var_add(cstring_t, in_args, arg_name);
            }
        }
    }
    if(amxc_llist_is_empty(&funcs->data.vl)) {
        amxc_var_delete(&funcs);
    }

    amxc_string_clean(&func_name);
}

static amxc_var_t* amxb_pcb_update_supported_path(object_t* pcb_object,
                                                  supported_path_t* sup_path,
                                                  amxc_var_t* var) {
    amxc_var_t* rv = NULL;
    amxc_string_t full_path;
    amxc_string_init(&full_path, 0);

    if(object_isTemplate(pcb_object)) {
        int length = strlen(sup_path->supported_path);
        char* p = sup_path->supported_path;
        if((length >= 4) && (strncmp(p + length - 4, "{i}.", 4) != 0)) {
            amxc_string_appendf(&full_path, "%s{i}.", p);
            free(p);
            sup_path->supported_path
                = amxc_string_dup(&full_path, 0, amxc_string_text_length(&full_path));
        } else {
            amxc_string_appendf(&full_path, "%s", sup_path->supported_path);
        }
    } else {
        amxc_string_appendf(&full_path, "%s", sup_path->supported_path);
    }

    rv = amxc_var_add_key(amxc_htable_t, var, amxc_string_get(&full_path, 0), NULL);
    amxc_string_clean(&full_path);

    return rv;
}

static amxc_var_t* amxb_pcb_add_supported_path(object_t* pcb_object,
                                               supported_path_t* sup_path,
                                               amxc_htable_t* objects,
                                               const char* object_ipath,
                                               amxc_var_t* var) {
    amxc_var_t* rv = NULL;
    const char* obj_name = object_name(pcb_object, 0);
    amxc_string_t full_path;
    amxc_string_init(&full_path, 0);

    amxc_string_appendf(&full_path, "%s%s.", sup_path->supported_path, obj_name);
    if(object_isTemplate(pcb_object)) {
        amxc_string_appendf(&full_path, "{i}.");
    }

    rv = amxc_var_add_key(amxc_htable_t, var, amxc_string_get(&full_path, 0), NULL);

    sup_path = (supported_path_t*) calloc(1, sizeof(supported_path_t));
    sup_path->supported_path = amxc_string_dup(&full_path,
                                               0,
                                               amxc_string_text_length(&full_path));
    amxc_htable_insert(objects, object_ipath, &sup_path->hit);

    amxc_string_clean(&full_path);
    return rv;
}

static void amxb_pcb_ipath_to_spath(const char* ipath, amxc_string_t* spath) {
    amxc_llist_t parts;
    const char* sep = "";

    amxc_llist_init(&parts);
    amxc_string_setf(spath, "%s", ipath);

    amxc_string_split_to_llist(spath, &parts, '.');
    amxc_string_clean(spath);

    amxc_llist_for_each(it, &parts) {
        amxc_string_t* part = amxc_container_of(it, amxc_string_t, it);
        if(amxc_string_is_numeric(part)) {
            amxc_string_appendf(spath, "%s{i}", sep);
        } else {
            amxc_string_appendf(spath, "%s%s", sep, amxc_string_get(part, 0));
        }
        amxc_llist_it_clean(it, amxc_string_list_it_free);
        sep = ".";
    }

    if(!amxc_string_is_empty(spath)) {
        amxc_string_appendf(spath, "%s", sep);
    }
    amxc_llist_clean(&parts, amxc_string_list_it_free);
}

static int amxb_pcb_object_to_supported_var_common(object_t* pcb_object,
                                                   amxc_var_t* var,
                                                   void* priv,
                                                   amxc_var_t** obj_var) {
    amxc_htable_t* objects = (amxc_htable_t*) priv;
    amxc_htable_it_t* it = NULL;
    supported_path_t* sup_path = NULL;
    int rv = -1;
    char* object_ipath = object_pathChar(pcb_object, path_attr_default);
    char* parent_ipath = object_pathChar(pcb_object, path_attr_parent | path_attr_default);

    when_true(object_isInstance(pcb_object), exit);

    it = amxc_htable_get(objects, object_ipath);
    if(it != NULL) {
        sup_path = amxc_htable_it_get_data(it, supported_path_t, hit);
        *obj_var = amxb_pcb_update_supported_path(pcb_object, sup_path, var);
        when_null(*obj_var, exit);
    } else {
        it = amxc_htable_get(objects, parent_ipath);
        when_true(it == NULL, exit);
        sup_path = amxc_htable_it_get_data(it, supported_path_t, hit);
        *obj_var = amxb_pcb_add_supported_path(pcb_object,
                                               sup_path,
                                               objects,
                                               object_ipath,
                                               var);
    }
    amxc_var_add_key(bool, *obj_var, "is_multi_instance", object_isTemplate(pcb_object));
    if(object_isTemplate(pcb_object)) {
        if(object_attributes(pcb_object) & object_attr_read_only) {
            amxc_var_add_key(uint32_t, *obj_var, "access", 0);
        } else {
            amxc_var_add_key(uint32_t, *obj_var, "access", 1);
        }
    }

    rv = 0;
exit:
    free(object_ipath);
    free(parent_ipath);
    return rv;
}

static void amxb_pcb_object_to_supported_var(object_t* pcb_object,
                                             amxc_var_t* var,
                                             void* priv) {
    supported_data_t* data = (supported_data_t*) priv;
    amxc_var_t* obj_var = NULL;

    if(amxb_pcb_object_to_supported_var_common(pcb_object, var, &data->objects, &obj_var) == 0) {
        if((data->flags & AMXB_FLAG_PARAMETERS) != 0) {
            amxb_pcb_describe_param_usp(pcb_object, obj_var);
        }
        if((data->flags & AMXB_FLAG_EVENTS) != 0) {
            amxb_pcb_describe_event_usp(pcb_object, obj_var);
        }
        amxb_pcb_describe_func_usp(pcb_object, obj_var);
    }
}

static void amxb_pcb_object_to_supported_var_first_lvl(object_t* pcb_object,
                                                       amxc_var_t* var,
                                                       void* priv) {
    supported_data_t* data = (supported_data_t*) priv;
    amxc_var_t* obj_var = NULL;
    const amxc_htable_t* o = amxc_var_constcast(amxc_htable_t, var);
    bool first = (o == NULL || amxc_htable_is_empty(o));

    if(amxb_pcb_object_to_supported_var_common(pcb_object, var, &data->objects, &obj_var) == 0) {
        if(first) {
            if((data->flags & AMXB_FLAG_PARAMETERS) != 0) {
                amxb_pcb_describe_param_usp(pcb_object, obj_var);
            }
            if((data->flags & AMXB_FLAG_EVENTS) != 0) {
                amxb_pcb_describe_event_usp(pcb_object, obj_var);
            }
            amxb_pcb_describe_func_usp(pcb_object, obj_var);
        }
    }
}

static int amxb_pcb_get_supported_pcb_object(pcb_t* pcb_ctx,
                                             peer_info_t* peer,
                                             amxd_path_t* path,
                                             uint32_t flags,
                                             amxc_var_t* values) {
    int retval = 0;
    char* object = amxd_path_get_supported_path(path);
    request_t* req = NULL;
    supported_path_t* supported_path = NULL;
    uint32_t req_flags = 0;
    amxb_pcb_convert_t fn = amxb_pcb_object_to_supported_var;
    amxc_string_t spath;
    supported_data_t data;


    data.flags = flags;
    amxc_htable_init(&data.objects, 10);
    amxc_string_init(&spath, 0);
    object[strlen(object) - 1] = 0;

    req_flags |= request_getObject_template_info;
    req_flags |= (flags & AMXB_FLAG_FUNCTIONS) != 0 ? request_getObject_functions : 0;
    req_flags |= (flags & AMXB_FLAG_PARAMETERS) != 0  ? request_getObject_parameters : 0;
    req_flags |= (flags & AMXB_FLAG_EVENTS) != 0  ? request_getObject_parameters : 0;
    req_flags |= (flags & AMXB_FLAG_PROTECTED) != 0 ? AMXB_PCB_PROTECTED_ACCESS : 0;

    supported_path = (supported_path_t*) calloc(1, sizeof(supported_path_t));
    amxb_pcb_ipath_to_spath(amxd_path_get(path, 0), &spath);
    supported_path->supported_path = amxc_string_take_buffer(&spath);
    amxc_htable_insert(&data.objects, object, &supported_path->hit);

    req = request_create_getObject(object,
                                   (flags & AMXB_FLAG_FIRST_LVL) != 0 ? 1 : -1,
                                   req_flags |
                                   request_no_object_caching);

    if((flags & AMXB_FLAG_FIRST_LVL) != 0) {
        fn = amxb_pcb_object_to_supported_var_first_lvl;
    }
    retval = amxb_pcb_fetch_object(pcb_ctx,
                                   peer,
                                   req,
                                   values,
                                   fn,
                                   &data);

    request_destroy(req);
    amxc_string_clean(&spath);
    free(object);
    amxc_htable_clean(&data.objects, amxb_pcb_del_sup_path);
    return retval;
}

int amxb_pcb_get_supported(void* const ctx,
                           const char* object,
                           const char* search_path,
                           uint32_t flags,
                           amxc_var_t* values,
                           UNUSED int timeout) {
    int retval = -1;
    pcb_t* pcb_ctx = amxb_pcb_ctx();
    amxb_pcb_t* amxb_pcb = (amxb_pcb_t*) ctx;
    peer_info_t* peer = amxb_pcb->peer;
    amxd_path_t path;
    amxc_var_t* obj_data = NULL;
    char* full_path = NULL;

    amxd_path_init(&path, NULL);
    amxd_path_setf(&path, true, "%s%s", object, search_path == NULL ? "" : search_path);
    if((search_path != NULL) && (*search_path != 0)) {
        amxd_path_setf(&path, false, "%s%s", object, search_path);
    } else {
        amxd_path_setf(&path, true, "%s", object);
    }

    full_path = amxd_path_get_supported_path(&path);

    amxc_var_set_type(values, AMXC_VAR_ID_LIST);
    obj_data = amxc_var_add(amxc_htable_t, values, NULL);
    retval = amxb_pcb_get_supported_pcb_object(pcb_ctx,
                                               peer,
                                               &path,
                                               flags,
                                               obj_data);

    free(full_path);
    amxd_path_clean(&path);
    return retval;
}
