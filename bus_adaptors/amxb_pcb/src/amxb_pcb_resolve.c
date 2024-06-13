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


#define RESOLVE_CONTINUE 1
#define RESOLVE_ADD      2
#define RESOLVE_DROP     3
#define RESOLVE_ERROR    4

typedef struct _resolve_data {
    int32_t requested_depth;
    uint32_t flags;
    char* current_path;
    uint32_t current_path_len;
    uint32_t pcb_flags;
    uint32_t action;
    amxc_var_t* objects;
    amxd_path_t* path;
    int32_t base_depth;
    int32_t request_path_depth;
    const char* param;
    bool is_supported;
    bool is_multi_path;
    amxp_expr_t* filter;
} resolve_data_t;

static void amxb_pcb_object_describe_param(object_t* pcb_object,
                                           parameter_t* pcb_param,
                                           amxc_var_t* var_param);

static int32_t amxb_pcb_object_depth(const char* path) {
    uint32_t length = path == NULL ? 0 : strlen(path);
    int32_t depth = 0;
    for(uint32_t i = 0; i < length; i++) {
        if(path[i] == '.') {
            depth++;
        }
    }

    return depth;
}

static int32_t amxb_pcb_rel_object_depth(amxc_var_t* parts) {
    int32_t depth = 0;
    amxc_var_for_each(part, parts) {
        const char* txt = amxc_var_constcast(cstring_t, part);
        if((txt[0] == '*') || (txt[0] == '[')) {
            continue;
        }
        depth++;
    }

    return depth;
}

static amxc_var_t* amxb_pcb_object_add(object_t* pcb_object,
                                       amxc_var_t* var,
                                       UNUSED uint32_t pcb_flags,
                                       const char* param_name,
                                       amxp_expr_t* expr,
                                       uint32_t flags) {
    parameter_t* param = NULL;
    amxc_var_t* obj_var = NULL;
    uint32_t attrs = object_attributes(pcb_object);
    char* path = object_pathChar(pcb_object, path_attr_default);
    amxc_var_t* var_attrs = NULL;
    amxc_string_t str_path;

    amxc_string_init(&str_path, 0);
    amxc_string_push_buffer(&str_path, path, strlen(path) + 1);
    amxc_string_append(&str_path, ".", 1);

    if((flags & RESOLV_NO_OBJ_PATH) == 0) {
        if((flags & RESOLV_LIST) != 0) {
            obj_var = amxc_var_add_key(bool, var, amxc_string_get(&str_path, 0), true);
            goto exit;
        } else {
            obj_var = amxc_var_add_key(amxc_htable_t, var, amxc_string_get(&str_path, 0), NULL);
        }
    } else {
        obj_var = var;
    }

    var_attrs = amxc_var_add_key(amxc_htable_t, obj_var, "%attributes", NULL);

    amxc_var_add_key(bool, var_attrs, "private", false);
    amxc_var_add_key(bool, var_attrs, "read-only", (attrs & object_attr_read_only) != 0);
    amxc_var_add_key(bool, var_attrs, "locked", false);
    amxc_var_add_key(bool, var_attrs, "protected", false);
    amxc_var_add_key(bool, var_attrs, "persistent", (attrs & object_attr_persistent) != 0);

    if(object_isInstance(pcb_object)) {
        amxc_var_add_key(uint32_t, obj_var, "%type_id", amxd_object_instance);
    } else if(object_isTemplate(pcb_object)) {
        amxc_var_add_key(uint32_t, obj_var, "%type_id", amxd_object_template);
    } else {
        amxc_var_add_key(uint32_t, obj_var, "%type_id", amxd_object_singleton);
    }
    if((flags & (RESOLV_PARAMETERS | RESOLV_KEY_PARAMETERS)) != 0) {
        amxc_var_t meta_data;
        amxc_var_init(&meta_data);
        object_for_each_parameter(param, pcb_object) {
            const char* obj_param_name = parameter_name(param);
            const variant_t* param_value = parameter_getValue(param);
            uint32_t a = parameter_attributes(param);
            if(((flags & RESOLV_PARAMETERS) != 0) ||
               (((flags & RESOLV_KEY_PARAMETERS) != 0) && ((a & parameter_attr_key) != 0))) {
                if(!param_name || (strcmp(param_name, obj_param_name) == 0)) {
                    amxc_var_t* var_item = NULL;
                    if(expr != NULL) {
                        amxc_var_set_type(&meta_data, AMXC_VAR_ID_HTABLE);
                        amxb_pcb_object_describe_param(pcb_object, param, &meta_data);
                        if(!amxp_expr_eval_var(expr, &meta_data, NULL)) {
                            continue;
                        }
                    }
                    var_item = amxc_var_add_new_key(obj_var, obj_param_name);
                    amxb_pcb_from_pcb_var(param_value, var_item);
                }
            }
        }
        amxc_var_clean(&meta_data);
        if(param_name != NULL) {
            if(GETP_ARG(obj_var, param_name) == NULL) {
                amxc_var_delete(&obj_var);
            }
        }
    }

    if(((flags & RESOLV_SUB_OBJECTS) != 0) && object_hasChildren(pcb_object)) {
        object_t* pcb_child = NULL;
        object_for_each_child(pcb_child, pcb_object) {
            amxc_var_t* sub = amxc_var_add_key(amxc_htable_t, obj_var, object_name(pcb_child, 0), NULL);
            amxb_pcb_object_add(pcb_child, sub, pcb_flags, param_name, expr, flags | RESOLV_NO_OBJ_PATH);
        }
    }

exit:
    amxc_string_clean(&str_path);
    return obj_var;
}

static int amxc_pcb_func_type_to_var_type(int func_type) {
    if(func_type > 9) {
        switch(func_type) {
        case function_type_double:
            func_type = AMXC_VAR_ID_DOUBLE;
            break;
        case function_type_bool:
            func_type = AMXC_VAR_ID_BOOL;
            break;
        case function_type_list:
            func_type = AMXC_VAR_ID_LIST;
            break;
        case function_type_variant:
            func_type = AMXC_VAR_ID_ANY;
            break;
        case function_type_file_descriptor:
            func_type = AMXC_VAR_ID_FD;
            break;
        case function_type_date_time:
            func_type = AMXC_VAR_ID_TIMESTAMP;
            break;
        default:
            func_type = AMXC_VAR_ID_ANY;
            break;
        }
    }

    return func_type;
}

static void amxb_pcb_object_describe_param(object_t* pcb_object,
                                           parameter_t* pcb_param,
                                           amxc_var_t* var_param) {
    amxc_var_t* value = amxc_var_add_new_key(var_param, "value");
    amxc_var_t* var_attrs = amxc_var_add_key(amxc_htable_t, var_param, "attributes", NULL);
    uint32_t type_id = AMXC_VAR_ID_NULL;
    uint32_t attrs = parameter_attributes(pcb_param);
    const char* param_name = parameter_name(pcb_param);

    amxb_pcb_from_pcb_var(parameter_getValue(pcb_param), value);
    type_id = amxc_var_type_of(value);
    amxc_var_add_key(bool, var_attrs, "private", false);
    amxc_var_add_key(bool, var_attrs, "read-only", (attrs & parameter_attr_read_only) != 0);
    amxc_var_add_key(bool, var_attrs, "locked", false);
    amxc_var_add_key(bool, var_attrs, "protected", false);
    amxc_var_add_key(bool, var_attrs, "key", (attrs & parameter_attr_key) != 0);
    amxc_var_add_key(bool, var_attrs, "counter", false);
    amxc_var_add_key(bool, var_attrs, "persistent", (attrs & parameter_attr_persistent) != 0);
    amxc_var_add_key(bool, var_attrs, "instance", (object_isInstance(pcb_object) || object_isTemplate(pcb_object)) &&
                     (attrs & parameter_attr_template_only) == 0);
    amxc_var_add_key(bool, var_attrs, "volatile", (attrs & (parameter_attr_volatile | parameter_attr_volatile_handler)) != 0);
    amxc_var_add_key(bool, var_attrs, "template", (attrs & parameter_attr_template_only) != 0);
    amxc_var_add_key(cstring_t, var_param, "name", param_name);
    amxc_var_add_key(cstring_t, var_param, "type_name", amxc_var_get_type_name_from_id(type_id));
    amxc_var_add_key(uint32_t, var_param, "type_id", type_id);
}

static void amxb_pcb_object_describe_params(object_t* pcb_object,
                                            amxc_var_t* params) {
    parameter_t* pcb_param = NULL;

    object_for_each_parameter(pcb_param, pcb_object) {
        const char* param_name = parameter_name(pcb_param);
        amxc_var_t* var_param = amxc_var_add_key(amxc_htable_t, params, param_name, NULL);
        amxb_pcb_object_describe_param(pcb_object, pcb_param, var_param);
    }
}

static void amxb_pcb_object_describe_funcs(object_t* pcb_object,
                                           amxc_var_t* funcs) {
    function_t* func = NULL;

    object_for_each_function(func, pcb_object) {
        function_argument_t* arg = NULL;
        amxc_var_t* var_args = NULL;
        const char* name = function_name(func);
        uint32_t ftype = amxc_pcb_func_type_to_var_type(function_type(func));
        uint32_t attrs = function_attributes(func);
        amxc_var_t* var_func_attrs = NULL;
        amxc_var_t* var_func = amxc_var_add_key(amxc_htable_t,
                                                funcs,
                                                name,
                                                NULL);
        amxc_var_add_key(cstring_t, var_func, "name", name);
        amxc_var_add_key(cstring_t, var_func, "type_name", amxc_var_get_type_name_from_id(ftype));
        amxc_var_add_key(uint32_t, var_func, "type_id", ftype);
        var_func_attrs = amxc_var_add_key(amxc_htable_t, var_func, "attributes", NULL);
        amxc_var_add_key(bool, var_func_attrs, "instance", (object_isInstance(pcb_object) ||
                                                            object_isTemplate(pcb_object)) &&
                         (attrs & function_attr_template_only) == 0);
        amxc_var_add_key(bool, var_func_attrs, "template", (attrs & function_attr_template_only) != 0);
        amxc_var_add_key(bool, var_func_attrs, "asynchronous", (attrs & function_attr_async) != 0);
        amxc_var_add_key(bool, var_func_attrs, "private", false);
        amxc_var_add_key(bool, var_func_attrs, "protected", false);

        var_args = amxc_var_add_key(amxc_llist_t, var_func, "arguments", NULL);
        for(arg = function_firstArgument(func); arg; arg = function_nextArgument(arg)) {
            argument_attribute_t arg_attrs = argument_attributes(arg);
            const char* arg_name = argument_name(arg);
            amxc_var_t* var_arg = amxc_var_add(amxc_htable_t, var_args, NULL);
            amxc_var_t* var_arg_attrs = amxc_var_add_key(amxc_htable_t, var_arg, "attributes", NULL);
            uint32_t atype = amxb_var_type_from_pcb_arg_type(argument_type(arg));
            if((arg_attrs & (argument_attr_in | argument_attr_out)) == 0) {
                amxc_var_add_key(bool, var_arg_attrs, "in", (arg_attrs & argument_attr_in) != 0);
            } else {
                amxc_var_add_key(bool, var_arg_attrs, "in", (arg_attrs & argument_attr_in) != 0);
                amxc_var_add_key(bool, var_arg_attrs, "out", (arg_attrs & argument_attr_out) != 0);
            }
            amxc_var_add_key(bool, var_arg_attrs, "mandatory", (arg_attrs & argument_attr_mandatory) != 0);
            amxc_var_add_key(bool, var_arg_attrs, "strict", false);
            amxc_var_add_key(cstring_t, var_arg, "name", arg_name);
            amxc_var_add_key(cstring_t, var_arg, "type_name", amxc_var_get_type_name_from_id(atype));
            amxc_var_add_key(uint32_t, var_arg, "type_id", atype);
        }
    }
}

static void amxb_pcb_object_to_describe_var(object_t* pcb_object,
                                            amxc_var_t* var,
                                            uint32_t pcb_flags,
                                            bool parameters,
                                            bool functions,
                                            bool objects,
                                            bool instances) {
    char* object_ipath = object_pathChar(pcb_object, path_attr_default);
    char* object_kpath = object_pathChar(pcb_object, path_attr_key_notation);
    uint32_t attrs = object_attributes(pcb_object);
    amxc_var_t* var_attrs = NULL;
    amxc_string_t str_path;
    amxc_string_init(&str_path, 0);

    when_str_empty(object_ipath, exit);

    if(object_isInstance(pcb_object)) {
        free(object_ipath);
        free(object_kpath);
        object_ipath = object_pathChar(pcb_object, path_attr_default | path_attr_parent);
        object_kpath = object_pathChar(pcb_object, path_attr_key_notation | path_attr_parent);
    }
    amxc_string_push_buffer(&str_path, object_ipath, strlen(object_ipath) + 1);
    amxc_string_append(&str_path, ".", 1);
    object_ipath = amxc_string_take_buffer(&str_path);
    amxc_string_push_buffer(&str_path, object_kpath, strlen(object_kpath) + 1);
    amxc_string_append(&str_path, ".", 1);
    object_kpath = amxc_string_take_buffer(&str_path);

    amxc_var_add_key(cstring_t, var, "path", object_ipath);
    amxc_var_add_key(cstring_t, var, "object", object_kpath);
    amxc_var_add_key(cstring_t, var, "name", object_name(pcb_object, path_attr_key_notation));
    if(object_isInstance(pcb_object)) {
        amxc_var_add_key(uint32_t, var, "index", atol(object_name(pcb_object, path_attr_default)));
        amxc_var_add_key(cstring_t, var, "type_name", "instance");
        amxc_var_add_key(uint32_t, var, "type_id", amxd_object_instance);
    } else if(object_isTemplate(pcb_object)) {
        amxc_var_add_key(cstring_t, var, "type_name", "template");
        amxc_var_add_key(uint32_t, var, "type_id", amxd_object_template);
    } else {
        amxc_var_add_key(cstring_t, var, "type_name", "singleton");
        amxc_var_add_key(uint32_t, var, "type_id", amxd_object_singleton);
    }
    var_attrs = amxc_var_add_key(amxc_htable_t, var, "attributes", NULL);
    amxc_var_add_key(bool, var_attrs, "private", false);
    amxc_var_add_key(bool, var_attrs, "read-only", (attrs & object_attr_read_only) != 0);
    amxc_var_add_key(bool, var_attrs, "locked", false);
    amxc_var_add_key(bool, var_attrs, "protected", false);
    amxc_var_add_key(bool, var_attrs, "persistent", (attrs & object_attr_persistent) != 0);

    if(parameters) {
        amxc_var_t* var_params = amxc_var_add_key(amxc_htable_t, var, "parameters", NULL);
        amxb_pcb_object_describe_params(pcb_object, var_params);
    }

    if(functions) {
        amxc_var_t* var_params = amxc_var_add_key(amxc_htable_t, var, "functions", NULL);
        amxb_pcb_object_describe_funcs(pcb_object, var_params);
    }

    if(objects && !object_isTemplate(pcb_object)) {
        object_t* child = NULL;
        amxc_var_t* objs = amxc_var_add_key(amxc_llist_t, var, "objects", NULL);
        object_for_each_child(child, pcb_object) {
            amxc_var_add(cstring_t, objs, object_name(child, path_attr_key_notation));
        }
        if((objs != NULL) && amxc_llist_is_empty(&objs->data.vl)) {
            amxc_var_delete(&objs);
        }
    }

    if(instances && object_isTemplate(pcb_object)) {
        object_t* instance = NULL;
        amxc_var_t* objs = amxc_var_add_key(amxc_llist_t, var, "instances", NULL);
        object_for_each_instance(instance, pcb_object) {
            amxc_var_add(cstring_t, objs, object_name(instance, pcb_flags));
        }
        if((objs != NULL) && amxc_llist_is_empty(&objs->data.vl)) {
            amxc_var_delete(&objs);
        }
    }

exit:
    amxc_string_clean(&str_path);
    free(object_ipath);
    free(object_kpath);
    return;
}

static void amxb_pcb_set_drop(resolve_data_t* data,
                              char** path) {
    data->action = RESOLVE_DROP;
    free(data->current_path);
    data->current_path = *path;
    data->current_path_len = strlen(*path);
    *path = NULL;
}

static bool amxb_pcb_verify_expr(amxc_var_t* obj_var,
                                 char** path,
                                 const char* expression,
                                 resolve_data_t* data,
                                 int32_t depth) {
    bool retval = false;
    amxp_expr_t expr;
    amxp_expr_init(&expr, expression);
    retval = amxp_expr_eval_var(&expr, obj_var, NULL);
    if(!retval) {
        amxb_pcb_set_drop(data, path);
    } else if(depth < data->request_path_depth) {
        retval = false;
    }

    amxc_var_delete(&obj_var);
    amxp_expr_clean(&expr);
    return retval;
}

static void amxb_pcb_set_action(object_t* pcb_object,
                                char** path,
                                resolve_data_t* data,
                                int32_t depth) {
    const char* part = GETI_CHAR(&data->path->parts, depth - data->base_depth);
    const char* name = object_name(pcb_object, data->pcb_flags);
    amxc_var_t* var = data->objects;

    data->is_multi_path = false;

    if(part != NULL) {
        if(object_isInstance(pcb_object)) {
            switch(part[0]) {
            case '[': {
                amxc_var_t* obj_var = amxb_pcb_object_add(pcb_object, var, data->pcb_flags,
                                                          NULL, data->filter,
                                                          RESOLV_PARAMETERS | RESOLV_SUB_OBJECTS);
                if(amxb_pcb_verify_expr(obj_var, path, part + 1, data, depth)) {
                    if((data->flags & RESOLV_DESCRIBE) == 0) {
                        amxb_pcb_object_add(pcb_object, var, data->pcb_flags,
                                            data->param, data->filter, data->flags);
                    } else {
                        bool parameters = ((data->flags & (RESOLV_PARAMETERS | RESOLV_KEY_PARAMETERS)) != 0);
                        bool functions = ((data->flags & RESOLV_FUNCTIONS) != 0);
                        bool objects = ((data->flags & RESOLV_OBJECTS) != 0);
                        bool instances = ((data->flags & RESOLV_INSTANCES) != 0);
                        amxb_pcb_object_to_describe_var(pcb_object, var, data->pcb_flags,
                                                        parameters, functions,
                                                        objects, instances);
                    }
                }
                goto exit;
            }
            break;
            case '.':
            case '*':
                break;
            default:
                if(strcmp(name, part) != 0) {
                    amxb_pcb_set_drop(data, path);
                    goto exit;
                }
                break;
            }
        } else {
            if(object_isTemplate(pcb_object)) {
                data->is_supported = true;
            } else {
                data->is_supported = false;
            }
            if((part[0] == '*') || (part[0] == '[')) {
                if(object_isTemplate(pcb_object) &&
                   ((data->flags & RESOLV_DESCRIBE) != 0)) {
                    data->action = RESOLVE_CONTINUE;
                } else {
                    data->action = RESOLVE_ERROR;
                    goto exit;
                }
            }
            if((part[0] != '.') && (strcmp(name, part) != 0)) {
                amxb_pcb_set_drop(data, path);
                goto exit;
            }
        }
    }
    if(depth == data->request_path_depth) {
        if((data->action == RESOLVE_CONTINUE) || ( data->action == RESOLVE_ADD)) {
            data->action = RESOLVE_ADD;
            if(object_isTemplate(pcb_object) && ((data->flags & RESOLV_TEMPLATES) == 0)) {
                data->is_multi_path = true;
                goto exit;
            }
            if((data->flags & RESOLV_DESCRIBE) == 0) {
                amxb_pcb_object_add(pcb_object, var, data->pcb_flags, data->param, data->filter, data->flags);
            } else {
                bool parameters = ((data->flags & (RESOLV_PARAMETERS | RESOLV_KEY_PARAMETERS)) != 0);
                bool functions = ((data->flags & RESOLV_FUNCTIONS) != 0);
                bool objects = ((data->flags & RESOLV_OBJECTS) != 0);
                bool instances = ((data->flags & RESOLV_INSTANCES) != 0);
                amxb_pcb_object_to_describe_var(pcb_object, var, data->pcb_flags,
                                                parameters, functions,
                                                objects, instances);
            }
        }
    } else {
        if(data->action == RESOLVE_ADD) {
            data->action = RESOLVE_CONTINUE;
        }
    }

exit:
    return;
}

static void amxb_pcb_object_filter(object_t* pcb_object,
                                   amxc_var_t* var,
                                   void* priv) {
    resolve_data_t* data = (resolve_data_t*) priv;
    char* path = object_pathChar(pcb_object, path_attr_default);
    int32_t depth = amxb_pcb_object_depth(path) + 1;
    amxd_path_t normalized_path;

    amxd_path_init(&normalized_path, NULL);
    amxd_path_setf(&normalized_path, true, "%s", path);
    free(path);
    path = amxc_string_take_buffer(&normalized_path.path);

    if(data->action == RESOLVE_ERROR) {
        goto exit;
    }

    if((data->flags & RESOLV_NO_SINGLETON) == RESOLV_NO_SINGLETON) {
        if(object_isTemplate(pcb_object)) {
            goto exit;
        }
        if(!object_isInstance(pcb_object)) {
            const amxc_htable_t* objs = amxc_var_constcast(amxc_htable_t, var);
            if(amxc_htable_is_empty(objs)) {
                data->action = RESOLVE_ERROR;
                goto exit;
            }
            goto exit;
        }
    }

    if(data->current_path &&
       ( strncmp(data->current_path, path, data->current_path_len) != 0)) {
        data->action = RESOLVE_CONTINUE;
        free(data->current_path);
        data->current_path = NULL;
        data->current_path_len = 0;
    }

    if(data->action == RESOLVE_DROP) {
        goto exit;
    }

    if(depth > data->request_path_depth) {
        if(((data->flags & RESOLV_EXACT_DEPTH) != 0) &&
           ( depth > (data->request_path_depth + data->requested_depth))) {
            goto exit;
        }
        if(object_isTemplate(pcb_object) && ((data->flags & RESOLV_TEMPLATES) == 0)) {
            goto exit;
        }
        if((data->flags & RESOLV_DESCRIBE) == 0) {
            amxb_pcb_object_add(pcb_object, var, data->pcb_flags, data->param, data->filter, data->flags);
        } else {
            bool parameters = ((data->flags & (RESOLV_PARAMETERS | RESOLV_KEY_PARAMETERS)) != 0);
            bool functions = ((data->flags & RESOLV_FUNCTIONS) != 0);
            bool objects = ((data->flags & RESOLV_OBJECTS) != 0);
            bool instances = ((data->flags & RESOLV_INSTANCES) != 0);
            amxb_pcb_object_to_describe_var(pcb_object, var, data->pcb_flags,
                                            parameters, functions,
                                            objects, instances);
        }
    } else {
        amxb_pcb_set_action(pcb_object, &path, data, depth);
    }

exit:
    amxd_path_clean(&normalized_path);
    free(path);
    return;
}

static void amxb_pcb_clean_path_parts(amxc_var_t* parts) {
    amxc_var_for_each(part, parts) {
        uint32_t len = strlen(part->data.s);
        if((len == 1) && (part->data.s[0] == '.')) {
            amxc_var_delete(&part);
            continue;
        }
        if(part->data.s[0] == '[') {
            part->data.s[len - 1] = 0;
        }
        if(part->data.s[len - 1] == '.') {
            part->data.s[len - 1] = 0;
        }
    }

    if(!amxc_llist_is_empty(&parts->data.vl)) {
        amxc_var_t* start = NULL;
        amxc_var_new(&start);
        amxc_var_set(cstring_t, start, ".");
        amxc_var_set_index(parts, 0, start, AMXC_VAR_FLAG_DEFAULT);
    }
}

static int amxb_pcb_collect_objects(amxb_pcb_t* pcb_ctx,
                                    amxd_path_t* path,
                                    resolve_data_t* data) {
    int retval = 0;
    pcb_t* pcb = amxb_pcb_ctx();
    peer_info_t* peer = pcb_ctx->peer;
    request_t* req = NULL;
    char* fixed_path = amxd_path_get_fixed_part(path, true);
    uint32_t depth = 0;
    const char* param = amxd_path_get_param(path);
    uint32_t req_flags = 0;

    if((data->requested_depth == INT32_MAX) || (data->requested_depth == -1)) {
        depth = UINT32_MAX;
    } else {
        depth = amxb_pcb_rel_object_depth(&path->parts) + data->requested_depth;
    }

    when_str_empty(fixed_path, exit);
    fixed_path[strlen(fixed_path) - 1] = 0;

    amxb_pcb_clean_path_parts(&path->parts);
    if(amxc_llist_is_empty(&path->parts.data.vl)) {
        data->action = RESOLVE_ADD;
    }

    data->current_path = NULL;
    data->current_path_len = 0;
    data->pcb_flags = req_flags;
    data->base_depth = amxb_pcb_object_depth(fixed_path) + 1;
    data->param = param;

    if(param != NULL) {
        data->requested_depth = 0;
        depth = amxc_llist_size(&path->parts.data.vl);
        if(depth > 0) {
            depth--;
        }
    }

    req_flags |= (data->flags & (RESOLV_PARAMETERS | RESOLV_KEY_PARAMETERS)) != 0 ? request_getObject_parameters : 0;
    req_flags |= (data->flags & RESOLV_FUNCTIONS) != 0 ? request_getObject_functions : 0;
    req_flags |= (data->flags & RESOLV_OBJECTS) != 0 ? request_getObject_children : 0;
    req_flags |= (data->flags & RESOLV_INSTANCES) != 0 ? request_getObject_instances : 0;
    req_flags |= (data->flags & RESOLV_DESCRIBE) != 0? request_getObject_template_info:0;
    if(data->flags & RESOLV_DESCRIBE) {
        req_flags |= request_getObject_instances;
        depth++;
    }

    req = request_create_getObject(fixed_path, depth,
                                   req_flags |
                                   request_no_object_caching);

    retval = amxb_pcb_fetch_object(pcb, peer, req, data->objects,
                                   amxb_pcb_object_filter, data);
    amxb_pcb_request_destroy(req);

    if(retval == amxd_status_object_not_found) {
        req_flags |= request_common_path_key_notation;
        data->pcb_flags |= request_common_path_key_notation;
        req = request_create_getObject(fixed_path, depth,
                                       req_flags |
                                       request_no_object_caching);

        retval = amxb_pcb_fetch_object(pcb, peer, req, data->objects,
                                       amxb_pcb_object_filter, data);
        amxb_pcb_request_destroy(req);
    }

    if(data->action == RESOLVE_ERROR) {
        amxc_var_clean(data->objects);
    }
    free(data->current_path);

exit:
    free(fixed_path);
    return retval;
}

int amxb_pcb_resolve(amxb_pcb_t* pcb_ctx,
                     const char* object_path,
                     const char* rel_path,
                     const char* filter,
                     int32_t depth,
                     uint32_t flags,
                     bool* key_path,
                     amxc_var_t* resolved_objects) {
    int retval = amxd_status_unknown_error;
    amxd_path_t full_path;
    peer_info_t* peer = pcb_ctx->peer;
    char* fixed_path = NULL;
    pcb_t* pcb = amxb_pcb_ctx();
    resolve_data_t data;

    amxd_path_init(&full_path, NULL);
    if((rel_path != NULL) && (*rel_path != 0)) {
        amxd_path_setf(&full_path, false, "%s%s", object_path, rel_path);
    } else {
        amxd_path_setf(&full_path, true, "%s", object_path);
    }

    data.requested_depth = depth;
    data.flags = flags;
    data.current_path = NULL;
    data.action = RESOLVE_CONTINUE;
    data.objects = resolved_objects;
    data.path = &full_path;
    data.request_path_depth = 0;
    data.pcb_flags = 0;
    data.is_supported = false;
    data.is_multi_path = false;
    data.filter = NULL;
    amxc_var_for_each(part, (&full_path.parts)) {
        const char* p = amxc_var_constcast(cstring_t, part);
        if((p != NULL) && (p[0] != '.')) {
            data.request_path_depth++;
        }
    }

    if((flags & RESOLV_NO_AMX_CHECK) == 0) {
        fixed_path = amxd_path_get_first(&full_path, false);
        if(amxb_pcb_remote_is_amx(pcb, peer, fixed_path, &retval)) {
            retval = -1; // is amx
            goto exit;
        }
    }

    if((filter != NULL) && (*filter != 0)) {
        amxp_expr_new(&data.filter, filter);
    }
    amxb_pcb_collect_objects(pcb_ctx, &full_path, &data);
    amxp_expr_delete(&data.filter);
    if(amxc_htable_is_empty(amxc_var_constcast(amxc_htable_t, resolved_objects))) {
        if(data.is_multi_path) {
            *key_path = ((data.pcb_flags & request_common_path_key_notation) != 0);
            retval = amxd_status_ok;
            goto exit;
        }
        if((amxd_path_is_search_path(&full_path) && !data.is_supported) ||
           (!amxd_path_is_search_path(&full_path))) {
            retval = amxd_status_object_not_found;
            goto exit;
        }
    }
    *key_path = ((data.pcb_flags & request_common_path_key_notation) != 0);
    retval = amxd_status_ok;

exit:
    free(fixed_path);
    amxd_path_clean(&full_path);
    return retval;
}