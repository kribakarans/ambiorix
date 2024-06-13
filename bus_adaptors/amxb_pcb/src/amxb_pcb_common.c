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
#include "amxb_pcb_serialize.h"

static void amxb_pcb_reply_objects(amxb_pcb_deferred_t* fcall,
                                   amxd_object_t* object,
                                   amxc_var_t* reply_objects);

static bool amxb_pcb_must_reply_params(const amxc_var_t* const object,
                                       uint32_t req_attrs) {

    if((GET_UINT32(object, "type_id") == amxd_object_template) &&
       ((req_attrs & request_getObject_template_info) == 0)) {
        return false;
    }

    if((req_attrs & request_getObject_parameters) == 0) {
        return false;
    }

    return true;
}

static void amxb_pcb_delete_fcall(amxc_llist_it_t* it) {
    amxb_pcb_deferred_t* fcall = amxc_container_of(it, amxb_pcb_deferred_t, it);
    amxd_function_set_deferred_cb(fcall->call_id, NULL, NULL);
    amxd_function_deferred_remove(fcall->call_id);
    free(fcall);
}

static void amxb_pcb_cancel_deferred(request_t* req, void* priv) {
    amxb_pcb_deferred_t* fcall = (amxb_pcb_deferred_t*) priv;
    amxd_function_set_deferred_cb(fcall->call_id, NULL, NULL);
    amxd_function_deferred_remove(fcall->call_id);
    request_setData(req, NULL);
    amxc_llist_clean(&fcall->calls, amxb_pcb_delete_fcall);
    free(fcall);
}

static void amxb_pcb_amx_call_done(const amxc_var_t* const data,
                                   void* const priv) {
    amxb_pcb_deferred_t* fcall = (amxb_pcb_deferred_t*) priv;
    amxd_status_t status = (amxd_status_t) GET_UINT32(data, "status");
    amxc_var_t* ret = GET_ARG(data, "retval");
    amxd_object_t* object = NULL;

    when_null(fcall, exit);
    when_null(fcall->amxb_pcb, exit);
    object = amxb_pcb_find_object(fcall->amxb_pcb, fcall->req, NULL);

    if(status != amxd_status_ok) {
        if(request_type(fcall->req) == request_type_exec_function) {
            amxb_pcb_exec_return(status, fcall->amxb_pcb->peer, fcall->req, NULL, ret, request_functionName(fcall->req));
        } else {
            amxb_amxd_status_to_pcb_error(status, fcall->amxb_pcb->peer, fcall->req, NULL);
        }
        amxb_pcb_serialize_reply_end(fcall->amxb_pcb->peer, fcall->req);
        amxb_pcb_set_request_done(fcall->amxb_pcb->peer, fcall->req);

        request_setData(fcall->req, NULL);
        request_setDestroyHandler(fcall->req, NULL);

        request_destroy(fcall->req);
        free(fcall);
    } else {
        if(request_type(fcall->req) != request_type_exec_function) {
            amxb_pcb_reply_objects(fcall, object, ret);
            if(request_type(fcall->req) == request_type_delete_instance) {
                free(fcall);
            }
        } else {
            amxb_pcb_exec_return(status, fcall->amxb_pcb->peer, fcall->req, NULL, ret, request_functionName(fcall->req));
            amxb_pcb_serialize_reply_end(fcall->amxb_pcb->peer, fcall->req);
            amxb_pcb_set_request_done(fcall->amxb_pcb->peer, fcall->req);
            request_setData(fcall->req, NULL);
            request_setDestroyHandler(fcall->req, NULL);
            request_destroy(fcall->req);
            free(fcall);
        }
    }

exit:
    return;
}

static void amxb_pcb_reply_object(amxb_pcb_deferred_t* fcall,
                                  amxd_object_t* object,
                                  const char* str_path,
                                  int base_len) {
    amxc_var_t describe_args;
    amxc_var_t object_info;
    amxb_pcb_deferred_t* sub_fcall = NULL;
    amxd_status_t status = amxd_status_ok;
    amxd_dm_access_t access = amxd_dm_access_public;

    amxc_var_init(&describe_args);
    amxc_var_init(&object_info);

    if((request_attributes(fcall->req) & AMXB_PCB_PROTECTED_ACCESS) != 0) {
        access = amxd_dm_access_protected;
    }

    amxc_var_set_type(&describe_args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(bool, &describe_args, "functions", true);
    amxc_var_add_key(bool, &describe_args, "parameters", true);
    amxc_var_add_key(bool, &describe_args, "events", true);
    amxc_var_add_key(bool, &describe_args, "objects", true);
    amxc_var_add_key(bool, &describe_args, "instances", true);
    amxc_var_add_key(uint32_t, &describe_args, "access", access);
    amxc_var_add_key(cstring_t, &describe_args, "rel_path", str_path + base_len);

    sub_fcall = (amxb_pcb_deferred_t*) calloc(1, sizeof(amxb_pcb_deferred_t));
    when_null(sub_fcall, exit);

    sub_fcall->req = fcall->req;
    sub_fcall->amxb_pcb = fcall->amxb_pcb;
    amxc_llist_append(&fcall->calls, &sub_fcall->it);

    status = (amxd_status_t) amxb_pcb_describe_object(sub_fcall, object, &describe_args, &object_info);
    if(status != amxd_status_deferred) {
        free(sub_fcall);
    }

exit:
    amxc_var_clean(&object_info);
    amxc_var_clean(&describe_args);
}

static void amxb_pcb_free_reply_item(UNUSED const char* key, amxc_htable_it_t* it) {
    free(it);
}

static void amxb_pcb_reply_objects(amxb_pcb_deferred_t* fcall,
                                   amxd_object_t* object,
                                   amxc_var_t* reply_objects) {
    amxc_array_t* keys = amxc_htable_get_sorted_keys(amxc_var_constcast(amxc_htable_t, reply_objects));
    char* obj_path = amxd_object_get_path(object, AMXD_OBJECT_TERMINATE);
    int len = obj_path == NULL? 0:strlen(obj_path);

    if(request_type(fcall->req) == request_type_create_instance) {
        const char* str_path = GET_CHAR(reply_objects, "path");
        amxb_pcb_reply_object(fcall, object, str_path, len);
    } else if(request_type(fcall->req) == request_type_delete_instance) {
        amxb_pcb_serialize_reply_end(fcall->amxb_pcb->peer, fcall->req);
        amxb_pcb_set_request_done(fcall->amxb_pcb->peer, fcall->req);
        request_setData(fcall->req, NULL);
        request_setDestroyHandler(fcall->req, NULL);
        request_destroy(fcall->req);
    } else {
        uint32_t attrs = request_attributes(fcall->req);
        amxd_path_t tmpl_obj_path;
        amxc_htable_t templates;
        amxd_path_init(&tmpl_obj_path, NULL);
        amxc_htable_init(&templates, 20);
        for(size_t i = 0; i < amxc_array_size(keys); i++) {
            const char* str_path = (const char*) amxc_array_get_data_at(keys, i);
            if((attrs & request_getObject_template_info) != 0) {
                char* def_path = NULL;
                amxc_htable_it_t* it = NULL;
                amxd_path_setf(&tmpl_obj_path, true, "%s", str_path);
                def_path = amxd_path_get_supported_path(&tmpl_obj_path);
                it = amxc_htable_get(&templates, def_path);
                if(it == NULL) {
                    amxb_pcb_reply_object(fcall, object, def_path, len);
                    it = (amxc_htable_it_t*) calloc(1, sizeof(amxc_htable_it_t));
                    amxc_htable_insert(&templates, def_path, it);
                }
                if(strcmp(def_path, str_path) != 0) {
                    amxb_pcb_reply_object(fcall, object, str_path, len);
                }
                free(def_path);
            } else {
                amxb_pcb_reply_object(fcall, object, str_path, len);
            }
        }
        amxd_path_clean(&tmpl_obj_path);
        amxc_htable_clean(&templates, amxb_pcb_free_reply_item);
    }

    free(obj_path);
    amxc_array_delete(&keys, NULL);
}

static void amxb_pcb_build_regexp_path(amxc_string_t* expr,
                                       amxc_llist_t* path_parts) {
    amxc_llist_for_each(it, path_parts) {
        amxc_string_t* part = amxc_string_from_llist_it(it);
        const char* str_part = amxc_string_get(part, 0);
        if((str_part == NULL) || (*str_part == 0)) {
            continue;
        }
        amxc_string_appendf(expr, "%s\\.", amxc_string_get(part, 0));
    }
}

static void amxb_pcb_build_object_expr(amxc_string_t* expr,
                                       const char* path,
                                       uint32_t depth) {
    amxc_llist_t path_parts;

    amxc_llist_init(&path_parts);
    amxc_string_set_at(expr, 0, path, strlen(path), amxc_string_no_flags);
    amxc_string_split_to_llist(expr, &path_parts, '.');
    amxc_string_reset(expr);

    switch(depth) {
    case UINT32_MAX:
        amxc_string_appendf(expr,
                            "(path starts with \"%s\" || object starts with \"%s\")",
                            path, path);
        break;
    case 0:
        amxc_string_appendf(expr, "(path == \"%s\" || object == \"%s\")", path, path);
        break;
    default:
        amxc_string_appendf(expr, "(path matches \"");
        amxb_pcb_build_regexp_path(expr, &path_parts);
        amxc_string_appendf(expr, "([A-Za-z0-9_\\-]*\\.){0,%d}$\" || object matches \"", depth);
        amxb_pcb_build_regexp_path(expr, &path_parts);
        amxc_string_appendf(expr, "([A-Za-z0-9_\\-]*\\.){0,%d}$\")", depth);
        break;
    }
    amxc_llist_clean(&path_parts, amxc_string_list_it_free);
}

amxd_status_t amxb_pcb_describe_object(amxb_pcb_deferred_t* fcall,
                                       amxd_object_t* object,
                                       amxc_var_t* describe_args,
                                       amxc_var_t* object_info) {
    amxd_status_t status = amxd_status_ok;
    uint32_t req_attrs = request_attributes(fcall->req);
    amxc_var_t* params = NULL;

    status = amxb_pcb_amx_call(fcall,
                               object,
                               "_describe",
                               describe_args,
                               object_info,
                               amxb_pcb_amx_describe_done);

    if(status == amxd_status_ok) {
        amxc_llist_it_take(&fcall->it);
        params = GET_ARG(object_info, "parameters");
        amxb_pcb_serialize_object_begin_v2(fcall->amxb_pcb->peer, fcall->req, object_info);
        if(amxb_pcb_must_reply_params(object_info, req_attrs)) {
            amxc_var_for_each(param, params) {
                llist_t* req_param_list = request_parameterList(fcall->req);
                if(llist_isEmpty(req_param_list) ||
                   request_findParameter(fcall->req, amxc_var_key(param))) {
                    amxb_pcb_serialize_object_param(fcall->amxb_pcb->peer, fcall->req, param);
                }
            }
        }
        amxb_pcb_serialize_object_end(fcall->amxb_pcb->peer, fcall->req);
        peer_flush(fcall->amxb_pcb->peer);
    } else if(status != amxd_status_deferred) {
        amxc_llist_it_take(&fcall->it);
    }

    return status;
}

void amxb_pcb_amx_describe_done(const amxc_var_t* const data,
                                void* const priv) {
    amxb_pcb_deferred_t* fcall = (amxb_pcb_deferred_t*) priv;
    amxb_pcb_deferred_t* main_fcall = amxc_container_of(fcall->it.llist, amxb_pcb_deferred_t, calls);
    amxc_var_t* object_info = GET_ARG(data, "retval");
    amxd_status_t status = (amxd_status_t) GET_UINT32(data, "status");
    amxc_var_t* params = NULL;
    uint32_t req_attrs = request_attributes(fcall->req);

    if(status == 0) {
        params = GET_ARG(object_info, "parameters");
        amxb_pcb_serialize_object_begin_v2(fcall->amxb_pcb->peer, fcall->req, object_info);
        if(amxb_pcb_must_reply_params(object_info, req_attrs)) {
            amxc_var_for_each(param, params) {
                amxb_pcb_serialize_object_param(fcall->amxb_pcb->peer, fcall->req, param);
            }
        }
        amxb_pcb_serialize_object_end(fcall->amxb_pcb->peer, fcall->req);
        peer_flush(fcall->amxb_pcb->peer);
    }

    amxc_llist_it_take(&fcall->it);
    if((main_fcall == NULL) || amxc_llist_is_empty(&main_fcall->calls)) {
        amxb_pcb_serialize_reply_end(fcall->amxb_pcb->peer, fcall->req);
        amxb_pcb_set_request_done(fcall->amxb_pcb->peer, fcall->req);
        request_setData(fcall->req, NULL);
        request_setDestroyHandler(fcall->req, NULL);
        if((main_fcall != NULL) && ((request_attributes(main_fcall->req) & request_notify_all) == 0)) {
            request_destroy(main_fcall->req);
        }
        free(main_fcall);
    }

    free(fcall);
}

amxd_status_t amxb_pcb_amx_call(amxb_pcb_deferred_t* fcall,
                                amxd_object_t* object,
                                const char* func_name,
                                amxc_var_t* args,
                                amxc_var_t* ret,
                                amxp_deferred_fn_t cb) {
    amxd_status_t retval = amxd_status_function_not_found;

    retval = amxd_object_invoke_function(object, func_name, args, ret);

    if(retval == amxd_status_deferred) {
        uint64_t call_id = amxc_var_constcast(uint64_t, ret);
        fcall->call_id = call_id;
        amxd_function_set_deferred_cb(call_id, cb, fcall);
    }

    return retval;
}

void amxb_pcb_error(peer_info_t* peer,
                    request_t* req,
                    uint32_t error,
                    const char* msg) {
    if(msg == NULL) {
        msg = request_path(req);
    }
    amxb_pcb_serialize_error(peer,
                             req,
                             error,
                             error_string(error),
                             msg);
}

amxd_object_t* amxb_pcb_find_object(amxb_pcb_t* amxb_pcb,
                                    request_t* req,
                                    amxc_var_t* rel_path) {
    amxd_object_t* obj = NULL;
    amxd_object_t* root = amxd_dm_get_root(amxb_pcb->dm);
    amxd_path_t obj_path;

    amxd_path_init(&obj_path, NULL);
    when_null(root, exit);

    if((request_attributes(req) & request_common_path_slash_separator) != 0) {
        amxc_string_t path;
        amxc_string_init(&path, 0);
        amxc_string_setf(&path, "%s", request_path(req));
        amxc_string_replace(&path, "/", ".", UINT32_MAX);
        amxc_string_replace(&path, "%", ".", UINT32_MAX);
        amxd_path_setf(&obj_path, true, "%s", amxc_string_get(&path, 0));
        amxc_string_clean(&path);
    } else {
        amxd_path_setf(&obj_path, true, "%s", request_path(req));
    }

    obj = amxd_object_findf(root, "%s", amxd_path_get(&obj_path, AMXD_OBJECT_TERMINATE));
    if(obj == NULL) {
        char* first = amxd_path_get_first(&obj_path, true);
        obj = amxd_object_findf(root, "%s", first);
        amxc_var_set(cstring_t, rel_path, amxd_path_get(&obj_path, AMXD_OBJECT_TERMINATE));
        free(first);
    } else {
        amxc_var_set(cstring_t, rel_path, "");
    }

exit:
    amxd_path_clean(&obj_path);
    return obj;
}

bool amxb_pcb_set_request_done(peer_info_t* peer,
                               request_t* req) {
    bool retval = true;
    if(!peer_flush(peer)) {
        peer_destroy(peer);
        retval = false;
    }
    request_setDone(req);

    return retval;
}

void amxb_pcb_build_get_args(amxc_var_t* args,
                             request_t* req) {
    llist_iterator_t* it = request_firstParameter(req);
    amxc_var_t* parameters = NULL;

    amxc_var_set_type(args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(int32_t, args, "depth", request_depth(req));
    amxc_var_add_key(bool, args, "templates", request_attributes(req) & request_getObject_template_info);

    parameters = amxc_var_add_key(amxc_llist_t, args, "parameters", NULL);
    while(it) {
        const char* param_name = request_parameterName(it);
        amxc_var_add(cstring_t, parameters, param_name);
        it = request_nextParameter(it);
    }
}

void amxb_pcb_build_set_args(amxc_var_t* args,
                             request_t* req) {
    llist_iterator_t* it = request_firstParameter(req);
    amxc_var_t* parameters = NULL;

    amxc_var_set_type(args, AMXC_VAR_ID_HTABLE);
    parameters = amxc_var_add_key(amxc_htable_t, args, "parameters", NULL);
    while(it) {
        const char* param_name = request_parameterName(it);
        variant_t* value = request_parameterValue(it);
        amxc_var_t* param_val = amxc_var_add_new_key(parameters, param_name);
        amxb_pcb_from_pcb_var(value, param_val);
        it = request_nextParameter(it);
    }
}

void amxb_pcb_build_add_instance_args(amxc_var_t* args,
                                      request_t* req) {
    llist_iterator_t* it = request_firstParameter(req);
    amxc_var_t* parameters = NULL;
    uint32_t index = request_instanceIndex(req);
    const char* key = request_instanceKey(req);

    amxc_var_set_type(args, AMXC_VAR_ID_HTABLE);
    parameters = amxc_var_add_key(amxc_htable_t, args, "parameters", NULL);
    amxc_var_add_key(uint32_t, args, "index", index);
    amxc_var_add_key(cstring_t, args, "name", key);
    while(it) {
        const char* param_name = request_parameterName(it);
        variant_t* value = request_parameterValue(it);
        amxc_var_t* param_val = amxc_var_add_new_key(parameters, param_name);
        amxb_pcb_from_pcb_var(value, param_val);
        it = request_nextParameter(it);
    }
}

void amxb_pcb_build_exec_args(amxc_var_t* args,
                              request_t* req,
                              amxc_var_t* func_def) {
    llist_iterator_t* it = request_firstParameter(req);
    amxc_var_t* func_args = NULL;

    amxc_var_set_type(args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, args, "method", request_functionName(req));
    func_args = amxc_var_add_key(amxc_htable_t, args, "args", NULL);
    if(func_def == NULL) {
        while(it) {
            const char* param_name = request_parameterName(it);
            variant_t* value = request_parameterValue(it);
            amxc_var_t* param_val = amxc_var_add_new_key(func_args, param_name);
            amxb_pcb_from_pcb_var(value, param_val);
            it = request_nextParameter(it);
        }
    } else {
        amxc_var_t* arg_defs = GET_ARG(func_def, "arguments");
        amxc_var_for_each(arg_def, arg_defs) {
            const char* param_name = GET_CHAR(arg_def, "name");
            variant_t* value = request_parameterValue(it);
            amxc_var_t* param_val = amxc_var_add_new_key(func_args, param_name);
            amxb_pcb_from_pcb_var(value, param_val);
            it = request_nextParameter(it);
            if(it == NULL) {
                break;
            }
        }
    }
}

bool amxb_pcb_handler_common(peer_info_t* peer,
                             request_t* req,
                             amxc_var_t* args,
                             const char* method) {
    bool retval = false;
    amxd_status_t status = amxd_status_unknown_error;
    amxb_bus_ctx_t* amxb_bus_ctx = amxb_pcb_find_peer(peer);
    amxb_pcb_t* amxb_pcb = NULL;
    amxd_object_t* object = NULL;
    amxc_var_t rv;
    amxc_var_t* rel_path = NULL;
    amxb_pcb_deferred_t* fcall = NULL;

    amxc_var_init(&rv);
    when_null(amxb_bus_ctx, exit);
    amxb_pcb = (amxb_pcb_t*) amxb_bus_ctx->bus_ctx;
    when_null(amxb_pcb, exit);
    rel_path = amxc_var_add_new_key(args, "rel_path");
    object = amxb_pcb_find_object(amxb_pcb, req, rel_path);
    when_null(object, exit);

    fcall = (amxb_pcb_deferred_t*) calloc(1, sizeof(amxb_pcb_deferred_t));
    when_null(fcall, exit);

    fcall->req = req;
    fcall->amxb_pcb = amxb_pcb;
    status = amxb_pcb_amx_call(fcall, object, method, args, &rv, amxb_pcb_amx_call_done);
    if(status == amxd_status_deferred) {
        request_setData(req, fcall);
        request_setDestroyHandler(req, amxb_pcb_cancel_deferred);
        request_setBusy(req);
        retval = true;
    } else {
        retval = status == amxd_status_ok ? true : false;
        if(status == amxd_status_ok) {
            if(request_type(req) != request_type_exec_function) {
                amxb_pcb_reply_objects(fcall, amxd_object_get_root(object), &rv);
            } else {
                amxb_pcb_exec_return(status, peer, req, args, &rv, request_functionName(req));
                request_setData(fcall->req, NULL);
                request_setDestroyHandler(fcall->req, NULL);
            }
        } else {
            if(request_type(req) == request_type_exec_function) {
                amxb_pcb_exec_return(status, peer, req, args, &rv, request_functionName(req));
            }
        }
        free(fcall);
    }

exit:
    amxc_var_clean(&rv);
    if(!retval) {
        amxb_amxd_status_to_pcb_error(status, peer, req, NULL);
    }
    if(status != amxd_status_deferred) {
        amxb_pcb_serialize_reply_end(peer, req);
        retval = amxb_pcb_set_request_done(peer, req);
    }
    return retval;
}

bool amxb_pcb_close_request_handler(peer_info_t* peer,
                                    request_t* req) {
    amxb_bus_ctx_t* amxb_bus_ctx = amxb_pcb_find_peer(peer);
    amxb_pcb_t* amxb_pcb = NULL;
    amxc_llist_it_t* it = NULL;
    amxc_llist_it_t* next = NULL;
    uint32_t req_id = request_closeRequestId(req);
    request_t* preq = pcb_findNotifyRequest(peer, req_id);
    when_null(amxb_bus_ctx, exit);

    amxb_pcb = (amxb_pcb_t*) amxb_bus_ctx->bus_ctx;
    it = amxc_llist_get_first(&amxb_pcb->subscribers);

    if((preq != NULL) && (request_type(preq) == request_type_exec_function)) {
        amxb_pcb_deferred_t* fcall = (amxb_pcb_deferred_t*) request_data(preq);
        if(fcall != NULL) {
            amxd_function_set_deferred_cb(fcall->call_id, NULL, NULL);
            amxd_function_deferred_remove(fcall->call_id);
        }
        request_destroy(preq);
    } else {
        amxc_var_t args;
        amxc_var_init(&args);
        amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);

        while(it) {
            amxb_pcb_sub_t* sub = amxc_llist_it_get_data(it, amxb_pcb_sub_t, lit);
            next = amxc_llist_it_get_next(it);
            if(request_id(sub->sub_req) == req_id) {
                amxc_llist_it_take(it);
                amxb_pcb_handler_common(peer, sub->sub_req, &args, "_unsubscribe");
                request_destroy(sub->sub_req);
                amxp_slot_disconnect_with_priv(&amxb_pcb->dm->sigmngr,
                                               amxb_pcb_send_notification,
                                               sub);
                free(sub);
            }
            it = next;
        }

        amxc_var_clean(&args);
    }

exit:
    return true;
}

int amxb_pcb_handle_subscription(request_t* req,
                                 const char* path,
                                 amxb_pcb_t* amxb_pcb) {
    int retval = -1;
    uint32_t depth = request_depth(req);
    amxc_string_t expression;
    amxb_pcb_sub_t* sub = NULL;
    amxd_path_t p;
    char* part = NULL;

    amxd_path_init(&p, NULL);
    amxc_string_init(&expression, 0);

    if(path == NULL) {
        when_null(request_path(req), exit);
        amxd_path_setf(&p, true, "%s", request_path(req));
    } else {
        amxd_path_setf(&p, true, "%s", path);
    }

    amxb_pcb_build_object_expr(&expression, amxd_path_get(&p, AMXD_OBJECT_TERMINATE), depth);

    if((request_attributes(req) & request_wait) != 0) {
        amxc_string_t wait_expr;
        amxc_string_init(&wait_expr, 0);

        part = amxd_path_get_last(&p, true);
        if((part != NULL) && (*part != 0)) {
            if(part[strlen(part) - 1] == '.') {
                part[strlen(part) - 1] = 0;
            }

            amxb_pcb_build_object_expr(&wait_expr, amxd_path_get(&p, AMXD_OBJECT_TERMINATE), depth);
            amxc_string_appendf(&wait_expr, " && (contains('index', 'name') && (index == '%s' || name == '%s'))", part, part);

            amxc_string_appendf(&expression, " || (%s)", amxc_string_get(&wait_expr, 0));
        }

        amxc_string_clean(&wait_expr);
    }

    sub = (amxb_pcb_sub_t*) calloc(1, sizeof(amxb_pcb_sub_t));
    when_null(sub, exit);
    sub->sub_req = req;
    sub->amxb_pcb = amxb_pcb;
    amxc_llist_append(&amxb_pcb->subscribers, &sub->lit);

    when_failed(amxp_slot_connect_filtered(&amxb_pcb->dm->sigmngr,
                                           ".*",
                                           amxc_string_get(&expression, 0),
                                           amxb_pcb_send_notification,
                                           sub), exit);

    retval = 0;

exit:
    free(part);
    amxd_path_clean(&p);
    amxc_string_clean(&expression);
    return retval;
}

void amxb_amxd_status_to_pcb_error(int status,
                                   peer_info_t* peer,
                                   request_t* req,
                                   const char* info) {
    switch(status) {
    case amxd_status_ok:
        break;
    case amxd_status_function_not_implemented:
        amxb_pcb_error(peer, req, pcb_error_function_not_implemented, info);
        break;
    case amxd_status_invalid_name:
        amxb_pcb_error(peer, req, pcb_error_invalid_name, info);
        break;
    case amxd_status_invalid_function_argument:
        amxb_pcb_error(peer, req, pcb_error_function_argument_missing, info);
        break;
    case amxd_status_invalid_function:
        amxb_pcb_error(peer, req, pcb_error_function_exec_failed, info);
        break;
    case amxd_status_parameter_not_found:
        amxb_pcb_error(peer, req, pcb_error_parameter_not_found, info);
        break;
    case amxd_status_object_not_found:
    case amxd_status_function_not_found:
    case amxd_status_invalid_path:
        amxb_pcb_error(peer, req, pcb_error_not_found, info);
        break;
    case amxd_status_invalid_value:
        amxb_pcb_error(peer, req, pcb_error_invalid_value, info);
        break;
    case amxd_status_unknown_error:
        amxb_pcb_error(peer, req, pcb_error_unknown_system_error, info);
        break;
    case amxd_status_permission_denied:
        amxb_pcb_error(peer, req, EACCES, info);
        break;
    case amxd_status_duplicate:
        amxb_pcb_error(peer, req, pcb_error_duplicate, info);
        break;
    default:
        amxb_pcb_error(peer, req, 0x10000000 | status, info);
        break;
    }
}

int amxb_pcb_error_to_amxd_status(int error) {
    int retval = 0;
    switch(error) {
    case pcb_error_not_found:
        retval = amxd_status_object_not_found;
        break;
    case pcb_error_not_template:
    case pcb_error_not_instance:
    case pcb_error_wrong_object_type:
        retval = amxd_status_invalid_type;
        break;
    case pcb_error_not_unique_name:
        retval = amxd_status_duplicate;
        break;
    case pcb_error_invalid_name:
        retval = amxd_status_invalid_name;
        break;
    case pcb_error_parameter_not_found:
        retval = amxd_status_parameter_not_found;
        break;
    case pcb_error_read_only:
        retval = amxd_status_read_only;
        break;
    case pcb_error_function_not_implemented:
    case pcb_error_function_object_mismatch:
        retval = amxd_status_function_not_implemented;
        break;
    case pcb_error_access_denied:
    case 13 /*EACCESS*/:
        retval = pcb_error_access_denied;
        break;
    case pcb_error_value_empty:
    case pcb_error_value_enum:
    case pcb_error_value_range:
    case pcb_error_string_length:
    case pcb_error_value_minimum:
    case pcb_error_value_maximum:
    case pcb_error_type_mismatch:
        retval = amxd_status_invalid_value;
        break;
    case pcb_error_duplicate:
        retval = amxd_status_duplicate;
        break;
    default:
        retval = amxd_status_unknown_error;
        break;
    }

    return retval;
}

void amxb_pcb_exec_return(amxd_status_t status,
                          peer_info_t* peer,
                          request_t* req,
                          amxc_var_t* args,
                          amxc_var_t* ret,
                          const char* func_name) {
    amxb_pcb_serialize_ret_val(peer, req, ret);
    amxb_pcb_serialize_out_args(peer, req, args);
    amxb_amxd_status_to_pcb_error(status, peer, req, func_name);
}

static void amxb_pcb_fetch_function_done(UNUSED const amxc_var_t* const data,
                                         UNUSED void* const priv) {
    amxb_pcb_deferred_t* fcall = (amxb_pcb_deferred_t*) priv;
    amxc_var_t* rv = GET_ARG(data, "retval");
    amxc_var_t args;
    amxd_status_t status = (amxd_status_t) GET_UINT32(data, "status");

    amxc_var_init(&args);

    if(status == 0) {
        amxc_var_t* func_def = GET_ARG(rv, "functions");
        func_def = GET_ARG(func_def, request_functionName(fcall->req));
        amxb_pcb_build_exec_args(&args, fcall->req, func_def);
        amxb_pcb_handler_common(fcall->amxb_pcb->peer, fcall->req, &args, "_exec");
    } else {
        amxb_amxd_status_to_pcb_error(amxd_status_function_not_found, fcall->amxb_pcb->peer, fcall->req, request_functionName(fcall->req));
        amxb_pcb_serialize_reply_end(fcall->amxb_pcb->peer, fcall->req);
        amxb_pcb_set_request_done(fcall->amxb_pcb->peer, fcall->req);

        request_setData(fcall->req, NULL);
        request_setDestroyHandler(fcall->req, NULL);

        request_destroy(fcall->req);
    }

    amxc_llist_it_take(&fcall->it);
    amxc_var_clean(&args);
    free(fcall);
}

bool amxb_pcb_fetch_function_def(peer_info_t* peer,
                                 request_t* req) {
    amxb_bus_ctx_t* amxb_bus_ctx = amxb_pcb_find_peer(peer);
    amxb_pcb_t* amxb_pcb = NULL;
    amxd_object_t* object = NULL;
    amxc_var_t args;
    amxc_var_t rv;
    int status = -1;
    bool retval = true;
    amxc_var_t* rel_path = NULL;
    amxb_pcb_deferred_t* fcall = NULL;
    amxd_dm_access_t access = amxd_dm_access_public;

    amxc_var_init(&args);
    amxc_var_init(&rv);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    when_null(amxb_bus_ctx, exit);
    amxb_pcb = (amxb_pcb_t*) amxb_bus_ctx->bus_ctx;
    when_null(amxb_pcb, exit);
    rel_path = amxc_var_add_new_key(&args, "rel_path");
    object = amxb_pcb_find_object(amxb_pcb, req, rel_path);
    when_null(object, exit);

    fcall = (amxb_pcb_deferred_t*) calloc(1, sizeof(amxb_pcb_deferred_t));
    when_null(fcall, exit);

    if((request_attributes(req) & AMXB_PCB_PROTECTED_ACCESS) != 0) {
        access = amxd_dm_access_protected;
    }

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(bool, &args, "functions", true);
    amxc_var_add_key(bool, &args, "parameters", false);
    amxc_var_add_key(bool, &args, "events", false);
    amxc_var_add_key(bool, &args, "objects", false);
    amxc_var_add_key(bool, &args, "instances", false);
    amxc_var_add_key(uint32_t, &args, "access", access);

    fcall->req = req;
    fcall->amxb_pcb = amxb_pcb;
    status = amxb_pcb_amx_call(fcall, object, "_describe", &args, &rv, amxb_pcb_fetch_function_done);
    if(status == amxd_status_deferred) {
        request_setData(req, fcall);
        request_setDestroyHandler(req, amxb_pcb_cancel_deferred);
        request_setBusy(req);
        retval = true;
    } else {
        retval = status == amxd_status_ok ? true : false;
        if(status == amxd_status_ok) {
            amxc_var_t* func_def = GET_ARG(&rv, "functions");
            func_def = GET_ARG(func_def, request_functionName(req));
            amxb_pcb_build_exec_args(&args, req, func_def);
            retval = amxb_pcb_handler_common(peer, req, &args, "_exec");
        }
        free(fcall);
    }

exit:
    if(!retval) {
        amxb_amxd_status_to_pcb_error(status, amxb_pcb->peer, req, NULL);
    }
    amxc_var_clean(&rv);
    amxc_var_clean(&args);
    return retval;
}
