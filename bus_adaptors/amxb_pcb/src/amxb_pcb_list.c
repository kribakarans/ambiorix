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


static bool amxb_pcb_list_done(request_t* req,
                               pcb_t* pcb,
                               peer_info_t* from,
                               void* userdata);

static int amxb_pcb_call_list(void* const ctx,
                              const char* object,
                              uint32_t flags,
                              uint32_t access,
                              amxc_var_t* ret,
                              int timeout) {
    int retval = -1;
    amxc_var_t args;
    amxb_request_t* request = NULL;
    amxd_path_t path;
    char* first_lvl = NULL;
    const char* rel_path = NULL;
    size_t first_lvl_len = 0;

    amxc_var_init(&args);
    when_failed(amxb_request_new(&request), exit);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);

    when_failed(amxd_path_init(&path, object), exit);
    if(amxd_path_get_param(&path) != NULL) {
        retval = amxd_status_object_not_found;
        goto exit;
    }
    first_lvl = amxd_path_get_first(&path, true);
    first_lvl_len = strlen(first_lvl);
    if(first_lvl[first_lvl_len - 1] == '.') {
        first_lvl[first_lvl_len - 1] = 0;
    }
    rel_path = amxd_path_get(&path, AMXD_OBJECT_TERMINATE);

    request->result = ret;

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(bool, &args, "parameters", (flags & AMXB_FLAG_PARAMETERS) != 0);
    amxc_var_add_key(bool, &args, "functions", (flags & AMXB_FLAG_FUNCTIONS) != 0);
    amxc_var_add_key(bool, &args, "objects", (flags & AMXB_FLAG_OBJECTS) != 0);
    amxc_var_add_key(bool, &args, "instances", (flags & AMXB_FLAG_INSTANCES) != 0);
    amxc_var_add_key(bool, &args, "template_info", (flags & AMXB_FLAG_TEMPLATE_INFO) != 0);
    amxc_var_add_key(uint32_t, &args, "access", access);
    if((rel_path != NULL) && (*rel_path != 0)) {
        amxc_var_add_key(cstring_t, &args, "rel_path", rel_path);
    }

    retval = amxb_pcb_invoke_root(ctx, first_lvl, "_list", &args, request, true, timeout);

exit:
    request->result = NULL;
    amxb_close_request(&request);
    free(first_lvl);
    amxc_var_clean(&args);
    amxd_path_clean(&path);
    return retval;
}

static void amxb_pcb_add_to_list(const char* object,
                                 amxc_string_t* full_name,
                                 amxc_var_t* list,
                                 amxc_var_t* retval) {
    if(list != NULL) {
        switch(amxc_var_type_of(list)) {
        case AMXC_VAR_ID_LIST: {
            amxc_var_for_each(name, list) {
                amxc_string_setf(full_name, "%s%s",
                                 object, amxc_var_constcast(cstring_t, name));
                amxc_var_add(cstring_t, retval, amxc_string_get(full_name, 0));
            }
        }
        break;
        case AMXC_VAR_ID_HTABLE: {
            const amxc_htable_t* data = amxc_var_constcast(amxc_htable_t, list);
            amxc_array_t* keys = amxc_htable_get_sorted_keys(data);
            uint32_t size = amxc_htable_size(data);
            for(uint32_t i = 0; i < size; i++) {
                const char* name = (const char*) amxc_array_get_data_at(keys, i);
                amxc_string_setf(full_name, "%s%s", object, name);
                amxc_var_add(cstring_t, retval, amxc_string_get(full_name, 0));
            }
            amxc_array_delete(&keys, NULL);
        }
        break;
        default:
            break;
        }
    }
}

static void amxb_pcb_build_list(amxb_request_t* request,
                                const char* object,
                                uint32_t flags,
                                amxc_var_t* full) {
    amxc_var_t* table = GETI_ARG(full, 0);
    amxc_var_t* obj = GET_ARG(table, "objects");
    amxc_var_t* inst = GET_ARG(table, "instances");
    amxc_var_t* funcs = GET_ARG(table, "functions");
    amxc_var_t* params = GET_ARG(table, "parameters");
    bool named = ((flags & AMXB_FLAG_NAMED) != 0);
    amxc_var_t retval;
    amxc_string_t full_name;
    const amxb_bus_ctx_t* bus_ctx = amxb_request_get_ctx(request);

    amxc_var_init(&retval);
    amxc_var_set_type(&retval, AMXC_VAR_ID_LIST);

    amxc_string_init(&full_name, strlen(object) + 32);
    if(inst) {
        amxc_var_for_each(name, inst) {
            amxc_var_t* var = NULL;
            if(named) {
                const char* key = NULL;
                var = amxc_var_get_key(name, "name", AMXC_VAR_FLAG_DEFAULT);
                key = amxc_var_constcast(cstring_t, var);
                amxc_string_setf(&full_name, "%s%s.", object, key);
            } else {
                uint32_t index = 0;
                var = amxc_var_get_key(name, "index", AMXC_VAR_FLAG_DEFAULT);
                index = amxc_var_dyncast(uint32_t, var);
                amxc_string_setf(&full_name, "%s%d.", object, index);
            }
            amxc_var_add(cstring_t, &retval, amxc_string_get(&full_name, 0));
        }
    }

    amxb_pcb_add_to_list(object, &full_name, params, &retval);
    amxb_pcb_add_to_list(object, &full_name, funcs, &retval);
    amxb_pcb_add_to_list(object, &full_name, obj, &retval);

    if(request->cb_fn) {
        request->cb_fn(bus_ctx, &retval, request->priv);
    }

    amxc_var_clean(&retval);
    amxc_string_clean(&full_name);
    return;
}

static void amxb_pcb_object_to_list(object_t* pcb_object,
                                    const char* req_path,
                                    const amxb_bus_ctx_t* ctx,
                                    amxb_request_t* request) {
    char* object_ipath = object_pathChar(pcb_object, path_attr_default);
    char* object_kpath = object_pathChar(pcb_object, path_attr_key_notation);
    amxc_string_t full_name;

    amxc_string_init(&full_name, 32);

    if((object_ipath == NULL) || (*object_ipath == 0)) {
        goto exit;
    }

    if((request->flags & (AMXB_FLAG_INSTANCES | AMXB_FLAG_OBJECTS)) != 0) {
        if((request->flags & AMXB_FLAG_NAMED) != 0) {
            amxc_string_setf(&full_name, "%s.", object_kpath);
        } else {
            amxc_string_setf(&full_name, "%s.", object_ipath);
        }
        if(strcmp(req_path, amxc_string_get(&full_name, 0)) != 0) {
            amxc_var_add(cstring_t, request->result, amxc_string_get(&full_name, 0));
        }
    }
    if((request->flags & AMXB_FLAG_PARAMETERS) != 0) {
        parameter_t* param = NULL;
        object_for_each_parameter(param, pcb_object) {
            const char* name = parameter_name(param);
            if((request->flags & AMXB_FLAG_NAMED) != 0) {
                amxc_string_setf(&full_name, "%s.%s", object_kpath, name);
            } else {
                amxc_string_setf(&full_name, "%s.%s", object_ipath, name);
            }
            amxc_var_add(cstring_t, request->result, amxc_string_get(&full_name, 0));
        }
    }
    if((request->flags & AMXB_FLAG_FUNCTIONS) != 0) {
        function_t* func = NULL;
        object_for_each_function(func, pcb_object) {
            const char* name = function_name(func);
            if((ctx->access < amxd_dm_access_protected) && (name[0] == '_')) {
                continue;
            }
            if((request->flags & AMXB_FLAG_NAMED) != 0) {
                amxc_string_setf(&full_name, "%s.%s", object_kpath, name);
            } else {
                amxc_string_setf(&full_name, "%s.%s", object_ipath, name);
            }
            amxc_var_add(cstring_t, request->result, amxc_string_get(&full_name, 0));
        }
    }

exit:
    amxc_string_clean(&full_name);
    free(object_ipath);
    free(object_kpath);
    return;
}

static bool amxb_pcb_list_item(request_t* req,
                               reply_item_t* item,
                               pcb_t* pcb,
                               peer_info_t* from,
                               void* userdata) {
    amxb_request_t* request = (amxb_request_t*) userdata;
    uint32_t attr = request_attributes(req);
    const char* path = request_path(req);

    switch(reply_item_type(item)) {
    case reply_type_error:
        if((reply_item_error(item) == pcb_error_not_found) &&
           ((attr & request_common_path_key_notation) == 0)) {
            request_setDoneHandler(req, NULL);
            request_destroy(req);
            req = request_create_getObject(path,
                                           request_depth(req),
                                           attr | request_common_path_key_notation |
                                           request_no_object_caching);
            request_setReplyItemHandler(req, amxb_pcb_list_item);
            request_setDoneHandler(req, amxb_pcb_list_done);
            request_setData(req, request);
            pcb_sendRequest(pcb, from, req);
        } else if(request->bus_retval == 0) {
            request->bus_retval = reply_item_error(item);
        }
        break;
    case reply_type_object: {
        const amxb_bus_ctx_t* ctx = amxb_request_get_ctx(request);
        amxb_pcb_object_to_list(reply_item_object(item), path, ctx, request);
        if(request->cb_fn != NULL) {
            request->cb_fn(ctx, request->result, request->priv);
            amxc_var_set_type(request->result, AMXC_VAR_ID_LIST);
        }
    }
    break;
    default:
        break;
    }

    return true;
}

static bool amxb_pcb_list_done(request_t* req,
                               UNUSED pcb_t* pcb,
                               UNUSED peer_info_t* from,
                               void* userdata) {
    amxb_request_t* request = (amxb_request_t*) userdata;

    if(request->cb_fn != NULL) {
        const amxb_bus_ctx_t* ctx = amxb_request_get_ctx(request);
        request->cb_fn(ctx, NULL, request->priv);
    }

    amxb_close_request(&request);
    request_destroy(req);

    return true;
}

static int amxb_pcb_list_collect(void* const ctx,
                                 const char* object,
                                 uint32_t flags,
                                 amxb_request_t* request) {
    int rv = -1;
    amxb_pcb_t* amxb_pcb = (amxb_pcb_t*) ctx;
    request_t* req = NULL;
    pcb_t* pcb = amxb_pcb_ctx();
    peer_info_t* peer = amxb_pcb->peer;
    amxd_path_t path;
    uint32_t req_flags = 0;

    amxd_path_init(&path, object);
    if(amxd_path_get_param(&path) != NULL) {
        rv = amxd_status_object_not_found;
        goto exit;
    }

    req_flags |= (flags & AMXB_FLAG_PARAMETERS) != 0 ? request_getObject_parameters : 0;
    req_flags |= (flags & AMXB_FLAG_FUNCTIONS) != 0 ? request_getObject_functions : 0;
    req_flags |= (flags & AMXB_FLAG_OBJECTS) != 0 ? request_getObject_children : 0;
    req_flags |= (flags & AMXB_FLAG_INSTANCES) != 0 ? request_getObject_instances : 0;
    req_flags |= (flags & AMXB_FLAG_TEMPLATE_INFO) != 0 ? request_getObject_template_info : 0;

    req = request_create_getObject(object == NULL ? "" : object,
                                   (flags & AMXB_FLAG_FIRST_LVL) == 0 ? UINT32_MAX : 0,
                                   req_flags |
                                   request_no_object_caching);

    request->flags = flags;
    request_setReplyItemHandler(req, amxb_pcb_list_item);
    request_setDoneHandler(req, amxb_pcb_list_done);
    request_setData(req, request);

    if(pcb_sendRequest(pcb, peer, req)) {
        rv = amxd_status_ok;
    }

    if((flags & AMXB_FLAG_EXISTS) != 0) {
        pcb_waitForReply(pcb, req, NULL);
    }

exit:
    amxd_path_clean(&path);
    return rv;
}

int amxb_pcb_list(void* const ctx,
                  const char* object,
                  uint32_t flags,
                  uint32_t access,
                  amxb_request_t* request) {
    int retval = -1;
    const amxb_bus_ctx_t* bus_ctx = NULL;

    bus_ctx = amxb_request_get_ctx(request);
    amxc_var_new(&request->result);

    amxc_var_set_type(request->result, AMXC_VAR_ID_LIST);
    if((object == NULL) || (*object == 0)) {
        retval = amxb_pcb_list_collect(ctx, object, flags, request);
        if(retval != 0) {
            request->cb_fn(bus_ctx, NULL, request->priv);
            amxc_var_delete(&request->result);
            amxb_close_request(&request);
        }
    } else {
        amxc_var_t data;
        amxc_var_init(&data);
        amxc_var_set_type(&data, AMXC_VAR_ID_LIST);
        if((flags & AMXB_FLAG_FIRST_LVL) != 0) {
            retval = amxb_pcb_call_list(ctx, object, flags, access, &data, 5);
        }
        if(retval == 0) {
            amxb_pcb_build_list(request, object, flags, &data);
            request->cb_fn(bus_ctx, NULL, request->priv);
            amxc_var_delete(&request->result);
            amxb_close_request(&request);
        } else {
            retval = amxb_pcb_list_collect(ctx, object, flags, request);
            if(retval != 0) {
                request->cb_fn(bus_ctx, NULL, request->priv);
                amxc_var_delete(&request->result);
                amxb_close_request(&request);
            }
        }
        amxc_var_clean(&data);
    }

    return retval;
}
