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


static int amxb_pcb_to_request_params(const amxc_htable_t* args,
                                      request_t* req) {
    amxc_htable_for_each(it, args) {
        const char* key = amxc_htable_it_get_key(it);
        variant_t pcb_arg;
        amxc_var_t* amxc_arg = amxc_var_from_htable_it(it);
        variant_initialize(&pcb_arg, variant_type_unknown);
        amxb_pcb_to_pcb_var(amxc_arg, &pcb_arg);
        request_addParameter(req, key, &pcb_arg);
        variant_cleanup(&pcb_arg);
    }

    return 0;
}

static void amxb_pcb_reply_function_return(const amxb_bus_ctx_t* ctx,
                                           amxb_request_t* request,
                                           reply_item_t* item,
                                           amxc_var_t* result) {
    const variant_t* value = reply_item_returnValue(item);
    argument_value_list_t* args = NULL;
    amxc_var_t* var_item = amxc_var_add_new(result);
    amxb_pcb_from_pcb_var(value, var_item);
    if(request->cb_fn != NULL) {
        request->cb_fn(ctx, var_item, request->priv);
    }
    args = reply_item_returnArguments(item);
    if((args != NULL) &&
       ( argument_valueFirstArgument(args) != NULL)) {
        var_item = amxc_var_add_new(result);
        amxc_var_set_type(var_item, AMXC_VAR_ID_HTABLE);
        for(argument_value_t* arg = argument_valueFirstArgument(args);
            arg != NULL;
            arg = argument_valueNextArgument(arg)) {
            const char* name = argument_valueName(arg);
            if((name != NULL) && (*name != 0)) {
                amxc_var_t* out_arg = amxc_var_add_new_key(var_item, name);
                value = argument_value(arg);
                amxb_pcb_from_pcb_var(value, out_arg);
            }
        }
        if(request->cb_fn != NULL) {
            request->cb_fn(ctx, var_item, request->priv);
        }
    }
}

bool amxb_pcb_result_data(UNUSED request_t* req,
                          reply_item_t* item,
                          UNUSED pcb_t* pcb,
                          UNUSED peer_info_t* from,
                          void* userdata) {
    amxb_request_t* request = (amxb_request_t*) userdata;
    amxc_var_t* result = request->result;
    const amxb_bus_ctx_t* ctx = NULL;
    ctx = amxb_request_get_ctx(request);

    switch(reply_item_type(item)) {
    case reply_type_error:
        if((reply_item_error(item) & 0x10000000) != 0) {
            request->bus_retval = reply_item_error(item) & 0x0000FFFF;
        } else if(request->bus_retval == 0) {
            request->bus_retval = amxb_pcb_error_to_amxd_status(reply_item_error(item));
        }
        break;
    case reply_type_function_return: {
        amxb_pcb_reply_function_return(ctx, request, item, result);
    }
    break;
    default:
        break;
    }

    return true;
}

bool amxb_pcb_request_done(UNUSED request_t* req,
                           UNUSED pcb_t* pcb,
                           UNUSED peer_info_t* from,
                           void* userdata) {
    amxb_request_t* request = (amxb_request_t*) userdata;
    const amxb_bus_ctx_t* ctx = NULL;
    ctx = amxb_request_get_ctx(request);

    if(request->done_fn != NULL) {
        request->done_fn(ctx,
                         request,
                         request->bus_retval,
                         request->priv);
    }

    return true;
}

int amxb_pcb_invoke_base(request_t** pcb_req,
                         const char* object,
                         const char* method,
                         amxc_var_t* args,
                         amxb_request_t* request,
                         bool key_path) {
    int retval = -1;
    const char* pcb_obj_path = NULL;
    amxd_path_t path;
    uint32_t flags = 0;

    amxd_path_init(&path, NULL);
    amxd_path_setf(&path, true, "%s", object);

    pcb_obj_path = amxd_path_get(&path, 0);
    flags = key_path ? request_common_path_key_notation : 0;
    *pcb_req = request_create_executeFunction(pcb_obj_path,
                                              method,
                                              flags |
                                              request_function_args_by_name);
    when_null(*pcb_req, exit);

    if(args != NULL) {
        const amxc_htable_t* htable_args = NULL;
        when_true(amxc_var_type_of(args) != AMXC_VAR_ID_HTABLE, exit);
        htable_args = amxc_var_constcast(amxc_htable_t, args);
        amxb_pcb_to_request_params(htable_args, *pcb_req);
    }

    amxc_var_set_type(request->result, AMXC_VAR_ID_LIST);

    retval = 0;

exit:
    amxd_path_clean(&path);
    return retval;
}

int amxb_pcb_invoke_impl(void* const ctx,
                         const char* object,
                         const char* method,
                         amxc_var_t* args,
                         amxb_request_t* request,
                         bool key_path,
                         int timeout) {
    int retval = -1;
    pcb_t* pcb_ctx = amxb_pcb_ctx();
    amxb_pcb_t* amxb_pcb = (amxb_pcb_t*) ctx;
    peer_info_t* peer = amxb_pcb->peer;
    request_t* pcb_req = NULL;

    struct timeval pcb_timeout = {
        .tv_sec = timeout,
        .tv_usec = 0
    };

    when_failed(amxb_pcb_invoke_base(&pcb_req,
                                     object,
                                     method,
                                     args,
                                     request,
                                     key_path), exit);

    request_setReplyItemHandler(pcb_req, amxb_pcb_result_data);
    request_setData(pcb_req, request);
    when_false(pcb_sendRequest(pcb_ctx, peer, pcb_req), exit);

    when_false(pcb_waitForReply(pcb_ctx, pcb_req, &pcb_timeout), exit);
    retval = request->bus_retval;

exit:
    if(pcb_req != NULL) {
        amxb_pcb_request_destroy(pcb_req);
    }
    return retval;
}

int amxb_pcb_invoke_root(void* const ctx,
                         const char* object,
                         const char* method,
                         amxc_var_t* args,
                         amxb_request_t* request,
                         bool key_path,
                         int timeout) {
    int retval = 0;
    amxd_path_t path;
    char* root_obj = NULL;
    int len = 0;
    amxc_var_t* rel_path = GET_ARG(args, "rel_path");

    amxd_path_init(&path, NULL);
    amxd_path_setf(&path, true, "%s", object);

    root_obj = amxd_path_get_first(&path, true);
    len = strlen(root_obj) - 1;
    if(root_obj[len] == '.') {
        root_obj[len] = 0;
    }

    if(rel_path == NULL) {
        amxc_var_add_key(cstring_t, args, "rel_path",
                         amxd_path_get(&path, AMXD_OBJECT_TERMINATE));
    } else {
        amxc_string_t full_rel_path;
        amxc_string_init(&full_rel_path, 0);
        amxc_string_setf(&full_rel_path, "%s%s",
                         amxd_path_get(&path, AMXD_OBJECT_TERMINATE),
                         GET_CHAR(rel_path, NULL));
        amxc_var_set(cstring_t, rel_path, amxc_string_get(&full_rel_path, 0));
        amxc_string_clean(&full_rel_path);
    }
    retval = amxb_pcb_invoke_impl(ctx, root_obj, method, args, request, key_path, timeout);

    free(root_obj);
    amxd_path_clean(&path);

    return retval;
}

int amxb_pcb_invoke(void* const ctx,
                    amxb_invoke_t* invoke_ctx,
                    amxc_var_t* args,
                    amxb_request_t* request,
                    int timeout) {
    amxb_pcb_t* amxb_pcb = (amxb_pcb_t*) ctx;
    uint32_t flags = RESOLV_NO_AMX_CHECK | RESOLV_LIST | RESOLV_EXACT_DEPTH | RESOLV_TEMPLATES;
    amxc_var_t resolved_table;
    bool key_path = false;
    int retval = amxd_status_unknown_error;
    amxc_var_t* exec_args = NULL;

    amxc_var_init(&resolved_table);
    when_str_empty(invoke_ctx->object, exit);

    amxc_var_set_type(&resolved_table, AMXC_VAR_ID_HTABLE);

    retval = amxb_pcb_resolve(amxb_pcb, invoke_ctx->object, NULL, NULL, 0,
                              flags, &key_path, &resolved_table);
    if(retval == -1) {
        amxc_var_new(&exec_args);
        amxc_var_set_type(exec_args, AMXC_VAR_ID_HTABLE);
        amxc_var_set_key(exec_args, "args", args, AMXC_VAR_FLAG_COPY);
        amxc_var_add_key(cstring_t, exec_args, "method", invoke_ctx->method);
        retval = amxb_pcb_invoke_root(ctx, invoke_ctx->object, "_exec",
                                      exec_args, request, key_path, timeout);
    } else {
        retval = amxb_pcb_invoke_impl(ctx, invoke_ctx->object, invoke_ctx->method,
                                      args, request, key_path, timeout);
    }

exit:
    amxc_var_delete(&exec_args);
    amxc_var_clean(&resolved_table);
    return retval;
}

int amxb_pcb_async_invoke(void* const ctx,
                          amxb_invoke_t* invoke_ctx,
                          amxc_var_t* args,
                          amxb_request_t* request) {
    int retval = amxd_status_unknown_error;
    pcb_t* pcb_ctx = amxb_pcb_ctx();
    amxb_pcb_t* amxb_pcb = (amxb_pcb_t*) ctx;
    peer_info_t* peer = amxb_pcb->peer;
    request_t* pcb_req = NULL;
    uint32_t flags = RESOLV_NO_AMX_CHECK | RESOLV_LIST | RESOLV_EXACT_DEPTH | RESOLV_TEMPLATES;
    amxc_var_t resolved_table;
    bool key_path = false;

    amxc_var_init(&resolved_table);
    when_str_empty(invoke_ctx->object, exit);

    amxc_var_set_type(&resolved_table, AMXC_VAR_ID_HTABLE);

    retval = amxb_pcb_resolve(amxb_pcb, invoke_ctx->object, NULL, NULL,
                              0, flags, &key_path, &resolved_table);
    when_failed(retval, exit);

    when_failed(amxb_pcb_invoke_base(&pcb_req,
                                     invoke_ctx->object,
                                     invoke_ctx->method,
                                     args,
                                     request,
                                     key_path), exit);

    request->bus_data = pcb_req;

    request_setReplyItemHandler(pcb_req, amxb_pcb_result_data);
    request_setDoneHandler(pcb_req, amxb_pcb_request_done);
    request_setData(pcb_req, request);

    when_false(pcb_sendRequest(pcb_ctx, peer, pcb_req), exit);

    retval = 0;

exit:
    amxc_var_clean(&resolved_table);

    if(retval != 0) {
        if(pcb_req != NULL) {
            request_destroy(pcb_req);
        }
        request->bus_data = NULL;
    }
    return retval;
}

int amxb_pcb_wait_request(UNUSED void* const ctx,
                          amxb_request_t* request,
                          int timeout) {
    int retval = -1;
    pcb_t* pcb_ctx = amxb_pcb_ctx();
    request_t* pcb_req = (request_t*) request->bus_data;

    struct timeval pcb_timeout = {
        .tv_sec = timeout,
        .tv_usec = 0
    };

    when_false(pcb_waitForReply(pcb_ctx, pcb_req, &pcb_timeout), exit);
    retval = request->bus_retval;

exit:
    return retval;
}

int amxb_pcb_close_request(UNUSED void* const ctx,
                           amxb_request_t* request) {
    request_t* pcb_req = (request_t*) request->bus_data;

    if(pcb_req != NULL) {
        request_destroy(pcb_req);
    }

    request->bus_data = NULL;

    return 0;
}
