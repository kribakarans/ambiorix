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
#include <errno.h>
#include <fcntl.h>
#include <string.h>

#include <amxc/amxc.h>
#include <amxp/amxp.h>

#include <amxd/amxd_dm.h>
#include <amxd/amxd_object.h>

#include <amxb/amxb_be_intf.h>
#include <amxb/amxb.h>

#include "amxb_priv.h"

static int isdot(int c) {
    if(c == '.') {
        return 1;
    }

    return 0;
}

static int isbrace(int c) {
    if((c == '(') || (c == ')')) {
        return 1;
    }

    return 0;
}

static void amxb_trim(char* str, amxc_string_is_char_fn_t fn) {
    amxc_string_t txt;
    amxc_string_init(&txt, 0);
    amxc_string_push_buffer(&txt, str, strlen(str) + 1);
    amxc_string_trimr(&txt, fn);
    amxc_string_take_buffer(&txt);
    amxc_string_clean(&txt);
}

static void amxb_complete_async_invoke(UNUSED const amxc_var_t* const data,
                                       void* const priv) {
    amxb_req_t* req = (amxb_req_t*) priv;
    amxb_request_t* request = &req->data;
    amxb_bus_ctx_t* ctx = amxb_request_get_ctx(request);
    req->in_flight = false;

    if(req->closed) {
        if(!req->wait) {
            amxb_close_request(&request);
        }

        goto exit;
    }

    if((request->cb_fn != NULL) && (request->bus_retval == 0)) {
        request->cb_fn(ctx, request->result, request->priv);
    }
    if(request->done_fn != NULL) {
        request->done_fn(ctx, request, request->bus_retval, request->priv);
    }

exit:
    return;
}

static void amxb_complete_async_deferred_invoke(const amxc_var_t* const data,
                                                void* const priv) {
    amxc_var_t* rv = GET_ARG(data, "retval");
    amxb_req_t* req = (amxb_req_t*) priv;
    amxb_request_t* request = &req->data;

    amxc_var_set_type(request->result, AMXC_VAR_ID_LIST);
    amxc_var_take_it(rv);
    amxc_var_set_index(request->result, 0, rv, AMXC_VAR_FLAG_DEFAULT);
    request->bus_retval = GET_UINT32(data, "status");

    amxb_complete_async_invoke(NULL, priv);

    return;
}

static int amxb_invoke_local_impl(amxb_invoke_t* invoke_ctx,
                                  amxb_bus_ctx_t* ctx,
                                  amxc_var_t* args,
                                  amxb_request_t* request,
                                  bool async) {
    int retval = -1;
    amxb_req_t* req = amxc_container_of(request, amxb_req_t, data);
    amxc_var_t empty_args;
    amxc_var_t* fn_rv = NULL;
    amxc_var_t* out_args = NULL;
    amxd_object_t* object = NULL;
    amxc_var_init(&empty_args);
    amxc_var_set_type(&empty_args, AMXC_VAR_ID_HTABLE);

    object = amxb_fetch_local_object(ctx, invoke_ctx->object);
    when_null_status(object, exit, retval = amxd_status_object_not_found);

    if(args == NULL) {
        args = &empty_args;
    }

    amxc_var_set_type(request->result, AMXC_VAR_ID_LIST);
    fn_rv = amxc_var_add_new(request->result);

    retval = amxd_object_invoke_function(object, invoke_ctx->method, args, fn_rv);
    if(!amxc_htable_is_empty(amxc_var_constcast(amxc_htable_t, args))) {
        out_args = amxc_var_add_new(request->result);
        amxc_var_move(out_args, args);
    }

    request->bus_retval = retval;

    if(async) {
        if((request->done_fn != NULL) || (request->cb_fn != NULL)) {
            req->in_flight = true;
            if(retval == amxd_status_deferred) {
                uint64_t call_id = amxc_var_constcast(uint64_t, fn_rv);
                amxd_function_set_deferred_cb(call_id, amxb_complete_async_deferred_invoke, req);
                retval = 0;
            } else {
                amxp_sigmngr_deferred_call(NULL, amxb_complete_async_invoke, NULL, req);
                retval = 0;
            }
        }
    } else {
        if(retval == amxd_status_deferred) {
            uint64_t call_id = 0;
            req->in_flight = true;
            call_id = amxc_var_constcast(uint64_t, fn_rv);
            amxd_function_set_deferred_cb(call_id, amxb_complete_async_deferred_invoke, req);
        } else {
            when_failed(retval, exit);
            if(request->cb_fn != NULL) {
                request->cb_fn(ctx, request->result, request->priv);
            }
        }
    }

exit:
    amxc_var_clean(&empty_args);
    return retval;
}

static int amxb_invoke_be_impl(amxb_invoke_t* invoke_ctx,
                               amxb_bus_ctx_t* ctx,
                               amxc_var_t* args,
                               amxb_request_t* request,
                               int timeout,
                               bool async) {
    amxc_var_t* func_args = args;
    const amxb_be_funcs_t* fns = NULL;
    int retval = -1;

    timeout = amxb_get_minimal_timeout(timeout);
    if((amxc_var_type_of(args) == AMXC_VAR_ID_NULL) ||
       ( amxc_var_type_of(args) == AMXC_VAR_ID_INVALID)) {
        func_args = NULL;
    }

    fns = ctx->bus_fn;
    if(async) {
        if(amxb_is_valid_be_func(fns, invoke, fns->async_invoke)) {
            retval = fns->async_invoke(ctx->bus_ctx,
                                       invoke_ctx,
                                       func_args,
                                       request);
        } else {
            retval = AMXB_ERROR_NOT_SUPPORTED_OP;
        }
    } else {
        if(amxb_is_valid_be_func(fns, invoke, fns->invoke)) {
            retval = fns->invoke(ctx->bus_ctx,
                                 invoke_ctx,
                                 func_args,
                                 request,
                                 timeout);
        } else {
            retval = AMXB_ERROR_NOT_SUPPORTED_OP;
        }
    }

    return retval;
}

static int amxb_invoke_wait_local(amxb_req_t* req, int timeout) {
    int retval = -1;
    if(req->in_flight) {
        int fd = amxp_signal_fd();
        struct timeval t = {
            .tv_sec = timeout,
            .tv_usec = 0
        };

        fd_set readset;
        FD_ZERO(&readset);
        FD_SET(fd, &readset);

        req->wait = true;
        while(req->in_flight) {
            retval = select(fd + 1, &readset, NULL, NULL, &t);
            if(retval <= 0) {
                // timeout or error
                retval = -1;
                break;
            }
            amxp_signal_read();
        }
        req->wait = false;
    }
    if(!req->in_flight) {
        retval = req->data.bus_retval;
        if(req->closed) {
            amxb_request_t* request = &req->data;
            amxb_close_request(&request);
        }
    }

    return retval;
}

int amxb_new_invoke(amxb_invoke_t** invoke_ctx,
                    amxb_bus_ctx_t* const ctx,
                    const char* object,
                    const char* interface,
                    const char* method) {
    int retval = amxd_status_unknown_error;
    const amxb_be_funcs_t* fns = NULL;

    when_null(invoke_ctx, exit);
    when_not_null(*invoke_ctx, exit);
    when_null(ctx, exit);
    when_null(ctx->bus_ctx, exit);
    when_str_empty(method, exit);

    *invoke_ctx = (amxb_invoke_t*) calloc(1, sizeof(amxb_invoke_t));
    when_null((*invoke_ctx), exit);

    (*invoke_ctx)->object = object == NULL ? strdup("") : strdup(object);
    when_null((*invoke_ctx)->object, exit);
    (*invoke_ctx)->interface = interface == NULL ? NULL : strdup(interface);
    (*invoke_ctx)->method = strdup(method);
    when_null((*invoke_ctx)->method, exit);

    amxb_trim((*invoke_ctx)->object, isdot);
    amxb_trim((*invoke_ctx)->method, isbrace);

    fns = ctx->bus_fn;
    if(amxb_is_valid_be_func(fns, new_invoke, fns->new_invoke)) {
        retval = fns->new_invoke(*invoke_ctx);
    } else {
        retval = 0;
    }

    if(retval == 0) {
        amxc_llist_append(&ctx->invoke_ctxs, &(*invoke_ctx)->it);
    } else {
        amxb_free_invoke(invoke_ctx);
    }

exit:
    return retval;
}

void amxb_free_invoke(amxb_invoke_t** invoke_ctx) {
    const amxb_be_funcs_t* fns = NULL;
    amxb_bus_ctx_t* ctx = NULL;

    when_null(invoke_ctx, exit);
    when_null(*invoke_ctx, exit);

    if(amxc_llist_it_is_in_list(&(*invoke_ctx)->it)) {
        ctx = amxc_container_of((*invoke_ctx)->it.llist,
                                amxb_bus_ctx_t, invoke_ctxs);
        fns = ctx->bus_fn;
        if(amxb_is_valid_be_func(fns, free_invoke, fns->free_invoke)) {
            fns->free_invoke(*invoke_ctx);
        }
    }

    amxc_llist_it_take(&(*invoke_ctx)->it);
    free((*invoke_ctx)->object);
    free((*invoke_ctx)->interface);
    free((*invoke_ctx)->method);
    free((*invoke_ctx));

    *invoke_ctx = NULL;

exit:
    return;
}

int amxb_invoke(amxb_invoke_t* invoke_ctx,
                amxc_var_t* args,
                amxc_var_t* ret,
                amxb_be_cb_fn_t fn,
                void* priv,
                int timeout) {
    int retval = -1;
    amxb_bus_ctx_t* ctx = NULL;
    amxc_var_t temp_var;
    amxb_req_t* req = NULL;
    amxb_request_t* request = NULL;
    timeout = amxb_get_minimal_timeout(timeout);

    amxc_var_init(&temp_var);

    when_null(invoke_ctx, exit);
    when_null(invoke_ctx->it.llist, exit);

    ctx = amxc_container_of(invoke_ctx->it.llist, amxb_bus_ctx_t, invoke_ctxs);
    req = (amxb_req_t*) calloc(1, sizeof(amxb_req_t));
    when_null(req, exit);
    request = &req->data;

    request->result = (ret == NULL) ? &temp_var : ret;
    request->cb_fn = fn;
    request->done_fn = NULL;
    request->bus_retval = 0;
    request->bus_data = NULL;
    request->priv = priv;

    if(amxb_is_local_object(ctx, invoke_ctx->object)) {
        retval = amxb_invoke_local_impl(invoke_ctx, ctx, args, request, false);
        if(retval == amxd_status_deferred) {
            retval = amxb_invoke_wait_local(req, timeout);
        }
    } else {
        retval = amxb_invoke_be_impl(invoke_ctx, ctx, args, request, timeout, false);
    }
    free(req);

exit:
    amxc_var_clean(&temp_var);
    return retval;
}

int amxb_async_invoke(amxb_invoke_t* invoke_ctx,
                      amxc_var_t* args,
                      amxb_be_cb_fn_t fn,
                      amxb_be_done_cb_fn_t done_fn,
                      void* priv,
                      amxb_request_t** request) {
    int retval = -1;
    amxb_bus_ctx_t* ctx = NULL;
    amxb_req_t* req = NULL;

    when_null(invoke_ctx, exit);
    when_null(invoke_ctx->it.llist, exit);
    when_null(request, exit);
    ctx = amxc_container_of(invoke_ctx->it.llist, amxb_bus_ctx_t, invoke_ctxs);

    req = (amxb_req_t*) calloc(1, sizeof(amxb_req_t));
    when_null(req, exit);
    *request = &req->data;

    amxc_var_new(&req->data.result);
    req->data.cb_fn = fn;
    req->data.done_fn = done_fn;
    req->data.priv = priv;

    if(amxb_is_local_object(ctx, invoke_ctx->object)) {
        req->local = true;
        retval = amxb_invoke_local_impl(invoke_ctx, ctx, args, *request, true);
    } else {
        req->local = false;
        retval = amxb_invoke_be_impl(invoke_ctx, ctx, args, *request, 0, true);
    }

    if(retval == 0) {
        amxc_llist_append(&ctx->requests, &req->it);
    }

exit:
    if((retval != 0) && (req != NULL)) {
        amxc_var_delete(&req->data.result);
        free(req);
        *request = NULL;
    }

    return retval;
}

int amxb_wait_for_request(amxb_request_t* request, int timeout) {
    int retval = -1;
    amxb_req_t* req = NULL;
    const amxb_be_funcs_t* fns = NULL;
    const amxb_bus_ctx_t* ctx = NULL;

    when_null(request, exit);
    req = amxc_container_of(request, amxb_req_t, data);

    if(req->local) {
        retval = amxb_invoke_wait_local(req, timeout);
        goto exit;
    }

    ctx = amxb_request_get_ctx(request);
    when_null(ctx, exit);
    fns = ctx->bus_fn;

    if(amxb_is_valid_be_func(fns, wait_request, fns->wait_request)) {
        retval = fns->wait_request(ctx->bus_ctx, request, timeout);
    } else {
        retval = AMXB_ERROR_NOT_SUPPORTED_OP;
    }

exit:
    return retval;
}

int amxb_request_new(amxb_request_t** request) {
    amxb_req_t* req = NULL;
    int retval = AMXB_ERROR_UNKNOWN;

    req = (amxb_req_t*) calloc(1, sizeof(amxb_req_t));
    when_null(req, exit);

    *request = &req->data;
    retval = AMXB_STATUS_OK;

exit:
    return retval;
}

amxb_bus_ctx_t* amxb_request_get_ctx(amxb_request_t* request) {
    amxb_req_t* req = NULL;
    amxb_bus_ctx_t* ctx = NULL;

    when_null(request, exit);
    req = amxc_container_of(request, amxb_req_t, data);
    if(amxc_llist_it_is_in_list(&req->it)) {
        ctx = amxc_container_of(req->it.llist, amxb_bus_ctx_t, requests);
    }

exit:
    return ctx;
}

int amxb_close_request(amxb_request_t** request) {
    int retval = -1;
    const amxb_bus_ctx_t* ctx = NULL;
    const amxb_be_funcs_t* fns = NULL;
    amxb_req_t* req = NULL;

    when_null(request, exit);
    when_null((*request), exit);

    req = amxc_container_of(*request, amxb_req_t, data);
    amxc_var_delete(&(*request)->result);

    if(req->in_flight || req->wait) {
        req->closed = true;
        *request = NULL;
        retval = 0;
        goto exit;
    }

    retval = 0;
    when_false(amxc_llist_it_is_in_list(&req->it), exit_free);

    ctx = amxc_container_of(req->it.llist, amxb_bus_ctx_t, requests);
    fns = ctx->bus_fn;

    if(amxb_is_valid_be_func(fns, close_request, fns->close_request)) {
        retval = fns->close_request(ctx->bus_ctx, *request);
    } else {
        retval = AMXB_ERROR_NOT_SUPPORTED_OP;
    }

    amxc_llist_it_take(&req->it);

exit_free:
    free(req);
    *request = NULL;
exit:
    return retval;
}
