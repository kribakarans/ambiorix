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
#include <stdio.h>
#include <string.h>

#include "amx_fcgi.h"

#define str_is_empty(x) (x == NULL || *x == 0)

static void amx_fcgi_add_executed(amxc_var_t* dst,
                                  const char* path,
                                  const char* method) {
    amxc_string_t executed;
    amxc_string_init(&executed, 0);
    amxc_string_setf(&executed, "%s%s()", path, method);
    amxc_var_add_key(cstring_t, dst, "executed", amxc_string_get(&executed, 0));
    amxc_string_clean(&executed);
}

static void amx_fcgi_add_outargs(amxc_var_t* dst,
                                 const char* path,
                                 const char* method,
                                 amxc_var_t* data) {
    amxc_var_t* out = amxc_var_add(amxc_htable_t, dst, NULL);
    amxc_var_t* retval = GETI_ARG(data, 0);
    amxc_var_t* outargs = GETI_ARG(data, 1);

    amx_fcgi_add_executed(out, path, method);
    out = amxc_var_add_key(amxc_htable_t, out, "outputArgs", NULL);

    if(!amxc_var_is_null(retval)) {
        amxc_var_take_it(retval);
        if(amxc_var_type_of(retval) != AMXC_VAR_ID_HTABLE) {
            amxc_var_set_key(out, method, retval, AMXC_VAR_FLAG_DEFAULT);
        } else {
            amxc_var_move(out, retval);
            amxc_var_delete(&retval);
        }
    }

    if(!amxc_var_is_null(outargs)) {
        amxc_var_move(out, outargs);
    }
}

static void amx_fcgi_add_failure(amxc_var_t* dst,
                                 const char* path,
                                 const char* method,
                                 int status) {
    amxc_var_t* out = amxc_var_add(amxc_htable_t, dst, NULL);

    amx_fcgi_add_executed(out, path, method);
    out = amxc_var_add_key(amxc_htable_t, out, "failure", NULL);
    amxc_var_add_key(int32_t, out, "errcode", status);
    amxc_var_add_key(cstring_t, out, "errmsg", "");
}


static int amx_fcgi_verify_cmd(amxb_bus_ctx_t* ctx,
                               amx_fcgi_request_t* fcgi_req,
                               const char* fixed,
                               const char* method) {
    amxc_var_t* acls = NULL;
    amxc_var_t resolved;
    char* file = amx_fcgi_get_acl_file(fcgi_req);
    int retval = -1;
    bool allowed = false;
    amxc_string_t resolved_path;

    amxc_string_init(&resolved_path, 0);
    amxc_var_init(&resolved);

    when_str_empty(file, exit);

    acls = amxa_parse_files(file);
    retval = amxa_resolve_search_paths(ctx, acls, fixed);
    when_failed(retval, exit);

    allowed = amxa_is_operate_allowed(ctx, acls, fixed, method);
    when_false_status(allowed, exit, retval = -1);

    retval = 0;
exit:
    free(file);
    amxc_var_delete(&acls);
    amxc_var_clean(&resolved);
    amxc_string_clean(&resolved_path);

    return retval;
}

static void amx_fcgi_send_done_event(const amxb_bus_ctx_t* bus_ctx,
                                     amxb_request_t* req,
                                     int status,
                                     void* priv) {
    amxc_var_t* input = (amxc_var_t*) priv;
    amxc_var_t event_data;
    amxd_path_t path;
    char* p = NULL;

    amxd_path_init(&path, NULL);
    amxc_var_init(&event_data);
    amxc_var_set_type(&event_data, AMXC_VAR_ID_HTABLE);
    amxd_path_setf(&path, false, "%s", GET_CHAR(input, "path"));
    p = amxd_path_get_fixed_part(&path, false);
    p[strlen(p) - 1] = 0;

    amxc_var_add_key(cstring_t, &event_data, "notification", "dm:operation-complete");
    amxc_var_add_key(cstring_t, &event_data, "path", GET_CHAR(input, "path"));
    amxc_var_add_key(cstring_t, &event_data, "command_name", GET_CHAR(input, "method"));
    amxc_var_add_key(cstring_t, &event_data, "command_key", GET_CHAR(input, "commandKey"));
    if(status == 0) {
        amxc_var_set_key(&event_data, "output_args", req->result, AMXC_VAR_FLAG_COPY);
    } else {
        amxc_var_add_key(int32_t, &event_data, "err_code", status);
        amxc_var_add_key(cstring_t, &event_data, "err_msg", "");
    }

    amxp_sigmngr_emit_signal(&bus_ctx->sigmngr, p, &event_data);

    amxc_var_delete(&input);
    amxc_var_clean(&event_data);
    amxb_close_request(&req);
    amxd_path_clean(&path);
    free(p);
}

static int amx_fcgi_invoke_cmd(amxb_bus_ctx_t* ctx,
                               amx_fcgi_request_t* fcgi_req,
                               const char* cmdkey,
                               const char* dm_path,
                               const char* method,
                               amxc_var_t* args,
                               amxc_var_t* result,
                               bool acl_verify) {
    int rv = -1;
    int status = 204;

    if(acl_verify) {
        rv = amx_fcgi_verify_cmd(ctx, fcgi_req, dm_path, method);
        when_true_status(rv != 0, exit, status = 403);
    }

    if(str_is_empty(cmdkey)) {
        amxc_var_t out;
        amxc_var_init(&out);
        rv = amxb_call(ctx, dm_path, method, args, &out, 5);
        if(rv == 0) {
            amx_fcgi_add_outargs(result, dm_path, method, &out);
        } else {
            amx_fcgi_add_failure(result, dm_path, method, rv);
        }
        amxc_var_clean(&out);
    } else {
        amxc_var_t* exec = NULL;
        amxc_var_t* async_data = NULL;
        amxb_request_t* req = NULL;
        amxc_var_new(&async_data);
        amxc_var_set_type(async_data, AMXC_VAR_ID_HTABLE);
        amxc_var_add_key(cstring_t, async_data, "commandKey", cmdkey);
        amxc_var_add_key(cstring_t, async_data, "method", method);
        amxc_var_add_key(cstring_t, async_data, "path", dm_path);
        req = amxb_async_call(ctx, dm_path, method, args,
                              amx_fcgi_send_done_event, async_data);
        exec = amxc_var_add(amxc_htable_t, result, NULL);
        if(req == NULL) {
            amxc_var_delete(&async_data);
            status = 400;
            amx_fcgi_add_failure(exec, dm_path, method, status);
        } else {
            amx_fcgi_add_executed(exec, dm_path, method);
        }
    }

exit:
    return status;
}

int amx_fcgi_http_cmd(amx_fcgi_request_t* fcgi_req,
                      amxc_var_t* data,
                      bool acl_verify) {
    int status = 204;
    char* p = amxd_path_get_fixed_part(&fcgi_req->path, false);
    bool send_response = GET_BOOL(data, "sendresp");
    const char* method = GET_CHAR(data, "method");
    amxc_var_t* args = GET_ARG(data, "inputArgs");
    const char* cmdkey = GET_CHAR(data, "commandKey");
    amxb_bus_ctx_t* ctx = amxb_be_who_has(p);
    amxc_var_t paths;
    amxc_var_t result;

    amxc_var_init(&result);
    amxc_var_init(&paths);

    amxc_var_set_type(&result, AMXC_VAR_ID_LIST);

    when_null_status(ctx, exit, status = 404);
    amxb_set_access(ctx, AMXB_PUBLIC);

    if(amxd_path_is_search_path(&fcgi_req->path)) {
        amxb_resolve(ctx, &fcgi_req->path, &paths);
        when_true_status(amx_fcgi_is_empty(&paths), exit, status = 404);

        amxc_var_for_each(path, &paths) {
            const char* dm_path = GET_CHAR(path, NULL);
            status = amx_fcgi_invoke_cmd(ctx, fcgi_req, cmdkey, dm_path, method,
                                         args, &result, acl_verify);
            when_true(status != 204, exit);
        }
    } else {
        const char* dm_path = amxd_path_get(&fcgi_req->path, AMXD_OBJECT_TERMINATE);
        status = amx_fcgi_invoke_cmd(ctx, fcgi_req, cmdkey, dm_path, method,
                                     args, &result, acl_verify);
        when_true(status != 204, exit);
    }

    if(send_response) {
        if(str_is_empty(cmdkey)) {
            status = 202;
        } else {
            status = 201;
        }
    }

    amxc_var_clean(data);

    if(send_response) {
        amxc_var_move(data, &result);
    }

exit:
    amxc_var_clean(&result);
    amxc_var_clean(&paths);
    free(p);

    return status;
}
