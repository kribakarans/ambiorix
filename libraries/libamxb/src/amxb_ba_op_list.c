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
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>

#include <amxc/amxc.h>
#include <amxp/amxp.h>

#include <amxd/amxd_common.h>
#include <amxd/amxd_dm.h>
#include <amxd/amxd_path.h>
#include <amxd/amxd_object.h>

#include <amxb/amxb_be_intf.h>
#include <amxb/amxb.h>

#include "amxb_priv.h"

static void amxb_fill_list(amxc_var_t* ret,
                           const char* object,
                           amxc_string_t* full_name,
                           amxc_var_t* data) {
    if(data != NULL) {
        amxc_var_for_each(name, data) {
            const char* str_name = amxc_var_constcast(cstring_t, name);
            amxc_string_setf(full_name, "%s%s", object, str_name);
            amxc_var_add(cstring_t, ret, amxc_string_get(full_name, 0));
        }
    }
}

static void amxb_build_list(amxc_var_t* ret,
                            const char* object,
                            uint32_t flags,
                            amxc_var_t* full) {
    amxc_var_t* table = GETI_ARG(full, 0);
    amxc_var_t* obj = GET_ARG(table, "objects");
    amxc_var_t* inst = GET_ARG(table, "instances");
    amxc_var_t* funcs = GET_ARG(table, "functions");
    amxc_var_t* params = GET_ARG(table, "parameters");
    amxc_string_t full_name;

    amxc_string_init(&full_name, strlen(object) + 32);

    if(inst && ((flags & AMXB_FLAG_INSTANCES) != 0)) {
        amxc_var_for_each(name, inst) {
            if((flags & AMXB_FLAG_NAMED) != 0) {
                amxc_string_setf(&full_name, "%s%s.", object, GET_CHAR(name, "name"));
            } else {
                amxc_string_setf(&full_name, "%s%d.", object, GET_UINT32(name, "index"));
            }
            amxc_var_add(cstring_t, ret, amxc_string_get(&full_name, 0));
        }
    }
    if((flags & AMXB_FLAG_PARAMETERS) != 0) {
        amxb_fill_list(ret, object, &full_name, params);
    }
    if((flags & AMXB_FLAG_FUNCTIONS) != 0) {
        amxb_fill_list(ret, object, &full_name, funcs);
    }
    if((flags & AMXB_FLAG_OBJECTS) != 0) {
        amxb_fill_list(ret, object, &full_name, obj);
    }

    amxc_string_clean(&full_name);
    return;
}

static int amxb_invoke_list(amxb_bus_ctx_t* const bus_ctx,
                            const char* object,
                            uint32_t flags,
                            amxb_be_cb_fn_t fn,
                            void* priv) {
    amxb_invoke_t* invoke_ctx = NULL;
    amxc_var_t list_return;
    amxc_var_t args;
    amxd_path_t path;
    amxc_var_t ret;
    int retval = amxd_status_unknown_error;

    amxd_path_init(&path, NULL);
    amxd_path_setf(&path, true, "%s", object);
    amxc_var_init(&list_return);
    amxc_var_init(&ret);
    amxc_var_init(&args);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(bool, &args, "parameters", (flags & AMXB_FLAG_PARAMETERS) != 0);
    amxc_var_add_key(bool, &args, "functions", (flags & AMXB_FLAG_FUNCTIONS) != 0);
    amxc_var_add_key(bool, &args, "template_info", (flags & AMXB_FLAG_TEMPLATE_INFO) != 0);
    amxc_var_add_key(bool, &args, "instances", (flags & AMXB_FLAG_INSTANCES) != 0);
    amxc_var_add_key(bool, &args, "objects", (flags & AMXB_FLAG_OBJECTS) != 0);
    amxc_var_add_key(uint32_t, &args, "access", bus_ctx->access);
    retval = amxb_new_invoke(&invoke_ctx, bus_ctx, object, NULL, "_list");
    when_failed(retval, exit);
    retval = amxb_invoke(invoke_ctx, &args, &list_return, NULL, NULL, amxb_get_internal_timeout());
    when_failed(retval, exit);

    amxc_var_set_type(&ret, AMXC_VAR_ID_LIST);
    amxb_build_list(&ret, amxd_path_get(&path, AMXD_OBJECT_TERMINATE),
                    flags, &list_return);
    if(fn != NULL) {
        fn(bus_ctx, &ret, priv);
    }

exit:
    if(fn != NULL) {
        fn(bus_ctx, NULL, priv);
    }
    amxc_var_clean(&ret);
    amxd_path_clean(&path);
    amxc_var_clean(&args);
    amxc_var_clean(&list_return);
    amxb_free_invoke(&invoke_ctx);
    return retval;
}

int amxb_list(amxb_bus_ctx_t* const bus_ctx,
              const char* object,
              uint32_t flags,
              amxb_be_cb_fn_t fn,
              void* priv) {
    int retval = amxd_status_unknown_error;
    const amxb_be_funcs_t* fns = NULL;
    amxd_path_t path;
    bool lobject = false;

    amxd_path_init(&path, NULL);
    when_null(bus_ctx, exit);
    when_null(bus_ctx->bus_ctx, exit);
    if((object != NULL) && ((*object) != 0)) {
        lobject = amxb_is_local_object(bus_ctx, object);
    }
    fns = bus_ctx->bus_fn;

    if((object != NULL) && (*object != 0)) {
        amxd_path_setf(&path, true, "%s", object);
        if(lobject || !amxb_is_valid_be_func(fns, list, fns->list)) {
            retval = amxb_invoke_list(bus_ctx, object, flags, fn, priv);
        } else {
            amxb_req_t* req = (amxb_req_t*) calloc(1, sizeof(amxb_req_t));
            when_null(req, exit);
            req->data.cb_fn = fn;
            req->data.priv = priv;
            amxc_llist_append(&bus_ctx->requests, &req->it);
            retval = fns->list(bus_ctx->bus_ctx, object, flags,
                               bus_ctx->access, &req->data);
        }
    } else {
        if(amxb_is_valid_be_func(fns, list, fns->list)) {
            amxb_req_t* req = (amxb_req_t*) calloc(1, sizeof(amxb_req_t));
            when_null(req, exit);
            req->data.cb_fn = fn;
            req->data.priv = priv;
            amxc_llist_append(&bus_ctx->requests, &req->it);
            retval = fns->list(bus_ctx->bus_ctx, object, flags,
                               bus_ctx->access, &req->data);
        } else {
            if(fn != NULL) {
                fn(bus_ctx, NULL, priv);
            }
            retval = AMXB_ERROR_NOT_SUPPORTED_OP;
        }
    }

exit:
    amxb_log(bus_ctx, "get(_filtered)", object == NULL? "":object, retval);
    amxd_path_clean(&path);
    return retval;
}
