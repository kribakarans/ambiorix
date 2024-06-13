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
#include <amxp/amxp_expression.h>

#include <amxd/amxd_common.h>
#include <amxd/amxd_dm.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_object_event.h>
#include <amxd/amxd_path.h>

#include <amxb/amxb_be_intf.h>
#include <amxb/amxb.h>

#include "amxb_priv.h"

static int amxb_subscribe_local_impl(amxb_bus_ctx_t* ctx,
                                     const char* path,
                                     const char* expression,
                                     amxp_slot_fn_t slot_cb,
                                     void* priv) {
    int retval = -1;
    amxd_dm_t* dm = ctx->dm;
    amxd_object_t* object = amxd_dm_findf(dm, "%s", path);
    amxp_signal_t* signal = NULL;
    amxc_string_t local_expr;
    amxc_htable_it_t* sub_hit = NULL;

    amxc_string_init(&local_expr, 0);

    when_null(object, exit);

    signal = amxp_sigmngr_find_signal(&ctx->sigmngr, path);
    if(signal == NULL) {
        amxp_sigmngr_add_signal(&ctx->sigmngr, path);
    }
    retval = amxp_slot_connect(&ctx->sigmngr, path, expression, slot_cb, priv);
    when_failed(retval, exit);

    if(amxc_htable_contains(&ctx->subscriptions, path)) {
        goto exit;
    }

    sub_hit = (amxc_htable_it_t*) calloc(1, sizeof(amxc_htable_it_t));
    amxc_htable_insert(&ctx->subscriptions, path, sub_hit);

    amxc_string_appendf(&local_expr,
                        "object starts with \"%s.\" || path starts with \"%s.\"",
                        path,
                        path);
    retval = amxp_slot_connect(&ctx->dm->sigmngr,
                               "*",
                               amxc_string_get(&local_expr, 0),
                               amxb_dm_event_to_object_event,
                               sub_hit);

exit:
    amxc_string_clean(&local_expr);
    return retval;
}

static int amxb_subscribe_be_impl(amxb_bus_ctx_t* ctx,
                                  const char* path,
                                  const char* expression,
                                  amxp_slot_fn_t slot_cb,
                                  void* priv) {
    int retval = -1;
    amxp_signal_t* signal = NULL;

    signal = amxp_sigmngr_find_signal(&ctx->sigmngr, path);
    if(signal == NULL) {
        const amxb_be_funcs_t* fns = ctx->bus_fn;
        if(amxb_is_valid_be_func(fns, subscribe, fns->subscribe)) {
            retval = fns->subscribe(ctx->bus_ctx, path);
            when_failed(retval, exit);
            amxp_sigmngr_add_signal(&ctx->sigmngr, path);
        } else {
            retval = AMXB_ERROR_NOT_SUPPORTED_OP;
            goto exit;
        }
    }
    amxp_slot_connect(&ctx->sigmngr, path, expression, slot_cb, priv);

    retval = 0;

exit:
    return retval;
}

static void amxb_build_path(amxc_var_t* info, amxd_path_t* path) {
    amxc_var_t* obj_data = GETI_ARG(info, 0);
    uint32_t type = amxc_var_dyncast(uint32_t, GET_ARG(obj_data, "type_id"));
    const char* obj_path = GET_CHAR(obj_data, "path");
    uint32_t index = amxc_var_dyncast(uint32_t, GET_ARG(obj_data, "index"));
    char* spath = NULL;

    free(amxd_path_get_fixed_part(path, true));
    spath = strdup(amxd_path_get(path, AMXD_OBJECT_TERMINATE));

    if(type == amxd_object_instance) {
        amxd_path_setf(path, false, "%s%d.%s", obj_path, index, spath);
    } else {
        amxd_path_setf(path, false, "%s%s", obj_path, spath);
    }

    free(spath);
}

static int amxb_build_expression(amxc_string_t* str_expr,
                                 amxd_path_t* obj_path,
                                 const char* expression) {
    amxp_expr_status_t status = amxp_expr_status_ok;
    const char* sep = "";
    amxp_expr_t expr;

    if(amxd_path_is_search_path(obj_path)) {
        amxc_string_setf(str_expr, "%s", amxd_path_get(obj_path, AMXD_OBJECT_TERMINATE));
        amxc_string_replace(str_expr, "'", "\"", UINT32_MAX);
        amxc_string_prependf(str_expr, "path starts with search_path('");
        amxc_string_appendf(str_expr, "')");
        sep = " && ";
    } else {
        amxc_string_setf(str_expr, "%s", amxd_path_get(obj_path, AMXD_OBJECT_TERMINATE));
        amxc_string_replace(str_expr, "'", "\"", UINT32_MAX);
        amxc_string_prependf(str_expr, "(path starts with '");
        amxc_string_appendf(str_expr, "' || !(contains('path') && contains('object')))");
        sep = " && ";
    }

    if((expression != NULL) && (*expression != 0)) {
        amxc_string_appendf(str_expr, "%s(%s)", sep, expression);
    }

    if(!amxc_string_is_empty(str_expr)) {
        status = amxp_expr_init(&expr, amxc_string_get(str_expr, 0));
        amxp_expr_clean(&expr);
    }

    return status == amxp_expr_status_ok ? 0 : -1;
}


int amxb_subscribe(amxb_bus_ctx_t* const ctx,
                   const char* object,
                   const char* expression,
                   amxp_slot_fn_t slot_cb,
                   void* priv) {
    int retval = -1;
    char* obj_path = NULL;
    amxc_var_t info;
    amxd_path_t path;
    amxb_request_t* req = NULL;
    amxc_string_t rel_path;
    amxc_string_t str_expr;

    amxd_path_init(&path, NULL);
    amxc_var_init(&info);
    amxc_string_init(&rel_path, 64);
    amxc_string_init(&str_expr, 0);

    when_null(ctx, exit);
    when_null(ctx->bus_ctx, exit);
    when_null(object, exit);
    when_null(slot_cb, exit);

    amxd_path_setf(&path, true, "%s", object);
    if((path.type == amxd_path_invalid) ||
       (path.type == amxd_path_reference) ||
       (path.type == amxd_path_supported)) {
        goto exit;
    }
    obj_path = amxd_path_get_fixed_part(&path, false);

    retval = amxb_describe(ctx, obj_path, 0, &info, amxb_get_internal_timeout());
    if(retval == 0) {
        free(obj_path);
        amxb_build_path(&info, &path);
        obj_path = amxd_path_get_fixed_part(&path, false);
    }

    when_null(obj_path, exit);

    amxc_var_set_type(&info, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &info, "expression", expression);
    req = amxb_async_call(ctx, obj_path, "_subscribe", &info, NULL, NULL);
    amxb_close_request(&req);

    if(*obj_path != 0) {
        obj_path[strlen(obj_path) - 1] = 0;
    }

    retval = amxb_build_expression(&str_expr, &path, expression);
    when_failed(retval, exit);
    expression = amxc_string_get(&str_expr, 0);

    if(ctx->dm != NULL) {
        retval = amxb_subscribe_local_impl(ctx, obj_path, expression, slot_cb, priv);
        when_true(retval == 0, exit);
    }

    retval = amxb_subscribe_be_impl(ctx, obj_path, expression, slot_cb, priv);

exit:
    amxc_string_clean(&str_expr);
    amxc_string_clean(&rel_path);
    amxd_path_clean(&path);
    amxc_var_clean(&info);
    free(obj_path);
    return retval;
}

int amxb_unsubscribe(amxb_bus_ctx_t* const ctx,
                     const char* object,
                     amxp_slot_fn_t slot_cb,
                     void* priv) {
    int retval = -1;
    const amxb_be_funcs_t* fns = NULL;
    amxb_request_t* req = NULL;
    amxp_signal_t* signal = NULL;
    char* obj_path = NULL;
    amxc_var_t info;
    amxd_path_t path;

    amxd_path_init(&path, NULL);
    amxc_var_init(&info);

    when_null(ctx, exit);
    when_null(ctx->bus_ctx, exit);
    when_str_empty(object, exit);

    amxd_path_setf(&path, true, "%s", object);
    if((path.type == amxd_path_invalid) ||
       (path.type == amxd_path_reference) ||
       (path.type == amxd_path_supported)) {
        goto exit;
    }
    obj_path = amxd_path_get_fixed_part(&path, false);

    retval = amxb_describe(ctx, obj_path, 0, &info, amxb_get_internal_timeout());
    if(retval == 0) {
        free(obj_path);
        amxb_build_path(&info, &path);
        obj_path = amxd_path_get_fixed_part(&path, false);
    }

    when_null(obj_path, exit);

    amxc_var_set_type(&info, AMXC_VAR_ID_HTABLE);
    req = amxb_async_call(ctx, obj_path, "_unsubscribe", &info, NULL, NULL);
    amxb_close_request(&req);

    if(*obj_path != 0) {
        obj_path[strlen(obj_path) - 1] = 0;
    }

    retval = -1;
    signal = amxp_sigmngr_find_signal(&ctx->sigmngr, obj_path);
    when_null(signal, exit);

    if(priv == NULL) {
        amxp_slot_disconnect(&ctx->sigmngr, obj_path, slot_cb);
    } else {
        amxp_slot_disconnect_signal_with_priv(&ctx->sigmngr, obj_path, slot_cb, priv);
    }
    retval = 0;
    when_true(amxp_signal_has_slots(signal), exit);

    fns = ctx->bus_fn;
    if(amxb_is_valid_be_func(fns, unsubscribe, fns->unsubscribe)) {
        retval = fns->unsubscribe(ctx->bus_ctx,
                                  obj_path);
    } else {
        retval = AMXB_STATUS_OK;
    }

    amxp_signal_delete(&signal);

exit:
    free(obj_path);
    amxd_path_clean(&path);
    amxc_var_clean(&info);
    return retval;
}

int amxb_publish(amxb_bus_ctx_t* const ctx,
                 const char* object,
                 const char* name,
                 amxc_var_t* data) {
    int retval = -1;
    amxd_object_t* obj = NULL;

    when_null(ctx, exit);
    when_null(ctx->dm, exit);
    when_null(ctx->bus_ctx, exit);
    when_str_empty(object, exit);
    when_str_empty(name, exit);

    obj = amxd_object_findf(amxd_dm_get_root(ctx->dm), "%s", object);

    if(obj != NULL) {
        amxd_object_emit_signal(obj, name, data);
        retval = amxd_status_ok;
    } else {
        retval = amxd_status_object_not_found;
    }

exit:
    return retval;
}
