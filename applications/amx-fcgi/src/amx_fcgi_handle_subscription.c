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

#define EVENT_VALUE_CHANGED     AMXA_PERMIT_SUBS_VAL_CHANGE
#define EVENT_OBJECT_CREATION   AMXA_PERMIT_SUBS_OBJ_ADD
#define EVENT_OBJECT_DELETION   AMXA_PERMIT_SUBS_OBJ_DEL
#define EVENT_CUSTOM            AMXA_PERMIT_SUBS_EVT_OPER_COMP

#define EVENT_ALL   (EVENT_VALUE_CHANGED | EVENT_OBJECT_CREATION | EVENT_OBJECT_DELETION | EVENT_CUSTOM)

static void amx_fcgi_translate_notification_names(amxc_var_t* notifications,
                                                  uint32_t* bitmap) {
    if(amxc_var_is_null(notifications)) {
        (*bitmap) = EVENT_ALL;
    } else {
        amxc_var_for_each(name, notifications) {
            const char* n = GET_CHAR(name, NULL);
            if(strcmp(n, "ValueChange") == 0) {
                amxc_var_set(cstring_t, name, "dm:object-changed");
                (*bitmap) |= EVENT_VALUE_CHANGED;
            } else if(strcmp(n, "ObjectCreation") == 0) {
                amxc_var_set(cstring_t, name, "dm:instance-added");
                (*bitmap) |= EVENT_OBJECT_CREATION;
            } else if(strcmp(n, "ObjectDeletion") == 0) {
                amxc_var_set(cstring_t, name, "dm:instance-removed");
                (*bitmap) |= EVENT_OBJECT_DELETION;
            } else {
                (*bitmap) |= EVENT_CUSTOM;
            }
        }
    }
}

static void amx_fcgi_add_event_filter(amxc_string_t* str_expr,
                                      amxc_var_t* notifications,
                                      uint32_t bitmap) {
    const char* sep = "";
    bool close = false;
    const amxc_llist_t* lnotifications = amxc_var_constcast(amxc_llist_t, notifications);

    if(!amxc_string_is_empty(str_expr)) {
        sep = " && ";
    }

    if((bitmap != 0) && ((bitmap & EVENT_ALL) != EVENT_ALL)) {
        if(!amxc_llist_is_empty(lnotifications)) {
            amxc_var_cast(notifications, AMXC_VAR_ID_JSON);
            amxc_string_appendf(str_expr,
                                "%s((notification in %s)",
                                sep, amxc_var_get_const_jstring_t(notifications));
            sep = " || ";
            close = true;
        }

        if((bitmap & EVENT_CUSTOM) == EVENT_CUSTOM) {
            amxc_string_appendf(str_expr,
                                "%s not (notification in ['%s','%s','%s'])", sep,
                                "dm:object-changed", "dm:instance-added", "dm:instance-removed");

        }

        if(close) {
            amxc_string_appendf(str_expr, ")");
        }
    }
}

static int amx_fcgi_build_expression(amxc_string_t* str_expr,
                                     amxc_var_t* notifications,
                                     const char* filter) {
    amxp_expr_status_t status = amxp_expr_status_ok;
    const char* sep = "";
    amxp_expr_t expr;
    uint32_t bitmap = 0;

    if(!amxc_var_is_null(notifications)) {
        amx_fcgi_translate_notification_names(notifications, &bitmap);
        amx_fcgi_add_event_filter(str_expr, notifications, bitmap);
        if(!amxc_string_is_empty(str_expr)) {
            sep = " && ";
        }
    }

    if((filter != NULL) && (*filter != 0)) {
        amxc_string_appendf(str_expr, "%s(%s)", sep, filter);
    }

    if(!amxc_string_is_empty(str_expr)) {
        status = amxp_expr_init(&expr, amxc_string_get(str_expr, 0));
        amxp_expr_clean(&expr);
    }

    return status == amxp_expr_status_ok ? 0 : -1;
}

static int amx_fcgi_verify_subscribe(amxb_bus_ctx_t* ctx,
                                     amx_fcgi_request_t* fcgi_req,
                                     amxc_var_t* notifications,
                                     const char* fixed,
                                     subscription_t* sub) {
    int retval = -1;
    uint32_t bitmap = 0;
    amxc_var_t* acls = NULL;
    sub->acl_file = amx_fcgi_get_acl_file(fcgi_req);

    acls = amxa_parse_files(sub->acl_file);
    amxa_resolve_search_paths(ctx, acls, fixed);

    amx_fcgi_translate_notification_names(notifications, &bitmap);
    if(bitmap & EVENT_VALUE_CHANGED) {
        when_false(amxa_is_subs_allowed(acls, fixed, EVENT_VALUE_CHANGED), exit);
    }
    if(bitmap & EVENT_OBJECT_CREATION) {
        when_false(amxa_is_subs_allowed(acls, fixed, EVENT_OBJECT_CREATION), exit);
    }
    if(bitmap & EVENT_OBJECT_DELETION) {
        when_false(amxa_is_subs_allowed(acls, fixed, EVENT_OBJECT_DELETION), exit);
    }
    if(bitmap & EVENT_CUSTOM) {
        when_false(amxa_is_subs_allowed(acls, fixed, EVENT_CUSTOM), exit);
    }

    retval = 0;
exit:
    amxc_var_delete(&acls);
    return retval;
}

event_stream_t* amx_fcgi_subscription_get_stream(subscription_t* sub) {
    event_stream_t* stream = NULL;
    when_null(sub, exit);
    when_null(sub->it.ait, exit);

    if(sub->it.ait->array != NULL) {
        amxc_htable_t* ptable = amxc_container_of(sub->it.ait->array, amxc_htable_t, table);
        stream = amxc_container_of(ptable, event_stream_t, subscriptions);
    }

exit:
    return stream;
}

int amx_fcgi_http_subscribe(amx_fcgi_request_t* fcgi_req,
                            amxc_var_t* data,
                            bool acl_verify) {
    int status = 200;
    const char* stream_id = fcgi_req->raw_path;
    event_stream_t* stream = NULL;
    amxb_bus_ctx_t* ctx = NULL;
    const char* event_id = GET_CHAR(data, "subs-id");
    const char* input_path = GET_CHAR(data, "path");
    const char* filter = GET_CHAR(data, "filter");
    amxc_var_t* notifications = GET_ARG(data, "notifications");
    amxd_path_t path;
    char* p = NULL;
    subscription_t* sub = (subscription_t*) calloc(1, sizeof(subscription_t));
    amxc_string_t expr_str;

    amxd_path_init(&path, NULL);
    amxc_string_init(&expr_str, 0);

    when_null_status(sub, exit, status = 500);
    when_str_empty_status(input_path, exit, status = 400);
    when_str_empty_status(stream_id, exit, status = 400);
    when_str_empty_status(event_id, exit, status = 400);
    when_true_status(!amxc_var_is_null(notifications) &&
                     amxc_var_type_of(notifications) != AMXC_VAR_ID_LIST,
                     exit, status = 400);

    stream = amx_fcgi_get_stream(stream_id);
    when_null_status(stream, exit, status = 400);
    when_true_status(amxc_htable_contains(&stream->subscriptions, event_id),
                     exit, status = 400);

    amxd_path_setf(&path, false, "%s", input_path);
    p = amxd_path_get_fixed_part(&path, false);
    ctx = amxb_be_who_has(p);
    when_null_status(ctx, exit, status = 404);
    amxb_set_access(ctx, AMXB_PUBLIC);

    if(acl_verify) {
        when_failed_status(amx_fcgi_verify_subscribe(ctx, fcgi_req, notifications, p, sub), exit, status = 403);
    }

    amx_fcgi_build_expression(&expr_str, notifications, filter);

    if(amxb_subscription_new(&sub->subscription, ctx,
                             amxd_path_get(&path, AMXD_OBJECT_TERMINATE),
                             amxc_string_get(&expr_str, 0),
                             amx_fcgi_handle_event, sub) != 0) {
        status = 400;
        goto exit;
    }

    amxc_htable_insert(&stream->subscriptions, event_id, &sub->it);
    sub = NULL;

exit:
    amxc_string_clean(&expr_str);
    amxd_path_clean(&path);
    free(sub);
    free(p);
    return status;
}

int amx_fcgi_http_unsubscribe(amx_fcgi_request_t* fcgi_req,
                              UNUSED amxc_var_t* data,
                              UNUSED bool acl_verify) {
    int status = 200;
    const char* stream_id = fcgi_req->raw_path;
    const char* event_id = fcgi_req->info;
    event_stream_t* stream = NULL;
    amxc_htable_it_t* it = NULL;
    subscription_t* sub = NULL;

    when_str_empty_status(stream_id, exit, status = 400);
    when_str_empty_status(event_id, exit, status = 400);

    stream = amx_fcgi_get_stream(stream_id);
    when_null_status(stream, exit, status = 400);
    it = amxc_htable_get(&stream->subscriptions, event_id);
    when_null_status(it, exit, status = 404);

    sub = amxc_container_of(it, subscription_t, it);
    free(sub->acl_file);
    amxc_htable_it_clean(it, NULL);
    amxb_subscription_delete(&sub->subscription);
    free(sub);


exit:
    return status;
}