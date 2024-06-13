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

typedef struct _event_info {
    amxb_pcb_sub_t* amxb_pcb_sub;
    amxc_var_t* notification;
    char* object;
    amxp_timer_t* timer;
    request_t* req;
    amxc_llist_it_t it;
} event_info_t;

static amxc_llist_t pending_events;

static void amxb_pcb_event_drop(amxp_timer_t* timer, void* priv);

static void amxb_pcb_event_info_new(event_info_t** event_info, amxb_pcb_sub_t* amxb_pcb_sub) {
    *event_info = (event_info_t*) calloc(1, sizeof(event_info_t));
    (*event_info)->amxb_pcb_sub = amxb_pcb_sub;
    amxc_llist_append(&pending_events, &(*event_info)->it);
    amxp_timer_new(&(*event_info)->timer, amxb_pcb_event_drop, *event_info);
    amxp_timer_start((*event_info)->timer, 2000);
    amxp_timers_calculate();
    amxp_timers_check();
}

static void amxb_pcb_event_info_delete(event_info_t** event_info) {
    when_null(event_info, exit);
    when_null(*event_info, exit);

    (*event_info)->amxb_pcb_sub->reference--;
    if((*event_info)->amxb_pcb_sub->reference == 0) {
        amxc_htable_it_clean(&(*event_info)->amxb_pcb_sub->it, NULL);
        free((*event_info)->amxb_pcb_sub);
    }
    amxc_llist_it_take(&(*event_info)->it);
    request_destroy((*event_info)->req);
    amxc_var_delete(&(*event_info)->notification);
    amxp_timer_delete(&(*event_info)->timer);
    free((*event_info)->object);
    free((*event_info));
    *event_info = NULL;

exit:
    return;
}

static void amxb_pcb_event_drop(UNUSED amxp_timer_t* timer, void* priv) {
    event_info_t* event_info = (event_info_t*) priv;
    amxb_pcb_event_info_delete(&event_info);
}

static void amxb_pcb_delete_pending(amxc_llist_it_t* it) {
    event_info_t* event_info = amxc_container_of(it, event_info_t, it);
    amxb_pcb_event_info_delete(&event_info);
}

static void amxb_pcb_object_to_info(object_t* pcb_object,
                                    amxc_var_t* var,
                                    UNUSED void* priv) {
    const char* name = object_name(pcb_object, path_attr_key_notation);
    const char* index = object_name(pcb_object, path_attr_default);
    char* parent_path = object_pathChar(pcb_object, path_attr_parent | path_attr_key_notation);
    char* parent_ipath = object_pathChar(pcb_object, path_attr_parent | path_attr_default);

    amxc_string_t full_path;
    amxc_string_init(&full_path, 0);

    amxc_var_set_type(var, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, var, "name", name);
    amxc_var_add_key(cstring_t, var, "index", index);
    amxc_var_add_key(bool, var, "is_instance", object_isInstance(pcb_object));

    if(parent_path != NULL) {
        amxc_string_appendf(&full_path, "%s.", parent_path);
        amxc_var_add_key(cstring_t, var, "parent_object", amxc_string_get(&full_path, 0));
    } else {
        amxc_var_add_key(cstring_t, var, "parent_object", "");
    }

    if(parent_ipath != NULL) {
        amxc_string_reset(&full_path);
        amxc_string_appendf(&full_path, "%s.", parent_ipath);
        amxc_var_add_key(cstring_t, var, "parent_path", amxc_string_get(&full_path, 0));
    } else {
        amxc_var_add_key(cstring_t, var, "parent_path", "");
    }

    amxc_string_reset(&full_path);
    if(parent_path != NULL) {
        amxc_string_appendf(&full_path, "%s.%s.", parent_path, name);
    } else {
        amxc_string_appendf(&full_path, "%s.", name);
    }
    amxc_var_add_key(cstring_t, var, "object", amxc_string_get(&full_path, 0));

    amxc_string_reset(&full_path);
    if(parent_ipath != NULL) {
        amxc_string_appendf(&full_path, "%s.%s.", parent_ipath, index);
    } else {
        amxc_string_appendf(&full_path, "%s.", index);
    }
    amxc_var_add_key(cstring_t, var, "path", amxc_string_get(&full_path, 0));

    free(parent_path);
    free(parent_ipath);
    amxc_string_clean(&full_path);
}

static void amxb_pcb_object_to_var_params(object_t* pcb_object,
                                          amxc_var_t* var,
                                          UNUSED void* priv) {

    parameter_t* param = NULL;
    amxb_pcb_object_to_info(pcb_object, var, NULL);

    var = amxc_var_add_key(amxc_htable_t, var, "parameters", NULL);
    object_for_each_parameter(param, pcb_object) {
        const char* param_name = parameter_name(param);
        const variant_t* param_value = parameter_getValue(param);
        amxc_var_t* var_item = amxc_var_add_new_key(var, param_name);
        amxb_pcb_from_pcb_var(param_value, var_item);
    }
}

static void amxb_pcb_add_param(amxc_var_t* table,
                               notification_parameter_t* param,
                               const char* name) {
    variant_t* value = notification_parameter_variant(param);
    amxc_var_t* var_item = amxc_var_add_new_key(table, name);
    amxb_pcb_from_pcb_var(value, var_item);
}

static void amxb_pcb_update_notification(reply_item_t* item, amxc_var_t* notification) {
    amxc_var_t object_info;
    amxc_var_t* type = NULL;

    amxc_var_init(&object_info);

    amxb_pcb_object_to_var_params(reply_item_object(item), &object_info, NULL);

    type = GET_ARG(notification, "notification");
    when_true(reply_item_type(item) != reply_type_object, exit);

    if(strcmp(GET_CHAR(type, NULL), "dm:instance-added") == 0) {
        if(amxc_var_constcast(bool, amxc_var_get_key(&object_info, "is_instance", AMXC_VAR_FLAG_DEFAULT))) {
            amxc_var_set(cstring_t, type, "dm:instance-added");
            amxc_var_set_key(notification,
                             "object",
                             amxc_var_get_key(&object_info, "parent_object", AMXC_VAR_FLAG_DEFAULT),
                             AMXC_VAR_FLAG_DEFAULT);
            amxc_var_set_key(notification,
                             "name",
                             amxc_var_get_key(&object_info, "name", AMXC_VAR_FLAG_DEFAULT),
                             AMXC_VAR_FLAG_DEFAULT);
            amxc_var_set_key(notification,
                             "path",
                             amxc_var_get_key(&object_info, "parent_path", AMXC_VAR_FLAG_DEFAULT),
                             AMXC_VAR_FLAG_DEFAULT);
            amxc_var_set_key(notification,
                             "index",
                             amxc_var_get_key(&object_info, "index", AMXC_VAR_FLAG_DEFAULT),
                             AMXC_VAR_FLAG_DEFAULT);
            amxc_var_set_key(notification,
                             "parameters",
                             amxc_var_get_key(&object_info, "parameters", AMXC_VAR_FLAG_DEFAULT),
                             AMXC_VAR_FLAG_DEFAULT);

        } else {
            amxc_var_set(cstring_t, type, "dm:object-added");
            amxc_var_set_key(notification,
                             "object",
                             amxc_var_get_key(&object_info, "object", AMXC_VAR_FLAG_DEFAULT),
                             AMXC_VAR_FLAG_DEFAULT);
            amxc_var_set_key(notification,
                             "path",
                             amxc_var_get_key(&object_info, "path", AMXC_VAR_FLAG_DEFAULT),
                             AMXC_VAR_FLAG_DEFAULT);
        }

    } else {
        amxc_var_set_key(notification,
                         "object",
                         amxc_var_get_key(&object_info, "object", AMXC_VAR_FLAG_DEFAULT),
                         AMXC_VAR_FLAG_DEFAULT | AMXC_VAR_FLAG_UPDATE);
        amxc_var_set_key(notification,
                         "path",
                         amxc_var_get_key(&object_info, "path", AMXC_VAR_FLAG_DEFAULT),
                         AMXC_VAR_FLAG_DEFAULT | AMXC_VAR_FLAG_UPDATE);
    }

exit:
    amxc_var_clean(&object_info);
}

static bool amxb_pcb_object_details(request_t* req,
                                    reply_item_t* item,
                                    pcb_t* pcb,
                                    UNUSED peer_info_t* from,
                                    void* userdata) {
    event_info_t* event_info = (event_info_t*) userdata;
    amxb_pcb_t* amxb_pcb = NULL;
    const char* subscriber_object = NULL;

    when_null(event_info, exit);
    when_null(event_info->notification, exit);
    when_null(event_info->amxb_pcb_sub, exit);
    amxb_pcb = event_info->amxb_pcb_sub->amxb_pcb;
    subscriber_object = amxc_htable_it_get_key(&event_info->amxb_pcb_sub->it);

    if(reply_item_type(item) == reply_type_error) {
        if((request_attributes(req) & request_common_path_key_notation) != 0) {
            goto exit;
        }
        request_destroy(event_info->req);
        event_info->req = request_create_getObject(event_info->object,
                                                   0,
                                                   request_common_path_key_notation |
                                                   request_getObject_parameters |
                                                   request_no_object_caching);
        pcb_sendRequest(pcb, from, event_info->req);
        request_setData(event_info->req, event_info);
        request_setReplyItemHandler(event_info->req, amxb_pcb_object_details);
        event_info = NULL;
        goto exit;
    }

    amxb_pcb_update_notification(item, event_info->notification);
    amxp_sigmngr_emit_signal(amxb_pcb->sigmngr, subscriber_object, event_info->notification);


exit:
    amxb_pcb_event_info_delete(&event_info);
    return true;
}

static int amxb_pcb_get_details(pcb_t* pcb_ctx,
                                peer_info_t* remote,
                                notification_t* pcb_notification,
                                event_info_t* info) {
    const char* object = notification_objectPath(pcb_notification);
    int rv = 0;

    when_null_status(object, exit, rv = -1);
    info->object = strdup(object);
    when_null_status(info->object, exit, rv = -1);
    info->req = request_create_getObject(object,
                                         0,
                                         request_getObject_parameters |
                                         request_no_object_caching);
    if(info->req != NULL) {
        pcb_sendRequest(pcb_ctx, remote, info->req);
        request_setData(info->req, info);
        request_setReplyItemHandler(info->req, amxb_pcb_object_details);
        info->amxb_pcb_sub->reference++;
    } else {
        free(info->object);
        rv = -1;
    }

exit:
    return rv;
}

static int amxb_pcb_changed_to_amx_changed(amxb_pcb_sub_t* amxb_pcb_sub,
                                           pcb_t* pcb_ctx,
                                           peer_info_t* remote,
                                           notification_t* pcb_notification) {
    int rv = 0;
    event_info_t* info = NULL;

    notification_parameter_t* old_p = notification_getParameter(pcb_notification, "oldvalue");
    notification_parameter_t* new_p = notification_getParameter(pcb_notification, "newvalue");
    notification_parameter_t* param = notification_getParameter(pcb_notification, "parameter");
    char* param_name = notification_parameter_value(param);
    amxc_var_t* data = NULL;

    amxb_pcb_event_info_new(&info, amxb_pcb_sub);

    amxc_var_new(&info->notification);
    amxc_var_set_type(info->notification, AMXC_VAR_ID_HTABLE);

    amxc_var_add_key(cstring_t, info->notification, "notification", "dm:object-changed");
    data = amxc_var_add_key(amxc_htable_t, info->notification, "parameters", NULL);
    data = amxc_var_add_key(amxc_htable_t, data, param_name, NULL);

    amxb_pcb_add_param(data, old_p, "from");
    amxb_pcb_add_param(data, new_p, "to");

    rv = amxb_pcb_get_details(pcb_ctx, remote, pcb_notification, info);
    when_failed(rv, exit);

exit:
    free(param_name);
    return rv;
}

static int amxb_pcb_add_to_amx_add(amxb_pcb_sub_t* amxb_pcb_sub,
                                   pcb_t* pcb_ctx,
                                   peer_info_t* remote,
                                   notification_t* pcb_notification) {
    int rv = 0;
    event_info_t* info = NULL;

    amxb_pcb_event_info_new(&info, amxb_pcb_sub);

    amxc_var_new(&info->notification);
    amxc_var_set_type(info->notification, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, info->notification, "notification", "dm:instance-added");

    rv = amxb_pcb_get_details(pcb_ctx, remote, pcb_notification, info);
    when_failed(rv, exit);

exit:
    return rv;
}

static amxc_var_t* amxb_pcb_notif_params_to_data(amxc_var_t* notification,
                                                 notification_t* pcb_notification) {
    notification_parameter_t* param = NULL;
    amxc_var_t* data = NULL;

    data = amxc_var_add_key(amxc_htable_t, notification, "data", NULL);
    notification_for_each_parameter(param, pcb_notification) {
        variant_t* value = notification_parameter_variant(param);
        const char* name = notification_parameter_name(param);
        amxc_var_t* var_item = amxc_var_add_new_key(data, name);
        amxb_pcb_from_pcb_var(value, var_item);
    }

    return data;
}

static int amxb_pcb_custom_to_amx_custom(amxb_pcb_sub_t* amxb_pcb_sub,
                                         pcb_t* pcb_ctx,
                                         peer_info_t* remote,
                                         notification_t* pcb_notification) {
    int rv = 0;
    event_info_t* info = NULL;
    amxc_var_t* data = NULL;
    const char* notify_name = notification_name(pcb_notification);

    amxb_pcb_event_info_new(&info, amxb_pcb_sub);

    amxc_var_new(&info->notification);
    amxc_var_set_type(info->notification, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, info->notification, "notification", notify_name);
    data = amxb_pcb_notif_params_to_data(info->notification, pcb_notification);
    if(data != NULL) {
        amxc_var_take_it(data);
        amxc_var_for_each(v, data) {
            amxc_var_set_key(info->notification, amxc_var_key(v), v, AMXC_VAR_FLAG_DEFAULT);
        }
        amxc_var_delete(&data);
    }

    rv = amxb_pcb_get_details(pcb_ctx, remote, pcb_notification, info);
    when_failed(rv, exit);

exit:
    return rv;
}

static int amxb_pcb_del_to_amx_del(amxb_pcb_sub_t* amxb_pcb_sub,
                                   notification_t* pcb_notification) {
    int rv = 0;
    const char* object = notification_objectPath(pcb_notification);
    char* last = NULL;
    amxc_string_t str;
    amxd_path_t path;
    bool is_instance = false;
    amxc_var_t notification;
    amxb_pcb_t* amxb_pcb = amxb_pcb_sub->amxb_pcb;
    const char* subscriber_object = amxc_htable_it_get_key(&amxb_pcb_sub->it);

    amxc_var_init(&notification);
    amxc_var_set_type(&notification, AMXC_VAR_ID_HTABLE);

    amxc_string_init(&str, 0);
    amxd_path_init(&path, NULL);
    amxd_path_setf(&path, true, "%s", object);

    last = amxd_path_get_last(&path, false);
    amxc_string_push_buffer(&str, last, strlen(last) + 1);
    amxc_string_trim(&str, ispunct);
    is_instance = amxc_string_is_numeric(&str);

    if(is_instance) {
        amxc_var_t* index = NULL;
        last = amxd_path_get_last(&path, true);
        index = amxc_var_add_key(cstring_t, &notification, "index", amxc_string_get(&str, 0));
        amxc_var_cast(index, AMXC_VAR_ID_UINT32);
        amxc_var_add_key(cstring_t, &notification, "notification", "dm:instance-removed");
        amxc_var_add_key(cstring_t, &notification,
                         "path", amxd_path_get(&path, AMXD_OBJECT_TERMINATE));
        free(last);
    } else {
        amxc_var_add_key(cstring_t, &notification, "notification", "dm:object-removed");
        amxc_var_add_key(cstring_t, &notification,
                         "path", amxd_path_get(&path, AMXD_OBJECT_TERMINATE));
    }

    amxp_sigmngr_emit_signal(amxb_pcb->sigmngr, subscriber_object, &notification);

    amxc_var_clean(&notification);
    amxd_path_clean(&path);
    amxc_string_clean(&str);
    return rv;
}

static void amxb_pcb_check_notify_path(notification_t* pcb_notification,
                                       const char* subscriber) {
    amxd_path_t path;
    amxc_string_t prefix;
    char* part = NULL;
    const char* notify_path = notification_objectPath(pcb_notification);
    const char* modified = NULL;
    int len = strlen(subscriber);

    amxd_path_init(&path, NULL);
    amxc_string_init(&prefix, 0);

    if(strncmp(subscriber, notify_path, len) == 0) {
        goto exit;
    }

    // Translate notification path
    amxd_path_setf(&path, true, "%s", subscriber);
    part = amxd_path_get_first(&path, true);
    amxc_string_appendf(&prefix, "%s", part);
    free(part);

    modified = amxd_path_get(&path, 0);
    len = strlen(modified);

    if(strncmp(modified, notify_path, len) == 0) {
        amxc_string_appendf(&prefix, "%s", notify_path);
        notification_setObjectPath(pcb_notification, amxc_string_get(&prefix, 0));
        goto exit;
    }

    amxd_path_setf(&path, true, "%s", notify_path);
    part = amxd_path_get_first(&path, true);
    free(part);

    notify_path = amxd_path_get(&path, 0);

    if(strncmp(subscriber, notify_path, len) == 0) {
        amxc_string_appendf(&prefix, "%s", notify_path);
        notification_setObjectPath(pcb_notification, amxd_path_get(&path, 0));
        goto exit;
    }

exit:
    amxc_string_clean(&prefix);
    amxd_path_clean(&path);
    return;
}

static void amxb_pcb_notif_translate(amxb_pcb_sub_t* amxb_pcb_sub,
                                     pcb_t* pcb,
                                     peer_info_t* from,
                                     notification_t* pcb_notification) {
    uint32_t notify_type = notification_type(pcb_notification);
    const char* subscriber_object = amxc_htable_it_get_key(&amxb_pcb_sub->it);

    amxb_pcb_check_notify_path(pcb_notification, subscriber_object);

    if(notify_type < 100) {
        switch(notify_type) {
        case notify_value_changed:
            amxb_pcb_changed_to_amx_changed(amxb_pcb_sub, pcb, from, pcb_notification);
            break;
        case notify_object_added:
            amxb_pcb_add_to_amx_add(amxb_pcb_sub, pcb, from, pcb_notification);
            break;
        case notify_object_deleted:
            amxb_pcb_del_to_amx_del(amxb_pcb_sub, pcb_notification);
            break;
        }
    } else if(notify_type == 1000) {
        amxc_var_t notification;
        amxc_var_t* data = NULL;
        const char* path = NULL;
        const char* object = NULL;
        uint32_t len = 0;
        const char* notify_name = notification_name(pcb_notification);
        amxc_var_init(&notification);
        amxc_var_set_type(&notification, AMXC_VAR_ID_HTABLE);
        data = amxb_pcb_notif_params_to_data(&notification, pcb_notification);
        path = GETP_CHAR(data, "path");
        object = GETP_CHAR(data, "object");
        len = strlen(subscriber_object);
        if(((path != NULL) && (strncmp(path, subscriber_object, len) == 0)) ||
           ((object != NULL) && (strncmp(object, subscriber_object, len) == 0))) {
            amxc_var_add_key(cstring_t, data, "notification", notify_name);
            amxp_sigmngr_emit_signal(amxb_pcb_sub->amxb_pcb->sigmngr, subscriber_object, data);
        } else {
            amxb_pcb_custom_to_amx_custom(amxb_pcb_sub, pcb, from, pcb_notification);
        }
        amxc_var_clean(&notification);
    } else {
        amxb_pcb_custom_to_amx_custom(amxb_pcb_sub, pcb, from, pcb_notification);
    }
}

bool amxb_pcb_notification(request_t* req,
                           reply_item_t* item,
                           pcb_t* pcb,
                           peer_info_t* from,
                           void* userdata) {
    amxb_pcb_sub_t* amxb_pcb_sub = (amxb_pcb_sub_t*) userdata;
    notification_t* pcb_notification = NULL;

    when_null(amxb_pcb_sub, exit);

    if(reply_item_type(item) == reply_type_error) {
        uint32_t flags = request_attributes(amxb_pcb_sub->sub_req);
        const char* object = amxc_htable_it_get_key(&amxb_pcb_sub->it);
        uint32_t error = reply_item_error(item);

        amxb_pcb_sub->sub_req = NULL;
        request_setData(req, NULL);
        request_destroy(req);

        when_true(error != pcb_error_connection_shutdown, exit);

        amxb_pcb_sub->sub_req = request_create_getObject(object, -1, flags);
        when_false(pcb_sendRequest(pcb, from, amxb_pcb_sub->sub_req), exit);
        request_setData(amxb_pcb_sub->sub_req, amxb_pcb_sub);
        request_setReplyItemHandler(amxb_pcb_sub->sub_req, amxb_pcb_notification);
        goto exit;
    }
    when_true(reply_item_type(item) != reply_type_notification, exit);
    pcb_notification = reply_item_notification(item);

    amxb_pcb_notif_translate(amxb_pcb_sub, pcb, from, pcb_notification);

exit:
    return true;
}

void amxb_pcb_clear_pending(void) {
    amxc_llist_clean(&pending_events, amxb_pcb_delete_pending);
}