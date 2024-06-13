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

#include <amxc/amxc.h>
#include <yajl/yajl_gen.h>
#include <amxj/amxj_variant.h>
#include <amxd/amxd_function.h>
#include <amxd/amxd_action.h>
#include <amxd/amxd_object_event.h>

#include <amxa/amxa_merger.h>
#include <amxa/amxa_permissions.h>
#include <amxa/amxa_resolver.h>
#include <amxa/amxa_validator.h>

#include <usermngt/usermngt.h>
typedef struct _pcb_request_data {
    peer_info_t* peer;
    request_t* req;
    amxb_bus_ctx_t* amxb_bus_ctx;
    amxc_var_t* acls;
} amxb_pcb_request_data_t;

static void amxb_pcb_reply_event_object(amxb_pcb_sub_t* sub,
                                        const char* str_path);

static bool amxb_pcb_is_allowed(amxb_bus_ctx_t* amxb_bus_ctx,
                                amxc_var_t* acls,
                                const char* obj_path) {
    bool retval = true;
    amxc_llist_t filters;
    amxc_var_t resolved_acls;

    amxc_var_init(&resolved_acls);
    amxc_llist_init(&filters);

    when_null(acls, exit);
    amxc_var_copy(&resolved_acls, acls);

    retval = false;

    when_failed(amxa_resolve_search_paths(amxb_bus_ctx, &resolved_acls, obj_path), exit);
    when_failed(amxa_get_filters(&resolved_acls, AMXA_PERMIT_GET, &filters, obj_path), exit);
    when_false(amxa_is_get_allowed(&filters, obj_path), exit);

    retval = true;

exit:
    amxc_var_clean(&resolved_acls);
    amxc_llist_clean(&filters, amxc_string_list_it_free);
    return retval;
}

static bool amxb_pcb_must_reply_params(const amxd_object_t* const object,
                                       uint32_t req_attrs) {

    if((amxd_object_get_type(object) == amxd_object_template) &&
       ((req_attrs & request_getObject_template_info) == 0)) {
        return false;
    }

    if((req_attrs & request_getObject_parameters) == 0) {
        return false;
    }

    return true;
}

static void amxb_pcb_reply_object_params(amxb_bus_ctx_t* amxb_bus_ctx,
                                         peer_info_t* peer,
                                         request_t* req,
                                         amxd_object_t* object,
                                         amxc_var_t* acls) {
    char* obj_path = amxd_object_get_path(object, AMXD_OBJECT_TERMINATE | AMXD_OBJECT_INDEXED);
    amxd_dm_access_t access = amxd_dm_access_public;
    amxc_llist_t filters;
    amxc_var_t params;
    amxc_var_t resolved_acls;

    amxc_var_init(&resolved_acls);
    amxc_var_copy(&resolved_acls, acls);
    amxc_llist_init(&filters);

    amxc_var_init(&params);
    if((request_attributes(req) & AMXB_PCB_PROTECTED_ACCESS) != 0) {
        access = amxd_dm_access_protected;
    }
    amxd_object_describe_params(object, &params, access);

    if(acls != NULL) {
        when_failed(amxa_resolve_search_paths(amxb_bus_ctx, &resolved_acls, obj_path), exit);
        when_failed(amxa_get_filters(&resolved_acls, AMXA_PERMIT_GET, &filters, obj_path), exit);
    }

    amxc_var_for_each(param, &params) {
        const char* param_name = amxc_var_key(param);
        if(acls == NULL) {
            amxb_pcb_serialize_object_param(peer, req, param);
        } else {
            if(amxa_is_get_param_allowed(obj_path, param_name, &filters)) {
                amxb_pcb_serialize_object_param(peer, req, param);
            }
        }
    }

    amxc_var_clean(&params);
    amxd_object_describe_events(object, &params, amxd_dm_access_protected);

    amxc_var_for_each(event, &params) {
        amxc_var_cast(event, AMXC_VAR_ID_JSON);
        amxb_pcb_serialize_object_event(peer, req, amxc_var_key(event), event);
    }

exit:
    free(obj_path);
    amxc_var_clean(&params);
    amxc_var_clean(&resolved_acls);
    amxc_llist_clean(&filters, amxc_string_list_it_free);
    return;
}

static bool amxb_pcb_filter_object(amxd_object_t* const object,
                                   int32_t depth,
                                   void* priv) {
    bool retval = true;
    amxb_pcb_request_data_t* data = (amxb_pcb_request_data_t*) priv;
    uint32_t req_attrs = request_attributes(data->req);
    amxd_object_t* parent = amxd_object_get_parent(object);
    char* obj_path = amxd_object_get_path(object, AMXD_OBJECT_TERMINATE | AMXD_OBJECT_INDEXED);

    when_true(amxd_object_get_type(object) == amxd_object_root, exit);

    if(amxd_object_is_attr_set(object, amxd_oattr_private)) {
        retval = false;
        goto exit;
    }

    if(!amxb_pcb_is_allowed(data->amxb_bus_ctx, data->acls, obj_path)) {
        amxb_pcb_serialize_error(data->peer, data->req, EACCES, "Permission denied", obj_path);
        retval = false;
        goto exit;
    }

    if(amxd_object_get_type(parent) == amxd_object_template) {
        if((amxd_object_get_type(object) == amxd_object_singleton) ||
           ( amxd_object_get_type(object) == amxd_object_template)) {
            if((req_attrs & request_getObject_template_info) == 0) {
                retval = false;
                goto exit;
            }
        } else {
            if(((req_attrs & request_getObject_instances) == 0) && (depth < 0)) {
                retval = false;
                goto exit;
            }
        }
    }
    if(((req_attrs & (request_getObject_children |
                      request_getObject_instances)) == 0) &&
       ( depth < 0)) {
        retval = false;
        goto exit;
    }

exit:
    free(obj_path);
    return retval;
}

static void amxb_pcb_reply_get_object(amxd_object_t* const object,
                                      int32_t depth,
                                      void* priv) {
    amxb_pcb_request_data_t* data = (amxb_pcb_request_data_t*) priv;
    uint32_t req_attrs = request_attributes(data->req);

    when_true(object->type == amxd_object_root, exit);

    amxb_pcb_serialize_object_begin(data->peer, data->req, object);
    if(amxb_pcb_must_reply_params(object, req_attrs)) {
        amxb_pcb_reply_object_params(data->amxb_bus_ctx, data->peer, data->req, object, data->acls);
    }
    amxb_pcb_serialize_object_end(data->peer, data->req);

    if(depth == 0) {
        bool childeren = ((amxd_object_get_type(object) == amxd_object_template &&
                           (req_attrs & request_getObject_template_info) != 0) ||
                          (amxd_object_get_type(object) != amxd_object_template));
        request_setAttributes(data->req,
                              req_attrs & ~(request_getObject_functions |
                                            request_getObject_parameters |
                                            request_getObject_children |
                                            request_getObject_instances));
        if(childeren) {
            if((req_attrs & request_getObject_children) != 0) {
                amxd_object_for_each(child, it, object) {
                    amxd_object_t* child = amxc_container_of(it, amxd_object_t, it);
                    amxb_pcb_serialize_object_begin(data->peer, data->req, child);
                    if(amxb_pcb_must_reply_params(child, request_attributes(data->req))) {
                        amxb_pcb_reply_object_params(data->amxb_bus_ctx, data->peer, data->req, child, data->acls);
                    }
                    amxb_pcb_serialize_object_end(data->peer, data->req);
                }
            }
        }
        if((req_attrs & request_getObject_instances) != 0) {
            amxd_object_for_each(instance, it, object) {
                amxd_object_t* child = amxc_container_of(it, amxd_object_t, it);
                amxb_pcb_serialize_object_begin(data->peer, data->req, child);
                if(amxb_pcb_must_reply_params(child, request_attributes(data->req))) {
                    amxb_pcb_reply_object_params(data->amxb_bus_ctx, data->peer, data->req, child, data->acls);
                }
                amxb_pcb_serialize_object_end(data->peer, data->req);
            }
        }
        request_setAttributes(data->req, req_attrs);
    }

exit:
    return;
}

static void amxb_pcb_args_to_htable_var(request_t* req,
                                        amxc_var_t* args,
                                        amxd_function_t* func) {
    argument_value_list_t* args_list = request_parameterList(req);
    argument_value_t* arg = argument_valueFirstArgument(args_list);
    uint32_t attrs = request_attributes(req);

    if((attrs & request_function_args_by_name) == request_function_args_by_name) {
        while(arg) {
            const char* arg_name = argument_valueName(arg);
            variant_t* arg_value = argument_value(arg);
            amxc_var_t* converted = amxc_var_add_new_key(args, arg_name);
            if(converted != NULL) {
                amxb_pcb_from_pcb_var(arg_value, converted);
            }
            arg = argument_valueNextArgument(arg);
        }
    } else {
        amxc_llist_for_each(it, (&func->args)) {
            amxd_func_arg_t* arg_def = amxc_llist_it_get_data(it, amxd_func_arg_t, it);
            variant_t* arg_value = argument_value(arg);
            amxc_var_t* converted = amxc_var_add_new_key(args, arg_def->name);
            if(converted != NULL) {
                amxb_pcb_from_pcb_var(arg_value, converted);
            }
            arg = argument_valueNextArgument(arg);
            if(arg == NULL) {
                break;
            }
        }
    }
}

static void amxb_pcb_exec_done(const amxc_var_t* const data,
                               void* const priv) {
    amxb_pcb_deferred_t* fcall = (amxb_pcb_deferred_t*) priv;
    amxd_status_t status = (amxd_status_t) GET_UINT32(data, "status");
    amxc_var_t* ret = GET_ARG(data, "retval");
    amxc_var_t* args = GET_ARG(data, "args");

    amxb_pcb_exec_return(status, fcall->amxb_pcb->peer, fcall->req, args, ret, NULL);
    amxb_pcb_serialize_reply_end(fcall->amxb_pcb->peer, fcall->req);
    amxb_pcb_set_request_done(fcall->amxb_pcb->peer, fcall->req);

    request_setData(fcall->req, NULL);
    request_setDestroyHandler(fcall->req, NULL);

    request_destroy(fcall->req);
    free(fcall);
}

static void amxb_pcb_exec_cancel(request_t* req, void* priv) {
    amxb_pcb_deferred_t* fcall = (amxb_pcb_deferred_t*) priv;
    amxd_function_set_deferred_cb(fcall->call_id, NULL, NULL);
    amxd_function_deferred_remove(fcall->call_id);
    request_setData(req, NULL);
    free(fcall);
}

static amxd_status_t amxb_pcb_exec_function(peer_info_t* peer,
                                            request_t* req,
                                            amxd_object_t* object,
                                            const char* func_name) {
    amxd_status_t retval = amxd_status_function_not_found;
    amxc_var_t args;
    amxc_var_t ret;
    amxd_function_t* func = amxd_object_get_function(object, func_name);
    amxb_bus_ctx_t* amxb_bus_ctx = amxb_pcb_find_peer(peer);

    when_null(amxb_bus_ctx, exit);

    if(func == NULL) {
        amxb_amxd_status_to_pcb_error(amxd_status_function_not_found, peer, req, NULL);
        goto exit;
    }
    if(object->attr.priv == 1) {
        amxb_amxd_status_to_pcb_error(amxd_status_object_not_found, peer, req, NULL);
        goto exit;
    }
    if(func->attr.priv == 1) {
        amxb_amxd_status_to_pcb_error(amxd_status_function_not_found, peer, req, NULL);
        goto exit;
    }
    amxc_var_init(&args);
    amxc_var_init(&ret);
    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);

    amxb_pcb_args_to_htable_var(req, &args, func);
    retval = amxd_object_invoke_function(object, func->name, &args, &ret);

    if(retval != amxd_status_deferred) {
        amxb_pcb_exec_return(retval, peer, req, &args, &ret, NULL);
    } else {
        uint64_t call_id = amxc_var_constcast(uint64_t, &ret);
        amxb_pcb_deferred_t* fcall = (amxb_pcb_deferred_t*) calloc(1, sizeof(amxb_pcb_deferred_t));
        fcall->req = req;
        fcall->call_id = call_id;
        fcall->amxb_pcb = (amxb_pcb_t*) amxb_bus_ctx->bus_ctx;
        request_setData(req, fcall);
        amxd_function_set_deferred_cb(call_id, amxb_pcb_exec_done, fcall);
    }

    amxc_var_clean(&args);
    amxc_var_clean(&ret);

exit:
    return retval;
}

static void amxb_pcb_notification_type(const char* sig_name,
                                       uint32_t* type,
                                       const char** name) {
    if(strcmp(sig_name, "dm:instance-added") == 0) {
        *type = notify_object_added;
        *name = "add";
    } else if(strcmp(sig_name, "dm:instance-removed") == 0) {
        *type = notify_object_deleted;
        *name = "delete";
    } else if(strcmp(sig_name, "dm:object-changed") == 0) {
        *type = notify_value_changed;
        *name = "changed";
    } else {
        *type = 1001;
        *name = "custom";
    }
}

static bool amxb_pcb_check_need_param(request_t* req, const char* key) {
    bool needed = false;
    llist_t* req_params = request_parameterList(req);

    if(llist_isEmpty(req_params)) {
        needed = true;
        goto exit;
    }

    if(request_findParameter(req, key) != NULL) {
        needed = true;
    }

exit:
    return needed;
}

static void amxb_pcb_send_object_update(amxb_pcb_sub_t* sub,
                                        const amxc_var_t* const data,
                                        uint32_t type) {
    if(((request_attributes(sub->sub_req) & request_notify_no_updates) == 0) && (type < 100)) {
        amxc_string_t event_path;
        amxc_string_init(&event_path, 0);
        if(type == notify_object_added) {
            amxc_string_setf(&event_path, "%s%d", GET_CHAR(data, "path"), GET_UINT32(data, "index"));
        } else {
            amxc_string_setf(&event_path, "%s", GET_CHAR(data, "path"));
        }
        amxb_pcb_reply_event_object(sub, amxc_string_get(&event_path, 0));
        amxc_string_clean(&event_path);
    }
}

static void amxb_pcb_send_changed_notifications(amxb_pcb_sub_t* sub,
                                                const amxc_var_t* const data,
                                                uint32_t type,
                                                const char* name,
                                                const char* path) {
    amxc_var_t* real_data = NULL;
    amxc_var_t* var_params = amxc_var_get_path(data,
                                               "parameters",
                                               AMXC_VAR_FLAG_DEFAULT);
    const amxc_htable_t* params
        = amxc_var_constcast(amxc_htable_t, var_params);
    int path_len = strlen(path);
    ((char*) path)[path_len - 1] = 0;

    amxc_var_new(&real_data);
    amxc_var_set_type(real_data, AMXC_VAR_ID_HTABLE);
    amxc_htable_for_each(hit, params) {
        const char* key = amxc_htable_it_get_key(hit);
        amxc_var_t* param_data = amxc_var_from_htable_it(hit);
        amxc_var_t* old_p = amxc_var_get_path(param_data, "from", AMXC_VAR_FLAG_DEFAULT);
        amxc_var_t* new_p = amxc_var_get_path(param_data, "to", AMXC_VAR_FLAG_DEFAULT);
        if(strcmp(key, "object") == 0) {
            continue;
        }
        if(!amxb_pcb_check_need_param(sub->sub_req, key)) {
            continue;
        }
        amxc_var_add_key(cstring_t, real_data, "parameter", key);
        amxc_var_set_key(real_data, "oldvalue", old_p, AMXC_VAR_FLAG_COPY);
        amxc_var_set_key(real_data, "newvalue", new_p, AMXC_VAR_FLAG_COPY);
        amxb_pcb_serialize_notification(sub->amxb_pcb->peer,
                                        sub->sub_req,
                                        type,
                                        name,
                                        path,
                                        real_data);
        amxb_pcb_serialize_reply_end(sub->amxb_pcb->peer, sub->sub_req);
        amxb_pcb_send_object_update(sub, data, type);
        amxc_var_clean(real_data);
        amxc_var_set_type(real_data, AMXC_VAR_ID_HTABLE);
    }

    ((char*) path)[path_len - 1] = '.';
    amxc_var_delete(&real_data);
}

static bool amxb_pcb_must_send_notif(amxb_pcb_sub_t* sub, uint32_t type) {
    bool must_send = ((request_attributes(sub->sub_req) & type) != 0);
    switch(type) {
    case notify_value_changed:
        must_send = ((request_attributes(sub->sub_req) &
                      request_notify_values_changed) != 0);
        break;
    case notify_object_added:
        must_send = ((request_attributes(sub->sub_req) &
                      request_notify_object_added) != 0);
        break;
    case notify_object_deleted:
        must_send = ((request_attributes(sub->sub_req) &
                      request_notify_object_deleted) != 0);
        break;
    }

    return must_send;
}

static void amxb_pcb_send_pcb_compat_notif(amxb_pcb_sub_t* sub,
                                           const char* path,
                                           const amxc_var_t* const data,
                                           uint32_t type,
                                           const char* name) {
    amxc_string_t str_path;
    amxc_string_init(&str_path, 0);

    if(!amxb_pcb_must_send_notif(sub, type)) {
        goto exit;
    }

    if(type == notify_object_added) {
        const char* instance_name =
            amxc_var_constcast(cstring_t, amxc_var_get_path(data, "name", 0));
        amxc_string_appendf(&str_path, "%s%s", path, instance_name);
        path = amxc_string_get(&str_path, 0);
    } else if(type == notify_object_deleted) {
        const char* instance_name =
            amxc_var_constcast(cstring_t, amxc_var_get_path(data, "name", 0));
        if(instance_name == NULL) {
            amxc_string_appendf(&str_path, "%s", path);
            str_path.last_used--;
        } else {
            amxc_string_appendf(&str_path, "%s%s", path, instance_name);
        }
        path = amxc_string_get(&str_path, 0);
    }

    if(type == notify_value_changed) {
        amxb_pcb_send_changed_notifications(sub, data, type, name, path);
    } else {
        amxb_pcb_serialize_notification(sub->amxb_pcb->peer,
                                        sub->sub_req,
                                        type,
                                        name,
                                        path,
                                        data);
        amxb_pcb_serialize_reply_end(sub->amxb_pcb->peer, sub->sub_req);
        amxb_pcb_send_object_update(sub, data, type);
    }

exit:
    amxc_string_clean(&str_path);
}

static void amxb_pcb_reply_dm_objects(request_t* req,
                                      amxd_object_t* object,
                                      amxb_pcb_request_data_t* data) {
    uint32_t depth = request_depth(req);

    if((request_attributes(req) & request_notify_only) == 0) {
        amxd_object_hierarchy_walk(object,
                                   amxd_direction_down,
                                   amxb_pcb_filter_object,
                                   amxb_pcb_reply_get_object,
                                   depth == UINT32_MAX ? INT32_MAX : depth,
                                   data);
    }
}

static void amxb_pcb_reply_event_object(amxb_pcb_sub_t* sub,
                                        const char* str_path) {
    amxc_var_t describe_args;
    amxc_var_t object_info;
    amxb_pcb_deferred_t* fcall = NULL;
    amxd_status_t status = amxd_status_ok;
    amxd_dm_access_t access = amxd_dm_access_public;
    amxd_object_t* object = NULL;
    amxd_object_t* root = amxd_dm_get_root(sub->amxb_pcb->dm);
    amxd_path_t obj_path;

    amxc_var_init(&describe_args);
    amxc_var_init(&object_info);
    amxd_path_init(&obj_path, NULL);

    if((request_attributes(sub->sub_req) & AMXB_PCB_PROTECTED_ACCESS) != 0) {
        access = amxd_dm_access_protected;
    }

    object = amxd_object_findf(root, "%s", str_path);
    if(object == NULL) {
        char* first = amxd_path_get_first(&obj_path, true);
        object = amxd_object_findf(root, "%s", first);
        free(first);
    } else {
        amxd_path_clean(&obj_path);
    }

    amxc_var_set_type(&describe_args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(bool, &describe_args, "functions", false);
    amxc_var_add_key(bool, &describe_args, "parameters", true);
    amxc_var_add_key(bool, &describe_args, "events", false);
    amxc_var_add_key(bool, &describe_args, "objects", false);
    amxc_var_add_key(bool, &describe_args, "instances", false);
    amxc_var_add_key(uint32_t, &describe_args, "access", access);
    amxc_var_add_key(cstring_t, &describe_args, "rel_path", amxd_path_get(&obj_path, AMXD_OBJECT_TERMINATE));

    fcall = (amxb_pcb_deferred_t*) calloc(1, sizeof(amxb_pcb_deferred_t));
    when_null(fcall, exit);
    fcall->req = sub->sub_req;
    fcall->amxb_pcb = sub->amxb_pcb;

    status = amxb_pcb_describe_object(fcall, object, &describe_args, &object_info);
    if(status != amxd_status_deferred) {
        free(fcall);
    }

exit:
    amxc_var_clean(&object_info);
    amxc_var_clean(&describe_args);
    amxd_path_clean(&obj_path);
}

void amxb_pcb_send_notification(const char* const sig_name,
                                const amxc_var_t* const data,
                                void* const priv) {
    amxb_pcb_sub_t* sub = (amxb_pcb_sub_t*) priv;
    char* path = NULL;
    uint32_t type = 0;
    const char* name = "";
    uint32_t path_len = 0;

    if(request_attributes(sub->sub_req) & request_common_path_key_notation) {
        path = amxc_var_dyncast(cstring_t, GET_ARG(data, "object"));
    } else {
        path = amxc_var_dyncast(cstring_t, GET_ARG(data, "path"));
    }
    amxb_pcb_notification_type(sig_name, &type, &name);

    if(type < 100) {
        if(request_attributes(sub->sub_req) & AMXB_PCB_AMX_EVENTING) {
            amxb_pcb_serialize_notification(sub->amxb_pcb->peer,
                                            sub->sub_req,
                                            1000,
                                            sig_name,
                                            path,
                                            data);
            amxb_pcb_serialize_reply_end(sub->amxb_pcb->peer, sub->sub_req);
        } else {
            amxb_pcb_send_pcb_compat_notif(sub, path, data, type, name);
        }
    } else {
        if((request_attributes(sub->sub_req) & request_notify_custom) != 0) {
            if(((request_attributes(sub->sub_req) & AMXB_PCB_AMX_EVENTING) == 0) &&
               (path != NULL) && (*path != 0)) {
                path_len = strlen(path);
                if(path[path_len - 1] == '.') {
                    path[path_len - 1] = 0;
                }
            }
            amxb_pcb_serialize_notification(sub->amxb_pcb->peer,
                                            sub->sub_req,
                                            1000,
                                            sig_name,
                                            path,
                                            data);
            amxb_pcb_serialize_reply_end(sub->amxb_pcb->peer, sub->sub_req);
        }
    }

    connection_setEventsAvailable();
    peer_flush(sub->amxb_pcb->peer);
    free(path);
}

static amxd_object_t* amxb_pcb_set_instance_attrs(request_t* req,
                                                  amxc_var_t* data,
                                                  amxd_object_t* object) {
    amxc_var_t* var_index = amxc_var_get_key(data, "index", AMXC_VAR_FLAG_DEFAULT);
    uint32_t index = amxc_var_dyncast(uint32_t, var_index);
    amxd_object_t* instance = amxd_object_get_instance(object, NULL, index);
    uint32_t attributes = request_attributes(req);

    if((attributes & (request_createObject_persistent |
                      request_createObject_not_persistent)) != 0) {
        if((attributes & request_createObject_persistent) != 0) {
            amxd_object_set_attr(instance, amxd_oattr_persistent, true);
        } else {
            amxd_object_set_attr(instance, amxd_oattr_persistent, false);
        }
    } else {
        if(amxd_object_is_attr_set(object, amxd_oattr_persistent)) {
            amxd_object_set_attr(instance, amxd_oattr_persistent, true);
        } else {
            amxd_object_set_attr(instance, amxd_oattr_persistent, false);
        }
    }

    return instance;
}

static char* amxb_pcb_get_acl_file(const char* user_name) {
    char* file = NULL;
    amxc_string_t acl_file;
    const amxc_var_t* acl_dir = amxb_pcb_get_config_option("acl-dir");

    amxc_string_init(&acl_file, 0);
    if(user_name != NULL) {
        amxc_string_setf(&acl_file, "%s/merged/%s.json", GET_CHAR(acl_dir, NULL), user_name);
        file = amxc_string_take_buffer(&acl_file);
    }

    amxc_string_clean(&acl_file);
    return file;
}

static amxc_var_t* amxb_pcb_get_acls(const char* user_name) {
    amxc_var_t* acls = NULL;
    char* acl_file = amxb_pcb_get_acl_file(user_name);

    when_null(acl_file, exit);
    acls = amxa_parse_files(acl_file);
    free(acl_file);

exit:
    return acls;
}

static void amxb_pcb_build_del_instance_args(amxc_var_t* args,
                                             amxd_object_t* instance) {
    uint32_t index = amxd_object_get_index(instance);
    const char* name = amxd_object_get_name(instance, AMXD_OBJECT_NAMED);

    amxc_var_set_type(args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(uint32_t, args, "index", index);
    amxc_var_add_key(cstring_t, args, "name", name);
}

bool amxb_pcb_get_object(peer_info_t* peer,
                         UNUSED datamodel_t* datamodel,
                         request_t* req) {
    bool retval = false;

    amxb_bus_ctx_t* amxb_bus_ctx = amxb_pcb_find_peer(peer);
    amxb_pcb_t* amxb_pcb = NULL;
    amxd_object_t* obj = NULL;
    amxc_var_t rel_path;

    amxb_pcb_request_data_t data = {
        .peer = peer,
        .req = req,
        .amxb_bus_ctx = amxb_bus_ctx,
        .acls = NULL
    };

    amxc_var_init(&rel_path);

    if(request_userID(req) != 0) {
        const usermngt_user_t* user = usermngt_userFindByID(request_userID(req));
        data.acls = amxb_pcb_get_acls(user == NULL? "untrusted":usermngt_userName(user));
        when_null(data.acls, exit);
    }

    when_null(amxb_bus_ctx, exit);
    amxb_pcb = (amxb_pcb_t*) amxb_bus_ctx->bus_ctx;
    when_null(amxb_pcb, exit);
    obj = amxb_pcb_find_object(amxb_pcb, req, &rel_path);

    if(obj == NULL) {
        if((request_attributes(req) & (request_notify_all | request_wait)) != 0) {
            char* path = amxd_object_get_path(obj, AMXD_OBJECT_TERMINATE | AMXD_OBJECT_INDEXED);
            request_setAttributes(req, request_attributes(req) | request_notify_all);
            if(amxb_pcb_handle_subscription(req, path, amxb_pcb) != 0) {
                amxb_amxd_status_to_pcb_error(amxd_status_unknown_error, peer, req, NULL);
            }
            free(path);
        } else {
            goto exit;
        }
    } else if(amxd_object_get_type(obj) == amxd_object_root) {
        uint32_t depth = request_depth(req);
        amxd_object_for_each(child, child_it, obj) {
            amxd_object_t* child = amxc_container_of(child_it, amxd_object_t, it);
            if(depth == 0) {
                uint32_t attrs = request_attributes(req);
                attrs &= ~(request_getObject_parameters | request_getObject_children);
                request_setAttributes(req, attrs);
            }
            amxb_pcb_reply_dm_objects(req, child, &data);
        }
    } else {
        const char* path = GET_CHAR(&rel_path, NULL);
        if((path != NULL) && (*path != 0)) {
            obj = amxd_object_findf(obj, "%s", path);
        }
        if(obj != NULL) {
            amxb_pcb_reply_dm_objects(req, obj, &data);
        }
        if(((request_attributes(req) & request_notify_all) != 0) ||
           ((obj == NULL) && ((request_attributes(req) & request_wait) != 0))) {
            char* obj_path = amxd_object_get_path(obj, AMXD_OBJECT_TERMINATE | AMXD_OBJECT_INDEXED);
            if(amxb_pcb_handle_subscription(req, obj_path, amxb_pcb) != 0) {
                amxb_amxd_status_to_pcb_error(amxd_status_unknown_error, peer, req, NULL);
            }
            free(obj_path);
        } else if(obj == NULL) {
            goto exit;
        }
    }
    amxb_pcb_serialize_reply_end(peer, req);
    retval = true;

exit:
    amxc_var_clean(&rel_path);

    if(!retval) {
        if(obj == NULL) {
            amxb_amxd_status_to_pcb_error(amxd_status_object_not_found, peer, req, NULL);
        }
        amxb_pcb_serialize_reply_end(peer, req);
    }
    retval = amxb_pcb_set_request_done(peer, req);
    amxc_var_delete(&data.acls);
    return retval;
}

bool amxb_pcb_set_object(peer_info_t* peer,
                         UNUSED datamodel_t* datamodel,
                         request_t* req) {
    bool retval = false;
    amxd_status_t status = amxd_status_unknown_error;
    amxb_bus_ctx_t* amxb_bus_ctx = amxb_pcb_find_peer(peer);
    amxb_pcb_t* amxb_pcb = NULL;
    amxd_object_t* object = NULL;
    amxc_var_t args;
    amxc_var_t rv;
    amxc_var_t* acls = NULL;
    amxc_var_t resolved_acls;
    amxc_var_t rel_path;
    const char* path = NULL;

    amxc_var_init(&rel_path);
    amxc_var_init(&args);
    amxc_var_init(&rv);
    amxc_var_init(&resolved_acls);

    if(request_userID(req) != 0) {
        const usermngt_user_t* user = usermngt_userFindByID(request_userID(req));
        acls = amxb_pcb_get_acls(user == NULL? "untrusted":usermngt_userName(user));
        when_null(acls, exit);
    }

    when_null(amxb_bus_ctx, exit);
    amxb_pcb = (amxb_pcb_t*) amxb_bus_ctx->bus_ctx;
    when_null(amxb_pcb, exit);
    object = amxb_pcb_find_object(amxb_pcb, req, &rel_path);
    when_null(object, exit);
    path = GET_CHAR(&rel_path, NULL);
    if((path != NULL) && (*path != 0)) {
        object = amxd_object_findf(object, "%s", path);
        when_null(object, exit);
    }

    amxb_pcb_build_set_args(&args, req);
    if(acls != NULL) {
        char* obj_path = amxd_object_get_path(object, AMXD_OBJECT_TERMINATE | AMXD_OBJECT_INDEXED);
        amxc_var_t* params = GET_ARG(&args, "parameters");
        amxc_var_copy(&resolved_acls, acls);
        amxa_resolve_search_paths(amxb_bus_ctx, &resolved_acls, obj_path);
        amxc_var_for_each(var, params) {
            const char* param = amxc_var_key(var);
            bool allowed = amxa_is_set_allowed(amxb_bus_ctx, &resolved_acls, obj_path, param);
            if(!allowed) {
                amxb_amxd_status_to_pcb_error(amxd_status_permission_denied, peer, req, NULL);
                free(obj_path);
                goto exit;
            }
        }
        free(obj_path);
    }

    status = amxd_object_invoke_function(object, "_set", &args, &rv);
    retval = status == amxd_status_ok ? true : false;

exit:
    amxc_var_clean(&rv);
    amxc_var_clean(&args);
    amxc_var_clean(&resolved_acls);
    amxc_var_clean(&rel_path);
    if(!retval) {
        if(object == NULL) {
            amxb_amxd_status_to_pcb_error(amxd_status_object_not_found, peer, req, NULL);
        } else {
            amxb_amxd_status_to_pcb_error(amxd_status_invalid_value, peer, req, NULL);
        }
    } else {
        amxb_pcb_request_data_t data = {
            .peer = peer,
            .req = req,
            .amxb_bus_ctx = amxb_bus_ctx,
            .acls = acls
        };

        request_setAttributes(req, request_attributes(req) |
                              request_getObject_parameters |
                              request_getObject_instances);
        amxb_pcb_reply_dm_objects(req, object, &data);
    }
    amxc_var_delete(&acls);
    amxb_pcb_serialize_reply_end(peer, req);
    retval = amxb_pcb_set_request_done(peer, req);
    return retval;
}

bool amxb_pcb_add_instance(peer_info_t* peer,
                           UNUSED datamodel_t* datamodel,
                           request_t* req) {
    bool retval = false;
    amxd_status_t status = amxd_status_unknown_error;
    amxb_bus_ctx_t* amxb_bus_ctx = amxb_pcb_find_peer(peer);
    amxb_pcb_t* amxb_pcb = NULL;
    amxd_object_t* object = NULL;
    amxd_object_t* instance = NULL;
    amxc_var_t args;
    amxc_var_t rv;
    amxc_var_t* acls = NULL;
    amxc_var_t resolved_acls;
    amxc_var_t rel_path;
    const char* path = NULL;

    amxc_var_init(&rel_path);
    amxc_var_init(&args);
    amxc_var_init(&rv);
    amxc_var_init(&resolved_acls);

    if(request_userID(req) != 0) {
        const usermngt_user_t* user = usermngt_userFindByID(request_userID(req));
        acls = amxb_pcb_get_acls(user == NULL? "untrusted":usermngt_userName(user));
        when_null(acls, exit);
    }

    when_null(amxb_bus_ctx, exit);
    amxb_pcb = (amxb_pcb_t*) amxb_bus_ctx->bus_ctx;
    when_null(amxb_pcb, exit);
    object = amxb_pcb_find_object(amxb_pcb, req, &rel_path);
    when_null(object, exit);
    path = GET_CHAR(&rel_path, NULL);
    if((path != NULL) && (*path != 0)) {
        object = amxd_object_findf(object, "%s", path);
        when_null(object, exit);
    }

    if(acls != NULL) {
        char* obj_path = amxd_object_get_path(object, AMXD_OBJECT_TERMINATE | AMXD_OBJECT_INDEXED);
        amxc_var_copy(&resolved_acls, acls);
        amxa_resolve_search_paths(amxb_bus_ctx, &resolved_acls, obj_path);
        if(!amxa_is_add_allowed(amxb_bus_ctx, &resolved_acls, obj_path)) {
            amxb_amxd_status_to_pcb_error(amxd_status_permission_denied, peer, req, NULL);
            free(obj_path);
            goto exit;
        }
        free(obj_path);
    }

    amxb_pcb_build_add_instance_args(&args, req);
    status = amxd_object_invoke_function(object, "_add", &args, &rv);
    retval = status == amxd_status_ok ? true : false;
    when_failed(status, exit);
    instance = amxb_pcb_set_instance_attrs(req, &rv, object);
    retval = instance == NULL ? false : true;

exit:
    amxc_var_clean(&rv);
    amxc_var_clean(&args);
    amxc_var_clean(&resolved_acls);
    amxc_var_clean(&rel_path);
    if(!retval) {
        if(object == NULL) {
            amxb_amxd_status_to_pcb_error(amxd_status_object_not_found, peer, req, NULL);
        } else {
            amxb_amxd_status_to_pcb_error(status, peer, req, NULL);
        }
    } else {
        amxb_pcb_request_data_t data = {
            .peer = peer,
            .req = req,
            .amxb_bus_ctx = amxb_bus_ctx,
            .acls = acls
        };

        request_setAttributes(req, request_attributes(req) |
                              request_getObject_parameters |
                              request_getObject_instances);
        amxb_pcb_reply_dm_objects(req, instance, &data);
    }
    amxc_var_delete(&acls);
    amxb_pcb_serialize_reply_end(peer, req);
    retval = amxb_pcb_set_request_done(peer, req);
    return retval;
}

bool amxb_pcb_del_instance(peer_info_t* peer,
                           UNUSED datamodel_t* datamodel,
                           request_t* req) {
    bool retval = false;
    amxd_status_t status = amxd_status_unknown_error;
    amxb_bus_ctx_t* amxb_bus_ctx = amxb_pcb_find_peer(peer);
    amxb_pcb_t* amxb_pcb = NULL;
    amxd_object_t* object = NULL;
    amxd_object_t* instance = NULL;
    amxc_var_t args;
    amxc_var_t rv;
    amxc_var_t* acls = NULL;
    amxc_var_t rel_path;
    const char* path = NULL;

    amxc_var_init(&rel_path);
    amxc_var_init(&args);
    amxc_var_init(&rv);

    if(request_userID(req) != 0) {
        const usermngt_user_t* user = usermngt_userFindByID(request_userID(req));
        acls = amxb_pcb_get_acls(user == NULL? "untrusted":usermngt_userName(user));
        when_null(acls, exit);
    }

    when_null(amxb_bus_ctx, exit);
    amxb_pcb = (amxb_pcb_t*) amxb_bus_ctx->bus_ctx;
    when_null(amxb_pcb, exit);
    instance = amxb_pcb_find_object(amxb_pcb, req, &rel_path);
    when_null(instance, exit);
    path = GET_CHAR(&rel_path, NULL);
    if((path != NULL) && (*path != 0)) {
        instance = amxd_object_findf(object, "%s", path);
        when_null(instance, exit);
    }

    object = amxd_object_get_parent(instance);

    if(acls != NULL) {
        char* obj_path = amxd_object_get_path(object, AMXD_OBJECT_TERMINATE | AMXD_OBJECT_INDEXED);
        amxa_resolve_search_paths(amxb_bus_ctx, acls, obj_path);
        if(!amxa_is_del_allowed(amxb_bus_ctx, acls, obj_path)) {
            amxb_amxd_status_to_pcb_error(amxd_status_permission_denied, peer, req, NULL);
            free(obj_path);
            goto exit;
        }
        free(obj_path);
    }

    amxb_pcb_build_del_instance_args(&args, instance);
    status = amxd_object_invoke_function(object, "_del", &args, &rv);
    retval = status == amxd_status_ok ? true : false;

exit:
    amxc_var_clean(&rv);
    amxc_var_clean(&args);
    amxc_var_clean(&rel_path);
    if(!retval) {
        if(object == NULL) {
            amxb_amxd_status_to_pcb_error(amxd_status_object_not_found, peer, req, NULL);
        } else {
            amxb_amxd_status_to_pcb_error(amxd_status_invalid_value, peer, req, NULL);
        }
    }
    amxc_var_delete(&acls);
    amxb_pcb_serialize_reply_end(peer, req);
    retval = amxb_pcb_set_request_done(peer, req);
    return retval;
}

bool amxb_pcb_execute(peer_info_t* peer,
                      UNUSED datamodel_t* datamodel,
                      request_t* req) {
    bool retval = false;
    amxb_bus_ctx_t* amxb_bus_ctx = amxb_pcb_find_peer(peer);
    amxb_pcb_t* amxb_pcb = NULL;
    amxd_object_t* dm_obj = NULL;
    const char* func_name = request_functionName(req);
    amxd_status_t rv = amxd_status_object_not_found;
    amxc_var_t* acls = NULL;
    amxc_var_t rel_path;
    const char* path = NULL;

    amxc_var_init(&rel_path);

    if(request_userID(req) != 0) {
        const usermngt_user_t* user = usermngt_userFindByID(request_userID(req));
        acls = amxb_pcb_get_acls(user == NULL? "untrusted":usermngt_userName(user));
        when_null(acls, exit);
    }

    when_null(amxb_bus_ctx, exit);
    amxb_pcb = (amxb_pcb_t*) amxb_bus_ctx->bus_ctx;
    when_null(amxb_pcb, exit);
    dm_obj = amxb_pcb_find_object(amxb_pcb, req, &rel_path);
    path = GET_CHAR(&rel_path, NULL);
    if((path != NULL) && (*path != 0)) {
        dm_obj = amxd_object_findf(dm_obj, "%s", path);
    }
    if(dm_obj == NULL) {
        amxb_amxd_status_to_pcb_error(amxd_status_object_not_found, peer, req, NULL);
        goto exit;
    }

    if(acls != NULL) {
        char* obj_path = amxd_object_get_path(dm_obj, AMXD_OBJECT_TERMINATE | AMXD_OBJECT_INDEXED);
        amxa_resolve_search_paths(amxb_bus_ctx, acls, obj_path);
        if(!amxa_is_operate_allowed(amxb_bus_ctx, acls, obj_path, func_name)) {
            amxb_amxd_status_to_pcb_error(amxd_status_permission_denied, peer, req, NULL);
            free(obj_path);
            goto exit;
        }
        free(obj_path);
    }

    rv = amxb_pcb_exec_function(peer, req, dm_obj, func_name);

exit:
    amxc_var_clean(&rel_path);
    if(rv != amxd_status_deferred) {
        amxb_pcb_serialize_reply_end(peer, req);
        retval = amxb_pcb_set_request_done(peer, req);
    } else {
        request_setDestroyHandler(req, amxb_pcb_exec_cancel);
        request_setBusy(req);
        retval = true;
    }
    amxc_var_delete(&acls);
    return retval;
}
