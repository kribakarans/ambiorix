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
#include <string.h>

#include <amxc/amxc.h>

#include <amxp/amxp_signal.h>
#include <amxp/amxp_slot.h>
#include <amxp/amxp_expression.h>

#include <amxd/amxd_types.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_path.h>
#include <amxd/amxd_dm.h>

#include <amxb/amxb.h>

#include <amxs/amxs_sync_ctx.h>
#include <amxs/amxs_util.h>
#include <amxs/amxs_sync_object.h>
#include <amxs/amxs_sync_param.h>

#include "amxs_priv.h"
#include "amxs_sync_entry.h"

static void amxs_callback(amxs_sync_direction_t direction,
                          const amxc_var_t* const data,
                          void* const priv,
                          bool batch) {
    amxs_status_t status = amxs_status_unknown_error;
    amxs_sync_entry_t* entry = (amxs_sync_entry_t*) priv;
    amxc_var_t trans_data;
    amxs_translation_cb_t trans_cb = batch ? amxs_sync_batch_param_copy_trans_cb : entry->translation_cb;
    amxs_action_cb_t action_cb = batch ? amxs_sync_param_copy_action_cb : entry->action_cb;

    amxc_var_init(&trans_data);

    if(trans_cb != NULL) {
        status = trans_cb(entry, direction, data, &trans_data, entry->priv);
        when_failed(status, exit);
    } else {
        amxc_var_copy(&trans_data, data);
    }

    if(action_cb != NULL) {
        status = action_cb(entry, direction, &trans_data, entry->priv);
        when_failed(status, exit);
    }

exit:
    amxc_var_clean(&trans_data);
}

static void amxs_callback_a(UNUSED const char* const sig_name,
                            const amxc_var_t* const data,
                            void* const priv) {
    amxs_callback(amxs_sync_a_to_b, data, priv, false);
}

static void amxs_callback_b(UNUSED const char* const sig_name,
                            const amxc_var_t* const data,
                            void* const priv) {
    amxs_callback(amxs_sync_b_to_a, data, priv, false);
}

static void amxs_batch_callback_a(UNUSED const char* const sig_name,
                                  const amxc_var_t* const data,
                                  void* const priv) {
    amxs_callback(amxs_sync_a_to_b, data, priv, true);
}

static void amxs_batch_callback_b(UNUSED const char* const sig_name,
                                  const amxc_var_t* const data,
                                  void* const priv) {
    amxs_callback(amxs_sync_b_to_a, data, priv, true);
}

static amxs_status_t amxs_subscribe_child_entries(amxs_sync_ctx_t* ctx,
                                                  amxs_sync_entry_t* entry,
                                                  amxs_sync_direction_t direction);

static amxs_status_t amxs_subscribe_batch_params(amxs_sync_ctx_t* ctx,
                                                 amxs_sync_entry_t* entry,
                                                 amxs_sync_direction_t direction) {
    amxs_status_t status = amxs_status_unknown_error;
    const char* object = amxs_sync_entry_get_name(ctx, direction);
    amxb_bus_ctx_t* bus_ctx = amxs_sync_ctx_get_bus_ctx(ctx, direction);
    amxp_slot_fn_t fn = direction == amxs_sync_a_to_b ? amxs_batch_callback_a : amxs_batch_callback_b;
    amxc_var_t params;
    amxb_subscription_t* sub = NULL;
    char* path = NULL;
    amxc_string_t str;
    int ret = -1;

    amxc_var_init(&params);
    amxc_var_set_type(&params, AMXC_VAR_ID_LIST);
    amxc_string_init(&str, 0);

    status = amxs_sync_entry_get_batch_params(entry, &params, direction);
    when_failed(status, exit);
    when_null_status(amxc_var_get_first(&params), exit, status = amxs_status_ok);

    path = amxs_sync_entry_get_regex_path(entry, direction);
    when_str_empty(path, exit);

    amxc_string_setf(&str, "notification matches 'dm:object-(changed|added|removed)' && path matches '%s' && (", path);
    amxc_var_for_each(var, &params) {
        amxc_string_appendf(&str, " contains('parameters.%s') ||", GET_CHAR(var, NULL));
    }
    amxc_string_remove_at(&str, amxc_string_text_length(&str) - 3, 3);
    amxc_string_append(&str, ")", 1);

    ret = amxb_subscription_new(&sub, bus_ctx, object, amxc_string_get(&str, 0), fn, entry);
    when_failed(ret, exit);
    amxc_llist_append(&ctx->subscriptions, &sub->it);

exit:
    amxc_var_clean(&params);
    free(path);
    amxc_string_clean(&str);
    return status;
}

static amxs_status_t amxs_subscribe(amxs_sync_ctx_t* ctx,
                                    amxs_sync_entry_t* entry,
                                    amxs_sync_direction_t direction) {
    amxs_status_t status = amxs_status_unknown_error;
    amxb_subscription_t* sub = NULL;
    amxc_string_t str;
    char* path = NULL;
    int ret = -1;
    amxb_bus_ctx_t* bus_ctx = amxs_sync_ctx_get_bus_ctx(ctx, direction);
    const char* object = amxs_sync_entry_get_name(ctx, direction);
    const char* name = amxs_sync_entry_get_name(entry, direction);
    amxp_slot_fn_t fn = direction == amxs_sync_a_to_b ? amxs_callback_a : amxs_callback_b;
    amxd_path_t p;

    amxd_path_init(&p, name);
    amxc_string_init(&str, 0);

    switch(entry->type) {
    case amxs_sync_type_param:
        if(amxs_sync_entry_is_batch_param(entry)) {
            break;
        }
        amxc_string_setf(&str, "notification matches 'dm:object-(changed|added|removed)' && contains('parameters.%s')", name);
        path = amxs_sync_entry_get_regex_parent_path(entry, direction);
        when_str_empty(path, exit);
        amxc_string_appendf(&str, " && path matches '%s'", path);
        ret = amxb_subscription_new(&sub, bus_ctx, object, amxc_string_get(&str, 0), fn, entry);
        amxp_slot_connect(amxs_sync_entry_get_signal_manager(entry), "sync:instance-added", amxc_string_get(&str, 0), fn, entry);
        when_failed(ret, exit);
        amxc_llist_append(&ctx->subscriptions, &sub->it);
        break;
    case amxs_sync_type_object:
        if(amxd_path_is_instance_path(&p)) {
            amxs_subscribe_batch_params(ctx, entry, direction);
            amxs_subscribe_child_entries(ctx, entry, direction);
            break;
        }
        path = amxs_sync_entry_get_regex_path(entry, direction);
        when_str_empty(path, exit);
        amxc_string_setf(&str, "notification matches 'dm:instance-*' && path matches '%s'", path);
        ret = amxb_subscription_new(&sub, bus_ctx, object, amxc_string_get(&str, 0), fn, entry);
        when_failed(ret, exit);
        amxc_llist_append(&ctx->subscriptions, &sub->it);
        amxs_subscribe_batch_params(ctx, entry, direction);
        amxs_subscribe_child_entries(ctx, entry, direction);
        break;
    case amxs_sync_type_ctx:
        amxs_subscribe_batch_params(ctx, entry, direction);
        amxs_subscribe_child_entries(ctx, entry, direction);
        break;
    default:
        break;
    }

    status = amxs_status_ok;

exit:
    amxd_path_clean(&p);
    free(path);
    amxc_string_clean(&str);
    return status;
}

static amxs_status_t amxs_subscribe_child_entries(amxs_sync_ctx_t* ctx,
                                                  amxs_sync_entry_t* entry,
                                                  amxs_sync_direction_t direction) {
    amxs_status_t status = amxs_status_unknown_error;

    amxc_llist_for_each(it, &entry->entries) {
        amxs_sync_entry_t* child = amxc_container_of(it, amxs_sync_entry_t, it);
        if(amxs_sync_entry_direction_allowed(child, direction)) {
            status = amxs_subscribe(ctx, child, direction);
            when_failed(status, exit);
        }
    }

    status = amxs_status_ok;

exit:
    return status;
}

static int amxs_var_find_keys_regex(const amxc_var_t* var,
                                    amxc_llist_t* paths,
                                    const char* expr_str) {
    amxc_string_t str;
    int ret = -1;

    amxc_string_init(&str, 0);

    amxc_var_for_each(variant, var) {
        amxp_expr_t expr;
        amxp_expr_status_t status;

        amxc_string_setf(&str, "'%s' matches '%s'", amxc_var_key(variant), expr_str);
        status = amxp_expr_init(&expr, amxc_string_get(&str, 0));
        when_failed(status, exit);
        if(amxp_expr_eval(&expr, &status)) {
            amxc_llist_add_string(paths, amxc_var_key(variant));
        }
        amxp_expr_clean(&expr);
    }

    ret = 0;

exit:
    amxc_string_clean(&str);
    return ret;
}

static void amxs_var_fill_initial_instance_data(const char* object,
                                                const char* instance,
                                                amxc_var_t* init_data,
                                                const amxc_var_t* data) {
    unsigned int index = strtoul(instance + strlen(object), NULL, 0);
    amxc_var_t* tmp = NULL;

    amxc_var_set_type(init_data, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, init_data, "path", object);
    amxc_var_add_key(cstring_t, init_data, "notification", "sync:init-object");
    amxc_var_add_key(uint32_t, init_data, "index", index);
    tmp = amxc_var_add_new_key(init_data, "parameters");
    amxc_var_copy(tmp, GET_ARG(data, instance));
}

static void amxs_var_fill_initial_param_data(const char* object,
                                             const char* name,
                                             amxc_var_t* init_data,
                                             const amxc_var_t* data) {
    amxc_var_t* params = NULL;
    amxc_var_t* param = NULL;

    amxc_var_set_type(init_data, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, init_data, "path", object);
    amxc_var_add_key(cstring_t, init_data, "notification", "sync:init-param");
    params = amxc_var_add_new_key(init_data, "parameters");
    amxc_var_set_type(params, AMXC_VAR_ID_HTABLE);
    param = amxc_var_add_new_key(params, name);
    amxc_var_copy(param, data);
}

static amxs_status_t amxs_initial_sync_child_entries(amxs_sync_entry_t* entry,
                                                     const char* const parent_path,
                                                     amxs_sync_direction_t parent_direction,
                                                     const amxc_var_t* const data_a,
                                                     const amxc_var_t* const data_b);

static void amxs_var_fill_initial_batch_param_data(const char* object,
                                                   amxc_var_t* init_data,
                                                   const amxc_var_t* data) {
    amxc_var_t* params = NULL;

    amxc_var_set_type(init_data, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, init_data, "path", object);
    amxc_var_add_key(cstring_t, init_data, "notification", "sync:init-batch-param");
    params = amxc_var_add_new_key(init_data, "parameters");
    amxc_var_set_type(params, AMXC_VAR_ID_HTABLE);
    amxc_var_copy(params, data);
}

static amxs_status_t amxs_initial_sync_batch_params(UNUSED amxs_sync_entry_t* entry,
                                                    UNUSED const char* const object,
                                                    UNUSED amxs_sync_direction_t direction,
                                                    UNUSED const amxc_var_t* const data) {
    amxs_status_t status = amxs_status_unknown_error;
    amxc_var_t init_data;
    amxc_var_t* var = GET_ARG(data, object);

    amxc_var_init(&init_data);

    when_null_status(var, exit, status = amxs_status_object_not_found);

    amxs_var_fill_initial_batch_param_data(object, &init_data, var);
    amxs_callback(direction, &init_data, entry, true);

    status = amxs_status_ok;

exit:
    amxc_var_clean(&init_data);
    return status;
}

static amxs_status_t amxs_initial_sync_object(amxs_sync_entry_t* entry,
                                              const char* const object,
                                              amxs_sync_direction_t direction,
                                              const amxc_var_t* const data_a,
                                              const amxc_var_t* const data_b) {
    amxs_status_t status = amxs_status_unknown_error;
    const amxc_var_t* data = direction == amxs_sync_a_to_b ? data_a : data_b;
    amxc_string_t str;
    amxc_llist_t list;
    amxc_var_t init_data;

    amxc_string_init(&str, 0);
    amxc_llist_init(&list);
    amxc_var_init(&init_data);

    amxc_string_setf(&str, "%s[0-9]+\\.$", object);
    when_failed(amxs_var_find_keys_regex(data, &list, amxc_string_get(&str, 0)), exit);

    // This only lists instance objects
    amxc_llist_for_each(it, &list) {
        const char* instance = amxc_string_get(amxc_llist_it_get_data(it, amxc_string_t, it), 0);

        amxs_var_fill_initial_instance_data(object, instance, &init_data, data);
        amxs_callback(direction, &init_data, entry, false);

        status = amxs_initial_sync_child_entries(entry, instance, direction, data_a, data_b);
        when_failed(status, exit);
    }

    // find variant with the exact object name
    // this will match in case the object is an instance or a non template object
    if(amxc_var_get_pathf(data, AMXC_VAR_FLAG_DEFAULT, "'%s'", object) != NULL) {
        status = amxs_initial_sync_batch_params(entry, object, direction, data);
        when_failed(status, exit);
    }

    if(GET_ARG(data, object) != NULL) {
        status = amxs_initial_sync_child_entries(entry, object, direction, data_a, data_b);
        when_failed(status, exit);
    }

    status = amxs_status_ok;

exit:
    amxc_string_clean(&str);
    amxc_llist_clean(&list, amxc_string_list_it_free);
    amxc_var_clean(&init_data);
    return status;
}

static amxs_status_t amxs_initial_sync_param(amxs_sync_entry_t* entry,
                                             const char* const object,
                                             const char* const param,
                                             amxs_sync_direction_t direction,
                                             const amxc_var_t* const data) {
    amxs_status_t status = amxs_status_unknown_error;
    amxc_var_t init_data;
    amxc_var_t* var = GET_ARG(data, object);

    amxc_var_init(&init_data);

    when_true_status(amxs_sync_entry_is_batch_param(entry), exit, status = amxs_status_ok);
    when_null_status(var, exit, status = amxs_status_object_not_found);

    var = GET_ARG(var, param);
    when_null_status(var, exit, status = amxs_status_ok);

    amxs_var_fill_initial_param_data(object, param, &init_data, var);
    amxs_callback(direction, &init_data, entry, false);

    status = amxs_status_ok;

exit:
    amxc_var_clean(&init_data);
    return status;
}

static amxs_status_t amxs_initial_sync_entry(amxs_sync_entry_t* entry,
                                             const char* const parent_path,
                                             amxs_sync_direction_t parent_direction,
                                             const amxc_var_t* const data_a,
                                             const amxc_var_t* const data_b) {
    amxs_status_t status = amxs_status_unknown_error;
    amxs_sync_direction_t direction = amxs_sync_entry_get_initial_direction(entry);
    const amxc_var_t* data = direction == amxs_sync_a_to_b ? data_a : data_b;
    const char* name = NULL;
    amxc_string_t object;

    when_null(data, exit);

    amxc_string_init(&object, 0);

    name = amxs_sync_entry_get_name(entry, direction);
    if(direction != parent_direction) {
        char* opposite_parent_path = amxs_sync_entry_get_opposite_parent_path(entry, parent_direction, parent_path);
        amxc_string_set(&object, opposite_parent_path);
        free(opposite_parent_path);
    } else {
        amxc_string_set(&object, parent_path);
    }

    switch(entry->type) {
    case amxs_sync_type_ctx:
        status = amxs_initial_sync_object(entry, name, direction, data_a, data_b);
        when_failed(status, exit);
        break;
    case amxs_sync_type_object:
        amxc_string_appendf(&object, "%s", name);
        status = amxs_initial_sync_object(entry, amxc_string_get(&object, 0), direction, data_a, data_b);
        break;
    case amxs_sync_type_param:
        status = amxs_initial_sync_param(entry, amxc_string_get(&object, 0), name, direction, data);
        break;
    default:
        break;
    }

exit:
    amxc_string_clean(&object);
    return status;
}

static amxs_status_t amxs_initial_sync_child_entries(amxs_sync_entry_t* entry,
                                                     const char* const parent_path,
                                                     amxs_sync_direction_t parent_direction,
                                                     const amxc_var_t* const data_a,
                                                     const amxc_var_t* const data_b) {
    amxs_status_t status = amxs_status_unknown_error;

    amxc_llist_for_each(it, &entry->entries) {
        amxs_sync_entry_t* child = amxc_container_of(it, amxs_sync_entry_t, it);
        status = amxs_initial_sync_entry(child, parent_path, parent_direction, data_a, data_b);
        when_failed(status, exit);
    }

    status = amxs_status_ok;

exit:
    return status;
}

static amxd_object_type_t amxb_get_object_type(amxb_bus_ctx_t* ctx, const char* path) {
    amxd_object_type_t rv = amxd_object_singleton;
    amxc_var_t ret;

    amxc_var_init(&ret);
    if(amxb_describe(ctx, path, 0, &ret, 5) == 0) {
        rv = (amxd_object_type_t) GETP_UINT32(&ret, "0.type_id");
    }
    amxc_var_clean(&ret);

    return rv;
}

static uint32_t amxs_sync_depth(amxs_sync_ctx_t* sync_ctx,
                                amxs_sync_entry_t* sync_entry,
                                amxs_sync_direction_t direction,
                                amxc_string_t* path,
                                uint32_t start) {
    uint32_t depth = start;
    uint32_t path_pos = amxc_string_text_length(path);
    const char* sync_path = NULL;
    amxb_bus_ctx_t* ctx = NULL;
    amxd_path_t rel_path;
    char* part = NULL;
    char* endptr = NULL;
    amxd_object_type_t type = amxd_object_singleton;

    sync_entry = sync_entry == NULL? sync_ctx:sync_entry;
    ctx = (direction == amxs_sync_a_to_b)? sync_ctx->bus_ctx_a:sync_ctx->bus_ctx_b;
    sync_path = (direction == amxs_sync_a_to_b)? sync_entry->a: sync_entry->b;

    when_null(sync_path, exit);

    amxd_path_init(&rel_path, sync_path);
    amxc_string_appendf(path, "%s", sync_path);
    start += (sync_entry == sync_ctx)? 0:amxd_path_get_depth(&rel_path);

    part = amxd_path_get_first(&rel_path, true);
    if(strtoull(part, &endptr, 10) != 0) {
        // if the relative path starts with a number then it is an instance
        // decrease by 1 as the parent sync entry already added 1 for a template
        start -= 1;
    }
    free(part);
    amxd_path_clean(&rel_path);

    depth = start;
    amxc_llist_iterate(it, &sync_entry->entries) {
        uint32_t tree_depth = 0;
        amxs_sync_entry_t* entry = amxc_container_of(it, amxs_sync_entry_t, it);
        if(entry->type == amxs_sync_type_object) {
            tree_depth = amxs_sync_depth(sync_ctx, entry, direction, path, start);
            if(tree_depth > depth) {
                depth = tree_depth;
            }
        }
    }

    // If the current entry in the sync hierarchy is a template object the instances must be
    // monitored as well, so add 1 in the depth
    type = amxb_get_object_type(ctx, amxc_string_get(path, 0));
    if(type == amxd_object_template) {
        depth++;
    }

    amxc_string_remove_at(path, path_pos, strlen(sync_path));

exit:
    return depth;
}

static amxs_status_t amxs_do_initial_sync(amxs_sync_ctx_t* ctx) {
    amxs_status_t status = amxs_status_unknown_error;
    int ret = -1;
    amxc_var_t data_a;
    amxc_var_t data_b;
    uint32_t orig_access = AMXB_PROTECTED;
    uint32_t depth = 0;
    amxc_string_t path;
    amxs_sync_direction_t direction = amxs_sync_entry_get_initial_direction(ctx);
    bool bidirectional = amxs_sync_entry_is_bidirectional(ctx);

    amxc_var_init(&data_a);
    amxc_var_init(&data_b);
    amxc_string_init(&path, 64);

    if((direction == amxs_sync_a_to_b) || bidirectional) {
        if((ctx->bus_ctx_a != NULL) && (ctx->bus_ctx_a->access != AMXB_PROTECTED)) {
            orig_access = ctx->bus_ctx_a->access;
            amxb_set_access(ctx->bus_ctx_a, AMXB_PROTECTED);
        }
        depth = amxs_sync_depth(ctx, NULL, amxs_sync_a_to_b, &path, 0);
        ret = amxb_get(ctx->bus_ctx_a, ctx->a, depth, &data_a, 5);
        amxb_set_access(ctx->bus_ctx_a, orig_access);
        if((ctx->attributes & AMXS_SYNC_ONLY_B_TO_A) == 0) {
            when_failed(ret, exit);
        }
    }

    if((direction == amxs_sync_b_to_a) || bidirectional) {
        if((ctx->bus_ctx_b != NULL) && (ctx->bus_ctx_b->access != AMXB_PROTECTED)) {
            orig_access = ctx->bus_ctx_b->access;
            amxb_set_access(ctx->bus_ctx_b, AMXB_PROTECTED);
        }
        depth = amxs_sync_depth(ctx, NULL, amxs_sync_b_to_a, &path, 0);
        ret = amxb_get(ctx->bus_ctx_b, ctx->b, depth, &data_b, 5);
        amxb_set_access(ctx->bus_ctx_b, orig_access);
        if((ctx->attributes & AMXS_SYNC_ONLY_A_TO_B) == 0) {
            when_failed(ret, exit);
        }
    }

    status = amxs_initial_sync_entry(ctx, NULL, amxs_sync_invalid, GETI_ARG(&data_a, 0), GETI_ARG(&data_b, 0));

exit:
    amxc_string_clean(&path);
    amxc_var_clean(&data_a);
    amxc_var_clean(&data_b);
    return status;
}

static amxs_status_t amxs_sync_ctx_validate_path(amxs_sync_ctx_t* ctx, amxs_sync_direction_t direction) {
    amxc_var_t data;
    amxb_bus_ctx_t* bus_ctx = NULL;
    char** path = NULL;
    const char* new_path = NULL;
    amxs_status_t stat = amxs_status_object_not_found;
    int ret = -1;
    amxc_llist_it_t* it = NULL;
    amxd_path_t p;

    amxc_var_init(&data);
    amxd_path_init(&p, NULL);
    when_null(ctx, exit);

    bus_ctx = direction == amxs_sync_a_to_b ? ctx->bus_ctx_a : ctx->bus_ctx_b;
    path = direction == amxs_sync_a_to_b ? &ctx->a : &ctx->b;

    when_null(bus_ctx, exit);
    when_str_empty(*path, exit);

    amxd_path_setf(&p, true, "%s", *path);
    ret = amxb_resolve(bus_ctx, &p, &data);
    when_failed(ret, exit);

    it = amxc_llist_get_first(amxc_var_constcast(amxc_llist_t, &data));
    if((it == NULL) || (amxc_llist_it_get_next(it) != NULL)) {
        goto exit;
    }

    new_path = GET_CHAR(amxc_llist_it_get_data(it, amxc_var_t, lit), NULL);
    when_str_empty(new_path, exit);
    free(*path);
    *path = strdup(new_path);

    stat = amxs_status_ok;

exit:
    amxd_path_clean(&p);
    amxc_var_clean(&data);
    return stat;
}

static amxs_status_t amxs_sync_ctx_verify_local_dm(amxs_sync_ctx_t* ctx,
                                                   amxs_sync_direction_t direction) {
    amxs_status_t status = amxs_status_unknown_error;
    amxd_dm_t* dm = NULL;
    const char* path = NULL;

    when_null(ctx, exit);

    dm = direction == amxs_sync_a_to_b ? ctx->local_dm_b : ctx->local_dm_a;
    path = direction == amxs_sync_a_to_b ? ctx->b : ctx->a;
    when_null_status(dm, exit, status = amxs_status_ok);

    when_null_status(amxd_dm_findf(dm, "%s", path), exit, status = amxs_status_object_not_found);

    status = amxs_status_ok;

exit:
    return status;
}

static bool amxs_sync_ctx_paths_match(const char* new_path, const char* old_path) {
    bool retval = false;
    amxd_path_t old_p;
    amxd_path_t new_p;
    char* supported_old = NULL;
    char* supported_new = NULL;

    amxd_path_init(&old_p, NULL);
    amxd_path_init(&new_p, NULL);

    amxd_path_setf(&old_p, false, "%s", new_path);
    amxd_path_setf(&new_p, false, "%s", old_path);

    supported_old = amxd_path_get_supported_path(&old_p);
    supported_new = amxd_path_get_supported_path(&new_p);

    retval = strcmp(supported_old, supported_new) == 0;

    free(supported_old);
    free(supported_new);
    amxd_path_clean(&old_p);
    amxd_path_clean(&new_p);

    return retval;
}

amxs_status_t amxs_sync_ctx_new(amxs_sync_ctx_t** ctx,
                                const char* object_a,
                                const char* object_b,
                                int attributes) {
    return amxs_sync_entry_new(ctx,
                               object_a,
                               object_b,
                               attributes,
                               NULL,
                               NULL,
                               amxs_sync_type_ctx,
                               NULL);
}

void amxs_sync_ctx_delete(amxs_sync_ctx_t** ctx) {
    when_null(ctx, exit);
    when_null(*ctx, exit);
    when_false((*ctx)->type == amxs_sync_type_ctx, exit);

    amxs_sync_entry_delete(ctx);

exit:
    return;
}

amxs_status_t amxs_sync_ctx_init(amxs_sync_ctx_t* ctx,
                                 const char* object_a,
                                 const char* object_b,
                                 int attributes) {
    return amxs_sync_entry_init(ctx,
                                object_a,
                                object_b,
                                attributes,
                                NULL,
                                NULL,
                                amxs_sync_type_ctx,
                                NULL);
}

void amxs_sync_ctx_clean(amxs_sync_ctx_t* ctx) {
    when_null(ctx, exit);
    when_false(ctx->type == amxs_sync_type_ctx, exit);

    amxs_sync_entry_clean(ctx);

exit:
    return;
}

amxs_status_t amxs_sync_ctx_copy(amxs_sync_ctx_t** dest, amxs_sync_ctx_t* src, void* priv) {
    return amxs_sync_entry_copy(dest, src, priv);
}

amxs_status_t amxs_sync_ctx_start_sync(amxs_sync_ctx_t* ctx) {
    amxs_status_t status = amxs_status_unknown_error;
    when_null(ctx, exit);

    when_false_status(ctx->type == amxs_sync_type_ctx, exit, status = amxs_status_invalid_type);
    when_true_status(amxc_llist_is_empty(&ctx->entries), exit, status = amxs_status_empty_context);

    if(ctx->bus_ctx_a == NULL) {
        ctx->bus_ctx_a = amxb_be_who_has(ctx->a);
    }
    if(ctx->bus_ctx_b == NULL) {
        ctx->bus_ctx_b = amxb_be_who_has(ctx->b);
    }

    if((ctx->attributes & AMXS_SYNC_ONLY_B_TO_A) == 0) {
        when_null_status(ctx->bus_ctx_a, exit, status = amxs_status_object_not_found);
        when_failed_status(amxs_sync_ctx_validate_path(ctx, amxs_sync_a_to_b), exit,
                           status = amxs_status_object_not_found);
        when_failed_status(amxs_sync_ctx_verify_local_dm(ctx, amxs_sync_b_to_a), exit,
                           status = amxs_status_object_not_found);
    }

    if((ctx->attributes & AMXS_SYNC_ONLY_A_TO_B) == 0) {
        when_null_status(ctx->bus_ctx_b, exit, status = amxs_status_object_not_found);
        when_failed_status(amxs_sync_ctx_validate_path(ctx, amxs_sync_b_to_a), exit,
                           status = amxs_status_object_not_found);
        when_failed_status(amxs_sync_ctx_verify_local_dm(ctx, amxs_sync_a_to_b), exit,
                           status = amxs_status_object_not_found);
    }

    if((ctx->attributes & AMXS_SYNC_ONLY_B_TO_A) == 0) {
        status = amxs_subscribe(ctx, ctx, amxs_sync_a_to_b);
        when_failed(status, cleanup_subs);
    }

    if((ctx->attributes & AMXS_SYNC_ONLY_A_TO_B) == 0) {
        status = amxs_subscribe(ctx, ctx, amxs_sync_b_to_a);
        when_failed(status, cleanup_subs);
    }

    status = amxs_do_initial_sync(ctx);
    when_failed(status, cleanup_subs);

cleanup_subs:
    if(status != amxs_status_ok) {
        amxc_llist_clean(&ctx->subscriptions, amxs_llist_it_delete_subscription);
    }

exit:
    return status;
}

void amxs_sync_ctx_stop_sync(amxs_sync_ctx_t* ctx) {
    when_null(ctx, exit);
    when_false(ctx->type == amxs_sync_type_ctx, exit);

    amxc_llist_clean(&ctx->subscriptions, amxs_llist_it_delete_subscription);

exit:
    return;
}

amxs_status_t amxs_sync_ctx_set_paths(amxs_sync_ctx_t* const ctx,
                                      const char* object_a,
                                      const char* object_b) {
    amxs_status_t status = amxs_status_unknown_error;
    char* supported_a = NULL;
    char* supported_b = NULL;

    when_null(ctx, exit);
    when_str_empty_status(object_a, exit, status = amxs_status_invalid_arg);
    when_str_empty_status(object_b, exit, status = amxs_status_invalid_arg);

    supported_a = ctx->a;
    supported_b = ctx->b;

    ctx->a = strdup(object_a);
    ctx->b = strdup(object_b);

    if(ctx->bus_ctx_a == NULL) {
        ctx->bus_ctx_a = amxb_be_who_has(ctx->a);
    }
    if(ctx->bus_ctx_b == NULL) {
        ctx->bus_ctx_b = amxb_be_who_has(ctx->b);
    }

    when_failed_status(amxs_sync_ctx_validate_path(ctx, amxs_sync_a_to_b), exit,
                       status = amxs_status_object_not_found);
    when_failed_status(amxs_sync_ctx_validate_path(ctx, amxs_sync_b_to_a), exit,
                       status = amxs_status_object_not_found);

    when_false_status(amxs_sync_ctx_paths_match(ctx->a, supported_a), exit, status = amxs_status_invalid_arg);
    when_false_status(amxs_sync_ctx_paths_match(ctx->b, supported_b), exit, status = amxs_status_invalid_arg);

    status = amxs_status_ok;

exit:
    free(supported_a);
    free(supported_b);
    return status;
}

amxs_status_t amxs_sync_ctx_add_param(amxs_sync_ctx_t* ctx, amxs_sync_param_t* param) {
    amxs_status_t status = amxs_status_unknown_error;
    when_null(ctx, exit);
    when_null(param, exit);
    when_false_status(ctx->type == amxs_sync_type_ctx, exit, status = amxs_status_invalid_type);
    when_false_status(param->type == amxs_sync_type_param, exit, status = amxs_status_invalid_type);

    status = amxs_sync_entry_add_entry(ctx, param);

exit:
    return status;
}

amxs_status_t amxs_sync_ctx_add_new_param(amxs_sync_ctx_t* ctx,
                                          const char* param_a,
                                          const char* param_b,
                                          int attributes,
                                          amxs_translation_cb_t translation_cb,
                                          amxs_action_cb_t action_cb,
                                          void* priv) {
    amxs_status_t status = amxs_status_unknown_error;
    amxs_sync_param_t* param = NULL;

    status = amxs_sync_param_new(&param, param_a, param_b, attributes, translation_cb, action_cb, priv);
    when_failed(status, exit);

    status = amxs_sync_ctx_add_param(ctx, param);
    if(status != amxs_status_ok) {
        amxs_sync_param_delete(&param);
    }

exit:
    return status;
}

amxs_status_t amxs_sync_ctx_add_new_copy_param(amxs_sync_ctx_t* ctx,
                                               const char* param_a,
                                               const char* param_b,
                                               int attributes) {
    return amxs_sync_ctx_add_new_param(ctx,
                                       param_a,
                                       param_b,
                                       attributes | AMXS_SYNC_PARAM_BATCH,
                                       NULL,
                                       NULL,
                                       NULL);
}

amxs_status_t amxs_sync_ctx_add_object(amxs_sync_ctx_t* ctx, amxs_sync_object_t* object) {
    amxs_status_t status = amxs_status_unknown_error;
    when_null(ctx, exit);
    when_null(object, exit);
    when_false_status(ctx->type == amxs_sync_type_ctx, exit, status = amxs_status_invalid_type);
    when_false_status(object->type == amxs_sync_type_object, exit, status = amxs_status_invalid_type);

    status = amxs_sync_entry_add_entry(ctx, object);

exit:
    return status;
}

amxs_status_t amxs_sync_ctx_add_new_object(amxs_sync_ctx_t* ctx,
                                           const char* object_a,
                                           const char* object_b,
                                           int attributes,
                                           amxs_translation_cb_t translation_cb,
                                           amxs_action_cb_t action_cb,
                                           void* priv) {
    amxs_status_t status = amxs_status_unknown_error;
    amxs_sync_object_t* object = NULL;

    status = amxs_sync_object_new(&object, object_a, object_b, attributes, translation_cb, action_cb, priv);
    when_failed(status, exit);

    status = amxs_sync_ctx_add_object(ctx, object);
    if(status != amxs_status_ok) {
        amxs_sync_object_delete(&object);
    }

exit:
    return status;
}

amxs_status_t amxs_sync_ctx_add_new_copy_object(amxs_sync_ctx_t* ctx,
                                                const char* object_a,
                                                const char* object_b,
                                                int attributes) {
    return amxs_sync_ctx_add_new_object(ctx,
                                        object_a,
                                        object_b,
                                        attributes,
                                        amxs_sync_object_copy_trans_cb,
                                        amxs_sync_object_copy_action_cb,
                                        NULL);
}

amxs_status_t amxs_sync_ctx_set_local_dm(amxs_sync_ctx_t* ctx,
                                         amxd_dm_t* dm_a,
                                         amxd_dm_t* dm_b) {
    amxs_status_t status = amxs_status_unknown_error;
    when_null(ctx, exit);
    when_false_status(ctx->type == amxs_sync_type_ctx, exit, status = amxs_status_invalid_type);

    if(((ctx->attributes & AMXS_SYNC_ONLY_B_TO_A) != 0) && (dm_b != NULL)) {
        status = amxs_status_invalid_arg;
        goto exit;
    }

    if(((ctx->attributes & AMXS_SYNC_ONLY_A_TO_B) != 0) && (dm_a != NULL)) {
        status = amxs_status_invalid_arg;
        goto exit;
    }

    ctx->local_dm_a = dm_a;
    ctx->local_dm_b = dm_b;

    status = amxs_status_ok;

exit:
    return status;
}
