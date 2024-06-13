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

#include <amxp/amxp.h>

#include <amxd/amxd_object.h>
#include <amxd/amxd_path.h>
#include <amxd/amxd_transaction.h>
#include <amxd/amxd_dm.h>

#include <amxs/amxs_types.h>
#include <amxs/amxs_util.h>

#include "amxs_priv.h"

bool amxs_sync_entry_remove_bidrection_object(const amxs_sync_entry_t* entry,
                                              amxs_sync_direction_t direction,
                                              const char* path) {
    bool ret = false;
    amxc_var_t* opposite_list = NULL;
    amxc_var_t* opposite = NULL;
    amxs_sync_ctx_t* ctx = amxs_sync_entry_get_ctx(entry);

    when_null(entry, exit);
    when_null(ctx, exit);
    when_str_empty(path, exit);
    when_false(amxs_sync_entry_is_bidirectional(entry), exit);

    opposite_list = direction == amxs_sync_a_to_b ? &ctx->b_to_a : &ctx->a_to_b;
    opposite = GET_ARG(opposite_list, path);

    if(opposite != NULL) {
        amxc_var_delete(&opposite);
        ret = true;
    }

exit:
    return ret;
}

bool amxs_sync_entry_check_bidrection_object(const amxs_sync_entry_t* entry,
                                             amxs_sync_direction_t direction,
                                             const char* path,
                                             const char* opposite_path) {
    bool ret = false;
    amxd_path_t check_path;
    amxc_var_t* opposite_list = NULL;
    amxc_var_t* current_list = NULL;
    amxc_var_t* opposite = NULL;
    amxs_sync_ctx_t* ctx = amxs_sync_entry_get_ctx(entry);

    amxd_path_init(&check_path, opposite_path);

    when_null(entry, exit);
    when_null(ctx, exit);
    when_str_empty(path, exit);
    when_str_empty(opposite_path, exit);
    when_false(amxs_sync_entry_is_bidirectional(entry), exit);

    opposite_list = direction == amxs_sync_a_to_b ? &ctx->b_to_a : &ctx->a_to_b;
    current_list = direction == amxs_sync_a_to_b ? &ctx->a_to_b : &ctx->b_to_a;
    opposite = GET_ARG(opposite_list, path);

    when_true(amxd_path_is_instance_path(&check_path), exit);

    if(opposite != NULL) {
        amxc_var_delete(&opposite);
        ret = true;
    } else {
        amxc_var_add_key(bool, current_list, opposite_path, true);
    }

exit:
    amxd_path_clean(&check_path);
    return ret;
}

static bool amxs_sync_entry_check_bidirectional_param(amxc_var_t* list,
                                                      amxc_var_t* value) {
    bool ret = false;

    when_null(list, exit);
    when_null(value, exit);

    amxc_var_for_each(var, list) {
        int count = 1;
        int result = 0;

        if((amxc_var_compare(value, var, &result) == 0) && (result == 0)) {
            amxc_var_for_each(var_rm, list) {
                amxc_var_take_it(var_rm);
                amxc_var_delete(&var_rm);
                count--;
                if(count == 0) {
                    break;
                }
            }
            ret = true;
            goto exit;
        }
        count++;
    }

exit:
    return ret;
}

bool amxs_sync_entry_check_bidirectional_loop(const amxs_sync_entry_t* entry,
                                              amxs_sync_direction_t direction,
                                              amxc_var_t* value,
                                              const char* path,
                                              const char* opposite_path) {
    bool ret = false;
    amxc_string_t str;
    amxc_var_t* current_list = NULL;
    amxc_var_t* opposite_list = NULL;
    amxc_var_t* current_table = NULL;
    amxc_var_t* opposite_table = NULL;
    amxc_var_t* value_storage = NULL;
    amxs_sync_ctx_t* ctx = amxs_sync_entry_get_ctx(entry);

    amxc_string_init(&str, 0);

    when_null(entry, exit);
    when_null(ctx, exit);
    when_null(value, exit);
    when_str_empty(path, exit);
    when_str_empty(opposite_path, exit);
    when_false(amxs_sync_entry_is_bidirectional(entry), exit);

    opposite_table = direction == amxs_sync_a_to_b ? &ctx->b_to_a : &ctx->a_to_b;
    current_table = direction == amxs_sync_a_to_b ? &ctx->a_to_b : &ctx->b_to_a;

    // Find current path in opposite table
    amxc_string_setf(&str, "%s%s", path, amxs_sync_entry_get_name(entry, direction));
    opposite_list = GET_ARG(opposite_table, amxc_string_get(&str, 0));
    if(opposite_list != NULL) {
        // Entry found, do the regular loop detection for parameters
        ret = amxs_sync_entry_check_bidirectional_param(opposite_list, value);
        when_true(ret, exit);
    }

    amxc_string_setf(&str, "%s%s", opposite_path, amxs_sync_entry_get_opposite_name(entry, direction));
    current_list = GET_ARG(current_table, amxc_string_get(&str, 0));
    if(current_list == NULL) {
        // Add the opposite path to the current ctx htable
        current_list = amxc_var_add_key(amxc_llist_t, current_table, amxc_string_get(&str, 0), NULL);
    }

    // Add the current value to the current list
    value_storage = amxc_var_add_new(current_list);
    amxc_var_copy(value_storage, value);

exit:
    amxc_string_clean(&str);
    return ret;
}

bool amxs_sync_entry_is_bidirectional(const amxs_sync_entry_t* entry) {
    bool ret = true;

    when_null(entry, exit);
    if((entry->attributes & (AMXS_SYNC_ONLY_B_TO_A | AMXS_SYNC_ONLY_A_TO_B)) != 0) {
        ret = false;
    }

exit:
    return ret;
}

bool amxs_sync_entry_direction_allowed(const amxs_sync_entry_t* const entry,
                                       amxs_sync_direction_t direction) {
    bool ret = true;

    if((direction == amxs_sync_a_to_b) &&
       ((entry->attributes & AMXS_SYNC_ONLY_B_TO_A) != 0)) {
        ret = false;
        goto exit;
    }

    if((direction == amxs_sync_b_to_a) &&
       ((entry->attributes & AMXS_SYNC_ONLY_A_TO_B) != 0)) {
        ret = false;
        goto exit;
    }

exit:
    return ret;
}

bool amxs_sync_entry_is_batch_param(const amxs_sync_entry_t* const entry) {
    bool ret = false;

    when_null(entry, exit);
    when_false(entry->type == amxs_sync_type_param, exit);
    when_true((entry->attributes & AMXS_SYNC_PARAM_BATCH) == 0, exit);

    ret = true;

exit:
    return ret;
}

const char* amxs_sync_entry_get_name(const amxs_sync_entry_t* const entry,
                                     amxs_sync_direction_t direction) {
    const char* name = NULL;
    when_null(entry, exit);

    name = direction == amxs_sync_a_to_b ? entry->a : entry->b;

exit:
    return name;
}

const char* amxs_sync_entry_get_opposite_name(const amxs_sync_entry_t* const entry,
                                              amxs_sync_direction_t direction) {
    const char* opposite = NULL;
    when_null(entry, exit);

    opposite = direction == amxs_sync_a_to_b ? entry->b : entry->a;

exit:
    return opposite;
}

amxs_sync_entry_t* amxs_sync_entry_get_parent(const amxs_sync_entry_t* const entry) {
    amxs_sync_entry_t* parent = NULL;
    when_null(entry, exit);
    when_false(amxc_llist_it_is_in_list(&entry->it), exit);

    parent = amxc_container_of(entry->it.llist, amxs_sync_entry_t, entries);

exit:
    return parent;
}

amxs_sync_ctx_t* amxs_sync_entry_get_ctx(const amxs_sync_entry_t* const entry) {
    amxs_sync_ctx_t* ctx = NULL;
    amxs_sync_entry_t* tmp = NULL;
    when_null(entry, exit);

    when_true_status(entry->type == amxs_sync_type_ctx, exit, ctx = (amxs_sync_ctx_t*) entry);

    tmp = amxs_sync_entry_get_parent(entry);
    while(tmp != NULL && tmp->type != amxs_sync_type_ctx) {
        tmp = amxs_sync_entry_get_parent(tmp);
    }

    if((tmp != NULL) && (tmp->type == amxs_sync_type_ctx)) {
        ctx = tmp;
    }

exit:
    return ctx;
}

amxp_signal_mngr_t* amxs_sync_entry_get_signal_manager(const amxs_sync_entry_t* const entry) {
    amxp_signal_mngr_t* sig_mngr = NULL;
    amxs_sync_ctx_t* ctx = NULL;

    ctx = amxs_sync_entry_get_ctx(entry);
    when_null(ctx, exit);

    sig_mngr = ctx->sig_mngr;

exit:
    return sig_mngr;
}


amxb_bus_ctx_t* amxs_sync_ctx_get_opposite_bus_ctx(const amxs_sync_ctx_t* const ctx,
                                                   amxs_sync_direction_t direction) {
    amxb_bus_ctx_t* bus_ctx = NULL;
    when_null(ctx, exit);
    when_false(ctx->type == amxs_sync_type_ctx, exit);

    bus_ctx = direction == amxs_sync_a_to_b ? ctx->bus_ctx_b : ctx->bus_ctx_a;

exit:
    return bus_ctx;
}

amxb_bus_ctx_t* amxs_sync_ctx_get_bus_ctx(const amxs_sync_ctx_t* const ctx,
                                          amxs_sync_direction_t direction) {
    amxb_bus_ctx_t* bus_ctx = NULL;
    when_null(ctx, exit);
    when_false(ctx->type == amxs_sync_type_ctx, exit);

    bus_ctx = direction == amxs_sync_a_to_b ? ctx->bus_ctx_a : ctx->bus_ctx_b;

exit:
    return bus_ctx;
}

amxd_dm_t* amxs_sync_ctx_get_opposite_dm(const amxs_sync_ctx_t* ctx,
                                         amxs_sync_direction_t direction) {
    amxd_dm_t* dm = NULL;
    when_null(ctx, exit);
    when_false(ctx->type == amxs_sync_type_ctx, exit);

    dm = direction == amxs_sync_a_to_b ? ctx->local_dm_b : ctx->local_dm_a;

exit:
    return dm;
}

amxd_dm_t* amxs_sync_ctx_get_dm(const amxs_sync_ctx_t* ctx,
                                amxs_sync_direction_t direction) {
    amxd_dm_t* dm = NULL;
    when_null(ctx, exit);
    when_false(ctx->type == amxs_sync_type_ctx, exit);

    dm = direction == amxs_sync_a_to_b ? ctx->local_dm_a : ctx->local_dm_b;

exit:
    return dm;
}

unsigned int amxs_sync_entry_get_opposite_index(const amxs_sync_entry_t* const entry,
                                                UNUSED amxs_sync_direction_t direction,
                                                unsigned int index) {
    int new_index = 0;
    when_null(entry, exit);

    new_index = index;

exit:
    return new_index;
}

static int amxs_sync_entry_build_opposite_path_entry(const amxs_sync_entry_t* const entry,
                                                     amxs_sync_direction_t direction,
                                                     amxd_path_t* path,
                                                     amxc_string_t* path_str) {
    char* last = amxd_path_get_last(path, true);
    char* ptr = NULL;
    unsigned int index = strtoul(last, &ptr, 0);
    int ret = -1;
    const char* name = amxs_sync_entry_get_name(entry, direction);
    amxc_string_t str;

    amxc_string_init(&str, 0);

    if(strcmp(name, last) == 0) {
        amxc_string_prependf(path_str, "%s", amxs_sync_entry_get_opposite_name(entry, direction));
    } else if(strstr(name, last) != NULL) {
        amxc_string_set(&str, last);
        do {
            free(last);
            last = amxd_path_get_last(path, true);
            when_null(last, exit);
            amxc_string_prependf(&str, "%s", last);
        } while(strcmp(amxc_string_get(&str, 0), name) != 0);
        amxc_string_prependf(path_str, "%s", amxs_sync_entry_get_opposite_name(entry, direction));
    } else if(last != ptr) {
        index = amxs_sync_entry_get_opposite_index(entry, direction, index);
        amxc_string_prependf(path_str, "%u.", index);
        amxs_sync_entry_build_opposite_path_entry(entry, direction, path, path_str);
    }

    ret = 0;

exit:
    free(last);
    amxc_string_clean(&str);
    return ret;
}

char* amxs_sync_entry_get_opposite_path(const amxs_sync_entry_t* const entry,
                                        amxs_sync_direction_t direction,
                                        const char* const old_path) {
    char* new_path = NULL;
    amxc_string_t path_str;
    amxd_path_t path;
    const amxs_sync_entry_t* tmp = entry;

    when_null(entry, exit);
    when_str_empty(old_path, exit);

    amxd_path_init(&path, old_path);
    amxc_string_init(&path_str, 0);

    while(amxd_path_get_depth(&path) != 0 && tmp != NULL) {
        when_false(amxs_sync_entry_build_opposite_path_entry(tmp, direction, &path, &path_str) == 0, exit);
        tmp = amxs_sync_entry_get_parent(tmp);
    }

    new_path = amxc_string_take_buffer(&path_str);

exit:
    amxd_path_clean(&path);
    amxc_string_clean(&path_str);
    return new_path;
}

char* amxs_sync_entry_get_opposite_parent_path(const amxs_sync_entry_t* const entry,
                                               amxs_sync_direction_t direction,
                                               const char* const old_path) {
    char* new_path = NULL;
    amxs_sync_entry_t* parent = amxs_sync_entry_get_parent(entry);
    when_null(parent, exit);

    new_path = amxs_sync_entry_get_opposite_path(parent, direction, old_path);

exit:
    return new_path;
}

char* amxs_sync_entry_get_regex_path(const amxs_sync_entry_t* const entry,
                                     amxs_sync_direction_t direction) {
    char* path_str = NULL;
    const amxs_sync_entry_t* tmp = entry;
    amxc_string_t str;

    when_null(entry, exit);
    amxc_string_init(&str, 0);
    amxc_string_set(&str, "$");

    while(tmp != NULL) {
        amxd_path_t path;
        const char* name = amxs_sync_entry_get_name(tmp, direction);
        when_str_empty(name, exit);
        amxd_path_init(&path, name);

        if((entry->type == amxs_sync_type_object) && (amxd_path_is_instance_path(&path) == false)) {
            amxc_string_prependf(&str, "%s([0-9]+\\.)?", name);
        } else {
            amxc_string_prependf(&str, "%s", name);
        }
        amxd_path_clean(&path);
        tmp = amxs_sync_entry_get_parent(tmp);
    }
    amxc_string_prependf(&str, "%s", "^");

    path_str = amxc_string_take_buffer(&str);

exit:
    amxc_string_clean(&str);
    return path_str;
}

char* amxs_sync_entry_get_regex_parent_path(const amxs_sync_entry_t* const entry,
                                            amxs_sync_direction_t direction) {
    char* path = NULL;
    amxs_sync_entry_t* parent = amxs_sync_entry_get_parent(entry);
    when_null(parent, exit);

    path = amxs_sync_entry_get_regex_path(parent, direction);

exit:
    return path;
}

amxs_status_t amxs_sync_entry_get_batch_params(const amxs_sync_entry_t* const entry,
                                               amxc_var_t* params,
                                               amxs_sync_direction_t direction) {
    amxs_status_t status = amxs_status_invalid_arg;

    when_null(entry, exit);
    when_null(params, exit);
    when_true_status(entry->type == amxs_sync_type_param, exit, status = amxs_status_invalid_type);

    amxc_llist_iterate(it, &entry->entries) {
        amxs_sync_entry_t* child = amxc_llist_it_get_data(it, amxs_sync_entry_t, it);
        if(!amxs_sync_entry_is_batch_param(child)) {
            continue;
        }

        if(!amxs_sync_entry_direction_allowed(child, direction)) {
            continue;
        }

        amxc_var_add(cstring_t, params, direction == amxs_sync_a_to_b ? child->a : child->b);
    }

    status = amxs_status_ok;

exit:
    return status;
}

amxs_status_t amxs_sync_param_copy_trans_cb(const amxs_sync_entry_t* entry,
                                            amxs_sync_direction_t direction,
                                            const amxc_var_t* input,
                                            amxc_var_t* output,
                                            UNUSED void* priv) {
    amxs_status_t status = amxs_status_unknown_error;
    amxc_var_t* params = GET_ARG(input, "parameters");
    amxc_var_t* output_params = NULL;
    const char* path = GET_CHAR(input, "path");
    const char* notification = GET_CHAR(input, "notification");
    const char* entry_name = amxs_sync_entry_get_name(entry, direction);
    char* opposite_path = NULL;
    amxs_sync_entry_t* parent_entry = amxs_sync_entry_get_parent(entry);

    when_null(params, exit);
    when_str_empty(path, exit);
    when_str_empty(entry_name, exit);
    when_str_empty(notification, exit);

    opposite_path = amxs_sync_entry_get_opposite_parent_path(entry, direction, path);
    when_str_empty(opposite_path, exit);

    amxc_var_set_type(output, AMXC_VAR_ID_HTABLE);
    output_params = amxc_var_add_key(amxc_htable_t, output, "parameters", NULL);
    amxc_var_add_key(cstring_t, output, "path", opposite_path);

    // When doing initial sync, protect agains loop-back add-object events
    if((strcmp(notification, "dm:object-added") == 0) ||
       (strcmp(notification, "sync:init-param") == 0)) {
        // This translation callback function is called on parameter entries
        // Here the object entry is needed, take parent.
        // Handle loop prevention, returns true if this object-added is to be ignored
        if(amxs_sync_entry_check_bidrection_object(parent_entry, direction, path, opposite_path)) {
            status = amxs_status_ok;
            goto exit;
        }
    } else {
        amxs_sync_entry_remove_bidrection_object(parent_entry, direction, path);
        if(strcmp(notification, "dm:object-removed") == 0) {
            status = amxs_status_ok;
            goto exit;
        }
    }

    amxc_var_for_each(param, params) {
        if(strcmp(amxc_var_key(param), entry_name) == 0) {
            amxc_var_t* value = NULL;
            amxc_var_t* new_param = NULL;

            if((strcmp(notification, "sync:init-param") == 0) ||
               (strcmp(notification, "dm:object-added") == 0)) {
                value = param;
            } else {
                value = GET_ARG(param, "to");
            }

            // Handle loop prevention, returns true if this parameter is to be ignored
            if(strcmp(notification, "dm:object-added") != 0) {
                if(amxs_sync_entry_check_bidirectional_loop(entry, direction, value, path, opposite_path)) {
                    continue;
                }
            }

            new_param = amxc_var_add_new_key(output_params, amxs_sync_entry_get_opposite_name(entry, direction));
            amxc_var_copy(new_param, value);
        }
    }

    status = amxs_status_ok;

exit:
    free(opposite_path);
    return status;
}

amxs_status_t amxs_sync_batch_param_copy_trans_cb(const amxs_sync_entry_t* entry,
                                                  amxs_sync_direction_t direction,
                                                  const amxc_var_t* input,
                                                  amxc_var_t* output,
                                                  UNUSED void* priv) {
    amxs_status_t status = amxs_status_unknown_error;
    amxc_var_t* params = GET_ARG(input, "parameters");
    amxc_var_t* output_params = NULL;
    const char* path = GET_CHAR(input, "path");
    const char* notification = GET_CHAR(input, "notification");
    const char* entry_name = amxs_sync_entry_get_name(entry, direction);
    char* opposite_path = NULL;

    when_null(params, exit);
    when_str_empty(path, exit);
    when_str_empty(entry_name, exit);
    when_str_empty(notification, exit);

    opposite_path = amxs_sync_entry_get_opposite_path(entry, direction, path);
    when_str_empty(opposite_path, exit);

    amxc_var_set_type(output, AMXC_VAR_ID_HTABLE);
    output_params = amxc_var_add_key(amxc_htable_t, output, "parameters", NULL);
    amxc_var_add_key(cstring_t, output, "path", opposite_path);

    if((strcmp(notification, "dm:object-added") == 0) ||
       (strcmp(notification, "sync:init-batch-param") == 0)) {
        // Handle loop prevention, returns true if this object-added is to be ignored
        if(amxs_sync_entry_check_bidrection_object(entry, direction, path, opposite_path)) {
            status = amxs_status_ok;
            goto exit;
        }
    } else {
        amxs_sync_entry_remove_bidrection_object(entry, direction, path);
        if(strcmp(notification, "dm:object-removed") == 0) {
            status = amxs_status_ok;
            goto exit;
        }
    }


    amxc_llist_iterate(it, &entry->entries) {
        amxs_sync_entry_t* child = amxc_llist_it_get_data(it, amxs_sync_entry_t, it);
        amxc_var_t* param = NULL;
        amxc_var_t* new_param = NULL;
        amxc_var_t* value = NULL;

        if(!amxs_sync_entry_is_batch_param(child)) {
            continue;
        }

        param = GETP_ARG(params, amxs_sync_entry_get_name(child, direction));
        if(param == NULL) {
            continue;
        }

        if((strcmp(notification, "sync:init-batch-param") == 0) ||
           (strcmp(notification, "dm:object-added") == 0)) {
            value = param;
        } else {
            value = GET_ARG(param, "to");
        }

        // Handle loop prevention, returns true if this parameter is to be ignored
        if(strcmp(notification, "dm:object-added") != 0) {
            if(amxs_sync_entry_check_bidirectional_loop(child, direction, value, path, opposite_path)) {
                continue;
            }
        }

        new_param = amxc_var_add_new_key(output_params, amxs_sync_entry_get_opposite_name(child, direction));
        amxc_var_copy(new_param, value);
    }

    status = amxs_status_ok;

exit:
    free(opposite_path);
    return status;
}

amxs_status_t amxs_sync_param_copy_action_cb(const amxs_sync_entry_t* entry,
                                             amxs_sync_direction_t direction,
                                             amxc_var_t* data,
                                             UNUSED void* priv) {
    amxs_status_t status = amxs_status_unknown_error;
    const char* path = GET_CHAR(data, "path");
    amxc_var_t* params = GET_ARG(data, "parameters");
    amxb_bus_ctx_t* bus_ctx = NULL;
    amxc_var_t ret;
    amxd_dm_t* dm = NULL;

    amxc_var_init(&ret);

    when_null(path, exit);
    when_null(params, exit);

    dm = amxs_sync_ctx_get_opposite_dm(amxs_sync_entry_get_ctx(entry), direction);
    if(dm != NULL) {
        amxd_trans_t trans;

        amxd_trans_init(&trans);
        amxd_trans_set_attr(&trans, amxd_tattr_change_ro, true);
        amxd_trans_select_pathf(&trans, "%s", path);
        amxc_var_for_each(var, params) {
            amxd_trans_set_param(&trans, amxc_var_key(var), var);
        }

        if(amxd_trans_apply(&trans, dm) == 0) {
            status = amxs_status_ok;
        }
        amxd_trans_clean(&trans);
    } else {
        bus_ctx = amxs_sync_ctx_get_opposite_bus_ctx(amxs_sync_entry_get_ctx(entry), direction);
        when_null(bus_ctx, exit);
        if(amxb_set(bus_ctx, path, params, &ret, 5) == 0) {
            status = amxs_status_ok;
        }
    }

exit:
    amxc_var_clean(&ret);
    return status;
}

static void amxs_notify_instance_added(const amxc_var_t* input, amxs_sync_entry_t* entry, const amxs_sync_direction_t direction) {
    amxc_var_t* parameters = NULL;
    amxc_var_t* changed_value = NULL;
    amxc_var_t event_data;
    amxc_string_t str_object;
    amxc_string_t str_path;
    amxc_string_t str_new_value;

    amxc_var_init(&event_data);
    amxc_var_set_type(&event_data, AMXC_VAR_ID_HTABLE);
    amxc_string_init(&str_object, 0);
    amxc_string_init(&str_path, 0);
    amxc_string_init(&str_new_value, 0);
    amxc_string_setf(&str_object, "%s%d.", GET_CHAR(input, "object"), GET_UINT32(input, "index"));
    amxc_string_setf(&str_path, "%s%d.", GET_CHAR(input, "path"), GET_UINT32(input, "index"));
    amxc_string_setf(&str_new_value, "parameters.%s", amxs_sync_entry_get_name(entry, direction));

    amxc_var_add_key(cstring_t, &event_data, "notification", "dm:object-changed");
    amxc_var_add_key(cstring_t, &event_data, "object", amxc_string_get(&str_object, 0));

    parameters = amxc_var_add_key(amxc_htable_t, &event_data, "parameters", NULL);
    changed_value = amxc_var_add_key(amxc_htable_t, parameters, amxs_sync_entry_get_name(entry, direction), NULL);
    amxc_var_set_key(changed_value, "from", NULL, AMXC_VAR_FLAG_DEFAULT);
    amxc_var_set_key(changed_value, "to", GETP_ARG(input, amxc_string_get(&str_new_value, 0)), AMXC_VAR_FLAG_DEFAULT);

    amxc_var_add_key(cstring_t, &event_data, "path", amxc_string_get(&str_path, 0));
    amxp_sigmngr_emit_signal(amxs_sync_entry_get_signal_manager(entry), "sync:instance-added", &event_data);

    amxc_var_clean(&event_data);
    amxc_string_clean(&str_new_value);
    amxc_string_clean(&str_path);
    amxc_string_clean(&str_object);
}

amxs_status_t amxs_sync_object_copy_trans_cb(const amxs_sync_entry_t* entry,
                                             amxs_sync_direction_t direction,
                                             const amxc_var_t* input,
                                             amxc_var_t* output,
                                             UNUSED void* priv) {
    amxs_status_t status = amxs_status_unknown_error;
    const char* path = GET_CHAR(input, "path");
    char* opposite_path = NULL;
    const char* notification = GET_CHAR(input, "notification");

    when_str_empty(path, exit);
    when_str_empty(notification, exit);
    opposite_path = amxs_sync_entry_get_opposite_path(entry, direction, path);
    when_str_empty(opposite_path, exit);

    amxc_var_set_type(output, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, output, "path", opposite_path);
    amxc_var_add_key(uint32_t, output, "index",
                     amxs_sync_entry_get_opposite_index(entry, direction, GET_UINT32(input, "index")));
    amxc_var_add_key(cstring_t, output, "notification", notification);

    if(((strcmp("dm:instance-added", notification) == 0) ||
        (strcmp("sync:init-object", notification) == 0)) &&
       (GET_ARG(input, "parameters") != NULL)) {
        amxc_var_t* params = GET_ARG(input, "parameters");
        amxc_var_t* output_params = amxc_var_add_new_key(output, "parameters");
        amxc_var_set_type(output_params, AMXC_VAR_ID_HTABLE);

        amxc_llist_for_each(it, &entry->entries) {
            amxs_sync_entry_t* child = amxc_container_of(it, amxs_sync_entry_t, it);
            if(child->type != amxs_sync_type_param) {
                continue;
            }
            amxc_var_for_each(param, params) {
                if(strcmp(amxc_var_key(param), amxs_sync_entry_get_name(child, direction)) == 0) {
                    amxc_var_t* new_param = amxc_var_add_new_key(output_params, amxs_sync_entry_get_opposite_name(child, direction));
                    amxc_var_copy(new_param, param);
                }
            }

            /* Emit a sync:instance-added signal for each non batch parameter */
            if((amxs_sync_entry_is_batch_param(child) == false) &&
               (GET_CHAR(input, "object") != NULL) &&
               (GET_CHAR(input, "path") != NULL) &&
               (strcmp("dm:instance-added", notification) == 0)) {
                amxs_notify_instance_added(input, child, direction);
            }
        }
    }

    status = amxs_status_ok;

exit:
    free(opposite_path);
    return status;
}

amxs_status_t amxs_sync_object_copy_action_cb(const amxs_sync_entry_t* entry,
                                              amxs_sync_direction_t direction,
                                              amxc_var_t* data,
                                              UNUSED void* priv) {
    amxs_status_t status = amxs_status_unknown_error;
    const char* path = GET_CHAR(data, "path");
    const char* notification = GET_CHAR(data, "notification");
    uint32_t index = GET_UINT32(data, "index");
    amxb_bus_ctx_t* bus_ctx = NULL;
    amxc_var_t ret;

    amxc_var_init(&ret);

    when_null(path, exit);
    when_null(notification, exit);

    bus_ctx = amxs_sync_ctx_get_opposite_bus_ctx(amxs_sync_entry_get_ctx(entry), direction);
    when_null(bus_ctx, exit);

    if((strcmp(notification, "dm:instance-added") == 0) ||
       (strcmp(notification, "sync:init-object") == 0)) {
        amxc_var_t* params = GET_ARG(data, "parameters");
        amxc_string_t str;
        amxc_string_init(&str, 0);
        amxc_string_setf(&str, "%s%u.", path, index);
        if((amxb_get(bus_ctx, amxc_string_get(&str, 0), 0, &ret, 5) == 0) &&
           (GETP_ARG(&ret, "0.0") != NULL)) {
            if(amxb_set(bus_ctx, amxc_string_get(&str, 0), params, &ret, 5) == 0) {
                status = amxs_status_ok;
            }
        } else {
            if(amxb_add(bus_ctx, path, index, NULL, params, &ret, 5) == 0) {
                status = amxs_status_ok;
            }
        }
        amxc_string_clean(&str);
    } else {
        if(amxb_del(bus_ctx, path, index, NULL, &ret, 5) == 0) {
            status = amxs_status_ok;
        }
    }

exit:
    amxc_var_clean(&ret);
    return status;
}
