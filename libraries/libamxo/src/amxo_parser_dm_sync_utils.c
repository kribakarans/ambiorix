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

#include "amxo_parser_priv.h"
#include "amxo_parser.tab.h"
#include "amxo_parser_hooks_priv.h"

#define MSG_CREATION_FAILED \
    "Creation failed for %s and %s (direction = %d, status = %d)"
#define MSG_SET_DM_FAILED \
    "Set datamodel for %s and %s failed (direction = %d, status = %d)"
#define MSG_MUST_CONTAIN_SYNC_ENTRIES \
    "Object synchronisation must contain sub-entries"
#define MSG_BATCH_PARAM_WITH_CB \
    "Batch parameter synchronisation with callbacks have no effect"

typedef struct _amxo_sync_data {
    amxs_sync_entry_t* entry;
    amxc_llist_it_t it;
    amxc_htable_it_t hit;
} amxo_sync_data_t;

typedef amxs_status_t (* amxo_sync_add_item_fn_t) (amxs_sync_object_t* parent,
                                                   amxs_sync_object_t* child);

static amxc_htable_t sync_templates;

static amxo_sync_data_t* amxo_parser_get_sync_data(amxo_parser_t* pctx) {
    amxc_llist_it_t* it = amxc_llist_get_last(pctx->sync_contexts);
    amxo_sync_data_t* data = amxc_container_of(it, amxo_sync_data_t, it);

    return data;
}

static amxs_status_t amxo_parser_sync_add_item(amxo_parser_t* pctx,
                                               amxo_sync_data_t* data,
                                               amxo_sync_add_item_fn_t ctx_add,
                                               amxo_sync_add_item_fn_t object_add) {
    amxs_status_t status = amxs_status_unknown_error;
    amxo_sync_data_t* parent = NULL;

    parent = amxo_parser_get_sync_data(pctx);
    when_null(parent, exit);
    when_null(parent->entry, exit);

    switch(parent->entry->type) {
    case amxs_sync_type_ctx:
        status = ctx_add(parent->entry, data->entry);
        break;
    case amxs_sync_type_object:
        status = object_add(parent->entry, data->entry);
        break;
    default:
        break;
    }

    if(status == amxs_status_ok) {
        amxc_llist_append(pctx->sync_contexts, &data->it);
    }

exit:
    return status;
}

static amxd_dm_t* amxo_parser_get_sync_dm(amxo_parser_t* pctx,
                                          const char* path) {
    amxd_dm_t* dm = amxd_object_get_dm(pctx->object);
    dm = amxd_dm_findf(dm, "%s", path) == NULL? NULL:dm;
    return dm;
}

static void amxo_parser_sync_set_status(amxo_parser_t* pctx, amxs_status_t status) {
    switch(status) {
    case amxs_status_ok:
        pctx->status = amxd_status_ok;
        break;
    case amxs_status_duplicate:
        pctx->status = amxd_status_duplicate;
        break;
    case amxs_status_invalid_attr:
        pctx->status = amxd_status_invalid_attr;
        break;
    case amxs_status_invalid_arg:
        pctx->status = amxd_status_invalid_arg;
        break;
    case amxs_status_empty_context:
        pctx->status = amxd_status_invalid_value;
        break;
    case amxs_status_invalid_type:
        pctx->status = amxd_status_invalid_type;
        break;
    case amxs_status_object_not_found:
        pctx->status = amxd_status_object_not_found;
        break;
    case amxs_status_subscription_failed:
        pctx->status = amxd_status_function_not_found;
        break;
    default:
        pctx->status = amxd_status_unknown_error;
        break;
    }
}

amxs_sync_entry_type_t amxo_parser_get_sync_type(amxo_parser_t* pctx) {
    amxs_sync_entry_type_t type = amxs_sync_type_invalid;
    amxo_sync_data_t* sync_data = amxo_parser_get_sync_data(pctx);
    when_null(sync_data, exit);
    when_null(sync_data->entry, exit);

    type = sync_data->entry->type;

exit:
    return type;
}

bool amxo_parser_is_sync_item(amxo_parser_t* pctx) {
    amxs_sync_entry_type_t type = amxo_parser_get_sync_type(pctx);
    return (type == amxs_sync_type_object || type == amxs_sync_type_param);
}

int amxo_parser_sync_update_flags(int direction) {
    if((direction & AMXS_SYNC_ONLY_B_TO_A) == AMXS_SYNC_ONLY_B_TO_A) {
        direction |= AMXS_SYNC_INIT_B;
    }

    return direction;
}

void amxo_parser_del_sync_data(amxc_llist_it_t* it) {
    amxo_sync_data_t* data = amxc_container_of(it, amxo_sync_data_t, it);
    when_null(data, exit);

    amxc_llist_it_take(it);
    amxc_htable_it_clean(&data->hit, NULL);

    when_null(data->entry, exit);

    switch(data->entry->type) {
    case amxs_sync_type_ctx:
        amxs_sync_ctx_delete(&data->entry);
        break;
    case amxs_sync_type_object:
        amxs_sync_object_delete(&data->entry);
        break;
    case amxs_sync_type_param:
        amxs_sync_param_delete(&data->entry);
        break;
    default:
        break;
    }

exit:
    free(data);
}

void amxo_parser_pop_sync_item(amxo_parser_t* pctx) {
    amxo_sync_data_t* data = NULL;
    when_null(pctx->sync_contexts, exit);

    data = amxo_parser_get_sync_data(pctx);
    amxc_llist_it_take(&data->it);
    free(data);

exit:
    return;
}

int amxo_parser_push_sync_ctx(amxo_parser_t* pctx,
                              const char* path_a,
                              const char* path_b,
                              int direction) {
    amxs_status_t status = amxs_status_unknown_error;
    amxc_string_t res_path_a;
    amxc_string_t res_path_b;
    amxd_dm_t* dm_a = NULL;
    amxd_dm_t* dm_b = NULL;
    amxo_sync_data_t* data =
        (amxo_sync_data_t*) calloc(1, sizeof(amxo_sync_data_t));

    amxc_string_init(&res_path_a, 0);
    amxc_string_init(&res_path_b, 0);
    when_null(data, exit);

    if(amxc_string_set_resolved(&res_path_a, path_a, &pctx->config) > 0) {
        path_a = amxc_string_get(&res_path_a, 0);
    }
    if(amxc_string_set_resolved(&res_path_b, path_b, &pctx->config) > 0) {
        path_b = amxc_string_get(&res_path_b, 0);
    }

    status = amxs_sync_ctx_new(&data->entry, path_a, path_b, direction);
    if(status != 0) {
        amxo_parser_msg(pctx, MSG_CREATION_FAILED,
                        path_a, path_b, direction, status);
        amxo_parser_sync_set_status(pctx, status);
        data->entry = NULL;
        goto exit;
    }

    if((direction & AMXS_SYNC_ONLY_A_TO_B) == 0) {
        dm_a = amxo_parser_get_sync_dm(pctx, path_a);
    }
    if((direction & AMXS_SYNC_ONLY_B_TO_A) == 0) {
        dm_b = amxo_parser_get_sync_dm(pctx, path_b);
    }

    status = amxs_sync_ctx_set_local_dm(data->entry, dm_a, dm_b);
    if(status != 0) {
        amxo_parser_msg(pctx, MSG_SET_DM_FAILED,
                        path_a, path_b, direction, status);
        amxo_parser_sync_set_status(pctx, status);
        goto exit;
    }

    if(pctx->sync_contexts == NULL) {
        amxc_llist_new(&pctx->sync_contexts);
    }
    amxc_llist_append(pctx->sync_contexts, &data->it);

exit:
    if(status != 0) {
        if(data != NULL) {
            amxo_parser_del_sync_data(&data->it);
        }
    }
    amxc_string_clean(&res_path_a);
    amxc_string_clean(&res_path_b);
    return status;
}

int amxo_parser_push_sync_template(amxo_parser_t* pctx,
                                   const char* path_a,
                                   const char* path_b,
                                   int direction,
                                   const char* name) {
    int status = amxs_status_unknown_error;
    amxd_path_t path;
    amxo_sync_data_t* data = NULL;
    amxd_path_init(&path, NULL);

    status = amxo_parser_push_sync_ctx(pctx, path_a, path_b, direction);
    when_failed(status, exit);

    data = amxo_parser_get_sync_data(pctx);
    status = amxs_status_invalid_type;
    amxd_path_setf(&path, false, "%s", data->entry->a);
    when_true(amxd_path_is_instance_path(&path), exit);
    when_false(amxd_path_is_supported_path(&path) || amxd_path_is_object_path(&path), exit);
    amxd_path_setf(&path, false, "%s", data->entry->b);
    when_true(amxd_path_is_instance_path(&path), exit);
    when_false(amxd_path_is_supported_path(&path) || amxd_path_is_object_path(&path), exit);
    status = amxs_status_ok;

    amxc_htable_insert(&sync_templates, name, &data->hit);

exit:
    if(status != 0) {
        if(data != NULL) {
            amxo_parser_del_sync_data(&data->it);
        }
    }
    amxd_path_clean(&path);
    return status;
}

int amxo_parser_push_sync_object(amxo_parser_t* pctx,
                                 const char* path_a,
                                 const char* path_b,
                                 int direction) {
    amxs_status_t status = amxs_status_unknown_error;
    amxc_string_t res_a;
    amxc_string_t res_b;
    amxo_sync_data_t* data = NULL;

    amxc_string_init(&res_a, 0);
    amxc_string_init(&res_b, 0);

    data = (amxo_sync_data_t*) calloc(1, sizeof(amxo_sync_data_t));
    when_null(data, exit);

    if(amxc_string_set_resolved(&res_a, path_a, &pctx->config) > 0) {
        path_a = amxc_string_get(&res_a, 0);
    }
    if(amxc_string_set_resolved(&res_b, path_b, &pctx->config) > 0) {
        path_b = amxc_string_get(&res_b, 0);
    }

    status = amxs_sync_object_new_copy(&data->entry, path_a, path_b, direction);
    when_failed_status(status, exit, data->entry = NULL);

    status = amxo_parser_sync_add_item(pctx, data,
                                       amxs_sync_ctx_add_object,
                                       amxs_sync_object_add_object);

exit:
    if(status != 0) {
        amxo_parser_msg(pctx, MSG_CREATION_FAILED,
                        path_a, path_b, direction, status);
        amxo_parser_sync_set_status(pctx, status);
        if(data != NULL) {
            amxs_sync_object_delete(&data->entry);
        }
        free(data);
    }
    amxc_string_clean(&res_a);
    amxc_string_clean(&res_b);
    return status;
}

int amxo_parser_push_sync_parameter(amxo_parser_t* pctx,
                                    const char* param_a,
                                    const char* param_b,
                                    int direction) {
    amxs_status_t status = amxs_status_unknown_error;
    amxc_string_t res_a;
    amxc_string_t res_b;
    amxo_sync_data_t* data = NULL;

    amxc_string_init(&res_a, 0);
    amxc_string_init(&res_b, 0);

    data = (amxo_sync_data_t*) calloc(1, sizeof(amxo_sync_data_t));
    when_null(data, exit);

    if(amxc_string_set_resolved(&res_a, param_a, &pctx->config) > 0) {
        param_a = amxc_string_get(&res_a, 0);
    }
    if(amxc_string_set_resolved(&res_b, param_b, &pctx->config) > 0) {
        param_b = amxc_string_get(&res_b, 0);
    }

    status = amxs_sync_param_new_copy(&data->entry, param_a, param_b, direction);
    when_failed_status(status, exit, data->entry = NULL);

    status = amxo_parser_sync_add_item(pctx,
                                       data,
                                       amxs_sync_ctx_add_param,
                                       amxs_sync_object_add_param);

exit:
    if(status != 0) {
        amxo_parser_msg(pctx, MSG_CREATION_FAILED,
                        param_a, param_b, direction, status);
        amxo_parser_sync_set_status(pctx, status);
        if(data != NULL) {
            amxs_sync_param_delete(&data->entry);
        }
        free(data);
    }
    amxc_string_clean(&res_a);
    amxc_string_clean(&res_b);
    return status;
}

amxd_status_t amxo_parser_sync_set_translator(amxo_parser_t* pctx,
                                              amxs_translation_cb_t cb) {
    amxd_status_t status = amxd_status_unknown_error;
    amxo_sync_data_t* sync_data = amxo_parser_get_sync_data(pctx);
    when_null(sync_data, exit);
    when_null(sync_data->entry, exit);

    if(amxs_sync_entry_is_batch_param(sync_data->entry)) {
        amxo_parser_msg(pctx, MSG_BATCH_PARAM_WITH_CB);
        pctx->status = amxd_status_invalid_action;
    } else {
        sync_data->entry->translation_cb = cb;
        status = amxd_status_ok;
    }

exit:
    return status;
}

amxd_status_t amxo_parser_sync_set_action(amxo_parser_t* pctx,
                                          amxs_action_cb_t cb) {
    amxd_status_t status = amxd_status_unknown_error;
    amxo_sync_data_t* sync_data = amxo_parser_get_sync_data(pctx);
    when_null(sync_data, exit);
    when_null(sync_data->entry, exit);

    if(amxs_sync_entry_is_batch_param(sync_data->entry)) {
        amxo_parser_msg(pctx, MSG_BATCH_PARAM_WITH_CB);
        pctx->status = amxd_status_invalid_action;
    } else {
        sync_data->entry->action_cb = cb;
        status = amxd_status_ok;
    }

exit:
    return status;
}

bool amxo_parser_sync_item_contains_entries(amxo_parser_t* pctx) {
    bool retval = false;
    amxo_sync_data_t* sync_data = amxo_parser_get_sync_data(pctx);
    when_null(sync_data, exit);
    when_null(sync_data->entry, exit);

    retval = true;
    if(amxc_llist_is_empty(&sync_data->entry->entries)) {
        amxo_parser_msg(pctx, MSG_MUST_CONTAIN_SYNC_ENTRIES);
        pctx->status = amxd_status_invalid_action;
        retval = false;
    }

exit:
    return retval;
}

int amxo_parser_start_sync(amxc_llist_it_t* it) {
    int status = -1;
    amxo_sync_data_t* data = amxc_container_of(it, amxo_sync_data_t, it);
    when_null(data, exit);
    when_null(data->entry, exit);
    when_false(data->entry->type == amxs_sync_type_ctx, exit);

    if(amxc_htable_it_get_key(&data->hit) == NULL) {
        if(!amxs_sync_ctx_is_started(data->entry)) {
            status = amxs_sync_ctx_start_sync(data->entry);
        }
    } else {
        status = 0;
    }

exit:
    return status;
}

void amxo_parser_stop_sync(amxc_llist_it_t* it) {
    amxo_sync_data_t* data = amxc_container_of(it, amxo_sync_data_t, it);
    when_null(data, exit);
    when_null(data->entry, exit);
    when_false(data->entry->type == amxs_sync_type_ctx, exit);

    if(amxc_htable_it_get_key(&data->hit) == NULL) {
        amxs_sync_ctx_stop_sync(data->entry);
    }

exit:
    return;
}

void amxo_parser_sync_remove_invalid(amxo_parser_t* pctx) {
    when_null(pctx, exit);
    when_null(pctx->sync_contexts, exit);

    amxc_llist_for_each_reverse(it, pctx->sync_contexts) {
        amxo_sync_data_t* data = amxc_container_of(it, amxo_sync_data_t, it);
        switch(data->entry->type) {
        case amxs_sync_type_param:
        case amxs_sync_type_object:
            amxo_parser_del_sync_data(it);
            break;
        case amxs_sync_type_ctx:
            if(amxc_llist_is_empty(&data->entry->entries)) {
                amxo_parser_del_sync_data(it);
            }
            break;
        default:
            break;
        }
    }

    if(amxc_llist_is_empty(pctx->sync_contexts)) {
        amxc_llist_delete(&pctx->sync_contexts, NULL);
    }

exit:
    return;
}

amxs_sync_ctx_t* amxo_parser_sync_get(const char* sync_template) {
    amxs_sync_ctx_t* ctx = NULL;
    amxo_sync_data_t* sync_data = NULL;
    amxc_htable_it_t* hit = amxc_htable_get(&sync_templates, sync_template);

    when_null(hit, exit);
    sync_data = amxc_container_of(hit, amxo_sync_data_t, hit);

    ctx = sync_data->entry;

exit:
    return ctx;
}

CONSTRUCTOR_LVL(110) static void amxo_parser_sync_templates_init(void) {
    amxc_htable_init(&sync_templates, 10);
}

DESTRUCTOR_LVL(110) static void amxo_parser_sync_templates_cleanup(void) {
    amxc_htable_clean(&sync_templates, NULL);
}
