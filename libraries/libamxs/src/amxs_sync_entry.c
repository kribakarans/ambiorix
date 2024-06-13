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

#include "amxs_sync_entry.h"
#include "amxs_priv.h"

static void amxs_llist_it_delete_sync_entry(amxc_llist_it_t* it) {
    amxs_sync_entry_t* entry = amxc_container_of(it, amxs_sync_entry_t, it);

    amxs_sync_entry_delete(&entry);
}

static int amxs_sync_entry_compare_name(const char* const a, const char* const b) {
    int ret = -1;

    if((a == NULL) && (b != NULL)) {
        goto exit;
    }

    if((a != NULL) && (b == NULL)) {
        goto exit;
    }

    if(((a != NULL) && (b != NULL)) && (strcmp(a, b) != 0)) {
        goto exit;
    }

    ret = 0;

exit:
    return ret;
}

amxs_sync_direction_t amxs_sync_entry_get_initial_direction(const amxs_sync_entry_t* const entry) {
    amxs_sync_direction_t direction = amxs_sync_invalid;
    when_null(entry, exit);

    direction = (entry->attributes & AMXS_SYNC_INIT_B) == 0 ? amxs_sync_a_to_b : amxs_sync_b_to_a;

exit:
    return direction;
}

amxs_status_t amxs_sync_entry_new(amxs_sync_entry_t** entry,
                                  const char* a,
                                  const char* b,
                                  int attributes,
                                  amxs_translation_cb_t translation_cb,
                                  amxs_action_cb_t action_cb,
                                  amxs_sync_entry_type_t type,
                                  void* priv) {
    amxs_status_t status = amxs_status_unknown_error;
    when_null(entry, exit);

    *entry = (amxs_sync_entry_t*) calloc(1, sizeof(amxs_sync_entry_t));
    when_null(*entry, exit);

    status = amxs_sync_entry_init(*entry, a, b, attributes, translation_cb, action_cb, type, priv);
    if(status != amxs_status_ok) {
        free(*entry);
        *entry = NULL;
    }

exit:
    return status;
}

void amxs_sync_entry_delete(amxs_sync_entry_t** entry) {
    when_null(entry, exit);
    when_null(*entry, exit);

    amxs_sync_entry_clean(*entry);

    free(*entry);
    *entry = NULL;

exit:
    return;
}

amxs_status_t amxs_sync_entry_init(amxs_sync_entry_t* entry,
                                   const char* a,
                                   const char* b,
                                   int attributes,
                                   amxs_translation_cb_t translation_cb,
                                   amxs_action_cb_t action_cb,
                                   amxs_sync_entry_type_t type,
                                   void* priv) {
    amxs_status_t status = amxs_status_unknown_error;
    when_null(entry, exit);

    status = amxs_validate_attributes(attributes, 0);
    when_failed(status, exit);

    memset(entry, 0, sizeof(amxs_sync_entry_t));

    status = amxs_status_invalid_arg;
    if((attributes & AMXS_SYNC_ONLY_B_TO_A) == 0) {
        when_str_empty(a, exit);
    }

    if((attributes & AMXS_SYNC_ONLY_A_TO_B) == 0) {
        when_str_empty(b, exit);
    }

    if(a != NULL) {
        if((type != amxs_sync_type_param) && (a[strlen(a) - 1] != '.')) {
            status = amxs_status_invalid_arg;
            goto exit;
        }
        entry->a = strdup(a);
        when_null(entry->a, exit);
    }

    if(b != NULL) {
        if((type != amxs_sync_type_param) && (b[strlen(b) - 1] != '.')) {
            status = amxs_status_invalid_arg;
            goto exit;
        }
        entry->b = strdup(b);
        when_null(entry->b, exit);
    }

    entry->attributes = attributes;
    entry->action_cb = action_cb;
    entry->translation_cb = translation_cb;
    entry->type = type;
    entry->priv = priv;
    entry->bus_ctx_a = NULL;
    entry->bus_ctx_b = NULL;
    amxc_llist_it_init(&entry->it);
    amxc_llist_init(&entry->entries);
    amxc_llist_init(&entry->subscriptions);
    amxc_var_init(&entry->a_to_b);
    amxc_var_init(&entry->b_to_a);
    entry->local_dm_a = NULL;
    entry->local_dm_b = NULL;

    if(type == amxs_sync_type_ctx) {
        amxc_var_set_type(&entry->a_to_b, AMXC_VAR_ID_HTABLE);
        amxc_var_set_type(&entry->b_to_a, AMXC_VAR_ID_HTABLE);
        when_failed(amxp_sigmngr_new(&entry->sig_mngr), exit);
        amxp_sigmngr_add_signal(entry->sig_mngr, "sync:instance-added");
    }

    status = amxs_status_ok;

exit:
    if((status != amxs_status_ok) && (entry != NULL)) {
        free(entry->a);
        entry->a = NULL;
        free(entry->b);
        entry->b = NULL;
        amxc_var_clean(&entry->a_to_b);
        amxc_var_clean(&entry->b_to_a);
    }
    return status;
}

void amxs_sync_entry_clean(amxs_sync_entry_t* entry) {
    when_null(entry, exit);

    if(entry->type == amxs_sync_type_ctx) {
        amxp_sigmngr_delete(&entry->sig_mngr);
    }

    free(entry->a);
    entry->a = NULL;
    free(entry->b);
    entry->b = NULL;
    entry->attributes = 0;
    entry->action_cb = NULL;
    entry->translation_cb = NULL;
    entry->type = amxs_sync_type_invalid;
    entry->priv = NULL;
    entry->bus_ctx_a = NULL;
    entry->bus_ctx_b = NULL;
    amxc_llist_it_take(&entry->it);
    amxc_llist_clean(&entry->entries, amxs_llist_it_delete_sync_entry);
    amxc_llist_clean(&entry->subscriptions, amxs_llist_it_delete_subscription);
    amxc_var_clean(&entry->a_to_b);
    amxc_var_clean(&entry->b_to_a);

exit:
    return;
}

amxs_status_t amxs_sync_entry_copy(amxs_sync_entry_t** dest,
                                   amxs_sync_entry_t* src,
                                   void* priv) {
    amxs_status_t status = amxs_status_unknown_error;
    amxs_sync_entry_t* dst_child = NULL;
    amxs_sync_entry_t* src_child = NULL;

    when_null(dest, exit);
    when_null(src, exit);

    status = amxs_sync_entry_new(dest,
                                 src->a,
                                 src->b,
                                 src->attributes,
                                 src->translation_cb,
                                 src->action_cb,
                                 src->type,
                                 priv);
    when_failed(status, exit);

    (*dest)->local_dm_a = src->local_dm_a;
    (*dest)->local_dm_b = src->local_dm_b;

    amxc_llist_for_each(it, &src->entries) {
        src_child = amxc_container_of(it, amxs_sync_entry_t, it);
        amxs_sync_entry_copy(&dst_child, src_child, NULL);
        status = amxs_sync_entry_add_entry(*dest, dst_child);
        when_failed(status, exit);
    }

exit:
    if(status != 0) {
        amxs_sync_entry_delete(dest);
    }
    return status;
}

amxs_status_t amxs_sync_entry_add_entry(amxs_sync_entry_t* parent, amxs_sync_entry_t* child) {
    amxs_status_t status = amxs_status_unknown_error;
    when_null(parent, exit);
    when_null(child, exit);
    when_true(parent == child, exit);

    if((parent->type == amxs_sync_type_invalid) ||
       ( parent->type == amxs_sync_type_param) ||
       ( child->type == amxs_sync_type_invalid) ||
       ( child->type == amxs_sync_type_ctx)) {
        status = amxs_status_invalid_type;
        goto exit;
    }

    status = amxs_validate_attributes(parent->attributes, child->attributes);
    when_failed(status, exit);
    status = amxs_update_child_attributes(parent->attributes, &child->attributes);
    when_failed(status, exit);

    amxc_llist_iterate(it, &child->entries) {
        amxs_sync_entry_t* entry = amxc_container_of(it, amxs_sync_entry_t, it);

        status = amxs_update_child_attributes(child->attributes, &entry->attributes);
        when_failed(status, exit);
    }

    amxc_llist_iterate(it, &parent->entries) {
        amxs_sync_entry_t* entry = amxc_container_of(it, amxs_sync_entry_t, it);
        if(amxs_sync_entry_compare(entry, child) == 0) {
            status = amxs_status_duplicate;
            goto exit;
        }
    }
    amxc_llist_append(&parent->entries, &child->it);

    status = amxs_status_ok;

exit:
    return status;
}

int amxs_sync_entry_compare(amxs_sync_entry_t* entry1, amxs_sync_entry_t* entry2) {
    int ret = -1;

    if(entry1 == entry2) {
        ret = 0;
        goto exit;
    }

    if((entry1 == NULL) || (entry2 == NULL)) {
        goto exit;
    }

    if(entry1->type != entry2->type) {
        goto exit;
    }

    if(amxs_sync_entry_compare_name(entry1->a, entry2->a) != 0) {
        goto exit;
    }

    if(amxs_sync_entry_compare_name(entry1->b, entry2->b) != 0) {
        goto exit;
    }

    if(((entry1->attributes | entry2->attributes) & (AMXS_SYNC_ONLY_B_TO_A | AMXS_SYNC_ONLY_A_TO_B ))
       == (AMXS_SYNC_ONLY_B_TO_A | AMXS_SYNC_ONLY_A_TO_B)) {
        goto exit;
    }

    ret = 0;

exit:
    return ret;
}
