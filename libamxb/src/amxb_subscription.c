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

#include <amxc/amxc_macros.h>
#include <amxc/amxc.h>
#include <amxp/amxp.h>

#include <amxd/amxd_types.h>
#include <amxd/amxd_path.h>

#include <amxb/amxb_error.h>
#include <amxb/amxb_types.h>
#include <amxb/amxb_subscription.h>
#include <amxb/amxb_subscribe.h>

#include "amxb_priv.h"

static amxb_sub_t* amxb_sub_alloc(const char* object,
                                  amxp_slot_fn_t slot_cb,
                                  void* priv) {
    amxb_sub_t* sub = NULL;
    amxd_path_t path;

    amxd_path_init(&path, NULL);

    when_str_empty(object, exit);
    when_null(slot_cb, exit);

    amxd_path_setf(&path, true, "%s", object);

    sub = (amxb_sub_t*) calloc(1, sizeof(amxb_sub_t));
    when_null((sub), exit);
    sub->data.slot_cb = slot_cb;
    sub->data.priv = priv;

    sub->data.object = amxd_path_get_fixed_part(&path, false);
    if(sub->data.object == NULL) {
        free(sub);
        sub = NULL;
        goto exit;
    }

    if(*sub->data.object != 0) {
        sub->data.object[strlen(sub->data.object) - 1] = 0;
    }

exit:
    amxd_path_clean(&path);
    return sub;
}

static bool amxb_subscription_matches(const char* p1,
                                      const char* p2,
                                      int len1,
                                      int len2) {
    bool match = false;
    if(len1 < len2) {
        if(strncmp(p1, p2, len1) == 0) {
            match = true;
        }
    }
    return match;
}

static amxb_subscription_t* amxb_subscription_find_relation(amxb_bus_ctx_t* bus_ctx,
                                                            const char* object,
                                                            bool parent) {
    amxb_subscription_t* subscription = NULL;
    amxd_path_t search_path;
    amxd_path_t sub_path;
    char* fsp = NULL;
    int search_len = 0;

    amxd_path_init(&search_path, NULL);
    amxd_path_init(&sub_path, NULL);

    when_str_empty(object, exit);

    amxd_path_setf(&search_path, true, "%s", object);
    fsp = amxd_path_get_fixed_part(&search_path, false);
    search_len = strlen(fsp);

    amxc_llist_iterate(it, (&bus_ctx->client_subs)) {
        amxb_sub_t* sub = amxc_container_of(it, amxb_sub_t, it);
        char* fp = NULL;
        int sub_len = 0;
        amxd_path_setf(&sub_path, true, "%s", sub->data.object);

        fp = amxd_path_get_fixed_part(&sub_path, false);
        sub_len = strlen(fp);
        subscription = &sub->data;

        if(parent) {
            if(amxb_subscription_matches(fp, fsp, sub_len, search_len)) {
                free(fp);
                break;
            }
        } else {
            if(amxb_subscription_matches(fsp, fp, search_len, sub_len)) {
                free(fp);
                break;
            }
        }
        free(fp);
        subscription = NULL;
    }

exit:
    amxd_path_clean(&search_path);
    amxd_path_clean(&sub_path);
    free(fsp);
    return subscription;
}

int amxb_subscription_remove(amxb_subscription_t* subscription) {
    int rv = AMXB_STATUS_OK;
    amxb_sub_t* sub = amxc_container_of(subscription, amxb_sub_t, data);

    if(sub->it.llist != NULL) {
        amxb_bus_ctx_t* bus_ctx = NULL;
        bus_ctx = amxc_container_of(sub->it.llist, amxb_bus_ctx_t, client_subs);
        amxc_llist_it_take(&sub->it);
        rv = amxb_unsubscribe(bus_ctx, subscription->object, subscription->slot_cb,
                              subscription->priv);
    }

    return rv;
}

int amxb_subscription_new(amxb_subscription_t** subscription,
                          amxb_bus_ctx_t* bus_ctx,
                          const char* object,
                          const char* expression,
                          amxp_slot_fn_t slot_cb,
                          void* priv) {
    int retval = AMXB_ERROR_UNKNOWN;
    amxb_sub_t* sub = amxb_sub_alloc(object, slot_cb, priv);

    when_null(sub, exit);
    *subscription = &sub->data;

    retval = amxb_subscribe(bus_ctx,
                            object,
                            expression,
                            (*subscription)->slot_cb,
                            (*subscription)->priv);
    when_failed(retval, exit);
    amxc_llist_append(&bus_ctx->client_subs, &sub->it);

exit:
    if((retval != AMXB_STATUS_OK) && (sub != NULL)) {
        free((*subscription)->object);
        free(sub);
        *subscription = NULL;
    }
    return retval;
}

amxb_subscription_t* amxb_subscription_find(amxb_bus_ctx_t* bus_ctx,
                                            const char* object,
                                            amxp_slot_fn_t slot_cb,
                                            void* priv) {
    amxb_subscription_t* subscription = NULL;

    when_str_empty(object, exit);
    when_null(slot_cb, exit);

    amxc_llist_iterate(it, (&bus_ctx->client_subs)) {
        amxb_sub_t* sub = amxc_container_of(it, amxb_sub_t, it);
        subscription = &sub->data;
        if((strcmp(subscription->object, object) == 0) &&
           ( subscription->slot_cb == slot_cb) &&
           ( subscription->priv == priv)) {
            break;
        }
        subscription = NULL;
    }

exit:
    return subscription;
}

amxb_subscription_t* amxb_subscription_find_parent(amxb_bus_ctx_t* bus_ctx,
                                                   const char* object) {
    return amxb_subscription_find_relation(bus_ctx, object, true);
}

amxb_subscription_t* amxb_subscription_find_child(amxb_bus_ctx_t* bus_ctx,
                                                  const char* object) {
    return amxb_subscription_find_relation(bus_ctx, object, false);
}

int amxb_subscription_delete(amxb_subscription_t** subscription) {
    int rv = AMXB_STATUS_OK;
    amxb_sub_t* sub = NULL;

    when_null(subscription, exit);
    when_null(*subscription, exit);

    sub = amxc_container_of((*subscription), amxb_sub_t, data);
    rv = amxb_subscription_remove((*subscription));

    amxc_llist_it_take(&(*subscription)->it);
    free((*subscription)->object);
    free(sub);

    *subscription = NULL;

exit:
    return rv;
}

void amxb_subscription_remove_it(amxc_llist_it_t* it) {
    amxb_subscription_t* subscription = amxc_container_of(it, amxb_subscription_t, it);
    amxb_subscription_delete(&subscription);
}
