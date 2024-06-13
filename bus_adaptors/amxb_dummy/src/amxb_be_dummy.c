/****************************************************************************
**
** SPDX-License-Identifier: BSD-2-Clause-Patent
**
** SPDX-FileCopyrightText: Copyright (c) 2021 SoftAtHome
**
** Redistribution and use in source and binary forms, with or
** without modification, are permitted provided that the following
** conditions are met:
**
** 1. Redistributions of source code must retain the above copyright
** notice, this list of conditions and the following disclaimer.
**
** 2. Redistributions in binary form must reproduce the above
** copyright notice, this list of conditions and the following
** disclaimer in the documentation and/or other materials provided
** with the distribution.
**
** Subject to the terms and conditions of this license, each
** copyright holder and contributor hereby grants to those receiving
** rights under this license a perpetual, worldwide, non-exclusive,
** no-charge, royalty-free, irrevocable (except for failure to
** satisfy the conditions of this license) patent license to make,
** have made, use, offer to sell, sell, import, and otherwise
** transfer this software, where such license applies only to those
** patent claims, already acquired or hereafter acquired, licensable
** by such copyright holder or contributor that are necessarily
** infringed by:
**
** (a) their Contribution(s) (the licensed copyrights of copyright
** holders and non-copyrightable additions of contributors, in
** source or binary form) alone; or
**
** (b) combination of their Contribution(s) with the work of
** authorship to which such Contribution(s) was added by such
** copyright holder or contributor, if, at the time the Contribution
** is added, such addition causes such combination to be necessarily
** infringed. The patent license shall not apply to any other
** combinations which include the Contribution.
**
** Except as expressly stated above, no rights or licenses from any
** copyright holder or contributor is granted under this license,
** whether expressly, by implication, estoppel or otherwise.
**
** DISCLAIMER
**
** THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
** CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
** INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
** MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
** DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR
** CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
** SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
** LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
** USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
** AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
** LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
** ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
** POSSIBILITY OF SUCH DAMAGE.
**
****************************************************************************/

#include "amxb_be_dummy/amxb_be_dummy.h"
#include "amxb_dummy_version.h"
#include <stdlib.h>
#include <amxc/amxc_macros.h>

static amxp_signal_mngr_t* dummy_sigmngr = NULL;
typedef struct _dummy_ctx {
    int fd;
    amxc_htable_t subscriptions;
    amxd_dm_t* dm;
} dummy_ctx_t;

static void amxb_dummy_send_notification(const char* const sig_name,
                                         const amxc_var_t* const data,
                                         void* const priv) {
    amxc_var_t notification;
    amxc_htable_it_t* it = (amxc_htable_it_t*) priv;
    amxc_var_init(&notification);
    amxc_var_set_type(&notification, AMXC_VAR_ID_HTABLE);

    amxc_var_copy(&notification, data);
    amxc_var_add_key(cstring_t, &notification, "notification", sig_name);

    amxp_sigmngr_emit_signal(dummy_sigmngr, amxc_htable_it_get_key(it), &notification);

    amxc_var_clean(&notification);
}


static void amxb_dummy_free_subscription(UNUSED const char* key, amxc_htable_it_t* it) {
    free(it);
}

void* amxb_dummy_connect(UNUSED const char* host,
                         UNUSED const char* port,
                         UNUSED const char* path,
                         amxp_signal_mngr_t* sigmngr) {
    static int cur_fd = 100;
    dummy_ctx_t* d = (dummy_ctx_t*) calloc(1, sizeof(dummy_ctx_t));
    d->fd = cur_fd++;
    amxc_htable_init(&d->subscriptions, 5);
    dummy_sigmngr = sigmngr;
    return d;
}

int amxb_dummy_disconnect(UNUSED void* ctx) {
    dummy_sigmngr = NULL;
    return 0;
}

int amxb_dummy_get_fd(void* const ctx) {
    dummy_ctx_t* d = (dummy_ctx_t*) ctx;
    return d->fd;
}

void amxb_dummy_free(void* ctx) {
    dummy_ctx_t* d = (dummy_ctx_t*) ctx;
    amxc_htable_clean(&d->subscriptions, amxb_dummy_free_subscription);
    free(d);
}

int amxb_dummy_register_cb(void* const ctx,
                           amxd_dm_t* const dm) {
    dummy_ctx_t* d = (dummy_ctx_t*) ctx;
    d->dm = dm;
    return 0;
}

int amxb_dummy_subscribe(void* const ctx,
                         const char* object) {

    dummy_ctx_t* d = (dummy_ctx_t*) ctx;

    int retval = 0;
    amxc_string_t expression;
    amxc_htable_it_t* it = NULL;

    amxc_string_init(&expression, 0);

    when_failed(retval, exit);

    it = (amxc_htable_it_t*) calloc(1, sizeof(amxc_htable_it_t));
    amxc_htable_insert(&d->subscriptions, object, it);
    amxc_string_appendf(&expression, "path starts with \"%s.\"", object);
    amxp_slot_connect_filtered(&d->dm->sigmngr,
                               ".*",
                               amxc_string_get(&expression, 0),
                               amxb_dummy_send_notification,
                               it);

exit:
    amxc_string_clean(&expression);
    return retval;
}

int amxb_dummy_unsubscribe(void* const ctx,
                           const char* object) {
    dummy_ctx_t* d = (dummy_ctx_t*) ctx;

    amxc_htable_it_t* it = amxc_htable_get(&d->subscriptions, object);
    if(it != NULL) {
        amxp_slot_disconnect_with_priv(&d->dm->sigmngr, amxb_dummy_send_notification, it);
    }
    amxc_htable_it_clean(it, amxb_dummy_free_subscription);

    return 0;
}

static amxb_be_funcs_t amxb_dummy_impl = {
    .it = { .ait = NULL, .key = NULL, .next = NULL },
    .handle = NULL,
    .connections = { .head = NULL, .tail = NULL },
    .name = "dummy",
    .size = sizeof(amxb_be_funcs_t),
    .connect = amxb_dummy_connect,
    .disconnect = amxb_dummy_disconnect,
    .get_fd = amxb_dummy_get_fd,
    .read = NULL,
    .new_invoke = NULL,
    .free_invoke = NULL,
    .invoke = NULL,
    .async_invoke = NULL,
    .close_request = NULL,
    .wait_request = NULL,
    .subscribe = amxb_dummy_subscribe,
    .unsubscribe = amxb_dummy_unsubscribe,
    .free = amxb_dummy_free,
    .register_dm = amxb_dummy_register_cb,
    .get = NULL,
    .set = NULL,
    .add = NULL,
    .del = NULL,
    .get_supported = NULL,
    .set_config = NULL,
    .describe = NULL,
    .list = NULL,
    .listen = NULL,
    .accept = NULL,
    .read_raw = NULL,
    .wait_for = NULL,
    .capabilities = NULL,
    .has = NULL,
    .get_instances = NULL
};

static amxb_version_t sup_min_lib_version = {
    .major = 2,
    .minor = 0,
    .build = 0
};

static amxb_version_t sup_max_lib_version = {
    .major = 4,
    .minor = -1,
    .build = -1
};

static amxb_version_t dummy_be_version = {
    .major = AMXB_DUMMY_VERSION_MAJOR,
    .minor = AMXB_DUMMY_VERSION_MINOR,
    .build = AMXB_DUMMY_VERSION_BUILD,
};

amxb_be_info_t amxb_dummy_be_info = {
    .min_supported = &sup_min_lib_version,
    .max_supported = &sup_max_lib_version,
    .be_version = &dummy_be_version,
    .name = "dummy",
    .description = "AMXB Dummy Backend for testing",
    .funcs = &amxb_dummy_impl,
};

amxb_be_info_t* amxb_be_info(void) {
    return &amxb_dummy_be_info;
}
