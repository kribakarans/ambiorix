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
#include <string.h>

#include <amxc/amxc.h>
#include <amxp/amxp.h>
#include <amxd/amxd_dm.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_object_function.h>
#include <amxb/amxb_be.h>
#include <amxo/amxo.h>

#include "dummy_be.h"

#include <amxc/amxc_macros.h>
static amxd_dm_t remote_dm;
static amxo_parser_t parser;
static uint32_t caps = AMXB_BE_DISCOVER_DESCRIBE | AMXB_BE_DISCOVER_LIST | AMXB_BE_DISCOVER;
static amxp_signal_mngr_t* dummy_sigmngr = NULL;
static amxc_htable_t subscriptions;

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

static void* amxb_dummy_connect(UNUSED const char* host,
                                UNUSED const char* port,
                                UNUSED const char* path,
                                UNUSED amxp_signal_mngr_t* sigmngr) {

    amxd_dm_init(&remote_dm);
    amxo_parser_init(&parser);
    dummy_sigmngr = sigmngr;
    return &remote_dm;
}

static int amxb_dummy_disconnect(UNUSED void* ctx) {
    amxd_dm_clean(&remote_dm);
    dummy_sigmngr = NULL;
    return 0;
}

static int amxb_dummy_invoke(UNUSED void* const ctx,
                             amxb_invoke_t* invoke_ctx,
                             amxc_var_t* args,
                             amxb_request_t* request,
                             UNUSED int timeout) {

    amxc_var_t empty_args;
    amxc_var_t* return_value = NULL;
    amxc_var_init(&empty_args);
    amxc_var_set_type(&empty_args, AMXC_VAR_ID_HTABLE);
    amxc_var_set_type(request->result, AMXC_VAR_ID_LIST);

    int rv = 0;

    if(args == NULL) {
        args = &empty_args;
    }

    return_value = amxc_var_add_new(request->result);
    amxd_object_t* obj = amxd_dm_findf(&remote_dm, invoke_ctx->object);
    if(obj == NULL) {
        rv = amxd_status_invalid_path;
    } else {
        rv = amxd_object_invoke_function(obj, invoke_ctx->method, args, return_value);
    }

    amxc_var_clean(&empty_args);
    return rv;
}

static void amxb_dummy_free(UNUSED void* ctx) {
    amxo_parser_clean(&parser);
    amxd_dm_clean(&remote_dm);
}

static int amxb_dummy_register(UNUSED void* const ctx,
                               UNUSED amxd_dm_t* const dm) {
    return 0;
}

static bool amxb_dummy_has(UNUSED void* const ctx,
                           const char* object) {
    amxd_object_t* obj = amxd_dm_findf(&remote_dm, "%s", object);

    return obj != NULL;
}

static uint32_t amxb_dummy_capabilities(UNUSED void* const ctx) {
    return caps;
}

static int amxb_dummy_subscribe(UNUSED void* const ctx,
                                const char* object) {

    int retval = 0;
    amxc_string_t expression;
    amxc_htable_it_t* it = NULL;

    amxc_string_init(&expression, 0);

    when_failed(retval, exit);

    it = (amxc_htable_it_t*) calloc(1, sizeof(amxc_htable_it_t));
    amxc_htable_insert(&subscriptions, object, it);
    amxc_string_appendf(&expression, "path starts with \"%s.\"", object);
    amxp_slot_connect_filtered(&remote_dm.sigmngr,
                               ".*",
                               amxc_string_get(&expression, 0),
                               amxb_dummy_send_notification,
                               it);

exit:
    amxc_string_clean(&expression);
    return retval;
}

static int amxb_dummy_unsubscribe(UNUSED void* const ctx,
                                  const char* object) {
    amxc_htable_it_t* it = amxc_htable_get(&subscriptions, object);
    if(it != NULL) {
        amxp_slot_disconnect_with_priv(&remote_dm.sigmngr, amxb_dummy_send_notification, it);
    }
    amxc_htable_it_clean(it, amxb_dummy_free_subscription);

    return 0;
}

static amxb_be_funcs_t amxb_dummy_impl = {
    .connect = amxb_dummy_connect,
    .disconnect = amxb_dummy_disconnect,
    .get_fd = NULL,
    .read = NULL,
    .invoke = amxb_dummy_invoke,
    .async_invoke = NULL,
    .wait_request = NULL,
    .close_request = NULL,
    .subscribe = amxb_dummy_subscribe,
    .unsubscribe = amxb_dummy_unsubscribe,
    .free = amxb_dummy_free,
    .register_dm = amxb_dummy_register,
    .has = amxb_dummy_has,
    .capabilities = amxb_dummy_capabilities,
    .name = "dummy",
    .size = sizeof(amxb_be_funcs_t),
};

static amxb_version_t sup_min_lib_version = {
    .major = 2,
    .minor = 0,
    .build = -1
};

static amxb_version_t sup_max_lib_version = {
    .major = 2,
    .minor = -1,
    .build = -1
};

static amxb_version_t dummy_be_version = {
    .major = 0,
    .minor = 0,
    .build = 0,
};

amxb_be_info_t amxb_dummy_be_info = {
    .min_supported = &sup_min_lib_version,
    .max_supported = &sup_max_lib_version,
    .be_version = &dummy_be_version,
    .name = "dummy",
    .description = "AMXB Dummy Backend for testing",
    .funcs = &amxb_dummy_impl,
};

int test_register_dummy_be(void) {
    amxc_htable_init(&subscriptions, 5);
    return amxb_be_register(&amxb_dummy_impl);
}

int test_unregister_dummy_be(void) {
    amxc_htable_clean(&subscriptions, amxb_dummy_free_subscription);
    return amxb_be_unregister(&amxb_dummy_impl);
}

int test_load_dummy_remote(const char* odl) {
    amxd_object_t* root_obj = amxd_dm_get_root(&remote_dm);

    return amxo_parser_parse_file(&parser, odl, root_obj);
}

void test_set_dummy_caps(uint32_t dummy_caps) {
    caps = dummy_caps;
}

amxd_dm_t* test_get_dm(void) {
    return &remote_dm;
}

amxo_parser_t* test_get_parser(void) {
    return &parser;
}
