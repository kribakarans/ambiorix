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
#include <stdarg.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <setjmp.h>
#include <cmocka.h>

#include <amxc/amxc_variant.h>
#include <amxc/amxc_htable.h>
#include <amxc/amxc_lqueue.h>

#include <amxp/amxp_signal.h>
#include <amxp/amxp_slot.h>

#include <amxd/amxd_dm.h>

#include <amxb/amxb_be.h>
#include <amxb/amxb.h>

#include "test_amxb_ba_subscribe.h"

#include <amxc/amxc_macros.h>
static char* dummy_ctx = "xbus";
static char verify_host[64];
static char verify_port[64];
static char verify_path[64];
static int return_val;
static const char* sub_obj = NULL;

int __wrap_dlclose(void* handle);

static void handle_events(void) {
    printf("Handling events ");
    while(amxp_signal_read() == 0) {
        printf(".");
    }
    printf("\n");
}

static void* dummy_connect(const char* host,
                           const char* port,
                           const char* path,
                           UNUSED amxp_signal_mngr_t* sigmngr) {
    strcpy(verify_host, host);
    strcpy(verify_port, port);
    strcpy(verify_path, path);

    return dummy_ctx;
}

static int dummy_disconnect(void* ctx) {
    assert_ptr_equal(ctx, dummy_ctx);
    return return_val;
}

static int dummy_get_fd(void* ctx) {
    assert_ptr_equal(ctx, dummy_ctx);
    return return_val;
}

static void dummy_free(void* ctx) {
    assert_ptr_equal(ctx, dummy_ctx);
}

static int dummy_read(void* const ctx) {
    assert_ptr_equal(ctx, dummy_ctx);
    return return_val;
}

static int dummy_describe(void* const ctx,
                          const char* object,
                          UNUSED const char* search_path,
                          UNUSED uint32_t flags,
                          UNUSED uint32_t access,
                          amxc_var_t* values,
                          UNUSED int timeout) {
    assert_ptr_equal(ctx, dummy_ctx);
    amxc_var_set_type(values, AMXC_VAR_ID_LIST);
    amxc_var_t* obj_data = amxc_var_add(amxc_htable_t, values, NULL);

    amxc_string_t path;
    amxc_string_init(&path, 0);
    amxc_string_setf(&path, "%s%s", object, search_path);

    amxc_var_add_key(cstring_t, obj_data, "path", amxc_string_get(&path, 0));
    amxc_var_dump(values, STDOUT_FILENO);
    fflush(stdout);

    amxc_string_clean(&path);
    return 0;
}

static int dummy_subscribe(void* const ctx,
                           UNUSED const char* object) {
    assert_ptr_equal(ctx, dummy_ctx);
    return return_val;
}

static int dummy_unsubscribe(void* const ctx,
                             UNUSED const char* object) {
    assert_ptr_equal(ctx, dummy_ctx);
    return return_val;
}

static amxb_be_funcs_t dummy_be1 = {
    .connect = dummy_connect,
    .disconnect = dummy_disconnect,
    .get_fd = dummy_get_fd,
    .read = dummy_read,
    .subscribe = dummy_subscribe,
    .unsubscribe = dummy_unsubscribe,
    .describe = dummy_describe,
    .free = dummy_free,
    .name = "xbus",
    .size = sizeof(amxb_be_funcs_t),
};

static amxb_be_funcs_t dummy_be3 = {
    .connect = dummy_connect,
    .name = "zbus",
    .size = sizeof(amxb_be_funcs_t),
};

static amxb_be_funcs_t dummy_be4 = {
    .connect = dummy_connect,
    .subscribe = dummy_subscribe,
    .describe = dummy_describe,
    .name = "ybus",
    .size = sizeof(amxb_be_funcs_t),
};

int __wrap_dlclose(UNUSED void* handle) {
    return 0;
}

static void dummy_notify_handler(UNUSED const char* const sig_name,
                                 UNUSED const amxc_var_t* const data,
                                 UNUSED void* const priv) {
    return;
}

static void dummy_notify_handler2(UNUSED const char* const sig_name,
                                  UNUSED const amxc_var_t* const data,
                                  UNUSED void* const priv) {
    return;
}

void test_amxb_subscribe(UNUSED void** state) {
    amxb_bus_ctx_t* ctx = NULL;

    assert_int_equal(amxb_be_register(&dummy_be1), 0);
    assert_int_equal(amxb_be_register(&dummy_be3), 0);

    return_val = 0;
    sub_obj = "object";
    assert_int_equal(amxb_connect(&ctx, "xbus://test:80/var/run/xbus.sock"), 0);
    assert_int_not_equal(amxb_subscribe(ctx, "object", NULL, NULL, NULL), return_val);
    assert_int_not_equal(amxb_subscribe(ctx, NULL, NULL, NULL, NULL), return_val);
    assert_int_not_equal(amxb_subscribe(NULL, NULL, NULL, NULL, NULL), return_val);
    assert_int_equal(amxb_subscribe(ctx, "object", NULL, dummy_notify_handler, NULL), return_val);
    assert_int_equal(amxb_subscribe(ctx, "object", NULL, dummy_notify_handler, NULL), return_val);
    assert_int_equal(amxb_unsubscribe(ctx, "object", dummy_notify_handler, NULL), return_val);
    assert_int_equal(amxb_subscribe(ctx, "object.*.", NULL, dummy_notify_handler, NULL), return_val);
    assert_int_equal(amxb_unsubscribe(ctx, "object.*.", dummy_notify_handler, NULL), return_val);
    return_val = -1;
    sub_obj = "other_object";
    assert_int_equal(amxb_subscribe(ctx, "other_object", NULL, dummy_notify_handler, NULL), return_val);
    return_val = 0;
    assert_int_equal(amxb_disconnect(ctx), return_val);
    assert_int_not_equal(amxb_subscribe(ctx, "other_object", NULL, dummy_notify_handler, NULL), return_val);
    amxb_free(&ctx);

    return_val = 0;
    assert_int_not_equal(amxb_subscribe(ctx, "other_object", NULL, dummy_notify_handler, NULL), return_val);

    assert_int_equal(amxb_connect(&ctx, "zbus://test:80/var/run/zbus.sock"), 0);
    assert_int_equal(amxb_subscribe(ctx, "object", NULL, dummy_notify_handler, NULL), AMXB_ERROR_NOT_SUPPORTED_OP);
    amxb_free(&ctx);

    assert_int_equal(amxb_be_unregister(&dummy_be1), 0);
    assert_int_equal(amxb_be_unregister(&dummy_be3), 0);
}

void test_amxb_subscribe_invalid_path(UNUSED void** state) {
    amxb_bus_ctx_t* ctx = NULL;

    assert_int_equal(amxb_be_register(&dummy_be1), 0);
    assert_int_equal(amxb_be_register(&dummy_be3), 0);

    return_val = 0;
    sub_obj = "object";
    assert_int_equal(amxb_connect(&ctx, "xbus://test:80/var/run/xbus.sock"), 0);
    assert_int_not_equal(amxb_subscribe(ctx, "object.parameter+", NULL, dummy_notify_handler, NULL), return_val);
    assert_int_not_equal(amxb_subscribe(ctx, "object.parameter[testing].", NULL, dummy_notify_handler, NULL), return_val);
    assert_int_not_equal(amxb_subscribe(ctx, "object.{i}.", NULL, dummy_notify_handler, NULL), return_val);
    assert_int_not_equal(amxb_unsubscribe(ctx, "object.parameter+", dummy_notify_handler, NULL), return_val);
    assert_int_not_equal(amxb_unsubscribe(ctx, "object.parameter[testing].", dummy_notify_handler, NULL), return_val);
    assert_int_not_equal(amxb_unsubscribe(ctx, "object.{i}.", dummy_notify_handler, NULL), return_val);
    assert_int_equal(amxb_disconnect(ctx), return_val);
    amxb_free(&ctx);

    assert_int_equal(amxb_be_unregister(&dummy_be1), 0);
    assert_int_equal(amxb_be_unregister(&dummy_be3), 0);
}

void test_amxb_subscribe_should_not_segfault(UNUSED void** state) {
    amxb_bus_ctx_t* ctx = NULL;

    assert_int_equal(amxb_be_register(&dummy_be1), 0);

    assert_int_equal(amxb_connect(&ctx, "xbus://test:80/var/run/xbus.sock"), 0);
    sub_obj = "myroot.some_object.some_other";
    return_val = 0;
    assert_int_equal(amxb_subscribe(ctx, "myroot.some_object.some_other.", NULL, dummy_notify_handler, NULL), return_val);
    assert_int_equal(amxb_unsubscribe(ctx, "myroot.some_object.some_other.", dummy_notify_handler, NULL), return_val);

    amxb_free(&ctx);

    assert_int_equal(amxb_be_unregister(&dummy_be1), 0);
}

void test_amxb_unsubscribe(UNUSED void** state) {
    amxb_bus_ctx_t* ctx = NULL;

    assert_int_equal(amxb_be_register(&dummy_be1), 0);
    assert_int_equal(amxb_be_register(&dummy_be3), 0);
    assert_int_equal(amxb_be_register(&dummy_be4), 0);

    return_val = 0;
    sub_obj = "object";
    assert_int_equal(amxb_connect(&ctx, "xbus://test:80/var/run/xbus.sock"), 0);
    assert_int_not_equal(amxb_unsubscribe(ctx, "object", NULL, NULL), return_val);
    assert_int_not_equal(amxb_unsubscribe(ctx, NULL, NULL, NULL), return_val);
    assert_int_not_equal(amxb_unsubscribe(NULL, NULL, NULL, NULL), return_val);
    assert_int_equal(amxb_subscribe(ctx, "object", NULL, dummy_notify_handler, NULL), return_val);
    assert_int_equal(amxb_subscribe(ctx, "object", NULL, dummy_notify_handler, NULL), return_val);
    assert_int_equal(amxb_subscribe(ctx, "object", NULL, dummy_notify_handler2, NULL), return_val);
    assert_int_equal(amxb_unsubscribe(ctx, "object", dummy_notify_handler2, NULL), return_val);
    assert_int_equal(amxb_unsubscribe(ctx, "object", dummy_notify_handler, NULL), return_val);
    return_val = -1;
    sub_obj = "other_object";
    assert_int_equal(amxb_subscribe(ctx, "other_object", NULL, dummy_notify_handler, NULL), return_val);
    return_val = 0;
    assert_int_not_equal(amxb_unsubscribe(ctx, "other_object", dummy_notify_handler, NULL), return_val);
    assert_int_equal(amxb_subscribe(ctx, "other_object", NULL, dummy_notify_handler, NULL), return_val);
    assert_int_equal(amxb_disconnect(ctx), return_val);
    assert_int_not_equal(amxb_unsubscribe(ctx, "other_object", dummy_notify_handler, NULL), return_val);
    amxb_free(&ctx);

    return_val = 0;
    assert_int_not_equal(amxb_unsubscribe(ctx, "other_object", dummy_notify_handler, NULL), return_val);

    sub_obj = "test_object";
    assert_int_equal(amxb_connect(&ctx, "ybus://test:80/var/run/ybus.sock"), 0);
    assert_int_equal(amxb_subscribe(ctx, "test_object", NULL, dummy_notify_handler, NULL), return_val);
    assert_int_equal(amxb_unsubscribe(ctx, "test_object", dummy_notify_handler, NULL), return_val);
    amxb_free(&ctx);

    assert_int_equal(amxb_be_unregister(&dummy_be1), 0);
    assert_int_equal(amxb_be_unregister(&dummy_be3), 0);
    assert_int_equal(amxb_be_unregister(&dummy_be4), 0);
}


void test_amxb_subscription_new(UNUSED void** state) {
    amxb_bus_ctx_t* ctx = NULL;
    amxb_subscription_t* sub = NULL;
    amxb_subscription_t* fsub = NULL;

    assert_int_equal(amxb_be_register(&dummy_be1), 0);
    assert_int_equal(amxb_be_register(&dummy_be3), 0);

    return_val = 0;
    sub_obj = "object";
    assert_int_equal(amxb_connect(&ctx, "xbus://test:80/var/run/xbus.sock"), 0);
    assert_int_equal(amxb_subscription_new(&sub, ctx, "object", NULL, dummy_notify_handler, NULL), return_val);
    assert_non_null(sub);

    fsub = amxb_subscription_find(ctx, "object", dummy_notify_handler, NULL);
    assert_non_null(fsub);
    assert_ptr_equal(fsub, sub);

    assert_int_equal(amxb_subscription_delete(&sub), return_val);
    assert_null(sub);

    assert_int_equal(amxb_subscription_new(&sub, ctx, "object", NULL, dummy_notify_handler, NULL), return_val);
    assert_non_null(sub);

    assert_int_equal(amxb_disconnect(ctx), return_val);
    amxb_free(&ctx);

    assert_int_equal(amxb_subscription_delete(&sub), return_val);
    assert_null(sub);

    assert_int_equal(amxb_be_unregister(&dummy_be1), 0);
    assert_int_equal(amxb_be_unregister(&dummy_be3), 0);
}

static void test_wait_done(UNUSED const char* const sig_name,
                           UNUSED const amxc_var_t* const data,
                           void* const priv) {
    uint32_t* counter = (uint32_t*) priv;
    (*counter)++;
}

void test_amxb_wait_for(UNUSED void** state) {
    amxb_bus_ctx_t* ctx = NULL;
    uint32_t counter = 0;

    amxp_sigmngr_add_signal(NULL, "wait:done");
    amxp_slot_connect(NULL, "wait:done", NULL, test_wait_done, &counter);

    assert_int_equal(amxb_be_register(&dummy_be1), 0);
    assert_int_equal(amxb_be_register(&dummy_be3), 0);

    assert_int_equal(amxb_connect(&ctx, "xbus://test:80/var/run/xbus.sock"), 0);
    assert_int_equal(amxb_wait_for_object("MyObject"), 0);
    handle_events();
    assert_int_equal(counter, 1);

    assert_int_equal(amxb_wait_for_object("MyObject."), 0);
    assert_int_equal(amxb_wait_for_object("YetAnotherObject."), 0);
    assert_int_equal(amxb_wait_for_object("YetAnotherObject.SubObject."), 0);
    handle_events();
    assert_int_equal(counter, 2);

    amxb_free(&ctx);

    assert_int_equal(amxb_connect(&ctx, "zbus://test:80/var/run/zbus.sock"), 0);
    assert_int_equal(amxb_wait_for_object("MyObject."), 0);
    assert_int_equal(amxb_wait_for_object("YetAnotherObject."), 0);
    assert_int_equal(amxb_wait_for_object("YetAnotherObject.SubObject."), 0);
    handle_events();
    assert_int_equal(counter, 2);

    assert_int_equal(amxb_be_unregister(&dummy_be1), 0);
    assert_int_equal(amxb_be_unregister(&dummy_be3), 0);
}

void test_amxb_subscription_find(UNUSED void** state) {
    amxb_bus_ctx_t* ctx = NULL;
    amxb_subscription_t* sub1 = NULL;
    amxb_subscription_t* sub2 = NULL;
    amxb_subscription_t* fsub = NULL;

    assert_int_equal(amxb_be_register(&dummy_be1), 0);

    return_val = 0;
    sub_obj = "object";
    assert_int_equal(amxb_connect(&ctx, "xbus://test:80/var/run/xbus.sock"), 0);

    assert_int_equal(amxb_subscription_new(&sub1, ctx, "object.", NULL, dummy_notify_handler, NULL), return_val);
    assert_non_null(sub1);
    assert_int_equal(amxb_subscription_new(&sub2, ctx, "object.subobject.", NULL, dummy_notify_handler, NULL), return_val);
    assert_non_null(sub2);

    fsub = amxb_subscription_find_child(ctx, "object.");
    assert_non_null(fsub);
    assert_ptr_equal(sub2, fsub);

    fsub = amxb_subscription_find_parent(ctx, "object.subobject.");
    assert_non_null(fsub);
    assert_ptr_equal(sub1, fsub);

    fsub = amxb_subscription_find_parent(ctx, "test.subobject.");
    assert_null(fsub);

    fsub = amxb_subscription_find_child(ctx, "test.");
    assert_null(fsub);

    fsub = amxb_subscription_find_child(ctx, NULL);
    assert_null(fsub);

    fsub = amxb_subscription_find_parent(ctx, "");
    assert_null(fsub);

    assert_int_equal(amxb_subscription_delete(&sub1), 0);
    assert_int_equal(amxb_subscription_delete(&sub2), 0);

    assert_int_equal(amxb_disconnect(ctx), return_val);
    amxb_free(&ctx);

    assert_int_equal(amxb_be_unregister(&dummy_be1), 0);
}
