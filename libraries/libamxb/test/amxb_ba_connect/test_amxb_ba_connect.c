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

#include "test_amxb_ba_connect.h"

#include <amxc/amxc_macros.h>
static char* dummy_ctx = "xbus";
static char verify_host[64];
static char verify_port[64];
static char verify_path[64];
static int return_val;

int __wrap_dlclose(void* handle);

static void* dummy_connect(const char* host,
                           const char* port,
                           const char* path,
                           UNUSED amxp_signal_mngr_t* sigmngr) {
    if(host != NULL) {
        strcpy(verify_host, host);
    }
    if(port != NULL) {
        strcpy(verify_port, port);
    }
    strcpy(verify_path, path);

    return dummy_ctx;
}

static int dummy_disconnect(void* ctx) {
    assert_ptr_equal(ctx, dummy_ctx);
    return return_val;
}

static void* dummy_accept(UNUSED void* ctx, UNUSED amxp_signal_mngr_t* sigmngr) {
    return dummy_ctx;
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

static int dummy_read_raw(void* const ctx, UNUSED void* buf, UNUSED size_t size) {
    assert_ptr_equal(ctx, dummy_ctx);
    return return_val;
}

static amxb_be_funcs_t dummy_be1 = {
    .connect = dummy_connect,
    .disconnect = dummy_disconnect,
    .listen = dummy_connect,
    .accept = dummy_accept,
    .get_fd = dummy_get_fd,
    .read = dummy_read,
    .read_raw = dummy_read_raw,
    .free = dummy_free,
    .name = "xbus",
    .size = sizeof(amxb_be_funcs_t),
};

static amxb_be_funcs_t dummy_be2 = {
    .size = sizeof(amxb_be_funcs_t),
    .name = "ybus",
};

static amxb_be_funcs_t dummy_be3 = {
    .size = sizeof(amxb_be_funcs_t),
    .connect = dummy_connect,
    .name = "zbus",
};

int __wrap_dlclose(UNUSED void* handle) {
    return 0;
}

void test_amxb_connect(UNUSED void** state) {
    amxb_bus_ctx_t* ctx = NULL;
    assert_int_equal(amxb_be_register(&dummy_be1), 0);
    assert_int_equal(amxb_be_register(&dummy_be2), 0);

    assert_int_equal(amxb_connect(&ctx, "xbus://ipc:[/var/run/test.sock]"), AMXB_ERROR_INVALID_URI);
    assert_int_equal(amxb_connect(&ctx, "rommmel/test"), AMXB_ERROR_INVALID_URI);
    assert_int_equal(amxb_connect(NULL, "xbus://test:80/var/run/xbus.sock"), -1);
    assert_int_equal(amxb_connect(&ctx, "fake://test:80/var/run/fake.sock"), AMXB_ERROR_NOT_SUPPORTED_SCHEME);
    assert_ptr_equal(ctx, NULL);

    assert_int_equal(amxb_connect(&ctx, "ybus://test:80/var/run/ybus.sock"), AMXB_ERROR_NOT_SUPPORTED_OP);
    assert_ptr_equal(ctx, NULL);

    dummy_ctx = NULL;
    assert_int_equal(amxb_connect(&ctx, "xbus://test:80/var/run/xbus.sock"), AMXB_ERROR_BACKEND_FAILED);
    dummy_ctx = "xbus";
    assert_int_equal(amxb_connect(&ctx, "xbus://test:80/var/run/xbus.sock"), 0);
    assert_ptr_not_equal(ctx, NULL);
    assert_string_equal(verify_host, "test");
    assert_string_equal(verify_port, "80");
    assert_string_equal(verify_path, "/var/run/xbus.sock");
    assert_int_not_equal(amxb_connect(&ctx, "xbus://test:80/var/run/xbus.sock"), 0);
    assert_int_equal(amxb_disconnect(ctx), 0);
    amxb_free(&ctx);

    assert_int_equal(amxb_connect(&ctx, "xbus://test:80/var/run/xbus.sock"), 0);
    assert_int_equal(amxb_be_unregister(&dummy_be1), 0);
    ctx = NULL;
    assert_int_not_equal(amxb_disconnect(ctx), 0);
    amxb_free(&ctx);
    assert_ptr_equal(ctx, NULL);
    amxb_free(&ctx);
    amxb_free(NULL);

    assert_int_equal(amxb_be_unregister(&dummy_be2), 0);
}

void test_amxb_listen(UNUSED void** state) {
    amxb_bus_ctx_t* ctx = NULL;
    assert_int_equal(amxb_be_register(&dummy_be1), 0);

    dummy_ctx = "xbus";
    assert_int_equal(amxb_listen(&ctx, "xbus:/tmp/test.sock"), 0);
    assert_ptr_not_equal(ctx, NULL);
    assert_string_equal(verify_path, "/tmp/test.sock");
    assert_int_equal(amxb_disconnect(ctx), 0);
    amxb_free(&ctx);

    assert_int_equal(amxb_be_unregister(&dummy_be1), 0);
}

void test_amxb_accept(UNUSED void** state) {
    amxb_bus_ctx_t* lctx = NULL;
    amxb_bus_ctx_t* actx = NULL;
    assert_int_equal(amxb_be_register(&dummy_be1), 0);

    dummy_ctx = "xbus";
    assert_int_equal(amxb_listen(&lctx, "xbus:/tmp/test.sock"), 0);
    assert_int_equal(amxb_accept(lctx, &actx), 0);
    assert_ptr_not_equal(actx, NULL);
    assert_int_equal(amxb_disconnect(actx), 0);
    assert_int_equal(amxb_disconnect(lctx), 0);
    amxb_free(&lctx);
    amxb_free(&actx);

    assert_int_equal(amxb_be_unregister(&dummy_be1), 0);
}

void test_amxb_disconnect(UNUSED void** state) {
    amxb_bus_ctx_t* ctx = NULL;
    assert_int_equal(amxb_be_register(&dummy_be1), 0);
    assert_int_equal(amxb_be_register(&dummy_be3), 0);

    assert_int_not_equal(amxb_disconnect(NULL), 0);

    assert_int_equal(amxb_connect(&ctx, "xbus://test:80/var/run/xbus.sock"), 0);
    assert_ptr_not_equal(ctx, NULL);
    assert_int_equal(amxb_disconnect(ctx), 0);
    amxb_free(&ctx);

    assert_ptr_equal(ctx, NULL);
    assert_int_not_equal(amxb_disconnect(ctx), 0);
    assert_ptr_equal(ctx, NULL);

    assert_int_equal(amxb_connect(&ctx, "zbus://test:80/var/run/zbus.sock"), 0);
    assert_ptr_not_equal(ctx, NULL);
    assert_int_not_equal(amxb_disconnect(ctx), 0);
    assert_ptr_not_equal(ctx, NULL);
    amxb_free(&ctx);
    assert_ptr_equal(ctx, NULL);

    assert_int_equal(amxb_be_unregister(&dummy_be1), 0);
    assert_int_equal(amxb_be_unregister(&dummy_be3), 0);
}

void test_amxb_get_fd(UNUSED void** state) {
    amxb_bus_ctx_t* ctx = NULL;
    assert_int_equal(amxb_be_register(&dummy_be1), 0);
    assert_int_equal(amxb_be_register(&dummy_be3), 0);

    assert_int_not_equal(amxb_get_fd(NULL), 0);

    assert_int_equal(amxb_connect(&ctx, "xbus://test:80/var/run/xbus.sock"), 0);
    return_val = STDIN_FILENO;
    assert_int_equal(amxb_get_fd(ctx), return_val);
    return_val = -1;
    assert_int_equal(amxb_get_fd(ctx), return_val);
    return_val = 0;
    assert_int_equal(amxb_disconnect(ctx), 0);
    amxb_free(&ctx);

    return_val = 0;
    assert_int_equal(amxb_connect(&ctx, "zbus://test:80/var/run/zbus.sock"), 0);
    return_val = STDIN_FILENO;
    assert_int_equal(amxb_get_fd(ctx), -1);
    return_val = 0;
    assert_int_not_equal(amxb_disconnect(ctx), 0);
    amxb_free(&ctx);

    return_val = 0;
    assert_int_equal(amxb_be_unregister(&dummy_be1), 0);
    assert_int_equal(amxb_be_unregister(&dummy_be3), 0);
}

void test_amxb_read(UNUSED void** state) {
    amxb_bus_ctx_t* ctx = NULL;
    assert_int_equal(amxb_be_register(&dummy_be1), 0);
    assert_int_equal(amxb_be_register(&dummy_be3), 0);

    assert_int_equal(amxb_connect(&ctx, "xbus://test:80/var/run/xbus.sock"), 0);
    return_val = 0;
    assert_int_equal(amxb_read(ctx), return_val);
    return_val = -1;
    assert_int_equal(amxb_read(ctx), return_val);
    return_val = 0;
    assert_int_equal(amxb_disconnect(ctx), 0);
    amxb_free(&ctx);
    assert_ptr_equal(ctx, NULL);

    assert_int_equal(amxb_connect(&ctx, "zbus://test:80/var/run/zbus.sock"), 0);
    return_val = 0;
    assert_int_equal(amxb_read(ctx), -1);
    return_val = -1;
    assert_int_equal(amxb_read(ctx), -1);
    return_val = 0;
    amxb_free(&ctx);

    assert_int_equal(amxb_be_unregister(&dummy_be1), 0);
    assert_int_equal(amxb_be_unregister(&dummy_be3), 0);

    assert_int_not_equal(amxb_read(NULL), 0);
}

void test_amxb_find_uris(UNUSED void** state) {
    amxb_bus_ctx_t* ctx1 = NULL;
    amxb_bus_ctx_t* ctx2 = NULL;
    assert_int_equal(amxb_be_register(&dummy_be1), 0);
    assert_int_equal(amxb_be_register(&dummy_be3), 0);

    assert_int_equal(amxb_connect(&ctx1, "xbus://test:80/var/run/xbus.sock"), 0);
    assert_int_equal(amxb_connect(&ctx2, "zbus://test:80/var/run/zbus.sock"), 0);

    assert_ptr_equal(amxb_find_uri("xbus://test:80/var/run/xbus.sock"), ctx1);
    assert_ptr_equal(amxb_find_uri("zbus://test:80/var/run/zbus.sock"), ctx2);
    assert_ptr_equal(amxb_find_uri("ybus://test:80/var/run/ybus.sock"), NULL);

    amxb_free(&ctx1);
    amxb_free(&ctx2);

    assert_ptr_equal(amxb_find_uri("xbus://test:80/var/run/xbus.sock"), NULL);
    assert_ptr_equal(amxb_find_uri("zbus://test:80/var/run/zbus.sock"), NULL);
    assert_ptr_equal(amxb_find_uri("ybus://test:80/var/run/ybus.sock"), NULL);


    assert_int_equal(amxb_be_unregister(&dummy_be1), 0);
    assert_int_equal(amxb_be_unregister(&dummy_be3), 0);
}

void test_amxb_list_uris(UNUSED void** state) {
    amxb_bus_ctx_t* ctx1 = NULL;
    amxb_bus_ctx_t* ctx2 = NULL;
    amxc_array_t* array = NULL;
    assert_int_equal(amxb_be_register(&dummy_be1), 0);
    assert_int_equal(amxb_be_register(&dummy_be3), 0);

    assert_int_equal(amxb_connect(&ctx1, "xbus://test:80/var/run/xbus.sock"), 0);
    assert_int_equal(amxb_connect(&ctx2, "zbus://test:80/var/run/zbus.sock"), 0);

    array = amxb_list_uris();
    assert_int_equal(amxc_array_size(array), 2);
    amxc_array_delete(&array, NULL);

    amxb_free(&ctx1);
    amxb_free(&ctx2);

    array = amxb_list_uris();
    assert_int_equal(amxc_array_size(array), 0);
    amxc_array_delete(&array, NULL);

    assert_int_equal(amxb_be_unregister(&dummy_be1), 0);
    assert_int_equal(amxb_be_unregister(&dummy_be3), 0);
}

void test_amxb_read_raw(UNUSED void** state) {
    amxb_bus_ctx_t* ctx = NULL;
    char* buffer[100];
    assert_int_equal(amxb_be_register(&dummy_be1), 0);
    assert_int_equal(amxb_be_register(&dummy_be3), 0);

    assert_int_equal(amxb_connect(&ctx, "xbus://test:80/var/run/xbus.sock"), 0);
    return_val = 100;
    assert_int_equal(amxb_read_raw(ctx, buffer, 100), return_val);
    assert_int_equal(amxb_read_raw(ctx, NULL, 100), -1);
    assert_int_equal(amxb_read_raw(ctx, buffer, 0), -1);
    return_val = -1;
    assert_int_equal(amxb_read_raw(ctx, buffer, 100), return_val);
    return_val = 0;
    assert_int_equal(amxb_disconnect(ctx), 0);
    amxb_free(&ctx);
    assert_ptr_equal(ctx, NULL);

    assert_int_equal(amxb_connect(&ctx, "zbus://test:80/var/run/zbus.sock"), 0);
    return_val = 0;
    assert_int_equal(amxb_read_raw(ctx, buffer, 100), -1);
    return_val = -1;
    assert_int_equal(amxb_read_raw(ctx, buffer, 100), -1);
    return_val = 0;
    amxb_free(&ctx);

    assert_int_equal(amxb_be_unregister(&dummy_be1), 0);
    assert_int_equal(amxb_be_unregister(&dummy_be3), 0);

    assert_int_equal(amxb_read_raw(NULL, buffer, 100), -1);
}