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

#include "test_amxb_ba_invoke.h"

#include <amxc/amxc_macros.h>
static char* dummy_ctx = "xbus";
static char* dummy_bus_data = "xbus dummy data";
static char verify_host[64];
static char verify_port[64];
static char verify_path[64];
static int return_val;

int __wrap_dlclose(void* handle);

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

static int dummy_new_invoke(amxb_invoke_t* invoke_ctx) {
    assert_ptr_not_equal(invoke_ctx, NULL);
    return return_val;
}

static void dummy_free_invoke(amxb_invoke_t* invoke_ctx) {
    assert_ptr_not_equal(invoke_ctx, NULL);
    return;
}

static int dummy_invoke(void* const ctx,
                        amxb_invoke_t* invoke_ctx,
                        UNUSED amxc_var_t* args,
                        amxb_request_t* request,
                        int timeout) {
    assert_ptr_equal(ctx, dummy_ctx);
    assert_string_equal(invoke_ctx->object, "object");
    assert_string_equal(invoke_ctx->method, "method");
    assert_ptr_not_equal(request, NULL);
    assert_int_equal(timeout, 10);
    return return_val;
}

static int dummy_async_invoke(void* const ctx,
                              amxb_invoke_t* invoke_ctx,
                              UNUSED amxc_var_t* args,
                              amxb_request_t* request) {
    assert_ptr_equal(ctx, dummy_ctx);
    assert_string_equal(invoke_ctx->object, "object");
    assert_string_equal(invoke_ctx->method, "method");
    request->bus_data = dummy_bus_data;
    return return_val;
}

static int dummy_wait_request(void* const ctx,
                              amxb_request_t* request,
                              UNUSED int timeout) {
    assert_ptr_equal(ctx, dummy_ctx);
    assert_ptr_equal(request->bus_data, dummy_bus_data);

    return return_val;
}

static int dummy_close_request(void* const ctx,
                               amxb_request_t* request) {
    assert_ptr_equal(ctx, dummy_ctx);
    assert_ptr_equal(request->bus_data, dummy_bus_data);
    return return_val;
}

static amxb_be_funcs_t dummy_be1 = {
    .connect = dummy_connect,
    .disconnect = dummy_disconnect,
    .get_fd = dummy_get_fd,
    .read = dummy_read,
    .new_invoke = dummy_new_invoke,
    .free_invoke = dummy_free_invoke,
    .invoke = dummy_invoke,
    .async_invoke = dummy_async_invoke,
    .wait_request = dummy_wait_request,
    .close_request = dummy_close_request,
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
    .async_invoke = dummy_async_invoke,
    .name = "abus",
    .size = sizeof(amxb_be_funcs_t),
};

int __wrap_dlclose(UNUSED void* handle) {
    return 0;
}

void test_amxb_new_free_invoke(UNUSED void** state) {
    amxb_bus_ctx_t* ctx = NULL;
    amxb_invoke_t* invoke_ctx = NULL;

    assert_int_equal(amxb_be_register(&dummy_be1), 0);
    assert_int_equal(amxb_be_register(&dummy_be3), 0);

    assert_int_not_equal(amxb_new_invoke(&invoke_ctx, ctx, "object", NULL, "method"), 0);
    return_val = 0;
    assert_int_equal(amxb_connect(&ctx, "xbus://test:80/var/run/xbus.sock"), 0);
    assert_int_equal(amxb_new_invoke(&invoke_ctx, ctx, "object", NULL, "method"), 0);
    assert_int_not_equal(amxb_new_invoke(&invoke_ctx, ctx, "object", NULL, "method"), 0);
    amxb_free_invoke(&invoke_ctx);

    assert_int_not_equal(amxb_new_invoke(NULL, NULL, "object", NULL, "method"), 0);
    assert_int_not_equal(amxb_new_invoke(&invoke_ctx, NULL, "object", NULL, "method"), 0);
    assert_int_not_equal(amxb_new_invoke(&invoke_ctx, ctx, NULL, NULL, NULL), 0);
    assert_int_not_equal(amxb_new_invoke(&invoke_ctx, ctx, "object", NULL, NULL), 0);
    assert_int_not_equal(amxb_new_invoke(&invoke_ctx, ctx, "", NULL, ""), 0);
    assert_int_not_equal(amxb_new_invoke(&invoke_ctx, ctx, "object", NULL, ""), 0);
    assert_int_equal(amxb_new_invoke(&invoke_ctx, ctx, "object", "interface", "method"), 0);
    assert_string_equal(invoke_ctx->object, "object");
    assert_string_equal(invoke_ctx->interface, "interface");
    assert_string_equal(invoke_ctx->method, "method");
    assert_ptr_equal(invoke_ctx->it.llist, &ctx->invoke_ctxs);
    amxb_free_invoke(&invoke_ctx);
    amxb_free_invoke(&invoke_ctx);
    amxb_free_invoke(NULL);

    return_val = -1;
    assert_int_not_equal(amxb_new_invoke(&invoke_ctx, ctx, "object", NULL, "method"), 0);
    assert_ptr_equal(invoke_ctx, NULL);

    return_val = 0;
    assert_int_equal(amxb_disconnect(ctx), 0);
    assert_int_not_equal(amxb_new_invoke(&invoke_ctx, ctx, "object", NULL, "method"), 0);
    assert_ptr_equal(invoke_ctx, NULL);

    amxb_free(&ctx);

    assert_int_equal(amxb_be_unregister(&dummy_be1), 0);
    assert_int_equal(amxb_be_unregister(&dummy_be3), 0);
}

void test_amxb_invoke(UNUSED void** state) {
    amxb_bus_ctx_t* ctx = NULL;
    amxc_var_t ret;
    amxc_var_t args;
    amxb_invoke_t* invoke_ctx = NULL;

    amxc_var_init(&ret);
    amxc_var_init(&args);
    assert_int_equal(amxb_be_register(&dummy_be1), 0);
    assert_int_equal(amxb_be_register(&dummy_be3), 0);

    return_val = 0;
    assert_int_equal(amxb_connect(&ctx, "xbus://test:80/var/run/xbus.sock"), 0);
    assert_int_equal(amxb_new_invoke(&invoke_ctx, ctx, "object", NULL, "method"), 0);

    assert_int_equal(amxb_invoke(invoke_ctx, NULL, NULL, NULL, NULL, 10), return_val);
    assert_int_equal(amxb_invoke(invoke_ctx, NULL, &ret, NULL, NULL, 10), return_val);
    assert_int_equal(amxb_invoke(invoke_ctx, &args, &ret, NULL, NULL, 10), return_val);
    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxb_invoke(invoke_ctx, &args, &ret, NULL, NULL, 10), return_val);
    assert_int_not_equal(amxb_invoke(NULL, NULL, NULL, NULL, NULL, 0), 0);
    return_val = -1;
    assert_int_equal(amxb_invoke(invoke_ctx, NULL, NULL, NULL, NULL, 10), return_val);
    return_val = 0;
    assert_int_equal(amxb_disconnect(ctx), 0);
    amxb_free_invoke(&invoke_ctx);
    amxb_free(&ctx);
    assert_ptr_equal(ctx, NULL);

    assert_int_equal(amxb_connect(&ctx, "zbus://test:80/var/run/zbus.sock"), 0);
    assert_int_equal(amxb_new_invoke(&invoke_ctx, ctx, "object", NULL, "method"), 0);

    return_val = 0;
    assert_int_equal(amxb_invoke(invoke_ctx, NULL, NULL, NULL, NULL, 0), AMXB_ERROR_NOT_SUPPORTED_OP);
    return_val = -1;
    assert_int_equal(amxb_invoke(invoke_ctx, NULL, NULL, NULL, NULL, 0), AMXB_ERROR_NOT_SUPPORTED_OP);
    return_val = 0;
    amxb_free(&ctx);
    amxb_free_invoke(&invoke_ctx);

    return_val = 0;
    assert_int_equal(amxb_connect(&ctx, "xbus://test:80/var/run/xbus.sock"), 0);
    assert_int_equal(amxb_new_invoke(&invoke_ctx, ctx, "object", NULL, "method()"), 0);
    assert_int_equal(amxb_invoke(invoke_ctx, NULL, NULL, NULL, NULL, 10), return_val);
    assert_int_equal(amxb_invoke(invoke_ctx, NULL, &ret, NULL, NULL, 10), return_val);
    assert_int_equal(amxb_invoke(invoke_ctx, &args, &ret, NULL, NULL, 10), return_val);
    amxb_free(&ctx);
    amxb_free_invoke(&invoke_ctx);

    assert_int_equal(amxb_be_unregister(&dummy_be1), 0);
    assert_int_equal(amxb_be_unregister(&dummy_be3), 0);
    amxc_var_clean(&ret);
    amxc_var_clean(&args);
}

void test_amxb_async_invoke_and_close(UNUSED void** state) {
    amxb_bus_ctx_t* ctx = NULL;
    amxc_var_t args;
    amxb_request_t* request = NULL;
    amxb_invoke_t* invoke_ctx = NULL;

    amxc_var_init(&args);
    assert_int_equal(amxb_be_register(&dummy_be1), 0);
    assert_int_equal(amxb_be_register(&dummy_be3), 0);
    assert_int_equal(amxb_be_register(&dummy_be4), 0);


    return_val = 0;
    assert_int_equal(amxb_connect(&ctx, "xbus://test:80/var/run/xbus.sock"), 0);
    assert_int_equal(amxb_new_invoke(&invoke_ctx, ctx, "object", NULL, "method"), 0);

    assert_int_equal(amxb_async_invoke(invoke_ctx, NULL, NULL, NULL, NULL, &request), return_val);
    assert_ptr_not_equal(request, NULL);
    assert_int_equal(amxb_close_request(&request), 0);
    assert_int_not_equal(amxb_close_request(&request), 0);

    assert_int_not_equal(amxb_async_invoke(invoke_ctx, NULL, NULL, NULL, NULL, NULL), return_val);
    assert_ptr_equal(request, NULL);

    assert_int_equal(amxb_async_invoke(invoke_ctx, &args, NULL, NULL, NULL, &request), return_val);
    assert_ptr_not_equal(request, NULL);
    assert_int_equal(amxb_close_request(&request), 0);
    assert_ptr_equal(request, NULL);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxb_async_invoke(invoke_ctx, &args, NULL, NULL, NULL, &request), return_val);
    assert_ptr_not_equal(request, NULL);
    assert_int_equal(amxb_close_request(&request), 0);
    assert_ptr_equal(request, NULL);

    assert_int_not_equal(amxb_async_invoke(NULL, NULL, NULL, NULL, NULL, &request), 0);
    assert_ptr_equal(request, NULL);

    return_val = -1;
    assert_int_equal(amxb_async_invoke(invoke_ctx, NULL, NULL, NULL, NULL, &request), return_val);
    assert_ptr_equal(request, NULL);

    return_val = 0;
    amxb_free_invoke(&invoke_ctx);
    assert_int_equal(amxb_disconnect(ctx), 0);
    amxb_free(&ctx);
    assert_ptr_equal(ctx, NULL);

    assert_int_equal(amxb_connect(&ctx, "abus://atest:8080/var/run/abus.sock"), 0);
    assert_int_equal(amxb_new_invoke(&invoke_ctx, ctx, "object", NULL, "method"), 0);

    return_val = 0;
    assert_int_equal(amxb_async_invoke(invoke_ctx, NULL, NULL, NULL, NULL, &request), 0);
    assert_ptr_not_equal(request, NULL);
    assert_int_equal(amxb_close_request(&request), AMXB_ERROR_NOT_SUPPORTED_OP);
    assert_ptr_equal(request, NULL);
    assert_int_not_equal(amxb_disconnect(ctx), 0);
    amxb_free_invoke(&invoke_ctx);
    amxb_free(&ctx);

    assert_int_equal(amxb_connect(&ctx, "zbus://test:80/var/run/zbus.sock"), 0);
    assert_int_equal(amxb_new_invoke(&invoke_ctx, ctx, "object", NULL, "method"), 0);

    return_val = 0;
    assert_int_equal(amxb_async_invoke(invoke_ctx, NULL, NULL, NULL, NULL, &request), AMXB_ERROR_NOT_SUPPORTED_OP);
    assert_ptr_equal(request, NULL);
    return_val = -1;
    assert_int_equal(amxb_async_invoke(invoke_ctx, NULL, NULL, NULL, NULL, &request), AMXB_ERROR_NOT_SUPPORTED_OP);
    assert_ptr_equal(request, NULL);
    return_val = 0;
    amxb_free(&ctx);

    assert_int_equal(amxb_be_unregister(&dummy_be1), 0);
    assert_int_equal(amxb_be_unregister(&dummy_be3), 0);
    assert_int_equal(amxb_be_unregister(&dummy_be4), 0);
    amxc_var_clean(&args);

    assert_int_not_equal(amxb_async_invoke(invoke_ctx, NULL, NULL, NULL, NULL, &request), 0);
    assert_ptr_equal(request, NULL);
    assert_int_not_equal(amxb_close_request(NULL), 0);
    amxb_free_invoke(&invoke_ctx);
}

void test_amxb_api_after_backend_removal(UNUSED void** state) {
    amxb_bus_ctx_t* ctx = NULL;
    amxb_request_t* request = NULL;
    amxb_invoke_t* invoke_ctx = NULL;

    assert_int_equal(amxb_be_register(&dummy_be1), 0);

    return_val = 0;
    assert_int_equal(amxb_connect(&ctx, "xbus://test:80/var/run/xbus.sock"), 0);
    assert_int_equal(amxb_new_invoke(&invoke_ctx, ctx, "object", NULL, "method"), 0);
    assert_int_equal(amxb_async_invoke(invoke_ctx, NULL, NULL, NULL, NULL, &request), return_val);

    assert_int_equal(amxb_be_unregister(&dummy_be1), 0);
    ctx = NULL;

    assert_int_not_equal(amxb_disconnect(ctx), 0);
    assert_int_not_equal(amxb_read(ctx), 0);
    assert_int_equal(amxb_get_fd(ctx), -1);
    assert_int_equal(amxb_close_request(&request), 0);
    assert_ptr_equal(request, NULL);
    assert_int_not_equal(amxb_async_invoke(invoke_ctx, NULL, NULL, NULL, NULL, &request), 0);
    assert_ptr_equal(request, NULL);
    assert_int_not_equal(amxb_invoke(invoke_ctx, NULL, NULL, NULL, NULL, 10), 0);

    amxb_free_invoke(&invoke_ctx);
    amxb_free(&ctx);
}

void test_amxb_wait_for_request(UNUSED void** state) {
    amxb_bus_ctx_t* ctx = NULL;
    amxb_request_t* request = NULL;
    amxb_invoke_t* invoke_ctx = NULL;

    assert_int_equal(amxb_be_register(&dummy_be1), 0);
    assert_int_equal(amxb_be_register(&dummy_be4), 0);

    assert_int_equal(amxb_connect(&ctx, "xbus://atest:8080/var/run/xbus.sock"), 0);
    return_val = 0;
    assert_int_equal(amxb_new_invoke(&invoke_ctx, ctx, "object", NULL, "method"), NULL);
    assert_int_equal(amxb_async_invoke(invoke_ctx, NULL, NULL, NULL, NULL, &request), 0);
    assert_ptr_not_equal(request, NULL);

    assert_int_equal(amxb_wait_for_request(request, 5), 0);
    assert_int_equal(amxb_close_request(&request), 0);
    assert_ptr_equal(request, NULL);

    assert_int_not_equal(amxb_wait_for_request(request, 5), 0);

    amxb_free_invoke(&invoke_ctx);
    assert_int_equal(amxb_disconnect(ctx), 0);
    amxb_free(&ctx);

    assert_int_equal(amxb_connect(&ctx, "abus://atest:8080/var/run/abus.sock"), 0);
    return_val = 0;
    assert_int_equal(amxb_new_invoke(&invoke_ctx, ctx, "object", NULL, "method"), 0);
    assert_int_equal(amxb_async_invoke(invoke_ctx, NULL, NULL, NULL, NULL, &request), 0);
    assert_ptr_not_equal(request, NULL);

    assert_int_equal(amxb_wait_for_request(request, 5), AMXB_ERROR_NOT_SUPPORTED_OP);
    assert_int_equal(amxb_close_request(&request), AMXB_ERROR_NOT_SUPPORTED_OP);

    amxb_free_invoke(&invoke_ctx);
    amxb_free(&ctx);

    assert_int_equal(amxb_be_unregister(&dummy_be1), 0);
    assert_int_equal(amxb_be_unregister(&dummy_be4), 0);
}

void test_amxb_async_call(UNUSED void** state) {
    amxb_bus_ctx_t* ctx = NULL;
    amxb_request_t* request = NULL;

    assert_int_equal(amxb_be_register(&dummy_be1), 0);
    assert_int_equal(amxb_be_register(&dummy_be4), 0);

    assert_int_equal(amxb_connect(&ctx, "xbus://atest:8080/var/run/xbus.sock"), 0);
    return_val = 0;
    request = amxb_async_call(ctx, "object", "method", NULL, NULL, NULL);
    assert_non_null(request);

    assert_int_equal(amxb_wait_for_request(request, 5), 0);
    assert_int_equal(amxb_close_request(&request), 0);
    assert_ptr_equal(request, NULL);

    assert_int_not_equal(amxb_wait_for_request(request, 5), 0);

    assert_int_equal(amxb_disconnect(ctx), 0);
    amxb_free(&ctx);

    assert_int_equal(amxb_connect(&ctx, "abus://atest:8080/var/run/abus.sock"), 0);
    return_val = 0;
    request = amxb_async_call(ctx, "object", "method", NULL, NULL, NULL);
    assert_non_null(request);

    assert_int_equal(amxb_wait_for_request(request, 5), AMXB_ERROR_NOT_SUPPORTED_OP);
    assert_int_equal(amxb_close_request(&request), AMXB_ERROR_NOT_SUPPORTED_OP);

    amxb_free(&ctx);

    assert_int_equal(amxb_be_unregister(&dummy_be1), 0);
    assert_int_equal(amxb_be_unregister(&dummy_be4), 0);
}