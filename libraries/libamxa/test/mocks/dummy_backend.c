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
#define _GNU_SOURCE

#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include "dummy_backend.h"

#define UNUSED __attribute__((unused))

typedef struct _dummy_ctx {
    int fd[2];
} dummy_ctx_t;

static void* amxb_dummy_connect(UNUSED const char* host,
                                UNUSED const char* port,
                                UNUSED const char* path,
                                UNUSED amxp_signal_mngr_t* sigmngr) {
    dummy_ctx_t* d = calloc(1, sizeof(dummy_ctx_t));
    pipe(d->fd);
    return d;
}

static int amxb_dummy_disconnect(UNUSED void* ctx) {
    dummy_ctx_t* d = (dummy_ctx_t*) ctx;
    close(d->fd[0]);
    close(d->fd[1]);
    return 0;
}

static int amxb_dummy_get_fd(UNUSED void* const ctx) {
    dummy_ctx_t* d = (dummy_ctx_t*) ctx;
    return d->fd[0];
}

static int amxb_dummy_read(void* const ctx) {
    dummy_ctx_t* d = (dummy_ctx_t*) ctx;
    char buffer[1024];
    read(d->fd[0], buffer, 1024);

    return 0;
}

static void amxb_dummy_free(void* ctx) {
    free(ctx);
}

static int amxb_dummy_register(UNUSED void* const ctx,
                               UNUSED amxd_dm_t* const dm) {
    return 0;
}

static void* amxb_dummy_listen(UNUSED const char* host,
                               UNUSED const char* port,
                               const char* path,
                               UNUSED amxp_signal_mngr_t* sigmngr) {
    const char* valid_uri = "/var/run/dummy_listen.sock";
    dummy_ctx_t* d = NULL;

    if(strncmp(valid_uri, path, 100) == 0) {
        d = calloc(1, sizeof(dummy_ctx_t));
        pipe(d->fd);
    }
    return d;
}

static amxb_be_funcs_t amxb_dummy_impl = {
    .connect = amxb_dummy_connect,
    .disconnect = amxb_dummy_disconnect,
    .get_fd = amxb_dummy_get_fd,
    .read = amxb_dummy_read,
    .listen = amxb_dummy_listen,
    .invoke = NULL,
    .async_invoke = NULL,
    .wait_request = NULL,
    .close_request = NULL,
    .subscribe = NULL,
    .unsubscribe = NULL,
    .free = amxb_dummy_free,
    .register_dm = amxb_dummy_register,
    .name = "dummy",
    .size = sizeof(amxb_be_funcs_t),
};

static amxb_version_t sup_min_lib_version = {
    .major = 2,
    .minor = 0,
    .build = 0
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
    return amxb_be_register(&amxb_dummy_impl);
}

int test_unregister_dummy_be(void) {
    return amxb_be_unregister(&amxb_dummy_impl);
}

int test_write_data(amxb_bus_ctx_t* bus_ctx, const char* data, size_t len) {
    dummy_ctx_t* ctx = (dummy_ctx_t*) bus_ctx->bus_ctx;

    return write(ctx->fd[1], data, len);
}