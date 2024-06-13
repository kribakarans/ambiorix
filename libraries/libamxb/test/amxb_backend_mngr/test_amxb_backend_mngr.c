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
#include <dlfcn.h>
#include <stdarg.h>
#include <stddef.h>
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

#include "test_amxb_backend_mngr.h"

#include <amxc/amxc_macros.h>

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

void* __real_dlopen(const char* filename, int flag);
int __real_dlclose(void* handle);

void* __wrap_dlopen(const char* filename, int flag);
int __wrap_dlclose(void* handle);
void* __wrap_dlsym(void* handle, const char* symbol);

static void* fake_handle = NULL;
static char* fake_ctx = "fake";
static int return_val = 0;

static uint32_t min_version_id = 0;
static uint32_t max_version_id = 0;
static bool has_info = true;
static bool register_be = true;

static amxb_version_t sup_min_version[] = {
    {                               // id = 0
        .major = 0,
        .minor = -1,
        .build = -1,
    },
    {                               // id = 1
        .major = 0,
        .minor = 1,
        .build = -1,
    },
    {                               // id = 2
        .major = 0,
        .minor = 1,
        .build = -1,
    },
    {                               // id = 3
        .major = 0,
        .minor = 0,
        .build = -1
    },
    {                               // id = 4
        .major = 999,
        .minor = 999,
        .build = 999
    },
    {                               // id = 5
        .major = 4,
        .minor = 999,
        .build = 999
    },
    {                               // id = 6
        .major = 4,
        .minor = 9,
        .build = 999
    },
    {
        .major = -1,
    }
};

static amxb_version_t sup_max_version[] = {
    {                               // id = 0
        .major = 4,
        .minor = 99,
        .build = 999,
    },
    {
        .major = 4,
        .minor = 9,
        .build = 999,
    },
    {
        .major = -1,
    }
};

static amxb_version_t be_version = {
    .major = 0,
    .minor = 0,
    .build = 7
};

static amxb_be_info_t be_info = {
    .be_version = &be_version,
    .name = "dummy",
    .description = "Dummy description",
};

static amxb_be_info_t* fake_get_version_info() {
    if(min_version_id == UINT32_MAX) {
        be_info.min_supported = NULL;
    } else {
        be_info.min_supported = &sup_min_version[min_version_id];
    }
    if(max_version_id == UINT32_MAX) {
        be_info.max_supported = NULL;
    } else {
        be_info.max_supported = &sup_max_version[max_version_id];
    }

    return &be_info;
}

static void* fake_connect(UNUSED const char* host,
                          UNUSED const char* port,
                          UNUSED const char* path,
                          UNUSED amxp_signal_mngr_t* sigmngr) {
    return fake_ctx;
}

static int fake_disconnect(void* ctx) {
    assert_ptr_equal(ctx, fake_ctx);
    return 0;
}

static amxb_be_funcs_t dummy_be1 = {
    .connect = fake_connect,
    .disconnect = fake_disconnect,
    .size = sizeof(amxb_be_funcs_t),
    .name = "xbus",
};

static amxb_be_funcs_t dummy_be2 = {
    .connect = NULL,
    .size = sizeof(amxb_be_funcs_t),
    .name = "xbus",
};

static amxb_be_funcs_t dummy_be3 = {
    .connect = NULL,
    .size = sizeof(amxb_be_funcs_t),
    .name = "ybus",
};

static amxb_be_funcs_t dummy_be4 = {
    .connect = NULL,
    .size = sizeof(amxb_be_funcs_t),
    .name = "",
};

static amxb_be_funcs_t dummy_be5 = {
    .connect = NULL,
    .size = sizeof(amxb_be_funcs_t),
    .name = NULL,
};

static amxb_be_funcs_t dummy_be6 = {
    .connect = NULL,
    .size = sizeof(amxb_be_funcs_t),
    .name = "test",
};

void* __wrap_dlopen(UNUSED const char* filename, UNUSED int flag) {
    if(fake_handle != NULL) {
        if(register_be) {
            if(dummy_be1.handle == NULL) {
                assert_int_equal(amxb_be_register(&dummy_be1), 0);
                assert_ptr_equal(dummy_be1.handle, NULL);
            } else if(dummy_be3.handle == NULL) {
                assert_int_equal(amxb_be_register(&dummy_be3), 0);
                assert_ptr_equal(dummy_be3.handle, NULL);
            } else {
                return NULL;
            }
        }
    }
    return fake_handle;
}

int __wrap_dlclose(UNUSED void* handle) {
    return return_val;
}

void* __wrap_dlsym(UNUSED void* handle, const char* symbol) {
    assert_string_equal(symbol, "amxb_be_info");
    if(has_info) {
        return fake_get_version_info;
    } else {
        return NULL;
    }
}

void test_amxb_be_register(UNUSED void** state) {
    assert_int_not_equal(amxb_be_register(NULL), 0);
    assert_int_equal(amxb_be_register(&dummy_be1), 0);
    assert_int_not_equal(amxb_be_register(&dummy_be1), 0);
    assert_int_not_equal(amxb_be_register(&dummy_be2), 0);
    assert_int_equal(amxb_be_register(&dummy_be3), 0);
    assert_int_not_equal(amxb_be_register(&dummy_be4), 0);
    assert_int_not_equal(amxb_be_register(&dummy_be5), 0);

    assert_int_equal(amxb_be_unregister(&dummy_be1), 0);
    assert_int_equal(amxb_be_unregister(&dummy_be3), 0);
    assert_ptr_equal(dummy_be3.handle, NULL);
    assert_ptr_equal(dummy_be1.handle, NULL);
}

void test_amxb_be_unregister(UNUSED void** state) {
    assert_int_equal(amxb_be_register(&dummy_be1), 0);
    assert_int_equal(amxb_be_register(&dummy_be3), 0);

    assert_int_not_equal(amxb_be_unregister(NULL), 0);
    assert_int_not_equal(amxb_be_unregister(&dummy_be2), 0);
    assert_int_not_equal(amxb_be_unregister(&dummy_be4), 0);
    assert_int_not_equal(amxb_be_unregister(&dummy_be5), 0);
    assert_int_not_equal(amxb_be_unregister(&dummy_be6), 0);

    assert_int_equal(amxb_be_unregister(&dummy_be1), 0);
    assert_int_equal(amxb_be_unregister(&dummy_be3), 0);
    assert_ptr_equal(dummy_be3.handle, NULL);
    assert_ptr_equal(dummy_be1.handle, NULL);
}

void test_amxb_be_find(UNUSED void** state) {
    const amxb_be_funcs_t* funcs = NULL;

    assert_int_equal(amxb_be_register(&dummy_be1), 0);
    assert_int_equal(amxb_be_register(&dummy_be3), 0);

    funcs = amxb_be_find(NULL);
    assert_ptr_equal(funcs, NULL);

    funcs = amxb_be_find("test");
    assert_ptr_equal(funcs, NULL);

    funcs = amxb_be_find("");
    assert_ptr_equal(funcs, NULL);

    funcs = amxb_be_find("xbus");
    assert_ptr_not_equal(funcs, NULL);
    assert_ptr_equal(funcs, &dummy_be1);

    funcs = amxb_be_find("ybus");
    assert_ptr_not_equal(funcs, NULL);
    assert_ptr_equal(funcs, &dummy_be3);

    assert_int_equal(amxb_be_unregister(&dummy_be1), 0);
    assert_int_equal(amxb_be_unregister(&dummy_be3), 0);
    assert_ptr_equal(dummy_be3.handle, NULL);
    assert_ptr_equal(dummy_be1.handle, NULL);
}

void test_amxb_be_load(UNUSED void** state) {
    const amxb_be_funcs_t* funcs = NULL;
    fake_handle = __real_dlopen(NULL, RTLD_NOW);

    min_version_id = 0;
    max_version_id = 1;
    assert_int_not_equal(amxb_be_load(NULL), 0);
    assert_int_not_equal(amxb_be_load(""), 0);
    assert_int_equal(amxb_be_load("/path/to/some/sofile.so"), 0);
    assert_ptr_equal(dummy_be1.handle, fake_handle);
    assert_int_equal(amxb_be_unregister(&dummy_be1), 0);
    assert_ptr_equal(dummy_be1.handle, NULL);

    funcs = amxb_be_find("xbus");
    assert_ptr_equal(funcs, NULL);

    register_be = false;
    assert_int_equal(amxb_be_load("/path/to/some/sofile.so"), 0);
    assert_int_equal(amxb_be_unregister(&dummy_be1), 0);
    assert_ptr_equal(dummy_be1.handle, NULL);
    register_be = true;

    fake_handle = NULL;
    assert_int_not_equal(amxb_be_load("/path/to/some/sofile.so"), 0);
}

void test_amxb_be_load_same_multiple_times(UNUSED void** state) {
    fake_handle = __real_dlopen(NULL, RTLD_NOW);

    register_be = false;
    min_version_id = 0;
    max_version_id = 1;
    assert_int_equal(amxb_be_load("/path/to/some/sofile.so"), 0);
    assert_ptr_equal(dummy_be1.handle, fake_handle);
    assert_int_equal(amxb_be_load("/path/to/some/sofile.so"), 0);
    assert_ptr_equal(dummy_be1.handle, fake_handle);
    assert_int_equal(amxb_be_load("/path/to/some/sofile.so"), 0);
    assert_ptr_equal(dummy_be1.handle, fake_handle);
    assert_int_equal(amxb_be_unregister(&dummy_be1), 0);
    assert_ptr_equal(dummy_be1.handle, NULL);
    register_be = true;
}

void test_amxb_be_load_multiple(UNUSED void** state) {
    amxc_var_t shared_objects;
    fake_handle = __real_dlopen(NULL, RTLD_NOW);

    amxc_var_init(&shared_objects);

    min_version_id = 0;
    max_version_id = 1;

    assert_int_not_equal(amxb_be_load_multiple(NULL), 0);
    assert_int_not_equal(amxb_be_load_multiple(&shared_objects), 0);

    amxc_var_set_type(&shared_objects, AMXC_VAR_ID_CSTRING);
    assert_int_not_equal(amxb_be_load_multiple(&shared_objects), 0);
    amxc_var_set_type(&shared_objects, AMXC_VAR_ID_LIST);
    assert_int_not_equal(amxb_be_load_multiple(&shared_objects), 0);

    amxc_var_set(cstring_t, &shared_objects, "/path/to/some/sofile.so");
    assert_int_equal(amxb_be_load_multiple(&shared_objects), 0);
    assert_ptr_equal(dummy_be1.handle, fake_handle);
    assert_int_equal(amxb_be_unregister(&dummy_be1), 0);

    amxc_var_set_type(&shared_objects, AMXC_VAR_ID_LIST);
    amxc_var_add(cstring_t, &shared_objects, "/path/to/some/sofile1.so");
    amxc_var_add(cstring_t, &shared_objects, "/path/to/some/sofile2.so");
    assert_int_equal(amxb_be_load_multiple(&shared_objects), 0);
    assert_ptr_equal(dummy_be1.handle, fake_handle);
    assert_ptr_equal(dummy_be3.handle, fake_handle);
    assert_int_equal(amxb_be_unregister(&dummy_be1), 0);
    assert_int_equal(amxb_be_unregister(&dummy_be3), 0);

    amxc_var_add(cstring_t, &shared_objects, "/path/to/some/sofile1.so");
    amxc_var_add(cstring_t, &shared_objects, "/path/to/some/sofile2.so");
    amxc_var_add(cstring_t, &shared_objects, "/path/to/some/sofile3.so");
    assert_int_not_equal(amxb_be_load_multiple(&shared_objects), 0);
    assert_ptr_equal(dummy_be1.handle, fake_handle);
    assert_ptr_equal(dummy_be3.handle, fake_handle);
    assert_int_equal(amxb_be_unregister(&dummy_be1), 0);
    assert_int_equal(amxb_be_unregister(&dummy_be3), 0);

    amxc_var_set_type(&shared_objects, AMXC_VAR_ID_CSTRING);
    amxc_var_set(cstring_t, &shared_objects, "/path/to/some/sofile1.so:/path/to/some/sofile2.so");
    assert_int_equal(amxb_be_load_multiple(&shared_objects), 0);
    assert_ptr_equal(dummy_be1.handle, fake_handle);
    assert_ptr_equal(dummy_be3.handle, fake_handle);
    assert_int_equal(amxb_be_unregister(&dummy_be1), 0);
    assert_int_equal(amxb_be_unregister(&dummy_be3), 0);

    amxc_var_set_type(&shared_objects, AMXC_VAR_ID_CSTRING);
    amxc_var_set(cstring_t, &shared_objects, "/path/to/some/sofile1.so:/path/to/some/sofile2.so:/path/to/some/sofile3.so");
    assert_int_not_equal(amxb_be_load_multiple(&shared_objects), 0);
    assert_ptr_equal(dummy_be1.handle, fake_handle);
    assert_ptr_equal(dummy_be3.handle, fake_handle);
    assert_int_equal(amxb_be_unregister(&dummy_be1), 0);
    assert_int_equal(amxb_be_unregister(&dummy_be3), 0);

    amxc_var_clean(&shared_objects);
}

void test_amxb_be_remove(UNUSED void** state) {
    amxb_bus_ctx_t* c1 = NULL;

    fake_handle = __real_dlopen(NULL, RTLD_NOW);

    min_version_id = 0;
    max_version_id = 1;

    assert_int_equal(amxb_be_register(&dummy_be1), 0);
    dummy_be1.handle = fake_handle;

    assert_int_not_equal(amxb_be_remove(NULL), 0);
    assert_int_not_equal(amxb_be_remove(""), 0);

    assert_int_equal(amxb_connect(&c1, "xbus:///var/run/test.sock"), 0);

    assert_int_equal(amxb_be_remove("xbus"), 0);
    assert_int_not_equal(amxb_be_unregister(&dummy_be1), 0);
    assert_int_not_equal(amxb_be_remove("xbus"), 0);

    assert_int_equal(amxb_be_register(&dummy_be1), 0);
    dummy_be1.handle = NULL;
    assert_int_not_equal(amxb_be_remove("xbus"), 0);
    assert_int_equal(amxb_be_unregister(&dummy_be1), 0);

    assert_int_equal(amxb_be_register(&dummy_be1), 0);
    dummy_be1.handle = fake_handle;
    return_val = -1;
    assert_int_not_equal(amxb_be_remove("xbus"), 0);
    return_val = 0;
    assert_int_not_equal(amxb_be_unregister(&dummy_be1), 0);
}

void test_amxb_be_remove_all(UNUSED void** state) {
    fake_handle = __real_dlopen(NULL, RTLD_NOW);
    amxb_bus_ctx_t* c1 = NULL;
    amxb_bus_ctx_t* c2 = NULL;

    assert_int_equal(amxb_be_register(&dummy_be1), 0);
    assert_int_equal(amxb_be_register(&dummy_be3), 0);
    dummy_be1.handle = fake_handle;
    dummy_be2.handle = fake_handle;

    assert_int_equal(amxb_connect(&c1, "xbus:///var/run/test.sock"), 0);
    assert_int_equal(amxb_connect(&c2, "xbus:///var/run/test.sock"), 0);

    amxb_free(&c1);

    amxb_be_remove_all();
    assert_int_not_equal(amxb_be_unregister(&dummy_be1), 0);
    dummy_be1.handle = NULL;
    assert_int_not_equal(amxb_be_unregister(&dummy_be3), 0);
    dummy_be3.handle = NULL;

    assert_int_equal(amxb_be_register(&dummy_be1), 0);
    dummy_be1.handle = fake_handle;
    return_val = -1;
    amxb_be_remove_all();
    return_val = 0;
    assert_int_not_equal(amxb_be_unregister(&dummy_be1), 0);
    dummy_be1.handle = NULL;
}

void test_amxb_be_load_version_checking(UNUSED void** state) {
    fake_handle = __real_dlopen(NULL, RTLD_NOW);

    min_version_id = 0;
    max_version_id = 0;
    for(uint32_t i = 0; i < ARRAY_SIZE(sup_min_version); i++) {
        min_version_id = i;
        if(i < 4) {
            assert_int_equal(amxb_be_load("/path/to/some/sofile.so"), 0);
            assert_ptr_equal(dummy_be1.handle, fake_handle);
            assert_int_equal(amxb_be_unregister(&dummy_be1), 0);
        } else {
            assert_int_not_equal(amxb_be_load("/path/to/some/sofile.so"), 0);
            assert_int_equal(amxb_be_unregister(&dummy_be1), 0);
        }
    }

    min_version_id = 0;
    max_version_id = 1;
    for(uint32_t i = 0; i < ARRAY_SIZE(sup_min_version); i++) {
        min_version_id = i;
        if(i < 4) {
            assert_int_equal(amxb_be_load("/path/to/some/sofile.so"), 0);
            assert_ptr_equal(dummy_be1.handle, fake_handle);
            assert_int_equal(amxb_be_unregister(&dummy_be1), 0);
        } else {
            assert_int_not_equal(amxb_be_load("/path/to/some/sofile.so"), 0);
            assert_int_equal(amxb_be_unregister(&dummy_be1), 0);
        }
    }

    min_version_id = UINT32_MAX;
    assert_int_not_equal(amxb_be_load("/path/to/some/sofile.so"), 0);
    assert_int_equal(amxb_be_unregister(&dummy_be1), 0);
    min_version_id = 0;
    max_version_id = UINT32_MAX;
    assert_int_not_equal(amxb_be_load("/path/to/some/sofile.so"), 0);
    assert_int_equal(amxb_be_unregister(&dummy_be1), 0);
    max_version_id = 0;
    has_info = false;
    assert_int_not_equal(amxb_be_load("/path/to/some/sofile.so"), 0);
    assert_int_equal(amxb_be_unregister(&dummy_be1), 0);
    has_info = true;
}

void test_amxb_be_get_version(UNUSED void** state) {
    amxb_version_t* libv = (amxb_version_t*) amxb_get_version();
    amxb_version_t* libv2 = NULL;
    assert_ptr_not_equal(libv, NULL);
    assert_int_not_equal(libv->major, 99999);
    libv->major = 99999;
    assert_int_equal(libv->major, 99999);
    libv2 = (amxb_version_t*) amxb_get_version();
    assert_ptr_equal(libv, libv2);
    assert_int_not_equal(libv->major, 99999);
    assert_int_not_equal(libv2->major, 99999);
}

void test_amxb_set_config(UNUSED void** state) {
    amxc_var_t config;

    amxc_var_init(&config);
    amxc_var_set_type(&config, AMXC_VAR_ID_HTABLE);

    amxc_var_add_key(amxc_htable_t, &config, "dummy", NULL);
    assert_int_equal(amxb_set_config(&config), 0);

    amxc_var_clean(&config);
}

void test_amxb_be_get_info(UNUSED void** state) {
    fake_handle = __real_dlopen(NULL, RTLD_NOW);
    const amxb_be_info_t* info = NULL;

    assert_int_equal(amxb_be_register(&dummy_be1), 0);

    info = amxb_be_get_info("xbus");
    assert_non_null(info);
    info = amxb_be_get_info("test");
    assert_null(info);
    info = amxb_be_get_info("");
    assert_null(info);
    info = amxb_be_get_info(NULL);
    assert_null(info);

    amxb_be_remove_all();

    info = amxb_be_get_info("xbus");
    assert_null(info);

    return_val = 0;
    assert_int_not_equal(amxb_be_unregister(&dummy_be1), 0);
}