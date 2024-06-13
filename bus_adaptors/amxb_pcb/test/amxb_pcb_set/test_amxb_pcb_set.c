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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <signal.h>

#include <amxc/amxc.h>
#include <amxp/amxp.h>

#include <amxd/amxd_dm.h>

#include <amxb/amxb.h>

#include "test_amxb_pcb_set.h"

static amxb_bus_ctx_t* bus_ctx = NULL;

static void test_generic_setup() {
    amxc_string_t txt;
    amxc_string_init(&txt, 0);

    amxc_string_setf(&txt, "pcb_sysbus -n test_bus -I /tmp/test.sock");
    system(amxc_string_get(&txt, 0));
    sleep(1);
    amxc_string_clean(&txt);
}

static void test_generic_teardown() {
    amxc_string_t txt;
    amxc_string_init(&txt, 0);

    amxc_string_setf(&txt, "killall test_bus");
    system(amxc_string_get(&txt, 0));

    amxc_string_clean(&txt);
}

int test_amxb_pcb_set_pcb_setup(UNUSED void** state) {
    amxc_string_t txt;

    test_generic_setup();

    amxc_string_init(&txt, 0);
    amxc_string_setf(&txt, "pcb_app -u pcb://ipc:[/tmp/test.sock] -n nemo_test -c ../test_data/test_nemo_pcb.odl");
    system(amxc_string_get(&txt, 0));

    amxc_string_clean(&txt);

    assert_int_equal(amxb_be_load("../mod-amxb-test-pcb.so"), 0);
    assert_int_equal(amxb_connect(&bus_ctx, "pcb:/tmp/test.sock"), 0);

    sleep(1);

    return 0;
}

int test_amxb_pcb_set_pcb_teardown(UNUSED void** state) {
    amxb_disconnect(bus_ctx);
    amxb_free(&bus_ctx);

    system("killall nemo_test");

    amxb_be_remove_all();

    test_generic_teardown();
    return 0;
}

int test_amxb_pcb_set_amx_setup(UNUSED void** state) {
    amxc_string_t txt;

    test_generic_setup();

    amxc_string_init(&txt, 0);

    unlink("test_config.odl");
    int fd = open("test_config.odl", O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IRGRP | S_IROTH);
    assert_int_not_equal(fd, -1);
    if(use_async_handlers()) {
        amxc_string_setf(&txt, "%%config { %%global backends = ['../mod-amxb-test-pcb.so']; %%global uris = [ 'pcb:/tmp/test.sock' ];  %%global pcb.use-async-handlers = true; }\n");
    } else {
        amxc_string_setf(&txt, "%%config { %%global backends = ['../mod-amxb-test-pcb.so']; %%global uris = [ 'pcb:/tmp/test.sock' ];  %%global pcb.use-async-handlers = false; }\n");
    }
    write(fd, amxc_string_get(&txt, 0), amxc_string_text_length(&txt));
    close(fd);

    amxc_string_reset(&txt);
    amxc_string_setf(&txt, "amxrt -A -D test_config.odl ../test_data//test_nemo.odl");
    system(amxc_string_get(&txt, 0));

    amxc_string_clean(&txt);

    assert_int_equal(amxb_be_load("../mod-amxb-test-pcb.so"), 0);
    assert_int_equal(amxb_connect(&bus_ctx, "pcb:/tmp/test.sock"), 0);

    sleep(1);

    return 0;
}

int test_amxb_pcb_set_amx_teardown(UNUSED void** state) {
    amxb_disconnect(bus_ctx);
    amxb_free(&bus_ctx);

    system("killall amxrt");

    amxb_be_remove_all();
    unlink("test_config.odl");
    test_generic_teardown();

    return 0;
}

void test_pcb_set_index_path(UNUSED void** state) {
    amxc_var_t values;
    amxc_var_t ret;
    amxc_var_t* results = NULL;
    const char* path = "NeMo.Intf.1.Query.100.";
    amxc_var_init(&values);
    amxc_var_init(&ret);

    amxc_var_set_type(&values, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &values, "Description", "change1");
    assert_int_equal(amxb_set(bus_ctx, path, &values, &ret, 5), 0);
    amxc_var_dump(&ret, STDOUT_FILENO);
    assert_int_equal(amxc_var_type_of(&ret), AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_llist_size(&ret.data.vl), 1);
    results = GETI_ARG(&ret, 0);
    assert_non_null(results);
    assert_int_equal(amxc_var_type_of(results), AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_htable_size(&results->data.vm), 1);
    results = GET_ARG(results, path);
    assert_non_null(results);
    assert_int_equal(amxc_var_type_of(results), AMXC_VAR_ID_HTABLE);
    assert_non_null(GET_ARG(results, "Description"));

    amxc_var_clean(&values);
    amxc_var_clean(&ret);
}

void test_pcb_set_key_path(UNUSED void** state) {
    amxc_var_t values;
    amxc_var_t ret;
    amxc_var_t* results = NULL;
    const char* path = "NeMo.Intf.lan.Query.100.";
    const char* ipath = "NeMo.Intf.1.Query.100.";
    amxc_var_init(&values);
    amxc_var_init(&ret);

    amxc_var_set_type(&values, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &values, "Description", "change2");
    assert_int_equal(amxb_set(bus_ctx, path, &values, &ret, 5), 0);
    amxc_var_dump(&ret, STDOUT_FILENO);
    assert_int_equal(amxc_var_type_of(&ret), AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_llist_size(&ret.data.vl), 1);
    results = GETI_ARG(&ret, 0);
    assert_non_null(results);
    assert_int_equal(amxc_var_type_of(results), AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_htable_size(&results->data.vm), 1);
    results = GET_ARG(results, ipath);
    assert_non_null(results);
    assert_int_equal(amxc_var_type_of(results), AMXC_VAR_ID_HTABLE);
    assert_non_null(GET_ARG(results, "Description"));

    amxc_var_clean(&values);
    amxc_var_clean(&ret);
}

void test_pcb_set_search_path(UNUSED void** state) {
    amxc_var_t values;
    amxc_var_t ret;
    amxc_var_t* results = NULL;
    const char* path = "NeMo.Intf.*.Query.[ResultString == 'nok'].";
    amxc_var_init(&values);
    amxc_var_init(&ret);

    amxc_var_set_type(&values, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &values, "Description", "change3");
    assert_int_equal(amxb_set(bus_ctx, path, &values, &ret, 5), 0);
    amxc_var_dump(&ret, STDOUT_FILENO);
    assert_int_equal(amxc_var_type_of(&ret), AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_llist_size(&ret.data.vl), 1);
    results = GETI_ARG(&ret, 0);
    assert_non_null(results);
    assert_int_equal(amxc_var_type_of(results), AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_htable_size(&results->data.vm), 3);

    amxc_var_clean(&values);
    amxc_var_clean(&ret);
}

void test_pcb_set_non_existing(UNUSED void** state) {
    amxc_var_t values;
    amxc_var_t ret;
    const char* path = "NeMo.Intf.dummy.Query.101.";
    amxc_var_init(&values);
    amxc_var_init(&ret);

    amxc_var_set_type(&values, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &values, "Description", "change3");
    assert_int_not_equal(amxb_set(bus_ctx, path, &values, &ret, 5), 0);

    amxc_var_clean(&values);
    amxc_var_clean(&ret);
}

void test_pcb_set_invalid_value(UNUSED void** state) {
    amxc_var_t values;
    amxc_var_t ret;
    const char* path = "NeMo.Intf.2.";
    amxc_var_init(&values);
    amxc_var_init(&ret);

    amxc_var_set_type(&values, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &values, "Flags", "red");
    assert_int_not_equal(amxb_set(bus_ctx, path, &values, &ret, 5), 0);

    amxc_var_clean(&values);
    amxc_var_clean(&ret);
}

void test_pcb_set_multiple(UNUSED void** state) {
    amxc_var_t req_paths;
    amxc_var_t ret;
    amxc_var_t* req_path = NULL;
    amxc_var_t* params = NULL;

    amxc_var_init(&req_paths);
    amxc_var_init(&ret);

    amxc_var_set_type(&req_paths, AMXC_VAR_ID_LIST);
    req_path = amxc_var_add(amxc_htable_t, &req_paths, NULL);
    amxc_var_add_key(cstring_t, req_path, "path", "NeMo.Intf.1.Query.*.");
    params = amxc_var_add_key(amxc_htable_t, req_path, "parameters", NULL);
    amxc_var_add_key(cstring_t, params, "Description", "Test Description");

    req_path = amxc_var_add(amxc_htable_t, &req_paths, NULL);
    amxc_var_add_key(cstring_t, req_path, "path", "NeMo.Intf.2.Query.[ResultString == 'nok'].");
    params = amxc_var_add_key(amxc_htable_t, req_path, "parameters", NULL);
    amxc_var_add_key(cstring_t, params, "ResultString", "ok");

    req_path = amxc_var_add(amxc_htable_t, &req_paths, NULL);
    amxc_var_add_key(cstring_t, req_path, "path", "NeMo.Intf.3.ULIntf.1.");
    params = amxc_var_add_key(amxc_htable_t, req_path, "parameters", NULL);
    amxc_var_add_key(cstring_t, params, "Name", "test");

    amxc_var_dump(&req_paths, STDOUT_FILENO);

    assert_int_not_equal(amxb_set_multiple(bus_ctx, 0, &req_paths, &ret, 5), 0);
    amxc_var_dump(&ret, STDOUT_FILENO);

    amxc_var_clean(&req_paths);
    amxc_var_clean(&ret);
}

void test_pcb_set_multiple_allow_partial(UNUSED void** state) {
    amxc_var_t req_paths;
    amxc_var_t ret;
    amxc_var_t* req_path = NULL;
    amxc_var_t* params = NULL;

    amxc_var_init(&req_paths);
    amxc_var_init(&ret);

    amxc_var_set_type(&req_paths, AMXC_VAR_ID_LIST);
    req_path = amxc_var_add(amxc_htable_t, &req_paths, NULL);
    amxc_var_add_key(cstring_t, req_path, "path", "NeMo.Intf.1.Query.*.");
    params = amxc_var_add_key(amxc_htable_t, req_path, "parameters", NULL);
    amxc_var_add_key(cstring_t, params, "Description", "Test Description");

    req_path = amxc_var_add(amxc_htable_t, &req_paths, NULL);
    amxc_var_add_key(cstring_t, req_path, "path", "NeMo.Intf.2.Query.[ResultString == 'nok'].");
    params = amxc_var_add_key(amxc_htable_t, req_path, "parameters", NULL);
    amxc_var_add_key(cstring_t, params, "ResultString", "ok");

    req_path = amxc_var_add(amxc_htable_t, &req_paths, NULL);
    amxc_var_add_key(cstring_t, req_path, "path", "NeMo.Intf.3.ULIntf.1.");
    params = amxc_var_add_key(amxc_htable_t, req_path, "parameters", NULL);
    amxc_var_add_key(cstring_t, params, "Name", "test");

    amxc_var_dump(&req_paths, STDOUT_FILENO);

    assert_int_equal(amxb_set_multiple(bus_ctx, AMXB_FLAG_PARTIAL, &req_paths, &ret, 5), 0);
    amxc_var_dump(&ret, STDOUT_FILENO);

    amxc_var_clean(&req_paths);
    amxc_var_clean(&ret);
}

void test_pcb_set_multiple_only_optionals(UNUSED void** state) {
    amxc_var_t req_paths;
    amxc_var_t ret;
    amxc_var_t* req_path = NULL;
    amxc_var_t* params = NULL;

    amxc_var_init(&req_paths);
    amxc_var_init(&ret);

    amxc_var_set_type(&req_paths, AMXC_VAR_ID_LIST);
    req_path = amxc_var_add(amxc_htable_t, &req_paths, NULL);
    amxc_var_add_key(cstring_t, req_path, "path", "NeMo.Intf.1.Query.*.");
    params = amxc_var_add_key(amxc_htable_t, req_path, "oparameters", NULL);
    amxc_var_add_key(cstring_t, params, "Description", "Test Description");

    req_path = amxc_var_add(amxc_htable_t, &req_paths, NULL);
    amxc_var_add_key(cstring_t, req_path, "path", "NeMo.Intf.2.Query.[ResultString == 'ok'].");
    params = amxc_var_add_key(amxc_htable_t, req_path, "oparameters", NULL);
    amxc_var_add_key(cstring_t, params, "ResultString", "nok");

    req_path = amxc_var_add(amxc_htable_t, &req_paths, NULL);
    amxc_var_add_key(cstring_t, req_path, "path", "NeMo.Intf.3.ULIntf.1.");
    params = amxc_var_add_key(amxc_htable_t, req_path, "oparameters", NULL);
    amxc_var_add_key(cstring_t, params, "Name", "test");

    amxc_var_dump(&req_paths, STDOUT_FILENO);

    assert_int_equal(amxb_set_multiple(bus_ctx, 0, &req_paths, &ret, 5), 0);
    amxc_var_dump(&ret, STDOUT_FILENO);

    amxc_var_clean(&req_paths);
    amxc_var_clean(&ret);
}

void test_pcb_client_set(UNUSED void** state) {
    amxc_string_t txt;
    amxc_string_init(&txt, 0);

    amxc_string_setf(&txt, "pcb_cli -i pcb://ipc:[/tmp/test.sock] NeMo.Intf.1.Query.100.Description=\"pcb_cli\"");
    system(amxc_string_get(&txt, 0));

    amxc_string_setf(&txt, "pcb_cli pcb://ipc:[/tmp/test.sock] NeMo.Intf.lan.Query.100.Description=\"pcb_cli\"");
    system(amxc_string_get(&txt, 0));

    amxc_string_setf(&txt, "pcb_cli pcb://ipc:[/tmp/test.sock] NeMo.Intf.XDSL.Not.In.Supported.2..Description=\"pcb_cli\"");
    system(amxc_string_get(&txt, 0));

    amxc_string_clean(&txt);

}