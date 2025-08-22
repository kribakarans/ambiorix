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
#include <dlfcn.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <sys/types.h>
#include <signal.h>

#include <amxc/amxc.h>
#include <amxp/amxp.h>

#include <amxd/amxd_dm.h>
#include <amxo/amxo.h>

#include <amxb/amxb.h>
#include <amxb/amxb_register.h>

#include "dummy_be.h"
#include "test_amxb_local.h"

#include <amxc/amxc_macros.h>
static amxb_bus_ctx_t* bus_ctx = NULL;
static amxd_dm_t dm;
static amxo_parser_t parser;

static void event_handler(const char* const sig_name,
                          const amxc_var_t* const data,
                          void* const priv) {
    int* event_count = (int*) priv;
    printf("Event received = %s\n", sig_name);
    fflush(stdout);
    amxc_var_dump(data, STDOUT_FILENO);
    (*event_count)++;
}


static void handle_events(void) {
    printf("Handling events ");
    while(amxp_signal_read() == 0) {
        printf(".");
    }
    printf("\n");
}

static void test_request_done_keep(UNUSED const amxb_bus_ctx_t* bus_ctx,
                                   amxb_request_t* req,
                                   int status,
                                   UNUSED void* priv) {
    if(status == 0) {
        amxc_var_dump(req->result, STDOUT_FILENO);
    }
}

static void test_request_done(UNUSED const amxb_bus_ctx_t* bus_ctx,
                              amxb_request_t* req,
                              int status,
                              UNUSED void* priv) {
    if(status == 0) {
        amxc_var_dump(req->result, STDOUT_FILENO);
    }

    amxb_close_request(&req);
}

int test_amxb_local_setup(UNUSED void** state) {
    amxd_object_t* root_obj = NULL;

    test_register_dummy_be();

    assert_int_equal(amxb_connect(&bus_ctx, "dummy:/tmp/dummy.sock"), 0);

    assert_int_equal(amxd_dm_init(&dm), amxd_status_ok);
    assert_int_equal(amxo_parser_init(&parser), 0);

    root_obj = amxd_dm_get_root(&dm);
    assert_non_null(root_obj);

    assert_int_equal(amxo_parser_parse_file(&parser, "./test.odl", root_obj), 0);

    handle_events();

    assert_int_equal(amxb_register(bus_ctx, &dm), 0);

    return 0;
}

int test_amxb_local_teardown(UNUSED void** state) {
    amxb_disconnect(bus_ctx);
    amxb_free(&bus_ctx);

    amxb_be_remove_all();

    amxo_parser_clean(&parser);
    amxd_dm_clean(&dm);

    test_unregister_dummy_be();

    return 0;
}

void test_amxb_call(UNUSED void** state) {
    amxc_var_t values;
    amxc_var_t* results = NULL;
    amxc_var_init(&values);

    assert_int_equal(amxb_call(bus_ctx, "Device.Ethernet.Interface.1", "_get", NULL, NULL, 1), 0);

    assert_int_equal(amxb_call(bus_ctx, "Device.Ethernet.Interface.1", "_get", NULL, &values, 1), 0);
    amxc_var_dump(&values, STDOUT_FILENO);
    results = amxc_var_get_index(&values, 0, AMXC_VAR_FLAG_DEFAULT);
    assert_int_equal(amxc_var_type_of(results), AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_htable_size(&results->data.vm), 1);

    assert_int_not_equal(amxb_call(bus_ctx, "Device.Link.Interface.1", "_get", NULL, NULL, 1), 0);

    amxc_var_clean(&values);
}

void test_amxb_async_call(UNUSED void** state) {
    amxb_request_t* request = NULL;

    request = amxb_async_call(bus_ctx, "Device.Ethernet.Interface.1", "_get", NULL, test_request_done_keep, NULL);
    assert_non_null(request);
    assert_int_equal(amxb_wait_for_request(request, 10), 0);
    amxc_var_dump(request->result, STDOUT_FILENO);
    amxb_close_request(&request);
    assert_null(request);

    request = amxb_async_call(bus_ctx, "Device.Ethernet.Interface.1", "_get", NULL, test_request_done_keep, NULL);
    assert_non_null(request);
    amxb_close_request(&request);
    handle_events();

    request = amxb_async_call(bus_ctx, "Device.Ethernet.Interface.1", "_get", NULL, test_request_done, NULL);
    assert_non_null(request);
    handle_events();

    request = amxb_async_call(bus_ctx, "Device.Ethernet.Interface.1", "_get", NULL, test_request_done, NULL);
    assert_non_null(request);
    assert_int_equal(amxb_wait_for_request(request, 10), 0);
}

void test_amxb_get(UNUSED void** state) {
    amxc_var_t values;
    amxc_var_t* results = NULL;
    amxc_var_init(&values);

    assert_int_equal(amxb_get(bus_ctx, "Device.Ethernet.Interface.1.Status", 0, &values, 1), 0);
    assert_int_equal(amxc_var_type_of(&values), AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_llist_size(&values.data.vl), 1);
    amxc_var_dump(&values, STDOUT_FILENO);
    results = amxc_var_get_index(&values, 0, AMXC_VAR_FLAG_DEFAULT);
    assert_int_equal(amxc_var_type_of(results), AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_htable_size(&results->data.vm), 1);

    assert_int_equal(amxb_get(bus_ctx, "Device.Ethernet.Interface.*.Status", 0, &values, 1), 0);
    assert_int_equal(amxc_var_type_of(&values), AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_llist_size(&values.data.vl), 1);
    amxc_var_dump(&values, STDOUT_FILENO);
    results = amxc_var_get_index(&values, 0, AMXC_VAR_FLAG_DEFAULT);
    assert_int_equal(amxc_var_type_of(results), AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_htable_size(&results->data.vm), 4);

    assert_int_equal(amxb_get(bus_ctx, "Device.Ethernet.Interface.[Enable == true].Status", 0, &values, 1), 0);
    assert_int_equal(amxc_var_type_of(&values), AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_llist_size(&values.data.vl), 1);
    amxc_var_dump(&values, STDOUT_FILENO);
    results = amxc_var_get_index(&values, 0, AMXC_VAR_FLAG_DEFAULT);
    assert_int_equal(amxc_var_type_of(results), AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_htable_size(&results->data.vm), 2);

    assert_int_not_equal(amxb_get(bus_ctx, "Device.Ethernet.Link.[Enable == true].Status", 0, &values, 1), 0);

    assert_int_equal(amxb_get(bus_ctx, "Device.Alias", 0, &values, 1), 0);
    amxc_var_dump(&values, STDOUT_FILENO);
    assert_int_equal(amxb_get(bus_ctx, "Device.Port", 0, &values, 1), 0);
    amxc_var_dump(&values, STDOUT_FILENO);

    amxc_var_clean(&values);
}

void test_amxb_get_multiple(UNUSED void** state) {
    amxc_var_t values;
    amxc_var_init(&values);

    amxc_var_t paths;
    amxc_var_init(&paths);
    amxc_var_set_type(&paths, AMXC_VAR_ID_LIST);
    amxc_var_add(cstring_t, &paths, "Device.Ethernet.Interface.1.Status");
    amxc_var_add(cstring_t, &paths, "Device.Ethernet.Interface.20.");
    amxc_var_add(cstring_t, &paths, "Device.time.");

    assert_int_equal(amxb_get_multiple(bus_ctx, &paths, 0, &values, 5), 0);
    assert_int_equal(amxc_var_type_of(&values), AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_var_type_of(GETP_ARG(&values, "'Device.Ethernet.Interface.1.Status'.result")), AMXC_VAR_ID_LIST);
    assert_int_equal(GETP_UINT32(&values, "'Device.Ethernet.Interface.1.Status'.status"), 0);
    assert_string_equal(GETP_CHAR(&values, "'Device.Ethernet.Interface.1.Status'.result.0.'Device.Ethernet.Interface.1.'.Status"), "Up");

    amxc_var_dump(&values, STDOUT_FILENO);
    assert_int_equal(amxc_var_type_of(GETP_ARG(&values, "'Device.Ethernet.Interface.20.'.result")), AMXC_VAR_ID_LIST);
    assert_int_equal(GETP_UINT32(&values, "'Device.Ethernet.Interface.20.'.status"), 2);

    assert_int_equal(amxc_var_type_of(GETP_ARG(&values, "'Device.time.'.result")), AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_var_type_of(GETP_ARG(&values, "'Device.time.")), AMXC_VAR_ID_HTABLE);
    assert_int_equal(GETP_UINT32(&values, "'Device.time.'.status"), 2);

    amxc_var_dump(&values, STDOUT_FILENO);
    amxc_var_clean(&values);
    amxc_var_clean(&paths);
}

void test_amxb_get_instances(UNUSED void** state) {
    amxc_var_t values;
    amxc_var_t* results = NULL;
    amxc_var_init(&values);

    assert_int_equal(amxb_get_instances(bus_ctx, "Device.Ethernet.Interface.", 0, &values, 1), 0);
    assert_int_equal(amxc_var_type_of(&values), AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_llist_size(&values.data.vl), 1);
    amxc_var_dump(&values, STDOUT_FILENO);
    results = amxc_var_get_index(&values, 0, AMXC_VAR_FLAG_DEFAULT);
    assert_int_equal(amxc_var_type_of(results), AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_htable_size(&results->data.vm), 4);

    amxc_var_clean(&values);
}

void test_amxb_get_reference(UNUSED void** state) {
    amxc_var_t values;
    amxc_var_t* results = NULL;
    amxc_var_init(&values);

    assert_int_equal(amxb_get(bus_ctx, "Device.Reference+.", 0, &values, 1), 0);
    assert_int_equal(amxc_var_type_of(&values), AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_llist_size(&values.data.vl), 1);
    amxc_var_dump(&values, STDOUT_FILENO);
    results = amxc_var_get_index(&values, 0, AMXC_VAR_FLAG_DEFAULT);
    assert_int_equal(amxc_var_type_of(results), AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_htable_size(&results->data.vm), 1);

    assert_int_equal(amxb_get(bus_ctx, "Device.Refs#2+.", 0, &values, 1), 0);
    assert_int_equal(amxc_var_type_of(&values), AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_llist_size(&values.data.vl), 1);
    amxc_var_dump(&values, STDOUT_FILENO);
    results = amxc_var_get_index(&values, 0, AMXC_VAR_FLAG_DEFAULT);
    assert_int_equal(amxc_var_type_of(results), AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_htable_size(&results->data.vm), 1);

    assert_int_not_equal(amxb_get(bus_ctx, "Device.Refs#85+.", 0, &values, 1), 0);
    assert_int_not_equal(amxb_get(bus_ctx, "Device.Refs#0+.", 0, &values, 1), 0);

    amxc_var_clean(&values);
}

void test_amxb_get_key_path_reference(UNUSED void** state) {
    amxc_var_t values;
    amxc_var_t* results = NULL;
    amxc_var_init(&values);

    assert_int_equal(amxb_get(bus_ctx, "Device.TestObject.[Enabled == false].Reference+.", 0, &values, 1), 0);
    assert_int_equal(amxc_var_type_of(&values), AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_llist_size(&values.data.vl), 1);
    amxc_var_dump(&values, STDOUT_FILENO);
    results = amxc_var_get_index(&values, 0, AMXC_VAR_FLAG_DEFAULT);
    assert_int_equal(amxc_var_type_of(results), AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_htable_size(&results->data.vm), 1);

    assert_int_not_equal(amxb_get(bus_ctx, "Device.TestObject.[Enabled == true].Reference+.", 0, &values, 1), 0);

    amxc_var_clean(&values);
}

void test_amxb_set(UNUSED void** state) {
    amxc_var_t values;
    amxc_var_t ret;
    amxc_var_t* results = NULL;
    amxc_var_init(&ret);
    amxc_var_init(&values);

    amxc_var_set_type(&values, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(bool, &values, "Enable", false);
    amxc_var_add_key(cstring_t, &values, "Status", "Dormant");
    assert_int_equal(amxb_set(bus_ctx, "Device.Ethernet.Interface.1", &values, &ret, 1), 0);
    amxc_var_dump(&ret, STDOUT_FILENO);
    assert_int_equal(amxc_var_type_of(&ret), AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_var_type_of(GETI_ARG(&ret, 0)), AMXC_VAR_ID_HTABLE);
    results = GETP_ARG(&ret, "0.'Device.Ethernet.Interface.1.'");
    assert_non_null(results);
    assert_non_null(GET_ARG(results, "Enable"));
    assert_non_null(GET_ARG(results, "Status"));

    assert_int_equal(amxb_get(bus_ctx, "Device.Ethernet.Interface.1.", 0, &values, 1), 0);
    assert_int_equal(amxc_var_type_of(&values), AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_llist_size(&values.data.vl), 1);
    amxc_var_dump(&values, STDOUT_FILENO);
    results = amxc_var_get_index(&values, 0, AMXC_VAR_FLAG_DEFAULT);
    assert_non_null(results);
    results = amxc_var_get_key(results, "Device.Ethernet.Interface.1.", AMXC_VAR_FLAG_DEFAULT);
    assert_non_null(results);
    results = amxc_var_get_key(results, "Status", AMXC_VAR_FLAG_DEFAULT);
    assert_non_null(results);
    assert_string_equal(amxc_var_constcast(cstring_t, results), "Dormant");

    assert_int_not_equal(amxb_set(bus_ctx, "Device.Link.Interface.1", &values, &ret, 1), 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&values);
}

void test_amxb_add(UNUSED void** state) {
    amxc_var_t values;
    amxc_var_t ret;
    amxc_var_t* results = NULL;
    amxc_var_init(&ret);
    amxc_var_init(&values);

    amxc_var_set_type(&values, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(bool, &values, "Enable", false);
    amxc_var_add_key(cstring_t, &values, "Status", "Unknown");

    assert_int_equal(amxb_add(bus_ctx, "Device.Ethernet.Interface", 0, NULL, &values, &ret, 1), 0);
    assert_int_equal(amxb_get(bus_ctx, "Device.Ethernet.Interface.5.", 0, &values, 1), 0);
    assert_int_equal(amxc_var_type_of(&values), AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_llist_size(&values.data.vl), 1);
    amxc_var_dump(&values, STDOUT_FILENO);
    results = amxc_var_get_index(&values, 0, AMXC_VAR_FLAG_DEFAULT);
    results = amxc_var_get_key(results, "Device.Ethernet.Interface.5.", AMXC_VAR_FLAG_DEFAULT);
    results = amxc_var_get_key(results, "Status", AMXC_VAR_FLAG_DEFAULT);
    assert_string_equal(amxc_var_constcast(cstring_t, results), "Unknown");

    assert_int_not_equal(amxb_add(bus_ctx, "Device.Ethernet.Link", 0, NULL, NULL, NULL, 1), 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&values);
}

void test_amxb_del(UNUSED void** state) {
    amxc_var_t values;
    amxc_var_t ret;
    amxc_var_init(&ret);
    amxc_var_init(&values);

    assert_int_equal(amxb_del(bus_ctx, "Device.Ethernet.Interface", 5, NULL, &ret, 1), 0);
    assert_int_not_equal(amxb_get(bus_ctx, "Device.Ethernet.Interface.5.", 0, &values, 1), 0);

    assert_int_not_equal(amxb_del(bus_ctx, "Device.Ethernet.Interface", 5, NULL, &ret, 1), 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&values);
}

void test_search_path_expr_func(UNUSED void** state) {
    amxp_expr_t expr;
    const char* expression1 = "'Device.Ethernet.Interface.3.Stats.' in search_path('Device.Ethernet.Interface.*.Stats.')";
    const char* expression2 = "'Device.Ethernet.Interface.3.Stats.' in search_path('Device.Ethernet.Interface.3.Stats.')";
    const char* expression3 = "'Device.Ethernet.Interface.3.Stats.' in search_path('Device.Ethernet.Interface.[Enable == 1].Stats.')";

    amxp_expr_init(&expr, expression1);
    assert_true(amxp_expr_evaluate(&expr, NULL, NULL, NULL));
    amxp_expr_clean(&expr);

    amxp_expr_init(&expr, expression2);
    assert_true(amxp_expr_evaluate(&expr, NULL, NULL, NULL));
    amxp_expr_clean(&expr);

    amxp_expr_init(&expr, expression3);
    assert_false(amxp_expr_evaluate(&expr, NULL, NULL, NULL));
    amxp_expr_clean(&expr);
}

void test_amxb_subscribe(UNUSED void** state) {
    int event_count = 0;
    handle_events();

    event_count = 0;
    assert_int_equal(amxb_subscribe(bus_ctx, "Device.Ethernet.Interface", NULL, event_handler, &event_count), 0);

    assert_int_equal(amxb_add(bus_ctx, "Device.Ethernet.Interface", 0, NULL, NULL, NULL, 1), 0);

    handle_events();
    assert_int_not_equal(event_count, 0);
}

void test_amxb_subscribe_non_existing(UNUSED void** state) {
    int event_count = 0;
    handle_events();

    event_count = 0;
    assert_int_not_equal(amxb_subscribe(bus_ctx, "Device.Ethernet.Link.", NULL, event_handler, &event_count), 0);

    handle_events();
    assert_int_equal(event_count, 0);
}

void test_amxb_subscribe_twice(UNUSED void** state) {
    int event_count = 0;
    handle_events();

    event_count = 0;
    assert_int_equal(amxb_subscribe(bus_ctx, "Device.Ethernet.Interface", NULL, event_handler, &event_count), 0);
    assert_int_equal(amxb_subscribe(bus_ctx, "Device.Ethernet.Interface", NULL, event_handler, &event_count), 0);

    assert_int_equal(amxb_add(bus_ctx, "Device.Ethernet.Interface", 0, NULL, NULL, NULL, 1), 0);

    handle_events();
    assert_int_not_equal(event_count, 0);
}

void test_amxb_subscribe_instance(UNUSED void** state) {
    int event_count = 0;
    handle_events();

    event_count = 0;
    assert_int_equal(amxb_subscribe(bus_ctx, "Device.Ethernet.Interface.1.", NULL, event_handler, &event_count), 0);

    handle_events();
}

void test_amxb_publish(UNUSED void** state) {
    assert_int_equal(amxb_publish(bus_ctx, "Device.Ethernet.Interface.1.", "test", NULL), 0);
    assert_int_not_equal(amxb_publish(NULL, "Device.Ethernet.Interface.1.", "test", NULL), 0);
    assert_int_not_equal(amxb_publish(bus_ctx, NULL, "test", NULL), 0);
    assert_int_not_equal(amxb_publish(bus_ctx, "Device.Ethernet.Interface.1.", NULL, NULL), 0);
    assert_int_not_equal(amxb_publish(bus_ctx, "", "test", NULL), 0);
    assert_int_not_equal(amxb_publish(bus_ctx, "Device.Ethernet.", "", NULL), 0);
    assert_int_not_equal(amxb_publish(bus_ctx, "Device.Ethernet.Link.1.", "test", NULL), 0);
}

static void test_amxb_list_cb(const amxb_bus_ctx_t* bus_ctx,
                              UNUSED const amxc_var_t* const data,
                              UNUSED void* priv) {
    assert_non_null(bus_ctx);
    if(data != NULL) {
        assert_int_equal(amxc_var_type_of(data), AMXC_VAR_ID_LIST);
    }
}

void test_amxb_list(UNUSED void** state) {
    assert_int_equal(amxb_list(bus_ctx, "Device.Ethernet.Interface.1.", 0, test_amxb_list_cb, NULL), 0);
    assert_int_equal(amxb_list(bus_ctx, "Device.Ethernet.Interface.",
                               AMXB_FLAG_INSTANCES |
                               AMXB_FLAG_OBJECTS,
                               test_amxb_list_cb, NULL), 0);
    assert_int_equal(amxb_list(bus_ctx, "Device.Ethernet.Interface.1.",
                               AMXB_FLAG_PARAMETERS |
                               AMXB_FLAG_FUNCTIONS |
                               AMXB_FLAG_NAMED,
                               test_amxb_list_cb, NULL), 0);
    assert_int_equal(amxb_list(bus_ctx, "Device.Ethernet.Interface.",
                               AMXB_FLAG_PARAMETERS |
                               AMXB_FLAG_FUNCTIONS |
                               AMXB_FLAG_INSTANCES,
                               test_amxb_list_cb, NULL), 0);
    assert_int_not_equal(amxb_list(NULL, "Device.Ethernet.Interface.1.", 0, test_amxb_list_cb, NULL), 0);
    assert_int_not_equal(amxb_list(bus_ctx, NULL, 0, test_amxb_list_cb, NULL), 0);
}