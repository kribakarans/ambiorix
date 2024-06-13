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
#include <amxd/amxd_path.h>

#include <amxb/amxb.h>
#include <amxb/amxb_register.h>
#include <amxb/amxb_be_intf.h>

#include <amxo/amxo.h>

#include "dummy_be.h"
#include "test_amxb_e2e.h"

#include <amxc/amxc_macros.h>
static amxb_bus_ctx_t* bus_ctx = NULL;
static amxd_dm_t dm;
static amxo_parser_t parser;

int test_amxb_e2e_setup(UNUSED void** state) {
    amxd_dm_init(&dm);
    amxo_parser_init(&parser);

    test_register_dummy_be();

    assert_int_equal(amxb_connect(&bus_ctx, "dummy:/tmp/dummy.sock"), 0);

    test_load_dummy_remote("./test.odl");
    amxo_parser_parse_file(&parser, "./local.odl", amxd_dm_get_root(&dm));

    assert_int_equal(amxb_register(bus_ctx, &dm), 0);

    return 0;
}

int test_amxb_e2e_teardown(UNUSED void** state) {
    amxb_disconnect(bus_ctx);
    amxb_free(&bus_ctx);

    amxo_parser_clean(&parser);
    amxd_dm_clean(&dm);

    test_unregister_dummy_be();
    return 0;
}

void test_amxb_call(UNUSED void** state) {
    amxc_var_t values;
    amxc_var_t* results = NULL;
    amxc_var_init(&values);

    assert_int_equal(amxb_call(bus_ctx, "Device.Ethernet.Interface.1", "_get", NULL, NULL, 5), 0);

    assert_int_equal(amxb_call(bus_ctx, "Device.Ethernet.Interface.1", "_get", NULL, &values, 5), 0);
    amxc_var_dump(&values, STDOUT_FILENO);
    results = amxc_var_get_index(&values, 0, AMXC_VAR_FLAG_DEFAULT);
    assert_int_equal(amxc_var_type_of(results), AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_htable_size(&results->data.vm), 1);

    assert_int_not_equal(amxb_call(bus_ctx, "Device.Link.Interface.1", "_get", NULL, NULL, 5), 0);

    amxc_var_clean(&values);
}

void test_amxb_get(UNUSED void** state) {
    amxc_var_t values;
    amxc_var_t* results = NULL;
    amxc_var_init(&values);

    assert_int_equal(amxb_get(bus_ctx, "Device.Ethernet.Interface.1.Status", 0, &values, 5), 0);
    assert_int_equal(amxc_var_type_of(&values), AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_llist_size(&values.data.vl), 1);
    amxc_var_dump(&values, STDOUT_FILENO);
    results = amxc_var_get_index(&values, 0, AMXC_VAR_FLAG_DEFAULT);
    assert_int_equal(amxc_var_type_of(results), AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_htable_size(&results->data.vm), 1);

    assert_int_equal(amxb_get(bus_ctx, "Device.Ethernet.Interface.*.Status", 0, &values, 5), 0);
    assert_int_equal(amxc_var_type_of(&values), AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_llist_size(&values.data.vl), 1);
    amxc_var_dump(&values, STDOUT_FILENO);
    results = amxc_var_get_index(&values, 0, AMXC_VAR_FLAG_DEFAULT);
    assert_int_equal(amxc_var_type_of(results), AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_htable_size(&results->data.vm), 5);

    assert_int_equal(amxb_get(bus_ctx, "Device.Ethernet.Interface.[Enable == true].Status", 0, &values, 5), 0);
    assert_int_equal(amxc_var_type_of(&values), AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_llist_size(&values.data.vl), 1);
    amxc_var_dump(&values, STDOUT_FILENO);
    results = amxc_var_get_index(&values, 0, AMXC_VAR_FLAG_DEFAULT);
    assert_int_equal(amxc_var_type_of(results), AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_htable_size(&results->data.vm), 3);

    assert_int_not_equal(amxb_get(bus_ctx, "Device.Ethernet.Link.[Enable == true].Status", 0, &values, 5), 0);

    amxc_var_clean(&values);
}

void test_amxb_get_instances(UNUSED void** state) {
    amxc_var_t values;
    amxc_var_t* results = NULL;
    amxc_var_init(&values);

    assert_int_equal(amxb_get_instances(bus_ctx, "MQTT.Client.", 0, &values, 1), 0);
    assert_int_equal(amxc_var_type_of(&values), AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_llist_size(&values.data.vl), 1);
    amxc_var_dump(&values, STDOUT_FILENO);
    results = amxc_var_get_index(&values, 0, AMXC_VAR_FLAG_DEFAULT);
    assert_int_equal(amxc_var_type_of(results), AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_htable_size(&results->data.vm), 2);

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
    assert_int_equal(amxb_set(bus_ctx, "Device.Ethernet.Interface.1", &values, &ret, 5), 0);
    amxc_var_dump(&ret, STDOUT_FILENO);
    assert_int_equal(amxc_var_type_of(&ret), AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_var_type_of(GETI_ARG(&ret, 0)), AMXC_VAR_ID_HTABLE);
    results = GETP_ARG(&ret, "0.'Device.Ethernet.Interface.1.'");
    assert_non_null(results);
    assert_non_null(GET_ARG(results, "Enable"));
    assert_non_null(GET_ARG(results, "Status"));

    assert_int_equal(amxb_get(bus_ctx, "Device.Ethernet.Interface.1.", 0, &values, 5), 0);
    assert_int_equal(amxc_var_type_of(&values), AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_llist_size(&values.data.vl), 1);
    amxc_var_dump(&values, STDOUT_FILENO);
    results = amxc_var_get_index(&values, 0, AMXC_VAR_FLAG_DEFAULT);
    results = amxc_var_get_key(results, "Device.Ethernet.Interface.1.", AMXC_VAR_FLAG_DEFAULT);
    results = amxc_var_get_key(results, "Status", AMXC_VAR_FLAG_DEFAULT);
    assert_string_equal(amxc_var_constcast(cstring_t, results), "Dormant");

    assert_int_not_equal(amxb_set(bus_ctx, "Device.Link.Interface.1", &values, &ret, 5), 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&values);
}

void test_amxb_set_multiple(UNUSED void** state) {
    amxc_var_t req_paths;
    amxc_var_t ret;
    amxc_var_t* req_path = NULL;
    amxc_var_t* params = NULL;
    amxc_var_t* results = NULL;
    amxc_var_init(&ret);
    amxc_var_init(&req_paths);

    amxc_var_set_type(&req_paths, AMXC_VAR_ID_LIST);
    req_path = amxc_var_add(amxc_htable_t, &req_paths, NULL);
    amxc_var_add_key(cstring_t, req_path, "path", "Device.Ethernet.Interface.2.");
    params = amxc_var_add_key(amxc_htable_t, req_path, "parameters", NULL);
    amxc_var_add_key(cstring_t, params, "Status", "dummy-invalid");

    req_path = amxc_var_add(amxc_htable_t, &req_paths, NULL);
    amxc_var_add_key(cstring_t, req_path, "path", "Device.Ethernet.Interface.[Status == 'Dormant'].");
    params = amxc_var_add_key(amxc_htable_t, req_path, "parameters", NULL);
    amxc_var_add_key(bool, params, "Enable", false);

    req_path = amxc_var_add(amxc_htable_t, &req_paths, NULL);
    amxc_var_add_key(cstring_t, req_path, "path", "MQTT.Client.*.");
    params = amxc_var_add_key(amxc_htable_t, req_path, "parameters", NULL);
    amxc_var_add_key(bool, params, "Enable", true);
    amxc_var_add_key(cstring_t, params, "TransportProtocol", "TLS");

    req_path = amxc_var_add(amxc_htable_t, &req_paths, NULL);
    amxc_var_add_key(cstring_t, req_path, "path", "MQTT.Client.1.");
    params = amxc_var_add_key(amxc_htable_t, req_path, "parameters", NULL);
    amxc_var_add_key(bool, params, "Enable", true);
    amxc_var_add_key(cstring_t, params, "TransportProtocol", "TLS");

    amxc_var_dump(&req_paths, STDOUT_FILENO);

    assert_int_not_equal(amxb_set_multiple(bus_ctx, 0, &req_paths, &ret, 5), 0);
    amxc_var_dump(&ret, STDOUT_FILENO);

    assert_int_equal(amxc_var_type_of(&ret), AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_llist_size(amxc_var_constcast(amxc_llist_t, &ret)), 1);
    results = GETI_ARG(&ret, 0);
    assert_non_null(results);
    assert_non_null(GETP_ARG(results, "result.'Device.Ethernet.Interface.2.'.Status"));
    assert_int_equal(amxc_var_type_of(GETP_ARG(results, "result.'Device.Ethernet.Interface.2.'.Status")), AMXC_VAR_ID_HTABLE);

    amxc_var_clean(&ret);
    assert_int_equal(amxb_get(bus_ctx, "MQTT.Client.*.Enable", 0, &ret, 5), 0);
    assert_false(GETP_BOOL(&ret, "0.'MQTT.Client.1.'.Enable"));
    assert_false(GETP_BOOL(&ret, "0.'MQTT.Client.2.'.Enable"));

    amxc_var_clean(&ret);
    amxc_var_clean(&req_paths);
}

void test_amxb_set_multiple_same_path(UNUSED void** state) {
    amxc_var_t req_paths;
    amxc_var_t ret;
    amxc_var_t* req_path = NULL;
    amxc_var_t* params = NULL;
    amxc_var_t* results = NULL;
    amxc_var_init(&ret);
    amxc_var_init(&req_paths);

    amxc_var_set_type(&req_paths, AMXC_VAR_ID_LIST);
    req_path = amxc_var_add(amxc_htable_t, &req_paths, NULL);
    amxc_var_add_key(cstring_t, req_path, "path", "Device.Ethernet.Interface.2.");
    params = amxc_var_add_key(amxc_htable_t, req_path, "parameters", NULL);
    amxc_var_add_key(cstring_t, params, "Status", "Down");

    req_path = amxc_var_add(amxc_htable_t, &req_paths, NULL);
    amxc_var_add_key(cstring_t, req_path, "path", "Device.Ethernet.Interface.2.");
    params = amxc_var_add_key(amxc_htable_t, req_path, "parameters", NULL);
    amxc_var_add_key(bool, params, "Enable", false);
    amxc_var_dump(&req_paths, STDOUT_FILENO);

    assert_int_equal(amxb_set_multiple(bus_ctx, 0, &req_paths, &ret, 5), 0);
    amxc_var_dump(&ret, STDOUT_FILENO);

    assert_int_equal(amxc_var_type_of(&ret), AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_llist_size(amxc_var_constcast(amxc_llist_t, &ret)), 2);
    results = GETI_ARG(&ret, 0);
    assert_non_null(results);
    assert_non_null(GETP_ARG(results, "result.'Device.Ethernet.Interface.2.'.Status"));
    assert_int_equal(amxc_var_type_of(GETP_ARG(results, "result.'Device.Ethernet.Interface.2.'")), AMXC_VAR_ID_HTABLE);

    results = GETI_ARG(&ret, 1);
    assert_non_null(results);
    assert_non_null(GETP_ARG(results, "result.'Device.Ethernet.Interface.2.'.Enable"));
    assert_int_equal(amxc_var_type_of(GETP_ARG(results, "result.'Device.Ethernet.Interface.2.'")), AMXC_VAR_ID_HTABLE);

    amxc_var_clean(&ret);
    assert_int_equal(amxb_get(bus_ctx, "MQTT.Client.*.Enable", 0, &ret, 5), 0);
    assert_false(GETP_BOOL(&ret, "0.'MQTT.Client.1.'.Enable"));
    assert_false(GETP_BOOL(&ret, "0.'MQTT.Client.2.'.Enable"));

    amxc_var_clean(&ret);
    amxc_var_clean(&req_paths);
}

void test_amxb_set_multiple_allow_partial(UNUSED void** state) {
    amxc_var_t req_paths;
    amxc_var_t ret;
    amxc_var_t* req_path = NULL;
    amxc_var_t* params = NULL;
    amxc_var_t* results = NULL;
    amxc_var_init(&ret);
    amxc_var_init(&req_paths);

    amxc_var_set_type(&req_paths, AMXC_VAR_ID_LIST);
    req_path = amxc_var_add(amxc_htable_t, &req_paths, NULL);
    amxc_var_add_key(cstring_t, req_path, "path", "Device.Ethernet.Interface.2.");
    params = amxc_var_add_key(amxc_htable_t, req_path, "parameters", NULL);
    amxc_var_add_key(cstring_t, params, "Status", "dummy-invalid");

    req_path = amxc_var_add(amxc_htable_t, &req_paths, NULL);
    amxc_var_add_key(cstring_t, req_path, "path", "Device.Ethernet.Interface.[Status == 'Dormant'].");
    params = amxc_var_add_key(amxc_htable_t, req_path, "parameters", NULL);
    amxc_var_add_key(bool, params, "Enable", false);

    req_path = amxc_var_add(amxc_htable_t, &req_paths, NULL);
    amxc_var_add_key(cstring_t, req_path, "path", "MQTT.Client.*.");
    params = amxc_var_add_key(amxc_htable_t, req_path, "parameters", NULL);
    amxc_var_add_key(bool, params, "Enable", true);
    amxc_var_add_key(cstring_t, params, "TransportProtocol", "TLS");

    req_path = amxc_var_add(amxc_htable_t, &req_paths, NULL);
    amxc_var_add_key(cstring_t, req_path, "path", "MQTT.Client.[Alias == 'cpe-mybroker'].");
    params = amxc_var_add_key(amxc_htable_t, req_path, "parameters", NULL);
    amxc_var_add_key(bool, params, "Enable", true);
    amxc_var_add_key(cstring_t, params, "TransportProtocol", "TLS");

    amxc_var_dump(&req_paths, STDOUT_FILENO);

    assert_int_equal(amxb_set_multiple(bus_ctx, AMXB_FLAG_PARTIAL, &req_paths, &ret, 5), 0);
    amxc_var_dump(&ret, STDOUT_FILENO);

    assert_int_equal(amxc_var_type_of(&ret), AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_llist_size(amxc_var_constcast(amxc_llist_t, &ret)), 4);
    results = GETI_ARG(&ret, 0);
    assert_non_null(results);
    assert_non_null(GETP_ARG(results, "result.'Device.Ethernet.Interface.2.'.Status"));
    assert_int_equal(amxc_var_type_of(GETP_ARG(results, "result.'Device.Ethernet.Interface.2.'.Status")), AMXC_VAR_ID_HTABLE);

    results = GETI_ARG(&ret, 1);
    assert_non_null(results);
    assert_non_null(GETP_ARG(results, "result.'Device.Ethernet.Interface.1.'.Enable"));
    assert_int_equal(amxc_var_type_of(GETP_ARG(results, "result.'Device.Ethernet.Interface.1.'.Enable")), AMXC_VAR_ID_BOOL);
    assert_non_null(GETP_ARG(results, "result.'Device.Ethernet.Interface.5.'.Enable"));
    assert_int_equal(amxc_var_type_of(GETP_ARG(results, "result.'Device.Ethernet.Interface.5.'.Enable")), AMXC_VAR_ID_BOOL);

    results = GETI_ARG(&ret, 2);
    assert_non_null(results);
    assert_non_null(GETP_ARG(results, "result.'MQTT.Client.1.'.Enable"));
    assert_int_equal(amxc_var_type_of(GETP_ARG(results, "result.'MQTT.Client.1.'.Enable")), AMXC_VAR_ID_BOOL);
    assert_non_null(GETP_ARG(results, "result.'MQTT.Client.2.'.Enable"));
    assert_int_equal(amxc_var_type_of(GETP_ARG(results, "result.'MQTT.Client.2.'.Enable")), AMXC_VAR_ID_BOOL);

    results = GETI_ARG(&ret, 3);
    assert_non_null(results);

    amxc_var_clean(&ret);
    assert_int_equal(amxb_get(bus_ctx, "MQTT.Client.*.Enable", 0, &ret, 5), 0);
    assert_true(GETP_BOOL(&ret, "0.'MQTT.Client.1.'.Enable"));
    assert_true(GETP_BOOL(&ret, "0.'MQTT.Client.2.'.Enable"));

    amxc_var_clean(&ret);
    amxc_var_clean(&req_paths);
}

void test_amxb_set_multiple_optional_params(UNUSED void** state) {
    amxc_var_t req_paths;
    amxc_var_t ret;
    amxc_var_t* req_path = NULL;
    amxc_var_t* params = NULL;
    amxc_var_t* results = NULL;
    amxc_var_init(&ret);
    amxc_var_init(&req_paths);

    amxc_var_set_type(&req_paths, AMXC_VAR_ID_LIST);
    req_path = amxc_var_add(amxc_htable_t, &req_paths, NULL);
    amxc_var_add_key(cstring_t, req_path, "path", "Device.Ethernet.Interface.2.");
    params = amxc_var_add_key(amxc_htable_t, req_path, "oparameters", NULL);
    amxc_var_add_key(cstring_t, params, "Status", "dummy-invalid");

    req_path = amxc_var_add(amxc_htable_t, &req_paths, NULL);
    amxc_var_add_key(cstring_t, req_path, "path", "Device.Ethernet.Interface.[Status == 'Dormant'].");
    params = amxc_var_add_key(amxc_htable_t, req_path, "oparameters", NULL);
    amxc_var_add_key(bool, params, "Enable", false);

    req_path = amxc_var_add(amxc_htable_t, &req_paths, NULL);
    amxc_var_add_key(cstring_t, req_path, "path", "MQTT.Client.*.");
    params = amxc_var_add_key(amxc_htable_t, req_path, "oparameters", NULL);
    amxc_var_add_key(bool, params, "Enable", true);
    amxc_var_add_key(cstring_t, params, "TransportProtocol", "TLS");
    amxc_var_dump(&req_paths, STDOUT_FILENO);

    assert_int_equal(amxb_set_multiple(bus_ctx, AMXB_FLAG_PARTIAL, &req_paths, &ret, 5), 0);
    amxc_var_dump(&ret, STDOUT_FILENO);

    assert_int_equal(amxc_var_type_of(&ret), AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_llist_size(amxc_var_constcast(amxc_llist_t, &ret)), 3);
    results = GETI_ARG(&ret, 0);
    assert_non_null(results);
    assert_non_null(GETP_ARG(results, "result.'Device.Ethernet.Interface.2.'.Status"));
    assert_int_equal(amxc_var_type_of(GETP_ARG(results, "result.'Device.Ethernet.Interface.2.'.Status")), AMXC_VAR_ID_HTABLE);

    results = GETI_ARG(&ret, 1);
    assert_non_null(results);
    assert_non_null(GETP_ARG(results, "result.'Device.Ethernet.Interface.1.'.Enable"));
    assert_int_equal(amxc_var_type_of(GETP_ARG(results, "result.'Device.Ethernet.Interface.1.'.Enable")), AMXC_VAR_ID_BOOL);
    assert_non_null(GETP_ARG(results, "result.'Device.Ethernet.Interface.5.'.Enable"));
    assert_int_equal(amxc_var_type_of(GETP_ARG(results, "result.'Device.Ethernet.Interface.5.'.Enable")), AMXC_VAR_ID_BOOL);

    results = GETI_ARG(&ret, 2);
    assert_non_null(results);
    assert_non_null(GETP_ARG(results, "result.'MQTT.Client.1.'.Enable"));
    assert_int_equal(amxc_var_type_of(GETP_ARG(results, "result.'MQTT.Client.1.'.Enable")), AMXC_VAR_ID_BOOL);
    assert_non_null(GETP_ARG(results, "result.'MQTT.Client.2.'.Enable"));
    assert_int_equal(amxc_var_type_of(GETP_ARG(results, "result.'MQTT.Client.2.'.Enable")), AMXC_VAR_ID_BOOL);

    amxc_var_clean(&ret);
    amxc_var_clean(&req_paths);
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

    assert_int_equal(amxb_add(bus_ctx, "Device.Ethernet.Interface", 0, NULL, &values, &ret, 5), 0);
    assert_int_equal(amxb_get(bus_ctx, "Device.Ethernet.Interface.6.", 0, &values, 5), 0);
    assert_int_equal(amxc_var_type_of(&values), AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_llist_size(&values.data.vl), 1);
    amxc_var_dump(&values, STDOUT_FILENO);
    results = amxc_var_get_index(&values, 0, AMXC_VAR_FLAG_DEFAULT);
    results = amxc_var_get_key(results, "Device.Ethernet.Interface.6.", AMXC_VAR_FLAG_DEFAULT);
    results = amxc_var_get_key(results, "Status", AMXC_VAR_FLAG_DEFAULT);
    assert_string_equal(amxc_var_constcast(cstring_t, results), "Unknown");

    assert_int_not_equal(amxb_add(bus_ctx, "Device.Ethernet.Link", 0, NULL, NULL, NULL, 5), 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&values);
}

void test_amxb_del(UNUSED void** state) {
    amxc_var_t values;
    amxc_var_t ret;
    amxc_var_init(&values);
    amxc_var_init(&ret);

    assert_int_equal(amxb_del(bus_ctx, "Device.Ethernet.Interface", 5, NULL, &ret, 5), 0);
    assert_int_not_equal(amxb_get(bus_ctx, "Device.Ethernet.Interface.5.", 0, &values, 5), 0);

    assert_int_not_equal(amxb_del(bus_ctx, "Device.Ethernet.Interface", 5, NULL, &ret, 5), 0);

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

void test_amxb_get_supported(UNUSED void** state) {
    uint32_t flags = AMXB_FLAG_FUNCTIONS | AMXB_FLAG_PARAMETERS | AMXB_FLAG_EVENTS;
    amxc_var_t values;
    amxc_var_t* results = NULL;
    amxc_var_init(&values);


    assert_int_equal(amxb_get_supported(bus_ctx, "Device", flags, &values, 5), 0);
    assert_int_equal(amxc_var_type_of(&values), AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_llist_size(&values.data.vl), 1);
    amxc_var_dump(&values, STDOUT_FILENO);
    results = amxc_var_get_index(&values, 0, AMXC_VAR_FLAG_DEFAULT);
    assert_int_equal(amxc_var_type_of(results), AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_htable_size(&results->data.vm), 4);

    assert_int_equal(amxb_get_supported(bus_ctx, "Device.Ethernet.Interface.", flags, &values, 5), 0);
    assert_int_equal(amxc_var_type_of(&values), AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_llist_size(&values.data.vl), 1);
    amxc_var_dump(&values, STDOUT_FILENO);
    results = amxc_var_get_index(&values, 0, AMXC_VAR_FLAG_DEFAULT);
    assert_int_equal(amxc_var_type_of(results), AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_htable_size(&results->data.vm), 2);

    assert_int_equal(amxb_get_supported(bus_ctx, "Device.Ethernet.Interface.{i}.", flags, &values, 5), 0);
    assert_int_equal(amxc_var_type_of(&values), AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_llist_size(&values.data.vl), 1);
    amxc_var_dump(&values, STDOUT_FILENO);
    results = amxc_var_get_index(&values, 0, AMXC_VAR_FLAG_DEFAULT);
    assert_int_equal(amxc_var_type_of(results), AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_htable_size(&results->data.vm), 2);

    assert_int_equal(amxb_get_supported(bus_ctx, "Device.Ethernet.Interface.{i}", flags, &values, 5), 0);
    assert_int_equal(amxc_var_type_of(&values), AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_llist_size(&values.data.vl), 1);
    amxc_var_dump(&values, STDOUT_FILENO);
    results = amxc_var_get_index(&values, 0, AMXC_VAR_FLAG_DEFAULT);
    assert_int_equal(amxc_var_type_of(results), AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_htable_size(&results->data.vm), 2);

    assert_int_not_equal(amxb_get_supported(bus_ctx, "Device.Ethernet.Link", flags, &values, 5), 0);

    amxc_var_clean(&values);
}

void test_amxb_set_config(UNUSED void** state) {
    amxc_var_t config;

    amxc_var_init(&config);
    amxc_var_set_type(&config, AMXC_VAR_ID_HTABLE);

    amxc_var_add_key(amxc_htable_t, &config, "dummy", NULL);
    assert_int_equal(amxb_set_config(&config), 0);
    assert_int_equal(amxb_set_config(NULL), 0);

    amxc_var_clean(&config);
}

void test_amxb_resolve_failure(UNUSED void** state) {
    amxc_var_t resolved;
    amxc_var_init(&resolved);
    amxd_path_t path;
    amxd_path_init(&path, "Device.Ethernet.Interface.[Status == \"foo\"].");

    assert_int_equal(amxb_resolve(bus_ctx, &path, &resolved), 0);
    assert_true(amxc_var_type_of(&resolved) == AMXC_VAR_ID_NULL);

    amxc_var_clean(&resolved);
    amxd_path_clean(&path);
}

void test_amxb_who_has(UNUSED void** state) {
    assert_ptr_equal(amxb_be_who_has("Device.Ethernet.Interface."), bus_ctx);
    test_set_dummy_caps(AMXB_BE_DISCOVER_DESCRIBE);
    assert_ptr_equal(amxb_be_who_has("Device.Ethernet.Interface."), bus_ctx);
    test_set_dummy_caps(AMXB_BE_DISCOVER_LIST);
    assert_ptr_equal(amxb_be_who_has("Device.Ethernet.Interface."), bus_ctx);
    test_set_dummy_caps(AMXB_BE_DISCOVER_DESCRIBE | AMXB_BE_DISCOVER_LIST | AMXB_BE_DISCOVER);

    assert_ptr_equal(amxb_be_who_has("Device."), bus_ctx);
    assert_ptr_equal(amxb_be_who_has("Local.TestObject."), bus_ctx);

    assert_null(amxb_be_who_has(""));
    assert_null(amxb_be_who_has(NULL));
}

void test_amxb_who_has_cache_set_size(UNUSED void** state) {
    amxb_be_cache_set_size(2);
    assert_ptr_equal(amxb_be_who_has("Device.Ethernet.Interface."), bus_ctx);
    assert_ptr_equal(amxb_be_who_has("Local.TestObject."), bus_ctx);
    assert_ptr_equal(amxb_be_who_has("Device.Ethernet."), bus_ctx);
    assert_ptr_equal(amxb_be_who_has("Device."), bus_ctx);
    assert_null(amxb_be_who_has(""));
    assert_null(amxb_be_who_has(NULL));
}

void test_amxb_who_has_cache_remove_path(UNUSED void** state) {
    amxb_be_cache_remove_path("Device.");
    assert_ptr_equal(amxb_be_who_has("Device."), bus_ctx);
    assert_null(amxb_be_who_has(""));
    assert_null(amxb_be_who_has(NULL));
}

void test_amxb_cache_disable(UNUSED void** state) {
    amxb_be_cache_set_size(0);
    assert_ptr_equal(amxb_be_who_has("Device.Ethernet.Interface."), bus_ctx);
}
