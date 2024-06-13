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
#include <setjmp.h>
#include <stdarg.h>
#include <cmocka.h>
#include <string.h>

#include <amxc/amxc.h>
#include <amxp/amxp.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_dm.h>
#include <amxd/amxd_path.h>
#include <amxb/amxb.h>
#include <amxo/amxo.h>

#include "amxa/amxa_merger.h"
#include "amxa/amxa_permissions.h"
#include "amxa/amxa_validator.h"
#include "amxa/amxa_resolver.h"
#include "amxa/amxa_set.h"

#include "amxa_merger_priv.h"
#include "test_amxa_set_multiple.h"
#include "test_amxa_common.h"
#include "dummy_backend.h"

#define UNUSED __attribute__((unused))

const uint32_t AMXA_PERMIT_PARAM_ALL = AMXA_PERMIT_GET | AMXA_PERMIT_SET | AMXA_PERMIT_SUBS_VAL_CHANGE;
const uint32_t AMXA_PERMIT_OBJ_ALL = AMXA_PERMIT_OBJ_INFO | AMXA_PERMIT_ADD | AMXA_PERMIT_SUBS_OBJ_ADD;
const uint32_t AMXA_PERMIT_INST_ALL = AMXA_PERMIT_GET_INST | AMXA_PERMIT_DEL | AMXA_PERMIT_SUBS_OBJ_DEL;
const uint32_t AMXA_PERMIT_CMD_EVT_ALL = AMXA_PERMIT_CMD_INFO | AMXA_PERMIT_OPER | AMXA_PERMIT_SUBS_EVT_OPER_COMP;

static const char* acl_file = "set_rules_merged.json";

int test_amxa_set_setup(UNUSED void** state) {
    amxc_var_t* data = NULL;

    test_amxa_setup(NULL);

    data = data_from_json("set_rules.json");
    assert_int_equal(amxa_merge_rules(data, acl_file), 0);
    amxc_var_delete(&data);

    return 0;
}

int test_amxa_set_teardown(UNUSED void** state) {
    return test_amxa_teardown(NULL);
}

void test_set_multiple_fails_with_invalid_input(UNUSED void** state) {
    amxc_var_t request;
    amxb_bus_ctx_t* bus_ctx = test_amxa_get_bus_ctx();
    const char* dummy_file = "test";

    assert_int_equal(amxa_set_multiple(NULL, 0, NULL, NULL, NULL, 0), -1);
    assert_int_equal(amxa_set_multiple(bus_ctx, 0, NULL, NULL, NULL, 0), -1);
    assert_int_equal(amxa_set_multiple(bus_ctx, 0, "", NULL, NULL, 0), -1);
    assert_int_equal(amxa_set_multiple(bus_ctx, 0, dummy_file, NULL, NULL, 0), -1);
    assert_int_equal(amxa_set_multiple(bus_ctx, 0, dummy_file, &request, NULL, 0), -1);
}

void test_set_multiple_allowed_non_partial_success(UNUSED void** state) {
    amxc_var_t req_paths;
    amxc_var_t ret;
    amxc_var_t* req = NULL;
    amxc_var_t* parameters = NULL;
    amxb_bus_ctx_t* bus_ctx = test_amxa_get_bus_ctx();

    amxc_var_init(&req_paths);
    amxc_var_init(&ret);

    amxc_var_set_type(&req_paths, AMXC_VAR_ID_LIST);
    req = amxc_var_add(amxc_htable_t, &req_paths, NULL);
    amxc_var_add_key(cstring_t, req, "path", "DHCPv4.Client.1.");
    parameters = amxc_var_add_key(amxc_htable_t, req, "parameters", NULL);
    amxc_var_add_key(bool, parameters, "Enable", true);
    amxc_var_add_key(cstring_t, parameters, "Interface", "test");

    req = amxc_var_add(amxc_htable_t, &req_paths, NULL);
    amxc_var_add_key(cstring_t, req, "path", "DHCPv4.Relay.Forwarding.*.");
    parameters = amxc_var_add_key(amxc_htable_t, req, "parameters", NULL);
    amxc_var_add_key(bool, parameters, "Enable", true);
    amxc_var_add_key(cstring_t, parameters, "Interface", "test");

    assert_int_equal(amxa_set_multiple(bus_ctx, 0, acl_file, &req_paths, &ret, 5), 0);
    amxc_var_dump(&ret, STDOUT_FILENO);

    assert_true(test_verify_data(&ret, "0.status", "0"));
    assert_true(test_verify_data(&ret, "1.status", "0"));

    amxc_var_clean(&ret);
    amxc_var_clean(&req_paths);
}

void test_set_multiple_allowed_non_partial_failure(UNUSED void** state) {
    amxc_var_t req_paths;
    amxc_var_t ret;
    amxc_var_t* req = NULL;
    amxc_var_t* parameters = NULL;
    amxb_bus_ctx_t* bus_ctx = test_amxa_get_bus_ctx();

    amxc_var_init(&req_paths);
    amxc_var_init(&ret);

    amxc_var_set_type(&req_paths, AMXC_VAR_ID_LIST);
    req = amxc_var_add(amxc_htable_t, &req_paths, NULL);
    amxc_var_add_key(cstring_t, req, "path", "DHCPv4.Client.1.");
    parameters = amxc_var_add_key(amxc_htable_t, req, "parameters", NULL);
    amxc_var_add_key(bool, parameters, "Enable", true);
    amxc_var_add_key(cstring_t, parameters, "Interface", "test");

    req = amxc_var_add(amxc_htable_t, &req_paths, NULL);
    amxc_var_add_key(cstring_t, req, "path", "DHCPv4.Relay.Forwarding.*.");
    parameters = amxc_var_add_key(amxc_htable_t, req, "parameters", NULL);
    amxc_var_add_key(bool, parameters, "Enable", true);
    amxc_var_add_key(cstring_t, parameters, "Status", "test");

    assert_int_equal(amxa_set_multiple(bus_ctx, 0, acl_file, &req_paths, &ret, 5), amxd_status_read_only);
    amxc_var_dump(&ret, STDOUT_FILENO);

    assert_true(test_verify_data(&ret, "0.status", "15"));
    assert_true(test_verify_data(&ret, "0.result.'DHCPv4.Relay.Forwarding.1.'.Status.error_code", "15"));

    amxc_var_clean(&ret);
    amxc_var_clean(&req_paths);
}

void test_set_multiple_allowed_partial_failure(UNUSED void** state) {
    amxc_var_t req_paths;
    amxc_var_t ret;
    amxc_var_t* req = NULL;
    amxc_var_t* parameters = NULL;
    amxb_bus_ctx_t* bus_ctx = test_amxa_get_bus_ctx();

    amxc_var_init(&req_paths);
    amxc_var_init(&ret);

    amxc_var_set_type(&req_paths, AMXC_VAR_ID_LIST);
    req = amxc_var_add(amxc_htable_t, &req_paths, NULL);
    amxc_var_add_key(cstring_t, req, "path", "DHCPv4.Client.1.");
    parameters = amxc_var_add_key(amxc_htable_t, req, "parameters", NULL);
    amxc_var_add_key(bool, parameters, "Enable", true);
    amxc_var_add_key(cstring_t, parameters, "Interface", "test");

    req = amxc_var_add(amxc_htable_t, &req_paths, NULL);
    amxc_var_add_key(cstring_t, req, "path", "DHCPv4.Relay.Forwarding.*.");
    parameters = amxc_var_add_key(amxc_htable_t, req, "parameters", NULL);
    amxc_var_add_key(bool, parameters, "Enable", true);
    amxc_var_add_key(cstring_t, parameters, "Status", "test");

    assert_int_equal(amxa_set_multiple(bus_ctx, AMXB_FLAG_PARTIAL, acl_file, &req_paths, &ret, 5), 0);
    amxc_var_dump(&ret, STDOUT_FILENO);

    assert_true(test_verify_data(&ret, "0.status", "0"));
    assert_true(test_verify_data(&ret, "1.status", "15"));
    assert_true(test_verify_data(&ret, "1.result.'DHCPv4.Relay.Forwarding.1.'.Status.error_code", "15"));

    amxc_var_clean(&ret);
    amxc_var_clean(&req_paths);
}

void test_set_multiple_required_not_allowed_non_partial(UNUSED void** state) {
    amxc_var_t req_paths;
    amxc_var_t ret;
    amxc_var_t* req = NULL;
    amxc_var_t* parameters = NULL;
    amxb_bus_ctx_t* bus_ctx = test_amxa_get_bus_ctx();

    amxc_var_init(&req_paths);
    amxc_var_init(&ret);

    amxc_var_set_type(&req_paths, AMXC_VAR_ID_LIST);
    req = amxc_var_add(amxc_htable_t, &req_paths, NULL);
    amxc_var_add_key(cstring_t, req, "path", "DHCPv4.Client.1.SentOption.1.");
    parameters = amxc_var_add_key(amxc_htable_t, req, "parameters", NULL);
    amxc_var_add_key(bool, parameters, "Enable", true);
    amxc_var_add_key(cstring_t, parameters, "Value", "test");

    req = amxc_var_add(amxc_htable_t, &req_paths, NULL);
    amxc_var_add_key(cstring_t, req, "path", "DHCPv4.Relay.Forwarding.*.");
    parameters = amxc_var_add_key(amxc_htable_t, req, "parameters", NULL);
    amxc_var_add_key(bool, parameters, "Enable", true);
    amxc_var_add_key(cstring_t, parameters, "Status", "test");

    assert_int_equal(amxa_set_multiple(bus_ctx, 0, acl_file, &req_paths, &ret, 5), -1);
    amxc_var_dump(&ret, STDOUT_FILENO);

    assert_true(test_verify_data(&ret, "0.status", "23"));
    assert_true(test_verify_data(&ret, "0.result.'DHCPv4.Client.1.SentOption.1.'.Enable.error_code", "23"));
    assert_true(test_verify_data(&ret, "0.result.'DHCPv4.Client.1.SentOption.1.'.Value.error_code", "23"));

    amxc_var_clean(&ret);
    amxc_var_clean(&req_paths);
}

void test_set_multiple_required_not_allowed_partial(UNUSED void** state) {
    amxc_var_t req_paths;
    amxc_var_t ret;
    amxc_var_t* req = NULL;
    amxc_var_t* parameters = NULL;
    amxb_bus_ctx_t* bus_ctx = test_amxa_get_bus_ctx();

    amxc_var_init(&req_paths);
    amxc_var_init(&ret);

    amxc_var_set_type(&req_paths, AMXC_VAR_ID_LIST);
    req = amxc_var_add(amxc_htable_t, &req_paths, NULL);
    amxc_var_add_key(cstring_t, req, "path", "DHCPv4.Client.1.SentOption.1.");
    parameters = amxc_var_add_key(amxc_htable_t, req, "parameters", NULL);
    amxc_var_add_key(bool, parameters, "Enable", true);
    amxc_var_add_key(cstring_t, parameters, "Value", "test");

    req = amxc_var_add(amxc_htable_t, &req_paths, NULL);
    amxc_var_add_key(cstring_t, req, "path", "DHCPv4.Relay.Forwarding.*.");
    parameters = amxc_var_add_key(amxc_htable_t, req, "parameters", NULL);
    amxc_var_add_key(bool, parameters, "Enable", true);
    amxc_var_add_key(cstring_t, parameters, "Status", "test");

    assert_int_equal(amxa_set_multiple(bus_ctx, AMXB_FLAG_PARTIAL, acl_file, &req_paths, &ret, 5), 0);
    amxc_var_dump(&ret, STDOUT_FILENO);

    assert_true(test_verify_data(&ret, "0.status", "15"));
    assert_true(test_verify_data(&ret, "0.result.'DHCPv4.Relay.Forwarding.1.'.Status.error_code", "15"));
    assert_true(test_verify_data(&ret, "1.status", "23"));
    assert_true(test_verify_data(&ret, "1.result.'DHCPv4.Client.1.SentOption.1.'.Enable.error_code", "23"));
    assert_true(test_verify_data(&ret, "1.result.'DHCPv4.Client.1.SentOption.1.'.Value.error_code", "23"));

    amxc_var_clean(&ret);
    amxc_var_clean(&req_paths);
}

void test_set_multiple_optional_allowed_non_partial(UNUSED void** state) {
    amxc_var_t req_paths;
    amxc_var_t ret;
    amxc_var_t* req = NULL;
    amxc_var_t* parameters = NULL;
    amxc_var_t* oparameters = NULL;
    amxb_bus_ctx_t* bus_ctx = test_amxa_get_bus_ctx();

    amxc_var_init(&req_paths);
    amxc_var_init(&ret);

    amxc_var_set_type(&req_paths, AMXC_VAR_ID_LIST);
    req = amxc_var_add(amxc_htable_t, &req_paths, NULL);
    amxc_var_add_key(cstring_t, req, "path", "DHCPv4.Client.1.SentOption.1.");
    oparameters = amxc_var_add_key(amxc_htable_t, req, "oparameters", NULL);
    amxc_var_add_key(uint32_t, oparameters, "Tag", 123);

    req = amxc_var_add(amxc_htable_t, &req_paths, NULL);
    amxc_var_add_key(cstring_t, req, "path", "DHCPv4.Relay.Forwarding.*.");
    parameters = amxc_var_add_key(amxc_htable_t, req, "parameters", NULL);
    amxc_var_add_key(bool, parameters, "Enable", true);
    amxc_var_add_key(cstring_t, parameters, "Interface", "test");

    assert_int_equal(amxa_set_multiple(bus_ctx, 0, acl_file, &req_paths, &ret, 5), 0);
    amxc_var_dump(&ret, STDOUT_FILENO);

    assert_true(test_verify_data(&ret, "0.status", "0"));
    assert_true(test_verify_data(&ret, "1.status", "0"));

    amxc_var_clean(&ret);
    amxc_var_clean(&req_paths);
}

void test_set_multiple_optional_not_allowed_non_partial(UNUSED void** state) {
    amxc_var_t req_paths;
    amxc_var_t ret;
    amxc_var_t* req = NULL;
    amxc_var_t* parameters = NULL;
    amxc_var_t* oparameters = NULL;
    amxb_bus_ctx_t* bus_ctx = test_amxa_get_bus_ctx();

    amxc_var_init(&req_paths);
    amxc_var_init(&ret);

    amxc_var_set_type(&req_paths, AMXC_VAR_ID_LIST);
    req = amxc_var_add(amxc_htable_t, &req_paths, NULL);
    amxc_var_add_key(cstring_t, req, "path", "DHCPv4.Client.1.SentOption.1.");
    oparameters = amxc_var_add_key(amxc_htable_t, req, "oparameters", NULL);
    amxc_var_add_key(uint32_t, oparameters, "Tag", 123);
    amxc_var_add_key(cstring_t, oparameters, "Value", "test");

    req = amxc_var_add(amxc_htable_t, &req_paths, NULL);
    amxc_var_add_key(cstring_t, req, "path", "DHCPv4.Relay.Forwarding.*.");
    parameters = amxc_var_add_key(amxc_htable_t, req, "parameters", NULL);
    amxc_var_add_key(bool, parameters, "Enable", true);
    amxc_var_add_key(cstring_t, parameters, "Interface", "test");

    assert_int_equal(amxa_set_multiple(bus_ctx, 0, acl_file, &req_paths, &ret, 5), 0);
    amxc_var_dump(&ret, STDOUT_FILENO);
    assert_true(test_verify_data(&ret, "0.status", "0"));
    assert_true(test_verify_data(&ret, "0.result.'DHCPv4.Client.1.SentOption.1.'.Value.error_code", "23"));
    assert_true(test_verify_data(&ret, "1.status", "0"));

    amxc_var_clean(&ret);
    amxc_var_clean(&req_paths);
}

void test_set_multiple_optional_not_allowed_partial(UNUSED void** state) {
    amxc_var_t req_paths;
    amxc_var_t ret;
    amxc_var_t* req = NULL;
    amxc_var_t* parameters = NULL;
    amxc_var_t* oparameters = NULL;
    amxb_bus_ctx_t* bus_ctx = test_amxa_get_bus_ctx();

    amxc_var_init(&req_paths);
    amxc_var_init(&ret);

    amxc_var_set_type(&req_paths, AMXC_VAR_ID_LIST);
    req = amxc_var_add(amxc_htable_t, &req_paths, NULL);
    amxc_var_add_key(cstring_t, req, "path", "DHCPv4.Client.1.SentOption.1.");
    oparameters = amxc_var_add_key(amxc_htable_t, req, "oparameters", NULL);
    amxc_var_add_key(uint32_t, oparameters, "Tag", 123);
    amxc_var_add_key(cstring_t, oparameters, "Value", "test");

    req = amxc_var_add(amxc_htable_t, &req_paths, NULL);
    amxc_var_add_key(cstring_t, req, "path", "DHCPv4.Relay.Forwarding.*.");
    parameters = amxc_var_add_key(amxc_htable_t, req, "parameters", NULL);
    amxc_var_add_key(bool, parameters, "Enable", true);
    amxc_var_add_key(cstring_t, parameters, "Interface", "test");

    assert_int_equal(amxa_set_multiple(bus_ctx, AMXB_FLAG_PARTIAL, acl_file, &req_paths, &ret, 5), 0);
    amxc_var_dump(&ret, STDOUT_FILENO);

    assert_true(test_verify_data(&ret, "0.status", "0"));
    assert_true(test_verify_data(&ret, "0.result.'DHCPv4.Client.1.SentOption.1.'.Value.error_code", "23"));
    assert_true(test_verify_data(&ret, "1.status", "0"));

    amxc_var_clean(&ret);
    amxc_var_clean(&req_paths);
}

// Consider optional params with search path as required
void test_set_multiple_optional_with_search_path_non_partial(UNUSED void** state) {
    amxc_var_t req_paths;
    amxc_var_t ret;
    amxc_var_t* req = NULL;
    amxc_var_t* parameters = NULL;
    amxc_var_t* oparameters = NULL;
    amxb_bus_ctx_t* bus_ctx = test_amxa_get_bus_ctx();

    amxc_var_init(&req_paths);
    amxc_var_init(&ret);

    amxc_var_set_type(&req_paths, AMXC_VAR_ID_LIST);
    req = amxc_var_add(amxc_htable_t, &req_paths, NULL);
    amxc_var_add_key(cstring_t, req, "path", "DHCPv4.Client.*.SentOption.1.");
    oparameters = amxc_var_add_key(amxc_htable_t, req, "oparameters", NULL);
    amxc_var_add_key(uint32_t, oparameters, "Tag", 123);
    amxc_var_add_key(cstring_t, oparameters, "Value", "test");

    req = amxc_var_add(amxc_htable_t, &req_paths, NULL);
    amxc_var_add_key(cstring_t, req, "path", "DHCPv4.Relay.Forwarding.*.");
    parameters = amxc_var_add_key(amxc_htable_t, req, "parameters", NULL);
    amxc_var_add_key(bool, parameters, "Enable", true);
    amxc_var_add_key(cstring_t, parameters, "Interface", "test");

    assert_int_equal(amxa_set_multiple(bus_ctx, 0, acl_file, &req_paths, &ret, 5), -1);
    amxc_var_dump(&ret, STDOUT_FILENO);

    assert_true(test_verify_data(&ret, "0.status", "23"));
    assert_true(test_verify_data(&ret, "0.result.'DHCPv4.Client.1.SentOption.1.'.Value.error_code", "23"));

    amxc_var_clean(&ret);
    amxc_var_clean(&req_paths);
}

// Consider optional params with search path as required
void test_set_multiple_optional_with_search_path_partial(UNUSED void** state) {
    amxc_var_t req_paths;
    amxc_var_t ret;
    amxc_var_t* req = NULL;
    amxc_var_t* parameters = NULL;
    amxc_var_t* oparameters = NULL;
    amxb_bus_ctx_t* bus_ctx = test_amxa_get_bus_ctx();

    amxc_var_init(&req_paths);
    amxc_var_init(&ret);

    amxc_var_set_type(&req_paths, AMXC_VAR_ID_LIST);
    req = amxc_var_add(amxc_htable_t, &req_paths, NULL);
    amxc_var_add_key(cstring_t, req, "path", "DHCPv4.Client.*.SentOption.1.");
    oparameters = amxc_var_add_key(amxc_htable_t, req, "oparameters", NULL);
    amxc_var_add_key(uint32_t, oparameters, "Tag", 123);
    amxc_var_add_key(cstring_t, oparameters, "Value", "test");

    req = amxc_var_add(amxc_htable_t, &req_paths, NULL);
    amxc_var_add_key(cstring_t, req, "path", "DHCPv4.Relay.Forwarding.*.");
    parameters = amxc_var_add_key(amxc_htable_t, req, "parameters", NULL);
    amxc_var_add_key(bool, parameters, "Enable", true);
    amxc_var_add_key(cstring_t, parameters, "Interface", "test");

    assert_int_equal(amxa_set_multiple(bus_ctx, AMXB_FLAG_PARTIAL, acl_file, &req_paths, &ret, 5), 0);
    amxc_var_dump(&ret, STDOUT_FILENO);

    assert_true(test_verify_data(&ret, "0.status", "0"));
    assert_true(test_verify_data(&ret, "1.status", "23"));
    assert_true(test_verify_data(&ret, "1.result.'DHCPv4.Client.1.SentOption.1.'.Value.error_code", "23"));

    amxc_var_clean(&ret);
    amxc_var_clean(&req_paths);
}

void test_set_multiple_allowed_same_paths(UNUSED void** state) {
    amxc_var_t req_paths;
    amxc_var_t ret;
    amxc_var_t* req = NULL;
    amxc_var_t* parameters = NULL;
    amxb_bus_ctx_t* bus_ctx = test_amxa_get_bus_ctx();

    amxc_var_init(&req_paths);
    amxc_var_init(&ret);

    amxc_var_set_type(&req_paths, AMXC_VAR_ID_LIST);
    req = amxc_var_add(amxc_htable_t, &req_paths, NULL);
    amxc_var_add_key(cstring_t, req, "path", "DHCPv4.Client.1.");
    parameters = amxc_var_add_key(amxc_htable_t, req, "parameters", NULL);
    amxc_var_add_key(bool, parameters, "Enable", false);

    req = amxc_var_add(amxc_htable_t, &req_paths, NULL);
    amxc_var_add_key(cstring_t, req, "path", "DHCPv4.Client.1.");
    parameters = amxc_var_add_key(amxc_htable_t, req, "parameters", NULL);
    amxc_var_add_key(cstring_t, parameters, "Interface", "testing");

    assert_int_equal(amxa_set_multiple(bus_ctx, 0, acl_file, &req_paths, &ret, 5), 0);
    amxc_var_dump(&ret, STDOUT_FILENO);

    assert_true(test_verify_data(&ret, "0.status", "0"));
    assert_true(test_verify_data(&ret, "1.status", "0"));

    amxc_var_clean(&ret);
    amxc_var_clean(&req_paths);
}
