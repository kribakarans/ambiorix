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
#include <sys/stat.h>
#include <sys/types.h>

#include <amxc/amxc.h>
#include <amxp/amxp.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_dm.h>
#include <amxo/amxo.h>

#include "amxa/amxa_permissions.h"
#include "amxa/amxa_validator.h"
#include "amxa/amxa_merger.h"
#include "amxa_merger_priv.h"
#include "amxa/amxa_get_instances.h"

#include "test_amxa_get_inst.h"

#include "dummy_backend.h"
#include "test_amxa_common.h"

#define UNUSED __attribute__((unused))

static const char* acl_dir = NULL;
static const char* role = "root";
static amxc_string_t acl_file;

static void acl_initialize(void) {
    amxc_var_t* root_acls = NULL;
    amxo_parser_t* parser = test_amxa_get_parser();
    amxc_string_t path;

    amxc_string_init(&path, 0);

    // Mimic the acl-manager functionality
    acl_dir = GET_CHAR(&parser->config, "acl_dir");
    amxc_string_setf(&path, "%s/merged", acl_dir);
    mkdir(amxc_string_get(&path, 0), 0700);

    amxc_string_setf(&path, "%s/%s/", acl_dir, role);
    root_acls = amxa_parse_files(amxc_string_get(&path, 0));
    assert_non_null(root_acls);

    amxc_string_setf(&path, "%s/merged/%s.json", acl_dir, role);
    assert_int_equal(amxa_merge_rules(root_acls, amxc_string_get(&path, 0)), 0);

    // Init acl file to use in each of the real test functions
    amxc_string_init(&acl_file, 0);
    amxc_string_setf(&acl_file, "%s/merged/%s.json", acl_dir, role);

    amxc_string_clean(&path);
    amxc_var_delete(&root_acls);
}

static void acl_clean(void) {
    amxc_string_t path;

    amxc_string_init(&path, 0);

    remove(amxc_string_get(&acl_file, 0));

    amxc_string_setf(&path, "%s/merged", acl_dir);
    rmdir(amxc_string_get(&path, 0));

    amxc_string_clean(&acl_file);
    amxc_string_clean(&path);
}

int test_amxa_get_inst_setup(UNUSED void** state) {
    test_amxa_setup(NULL);
    acl_initialize();
    return 0;
}

int test_amxa_get_inst_teardown(UNUSED void** state) {
    acl_clean();
    return test_amxa_teardown(NULL);
}

void test_cannot_get_client_insts(UNUSED void** state) {
    amxb_bus_ctx_t* ctx = test_amxa_get_bus_ctx();
    const char* object = "DHCPv4.Client.";
    amxc_var_t ret;

    amxc_var_init(&ret);
    assert_int_equal(amxb_get_instances(ctx, object, INT32_MAX, &ret, 5), 0);
    amxc_var_dump(&ret, STDOUT_FILENO);

    amxc_var_set_type(&ret, AMXC_VAR_ID_NULL);
    assert_int_equal(amxa_get_instances(ctx, object, amxc_string_get(&acl_file, 0), INT32_MAX, &ret, 5),
                     amxd_status_permission_denied);
    amxc_var_dump(&ret, STDOUT_FILENO);
    assert_int_equal(amxc_var_type_of(&ret), AMXC_VAR_ID_NULL);

    amxc_var_clean(&ret);
}

void test_can_get_server_pool_inst_partially(UNUSED void** state) {
    amxb_bus_ctx_t* ctx = test_amxa_get_bus_ctx();
    const char* object = "DHCPv4.Server.Pool.";
    amxc_var_t ret;

    amxc_var_init(&ret);
    assert_int_equal(amxb_get_instances(ctx, object, INT32_MAX, &ret, 5), 0);
    amxc_var_dump(&ret, STDOUT_FILENO);

    amxc_var_set_type(&ret, AMXC_VAR_ID_NULL);
    assert_int_equal(amxa_get_instances(ctx, object, amxc_string_get(&acl_file, 0), INT32_MAX, &ret, 5), 0);
    amxc_var_dump(&ret, STDOUT_FILENO);

    assert_true(test_verify_data(&ret, "0.'DHCPv4.Server.Pool.1.'.Alias", "cpe-LAN"));
    assert_true(test_verify_data(&ret, "0.'DHCPv4.Server.Pool.1.Client.1.'.Alias", "cpe-client-1"));
    assert_true(test_verify_data(&ret, "0.'DHCPv4.Server.Pool.1.Client.1.IPv4Address.2.'.IPAddress", "0.0.0.0"));
    assert_null(GETP_ARG(&ret, "0.'DHCPv4.Server.Pool.1.Client.1.IPv4Address.1.'"));
    assert_null(GETP_ARG(&ret, "0.'DHCPv4.Server.Pool.1.StaticAddress.1.'"));

    amxc_var_clean(&ret);
}

void test_cannot_get_keys(UNUSED void** state) {
    amxb_bus_ctx_t* ctx = test_amxa_get_bus_ctx();
    const char* object = "DHCPv4.Relay.Forwarding.";
    amxc_var_t ret;

    amxc_var_init(&ret);
    assert_int_equal(amxb_get_instances(ctx, object, INT32_MAX, &ret, 5), 0);
    amxc_var_dump(&ret, STDOUT_FILENO);

    amxc_var_set_type(&ret, AMXC_VAR_ID_NULL);
    assert_int_equal(amxa_get_instances(ctx, object, amxc_string_get(&acl_file, 0), INT32_MAX, &ret, 5), 0);
    amxc_var_dump(&ret, STDOUT_FILENO);

    assert_non_null(GETP_ARG(&ret, "0.'DHCPv4.Relay.Forwarding.1.'"));
    assert_non_null(GETP_ARG(&ret, "0.'DHCPv4.Relay.Forwarding.2.'"));
    assert_null(GETP_ARG(&ret, "0.'DHCPv4.Relay.Forwarding.1.'.Alias"));
    assert_null(GETP_ARG(&ret, "0.'DHCPv4.Relay.Forwarding.2.'.Alias"));

    amxc_var_clean(&ret);
}

void test_amxa_get_instances_invalid_input(UNUSED void** state) {
    amxb_bus_ctx_t* ctx = test_amxa_get_bus_ctx();
    const char* object = "DHCPv4.Client.";
    amxc_var_t ret;

    amxc_var_init(&ret);

    assert_int_equal(amxa_get_instances(NULL, NULL, NULL, 0, NULL, 0), amxd_status_not_supported);
    assert_int_equal(amxa_get_instances(ctx, NULL, NULL, 0, NULL, 0), amxd_status_not_supported);
    assert_int_equal(amxa_get_instances(ctx, "", NULL, 0, NULL, 0), amxd_status_not_supported);
    assert_int_equal(amxa_get_instances(ctx, object, NULL, 0, NULL, 0), amxd_status_not_supported);
    assert_int_equal(amxa_get_instances(ctx, object, "", 0, NULL, 0), amxd_status_not_supported);
    assert_int_equal(amxa_get_instances(ctx, object, amxc_string_get(&acl_file, 0), 0, NULL, 0), amxd_status_not_supported);
    assert_int_equal(amxa_get_instances(ctx, object, "not-a-file", 0, &ret, 0), amxd_status_permission_denied);

    amxc_var_clean(&ret);
}

void test_amxa_get_instances_not_supported(UNUSED void** state) {
    amxb_bus_ctx_t* ctx = test_amxa_get_bus_ctx();
    const char* object = "DHCPv6.Client.*.";
    amxc_var_t ret;

    amxc_var_init(&ret);
    assert_int_equal(amxa_get_instances(ctx, object, amxc_string_get(&acl_file, 0), 0, &ret, 0), amxd_status_not_supported);
    amxc_var_clean(&ret);
}

void test_amxa_get_instances_not_a_template(UNUSED void** state) {
    amxb_bus_ctx_t* ctx = test_amxa_get_bus_ctx();
    const char* object = "DHCPv4.Server.";
    amxc_var_t ret;

    amxc_var_init(&ret);
    assert_int_equal(amxa_get_instances(ctx, object, amxc_string_get(&acl_file, 0), 0, &ret, 0), amxd_status_not_a_template);
    amxc_var_clean(&ret);
}

void test_amxa_get_instances_not_instantiated(UNUSED void** state) {
    amxb_bus_ctx_t* ctx = test_amxa_get_bus_ctx();
    const char* object = "DHCPv4.Server.Pool.10.Client.";
    amxc_var_t ret;

    amxc_var_init(&ret);
    assert_int_equal(amxa_get_instances(ctx, object, amxc_string_get(&acl_file, 0), 0, &ret, 0), amxd_status_not_instantiated);
    amxc_var_clean(&ret);
}
