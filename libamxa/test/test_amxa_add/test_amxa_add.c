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

#include <amxc/amxc.h>
#include <amxp/amxp.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_dm.h>
#include <amxd/amxd_transaction.h>
#include <amxd/amxd_path.h>
#include <amxb/amxb.h>
#include <amxo/amxo.h>

#include "amxa/amxa_merger.h"
#include "amxa/amxa_permissions.h"
#include "amxa/amxa_validator.h"
#include "amxa/amxa_resolver.h"

#include "amxa_merger_priv.h"
#include "test_amxa_add.h"
#include "dummy_backend.h"

#define UNUSED __attribute__((unused))

const uint32_t AMXA_PERMIT_PARAM_ALL = AMXA_PERMIT_GET | AMXA_PERMIT_SET | AMXA_PERMIT_SUBS_VAL_CHANGE;
const uint32_t AMXA_PERMIT_OBJ_ALL = AMXA_PERMIT_OBJ_INFO | AMXA_PERMIT_ADD | AMXA_PERMIT_SUBS_OBJ_ADD;
const uint32_t AMXA_PERMIT_INST_ALL = AMXA_PERMIT_GET_INST | AMXA_PERMIT_DEL | AMXA_PERMIT_SUBS_OBJ_DEL;
const uint32_t AMXA_PERMIT_CMD_EVT_ALL = AMXA_PERMIT_CMD_INFO | AMXA_PERMIT_OPER | AMXA_PERMIT_SUBS_EVT_OPER_COMP;

static amxd_dm_t dm;
static amxb_bus_ctx_t* bus_ctx = NULL;
static amxo_parser_t parser;
static const char* odl_root = "../reference-dm/dhcpv4_root.odl";
static const char* odl_defaults = "dhcpv4_defaults.odl";

static void handle_events(void) {
    printf("Handling events ");
    while(amxp_signal_read() == 0) {
        printf(".");
    }
    printf("\n");
}

static void connection_read(UNUSED int fd, UNUSED void* priv) {
    // Do nothing
}

int test_amxa_validate_setup(UNUSED void** state) {
    amxd_object_t* root_obj = NULL;

    assert_int_equal(amxd_dm_init(&dm), amxd_status_ok);
    assert_int_equal(amxo_parser_init(&parser), 0);

    assert_int_equal(test_register_dummy_be(), 0);
    root_obj = amxd_dm_get_root(&dm);
    assert_non_null(root_obj);

    assert_int_equal(amxo_parser_parse_file(&parser, odl_root, root_obj), 0);
    assert_int_equal(amxo_parser_parse_file(&parser, odl_defaults, root_obj), 0);

    assert_int_equal(amxb_connect(&bus_ctx, "dummy:/tmp/dummy.sock"), 0);
    amxo_connection_add(&parser, 101, connection_read, "dummy:/tmp/dummy.sock", AMXO_BUS, bus_ctx);
    amxb_register(bus_ctx, &dm);

    handle_events();
    return 0;
}

int test_amxa_validate_teardown(UNUSED void** state) {
    amxb_free(&bus_ctx);

    amxo_parser_clean(&parser);
    amxd_dm_clean(&dm);

    test_unregister_dummy_be();
    return 0;
}


void test_merge_add(UNUSED void** state) {
    amxc_var_t* data = NULL;
    uint32_t permissions = 0;

    data = data_from_json("add_rules.json");

    assert_int_equal(amxa_merge_rules(data, "add_rules_merged.json"), 0);

    amxc_var_delete(&data);

    // Read merged file and verify outputs
    data = data_from_json("add_rules_merged.json");

    permissions = GETP_UINT32(data, "DHCPv4.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_ALL);

    permissions = GETP_UINT32(data, "DHCPv4.Server.Pool.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_ADD);

    permissions = GETP_UINT32(data, "DHCPv4.Server.Pool.*.Client.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_NONE);

    amxc_var_delete(&data);
}

void test_resolve_add(UNUSED void** state) {
    amxc_var_t* acls = NULL;
    const char* root_path = "DHCPv4";
    uint32_t permissions = 0;
    uint32_t order = 0;

    acls = data_from_json("add_rules_merged.json");
    assert_non_null(acls);

    assert_int_equal(amxa_resolve_search_paths(bus_ctx, acls, root_path), 0);
    amxc_var_dump(acls, STDOUT_FILENO);

    permissions = GETP_UINT32(acls, "DHCPv4.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_ALL);
    order = GETP_UINT32(acls, "DHCPv4.\%Order");
    assert_int_equal(order, 1);

    permissions = GETP_UINT32(acls, "DHCPv4.Server.Pool.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_ADD);
    order = GETP_UINT32(acls, "DHCPv4.Server.Pool.\%Order");
    assert_int_equal(order, 2);

    permissions = GETP_UINT32(acls, "DHCPv4.Server.Pool.10.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_NONE);
    order = GETP_UINT32(acls, "DHCPv4.Server.Pool.10.\%Order");
    assert_int_equal(order, 3);

    permissions = GETP_UINT32(acls, "DHCPv4.Server.Pool.1.Client.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_NONE);
    order = GETP_UINT32(acls, "DHCPv4.Server.Pool.1.Client.\%Order");
    assert_int_equal(order, 4);

    permissions = GETP_UINT32(acls, "DHCPv4.Client.1.DummyOne.DummyTwo.DummyInst.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_ADD);
    order = GETP_UINT32(acls, "DHCPv4.Client.1.DummyOne.DummyTwo.DummyInst.\%Order");
    assert_int_equal(order, 5);

    amxc_var_delete(&acls);
}

void test_add_is_not_allowed_with_invalid_input(UNUSED void** state) {
    amxc_var_t access_rights;

    assert_false(amxa_is_add_allowed(NULL, NULL, NULL));
    assert_false(amxa_is_add_allowed(bus_ctx, NULL, NULL));
    assert_false(amxa_is_add_allowed(bus_ctx, &access_rights, NULL));
}

void test_add_is_allowed(UNUSED void** state) {
    amxc_var_t* access_rights = data_from_json("add_rules_merged.json");
    const char* root_path = "DHCPv4";
    const char* requested_path = "DHCPv4.Server.Pool.";

    assert_non_null(access_rights);

    assert_int_equal(amxa_resolve_search_paths(bus_ctx, access_rights, root_path), 0);

    assert_true(amxa_is_add_allowed(bus_ctx, access_rights, requested_path));

    amxc_var_delete(&access_rights);
}

void test_add_search_path_is_allowed(UNUSED void** state) {
    amxc_var_t* access_rights = data_from_json("add_rules_merged.json");
    const char* root_path = "DHCPv4";
    const char* requested_path = "DHCPv4.Server.Pool.[Alias=='test-pool'].StaticAddress.";

    assert_non_null(access_rights);

    assert_int_equal(amxa_resolve_search_paths(bus_ctx, access_rights, root_path), 0);

    assert_true(amxa_is_add_allowed(bus_ctx, access_rights, requested_path));

    amxc_var_delete(&access_rights);
}

void test_add_is_allowed_from_parent(UNUSED void** state) {
    amxc_var_t* access_rights = data_from_json("add_rules_merged.json");
    const char* root_path = "DHCPv4";
    const char* requested_path = "DHCPv4.Client.";

    assert_non_null(access_rights);

    assert_int_equal(amxa_resolve_search_paths(bus_ctx, access_rights, root_path), 0);

    assert_true(amxa_is_add_allowed(bus_ctx, access_rights, requested_path));

    amxc_var_delete(&access_rights);
}

void test_add_is_not_allowed(UNUSED void** state) {
    amxc_var_t* access_rights = data_from_json("add_rules_merged.json");
    const char* root_path = "DHCPv4";
    const char* requested_path = "DHCPv4.Server.Pool.1.Client.";

    assert_non_null(access_rights);

    assert_int_equal(amxa_resolve_search_paths(bus_ctx, access_rights, root_path), 0);

    assert_false(amxa_is_add_allowed(bus_ctx, access_rights, requested_path));

    amxc_var_delete(&access_rights);
}

void test_add_is_not_allowed_when_parent_is_missing(UNUSED void** state) {
    amxc_var_t* access_rights = data_from_json("add_rules_merged.json");
    const char* root_path = "DHCPv4";
    const char* requested_path = "DHCPv4.Server.Pool.2.Client.";

    assert_non_null(access_rights);

    assert_int_equal(amxa_resolve_search_paths(bus_ctx, access_rights, root_path), 0);

    assert_false(amxa_is_add_allowed(bus_ctx, access_rights, requested_path));

    amxc_var_delete(&access_rights);
}

void test_add_allowed_on_parent_not_on_child(UNUSED void** state) {
    amxc_var_t* access_rights = data_from_json("add_rules_merged.json");
    const char* root_path = "DHCPv4";
    const char* requested_path = "DHCPv4.Server.Pool.";
    amxd_trans_t trans;

    amxd_trans_init(&trans);
    amxd_trans_select_pathf(&trans, "%s", requested_path);
    amxd_trans_add_inst(&trans, 10, NULL);
    assert_int_equal(amxd_trans_apply(&trans, &dm), 0);

    assert_non_null(access_rights);

    assert_int_equal(amxa_resolve_search_paths(bus_ctx, access_rights, root_path), 0);

    assert_true(amxa_is_add_allowed(bus_ctx, access_rights, requested_path));

    amxd_trans_clean(&trans);
    amxc_var_delete(&access_rights);
}
