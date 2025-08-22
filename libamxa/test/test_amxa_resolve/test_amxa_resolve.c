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
#include <amxd/amxd_dm.h>
#include <amxd/amxd_path.h>
#include <amxd/amxd_object.h>
#include <amxb/amxb.h>
#include <amxo/amxo.h>

#include "amxa/amxa_resolver.h"

#include "test_amxa_resolve.h"
#include "amxa/amxa_permissions.h"
#include "amxa_merger_priv.h"
#include "dummy_backend.h"

#define UNUSED __attribute__((unused))

const uint32_t AMXA_PERMIT_PARAM_ALL = AMXA_PERMIT_GET | AMXA_PERMIT_SET | AMXA_PERMIT_SUBS_VAL_CHANGE;
const uint32_t AMXA_PERMIT_OBJ_ALL = AMXA_PERMIT_OBJ_INFO | AMXA_PERMIT_ADD | AMXA_PERMIT_SUBS_OBJ_ADD;
const uint32_t AMXA_PERMIT_INST_ALL = AMXA_PERMIT_GET | AMXA_PERMIT_GET_INST | AMXA_PERMIT_DEL | AMXA_PERMIT_SUBS_OBJ_DEL;
const uint32_t AMXA_PERMIT_CMD_EVT_ALL = AMXA_PERMIT_CMD_INFO | AMXA_PERMIT_OPER | AMXA_PERMIT_SUBS_EVT_OPER_COMP;

static amxd_dm_t dm;
static amxb_bus_ctx_t* bus_ctx = NULL;
static amxo_parser_t parser;
static const char* odl_root = "../reference-dm/dhcpv4_root.odl";
static const char* odl_device_root = "../reference-dm/device_dhcpv6.odl";
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

int test_amxa_resolve_setup(UNUSED void** state) {
    amxd_object_t* root_obj = NULL;
    int retval = 0;

    assert_int_equal(amxd_dm_init(&dm), amxd_status_ok);
    assert_int_equal(amxo_parser_init(&parser), 0);

    assert_int_equal(test_register_dummy_be(), 0);
    root_obj = amxd_dm_get_root(&dm);
    assert_non_null(root_obj);

    retval = amxo_parser_parse_file(&parser, odl_root, root_obj);
    assert_int_equal(retval, 0);
    retval = amxo_parser_parse_file(&parser, odl_device_root, root_obj);
    assert_int_equal(retval, 0);
    retval = amxo_parser_parse_file(&parser, odl_defaults, root_obj);
    assert_int_equal(retval, 0);
    handle_events();

    assert_int_equal(amxb_connect(&bus_ctx, "dummy:/tmp/dummy.sock"), 0);
    amxo_connection_add(&parser, 101, connection_read, "dummy:/tmp/dummy.sock", AMXO_BUS, bus_ctx);
    amxb_register(bus_ctx, &dm);

    handle_events();
    return 0;
}

int test_amxa_resolve_teardown(UNUSED void** state) {
    amxb_free(&bus_ctx);

    amxo_parser_clean(&parser);
    amxd_dm_clean(&dm);

    test_unregister_dummy_be();
    return 0;
}

void test_resolve_search_paths_invalid(UNUSED void** state) {
    amxc_var_t acls;
    amxc_var_init(&acls);

    assert_int_equal(amxa_resolve_search_paths(NULL, NULL, NULL), -1);
    assert_int_equal(amxa_resolve_search_paths(bus_ctx, NULL, NULL), -1);
    assert_int_equal(amxa_resolve_search_paths(bus_ctx, &acls, NULL), -1);
    amxc_var_set_type(&acls, AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxa_resolve_search_paths(bus_ctx, &acls, NULL), -1);
    assert_int_equal(amxa_resolve_search_paths(bus_ctx, &acls, ""), -1);

    // If the provided path cannot be found in the ACLs, there won't be anything that needs to be
    // resolved for this path, so the function can return 0
    assert_int_equal(amxa_resolve_search_paths(bus_ctx, &acls, "Greeter.History."), 0);

    amxc_var_clean(&acls);
}

// Simple parameter search path
void test_resolve_search_paths_2(UNUSED void** state) {
    amxc_var_t* acls = NULL;
    const char* root_path = "DHCPv4";
    uint32_t permissions = 0;
    uint32_t order = 0;

    acls = data_from_json("../examples/02_merged.json");
    assert_non_null(acls);

    assert_int_equal(amxa_resolve_search_paths(bus_ctx, acls, root_path), 0);
    amxc_var_dump(acls, STDOUT_FILENO);

    permissions = GETP_UINT32(acls, "DHCPv4.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_ALL);

    order = GETP_UINT32(acls, "DHCPv4.\%Order");
    assert_int_equal(order, 1);

    permissions = GETP_UINT32(acls, "DHCPv4.Server.Pool.1.Chaddr.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_NONE);

    order = GETP_UINT32(acls, "DHCPv4.Server.Pool.1.Chaddr.\%Order");
    assert_int_equal(order, 100);

    amxc_var_delete(&acls);
}

// Complex triple layered search path
void test_resolve_search_paths_9(UNUSED void** state) {
    amxc_var_t* acls = NULL;
    const char* root_path = "DHCPv4";
    uint32_t permissions = 0;
    uint32_t order = 0;

    acls = data_from_json("../examples/09_merged.json");
    assert_non_null(acls);

    assert_int_equal(amxa_resolve_search_paths(bus_ctx, acls, root_path), 0);
    amxc_var_dump(acls, STDOUT_FILENO);

    permissions = GETP_UINT32(acls, "DHCPv4.Client.1.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_PARAM_ALL);

    order = GETP_UINT32(acls, "DHCPv4.Client.1.\%Order");
    assert_int_equal(order, 2);

    permissions = GETP_UINT32(acls, "DHCPv4.Server.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_ALL);

    order = GETP_UINT32(acls, "DHCPv4.Server.\%Order");
    assert_int_equal(order, 3);

    permissions = GETP_UINT32(acls, "DHCPv4.Server.Pool.1.Client.1.IPv4Address.1.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_NONE);

    order = GETP_UINT32(acls, "DHCPv4.Server.Pool.1.Client.1.IPv4Address.1.\%Order");
    assert_int_equal(order, 4);

    amxc_var_delete(&acls);
}

// Fewer permissions per level
void test_resolve_search_paths_5(UNUSED void** state) {
    amxc_var_t* acls = NULL;
    const char* root_path = "DHCPv4";
    uint32_t permissions = 0;
    uint32_t order = 0;

    acls = data_from_json("../examples/05_merged.json");
    assert_non_null(acls);

    assert_int_equal(amxa_resolve_search_paths(bus_ctx, acls, root_path), 0);
    amxc_var_dump(acls, STDOUT_FILENO);

    permissions = GETP_UINT32(acls, "DHCPv4.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_ALL);

    order = GETP_UINT32(acls, "DHCPv4.\%Order");
    assert_int_equal(order, 1);

    permissions = GETP_UINT32(acls, "DHCPv4.Server.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_PARAM_ALL | AMXA_PERMIT_OBJ_ALL | AMXA_PERMIT_INST_ALL);

    order = GETP_UINT32(acls, "DHCPv4.Server.\%Order");
    assert_int_equal(order, 2);

    permissions = GETP_UINT32(acls, "DHCPv4.Server.Pool.1.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_PARAM_ALL | AMXA_PERMIT_OBJ_ALL);

    order = GETP_UINT32(acls, "DHCPv4.Server.Pool.1.\%Order");
    assert_int_equal(order, 3);

    permissions = GETP_UINT32(acls, "DHCPv4.Server.Pool.1.Client.1.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_PARAM_ALL);

    order = GETP_UINT32(acls, "DHCPv4.Server.Pool.1.Client.1.\%Order");
    assert_int_equal(order, 4);

    permissions = GETP_UINT32(acls, "DHCPv4.Server.Pool.1.Client.1.IPv4Address.1.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_NONE);

    order = GETP_UINT32(acls, "DHCPv4.Server.Pool.1.Client.1.IPv4Address.1.\%Order");
    assert_int_equal(order, 5);

    permissions = GETP_UINT32(acls, "DHCPv4.Server.Pool.1.Client.1.IPv4Address.2.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_NONE);

    order = GETP_UINT32(acls, "DHCPv4.Server.Pool.1.Client.1.IPv4Address.2.\%Order");
    assert_int_equal(order, 5);

    amxc_var_delete(&acls);
}

// Override some values with the search path based on the order
void test_search_path_override_some(UNUSED void** state) {
    amxc_var_t* acls = NULL;
    const char* root_path = "DHCPv4";
    uint32_t permissions = 0;
    uint32_t order = 0;
    amxc_var_t* client = NULL;
    amxc_var_t* new_rule = NULL;

    acls = data_from_json("../examples/06_merged.json");
    assert_non_null(acls);

    client = GETP_ARG(acls, "DHCPv4.Client");
    assert_non_null(client);
    new_rule = amxc_var_add_key(amxc_htable_t, client, "*", NULL);
    amxc_var_add_key(cstring_t, new_rule, "\%ACL", "0x467");
    amxc_var_add_key(uint32_t, new_rule, "\%Order", 18);

    assert_int_equal(amxa_resolve_search_paths(bus_ctx, acls, root_path), 0);
    amxc_var_dump(acls, STDOUT_FILENO);

    permissions = GETP_UINT32(acls, "DHCPv4.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_ALL);

    order = GETP_UINT32(acls, "DHCPv4.\%Order");
    assert_int_equal(order, 1);

    permissions = GETP_UINT32(acls, "DHCPv4.Client.1.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_PARAM_ALL | AMXA_PERMIT_OBJ_ALL);

    order = GETP_UINT32(acls, "DHCPv4.Client.1.\%Order");
    assert_int_equal(order, 18);

    permissions = GETP_UINT32(acls, "DHCPv4.Client.2.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_PARAM_ALL | AMXA_PERMIT_OBJ_ALL);

    order = GETP_UINT32(acls, "DHCPv4.Client.2.\%Order");
    assert_int_equal(order, 18);

    permissions = GETP_UINT32(acls, "DHCPv4.Client.3.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_ALL);

    order = GETP_UINT32(acls, "DHCPv4.Client.3.\%Order");
    assert_int_equal(order, 20);

    amxc_var_delete(&acls);
}

void test_search_path_resolves_to_empty_list(UNUSED void** state) {
    amxc_var_t* acls = NULL;
    amxc_var_t* dhcpv4 = NULL;
    amxc_var_t* server = NULL;
    amxc_var_t* pool = NULL;
    amxc_var_t* search_path = NULL;
    amxc_var_t* param = NULL;
    const char* root_path = "DHCPv4";

    amxc_var_new(&acls);
    amxc_var_set_type(acls, AMXC_VAR_ID_HTABLE);
    dhcpv4 = amxc_var_add_key(amxc_htable_t, acls, "DHCPv4", NULL);
    server = amxc_var_add_key(amxc_htable_t, dhcpv4, "Server", NULL);
    pool = amxc_var_add_key(amxc_htable_t, server, "Pool", NULL);
    search_path = amxc_var_add_key(amxc_htable_t, pool, "[Alias == \"foo\"]", NULL);
    param = amxc_var_add_key(amxc_htable_t, search_path, "Chaddr", NULL);
    amxc_var_add_key(cstring_t, param, "\%ACL", "0x0");
    amxc_var_add_key(uint32_t, param, "\%Order", 1);

    assert_int_equal(amxa_resolve_search_paths(bus_ctx, acls, root_path), 0);
    amxc_var_dump(acls, STDOUT_FILENO);
    assert_null(GET_ARG(acls, "DHCPv4"));

    amxc_var_delete(&acls);
}

void test_search_path_resolution_with_device_prefix(UNUSED void** state) {
    amxc_var_t* acls = NULL;
    amxc_var_t* device = NULL;
    amxc_var_t* dhcpv6 = NULL;
    amxc_var_t* client = NULL;
    amxc_var_t* search_path = NULL;
    const char* root_path = "Device.DHCPv6";
    uint32_t permissions = 0;
    uint32_t order = 0;

    amxc_var_new(&acls);
    amxc_var_set_type(acls, AMXC_VAR_ID_HTABLE);
    device = amxc_var_add_key(amxc_htable_t, acls, "Device", NULL);
    dhcpv6 = amxc_var_add_key(amxc_htable_t, device, "DHCPv6", NULL);
    client = amxc_var_add_key(amxc_htable_t, dhcpv6, "Client", NULL);
    search_path = amxc_var_add_key(amxc_htable_t, client, "[Enable==True]", NULL);
    amxc_var_add_key(cstring_t, search_path, "\%ACL", "0xFFF");
    amxc_var_add_key(uint32_t, search_path, "\%Order", 1);

    assert_int_equal(amxa_resolve_search_paths(bus_ctx, acls, root_path), 0);
    amxc_var_dump(acls, STDOUT_FILENO);

    permissions = GETP_UINT32(acls, "Device.DHCPv6.Client.2.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_ALL);

    order = GETP_UINT32(acls, "Device.DHCPv6.Client.2.\%Order");
    assert_int_equal(order, 1);

    amxc_var_delete(&acls);
}

void test_amxa_resolve_not_empty(UNUSED void** state) {
    amxc_var_t acls;
    amxc_var_t* device;

    amxc_var_init(&acls);
    amxc_var_set_type(&acls, AMXC_VAR_ID_HTABLE);
    device = amxc_var_add_key(amxc_htable_t, &acls, "Device", NULL);
    amxc_var_add_key(uint32_t, device, "\%Order", 1);
    amxc_var_add_key(cstring_t, device, "\%ACL", "0xFFF");

    amxa_resolve_search_paths(bus_ctx, &acls, "Device.MQTT.");
    amxc_var_dump(&acls, STDOUT_FILENO);
    assert_false(amxc_htable_is_empty(amxc_var_constcast(amxc_htable_t, &acls)));

    amxc_var_clean(&acls);
}
