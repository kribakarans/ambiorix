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
#include <amxd/amxd_path.h>
#include <amxb/amxb.h>
#include <amxo/amxo.h>

#include "amxa/amxa_permissions.h"
#include "amxa/amxa_validator.h"
#include "amxa/amxa_resolver.h"

#include "amxa_merger_priv.h"
#include "test_amxa_validate.h"
#include "dummy_backend.h"

#define UNUSED __attribute__((unused))

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

static amxc_var_t* var_low_level_permissions(void) {
    amxc_var_t* var = NULL;
    amxc_var_t* dhcpv4 = NULL;

    amxc_var_new(&var);
    amxc_var_set_type(var, AMXC_VAR_ID_HTABLE);
    dhcpv4 = amxc_var_add_key(amxc_htable_t, var, "DHCPv4", NULL);
    amxc_var_add_key(cstring_t, dhcpv4, "\%ACL", "0xFFF");

    return var;
}

static amxc_var_t* var_no_permissions(void) {
    amxc_var_t* var = NULL;
    amxc_var_t* dhcpv4 = NULL;

    amxc_var_new(&var);
    amxc_var_set_type(var, AMXC_VAR_ID_HTABLE);
    dhcpv4 = amxc_var_add_key(amxc_htable_t, var, "DHCPv4", NULL);
    amxc_var_add_key(cstring_t, dhcpv4, "\%ACL", "0x0");

    return var;
}

static amxc_var_t* var_with_device_prefix(void) {
    amxc_var_t* var = NULL;
    amxc_var_t* device = NULL;
    amxc_var_t* dhcpv4 = NULL;

    amxc_var_new(&var);
    amxc_var_set_type(var, AMXC_VAR_ID_HTABLE);
    device = amxc_var_add_key(amxc_htable_t, var, "Device", NULL);
    dhcpv4 = amxc_var_add_key(amxc_htable_t, device, "DHCPv4", NULL);
    amxc_var_add_key(cstring_t, dhcpv4, "\%ACL", "0xFFF");

    return var;
}

int test_amxa_validate_setup(UNUSED void** state) {
    amxd_object_t* root_obj = NULL;
    int retval = 0;

    assert_int_equal(amxd_dm_init(&dm), amxd_status_ok);
    assert_int_equal(amxo_parser_init(&parser), 0);

    assert_int_equal(test_register_dummy_be(), 0);
    root_obj = amxd_dm_get_root(&dm);
    assert_non_null(root_obj);

    retval = amxo_parser_parse_file(&parser, odl_root, root_obj);
    assert_int_equal(retval, 0);
    handle_events();

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

void test_amxa_get_filters_invalid(UNUSED void** state) {
    amxc_var_t* access_rights = var_low_level_permissions();
    amxc_llist_t filters;

    amxc_llist_init(&filters);
    assert_int_equal(amxa_get_filters(NULL, 0, NULL, NULL), -1);
    assert_int_equal(amxa_get_filters(access_rights, 0, NULL, NULL), -1);
    assert_int_equal(amxa_get_filters(access_rights, 0, &filters, NULL), -1);
    assert_int_equal(amxa_get_filters(access_rights, 0, &filters, ""), -1);
    assert_int_equal(amxa_get_filters(access_rights, 0, &filters, "foo"), -1);

    amxc_llist_clean(&filters, amxc_string_list_it_free);
    amxc_var_delete(&access_rights);
}

void test_validate_parent_acl(UNUSED void** state) {
    amxc_var_t* access_rights = var_low_level_permissions();
    const char* requested_path = "DHCPv4.Server.";
    amxc_llist_t filters;

    amxc_llist_init(&filters);
    assert_int_equal(amxa_get_filters(access_rights, AMXA_PERMIT_GET, &filters, requested_path), 0);
    assert_int_equal(amxc_llist_size(&filters), 0);

    amxc_llist_clean(&filters, amxc_string_list_it_free);
    amxc_var_delete(&access_rights);
}

void test_permissions_not_found(UNUSED void** state) {
    amxc_var_t* access_rights = var_low_level_permissions();
    const char* requested_path = "DHCPv6.";
    amxc_string_t* returned_filter = NULL;
    amxc_llist_t filters;

    amxc_llist_init(&filters);
    assert_int_equal(amxa_get_filters(access_rights, AMXA_PERMIT_GET, &filters, requested_path), 0);
    assert_int_equal(amxc_llist_size(&filters), 1);

    returned_filter = amxc_llist_it_get_data(amxc_llist_get_first(&filters), amxc_string_t, it);
    assert_non_null(returned_filter);
    assert_string_equal(amxc_string_get(returned_filter, 0), "DHCPv6");

    amxc_llist_clean(&filters, amxc_string_list_it_free);
    amxc_var_delete(&access_rights);
}

void test_parent_returns_filters(UNUSED void** state) {
    amxc_var_t* access_rights = var_no_permissions();
    const char* requested_path = "DHCPv4.Server.";
    amxc_string_t* returned_filter = NULL;
    amxc_llist_t filters;

    amxc_llist_init(&filters);
    assert_int_equal(amxa_get_filters(access_rights, AMXA_PERMIT_GET, &filters, requested_path), 0);
    assert_int_equal(amxc_llist_size(&filters), 1);

    returned_filter = amxc_llist_it_get_data(amxc_llist_get_first(&filters), amxc_string_t, it);
    assert_non_null(returned_filter);
    assert_string_equal(amxc_string_get(returned_filter, 0), "DHCPv4");

    amxc_llist_clean(&filters, amxc_string_list_it_free);
    amxc_var_delete(&access_rights);
}

void test_param_permissions_from_parent(UNUSED void** state) {
    amxc_var_t* access_rights = var_low_level_permissions();
    const char* requested_path = "DHCPv4.ClientNumberOfEntries";
    amxc_llist_t filters;

    amxc_llist_init(&filters);
    assert_int_equal(amxa_get_filters(access_rights, AMXA_PERMIT_GET, &filters, requested_path), 0);
    assert_int_equal(amxc_llist_size(&filters), 0);

    amxc_llist_clean(&filters, amxc_string_list_it_free);
    amxc_var_delete(&access_rights);
}

void test_recursive_parent_lookup(UNUSED void** state) {
    amxc_var_t* access_rights = var_low_level_permissions();
    const char* requested_path = "DHCPv4.Server.Pool.1.Client.1.";
    amxc_llist_t filters;

    amxc_llist_init(&filters);
    assert_int_equal(amxa_get_filters(access_rights, AMXA_PERMIT_GET, &filters, requested_path), 0);
    assert_int_equal(amxc_llist_size(&filters), 0);

    amxc_llist_clean(&filters, amxc_string_list_it_free);
    amxc_var_delete(&access_rights);
}

void test_current_level_all_permissions(UNUSED void** state) {
    amxc_var_t* access_rights = var_low_level_permissions();
    const char* requested_path = "DHCPv4.";
    amxc_llist_t filters;

    amxc_llist_init(&filters);
    assert_int_equal(amxa_get_filters(access_rights, AMXA_PERMIT_GET, &filters, requested_path), 0);
    assert_int_equal(amxc_llist_size(&filters), 0);

    amxc_llist_clean(&filters, amxc_string_list_it_free);
    amxc_var_delete(&access_rights);
}

void test_current_level_no_permissions(UNUSED void** state) {
    amxc_var_t* access_rights = var_no_permissions();
    const char* requested_path = "DHCPv4.";
    amxc_string_t* returned_filter = NULL;
    amxc_llist_t filters;

    amxc_llist_init(&filters);
    assert_int_equal(amxa_get_filters(access_rights, AMXA_PERMIT_GET, &filters, requested_path), 0);
    assert_int_equal(amxc_llist_size(&filters), 1);

    returned_filter = amxc_llist_it_get_data(amxc_llist_get_first(&filters), amxc_string_t, it);
    assert_non_null(returned_filter);
    assert_string_equal(amxc_string_get(returned_filter, 0), "DHCPv4");

    amxc_llist_clean(&filters, amxc_string_list_it_free);
    amxc_var_delete(&access_rights);
}

void test_parent_and_child_acls(UNUSED void** state) {
    amxc_var_t* access_rights = NULL;
    amxc_var_t* dhcpv4 = NULL;
    amxc_var_t* server = NULL;
    amxc_var_t* pool = NULL;
    amxc_var_t* instance = NULL;
    const char* requested_path = "DHCPv4.Server.";
    amxc_string_t* returned_filter = NULL;
    amxc_llist_t filters;

    amxc_var_new(&access_rights);
    amxc_var_set_type(access_rights, AMXC_VAR_ID_HTABLE);
    dhcpv4 = amxc_var_add_key(amxc_htable_t, access_rights, "DHCPv4", NULL);
    amxc_var_add_key(cstring_t, dhcpv4, "\%ACL", "0xFFF");
    server = amxc_var_add_key(amxc_htable_t, dhcpv4, "Server", NULL);
    pool = amxc_var_add_key(amxc_htable_t, server, "Pool", NULL);
    instance = amxc_var_add_key(amxc_htable_t, pool, "1", NULL);
    amxc_var_add_key(cstring_t, instance, "\%ACL", "0x0");
    amxc_var_dump(access_rights, STDOUT_FILENO);

    amxc_llist_init(&filters);
    assert_int_equal(amxa_get_filters(access_rights, AMXA_PERMIT_GET, &filters, requested_path), 0);
    assert_int_equal(amxc_llist_size(&filters), 1);

    returned_filter = amxc_llist_it_get_data(amxc_llist_get_first(&filters), amxc_string_t, it);
    assert_non_null(returned_filter);
    assert_string_equal(amxc_string_get(returned_filter, 0), "DHCPv4.Server.Pool.1");

    amxc_llist_clean(&filters, amxc_string_list_it_free);
    amxc_var_delete(&access_rights);
}

void test_missing_parent_rule_no_permissions(UNUSED void** state) {
    amxc_var_t* access_rights = NULL;
    amxc_var_t* dhcpv4 = NULL;
    amxc_var_t* server = NULL;
    amxc_var_t* pool = NULL;
    amxc_var_t* instance = NULL;
    const char* requested_path = "DHCPv4.Server.";
    amxc_string_t* returned_filter = NULL;
    amxc_llist_t filters;

    amxc_var_new(&access_rights);
    amxc_var_set_type(access_rights, AMXC_VAR_ID_HTABLE);
    dhcpv4 = amxc_var_add_key(amxc_htable_t, access_rights, "DHCPv4", NULL);
    server = amxc_var_add_key(amxc_htable_t, dhcpv4, "Server", NULL);
    pool = amxc_var_add_key(amxc_htable_t, server, "Pool", NULL);
    instance = amxc_var_add_key(amxc_htable_t, pool, "1", NULL);
    amxc_var_add_key(cstring_t, instance, "\%ACL", "0x0");
    amxc_var_dump(access_rights, STDOUT_FILENO);

    amxc_llist_init(&filters);
    assert_int_equal(amxa_get_filters(access_rights, AMXA_PERMIT_GET, &filters, requested_path), 0);
    assert_int_equal(amxc_llist_size(&filters), 1);

    returned_filter = amxc_llist_it_get_data(amxc_llist_get_first(&filters), amxc_string_t, it);
    assert_non_null(returned_filter);
    assert_string_equal(amxc_string_get(returned_filter, 0), "DHCPv4.Server");

    amxc_llist_clean(&filters, amxc_string_list_it_free);
    amxc_var_delete(&access_rights);
}

void test_access_allowed_if_acl_contains_device_prefix(UNUSED void** state) {
    amxc_var_t* access_rights = var_with_device_prefix();
    const char* requested_path = "Device.DHCPv4.";
    amxc_llist_t filters;

    amxc_llist_init(&filters);
    assert_int_equal(amxa_get_filters(access_rights, AMXA_PERMIT_ALL, &filters, requested_path), 0);
    assert_int_equal(amxc_llist_size(&filters), 0);

    amxc_llist_clean(&filters, amxc_string_list_it_free);
    amxc_var_delete(&access_rights);
}

void test_is_search_path_allowed(UNUSED void** state) {
    amxc_var_t* data = data_from_json("../examples/11_merged.json");

    assert_false(amxa_is_search_path_allowed(NULL, NULL, NULL));
    assert_false(amxa_is_search_path_allowed(bus_ctx, NULL, NULL));
    assert_false(amxa_is_search_path_allowed(bus_ctx, data, NULL));
    assert_false(amxa_is_search_path_allowed(bus_ctx, data, ""));
    assert_false(amxa_is_search_path_allowed(bus_ctx, data, "abc.def.*."));

    assert_true(amxa_is_search_path_allowed(bus_ctx, data, "DHCPv4."));
    assert_false(amxa_is_search_path_allowed(bus_ctx, data, "DHCPv4.Client.[Enable == True].")); // Would be true if instance existed
    assert_false(amxa_is_search_path_allowed(bus_ctx, data, "DHCPv4.Server.Pool.[Enable == True]."));

    amxc_var_delete(&data);
}

void test_is_search_path_allowed_when_instances_exist(UNUSED void** state) {
    amxd_object_t* root_obj = amxd_dm_get_root(&dm);
    amxc_var_t* data = data_from_json("../examples/11_merged.json");

    assert_non_null(root_obj);

    assert_int_equal(amxo_parser_parse_file(&parser, odl_defaults, root_obj), 0);
    handle_events();

    assert_true(amxa_is_search_path_allowed(bus_ctx, data, "DHCPv4."));
    assert_true(amxa_is_search_path_allowed(bus_ctx, data, "DHCPv4.Client.[Enable == True]."));
    assert_true(amxa_is_search_path_allowed(bus_ctx, data, "DHCPv4.Client.[Enable == False]."));
    assert_false(amxa_is_search_path_allowed(bus_ctx, data, "DHCPv4.Server.Pool.[Enable == True]."));
    assert_false(amxa_is_search_path_allowed(bus_ctx, data, "DHCPv4.Server.Pool.[Enable == False]."));

    amxc_var_delete(&data);
}

void test_is_search_path_with_param_allowed(UNUSED void** state) {
    amxd_object_t* root_obj = amxd_dm_get_root(&dm);
    amxc_var_t* data = data_from_json("../examples/11_merged.json");

    assert_non_null(root_obj);

    assert_true(amxa_is_search_path_allowed(bus_ctx, data, "DHCPv4.Client.[Enable == True].Alias"));
    assert_true(amxa_is_search_path_allowed(bus_ctx, data, "DHCPv4.Client.[Enable == False].Alias"));
    assert_false(amxa_is_search_path_allowed(bus_ctx, data, "DHCPv4.Server.Pool.[Enable == True].Alias"));
    assert_false(amxa_is_search_path_allowed(bus_ctx, data, "DHCPv4.Server.Pool.[Enable == False].Alias"));

    amxc_var_delete(&data);
}

void test_is_nested_search_path_allowed(UNUSED void** state) {
    amxc_var_t* data = data_from_json("../examples/11_merged.json");

    assert_true(amxa_is_search_path_allowed(bus_ctx, data, "DHCPv4.Client.[Enable == True]."));
    assert_true(amxa_is_search_path_allowed(bus_ctx, data, "DHCPv4.Client.[Enable == False]."));
    assert_false(amxa_is_search_path_allowed(bus_ctx, data, "DHCPv4.Client.[Enable == True].SentOption.[Enable == True].")); // Would be true if instance existed
    assert_false(amxa_is_search_path_allowed(bus_ctx, data, "DHCPv4.Client.[Enable == False].SentOption.[Enable == True]."));

    amxc_var_delete(&data);
}
