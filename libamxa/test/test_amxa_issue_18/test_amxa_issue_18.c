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

#include "amxa/amxa_merger.h"
#include "amxa/amxa_permissions.h"
#include "amxa/amxa_validator.h"
#include "amxa/amxa_resolver.h"

#include "amxa_merger_priv.h"
#include "test_amxa_issue_18.h"
#include "dummy_backend.h"

#define UNUSED __attribute__((unused))

static amxd_dm_t dm;
static amxb_bus_ctx_t* bus_ctx = NULL;
static amxo_parser_t parser;
static const char* odl = "test_dm.odl";

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

int test_amxa_issue_18_setup(UNUSED void** state) {
    amxc_var_t* data = NULL;
    amxd_object_t* root_obj = NULL;

    assert_int_equal(amxd_dm_init(&dm), amxd_status_ok);
    assert_int_equal(amxo_parser_init(&parser), 0);

    assert_int_equal(test_register_dummy_be(), 0);
    root_obj = amxd_dm_get_root(&dm);
    assert_non_null(root_obj);

    assert_int_equal(amxo_parser_parse_file(&parser, odl, root_obj), 0);

    assert_int_equal(amxb_connect(&bus_ctx, "dummy:/tmp/dummy.sock"), 0);
    amxo_connection_add(&parser, 101, connection_read, "dummy:/tmp/dummy.sock", AMXO_BUS, bus_ctx);
    amxb_register(bus_ctx, &dm);

    data = data_from_json("agent007.json");
    assert_int_equal(amxa_merge_rules(data, "set_rules_merged_agent007.json"), 0);
    amxc_var_delete(&data);

    data = data_from_json("guest.json");
    assert_int_equal(amxa_merge_rules(data, "set_rules_merged_guest.json"), 0);
    amxc_var_delete(&data);

    data = data_from_json("admin.json");
    assert_int_equal(amxa_merge_rules(data, "set_rules_merged_admin.json"), 0);
    amxc_var_delete(&data);

    data = data_from_json("device.json");
    assert_int_equal(amxa_merge_rules(data, "device_merged.json"), 0);
    amxc_var_delete(&data);

    handle_events();

    return 0;
}

int test_amxa_issue_18_teardown(UNUSED void** state) {
    amxb_free(&bus_ctx);

    amxo_parser_clean(&parser);
    amxd_dm_clean(&dm);

    test_unregister_dummy_be();
    return 0;
}

void test_resolve_multi_instance_agent007(UNUSED void** state) {
    amxc_var_t* acls = NULL;
    const char* path = "Greeter.History.";

    acls = data_from_json("set_rules_merged_agent007.json");
    assert_non_null(acls);

    assert_int_equal(amxa_resolve_search_paths(bus_ctx, acls, path), 0);
    amxc_var_dump(acls, STDOUT_FILENO);

    assert_non_null(GETP_ARG(acls, "Greeter.History.1"));
    assert_non_null(GETP_ARG(acls, "Greeter.History.2"));
    assert_non_null(GETP_ARG(acls, "Greeter.History.3"));

    amxc_var_delete(&acls);
}

void test_resolve_multi_instance_guest(UNUSED void** state) {
    amxc_var_t* acls = NULL;
    const char* path = "Greeter.History.";

    acls = data_from_json("set_rules_merged_guest.json");
    assert_non_null(acls);

    assert_int_equal(amxa_resolve_search_paths(bus_ctx, acls, path), 0);
    amxc_var_dump(acls, STDOUT_FILENO);

    assert_non_null(GETP_ARG(acls, "Greeter.History"));
    assert_null(amxc_var_get_path(acls, "Greeter.History.1", AMXC_VAR_FLAG_DEFAULT | AMXC_VAR_FLAG_NO_INDEX));
    assert_null(amxc_var_get_path(acls, "Greeter.History.2", AMXC_VAR_FLAG_DEFAULT | AMXC_VAR_FLAG_NO_INDEX));
    assert_null(amxc_var_get_path(acls, "Greeter.History.3", AMXC_VAR_FLAG_DEFAULT | AMXC_VAR_FLAG_NO_INDEX));

    amxc_var_delete(&acls);
}

void test_resolve_multi_instance_admin(UNUSED void** state) {
    amxc_var_t* acls = NULL;
    const char* path = "Greeter.History.";

    acls = data_from_json("set_rules_merged_admin.json");
    assert_non_null(acls);

    assert_int_equal(amxa_resolve_search_paths(bus_ctx, acls, path), 0);
    amxc_var_dump(acls, STDOUT_FILENO);

    assert_non_null(GETP_ARG(acls, "Greeter."));
    assert_null(GETP_ARG(acls, "Greeter.History"));
    assert_null(amxc_var_get_path(acls, "Greeter.History.1", AMXC_VAR_FLAG_DEFAULT | AMXC_VAR_FLAG_NO_INDEX));
    assert_null(amxc_var_get_path(acls, "Greeter.History.2", AMXC_VAR_FLAG_DEFAULT | AMXC_VAR_FLAG_NO_INDEX));
    assert_null(amxc_var_get_path(acls, "Greeter.History.3", AMXC_VAR_FLAG_DEFAULT | AMXC_VAR_FLAG_NO_INDEX));

    amxc_var_delete(&acls);
}

void test_resolve_instance_agent007(UNUSED void** state) {
    amxc_var_t* acls = NULL;
    const char* path = "Greeter.History.1.";

    acls = data_from_json("set_rules_merged_agent007.json");
    assert_non_null(acls);

    assert_int_equal(amxa_resolve_search_paths(bus_ctx, acls, path), 0);
    amxc_var_dump(acls, STDOUT_FILENO);

    assert_non_null(GETP_ARG(acls, "Greeter.History.1"));
    assert_non_null(GETP_ARG(acls, "Greeter.History.2"));
    assert_non_null(GETP_ARG(acls, "Greeter.History.3"));

    amxc_var_delete(&acls);
}

void test_resolve_instance_guest(UNUSED void** state) {
    amxc_var_t* acls = NULL;
    const char* path = "Greeter.History.1.";

    acls = data_from_json("set_rules_merged_guest.json");
    assert_non_null(acls);

    assert_int_equal(amxa_resolve_search_paths(bus_ctx, acls, path), 0);
    amxc_var_dump(acls, STDOUT_FILENO);

    assert_non_null(GETP_ARG(acls, "Greeter.History"));
    assert_null(amxc_var_get_path(acls, "Greeter.History.1", AMXC_VAR_FLAG_DEFAULT | AMXC_VAR_FLAG_NO_INDEX));
    assert_null(amxc_var_get_path(acls, "Greeter.History.2", AMXC_VAR_FLAG_DEFAULT | AMXC_VAR_FLAG_NO_INDEX));
    assert_null(amxc_var_get_path(acls, "Greeter.History.3", AMXC_VAR_FLAG_DEFAULT | AMXC_VAR_FLAG_NO_INDEX));

    amxc_var_delete(&acls);
}

void test_resolve_instance_admin(UNUSED void** state) {
    amxc_var_t* acls = NULL;
    const char* path = "Greeter.History.1.";

    acls = data_from_json("set_rules_merged_admin.json");
    assert_non_null(acls);

    assert_int_equal(amxa_resolve_search_paths(bus_ctx, acls, path), 0);
    amxc_var_dump(acls, STDOUT_FILENO);

    assert_non_null(GETP_ARG(acls, "Greeter"));
    assert_null(GETP_ARG(acls, "Greeter.History"));
    assert_null(amxc_var_get_path(acls, "Greeter.History.1", AMXC_VAR_FLAG_DEFAULT | AMXC_VAR_FLAG_NO_INDEX));
    assert_null(amxc_var_get_path(acls, "Greeter.History.2", AMXC_VAR_FLAG_DEFAULT | AMXC_VAR_FLAG_NO_INDEX));
    assert_null(amxc_var_get_path(acls, "Greeter.History.3", AMXC_VAR_FLAG_DEFAULT | AMXC_VAR_FLAG_NO_INDEX));

    amxc_var_delete(&acls);
}

void test_resolve_root_agent007(UNUSED void** state) {
    amxc_var_t* acls = NULL;
    const char* path = "Greeter.";

    acls = data_from_json("set_rules_merged_agent007.json");
    assert_non_null(acls);

    assert_int_equal(amxa_resolve_search_paths(bus_ctx, acls, path), 0);
    amxc_var_dump(acls, STDOUT_FILENO);

    assert_non_null(GETP_ARG(acls, "Greeter.History.1"));
    assert_non_null(GETP_ARG(acls, "Greeter.History.2"));
    assert_non_null(GETP_ARG(acls, "Greeter.History.3"));

    amxc_var_delete(&acls);
}

void test_resolve_root_guest(UNUSED void** state) {
    amxc_var_t* acls = NULL;
    const char* path = "Greeter.";

    acls = data_from_json("set_rules_merged_guest.json");
    assert_non_null(acls);

    assert_int_equal(amxa_resolve_search_paths(bus_ctx, acls, path), 0);
    amxc_var_dump(acls, STDOUT_FILENO);

    assert_non_null(GETP_ARG(acls, "Greeter.History"));
    assert_null(amxc_var_get_path(acls, "Greeter.History.1", AMXC_VAR_FLAG_DEFAULT | AMXC_VAR_FLAG_NO_INDEX));
    assert_null(amxc_var_get_path(acls, "Greeter.History.2", AMXC_VAR_FLAG_DEFAULT | AMXC_VAR_FLAG_NO_INDEX));
    assert_null(amxc_var_get_path(acls, "Greeter.History.3", AMXC_VAR_FLAG_DEFAULT | AMXC_VAR_FLAG_NO_INDEX));

    amxc_var_delete(&acls);
}

void test_resolve_root_admin(UNUSED void** state) {
    amxc_var_t* acls = NULL;
    const char* path = "Greeter.";

    acls = data_from_json("set_rules_merged_admin.json");
    assert_non_null(acls);

    assert_int_equal(amxa_resolve_search_paths(bus_ctx, acls, path), 0);
    amxc_var_dump(acls, STDOUT_FILENO);

    assert_non_null(GETP_ARG(acls, "Greeter"));
    assert_null(GETP_ARG(acls, "Greeter.History"));
    assert_null(amxc_var_get_path(acls, "Greeter.History.1", AMXC_VAR_FLAG_DEFAULT | AMXC_VAR_FLAG_NO_INDEX));
    assert_null(amxc_var_get_path(acls, "Greeter.History.2", AMXC_VAR_FLAG_DEFAULT | AMXC_VAR_FLAG_NO_INDEX));
    assert_null(amxc_var_get_path(acls, "Greeter.History.3", AMXC_VAR_FLAG_DEFAULT | AMXC_VAR_FLAG_NO_INDEX));

    amxc_var_delete(&acls);
}

void test_resolve_path_noacls(UNUSED void** state) {
    amxc_var_t* acls = NULL;
    const char* path = "Object.With.NoAcls.";

    acls = data_from_json("set_rules_merged_agent007.json");
    assert_non_null(acls);

    assert_int_equal(amxa_resolve_search_paths(bus_ctx, acls, path), 0);
    amxc_var_dump(acls, STDOUT_FILENO);

    assert_non_null(GETP_ARG(acls, "Greeter"));
    assert_non_null(GETP_ARG(acls, "Greeter.History"));
    assert_non_null(GETP_ARG(acls, "Greeter.History.[From != 'agent007']"));
    assert_non_null(GETP_ARG(acls, "Greeter.History.[From == 'agent007']"));
    assert_null(amxc_var_get_path(acls, "Greeter.History.1", AMXC_VAR_FLAG_DEFAULT | AMXC_VAR_FLAG_NO_INDEX));
    assert_null(amxc_var_get_path(acls, "Greeter.History.2", AMXC_VAR_FLAG_DEFAULT | AMXC_VAR_FLAG_NO_INDEX));
    assert_null(amxc_var_get_path(acls, "Greeter.History.3", AMXC_VAR_FLAG_DEFAULT | AMXC_VAR_FLAG_NO_INDEX));

    amxc_var_delete(&acls);
}

void test_filter_multi_instance(UNUSED void** state) {
    amxc_var_t* acls = NULL;
    amxc_llist_t filters;
    const char* path = "Greeter.History.";

    amxc_llist_init(&filters);

    acls = data_from_json("set_rules_merged_agent007.json");
    assert_non_null(acls);

    assert_int_equal(amxa_resolve_search_paths(bus_ctx, acls, path), 0);
    amxa_get_filters(acls, AMXA_PERMIT_GET, &filters, path);
    assert_int_equal(amxc_llist_size(&filters), 2);

    amxc_var_delete(&acls);
    amxc_llist_clean(&filters, amxc_string_list_it_free);
}

void test_filter_instance(UNUSED void** state) {
    amxc_var_t* acls = NULL;
    amxc_llist_t filters;
    const char* path = "Greeter.History.1.";

    amxc_llist_init(&filters);

    acls = data_from_json("set_rules_merged_agent007.json");
    assert_non_null(acls);

    assert_int_equal(amxa_resolve_search_paths(bus_ctx, acls, path), 0);
    amxa_get_filters(acls, AMXA_PERMIT_GET, &filters, path);
    assert_int_equal(amxc_llist_size(&filters), 1);

    amxc_llist_for_each(it, &filters) {
        amxc_string_t* str = amxc_container_of(it, amxc_string_t, it);
        assert_string_equal("Greeter.History.1", amxc_string_get(str, 0));
    }

    amxc_var_delete(&acls);
    amxc_llist_clean(&filters, amxc_string_list_it_free);
}

void test_filter_path_noacls(UNUSED void** state) {
    amxc_var_t* acls = NULL;
    amxc_llist_t filters;
    const char* path = "Object.With.NoAcls.";

    amxc_llist_init(&filters);

    acls = data_from_json("set_rules_merged_agent007.json");
    assert_non_null(acls);

    assert_int_equal(amxa_resolve_search_paths(bus_ctx, acls, path), 0);
    amxa_get_filters(acls, AMXA_PERMIT_GET, &filters, path);
    assert_int_equal(amxc_llist_size(&filters), 1);

    amxc_llist_for_each(it, &filters) {
        amxc_string_t* str = amxc_container_of(it, amxc_string_t, it);
        assert_string_equal("Object.With.NoAcls", amxc_string_get(str, 0));
    }
    amxc_var_delete(&acls);
    amxc_llist_clean(&filters, amxc_string_list_it_free);
}

void test_resolve_device_path_skipped(UNUSED void** state) {
    amxc_var_t* acls = NULL;
    const char* path = "Device.Firewall.";
    const amxc_htable_t* acl_table = NULL;

    acls = data_from_json("device_merged.json");
    assert_non_null(acls);
    amxc_var_dump(acls, STDOUT_FILENO);

    assert_int_equal(amxa_resolve_search_paths(bus_ctx, acls, path), 0);
    amxc_var_dump(acls, STDOUT_FILENO);
    acl_table = amxc_var_constcast(amxc_htable_t, acls);
    assert_false(amxc_htable_is_empty(acl_table));
    assert_non_null(GETP_ARG(acls, "Device.IP.Interface.[Enable==True]"));
    assert_non_null(GETP_ARG(acls, "Device.WiFi.Radio.[Enable==True]"));

    amxc_var_delete(&acls);
}

void test_resolve_device_path_not_skipped(UNUSED void** state) {
    amxc_var_t* acls = NULL;
    const char* path = "Device.";
    const amxc_htable_t* acl_table = NULL;

    acls = data_from_json("device_merged.json");
    assert_non_null(acls);
    amxc_var_dump(acls, STDOUT_FILENO);

    assert_int_equal(amxa_resolve_search_paths(bus_ctx, acls, path), 0);
    amxc_var_dump(acls, STDOUT_FILENO);
    acl_table = amxc_var_constcast(amxc_htable_t, acls);
    assert_false(amxc_htable_is_empty(acl_table));

    assert_null(amxc_var_get_path(acls, "Device.IP.Interface.1", AMXC_VAR_FLAG_DEFAULT | AMXC_VAR_FLAG_NO_INDEX));
    assert_null(amxc_var_get_path(acls, "Device.IP.Interface.1", AMXC_VAR_FLAG_DEFAULT | AMXC_VAR_FLAG_NO_INDEX));
    assert_non_null(amxc_var_get_path(acls, "Device.IP.Interface.2", AMXC_VAR_FLAG_DEFAULT | AMXC_VAR_FLAG_NO_INDEX));
    assert_non_null(amxc_var_get_path(acls, "Device.WiFi.Radio.2", AMXC_VAR_FLAG_DEFAULT | AMXC_VAR_FLAG_NO_INDEX));

    amxc_var_delete(&acls);
}
