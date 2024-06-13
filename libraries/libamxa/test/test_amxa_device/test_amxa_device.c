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
#include <amxc/amxc_macros.h>
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
#include "test_amxa_device.h"
#include "dummy_backend.h"

const uint32_t AMXA_PERMIT_PARAM_ALL = AMXA_PERMIT_GET | AMXA_PERMIT_SET | AMXA_PERMIT_SUBS_VAL_CHANGE;
const uint32_t AMXA_PERMIT_OBJ_ALL = AMXA_PERMIT_OBJ_INFO | AMXA_PERMIT_ADD | AMXA_PERMIT_SUBS_OBJ_ADD;
const uint32_t AMXA_PERMIT_INST_ALL = AMXA_PERMIT_GET_INST | AMXA_PERMIT_DEL | AMXA_PERMIT_SUBS_OBJ_DEL;
const uint32_t AMXA_PERMIT_CMD_EVT_ALL = AMXA_PERMIT_CMD_INFO | AMXA_PERMIT_OPER | AMXA_PERMIT_SUBS_EVT_OPER_COMP;

static amxd_dm_t dm;
static amxb_bus_ctx_t* bus_ctx = NULL;
static amxo_parser_t parser;
static const char* odl_root = "./tr181-device_definition.odl";
static const char* odl_defaults = "./tr181-device_defaults.odl";

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


void test_merge_device_rules(UNUSED void** state) {
    amxc_var_t* data = NULL;
    uint32_t permissions = 0;

    data = data_from_json("device_rules.json");

    assert_int_equal(amxa_merge_rules(data, "device_rules_merged.json"), 0);

    amxc_var_delete(&data);

    // Read merged file and verify outputs
    data = data_from_json("device_rules_merged.json");

    permissions = GETP_UINT32(data, "Device.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_GET | AMXA_PERMIT_OBJ_ALL | AMXA_PERMIT_INST_ALL |
                     AMXA_PERMIT_SUBS_EVT_OPER_COMP | AMXA_PERMIT_OPER | AMXA_PERMIT_CMD_INFO);

    permissions = GETP_UINT32(data, "Device.InterfaceStack.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_GET | AMXA_PERMIT_OBJ_INFO | AMXA_PERMIT_SUBS_OBJ_ADD |
                     AMXA_PERMIT_GET_INST | AMXA_PERMIT_CMD_INFO);

    amxc_var_delete(&data);
}

void test_device_get_allowed(UNUSED void** state) {
    amxc_var_t* access_rights = data_from_json("device_rules_merged.json");
    const char* requested_path = "Device.";
    amxc_llist_t filters;

    amxc_llist_init(&filters);

    assert_non_null(access_rights);

    assert_int_equal(amxa_get_filters(access_rights, AMXA_PERMIT_GET, &filters, requested_path), 0);
    assert_true(amxa_is_get_allowed(&filters, requested_path));

    amxc_var_delete(&access_rights);
    amxc_llist_clean(&filters, NULL);
}

void test_device_set_not_allowed(UNUSED void** state) {
    amxc_var_t* access_rights = data_from_json("device_rules_merged.json");
    const char* obj_path = "Device.";
    const char* param = "RootDataModelVersion";

    assert_non_null(access_rights);

    assert_false(amxa_is_set_allowed(bus_ctx, access_rights, obj_path, param));

    amxc_var_delete(&access_rights);
}

void test_device_add_not_allowed(UNUSED void** state) {
    amxc_var_t* access_rights = data_from_json("device_rules_merged.json");
    const char* obj_path = "Device.InterfaceStack.";

    assert_non_null(access_rights);

    assert_false(amxa_is_add_allowed(bus_ctx, access_rights, obj_path));

    amxc_var_delete(&access_rights);
}

void test_device_del_not_allowed(UNUSED void** state) {
    amxc_var_t* access_rights = data_from_json("device_rules_merged.json");
    const char* obj_path = "Device.InterfaceStack.1.";

    assert_non_null(access_rights);

    assert_false(amxa_is_del_allowed(bus_ctx, access_rights, obj_path));

    amxc_var_delete(&access_rights);
}

void test_device_subscribe_allowed(UNUSED void** state) {
    amxc_var_t* access_rights = data_from_json("device_rules_merged.json");
    const char* path = "Device.";

    assert_false(amxa_is_subs_allowed(access_rights, path, AMXA_PERMIT_SUBS_VAL_CHANGE));
    assert_true(amxa_is_subs_allowed(access_rights, path, AMXA_PERMIT_SUBS_OBJ_ADD));
    assert_true(amxa_is_subs_allowed(access_rights, path, AMXA_PERMIT_SUBS_OBJ_DEL));
    assert_true(amxa_is_subs_allowed(access_rights, path, AMXA_PERMIT_SUBS_EVT_OPER_COMP));

    path = "Device.InterfaceStack.1.";
    assert_false(amxa_is_subs_allowed(access_rights, path, AMXA_PERMIT_SUBS_VAL_CHANGE));
    assert_true(amxa_is_subs_allowed(access_rights, path, AMXA_PERMIT_SUBS_OBJ_ADD));
    assert_false(amxa_is_subs_allowed(access_rights, path, AMXA_PERMIT_SUBS_OBJ_DEL));
    assert_false(amxa_is_subs_allowed(access_rights, path, AMXA_PERMIT_SUBS_EVT_OPER_COMP));

    amxc_var_delete(&access_rights);
}

void test_device_operate_allowed(UNUSED void** state) {
    amxc_var_t* access_rights = data_from_json("device_rules_merged.json");
    const char* obj_path = "Device.";
    const char* method = "FactoryReset";

    assert_non_null(access_rights);

    assert_true(amxa_is_operate_allowed(bus_ctx, access_rights, obj_path, method));

    amxc_var_delete(&access_rights);
}

void test_can_resolve_device_search_path(UNUSED void** state) {
    amxc_var_t* acls = data_from_json("search_path_rules.json");

    assert_int_equal(amxa_merge_rules(acls, "search_path_rules_merged.json"), 0);
    amxc_var_delete(&acls);

    acls = data_from_json("search_path_rules_merged.json");
    amxc_var_dump(acls, STDOUT_FILENO);

    assert_non_null(GETP_ARG(acls, "Device"));
    assert_non_null(GETP_ARG(acls, "Device.Node.[Type == 'AntiTheft']"));
    assert_non_null(GETP_ARG(acls, "Device.Phonebook.Contact.[FirstName == 'James']"));

    amxa_resolve_search_paths(bus_ctx, acls, "Device.");
    amxc_var_dump(acls, STDOUT_FILENO);
    assert_non_null(GETP_ARG(acls, "Device"));
    assert_null(GETP_ARG(acls, "Device.Node.[Type == 'AntiTheft']"));
    assert_null(GETP_ARG(acls, "Device.Phonebook.Contact.[FirstName == 'James']"));
    assert_non_null(GETP_ARG(acls, "Device.Node.2"));
    assert_non_null(GETP_ARG(acls, "Device.Phonebook.Contact.2"));

    amxc_var_delete(&acls);
}

// Test that you can resolve search paths when the fixed path provided to amxa_resolve_search_paths
// is longer than the paths of the ACLs
void test_can_resolve_device_phonebook_search_path(UNUSED void** state) {
    amxc_var_t* acls = data_from_json("search_path_rules.json");

    assert_int_equal(amxa_merge_rules(acls, "search_path_rules_merged.json"), 0);
    amxc_var_delete(&acls);

    acls = data_from_json("search_path_rules_merged.json");
    amxc_var_dump(acls, STDOUT_FILENO);

    assert_non_null(GETP_ARG(acls, "Device"));
    assert_non_null(GETP_ARG(acls, "Device.Node.[Type == 'AntiTheft']"));
    assert_non_null(GETP_ARG(acls, "Device.Phonebook.Contact.[FirstName == 'James']"));

    amxa_resolve_search_paths(bus_ctx, acls, "Device.Phonebook.Contact.1.");
    amxc_var_dump(acls, STDOUT_FILENO);
    assert_non_null(GETP_ARG(acls, "Device"));
    assert_non_null(GETP_ARG(acls, "Device.Node.[Type == 'AntiTheft']"));
    assert_null(GETP_ARG(acls, "Device.Node.2"));
    assert_null(GETP_ARG(acls, "Device.Phonebook.Contact.[FirstName == 'James']"));
    assert_non_null(GETP_ARG(acls, "Device.Phonebook.Contact.2"));

    amxc_var_delete(&acls);
}
