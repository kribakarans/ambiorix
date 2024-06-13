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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <yajl/yajl_gen.h>

#include <amxc/amxc.h>
#include <amxp/amxp.h>
#include <amxj/amxj_variant.h>

#include <amxd/amxd_dm.h>
#include <amxd/amxd_object.h>

#include <amxo/amxo.h>
#include <amxa/amxa_merger.h>
#include <amxa/amxa_permissions.h>

#include "aclm.h"
#include "aclm_merge.h"
#include "aclm_utils.h"
#include "dm_role_events.h"
#include "dm_role_actions.h"

#include "test_aclm_merge.h"

static amxo_parser_t parser;
static amxd_dm_t dm;
static const char* odl_config = "./aclm-test.odl";
static const char* odl_definition = "../../odl/acl-manager_definition.odl";

static void handle_events(void) {
    printf("Handling events ");
    while(amxp_signal_read() == 0) {
        printf(".");
    }
    printf("\n");
}

int test_aclm_setup(UNUSED void** state) {
    int retval = 0;
    amxd_object_t* root_obj = NULL;

    amxd_dm_init(&dm);

    assert_int_equal(amxo_parser_init(&parser), 0);

    root_obj = amxd_dm_get_root(&dm);
    assert_non_null(root_obj);

    amxo_resolver_ftab_add(&parser, "aclm_role_added", AMXO_FUNC(_aclm_role_added));
    amxo_resolver_ftab_add(&parser, "aclm_role_removed", AMXO_FUNC(_aclm_role_removed));
    amxo_resolver_ftab_add(&parser, "role_instance_is_valid", AMXO_FUNC(_role_instance_is_valid));

    retval = amxo_parser_parse_file(&parser, odl_config, root_obj);
    assert_int_equal(retval, 0);

    retval = amxo_parser_parse_file(&parser, odl_definition, root_obj);
    assert_int_equal(retval, 0);

    return 0;
}

int test_aclm_teardown(UNUSED void** state) {
    assert_int_equal(_aclm_main(1, &dm, &parser), 0);
    amxo_parser_clean(&parser);
    amxd_dm_clean(&dm);

    return 0;
}

void test_can_merge_existing_acls(UNUSED void** state) {
    amxc_var_t* result = NULL;
    const char* acl_dir = NULL;
    uint32_t permissions = 0;

    assert_int_equal(_aclm_main(0, &dm, &parser), 0);

    amxc_var_dump(&parser.config, STDOUT_FILENO);

    acl_dir = GETP_CHAR(&parser.config, "acl_dir");
    assert_string_equal(acl_dir, "../acldir");

    result = amxa_parse_files("../acldir/merged/root.json");
    assert_non_null(result);

    permissions = GETP_UINT32(result, "DHCPv4.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_ALL);

    permissions = GETP_UINT32(result, "MQTT.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_ALL);

    amxc_var_delete(&result);

    result = amxa_parse_files("../acldir/merged/untrusted.json");
    assert_non_null(result);

    permissions = GETP_UINT32(result, "DHCPv4.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_ALL ^ AMXA_PERMIT_SUBS_OBJ_ADD);

    permissions = GETP_UINT32(result, "WiFi.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_ALL);

    amxc_var_delete(&result);
}

void test_can_add_acl_rule(UNUSED void** state) {
    amxc_var_t new_rule;
    amxc_var_t* wifi = NULL;
    amxc_var_t* result = NULL;
    amxo_connection_t* connection = NULL;
    uint32_t permissions = 0;

    amxc_var_init(&new_rule);
    amxc_var_set_type(&new_rule, AMXC_VAR_ID_HTABLE);
    wifi = amxc_var_add_key(amxc_htable_t, &new_rule, "WiFi.", NULL);
    amxc_var_add_key(uint32_t, wifi, "Order", 5);
    amxc_var_add_key(cstring_t, wifi, "Param", "rwxn");
    amxc_var_add_key(cstring_t, wifi, "Obj", "rwxn");
    amxc_var_add_key(cstring_t, wifi, "InstantiatedObj", "rwxn");
    amxc_var_add_key(cstring_t, wifi, "CommandEvent", "rwxn");

    aclm_write_json_var(&new_rule, "../acldir/root/wifi.json");

    connection = amxo_connection_get_first(aclm_get_parser(), AMXO_CUSTOM);
    assert_non_null(connection);
    connection->reader(connection->fd, NULL);

    result = amxa_parse_files("../acldir/merged/root.json");
    assert_non_null(result);

    permissions = GETP_UINT32(result, "WiFi.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_ALL);

    amxc_var_delete(&result);
    amxc_var_clean(&new_rule);
}

void test_can_move_acl_rule(UNUSED void** state) {
    amxo_connection_t* connection = NULL;
    amxc_var_t* result = NULL;

    assert_int_equal(rename("../acldir/root/tr181-mqtt.json", "../acldir/untrusted/tr181-mqtt.json"), 0);

    connection = amxo_connection_get_first(aclm_get_parser(), AMXO_CUSTOM);
    assert_non_null(connection);
    connection->reader(connection->fd, NULL);

    result = amxa_parse_files("../acldir/merged/root.json");
    assert_non_null(result);
    assert_null(GET_ARG(result, "MQTT"));
    amxc_var_delete(&result);

    result = amxa_parse_files("../acldir/merged/untrusted.json");
    assert_non_null(result);
    assert_non_null(GET_ARG(result, "MQTT"));
    amxc_var_delete(&result);

    assert_int_equal(rename("../acldir/untrusted/tr181-mqtt.json", "../acldir/root/tr181-mqtt.json"), 0);
    connection->reader(connection->fd, NULL);

    result = amxa_parse_files("../acldir/merged/root.json");
    assert_non_null(result);
    assert_non_null(GET_ARG(result, "MQTT"));
    amxc_var_delete(&result);

    result = amxa_parse_files("../acldir/merged/untrusted.json");
    assert_non_null(result);
    assert_null(GET_ARG(result, "MQTT"));
    amxc_var_delete(&result);
}

void test_can_remove_acl_rule(UNUSED void** state) {
    amxo_connection_t* connection = NULL;
    amxc_var_t* result = NULL;

    assert_int_equal(remove("../acldir/root/wifi.json"), 0);

    connection = amxo_connection_get_first(aclm_get_parser(), AMXO_CUSTOM);
    assert_non_null(connection);
    connection->reader(connection->fd, NULL);

    result = amxa_parse_files("../acldir/merged/root.json");
    assert_non_null(result);
    assert_null(GET_ARG(result, "WiFi"));

    amxc_var_delete(&result);
}

void test_can_add_acl_dir_with_rules(UNUSED void** state) {
    amxc_var_t new_rule;
    amxc_var_t* wifi = NULL;
    amxc_var_t* result = NULL;
    amxo_connection_t* connection = NULL;
    uint32_t permissions = 0;
    struct stat sb;

    assert_int_equal(mkdir("../acldir/new", 0700), 0);

    connection = amxo_connection_get_first(aclm_get_parser(), AMXO_CUSTOM);
    assert_non_null(connection);
    connection->reader(connection->fd, NULL);

    amxc_var_init(&new_rule);
    amxc_var_set_type(&new_rule, AMXC_VAR_ID_HTABLE);
    wifi = amxc_var_add_key(amxc_htable_t, &new_rule, "WiFi.", NULL);
    amxc_var_add_key(uint32_t, wifi, "Order", 1);
    amxc_var_add_key(cstring_t, wifi, "Param", "rwxn");
    amxc_var_add_key(cstring_t, wifi, "Obj", "rwxn");
    amxc_var_add_key(cstring_t, wifi, "InstantiatedObj", "rwxn");
    amxc_var_add_key(cstring_t, wifi, "CommandEvent", "rwxn");

    aclm_write_json_var(&new_rule, "../acldir/new/wifi.json");

    connection->reader(connection->fd, NULL);
    assert_int_equal(stat("../acldir/merged/new.json", &sb), 0);

    result = amxa_parse_files("../acldir/merged/new.json");
    assert_non_null(result);

    permissions = GETP_UINT32(result, "WiFi.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_ALL);

    amxc_var_delete(&result);
    amxc_var_clean(&new_rule);


    amxc_var_clean(&new_rule);
}

void test_can_rename_acl_role(UNUSED void** state) {
    amxo_connection_t* connection = NULL;
    amxc_var_t* result = NULL;
    struct stat sb;

    assert_int_equal(rename("../acldir/new", "../acldir/newer"), 0);

    connection = amxo_connection_get_first(aclm_get_parser(), AMXO_CUSTOM);
    assert_non_null(connection);
    connection->reader(connection->fd, NULL);

    handle_events();

    assert_int_not_equal(stat("../acldir/merged/new.json", &sb), 0);
    assert_int_equal(stat("../acldir/merged/newer.json", &sb), 0);

    result = amxa_parse_files("../acldir/merged/newer.json");
    assert_non_null(result);
    assert_non_null(GET_ARG(result, "WiFi"));
    amxc_var_delete(&result);
}

void test_can_remove_acl_dir(UNUSED void** state) {
    amxo_connection_t* connection = NULL;
    struct stat sb;

    assert_int_equal(remove("../acldir/newer/wifi.json"), 0);
    assert_int_equal(remove("../acldir/newer"), 0);

    connection = amxo_connection_get_first(aclm_get_parser(), AMXO_CUSTOM);
    assert_non_null(connection);
    connection->reader(connection->fd, NULL);

    handle_events();

    assert_int_not_equal(stat("../acldir/merged/newer.json", &sb), 0);
}

void test_aclm_merge_invalid(UNUSED void** state) {
    amxo_parser_t* parser = NULL;
    amxc_var_t var_invalid;

    assert_int_equal(aclm_merge(NULL, NULL), -1);
    assert_int_equal(aclm_merge("", NULL), -1);
    assert_int_equal(aclm_merge("/", NULL), -1);
    assert_int_equal(aclm_merge("/", ""), -1);

    parser = aclm_get_parser();
    assert_non_null(parser);

    amxc_var_init(&var_invalid);
    amxc_var_set_type(&var_invalid, AMXC_VAR_ID_CSTRING);
    amxc_var_set(cstring_t, &var_invalid, "");
    amxc_var_set_key(&parser->config, "acl_dir", &var_invalid, AMXC_VAR_FLAG_UPDATE | AMXC_VAR_FLAG_COPY);
    assert_int_equal(aclm_merge("../acldir/root", "root"), -1);
    amxc_var_clean(&var_invalid);
}

void test_aclm_merged_remove_invalid(UNUSED void** state) {
    assert_int_equal(aclm_merged_remove(NULL), -1);
    assert_int_equal(aclm_merged_remove(""), -1);
    assert_int_equal(aclm_merged_remove("role"), -1);
}
