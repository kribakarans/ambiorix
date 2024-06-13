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
#include <unistd.h>

#include <amxc/amxc.h>

#include "amxa/amxa_merger.h"
#include "amxa_merger_priv.h"

#include "test_amxa_merge.h"
#include "amxa/amxa_permissions.h"

#define UNUSED __attribute__((unused))

const uint32_t AMXA_PERMIT_PARAM_ALL = AMXA_PERMIT_GET | AMXA_PERMIT_SET | AMXA_PERMIT_SUBS_VAL_CHANGE;
const uint32_t AMXA_PERMIT_OBJ_ALL = AMXA_PERMIT_OBJ_INFO | AMXA_PERMIT_ADD | AMXA_PERMIT_SUBS_OBJ_ADD;
const uint32_t AMXA_PERMIT_INST_ALL = AMXA_PERMIT_GET_INST | AMXA_PERMIT_DEL | AMXA_PERMIT_SUBS_OBJ_DEL;
const uint32_t AMXA_PERMIT_CMD_EVT_ALL = AMXA_PERMIT_CMD_INFO | AMXA_PERMIT_OPER | AMXA_PERMIT_SUBS_EVT_OPER_COMP;

void test_amxa_merge_rules_invalid(UNUSED void** state) {
    amxc_var_t var;
    amxc_var_init(&var);

    assert_int_equal(amxa_merge_rules(NULL, NULL), -1);
    assert_int_equal(amxa_merge_rules(&var, NULL), -1);

    amxc_var_clean(&var);
}

void test_amxa_merge_non_existing_file(UNUSED void** state) {
    amxc_var_t* data = NULL;

    data = data_from_json("../examples/01_non_existing.json");

    assert_null(data);
}

void test_invalid_rule(UNUSED void** state) {
    amxc_var_t* data = NULL;

    data = data_from_json("./invalid/tr181-mqtt.json");
    assert_int_not_equal(amxa_merge_rules(data, "../invalid/merged.json"), 0);

    amxc_var_delete(&data);

    data = data_from_json("./invalid/dhcpv4.json");
    assert_int_not_equal(amxa_merge_rules(data, "../invalid/merged.json"), 0);

    amxc_var_delete(&data);
}

void test_single_rule(UNUSED void** state) {
    amxc_var_t* data = NULL;
    uint32_t permissions = 0;

    data = data_from_json("../examples/01_single_rule.json");

    assert_int_equal(amxa_merge_rules(data, "../examples/01_merged.json"), 0);

    amxc_var_delete(&data);

    // Read merged file and verify outputs
    data = data_from_json("../examples/01_merged.json");

    permissions = GETP_UINT32(data, "DHCPv4.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_ALL);

    amxc_var_delete(&data);
}

void test_deep_param_no_permissions(UNUSED void** state) {
    amxc_var_t* data = NULL;
    uint32_t permissions = 0;

    data = data_from_json("../examples/02_deep_param_no_permissions.json");

    assert_int_equal(amxa_merge_rules(data, "../examples/02_merged.json"), 0);

    amxc_var_delete(&data);

    // Read merged file and verify outputs
    data = data_from_json("../examples/02_merged.json");

    permissions = GETP_UINT32(data, "DHCPv4.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_ALL);

    permissions = GETP_UINT32(data, "DHCPv4.Server.Pool.[Alias == \"cpe-LAN\"].Chaddr.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_NONE);

    amxc_var_delete(&data);
}

void test_low_param_no_permissions(UNUSED void** state) {
    amxc_var_t* data = NULL;
    uint32_t permissions = 0;

    data = data_from_json("../examples/03_low_param_no_permissions.json");

    assert_int_equal(amxa_merge_rules(data, "../examples/03_merged.json"), 0);

    amxc_var_delete(&data);

    // Read merged file and verify outputs
    data = data_from_json("../examples/03_merged.json");

    permissions = GETP_UINT32(data, "DHCPv4.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_ALL);

    permissions = GETP_UINT32(data, "DHCPv4.ClientNumberOfEntries.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_NONE);

    amxc_var_delete(&data);
}

void test_no_cmd_event_permissions(UNUSED void** state) {
    amxc_var_t* data = NULL;
    uint32_t permissions = 0;

    data = data_from_json("../examples/04_no_cmd_event_permissions.json");

    assert_int_equal(amxa_merge_rules(data, "../examples/04_merged.json"), 0);

    amxc_var_delete(&data);

    // Read merged file and verify outputs
    data = data_from_json("../examples/04_merged.json");

    permissions = GETP_UINT32(data, "DHCPv4.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_ALL);

    permissions = GETP_UINT32(data, "DHCPv4.Client.*.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_PARAM_ALL | AMXA_PERMIT_OBJ_ALL | AMXA_PERMIT_INST_ALL);

    amxc_var_delete(&data);
}

void test_fewer_permissions_per_level(UNUSED void** state) {
    amxc_var_t* data = NULL;
    uint32_t permissions = 0;

    data = data_from_json("../examples/05_fewer_permissions_per_level.json");

    assert_int_equal(amxa_merge_rules(data, "../examples/05_merged.json"), 0);

    amxc_var_delete(&data);

    // Read merged file and verify outputs
    data = data_from_json("../examples/05_merged.json");

    permissions = GETP_UINT32(data, "DHCPv4.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_ALL);

    permissions = GETP_UINT32(data, "DHCPv4.Server.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_PARAM_ALL | AMXA_PERMIT_OBJ_ALL | AMXA_PERMIT_INST_ALL);

    permissions = GETP_UINT32(data, "DHCPv4.Server.Pool.*.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_PARAM_ALL | AMXA_PERMIT_OBJ_ALL);

    permissions = GETP_UINT32(data, "DHCPv4.Server.Pool.*.Client.*.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_PARAM_ALL);

    permissions = GETP_UINT32(data, "DHCPv4.Server.Pool.*.Client.*.IPv4Address.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_NONE);

    amxc_var_delete(&data);
}

void test_different_permissions_per_instance(UNUSED void** state) {
    amxc_var_t* data = NULL;
    uint32_t permissions = 0;

    data = data_from_json("../examples/06_different_permissions_per_instance.json");

    assert_int_equal(amxa_merge_rules(data, "../examples/06_merged.json"), 0);

    amxc_var_delete(&data);

    // Read merged file and verify outputs
    data = data_from_json("../examples/06_merged.json");

    permissions = GETP_UINT32(data, "DHCPv4.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_ALL);

    permissions = GETP_UINT32(data, "DHCPv4.Client.1.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_NONE);

    permissions = GETP_UINT32(data, "DHCPv4.Client.2.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_PARAM_ALL);

    permissions = GETP_UINT32(data, "DHCPv4.Client.3.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_ALL);

    amxc_var_delete(&data);
}

void test_multiple_subtrees(UNUSED void** state) {
    amxc_var_t* data = NULL;
    uint32_t permissions = 0;

    data = data_from_json("../examples/07_multiple_subtrees.json");

    assert_int_equal(amxa_merge_rules(data, "../examples/07_merged.json"), 0);

    amxc_var_delete(&data);

    // Read merged file and verify outputs
    data = data_from_json("../examples/07_merged.json");

    permissions = GETP_UINT32(data, "DHCPv4.Client.*.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_PARAM_ALL);

    permissions = GETP_UINT32(data, "DHCPv4.Server.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_ALL);

    permissions = GETP_UINT32(data, "DHCPv4.Server.Pool.*.StaticAddress.*.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_NONE);

    amxc_var_delete(&data);
}

void test_high_order_beats_low_order(UNUSED void** state) {
    amxc_var_t* data = NULL;
    uint32_t permissions = 0;
    uint32_t order = 0;

    data = data_from_json("../examples/08_high_order_beats_low_order.json");

    assert_int_equal(amxa_merge_rules(data, "../examples/08_merged.json"), 0);

    amxc_var_delete(&data);

    // Read merged file and verify outputs
    data = data_from_json("../examples/08_merged.json");

    permissions = GETP_UINT32(data, "DHCPv4.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_PARAM_ALL);

    order = GETP_UINT32(data, "DHCPv4.\%Order");
    assert_int_equal(order, 2);

    permissions = GETP_UINT32(data, "DHCPv4.Server.Pool.*.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_NONE);

    amxc_var_delete(&data);
}

void test_complex_search_paths(UNUSED void** state) {
    amxc_var_t* data = NULL;
    uint32_t permissions = 0;

    data = data_from_json("../examples/09_complex_search_paths.json");

    assert_int_equal(amxa_merge_rules(data, "../examples/09_merged.json"), 0);

    amxc_var_delete(&data);

    // Read merged file and verify outputs
    data = data_from_json("../examples/09_merged.json");

    permissions = GETP_UINT32(data, "DHCPv4.Client.*.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_PARAM_ALL);

    permissions = GETP_UINT32(data, "DHCPv4.Server.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_ALL);

    permissions = GETP_UINT32(data, "DHCPv4.Server.Pool.[Enable==False].Client.*.IPv4Address.[IPAddress==\"123.456.789.0\"].\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_NONE);

    amxc_var_delete(&data);
}

void test_merge_get_supported(UNUSED void** state) {
    amxc_var_t* data = NULL;
    uint32_t permissions = 0;

    data = data_from_json("../examples/10_get_supported.json");

    assert_int_equal(amxa_merge_rules(data, "../examples/10_merged.json"), 0);

    amxc_var_delete(&data);

    // Read merged file and verify outputs
    data = data_from_json("../examples/10_merged.json");

    permissions = GETP_UINT32(data, "DHCPv4.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_ALL);

    permissions = GETP_UINT32(data, "DHCPv4.Client.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_ALL ^ AMXA_PERMIT_CMD_INFO);

    permissions = GETP_UINT32(data, "DHCPv4.Server.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_ALL ^ AMXA_PERMIT_GET);

    permissions = GETP_UINT32(data, "DHCPv4.Relay.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_ALL ^ AMXA_PERMIT_OBJ_INFO);

    amxc_var_delete(&data);
}

void test_get_instances_rules(UNUSED void** state) {
    amxc_var_t* data = NULL;
    uint32_t permissions = 0;

    data = data_from_json("../examples/11_get_instances_rules.json");

    assert_int_equal(amxa_merge_rules(data, "../examples/11_merged.json"), 0);

    amxc_var_delete(&data);

    // Read merged file and verify outputs
    data = data_from_json("../examples/11_merged.json");

    permissions = GETP_UINT32(data, "DHCPv4.Client.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_INST_ALL);

    permissions = GETP_UINT32(data, "DHCPv4.Server.Pool.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_DEL | AMXA_PERMIT_SUBS_OBJ_DEL);

    permissions = GETP_UINT32(data, "DHCPv4.Client.1.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_DEL | AMXA_PERMIT_SUBS_OBJ_DEL);

    permissions = GETP_UINT32(data, "DHCPv4.Client.2.SentOption.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_DEL | AMXA_PERMIT_SUBS_OBJ_DEL);

    amxc_var_delete(&data);
}

void test_amxa_combine_rules_invalid(UNUSED void** state) {
    amxc_var_t src;
    amxc_var_t dst;

    amxc_var_init(&src);
    amxc_var_init(&dst);

    assert_int_equal(amxa_combine_rules(NULL, NULL), -1);
    assert_int_equal(amxa_combine_rules(&dst, NULL), -1);
    assert_int_equal(amxa_combine_rules(&dst, &src), -1);
    amxc_var_set_type(&dst, AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxa_combine_rules(&dst, &src), -1);

    amxc_var_clean(&src);
    amxc_var_clean(&dst);
}

void test_override_rule(UNUSED void** state) {
    amxc_var_t* data = NULL;
    amxc_var_t* dhcpv4 = NULL;
    amxc_var_t new_rule;

    amxc_var_init(&new_rule);
    amxc_var_set_type(&new_rule, AMXC_VAR_ID_HTABLE);
    dhcpv4 = amxc_var_add_key(amxc_htable_t, &new_rule, "DHCPv4.", NULL);
    amxc_var_add_key(uint32_t, dhcpv4, "Order", 1000);
    amxc_var_add_key(cstring_t, dhcpv4, "Param", "rwxn");

    data = data_from_json("../examples/01_single_rule.json");

    assert_int_equal(amxa_combine_rules(data, &new_rule), 0);
    amxc_var_dump(data, STDOUT_FILENO);
    assert_int_equal(GETP_UINT32(data, "'DHCPv4.'.Order"), 1000);
    assert_string_equal(GETP_CHAR(data, "'DHCPv4.'.Param"), "rwxn");
    assert_null(GETP_ARG(data, "'DHCPv4.'.Obj"));
    assert_null(GETP_ARG(data, "'DHCPv4.'.InstantiatedObj"));
    assert_null(GETP_ARG(data, "'DHCPv4.'.CommandEvent"));

    amxc_var_clean(&new_rule);
    amxc_var_delete(&data);
}

void test_extend_rules(UNUSED void** state) {
    amxc_var_t* data = NULL;
    amxc_var_t* dhcpv4 = NULL;
    amxc_var_t new_rule;

    amxc_var_init(&new_rule);
    amxc_var_set_type(&new_rule, AMXC_VAR_ID_HTABLE);
    dhcpv4 = amxc_var_add_key(amxc_htable_t, &new_rule, "DHCPv4.Client.", NULL);
    amxc_var_add_key(uint32_t, dhcpv4, "Order", 1000);
    amxc_var_add_key(cstring_t, dhcpv4, "Param", "rwxn");
    amxc_var_add_key(cstring_t, dhcpv4, "Obj", "rwxn");

    data = data_from_json("../examples/01_single_rule.json");

    assert_int_equal(amxa_combine_rules(data, &new_rule), 0);
    amxc_var_dump(data, STDOUT_FILENO);
    assert_int_equal(GETP_UINT32(data, "'DHCPv4.'.Order"), 1);
    assert_string_equal(GETP_CHAR(data, "'DHCPv4.'.Param"), "rwxn");
    assert_string_equal(GETP_CHAR(data, "'DHCPv4.'.Obj"), "rwxn");
    assert_string_equal(GETP_CHAR(data, "'DHCPv4.'.InstantiatedObj"), "rwxn");
    assert_string_equal(GETP_CHAR(data, "'DHCPv4.'.CommandEvent"), "rwxn");

    assert_int_equal(GETP_UINT32(data, "'DHCPv4.Client.'.Order"), 1000);
    assert_string_equal(GETP_CHAR(data, "'DHCPv4.Client.'.Param"), "rwxn");
    assert_string_equal(GETP_CHAR(data, "'DHCPv4.Client.'.Obj"), "rwxn");
    assert_null(GETP_ARG(data, "'DHCPv4.Client.'.InstantiatedObj"));
    assert_null(GETP_ARG(data, "'DHCPv4.Client.'.CommandEvent"));

    amxc_var_clean(&new_rule);
    amxc_var_delete(&data);
}

void test_lower_order_rule_is_ignored(UNUSED void** state) {
    amxc_var_t* data = NULL;
    amxc_var_t* dhcpv4 = NULL;
    amxc_var_t new_rule;

    amxc_var_init(&new_rule);
    amxc_var_set_type(&new_rule, AMXC_VAR_ID_HTABLE);
    dhcpv4 = amxc_var_add_key(amxc_htable_t, &new_rule, "DHCPv4.", NULL);
    amxc_var_add_key(uint32_t, dhcpv4, "Order", 0);
    amxc_var_add_key(cstring_t, dhcpv4, "Param", "rwxn");

    data = data_from_json("../examples/01_single_rule.json");

    assert_int_equal(amxa_combine_rules(data, &new_rule), 0);
    amxc_var_dump(data, STDOUT_FILENO);
    assert_int_equal(GETP_UINT32(data, "'DHCPv4.'.Order"), 1);
    assert_string_equal(GETP_CHAR(data, "'DHCPv4.'.Param"), "rwxn");
    assert_string_equal(GETP_CHAR(data, "'DHCPv4.'.Obj"), "rwxn");
    assert_string_equal(GETP_CHAR(data, "'DHCPv4.'.InstantiatedObj"), "rwxn");
    assert_string_equal(GETP_CHAR(data, "'DHCPv4.'.CommandEvent"), "rwxn");

    amxc_var_clean(&new_rule);
    amxc_var_delete(&data);
}

void test_combine_roles_invalid(UNUSED void** state) {
    amxc_var_t merged_roles;
    amxc_var_init(&merged_roles);

    assert_int_equal(amxa_combine_roles(NULL, NULL, NULL), -1);
    assert_int_equal(amxa_combine_roles(&merged_roles, NULL, NULL), -1);

    amxc_var_clean(&merged_roles);
}

void test_combine_roles_1_2(UNUSED void** state) {
    amxc_var_t* role1 = data_from_json("../examples/01_merged.json");
    amxc_var_t* role2 = data_from_json("../examples/02_merged.json");

    assert_int_equal(amxa_combine_roles(role1, role2, NULL), 0);
    amxc_var_dump(role1, STDOUT_FILENO);

    amxc_var_delete(&role1);
    amxc_var_delete(&role2);
}

void test_combine_roles_2_3(UNUSED void** state) {
    amxc_var_t* role1 = data_from_json("../examples/02_merged.json");
    amxc_var_t* role2 = data_from_json("../examples/03_merged.json");

    assert_int_equal(amxa_combine_roles(role1, role2, NULL), 0);
    amxc_var_dump(role1, STDOUT_FILENO);

    amxc_var_delete(&role1);
    amxc_var_delete(&role2);
}

void test_combine_roles_4_6(UNUSED void** state) {
    amxc_var_t* role1 = data_from_json("../examples/04_merged.json");
    amxc_var_t* role2 = data_from_json("../examples/06_merged.json");

    assert_int_equal(amxa_combine_roles(role1, role2, NULL), 0);
    amxc_var_dump(role1, STDOUT_FILENO);

    amxc_var_delete(&role1);
    amxc_var_delete(&role2);
}

void test_combine_roles_5_7(UNUSED void** state) {
    amxc_var_t* role1 = data_from_json("../examples/05_merged.json");
    amxc_var_t* role2 = data_from_json("../examples/07_merged.json");

    assert_int_equal(amxa_combine_roles(role1, role2, NULL), 0);
    amxc_var_dump(role1, STDOUT_FILENO);

    amxc_var_delete(&role1);
    amxc_var_delete(&role2);
}

void test_combine_roles_1_to_7(UNUSED void** state) {
    uint32_t permissions = 0;
    amxc_var_t* role1 = data_from_json("../examples/01_merged.json");
    amxc_var_t* role2 = data_from_json("../examples/02_merged.json");
    amxc_var_t* role3 = data_from_json("../examples/03_merged.json");
    amxc_var_t* role4 = data_from_json("../examples/04_merged.json");
    amxc_var_t* role5 = data_from_json("../examples/05_merged.json");
    amxc_var_t* role6 = data_from_json("../examples/06_merged.json");
    amxc_var_t* role7 = data_from_json("../examples/07_merged.json");

    assert_int_equal(amxa_combine_roles(role1, role2, NULL), 0);
    assert_int_equal(amxa_combine_roles(role1, role3, NULL), 0);
    assert_int_equal(amxa_combine_roles(role1, role4, NULL), 0);
    assert_int_equal(amxa_combine_roles(role1, role5, NULL), 0);
    assert_int_equal(amxa_combine_roles(role1, role6, NULL), 0);
    assert_int_equal(amxa_combine_roles(role1, role7, NULL), 0);
    amxc_var_dump(role1, STDOUT_FILENO);

    permissions = GETP_UINT32(role1, "DHCPv4.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_ALL);

    permissions = GETP_UINT32(role1, "DHCPv4.ClientNumberOfEntries.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_NONE);

    // Client
    permissions = GETP_UINT32(role1, "DHCPv4.Client.*.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_PARAM_ALL | AMXA_PERMIT_OBJ_ALL | AMXA_PERMIT_INST_ALL);

    // Server
    permissions = GETP_UINT32(role1, "DHCPv4.Server.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_ALL);

    permissions = GETP_UINT32(role1, "DHCPv4.Server.Pool.*.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_PARAM_ALL | AMXA_PERMIT_OBJ_ALL);

    permissions = GETP_UINT32(role1, "DHCPv4.Server.Pool.[Alias == \"cpe-LAN\"].Chaddr.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_NONE);

    permissions = GETP_UINT32(role1, "DHCPv4.Server.Pool.*.Client.*.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_PARAM_ALL);

    permissions = GETP_UINT32(role1, "DHCPv4.Server.Pool.*.Client.*.IPv4Address.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_NONE);

    permissions = GETP_UINT32(role1, "DHCPv4.Server.Pool.*.StaticAddress.*.\%ACL");
    assert_int_equal(permissions, AMXA_PERMIT_NONE);

    amxc_var_delete(&role1);
    amxc_var_delete(&role2);
    amxc_var_delete(&role3);
    amxc_var_delete(&role4);
    amxc_var_delete(&role5);
    amxc_var_delete(&role6);
    amxc_var_delete(&role7);
}

void test_amxa_parse_files_invalid(UNUSED void** state) {
    const char* foo = "bar";
    assert_null(amxa_parse_files(NULL));
    assert_null(amxa_parse_files(""));
    assert_null(amxa_parse_files(foo));
    assert_null(amxa_parse_files("/"));
}

void test_load_rules_from_dir(UNUSED void** state) {
    amxc_var_t* data = NULL;
    amxc_var_t* result = NULL;
    const char* outputfile = "../examples/multi_files_merged.json";
    char* current_wd = getcwd(NULL, 0);
    amxc_string_t full_dir;
    amxc_string_init(&full_dir, 0);
    amxc_string_setf(&full_dir, "%s/role_dir/", current_wd);

    data = amxa_parse_files(amxc_string_get(&full_dir, 0));
    assert_non_null(data);

    assert_int_equal(amxa_merge_rules(data, outputfile), 0);
    result = data_from_json(outputfile);
    amxc_var_dump(result, STDOUT_FILENO);

    assert_int_equal(GETP_UINT32(result, "DHCPv4.\%ACL"), AMXA_PERMIT_ALL);
    assert_int_equal(GETP_UINT32(result, "LocalAgent.\%ACL"), AMXA_PERMIT_ALL);
    assert_int_equal(GETP_UINT32(result, "MQTT.\%ACL"), AMXA_PERMIT_ALL);

    amxc_var_delete(&result);
    amxc_var_delete(&data);
    amxc_string_clean(&full_dir);
    free(current_wd);
}
