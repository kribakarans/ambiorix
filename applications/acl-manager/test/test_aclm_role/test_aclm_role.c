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
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <amxc/amxc.h>
#include <amxp/amxp.h>

#include <amxd/amxd_dm.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_transaction.h>

#include <amxo/amxo.h>

#include <amxa/amxa_merger.h>

#include "dm_role.h"
#include "dm_role_events.h"
#include "dm_role_actions.h"
#include "aclm_utils.h"

#include "test_aclm_role.h"

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

static void test_add_rule(const char* rule_file, const char* merged_file) {
    amxc_var_t data;
    amxc_var_t* dhcpv4 = NULL;
    amxo_connection_t* connection = NULL;
    struct stat sb;

    amxc_var_init(&data);
    amxc_var_set_type(&data, AMXC_VAR_ID_HTABLE);
    dhcpv4 = amxc_var_add_key(amxc_htable_t, &data, "DHCPv4.", NULL);
    amxc_var_add_key(uint32_t, dhcpv4, "Order", 1);
    amxc_var_add_key(cstring_t, dhcpv4, "Param", "rwxn");

    aclm_write_json_var(&data, rule_file);

    connection = amxo_connection_get_first(aclm_get_parser(), AMXO_CUSTOM);
    assert_non_null(connection);
    connection->reader(connection->fd, NULL);

    assert_int_equal(stat(merged_file, &sb), 0);

    amxc_var_clean(&data);
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

    assert_int_equal(_aclm_main(0, &dm, &parser), 0);

    return 0;
}

int test_aclm_teardown(UNUSED void** state) {
    assert_int_equal(remove("../acldir/foo/dhcpv4.json"), 0);
    assert_int_equal(rmdir("../acldir/foo"), 0);
    assert_int_equal(remove("../acldir/merged/foo.json"), 0);

    assert_int_equal(_aclm_main(1, &dm, &parser), 0);
    amxo_parser_clean(&parser);
    amxd_dm_clean(&dm);

    return 0;
}

void test_can_create_single_roles(UNUSED void** state) {
    amxd_trans_t trans;
    amxd_object_t* inst = NULL;

    amxd_trans_init(&trans);
    amxd_trans_select_pathf(&trans, "ACLManager.Role.");
    amxd_trans_add_inst(&trans, 0, NULL);
    amxd_trans_set_value(cstring_t, &trans, "Name", "foo");
    assert_int_equal(amxd_trans_apply(&trans, &dm), 0);

    amxd_trans_select_pathf(&trans, "ACLManager.Role.");
    amxd_trans_add_inst(&trans, 0, NULL);
    amxd_trans_set_value(cstring_t, &trans, "Name", "bar");
    assert_int_equal(amxd_trans_apply(&trans, &dm), 0);

    handle_events();

    inst = amxd_dm_findf(&dm, "ACLManager.Role.[Name == 'foo' && Type == 'Single'].");
    assert_non_null(inst);

    inst = amxd_dm_findf(&dm, "ACLManager.Role.[Name == 'bar' && Type == 'Single'].");
    assert_non_null(inst);

    test_add_rule("../acldir/foo/dhcpv4.json", "../acldir/merged/foo.json");
    test_add_rule("../acldir/bar/dhcpv4.json", "../acldir/merged/bar.json");

    amxd_trans_clean(&trans);
}

void test_can_create_combined_roles(UNUSED void** state) {
    amxd_trans_t trans;
    amxd_object_t* inst = NULL;
    struct stat sb;

    amxd_trans_init(&trans);
    amxd_trans_select_pathf(&trans, "ACLManager.Role.");
    amxd_trans_add_inst(&trans, 0, NULL);
    amxd_trans_set_value(cstring_t, &trans, "Name", "foo_bar");
    amxd_trans_set_value(cstring_t, &trans, "Type", "Combined");
    amxd_trans_set_value(cstring_t, &trans, "CombinedFrom", "foo,bar");
    assert_int_equal(amxd_trans_apply(&trans, &dm), 0);

    handle_events();

    inst = amxd_dm_findf(&dm, "ACLManager.Role.[Name == 'foo_bar' && Type == 'Combined' && \
                               CombinedFrom == 'foo,bar'].");
    assert_non_null(inst);

    assert_int_equal(stat("../acldir/merged/foo_bar.json", &sb), 0);

    amxd_trans_clean(&trans);
}

void test_cannot_create_role_with_invalid_params(UNUSED void** state) {
    amxd_trans_t trans;

    // Single role, combined from multiple roles
    amxd_trans_init(&trans);
    amxd_trans_select_pathf(&trans, "ACLManager.Role.");
    amxd_trans_add_inst(&trans, 0, NULL);
    amxd_trans_set_value(cstring_t, &trans, "Name", "fail");
    amxd_trans_set_value(cstring_t, &trans, "Type", "Single");
    amxd_trans_set_value(cstring_t, &trans, "CombinedFrom", "foo,bar");
    assert_int_not_equal(amxd_trans_apply(&trans, &dm), 0);
    amxd_trans_clean(&trans);

    // Combined role, combined from non-existing roles
    amxd_trans_init(&trans);
    amxd_trans_select_pathf(&trans, "ACLManager.Role.");
    amxd_trans_add_inst(&trans, 0, NULL);
    amxd_trans_set_value(cstring_t, &trans, "Name", "fail");
    amxd_trans_set_value(cstring_t, &trans, "Type", "Combined");
    amxd_trans_set_value(cstring_t, &trans, "CombinedFrom", "_does,_not,_exist");
    assert_int_not_equal(amxd_trans_apply(&trans, &dm), 0);
    amxd_trans_clean(&trans);
}

void test_can_remove_combined_role(UNUSED void** state) {
    amxd_trans_t trans;
    amxd_object_t* inst;
    struct stat sb;

    inst = amxd_dm_findf(&dm, "ACLManager.Role.[Name == 'foo_bar'].");
    assert_non_null(inst);

    amxd_trans_init(&trans);
    amxd_trans_select_pathf(&trans, "ACLManager.Role.");
    amxd_trans_del_inst(&trans, inst->index, NULL);
    assert_int_equal(amxd_trans_apply(&trans, &dm), 0);
    amxd_trans_clean(&trans);

    handle_events();

    assert_int_not_equal(stat("../acldir/merged/foo_bar.json", &sb), 0);
}

void test_can_remove_single_role(UNUSED void** state) {
    amxd_trans_t trans;
    amxd_object_t* inst;
    struct stat sb;

    inst = amxd_dm_findf(&dm, "ACLManager.Role.[Name == 'bar'].");
    assert_non_null(inst);

    amxd_trans_init(&trans);
    amxd_trans_select_pathf(&trans, "ACLManager.Role.");
    amxd_trans_del_inst(&trans, inst->index, NULL);
    assert_int_equal(amxd_trans_apply(&trans, &dm), 0);
    amxd_trans_clean(&trans);

    handle_events();

    assert_int_not_equal(stat("../acldir/bar", &sb), 0);
    assert_int_not_equal(stat("../acldir/merged/bar.json", &sb), 0);
}

void test_aclm_add_del_role_invalid(UNUSED void** state) {
    assert_int_not_equal(aclm_role_add(NULL), 0);
    assert_int_not_equal(aclm_role_add(""), 0);

    assert_int_not_equal(aclm_role_del(NULL), 0);
    assert_int_not_equal(aclm_role_del(""), 0);
}
