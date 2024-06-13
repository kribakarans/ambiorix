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

#include "test_aclm_inotify_disabled.h"

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

static void add_role(const char* name, const char* type, const char* combined_from) {
    amxd_trans_t trans;

    amxd_trans_init(&trans);
    amxd_trans_select_pathf(&trans, "ACLManager.Role.");
    amxd_trans_add_inst(&trans, 0, NULL);
    amxd_trans_set_value(cstring_t, &trans, "Name", name);
    amxd_trans_set_value(cstring_t, &trans, "Type", type);
    if(combined_from != NULL) {
        amxd_trans_set_value(cstring_t, &trans, "CombinedFrom", combined_from);
    }
    assert_int_equal(amxd_trans_apply(&trans, &dm), 0);
    amxd_trans_clean(&trans);
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
    amxo_resolver_ftab_add(&parser, "UpdateACL", AMXO_FUNC(_Role_UpdateACL));

    retval = amxo_parser_parse_file(&parser, odl_config, root_obj);
    assert_int_equal(retval, 0);

    retval = amxo_parser_parse_file(&parser, odl_definition, root_obj);
    assert_int_equal(retval, 0);

    assert_int_equal(_aclm_main(0, &dm, &parser), 0);

    add_role("dummy", "Single", NULL);
    add_role("master", "Single", NULL);
    add_role("combination", "Combined", "dummy,master");
    handle_events();

    return 0;
}

int test_aclm_teardown(UNUSED void** state) {
    aclm_role_del("combination");
    aclm_role_del("master");
    aclm_role_del("dummy");
    handle_events();

    assert_int_equal(_aclm_main(1, &dm, &parser), 0);
    amxo_parser_clean(&parser);
    amxd_dm_clean(&dm);

    return 0;
}

static void test_add_single_role(const char* role, const char* root_obj) {
    amxc_var_t data;
    amxc_var_t args;
    amxc_var_t ret;
    amxc_var_t* subobject = NULL;
    amxc_var_t* result = NULL;
    amxc_string_t rule_file;
    amxc_string_t merged_file;
    const char* acl_dir = GET_CHAR(&parser.config, "acl_dir");
    struct stat sb;
    amxd_object_t* role_obj = amxd_dm_findf(&dm, "ACLManager.Role.[Name == '%s'].", role);

    assert_non_null(role_obj);

    amxc_var_init(&data);
    amxc_var_init(&args);
    amxc_var_init(&ret);
    amxc_string_init(&rule_file, 0);
    amxc_string_init(&merged_file, 0);

    amxc_var_set_type(&data, AMXC_VAR_ID_HTABLE);
    subobject = amxc_var_add_key(amxc_htable_t, &data, root_obj, NULL);
    amxc_var_add_key(uint32_t, subobject, "Order", 1);
    amxc_var_add_key(cstring_t, subobject, "Param", "rwxn");

    amxc_string_setf(&rule_file, "%s/%s/%sjson", acl_dir, role, root_obj);
    aclm_write_json_var(&data, amxc_string_get(&rule_file, 0));
    assert_int_equal(stat(amxc_string_get(&rule_file, 0), &sb), 0);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxd_object_invoke_function(role_obj, "UpdateACL", &args, &ret), 0);

    amxc_string_setf(&merged_file, "%s/merged/%s.json", acl_dir, role);
    assert_int_equal(stat(amxc_string_get(&merged_file, 0), &sb), 0);
    result = amxa_parse_files(amxc_string_get(&merged_file, 0));
    assert_non_null(result);
    amxc_var_dump(result, STDOUT_FILENO);

    amxc_var_delete(&result);
    amxc_string_clean(&merged_file);
    amxc_string_clean(&rule_file);
    amxc_var_clean(&args);
    amxc_var_clean(&ret);
    amxc_var_clean(&data);
}

void test_can_update_acls_single(UNUSED void** state) {
    test_add_single_role("dummy", "DHCPv4.");
    test_add_single_role("master", "WiFi.");
}

void test_can_update_acls_combined(UNUSED void** state) {
    amxc_var_t args;
    amxc_var_t ret;
    amxc_var_t* result = NULL;
    const char* role = "combination";
    const char* acl_dir = GET_CHAR(&parser.config, "acl_dir");
    amxd_object_t* role_obj = amxd_dm_findf(&dm, "ACLManager.Role.[Name == '%s'].", role);
    amxc_string_t merged_file;
    struct stat sb;

    amxc_string_init(&merged_file, 0);
    amxc_var_init(&ret);
    amxc_var_init(&args);
    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxd_object_invoke_function(role_obj, "UpdateACL", &args, &ret), 0);

    amxc_string_setf(&merged_file, "%s/merged/%s.json", acl_dir, role);
    assert_int_equal(stat(amxc_string_get(&merged_file, 0), &sb), 0);
    result = amxa_parse_files(amxc_string_get(&merged_file, 0));
    assert_non_null(result);
    amxc_var_dump(result, STDOUT_FILENO);

    amxc_var_delete(&result);
    amxc_var_clean(&args);
    amxc_var_clean(&ret);
    amxc_string_clean(&merged_file);
}
