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
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <cmocka.h>
#include <unistd.h>
#include <signal.h>
#include <sys/signalfd.h>
#include <string.h>
#include <stdio.h>

#include <amxc/amxc.h>
#include <amxp/amxp_signal.h>
#include <amxp/amxp_slot.h>
#include <amxp/amxp_expression.h>

#include <amxd/amxd_common.h>
#include <amxd/amxd_transaction.h>
#include <amxd/amxd_dm.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_object_expression.h>

#include "test_amxd_object_search.h"

#include <amxc/amxc_macros.h>
static amxd_dm_t dm;

static void test_build_dm(void) {
    amxd_object_t* object = NULL;
    amxd_object_t* child_object = NULL;
    amxd_param_t* param = NULL;
    amxd_trans_t transaction;

    assert_int_equal(amxd_dm_init(&dm), 0);

    assert_int_equal(amxd_object_new(&object, amxd_object_singleton, "RootObject"), 0);
    assert_int_equal(amxd_dm_add_root_object(&dm, object), 0);

    assert_int_equal(amxd_object_new(&child_object, amxd_object_template, "TemplateObject"), 0);
    assert_int_equal(amxd_object_add_object(object, child_object), 0);

    assert_int_equal(amxd_param_new(&param, "Param1", AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(amxd_param_set_attr(param, amxd_pattr_key, true), 0);
    assert_int_equal(amxd_object_add_param(child_object, param), 0);
    assert_int_equal(amxd_param_new(&param, "Param2", AMXC_VAR_ID_BOOL), 0);
    assert_int_equal(amxd_object_add_param(child_object, param), 0);
    assert_int_equal(amxd_param_new(&param, "Param3", AMXC_VAR_ID_UINT32), 0);
    assert_int_equal(amxd_object_add_param(child_object, param), 0);
    assert_int_equal(amxd_param_new(&param, "Alias", AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(amxd_param_set_attr(param, amxd_pattr_key, true), 0);
    assert_int_equal(amxd_param_set_attr(param, amxd_pattr_unique, true), 0);
    assert_int_equal(amxd_object_add_param(child_object, param), 0);

    assert_int_equal(amxd_object_new(&object, amxd_object_singleton, "ChildObject"), 0);
    assert_int_equal(amxd_object_add_object(child_object, object), 0);
    assert_int_equal(amxd_param_new(&param, "Param1", AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(amxd_object_add_param(object, param), 0);
    assert_int_equal(amxd_param_new(&param, "Param3", AMXC_VAR_ID_UINT32), 0);
    assert_int_equal(amxd_object_add_param(object, param), 0);

    assert_int_equal(amxd_object_new(&child_object, amxd_object_template, "TemplateObject"), 0);
    assert_int_equal(amxd_object_add_object(object, child_object), 0);
    assert_int_equal(amxd_param_new(&param, "Alias", AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(amxd_param_set_attr(param, amxd_pattr_key, true), 0);
    assert_int_equal(amxd_param_set_attr(param, amxd_pattr_unique, true), 0);
    assert_int_equal(amxd_object_add_param(child_object, param), 0);

    amxd_trans_init(&transaction);
    amxd_trans_select_pathf(&transaction, "RootObject.TemplateObject");
    amxd_trans_add_inst(&transaction, 0, NULL);
    amxd_trans_set_value(cstring_t, &transaction, "Param1", "test1");
    amxd_trans_set_value(uint32_t, &transaction, "Param3", 100);
    amxd_trans_select_pathf(&transaction, ".ChildObject");
    amxd_trans_set_value(cstring_t, &transaction, "Param1", "sub-test1");
    amxd_trans_set_value(uint32_t, &transaction, "Param3", 200);

    amxd_trans_select_pathf(&transaction, ".^.^");
    amxd_trans_add_inst(&transaction, 0, NULL);
    amxd_trans_set_value(cstring_t, &transaction, "Param1", "test2");
    amxd_trans_set_value(uint32_t, &transaction, "Param3", 110);
    amxd_trans_select_pathf(&transaction, ".ChildObject");
    amxd_trans_set_value(cstring_t, &transaction, "Param1", "sub-test2");
    amxd_trans_set_value(uint32_t, &transaction, "Param3", 210);
    amxd_trans_select_pathf(&transaction, ".TemplateObject");
    amxd_trans_add_inst(&transaction, 0, "SubAlias");

    amxd_trans_select_pathf(&transaction, ".^.^.^.^");
    amxd_trans_add_inst(&transaction, 0, NULL);
    amxd_trans_set_value(cstring_t, &transaction, "Param1", "test3");
    amxd_trans_set_value(uint32_t, &transaction, "Param3", 120);
    amxd_trans_select_pathf(&transaction, ".ChildObject");
    amxd_trans_set_value(cstring_t, &transaction, "Param1", "sub-test3");
    amxd_trans_set_value(uint32_t, &transaction, "Param3", 220);

    amxd_trans_select_pathf(&transaction, ".^.^");
    amxd_trans_add_inst(&transaction, 0, NULL);
    amxd_trans_set_value(cstring_t, &transaction, "Param1", "test4");
    amxd_trans_set_value(uint32_t, &transaction, "Param3", 130);
    amxd_trans_select_pathf(&transaction, ".ChildObject");
    amxd_trans_set_value(cstring_t, &transaction, "Param1", "sub-test4");
    amxd_trans_set_value(uint32_t, &transaction, "Param3", 230);
    amxd_trans_select_pathf(&transaction, ".TemplateObject");
    amxd_trans_add_inst(&transaction, 0, "SubAlias");

    amxd_trans_select_pathf(&transaction, ".^.^.^.^");
    amxd_trans_add_inst(&transaction, 0, "Alias5");
    amxd_trans_set_value(cstring_t, &transaction, "Param1", "test5");
    amxd_trans_set_value(uint32_t, &transaction, "Param3", 140);
    amxd_trans_select_pathf(&transaction, ".ChildObject");
    amxd_trans_set_value(cstring_t, &transaction, "Param1", "sub-test5");
    amxd_trans_set_value(uint32_t, &transaction, "Param3", 240);
    amxd_trans_select_pathf(&transaction, ".TemplateObject");
    amxd_trans_add_inst(&transaction, 0, "SubAlias2");

    assert_int_equal(amxd_trans_apply(&transaction, &dm), 0);
    amxd_trans_clean(&transaction);
}

int test_object_search_setup(UNUSED void** state) {
    test_build_dm();
    return 0;
}

int test_object_search_teardown(UNUSED void** state) {
    amxd_dm_clean(&dm);

    return 0;
}

void test_can_search(UNUSED void** state) {
    amxc_llist_t paths;
    amxd_object_t* root_obj = amxd_dm_get_root(&dm);
    amxd_object_t* inst_obj = NULL;
    amxc_llist_init(&paths);

    assert_int_equal(amxd_object_resolve_pathf(root_obj, &paths, "RootObject.TemplateObject.1"), 0);
    assert_int_equal(amxc_llist_size(&paths), 1);
    assert_string_equal(amxc_string_get(amxc_string_from_llist_it(amxc_llist_get_first(&paths)), 0), "RootObject.TemplateObject.1.");
    amxc_llist_clean(&paths, amxc_string_list_it_free);

    assert_int_equal(amxd_object_resolve_pathf(root_obj, &paths, "RootObject.TemplateObject.[1]"), 0);
    assert_int_equal(amxc_llist_size(&paths), 1);
    assert_string_equal(amxc_string_get(amxc_string_from_llist_it(amxc_llist_get_first(&paths)), 0), "RootObject.TemplateObject.1.");
    amxc_llist_clean(&paths, amxc_string_list_it_free);

    assert_int_equal(amxd_object_resolve_pathf(root_obj, &paths, "RootObject.TemplateObject.cpe-TemplateObject-1."), 0);
    assert_int_equal(amxc_llist_size(&paths), 1);
    assert_string_equal(amxc_string_get(amxc_string_from_llist_it(amxc_llist_get_first(&paths)), 0), "RootObject.TemplateObject.1.");
    amxc_llist_clean(&paths, amxc_string_list_it_free);

    assert_int_equal(amxd_object_resolve_pathf(root_obj, &paths, "RootObject.TemplateObject.[cpe-TemplateObject-2]"), 0);
    assert_int_equal(amxc_llist_size(&paths), 1);
    assert_string_equal(amxc_string_get(amxc_string_from_llist_it(amxc_llist_get_first(&paths)), 0), "RootObject.TemplateObject.2.");
    amxc_llist_clean(&paths, amxc_string_list_it_free);

    assert_int_equal(amxd_object_resolve_pathf(root_obj, &paths, "RootObject.TemplateObject.[Param1=='test1']."), 0);
    assert_int_equal(amxc_llist_size(&paths), 1);
    assert_string_equal(amxc_string_get(amxc_string_from_llist_it(amxc_llist_get_first(&paths)), 0), "RootObject.TemplateObject.1.");
    amxc_llist_clean(&paths, amxc_string_list_it_free);

    assert_int_equal(amxd_object_resolve_pathf(root_obj, &paths, "RootObject.TemplateObject.[Param3>120]"), 0);
    assert_int_equal(amxc_llist_size(&paths), 2);
    assert_string_equal(amxc_string_get(amxc_string_from_llist_it(amxc_llist_get_first(&paths)), 0), "RootObject.TemplateObject.4.");
    amxc_llist_clean(&paths, amxc_string_list_it_free);

    assert_int_equal(amxd_object_resolve_pathf(root_obj, &paths, "RootObject.TemplateObject.*"), 0);
    assert_int_equal(amxc_llist_size(&paths), 5);
    assert_string_equal(amxc_string_get(amxc_string_from_llist_it(amxc_llist_get_first(&paths)), 0), "RootObject.TemplateObject.1.");
    amxc_llist_clean(&paths, amxc_string_list_it_free);

    inst_obj = amxd_dm_findf(&dm, "RootObject.TemplateObject.1.");
    assert_non_null(inst_obj);
    assert_int_equal(amxd_object_resolve_pathf(inst_obj, &paths, "^.[Param3>100]."), 0);
    assert_int_equal(amxc_llist_size(&paths), 4);
    amxc_llist_clean(&paths, amxc_string_list_it_free);

    inst_obj = amxd_dm_findf(&dm, "RootObject.");
    assert_non_null(inst_obj);

    inst_obj = amxd_dm_get_object(&dm, "RootObject.");
    assert_non_null(inst_obj);

    inst_obj = amxd_dm_findf(&dm, "RootObject.TemplateObject.1.ChildObject.");
    assert_non_null(inst_obj);
    assert_int_equal(amxd_object_resolve_pathf(inst_obj, &paths, "^.^.[Param3>110]."), 0);
    assert_int_equal(amxc_llist_size(&paths), 3);
    amxc_llist_clean(&paths, amxc_string_list_it_free);
}

void test_can_use_sub_object_in_expression(UNUSED void** state) {
    amxc_llist_t paths;
    amxd_object_t* root_obj = amxd_dm_get_root(&dm);
    bool key_path = false;
    amxc_llist_init(&paths);

    assert_int_equal(amxd_object_resolve_pathf(root_obj, &paths, "RootObject.TemplateObject.[ChildObject.Param1=='sub-test1']"), 0);
    assert_int_equal(amxc_llist_size(&paths), 1);
    assert_string_equal(amxc_string_get(amxc_string_from_llist_it(amxc_llist_get_first(&paths)), 0), "RootObject.TemplateObject.1.");
    amxc_llist_clean(&paths, amxc_string_list_it_free);

    assert_int_equal(amxd_dm_resolve_pathf(&dm, &paths, "RootObject.TemplateObject.[ChildObject.Param3>220]"), 0);
    assert_int_equal(amxc_llist_size(&paths), 2);
    assert_string_equal(amxc_string_get(amxc_string_from_llist_it(amxc_llist_get_first(&paths)), 0), "RootObject.TemplateObject.4.");
    amxc_llist_clean(&paths, amxc_string_list_it_free);

    assert_int_equal(amxd_dm_resolve_pathf_ext(&dm, &key_path, &paths, "RootObject.TemplateObject.[ChildObject.Param3>220]"), 0);
    assert_int_equal(amxc_llist_size(&paths), 2);
    assert_string_equal(amxc_string_get(amxc_string_from_llist_it(amxc_llist_get_first(&paths)), 0), "RootObject.TemplateObject.4.");
    amxc_llist_clean(&paths, amxc_string_list_it_free);

    assert_int_equal(amxd_object_resolve_pathf(root_obj, &paths, "RootObject.TemplateObject.*.ChildObject."), 0);
    assert_int_equal(amxc_llist_size(&paths), 5);
    assert_string_equal(amxc_string_get(amxc_string_from_llist_it(amxc_llist_get_first(&paths)), 0), "RootObject.TemplateObject.1.ChildObject.");
    amxc_llist_clean(&paths, amxc_string_list_it_free);

    assert_int_equal(amxd_object_resolve_pathf_ext(root_obj, &key_path, &paths, "RootObject.TemplateObject.*.ChildObject."), 0);
    assert_int_equal(amxc_llist_size(&paths), 5);
    assert_string_equal(amxc_string_get(amxc_string_from_llist_it(amxc_llist_get_first(&paths)), 0), "RootObject.TemplateObject.1.ChildObject.");
    amxc_llist_clean(&paths, amxc_string_list_it_free);

    assert_int_equal(amxd_dm_resolve_pathf(&dm, &paths, "RootObject.TemplateObject.*.ChildObject.TemplateObject.[Alias=='SubAlias']"), 0);
    assert_int_equal(amxc_llist_size(&paths), 2);
    assert_string_equal(amxc_string_get(amxc_string_from_llist_it(amxc_llist_get_first(&paths)), 0), "RootObject.TemplateObject.2.ChildObject.TemplateObject.1.");
    amxc_llist_clean(&paths, amxc_string_list_it_free);

    assert_int_equal(amxd_dm_resolve_pathf_ext(&dm, &key_path, &paths, "RootObject.TemplateObject.*.ChildObject.TemplateObject.[Alias=='SubAlias']"), 0);
    assert_int_equal(amxc_llist_size(&paths), 2);
    assert_string_equal(amxc_string_get(amxc_string_from_llist_it(amxc_llist_get_first(&paths)), 0), "RootObject.TemplateObject.2.ChildObject.TemplateObject.1.");
    amxc_llist_clean(&paths, amxc_string_list_it_free);

    assert_int_equal(amxd_object_resolve_pathf(root_obj, &paths, "RootObject.TemplateObject.Alias5.ChildObject.TemplateObject.[SubAlias2]"), 0);
    assert_int_equal(amxc_llist_size(&paths), 1);
    assert_string_equal(amxc_string_get(amxc_string_from_llist_it(amxc_llist_get_first(&paths)), 0), "RootObject.TemplateObject.5.ChildObject.TemplateObject.1.");
    amxc_llist_clean(&paths, amxc_string_list_it_free);

    assert_int_equal(amxd_object_resolve_pathf(root_obj, &paths, "RootObject.TemplateObject.[5].ChildObject.TemplateObject.[SubAlias2]"), 0);
    assert_int_equal(amxc_llist_size(&paths), 1);
    assert_string_equal(amxc_string_get(amxc_string_from_llist_it(amxc_llist_get_first(&paths)), 0), "RootObject.TemplateObject.5.ChildObject.TemplateObject.1.");
    amxc_llist_clean(&paths, amxc_string_list_it_free);

    assert_int_equal(amxd_object_resolve_pathf(root_obj, &paths, "RootObject.TemplateObject.[ChildObject.Param3 == 240].ChildObject.TemplateObject.*"), 0);
    assert_int_equal(amxc_llist_size(&paths), 1);
    assert_string_equal(amxc_string_get(amxc_string_from_llist_it(amxc_llist_get_first(&paths)), 0), "RootObject.TemplateObject.5.ChildObject.TemplateObject.1.");
    amxc_llist_clean(&paths, amxc_string_list_it_free);

    root_obj = amxd_dm_findf(&dm, "RootObject");
    assert_int_equal(amxd_object_resolve_pathf(root_obj, &paths, "."), 0);
    assert_int_equal(amxc_llist_size(&paths), 1);
    assert_string_equal(amxc_string_get(amxc_string_from_llist_it(amxc_llist_get_first(&paths)), 0), "RootObject.");
    amxc_llist_clean(&paths, amxc_string_list_it_free);

    assert_int_equal(amxd_object_resolve_pathf(root_obj, &paths, "%s", ""), 0);
    assert_int_equal(amxc_llist_size(&paths), 1);
    amxc_llist_clean(&paths, amxc_string_list_it_free);
}

void test_search_fails_with_invalid_expression(UNUSED void** state) {
    amxc_llist_t paths;
    amxd_object_t* root_obj = amxd_dm_get_root(&dm);
    amxc_llist_init(&paths);

    assert_int_not_equal(amxd_object_resolve_pathf(root_obj, &paths, "RootObject.TemplateObject.[ChildObject.Param3!>220]"), 0);
    assert_int_equal(amxc_llist_size(&paths), 0);
}

void test_search_fails_with_wildcard_or_expression_on_wrong_object(UNUSED void** state) {
    amxc_llist_t paths;
    amxd_object_t* root_obj = amxd_dm_get_root(&dm);
    amxc_llist_init(&paths);

    assert_int_not_equal(amxd_object_resolve_pathf(root_obj, &paths, "RootObject.TemplateObject.*.[Param3>200]"), 0);
    assert_int_equal(amxc_llist_size(&paths), 0);
    assert_int_not_equal(amxd_object_resolve_pathf(root_obj, &paths, "RootObject.TemplateObject.*.*"), 0);
    assert_int_equal(amxc_llist_size(&paths), 0);
    assert_int_not_equal(amxd_object_resolve_pathf(root_obj, &paths, "RootObject.*"), 0);
    assert_int_equal(amxc_llist_size(&paths), 0);
    assert_int_not_equal(amxd_object_resolve_pathf(root_obj, &paths, "RootObject.[Param3>300]"), 0);
    assert_int_equal(amxc_llist_size(&paths), 0);
    assert_int_not_equal(amxd_object_resolve_pathf(root_obj, &paths, "."), 0);
    assert_int_equal(amxc_llist_size(&paths), 0);
}

void test_search_fails_with_empty_expression(UNUSED void** state) {
    amxc_llist_t paths;
    amxd_object_t* root_obj = amxd_dm_get_root(&dm);
    amxc_llist_init(&paths);

    assert_int_not_equal(amxd_object_resolve_pathf(root_obj, &paths, "RootObject.TemplateObject.[]."), 0);
    assert_int_equal(amxc_llist_size(&paths), 0);
}

void test_search_list_is_empty_when_no_objects_found(UNUSED void** state) {
    amxc_llist_t paths;
    amxd_object_t* root_obj = amxd_dm_get_root(&dm);
    amxc_llist_init(&paths);

    assert_int_not_equal(amxd_object_resolve_pathf(root_obj, &paths, "RootObject.NotExisting.[Param3>100]."), 0);
    assert_int_equal(amxc_llist_size(&paths), 0);

    assert_int_not_equal(amxd_object_resolve_pathf(root_obj, &paths, "RootObject.TemplateObject.[Param3>100].NonExisting."), 0);
    assert_int_equal(amxc_llist_size(&paths), 0);

    assert_int_equal(amxd_object_resolve_pathf(root_obj, &paths, "RootObject.TemplateObject.[Param3>500].ChildObject."), 0);
    assert_int_equal(amxc_llist_size(&paths), 0);
}

void test_search_fails_with_invalid_path_syntax(UNUSED void** state) {
    amxc_llist_t paths;
    amxd_object_t* root_obj = amxd_dm_get_root(&dm);
    amxc_llist_init(&paths);

    assert_int_not_equal(amxd_object_resolve_pathf(root_obj, &paths, "RootObject.TemplateObject.Param3>100].ChildObject"), 0);
    assert_int_equal(amxc_llist_size(&paths), 0);

    assert_int_not_equal(amxd_object_resolve_pathf(root_obj, &paths, "RootObject.TemplateObject.[Param3>100.ChildObject"), 0);
    assert_int_equal(amxc_llist_size(&paths), 0);

    assert_int_not_equal(amxd_object_resolve_pathf(root_obj, &paths, "RootObject.TemplateObject.\"Param3>100\".ChildObject"), 0);
    assert_int_equal(amxc_llist_size(&paths), 0);

    assert_int_not_equal(amxd_object_resolve_pathf(root_obj, &paths, "RootObject.TemplateObject.`Param3>100\".ChildObject"), 0);
    assert_int_equal(amxc_llist_size(&paths), 0);
}

void test_can_search_on_objects_not_in_dm(UNUSED void** state) {
    amxc_llist_t paths;
    amxd_object_t* root_obj = amxd_dm_get_root(&dm);
    amxd_object_t* obj = amxd_object_get_child(root_obj, "RootObject");
    amxc_llist_init(&paths);

    amxc_llist_it_take(&obj->it);
    assert_ptr_equal(amxd_object_get_dm(obj), NULL);

    assert_int_equal(amxd_object_resolve_pathf(obj, &paths, "TemplateObject.*.ChildObject.TemplateObject.[Alias=='SubAlias']"), 0);
    assert_int_equal(amxc_llist_size(&paths), 2);
    assert_string_equal(amxc_string_get(amxc_string_from_llist_it(amxc_llist_get_first(&paths)), 0), "RootObject.TemplateObject.2.ChildObject.TemplateObject.1.");
    amxc_llist_clean(&paths, amxc_string_list_it_free);

    assert_non_null(amxd_object_findf(obj, "TemplateObject.[Param1=='test2'].ChildObject.TemplateObject.[Alias=='SubAlias']"));

    assert_int_equal(amxd_dm_add_root_object(&dm, obj), 0);
    assert_ptr_not_equal(amxd_object_get_dm(obj), NULL);
}