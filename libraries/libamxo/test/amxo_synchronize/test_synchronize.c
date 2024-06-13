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
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <inttypes.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <cmocka.h>

#include <amxc/amxc.h>
#include <amxp/amxp_signal.h>
#include <amxp/amxp_slot.h>
#include <amxd/amxd_dm.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_parameter.h>
#include <amxd/amxd_transaction.h>
#include <amxs/amxs.h>
#include <amxo/amxo.h>
#include <amxo/amxo_hooks.h>

#include "test_synchronize.h"
#include "../../include_priv/amxo_parser_priv.h"

#include <amxc/amxc_macros.h>

static amxs_status_t translate_object(UNUSED const amxs_sync_entry_t* entry,
                                      UNUSED amxs_sync_direction_t direction,
                                      UNUSED const amxc_var_t* input,
                                      UNUSED amxc_var_t* output,
                                      UNUSED void* priv) {
    printf("Translate object\n");
    return amxs_status_ok;
}

static amxs_status_t apply_object(UNUSED const amxs_sync_entry_t* entry,
                                  UNUSED amxs_sync_direction_t direction,
                                  UNUSED amxc_var_t* data,
                                  UNUSED void* priv) {
    printf("Apply object\n");
    return amxs_status_ok;
}

static amxs_status_t translate_param(UNUSED const amxs_sync_entry_t* entry,
                                     UNUSED amxs_sync_direction_t direction,
                                     UNUSED const amxc_var_t* input,
                                     UNUSED amxc_var_t* output,
                                     UNUSED void* priv) {
    printf("Translate param\n");
    return amxs_status_ok;
}

static amxs_status_t apply_param(UNUSED const amxs_sync_entry_t* entry,
                                 UNUSED amxs_sync_direction_t direction,
                                 UNUSED amxc_var_t* data,
                                 UNUSED void* priv) {
    printf("Apply param\n");
    return amxs_status_ok;
}

void test_can_parser_synchronize_definition(UNUSED void** state) {
    amxd_dm_t dm;
    amxo_parser_t parser;
    const char* file = "./odl/valid_synchronize.odl";

    const char* odl =
        "%populate {"
        "    synchronize 'A.' <-> 'B.' {"
        "        %batch parameter param_A <-> param_B;"
        "        object 'A_template.' <-> 'B_template.' {"
        "            %batch parameter uint_A <-> uint_B;"
        "            %batch parameter string_A <-> string_B;"
        "        }"
        "    }"
        "}";

    amxd_dm_init(&dm);
    amxo_parser_init(&parser);

    assert_int_equal(amxo_parser_parse_file(&parser, file, amxd_dm_get_root(&dm)), 0);
    assert_int_equal(amxo_parser_parse_string(&parser, odl, amxd_dm_get_root(&dm)), 0);
    assert_non_null(parser.sync_contexts);
    assert_false(amxc_llist_is_empty(parser.sync_contexts));

    assert_true(amxo_parser_get_sync_type(&parser) == amxs_sync_type_ctx);

    amxo_parser_clean(&parser);
    amxd_dm_clean(&dm);
}

void test_can_parser_synchronize_definition_alternate(UNUSED void** state) {
    amxd_dm_t dm;
    amxo_parser_t parser;
    const char* file = "./odl/valid_synchronize.odl";

    const char* odl1 =
        "%populate {"
        "    synchronize 'A.' <-> 'B.' {"
        "        %batch parameter param_A -> param_B;"
        "        %batch parameter param_A <- param_B;"
        "    }"
        "}";

    const char* odl2 =
        "%populate {"
        "    synchronize 'A.' <-> 'B.' {"
        "        %batch parameter param_A -> param_B;"
        "        %batch parameter param_B -> param_A;"
        "    }"
        "}";

    amxd_dm_init(&dm);
    amxo_parser_init(&parser);

    assert_int_equal(amxo_parser_parse_file(&parser, file, amxd_dm_get_root(&dm)), 0);
    assert_int_equal(amxo_parser_parse_string(&parser, odl1, amxd_dm_get_root(&dm)), 0);
    assert_non_null(parser.sync_contexts);
    assert_false(amxc_llist_is_empty(parser.sync_contexts));

    assert_true(amxo_parser_get_sync_type(&parser) == amxs_sync_type_ctx);

    assert_int_equal(amxo_parser_parse_string(&parser, odl2, amxd_dm_get_root(&dm)), 0);
    assert_non_null(parser.sync_contexts);
    assert_false(amxc_llist_is_empty(parser.sync_contexts));
    assert_int_equal(amxc_llist_size(parser.sync_contexts), 2);

    amxo_parser_clean(&parser);
    amxd_dm_clean(&dm);
}

void test_can_parser_synchronize_definition_with_vars(UNUSED void** state) {
    amxd_dm_t dm;
    amxo_parser_t parser;
    const char* file = "./odl/valid_synchronize.odl";

    const char* odl =
        "%populate {"
        "    synchronize '${prefix_}C.' <-> '${prefix_}D.' {"
        "        %batch parameter '${prefix_}string_C' <-> '${prefix_}string_D';"
        "        object '${prefix_}C_template.' <-> '${prefix_}D_template.' {"
        "            %batch parameter '${prefix_}string_C' <-> '${prefix_}string_D';"
        "        }"
        "    }"
        "}";

    amxd_dm_init(&dm);
    amxo_parser_init(&parser);

    assert_int_equal(amxo_parser_parse_file(&parser, file, amxd_dm_get_root(&dm)), 0);
    assert_int_equal(amxo_parser_parse_string(&parser, odl, amxd_dm_get_root(&dm)), 0);
    assert_non_null(parser.sync_contexts);
    assert_false(amxc_llist_is_empty(parser.sync_contexts));

    assert_true(amxo_parser_get_sync_type(&parser) == amxs_sync_type_ctx);

    amxo_parser_clean(&parser);
    amxd_dm_clean(&dm);
}

void test_can_parser_synchronize_definition_with_cb(UNUSED void** state) {
    amxd_dm_t dm;
    amxo_parser_t parser;
    const char* file = "./odl/valid_synchronize.odl";

    const char* odl =
        "%populate {"
        "    synchronize 'A.' <-> 'B.' {"
        "        parameter param_A <-> param_B {"
        "            on action translate call translate_param;"
        "            on action apply call apply_param;"
        "        }"
        "        object 'A_template.' <-> 'B_template.' {"
        "            on action translate call translate_object;"
        "            on action apply call apply_object;"
        "            %batch parameter uint_A <-> uint_B;"
        "            %batch parameter string_A <-> string_B;"
        "        }"
        "    }"
        "}";

    amxd_dm_init(&dm);
    amxo_parser_init(&parser);

    amxo_resolver_ftab_add(&parser, "translate_object", AMXO_FUNC(translate_object));
    amxo_resolver_ftab_add(&parser, "translate_param", AMXO_FUNC(translate_param));
    amxo_resolver_ftab_add(&parser, "apply_object", AMXO_FUNC(apply_object));
    amxo_resolver_ftab_add(&parser, "apply_param", AMXO_FUNC(apply_param));

    assert_int_equal(amxo_parser_parse_file(&parser, file, amxd_dm_get_root(&dm)), 0);
    assert_int_equal(amxo_parser_parse_string(&parser, odl, amxd_dm_get_root(&dm)), 0);
    assert_non_null(parser.sync_contexts);
    assert_false(amxc_llist_is_empty(parser.sync_contexts));

    amxo_parser_clean(&parser);
    amxd_dm_clean(&dm);
}

void test_parser_sync_duplicates_fails(UNUSED void** state) {
    amxd_dm_t dm;
    amxo_parser_t parser;
    const char* file = "./odl/valid_synchronize.odl";

    const char* odl1 =
        "%populate {"
        "    synchronize 'A.' <-> 'B.' {"
        "        %batch parameter param_A -> param_B;"
        "        %batch parameter param_A -> param_B;"
        "    }"
        "}";

    amxd_dm_init(&dm);
    amxo_parser_init(&parser);

    assert_int_equal(amxo_parser_parse_file(&parser, file, amxd_dm_get_root(&dm)), 0);
    assert_int_not_equal(amxo_parser_parse_string(&parser, odl1, amxd_dm_get_root(&dm)), 0);
    assert_non_null(parser.sync_contexts);

    amxo_parser_clean(&parser);
    amxd_dm_clean(&dm);
}

void test_parse_empty_synchronize_context_fails(UNUSED void** state) {
    amxd_dm_t dm;
    amxo_parser_t parser;
    const char* file = "./odl/valid_synchronize.odl";

    const char* odl =
        "%populate {"
        "    synchronize 'A.' <-> 'B.' { }"
        "}";

    amxd_dm_init(&dm);
    amxo_parser_init(&parser);

    assert_int_equal(amxo_parser_parse_file(&parser, file, amxd_dm_get_root(&dm)), 0);
    assert_int_not_equal(amxo_parser_parse_string(&parser, odl, amxd_dm_get_root(&dm)), 0);
    assert_null(parser.sync_contexts);

    amxo_parser_clean(&parser);
    amxd_dm_clean(&dm);
}

void test_parse_sync_invalid_context_paths_fails(UNUSED void** state) {
    amxd_dm_t dm;
    amxo_parser_t parser;
    const char* file = "./odl/valid_synchronize.odl";

    const char* odl1 =
        "%populate {"
        "    synchronize 'A' -> 'B' {"
        "        %batch parameter param_A -> param_B;"
        "    }"
        "}";

    const char* odl2 =
        "%populate {"
        "    synchronize '' -> '' {"
        "        %batch parameter param_A -> param_B;"
        "    }"
        "}";

    amxd_dm_init(&dm);
    amxo_parser_init(&parser);

    assert_int_equal(amxo_parser_parse_file(&parser, file, amxd_dm_get_root(&dm)), 0);
    assert_int_not_equal(amxo_parser_parse_string(&parser, odl1, amxd_dm_get_root(&dm)), 0);
    assert_null(parser.sync_contexts);

    assert_int_not_equal(amxo_parser_parse_string(&parser, odl2, amxd_dm_get_root(&dm)), 0);
    assert_null(parser.sync_contexts);

    amxo_parser_clean(&parser);
    amxd_dm_clean(&dm);
}

void test_parse_empty_synchronize_object_fails(UNUSED void** state) {
    amxd_dm_t dm;
    amxo_parser_t parser;
    const char* file = "./odl/valid_synchronize.odl";

    const char* odl =
        "%populate {"
        "    synchronize 'A.' <-> 'B.' {"
        "        object 'A_template.' <-> 'B_template.' {"
        "        }"
        "    }"
        "}";

    amxd_dm_init(&dm);
    amxo_parser_init(&parser);

    assert_int_equal(amxo_parser_parse_file(&parser, file, amxd_dm_get_root(&dm)), 0);
    assert_int_not_equal(amxo_parser_parse_string(&parser, odl, amxd_dm_get_root(&dm)), 0);
    assert_null(parser.sync_contexts);

    amxo_parser_clean(&parser);
    amxd_dm_clean(&dm);
}

void test_parse_synchronize_object_fails_without_entries(UNUSED void** state) {
    amxd_dm_t dm;
    amxo_parser_t parser;
    const char* file = "./odl/valid_synchronize.odl";

    const char* odl =
        "%populate {"
        "    synchronize 'A.' <-> 'B.' {"
        "        object 'A_template.' <-> 'B_template.' {"
        "            on action translate call object_translate;"
        "        }"
        "    }"
        "}";

    amxd_dm_init(&dm);
    amxo_parser_init(&parser);

    amxo_resolver_ftab_add(&parser, "param_translate", AMXO_FUNC(translate_object));

    assert_int_equal(amxo_parser_parse_file(&parser, file, amxd_dm_get_root(&dm)), 0);
    assert_int_not_equal(amxo_parser_parse_string(&parser, odl, amxd_dm_get_root(&dm)), 0);
    assert_null(parser.sync_contexts);

    amxo_parser_clean(&parser);
    amxd_dm_clean(&dm);
}

void test_parse_batch_parameter_with_cb_fails(UNUSED void** state) {
    amxd_dm_t dm;
    amxo_parser_t parser;
    const char* file = "./odl/valid_synchronize.odl";

    const char* odl1 =
        "%populate {"
        "    synchronize 'A.' <-> 'B.' {"
        "        %batch parameter param_A <-> param_B {"
        "            on action translate call param_translate;"
        "        }"
        "    }"
        "}";
    const char* odl2 =
        "%populate {"
        "    synchronize 'A.' <-> 'B.' {"
        "        %batch parameter param_A <-> param_B {"
        "            on action apply call param_apply;"
        "        }"
        "    }"
        "}";

    amxd_dm_init(&dm);
    amxo_parser_init(&parser);

    amxo_resolver_ftab_add(&parser, "param_translate", AMXO_FUNC(translate_param));
    amxo_resolver_ftab_add(&parser, "param_apply", AMXO_FUNC(apply_param));

    assert_int_equal(amxo_parser_parse_file(&parser, file, amxd_dm_get_root(&dm)), 0);
    assert_int_not_equal(amxo_parser_parse_string(&parser, odl1, amxd_dm_get_root(&dm)), 0);
    assert_null(parser.sync_contexts);

    assert_int_not_equal(amxo_parser_parse_string(&parser, odl2, amxd_dm_get_root(&dm)), 0);
    assert_null(parser.sync_contexts);

    amxo_parser_clean(&parser);
    amxd_dm_clean(&dm);
}

void test_create_sync_tree_fails_with_conflicting_directions(UNUSED void** state) {
    amxd_dm_t dm;
    amxo_parser_t parser;
    const char* file = "./odl/valid_synchronize.odl";

    const char* odl1 =
        "%populate {"
        "    synchronize 'A.' -> 'B.' {"
        "        %batch parameter param_A <- param_B;"
        "    }"
        "}";
    const char* odl2 =
        "%populate {"
        "    synchronize 'A.' <- 'B.' {"
        "        object 'A_template.' -> 'B_template.' {"
        "            %batch parameter uint_A <-> uint_B;"
        "        }"
        "    }"
        "}";

    amxd_dm_init(&dm);
    amxo_parser_init(&parser);

    assert_int_equal(amxo_parser_parse_file(&parser, file, amxd_dm_get_root(&dm)), 0);
    assert_int_not_equal(amxo_parser_parse_string(&parser, odl1, amxd_dm_get_root(&dm)), 0);
    assert_null(parser.sync_contexts);

    assert_int_not_equal(amxo_parser_parse_string(&parser, odl2, amxd_dm_get_root(&dm)), 0);
    assert_null(parser.sync_contexts);

    amxo_parser_clean(&parser);
    amxd_dm_clean(&dm);
}

void test_parse_synchronize_with_invalid_action_fails(UNUSED void** state) {
    amxd_dm_t dm;
    amxo_parser_t parser;
    const char* file = "./odl/valid_synchronize.odl";

    const char* odl =
        "%populate {"
        "    synchronize 'A.' <-> 'B.' {"
        "        %batch parameter param_A <-> param_B {"
        "            on action read call data_read;"
        "        }"
        "    }"
        "}";

    amxd_dm_init(&dm);
    amxo_parser_init(&parser);

    amxo_resolver_ftab_add(&parser, "data_read", AMXO_FUNC(translate_param));

    assert_int_equal(amxo_parser_parse_file(&parser, file, amxd_dm_get_root(&dm)), 0);
    assert_int_not_equal(amxo_parser_parse_string(&parser, odl, amxd_dm_get_root(&dm)), 0);
    assert_null(parser.sync_contexts);

    amxo_parser_clean(&parser);
    amxd_dm_clean(&dm);
}

void test_synchronize_start_fails_when_no_bus_connections(UNUSED void** state) {
    amxd_dm_t dm;
    amxo_parser_t parser;
    const char* file = "./odl/valid_synchronize.odl";

    const char* odl =
        "%populate {"
        "    synchronize 'A.' <-> 'B.' {"
        "        %batch parameter param_A <-> param_B;"
        "        object 'A_template.' <-> 'B_template.' {"
        "            %batch parameter uint_A <-> uint_B;"
        "            %batch parameter string_A <-> string_B;"
        "        }"
        "    }"
        "}";

    amxd_dm_init(&dm);
    amxo_parser_init(&parser);

    assert_int_equal(amxo_parser_parse_file(&parser, file, amxd_dm_get_root(&dm)), 0);
    assert_int_equal(amxo_parser_parse_string(&parser, odl, amxd_dm_get_root(&dm)), 0);
    assert_non_null(parser.sync_contexts);
    assert_false(amxc_llist_is_empty(parser.sync_contexts));

    assert_int_not_equal(amxo_parser_start_synchronize(&parser), 0);

    amxo_parser_clean(&parser);
    amxd_dm_clean(&dm);
}

void test_can_setup_synchronization(UNUSED void** state) {
    amxd_dm_t* dm = amxut_bus_dm();
    amxo_parser_t* parser = amxut_bus_parser();
    amxd_object_t* object = NULL;
    amxd_trans_t transaction;
    char* txt = NULL;

    const char* file = "./odl/valid_synchronize.odl";

    const char* odl =
        "%populate {"
        "    synchronize 'A.' <-> 'B.' {"
        "        %batch parameter param_A <-> param_B;"
        "        object 'A_template.' <-> 'B_template.' {"
        "            %batch parameter uint_A <-> uint_B;"
        "            %batch parameter string_A <-> string_B;"
        "        }"
        "    }"
        "}";


    amxd_trans_init(&transaction);

    assert_int_equal(amxo_parser_parse_file(parser, file, amxd_dm_get_root(dm)), 0);
    assert_int_equal(amxo_parser_parse_string(parser, odl, amxd_dm_get_root(dm)), 0);
    assert_non_null(parser->sync_contexts);
    assert_false(amxc_llist_is_empty(parser->sync_contexts));

    assert_int_equal(amxo_parser_start_synchronize(parser), 0);

    object = amxd_dm_findf(dm, "B");
    assert_non_null(object);
    assert_int_equal(amxd_object_get_value(uint32_t, object, "param_B", NULL), 2);

    amxd_trans_select_pathf(&transaction, "B.B_template.");
    amxd_trans_add_inst(&transaction, 0, NULL);
    assert_int_equal(amxd_trans_apply(&transaction, dm), 0);
    amxd_trans_clean(&transaction);

    while(amxp_signal_read() == 0) {
    }

    object = amxd_dm_findf(dm, "A.A_template.1.");
    assert_non_null(object);
    assert_int_equal(amxd_object_get_value(uint32_t, object, "uint_A", NULL), 3);
    txt = amxd_object_get_value(cstring_t, object, "string_A", NULL);
    assert_string_equal(txt, "I am B");
    free(txt);

    amxo_parser_stop_synchronize(parser);
}

void test_can_setup_synchronization_with_vars(UNUSED void** state) {
    amxd_dm_t* dm = amxut_bus_dm();
    amxo_parser_t* parser = amxut_bus_parser();

    const char* file = "./odl/valid_synchronize.odl";

    const char* odl =
        "%populate {"
        "    synchronize '${prefix_}C.' <-> '${prefix_}D.' {"
        "        %batch parameter '${prefix_}string_C' <-> '${prefix_}string_D';"
        "        object '${prefix_}C_template.' <-> '${prefix_}D_template.' {"
        "            %batch parameter '${prefix_}string_C' <-> '${prefix_}string_D';"
        "        }"
        "    }"
        "}";

    assert_int_equal(amxo_parser_parse_file(parser, file, amxd_dm_get_root(dm)), 0);
    assert_int_equal(amxo_parser_parse_string(parser, odl, amxd_dm_get_root(dm)), 0);
    assert_non_null(parser->sync_contexts);
    assert_false(amxc_llist_is_empty(parser->sync_contexts));

    assert_int_equal(amxo_parser_start_synchronize(parser), 0);
    amxo_parser_stop_synchronize(parser);
}


void test_synchronization_respects_direction(UNUSED void** state) {
    amxd_dm_t* dm = amxut_bus_dm();
    amxo_parser_t* parser = amxut_bus_parser();
    amxd_object_t* object = NULL;
    amxd_trans_t transaction;
    char* txt = NULL;

    const char* file = "./odl/valid_synchronize.odl";

    const char* odl =
        "%populate {"
        "    synchronize 'A.' -> 'B.' {"
        "        parameter param_A -> param_B;"
        "        object 'A_template.' -> 'B_template.' {"
        "            parameter uint_A -> uint_B;"
        "            parameter string_A -> string_B;"
        "        }"
        "    }"
        "}";


    amxd_trans_init(&transaction);

    assert_int_equal(amxo_parser_parse_file(parser, file, amxd_dm_get_root(dm)), 0);
    assert_int_equal(amxo_parser_parse_string(parser, odl, amxd_dm_get_root(dm)), 0);
    assert_non_null(parser->sync_contexts);
    assert_false(amxc_llist_is_empty(parser->sync_contexts));

    assert_int_equal(amxo_parser_start_synchronize(parser), 0);

    object = amxd_dm_findf(dm, "A");
    assert_non_null(object);
    assert_int_equal(amxd_object_get_value(uint32_t, object, "param_A", NULL), 2);

    amxd_trans_select_pathf(&transaction, "A.A_template.");
    amxd_trans_add_inst(&transaction, 0, NULL);
    assert_int_equal(amxd_trans_apply(&transaction, dm), 0);
    amxd_trans_clean(&transaction);

    while(amxp_signal_read() == 0) {
    }

    object = amxd_dm_findf(dm, "B.B_template.1.");
    assert_non_null(object);
    assert_int_equal(amxd_object_get_value(uint32_t, object, "uint_B", NULL), 1);
    txt = amxd_object_get_value(cstring_t, object, "string_B", NULL);
    assert_string_equal(txt, "I am A");
    free(txt);

    amxd_trans_select_pathf(&transaction, "B.B_template.1.");
    amxd_trans_set_value(cstring_t, &transaction, "string_B", "Hello");
    assert_int_equal(amxd_trans_apply(&transaction, dm), 0);
    amxd_trans_clean(&transaction);

    while(amxp_signal_read() == 0) {
    }

    object = amxd_dm_findf(dm, "A.A_template.1.");
    assert_non_null(object);
    txt = amxd_object_get_value(cstring_t, object, "string_A", NULL);
    assert_string_equal(txt, "I am A");
    free(txt);

    amxo_parser_stop_synchronize(parser);
}

void test_synchronization_respects_direction_2(UNUSED void** state) {
    amxd_dm_t* dm = amxut_bus_dm();
    amxo_parser_t* parser = amxut_bus_parser();
    amxd_object_t* object = NULL;
    amxd_trans_t transaction;
    char* txt = NULL;

    const char* file = "./odl/valid_synchronize.odl";

    const char* odl =
        "%populate {"
        "    synchronize 'A.' <-> 'B.' {"
        "        parameter param_A <-> param_B;"
        "        object 'A_template.' -> 'B_template.' {"
        "            parameter uint_A -> uint_B;"
        "            parameter string_A -> string_B;"
        "        }"
        "    }"
        "}";


    amxd_trans_init(&transaction);

    assert_int_equal(amxo_parser_parse_file(parser, file, amxd_dm_get_root(dm)), 0);
    assert_int_equal(amxo_parser_parse_string(parser, odl, amxd_dm_get_root(dm)), 0);
    assert_non_null(parser->sync_contexts);
    assert_false(amxc_llist_is_empty(parser->sync_contexts));

    assert_int_equal(amxo_parser_start_synchronize(parser), 0);

    object = amxd_dm_findf(dm, "A");
    assert_non_null(object);
    assert_int_equal(amxd_object_get_value(uint32_t, object, "param_A", NULL), 2);

    amxd_trans_select_pathf(&transaction, "A.A_template.");
    amxd_trans_add_inst(&transaction, 0, NULL);
    assert_int_equal(amxd_trans_apply(&transaction, dm), 0);
    amxd_trans_clean(&transaction);

    while(amxp_signal_read() == 0) {
    }

    object = amxd_dm_findf(dm, "B.B_template.1.");
    assert_non_null(object);
    assert_int_equal(amxd_object_get_value(uint32_t, object, "uint_B", NULL), 1);
    txt = amxd_object_get_value(cstring_t, object, "string_B", NULL);
    assert_string_equal(txt, "I am A");
    free(txt);

    amxd_trans_select_pathf(&transaction, "B.B_template.1.");
    amxd_trans_set_value(cstring_t, &transaction, "string_B", "Hello");
    assert_int_equal(amxd_trans_apply(&transaction, dm), 0);
    amxd_trans_clean(&transaction);

    while(amxp_signal_read() == 0) {
    }

    object = amxd_dm_findf(dm, "A.A_template.1.");
    assert_non_null(object);
    txt = amxd_object_get_value(cstring_t, object, "string_A", NULL);
    assert_string_equal(txt, "I am A");
    free(txt);

    amxo_parser_stop_synchronize(parser);
}

void test_synchronization_respects_direction_3(UNUSED void** state) {
    amxd_dm_t* dm = amxut_bus_dm();
    amxo_parser_t* parser = amxut_bus_parser();
    amxd_object_t* object = NULL;
    amxd_trans_t transaction;
    char* txt = NULL;

    const char* file = "./odl/valid_synchronize.odl";

    const char* odl =
        "%populate {"
        "    synchronize 'A.' <-> 'B.' {"
        "        %batch parameter param_A <-> param_B;"
        "        object 'A_template.' <-> 'B_template.' {"
        "            %batch parameter uint_A -> uint_B;"
        "            %batch parameter string_A -> string_B;"
        "        }"
        "    }"
        "}";


    amxd_trans_init(&transaction);

    assert_int_equal(amxo_parser_parse_file(parser, file, amxd_dm_get_root(dm)), 0);
    assert_int_equal(amxo_parser_parse_string(parser, odl, amxd_dm_get_root(dm)), 0);
    assert_non_null(parser->sync_contexts);
    assert_false(amxc_llist_is_empty(parser->sync_contexts));

    assert_int_equal(amxo_parser_start_synchronize(parser), 0);

    object = amxd_dm_findf(dm, "A");
    assert_non_null(object);
    assert_int_equal(amxd_object_get_value(uint32_t, object, "param_A", NULL), 2);

    amxd_trans_select_pathf(&transaction, "A.A_template.");
    amxd_trans_add_inst(&transaction, 0, NULL);
    assert_int_equal(amxd_trans_apply(&transaction, dm), 0);
    amxd_trans_clean(&transaction);

    while(amxp_signal_read() == 0) {
    }

    object = amxd_dm_findf(dm, "B.B_template.1.");
    assert_non_null(object);
    assert_int_equal(amxd_object_get_value(uint32_t, object, "uint_B", NULL), 1);
    txt = amxd_object_get_value(cstring_t, object, "string_B", NULL);
    assert_string_equal(txt, "I am A");
    free(txt);

    amxd_trans_select_pathf(&transaction, "B.B_template.1.");
    amxd_trans_set_value(cstring_t, &transaction, "string_B", "Hello");
    assert_int_equal(amxd_trans_apply(&transaction, dm), 0);
    amxd_trans_clean(&transaction);

    while(amxp_signal_read() == 0) {
    }

    object = amxd_dm_findf(dm, "A.A_template.1.");
    assert_non_null(object);
    txt = amxd_object_get_value(cstring_t, object, "string_A", NULL);
    assert_string_equal(txt, "I am A");
    free(txt);

    amxo_parser_stop_synchronize(parser);
}

void test_synchronization_can_set_readonly(UNUSED void** state) {
    amxd_dm_t* dm = amxut_bus_dm();
    amxo_parser_t* parser = amxut_bus_parser();
    amxd_object_t* object = NULL;
    amxd_trans_t transaction;
    char* txt = NULL;

    const char* file = "./odl/valid_synchronize.odl";

    const char* odl =
        "%populate {"
        "    synchronize 'A.' <- 'B.' {"
        "        %batch parameter param_A <- param_B;"
        "        object 'A_template.' <- 'B_template.' {"
        "            %batch parameter uint_A <- uint_B;"
        "            %batch parameter ReadOnlyText <- ReadOnlyText;"
        "        }"
        "    }"
        "}";


    amxd_trans_init(&transaction);

    assert_int_equal(amxo_parser_parse_file(parser, file, amxd_dm_get_root(dm)), 0);
    assert_int_equal(amxo_parser_parse_string(parser, odl, amxd_dm_get_root(dm)), 0);
    assert_non_null(parser->sync_contexts);
    assert_false(amxc_llist_is_empty(parser->sync_contexts));

    assert_int_equal(amxo_parser_start_synchronize(parser), 0);

    object = amxd_dm_findf(dm, "B");
    assert_non_null(object);

    amxd_trans_select_pathf(&transaction, "B.B_template.");
    amxd_trans_add_inst(&transaction, 0, NULL);
    assert_int_equal(amxd_trans_apply(&transaction, dm), 0);
    amxd_trans_clean(&transaction);

    while(amxp_signal_read() == 0) {
    }

    object = amxd_dm_findf(dm, "A.A_template.1.");
    assert_non_null(object);
    txt = amxd_object_get_value(cstring_t, object, "ReadOnlyText", NULL);
    assert_string_equal(txt, "5678");
    free(txt);

    amxo_parser_stop_synchronize(parser);
}

void test_synchronization_can_use_template(UNUSED void** state) {
    amxd_dm_t* dm = amxut_bus_dm();
    amxo_parser_t* parser = amxut_bus_parser();
    amxd_object_t* object = NULL;
    amxd_trans_t transaction;
    char* txt = NULL;
    amxs_sync_ctx_t* sync_ctx = NULL;

    const char* file = "./odl/valid_synchronize.odl";

    const char* odl =
        "%populate {"
        "    synchronize 'A.A_template.{i}.' <-> 'B.B_template.{i}.' as 'A2B'{"
        "        %batch parameter uint_A <-> uint_B;"
        "        %batch parameter string_A <-> string_B;"
        "    }"
        "}";


    amxd_trans_init(&transaction);

    assert_int_equal(amxo_parser_parse_file(parser, file, amxd_dm_get_root(dm)), 0);
    assert_int_equal(amxo_parser_parse_string(parser, odl, amxd_dm_get_root(dm)), 0);
    assert_non_null(parser->sync_contexts);
    assert_false(amxc_llist_is_empty(parser->sync_contexts));

    assert_int_equal(amxo_parser_start_synchronize(parser), 0);

    object = amxd_dm_findf(dm, "A");
    assert_non_null(object);

    amxd_trans_select_pathf(&transaction, "A.A_template.");
    amxd_trans_add_inst(&transaction, 0, NULL);
    assert_int_equal(amxd_trans_apply(&transaction, dm), 0);
    amxd_trans_clean(&transaction);

    object = amxd_dm_findf(dm, "B");
    assert_non_null(object);

    amxd_trans_select_pathf(&transaction, "B.B_template.");
    amxd_trans_add_inst(&transaction, 0, NULL);
    assert_int_equal(amxd_trans_apply(&transaction, dm), 0);
    amxd_trans_clean(&transaction);

    while(amxp_signal_read() == 0) {
    }

    sync_ctx = amxo_parser_new_sync_ctx("A2B", "A.A_template.1.", "B.B_template.1.");
    assert_non_null(sync_ctx);
    amxs_sync_ctx_start_sync(sync_ctx);

    amxd_trans_select_pathf(&transaction, "B.B_template.1.");
    amxd_trans_set_value(cstring_t, &transaction, "string_B", "Hello");
    assert_int_equal(amxd_trans_apply(&transaction, dm), 0);
    amxd_trans_clean(&transaction);

    while(amxp_signal_read() == 0) {
    }

    object = amxd_dm_findf(dm, "A.A_template.1.");
    assert_non_null(object);
    txt = amxd_object_get_value(cstring_t, object, "string_A", NULL);
    assert_string_equal(txt, "Hello");
    free(txt);

    amxs_sync_ctx_delete(&sync_ctx);
    assert_null(sync_ctx);
    amxo_parser_stop_synchronize(parser);
}

void test_synchronization_template_must_use_supported_path(UNUSED void** state) {
    amxd_dm_t* dm = amxut_bus_dm();
    amxo_parser_t* parser = amxut_bus_parser();

    const char* file = "./odl/valid_synchronize.odl";

    const char* odl1 =
        "%populate {"
        "    synchronize 'A.A_template.1.' <-> 'B.B_template.5.' as 'A1_2_B5'{"
        "        %batch parameter uint_A <-> uint_B;"
        "        %batch parameter string_A <-> string_B;"
        "    }"
        "}";
    const char* odl2 =
        "%populate {"
        "    synchronize 'A.A_template.[Alias == \"test\"].' <-> 'B.B_template.[Alias == \"mapped\"].' as 'A2B'{"
        "        %batch parameter uint_A <-> uint_B;"
        "        %batch parameter string_A <-> string_B;"
        "    }"
        "}";
    const char* odl3 =
        "%populate {"
        "    synchronize 'A.' <-> 'B.' as 'A2B_valid'{"
        "        %batch parameter param_A <-> param_B;"
        "    }"
        "}";


    assert_int_equal(amxo_parser_parse_file(parser, file, amxd_dm_get_root(dm)), 0);
    assert_int_not_equal(amxo_parser_parse_string(parser, odl1, amxd_dm_get_root(dm)), 0);
    assert_int_not_equal(amxo_parser_parse_string(parser, odl2, amxd_dm_get_root(dm)), 0);
    assert_int_equal(amxo_parser_parse_string(parser, odl3, amxd_dm_get_root(dm)), 0);
}
