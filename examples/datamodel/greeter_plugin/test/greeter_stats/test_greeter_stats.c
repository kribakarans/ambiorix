/****************************************************************************
**
** Copyright (c) 2020 SoftAtHome
**
** Redistribution and use in source and binary forms, with or
** without modification, are permitted provided that the following
** conditions are met:
**
** 1. Redistributions of source code must retain the above copyright
** notice, this list of conditions and the following disclaimer.
**
** 2. Redistributions in binary form must reproduce the above
** copyright notice, this list of conditions and the following
** disclaimer in the documentation and/or other materials provided
** with the distribution.
**
** Subject to the terms and conditions of this license, each
** copyright holder and contributor hereby grants to those receiving
** rights under this license a perpetual, worldwide, non-exclusive,
** no-charge, royalty-free, irrevocable (except for failure to
** satisfy the conditions of this license) patent license to make,
** have made, use, offer to sell, sell, import, and otherwise
** transfer this software, where such license applies only to those
** patent claims, already acquired or hereafter acquired, licensable
** by such copyright holder or contributor that are necessarily
** infringed by:
**
** (a) their Contribution(s) (the licensed copyrights of copyright
** holders and non-copyrightable additions of contributors, in
** source or binary form) alone; or
**
** (b) combination of their Contribution(s) with the work of
** authorship to which such Contribution(s) was added by such
** copyright holder or contributor, if, at the time the Contribution
** is added, such addition causes such combination to be necessarily
** infringed. The patent license shall not apply to any other
** combinations which include the Contribution.
**
** Except as expressly stated above, no rights or licenses from any
** copyright holder or contributor is granted under this license,
** whether expressly, by implication, estoppel or otherwise.
**
** DISCLAIMER
**
** THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
** CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
** INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
** MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
** DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR
** CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
** SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
** LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
** USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
** AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
** LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
** ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
** POSSIBILITY OF SUCH DAMAGE.
**
****************************************************************************/
#include <sys/stat.h>

#include <stdlib.h>
#include <stdio.h>
#include <setjmp.h>
#include <stdarg.h>
#include <cmocka.h>

#include <amxc/amxc_macros.h>
#include <amxc/amxc.h>
#include <amxp/amxp.h>

#include <amxd/amxd_dm.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_transaction.h>

#include <amxo/amxo.h>

#include "greeter.h"
#include "dm_greeter.h"
#include "test_greeter_stats.h"

#define GET_KEY(v, k) amxc_var_get_key(v, k, AMXC_VAR_FLAG_DEFAULT)
#define GET_IDX(v, i) amxc_var_get_index(v, i, AMXC_VAR_FLAG_DEFAULT)
#define CHAR(v) amxc_var_constcast(cstring_t, v)
#define UINT32(v) amxc_var_constcast(uint32_t, v)
#define BOOL(v) amxc_var_constcast(bool, v)

static amxd_dm_t dm;
static amxo_parser_t parser;
static const char* odl_defs = "../../odl/greeter_definition.odl";

static void handle_events(void) {
    printf("Handling events ");
    while(amxp_signal_read() == 0) {
        printf(".");
    }
    printf("\n");
}

int test_greeter_setup(UNUSED void** state) {
    amxd_object_t* root_obj = NULL;
    amxc_var_t save_file;
    amxd_trans_t trans;

    amxc_var_init(&save_file);
    assert_int_equal(amxd_dm_init(&dm), amxd_status_ok);
    assert_int_equal(amxo_parser_init(&parser), 0);

    root_obj = amxd_dm_get_root(&dm);
    assert_non_null(root_obj);

    amxc_var_set(cstring_t, &save_file, "./default_save_file.odl");
    amxo_parser_set_config(&parser, "save_file", &save_file);
    amxc_var_clean(&save_file);

    assert_int_equal(amxo_resolver_ftab_add(&parser, "Greeter.Statistics.stats_read", AMXO_FUNC(_stats_read)), 0);
    assert_int_equal(amxo_resolver_ftab_add(&parser, "Greeter.Statistics.stats_list", AMXO_FUNC(_stats_list)), 0);
    assert_int_equal(amxo_resolver_ftab_add(&parser, "Greeter.Statistics.stats_describe", AMXO_FUNC(_stats_describe)), 0);
    assert_int_equal(amxo_resolver_ftab_add(&parser, "Greeter.Statistics.reset", AMXO_FUNC(_Statistics_reset)), 0);
    assert_int_equal(amxo_resolver_ftab_add(&parser, "Greeter.Statistics.periodic_inform", AMXO_FUNC(_periodic_inform)), 0);

    assert_int_equal(amxo_parser_parse_file(&parser, odl_defs, root_obj), 0);

    _greeter_main(0, &dm, &parser);

    handle_events();

    amxd_trans_init(&trans);
    amxd_trans_select_pathf(&trans, "Greeter");
    amxd_trans_set_value(cstring_t, &trans, "State", "Start");
    assert_int_equal(amxd_trans_apply(&trans, &dm), amxd_status_ok);
    amxd_trans_clean(&trans);

    handle_events();

    return 0;
}

int test_greeter_teardown(UNUSED void** state) {
    _greeter_main(1, &dm, &parser);

    amxo_parser_clean(&parser);
    amxd_dm_clean(&dm);

    return 0;
}

void test_can_read_stats(UNUSED void** state) {
    amxd_object_t* stats = amxd_dm_findf(&dm, "Greeter.Statistics");
    amxc_var_t* values = NULL;
    amxc_var_t args;
    amxc_var_t ret;

    assert_non_null(stats);

    amxc_var_init(&args);
    amxc_var_init(&ret);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxd_object_invoke_function(stats, "_get", &args, &ret), amxd_status_ok);
    assert_int_equal(amxc_var_type_of(&ret), AMXC_VAR_ID_HTABLE);
    values = amxc_var_get_key(&ret, "Greeter.Statistics.", AMXC_VAR_FLAG_DEFAULT);
    assert_non_null(values);

    assert_non_null(amxc_var_get_key(values, "AddHistoryCount", AMXC_VAR_FLAG_DEFAULT));
    assert_non_null(amxc_var_get_key(values, "DelHistoryCount", AMXC_VAR_FLAG_DEFAULT));
    assert_non_null(amxc_var_get_key(values, "EventCount", AMXC_VAR_FLAG_DEFAULT));

    amxc_var_clean(&args);
    amxc_var_clean(&ret);
}

void test_can_read_specific_parameter_using_rel_path(UNUSED void** state) {
    amxd_object_t* stats = amxd_dm_findf(&dm, "Greeter.");
    amxc_var_t* values = NULL;
    amxc_var_t args;
    amxc_var_t ret;

    assert_non_null(stats);

    amxc_var_init(&args);
    amxc_var_init(&ret);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &args, "rel_path", "Statistics.EventCount");
    assert_int_equal(amxd_object_invoke_function(stats, "_get", &args, &ret), amxd_status_ok);
    assert_int_equal(amxc_var_type_of(&ret), AMXC_VAR_ID_HTABLE);
    values = amxc_var_get_key(&ret, "Greeter.Statistics.", AMXC_VAR_FLAG_DEFAULT);
    assert_non_null(values);

    assert_null(amxc_var_get_key(values, "AddHistoryCount", AMXC_VAR_FLAG_DEFAULT));
    assert_null(amxc_var_get_key(values, "DelHistoryCount", AMXC_VAR_FLAG_DEFAULT));
    assert_non_null(amxc_var_get_key(values, "EventCount", AMXC_VAR_FLAG_DEFAULT));

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &args, "rel_path", "Statistics.DelHistoryCount");
    assert_int_equal(amxd_object_invoke_function(stats, "_get", &args, &ret), amxd_status_ok);
    assert_int_equal(amxc_var_type_of(&ret), AMXC_VAR_ID_HTABLE);
    values = amxc_var_get_key(&ret, "Greeter.Statistics.", AMXC_VAR_FLAG_DEFAULT);
    assert_non_null(values);

    assert_null(amxc_var_get_key(values, "AddHistoryCount", AMXC_VAR_FLAG_DEFAULT));
    assert_non_null(amxc_var_get_key(values, "DelHistoryCount", AMXC_VAR_FLAG_DEFAULT));
    assert_null(amxc_var_get_key(values, "EventCount", AMXC_VAR_FLAG_DEFAULT));

    amxc_var_clean(&args);
    amxc_var_clean(&ret);
}

void test_can_read_specific_parameters(UNUSED void** state) {
    amxd_object_t* stats = amxd_dm_findf(&dm, "Greeter.");
    amxc_var_t* values = NULL;
    amxc_var_t args;
    amxc_var_t ret;

    assert_non_null(stats);

    amxc_var_init(&args);
    amxc_var_init(&ret);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &args, "rel_path", "Statistics.");
    values = amxc_var_add_key(amxc_llist_t, &args, "parameters", NULL);
    amxc_var_add(cstring_t, values, "AddHistoryCount");
    amxc_var_add(cstring_t, values, "EventCount");
    assert_int_equal(amxd_object_invoke_function(stats, "_get", &args, &ret), amxd_status_ok);
    assert_int_equal(amxc_var_type_of(&ret), AMXC_VAR_ID_HTABLE);
    values = amxc_var_get_key(&ret, "Greeter.Statistics.", AMXC_VAR_FLAG_DEFAULT);
    assert_non_null(values);

    assert_non_null(amxc_var_get_key(values, "AddHistoryCount", AMXC_VAR_FLAG_DEFAULT));
    assert_null(amxc_var_get_key(values, "DelHistoryCount", AMXC_VAR_FLAG_DEFAULT));
    assert_non_null(amxc_var_get_key(values, "EventCount", AMXC_VAR_FLAG_DEFAULT));

    amxc_var_clean(&args);
    amxc_var_clean(&ret);
}

void test_read_fails_when_reading_unknown_parameters(UNUSED void** state) {
    amxd_object_t* stats = amxd_dm_findf(&dm, "Greeter.");
    amxc_var_t* values = NULL;
    amxc_var_t args;
    amxc_var_t ret;

    assert_non_null(stats);

    amxc_var_init(&args);
    amxc_var_init(&ret);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &args, "rel_path", "Statistics.");
    values = amxc_var_add_key(amxc_llist_t, &args, "parameters", NULL);
    amxc_var_add(uint32_t, values, 1);
    assert_int_not_equal(amxd_object_invoke_function(stats, "get", &args, &ret), amxd_status_ok);
    assert_int_equal(amxc_var_type_of(&ret), AMXC_VAR_ID_NULL);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &args, "rel_path", "Statistics.");
    values = amxc_var_add_key(amxc_llist_t, &args, "parameters", NULL);
    amxc_var_add(cstring_t, values, "BytesReceived");
    assert_int_not_equal(amxd_object_invoke_function(stats, "get", &args, &ret), amxd_status_ok);
    assert_int_equal(amxc_var_type_of(&ret), AMXC_VAR_ID_NULL);

    amxc_var_clean(&args);
    amxc_var_clean(&ret);
}

void test_can_list_stats_object(UNUSED void** state) {
    amxd_object_t* stats = amxd_dm_findf(&dm, "Greeter.Statistics");
    amxc_var_t* values = NULL;
    amxc_var_t args;
    amxc_var_t ret;

    assert_non_null(stats);

    amxc_var_init(&args);
    amxc_var_init(&ret);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxd_object_invoke_function(stats, "_list", &args, &ret), amxd_status_ok);
    assert_int_equal(amxc_var_type_of(&ret), AMXC_VAR_ID_HTABLE);
    values = amxc_var_get_key(&ret, "parameters", AMXC_VAR_FLAG_DEFAULT);
    assert_non_null(values);

    for(int i = 0; i < 3; i++) {
        assert_non_null(amxc_var_get_index(values, i, AMXC_VAR_FLAG_DEFAULT));
    }
    assert_null(amxc_var_get_index(values, 3, AMXC_VAR_FLAG_DEFAULT));

    assert_string_equal(CHAR(GET_IDX(values, 0)), "AddHistoryCount");
    assert_string_equal(CHAR(GET_IDX(values, 1)), "DelHistoryCount");
    assert_string_equal(CHAR(GET_IDX(values, 2)), "EventCount");

    amxc_var_clean(&args);
    amxc_var_clean(&ret);
}

void test_can_describe_stats_object(UNUSED void** state) {
    amxd_object_t* stats = amxd_dm_findf(&dm, "Greeter.Statistics");
    amxc_var_t* values = NULL;
    amxc_var_t args;
    amxc_var_t ret;

    assert_non_null(stats);

    amxc_var_init(&args);
    amxc_var_init(&ret);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(bool, &args, "parameters", true);
    assert_int_equal(amxd_object_invoke_function(stats, "_describe", &args, &ret), amxd_status_ok);
    assert_int_equal(amxc_var_type_of(&ret), AMXC_VAR_ID_HTABLE);
    values = amxc_var_get_key(&ret, "parameters", AMXC_VAR_FLAG_DEFAULT);
    assert_int_equal(amxc_var_type_of(values), AMXC_VAR_ID_HTABLE);

    assert_non_null(amxc_var_get_key(values, "EventCount", AMXC_VAR_FLAG_DEFAULT));
    assert_non_null(amxc_var_get_key(values, "DelHistoryCount", AMXC_VAR_FLAG_DEFAULT));
    assert_non_null(amxc_var_get_key(values, "AddHistoryCount", AMXC_VAR_FLAG_DEFAULT));

    values = amxc_var_get_key(values, "DelHistoryCount", AMXC_VAR_FLAG_DEFAULT);
    assert_int_equal(amxc_var_type_of(values), AMXC_VAR_ID_HTABLE);
    assert_non_null(amxc_var_get_key(values, "attributes", AMXC_VAR_FLAG_DEFAULT));
    assert_non_null(amxc_var_get_key(values, "value", AMXC_VAR_FLAG_DEFAULT));
    assert_non_null(amxc_var_get_key(values, "name", AMXC_VAR_FLAG_DEFAULT));
    assert_non_null(amxc_var_get_key(values, "type_id", AMXC_VAR_FLAG_DEFAULT));
    assert_non_null(amxc_var_get_key(values, "type_name", AMXC_VAR_FLAG_DEFAULT));

    assert_int_equal(UINT32(GET_KEY(values, "type_id")), AMXC_VAR_ID_UINT32);
    assert_string_equal(CHAR(GET_KEY(values, "type_name")), "uint32_t");
    assert_string_equal(CHAR(GET_KEY(values, "name")), "DelHistoryCount");

    values = amxc_var_get_key(values, "attributes", AMXC_VAR_FLAG_DEFAULT);
    assert_non_null(amxc_var_get_key(values, "read-only", AMXC_VAR_FLAG_DEFAULT));
    assert_non_null(amxc_var_get_key(values, "volatile", AMXC_VAR_FLAG_DEFAULT));

    assert_true(BOOL(GET_KEY(values, "volatile")));
    assert_true(BOOL(GET_KEY(values, "read-only")));

    amxc_var_clean(&args);
    amxc_var_clean(&ret);
}

void test_can_call_stats_reset(UNUSED void** state) {
    amxd_object_t* stats = amxd_dm_findf(&dm, "Greeter.Statistics");
    amxc_var_t args;
    amxc_var_t ret;

    assert_non_null(stats);

    amxc_var_init(&args);
    amxc_var_init(&ret);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxd_object_invoke_function(stats, "reset", &args, &ret), amxd_status_ok);

    handle_events();

    amxc_var_clean(&args);
    amxc_var_clean(&ret);
}

void test_can_call_start_periodic_inform(UNUSED void** state) {
    amxd_object_t* stats = amxd_dm_findf(&dm, "Greeter.Statistics");
    amxc_var_t args;
    amxc_var_t ret;

    assert_non_null(stats);

    amxc_var_init(&args);
    amxc_var_init(&ret);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(uint32_t, &args, "secs", 10);
    assert_int_equal(amxd_object_invoke_function(stats, "periodic_inform", &args, &ret), amxd_status_ok);

    handle_events();

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(uint32_t, &args, "secs", 0);
    assert_int_equal(amxd_object_invoke_function(stats, "periodic_inform", &args, &ret), amxd_status_ok);

    amxc_var_clean(&args);
    amxc_var_clean(&ret);
}

void test_stats_action_list_invalid_invoke(UNUSED void** state) {
    amxd_object_t* greeter = amxd_dm_findf(&dm, "Greeter.Statistics");

    assert_int_not_equal(amxd_dm_invoke_action(greeter, NULL, action_object_list, NULL, NULL), 0);
}

void test_stats_action_describe_invalid_invoke(UNUSED void** state) {
    amxd_object_t* greeter = amxd_dm_findf(&dm, "Greeter.Statistics");

    assert_int_not_equal(amxd_dm_invoke_action(greeter, NULL, action_object_describe, NULL, NULL), 0);
}
