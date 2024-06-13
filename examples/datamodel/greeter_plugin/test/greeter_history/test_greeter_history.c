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
#include "test_greeter_history.h"

#define GET_KEY(v, k) amxc_var_get_key(v, k, AMXC_VAR_FLAG_DEFAULT)
#define CHAR(v) amxc_var_constcast(cstring_t, v)
#define UINT32(v) amxc_var_constcast(uint32_t, v)

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
    amxd_trans_t trans;

    assert_int_equal(amxd_dm_init(&dm), amxd_status_ok);
    assert_int_equal(amxo_parser_init(&parser), 0);

    root_obj = amxd_dm_get_root(&dm);
    assert_non_null(root_obj);

    assert_int_equal(amxo_resolver_ftab_add(&parser, "check_change", AMXO_FUNC(_State_check_change)), 0);
    assert_int_equal(amxo_resolver_ftab_add(&parser, "enable_greeter", AMXO_FUNC(_enable_greeter)), 0);
    assert_int_equal(amxo_resolver_ftab_add(&parser, "disable_greeter", AMXO_FUNC(_disable_greeter)), 0);
    assert_int_equal(amxo_resolver_ftab_add(&parser, "greeter_main", AMXO_FUNC(_greeter_main)), 0);
    assert_int_equal(amxo_resolver_ftab_add(&parser, "print_event", AMXO_FUNC(_print_event)), 0);
    assert_int_equal(amxo_resolver_ftab_add(&parser, "Greeter.say", AMXO_FUNC(_Greeter_say)), 0);
    assert_int_equal(amxo_resolver_ftab_add(&parser, "Greeter.setMaxHistory", AMXO_FUNC(_Greeter_setMaxHistory)), 0);
    assert_int_equal(amxo_resolver_ftab_add(&parser, "Greeter.History.clear", AMXO_FUNC(_History_clear)), 0);

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

void test_say_message_is_added_to_history(UNUSED void** state) {
    amxd_object_t* greeter = amxd_dm_findf(&dm, "Greeter");
    amxd_object_t* history = amxd_dm_findf(&dm, "Greeter.History.");
    uint32_t history_size = 0;
    amxc_var_t args;
    amxc_var_t ret;

    assert_non_null(greeter);
    assert_non_null(history);

    history_size = amxd_object_get_instance_count(history);

    amxc_var_init(&args);
    amxc_var_init(&ret);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &args, "from", "tests-history");
    amxc_var_add_key(cstring_t, &args, "message", "Added to history");

    assert_int_equal(amxd_object_invoke_function(greeter, "say", &args, &ret), amxd_status_ok);

    handle_events();

    assert_int_equal(amxd_object_get_instance_count(history), history_size + 1);
    history = amxd_object_findf(history, "%d.", history_size + 1);
    assert_non_null(history);
    amxd_object_get_params(history, &args, amxd_dm_access_protected);
    assert_string_equal(CHAR(GET_KEY(&args, "From")), "tests-history");
    assert_string_equal(CHAR(GET_KEY(&args, "Message")), "Added to history");

    amxc_var_clean(&args);
    amxc_var_clean(&ret);
}

void test_can_change_max_history_size(UNUSED void** state) {
    amxd_object_t* greeter = amxd_dm_findf(&dm, "Greeter");
    amxd_object_t* history = amxd_dm_findf(&dm, "Greeter.History.");
    uint32_t history_size = 0;
    amxc_var_t args;
    amxc_var_t ret;
    amxc_var_t value;

    assert_non_null(greeter);
    assert_non_null(history);

    amxc_var_init(&args);
    amxc_var_init(&ret);
    amxc_var_init(&value);

    history_size = amxd_object_get_instance_count(history);
    amxd_object_get_param(greeter, "MaxHistory", &value);
    assert_int_equal(UINT32(&value), 10);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(uint32_t, &args, "max", history_size + 3);
    assert_int_equal(amxd_object_invoke_function(greeter, "setMaxHistory", &args, &ret), amxd_status_ok);

    handle_events();

    amxd_object_get_param(greeter, "MaxHistory", &value);
    assert_int_equal(UINT32(&value), history_size + 3);

    amxc_var_clean(&args);
    amxc_var_clean(&ret);
    amxc_var_clean(&value);
}

void test_number_history_instances_are_not_exceeding_max_history_size(UNUSED void** state) {
    amxd_object_t* greeter = amxd_dm_findf(&dm, "Greeter");
    amxd_object_t* history = amxd_dm_findf(&dm, "Greeter.History.");
    uint32_t history_size = 0;
    amxc_var_t args;
    amxc_var_t ret;
    amxc_var_t value;

    assert_non_null(greeter);
    assert_non_null(history);

    amxc_var_init(&args);
    amxc_var_init(&ret);
    amxc_var_init(&value);

    amxd_object_get_param(greeter, "MaxHistory", &value);
    history_size = UINT32(&value);

    for(uint32_t i = 0; i < history_size + 1; i++) {
        amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
        amxc_var_add_key(cstring_t, &args, "from", "tests-history");
        amxc_var_add_key(cstring_t, &args, "message", "Checking MAX history");
        assert_int_equal(amxd_object_invoke_function(greeter, "say", &args, &ret), amxd_status_ok);
        handle_events();
    }

    assert_int_equal(amxd_object_get_instance_count(history), history_size);

    amxc_var_clean(&args);
    amxc_var_clean(&ret);
    amxc_var_init(&value);
}

void test_lower_max_history_size_deletes_instances(UNUSED void** state) {
    amxd_object_t* greeter = amxd_dm_findf(&dm, "Greeter");
    amxd_object_t* history = amxd_dm_findf(&dm, "Greeter.History.");
    uint32_t history_size = 0;
    amxc_var_t args;
    amxc_var_t ret;
    amxc_var_t value;

    assert_non_null(greeter);
    assert_non_null(history);

    amxc_var_init(&args);
    amxc_var_init(&ret);
    amxc_var_init(&value);

    history_size = amxd_object_get_instance_count(history);
    amxd_object_get_param(greeter, "MaxHistory", &value);

    assert_int_equal(UINT32(&value), history_size);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(uint32_t, &args, "max", history_size - 1);
    assert_int_equal(amxd_object_invoke_function(greeter, "setMaxHistory", &args, &ret), amxd_status_ok);

    handle_events();

    amxd_object_get_param(greeter, "MaxHistory", &value);
    assert_int_equal(UINT32(&value), history_size - 1);
    history_size = amxd_object_get_instance_count(history);
    assert_int_equal(UINT32(&value), history_size);

    amxc_var_clean(&args);
    amxc_var_clean(&ret);
    amxc_var_clean(&value);
}

void test_can_clear_history(UNUSED void** state) {
    amxd_object_t* greeter = amxd_dm_findf(&dm, "Greeter");
    amxd_object_t* history = amxd_dm_findf(&dm, "Greeter.History.");
    uint32_t history_size = 0;
    amxc_var_t args;
    amxc_var_t ret;

    assert_non_null(greeter);
    assert_non_null(history);

    amxc_var_init(&args);
    amxc_var_init(&ret);

    history_size = amxd_object_get_instance_count(history);
    assert_int_not_equal(history_size, 0);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxd_object_invoke_function(history, "clear", &args, &ret), amxd_status_ok);
    assert_int_equal(UINT32(&ret), history_size);

    handle_events();

    history_size = amxd_object_get_instance_count(history);
    assert_int_equal(history_size, 0);

    amxc_var_clean(&args);
    amxc_var_clean(&ret);
}

void test_say_message_fails_when_history_is_full_of_retained_messages(UNUSED void** state) {
    amxd_object_t* greeter = amxd_dm_findf(&dm, "Greeter");
    amxd_object_t* history = amxd_dm_findf(&dm, "Greeter.History.");
    uint32_t history_size = 0;
    amxc_var_t args;
    amxc_var_t ret;
    amxc_var_t value;

    assert_non_null(greeter);
    assert_non_null(history);

    amxc_var_init(&args);
    amxc_var_init(&ret);
    amxc_var_init(&value);

    amxd_object_get_param(greeter, "MaxHistory", &value);

    for(uint32_t i = 0; i < UINT32(&value); i++) {
        amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
        amxc_var_add_key(cstring_t, &args, "from", "tests-history");
        amxc_var_add_key(cstring_t, &args, "message", "Checking retained messages");
        amxc_var_add_key(bool, &args, "retain", true);
        assert_int_equal(amxd_object_invoke_function(greeter, "say", &args, &ret), amxd_status_ok);
        handle_events();
    }

    history_size = amxd_object_get_instance_count(history);
    assert_int_equal(history_size, UINT32(&value));

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &args, "from", "tests-history");
    amxc_var_add_key(cstring_t, &args, "message", "Failing say");
    assert_int_not_equal(amxd_object_invoke_function(greeter, "say", &args, &ret), amxd_status_ok);

    amxc_var_clean(&args);
    amxc_var_clean(&ret);
}

void test_set_max_history_when_lower_then_number_of_retained_messsages(UNUSED void** state) {
    amxd_object_t* greeter = amxd_dm_findf(&dm, "Greeter");
    amxd_object_t* history = amxd_dm_findf(&dm, "Greeter.History.");
    uint32_t history_size = 0;
    amxc_var_t args;
    amxc_var_t ret;
    amxc_var_t value;

    assert_non_null(greeter);
    assert_non_null(history);

    amxc_var_init(&args);
    amxc_var_init(&ret);
    amxc_var_init(&value);

    history_size = amxd_object_get_instance_count(history);
    amxd_object_get_param(greeter, "MaxHistory", &value);

    assert_int_equal(UINT32(&value), history_size);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(uint32_t, &args, "max", history_size - 1);
    assert_int_equal(amxd_object_invoke_function(greeter, "setMaxHistory", &args, &ret), amxd_status_ok);

    handle_events();

    assert_int_equal(UINT32(&ret), history_size);
    amxd_object_get_param(greeter, "MaxHistory", &value);
    assert_int_equal(UINT32(&value), history_size);
    history_size = amxd_object_get_instance_count(history);
    assert_int_equal(UINT32(&value), history_size);

    amxc_var_clean(&args);
    amxc_var_clean(&ret);
    amxc_var_clean(&value);
}

void test_can_increase_max_history(UNUSED void** state) {
    amxd_object_t* greeter = amxd_dm_findf(&dm, "Greeter");
    amxd_object_t* history = amxd_dm_findf(&dm, "Greeter.History.");
    uint32_t history_size = 0;
    amxc_var_t args;
    amxc_var_t ret;
    amxc_var_t value;

    assert_non_null(greeter);
    assert_non_null(history);

    amxc_var_init(&args);
    amxc_var_init(&ret);
    amxc_var_init(&value);

    amxd_object_get_param(greeter, "MaxHistory", &value);
    history_size = UINT32(&value);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(uint32_t, &args, "max", history_size + 5);
    assert_int_equal(amxd_object_invoke_function(greeter, "setMaxHistory", &args, &ret), amxd_status_ok);

    handle_events();

    assert_int_equal(UINT32(&ret), history_size + 5);
    amxd_object_get_param(greeter, "MaxHistory", &value);
    assert_int_equal(UINT32(&value), history_size + 5);

    amxc_var_clean(&args);
    amxc_var_clean(&ret);
    amxc_var_clean(&value);
}

void test_set_max_history_to_same_value_has_no_effect(UNUSED void** state) {
    amxd_object_t* greeter = amxd_dm_findf(&dm, "Greeter");
    amxd_object_t* history = amxd_dm_findf(&dm, "Greeter.History.");
    uint32_t history_size = 0;
    amxc_var_t args;
    amxc_var_t ret;
    amxc_var_t value;

    assert_non_null(greeter);
    assert_non_null(history);

    amxc_var_init(&args);
    amxc_var_init(&ret);
    amxc_var_init(&value);

    amxd_object_get_param(greeter, "MaxHistory", &value);
    history_size = UINT32(&value);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(uint32_t, &args, "max", history_size);
    assert_int_equal(amxd_object_invoke_function(greeter, "setMaxHistory", &args, &ret), amxd_status_ok);

    handle_events();

    assert_int_equal(UINT32(&ret), history_size);
    amxd_object_get_param(greeter, "MaxHistory", &value);
    assert_int_equal(UINT32(&value), history_size);

    amxc_var_clean(&args);
    amxc_var_clean(&ret);
    amxc_var_clean(&value);
}

void test_can_clear_history_does_not_remove_retained_messages(UNUSED void** state) {
    amxd_object_t* greeter = amxd_dm_findf(&dm, "Greeter");
    amxd_object_t* history = amxd_dm_findf(&dm, "Greeter.History.");
    uint32_t history_size = 0;
    amxc_var_t args;
    amxc_var_t ret;

    assert_non_null(greeter);
    assert_non_null(history);

    amxc_var_init(&args);
    amxc_var_init(&ret);

    history_size = amxd_object_get_instance_count(history);
    assert_int_not_equal(history_size, 0);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxd_object_invoke_function(history, "clear", &args, &ret), amxd_status_ok);
    assert_int_equal(UINT32(&ret), 0);

    handle_events();

    assert_int_equal(amxd_object_get_instance_count(history), history_size);

    amxc_var_clean(&args);
    amxc_var_clean(&ret);
}

void test_can_force_clear_history_does_remove_retained_messages(UNUSED void** state) {
    amxd_object_t* greeter = amxd_dm_findf(&dm, "Greeter");
    amxd_object_t* history = amxd_dm_findf(&dm, "Greeter.History.");
    uint32_t history_size = 0;
    amxc_var_t args;
    amxc_var_t ret;

    assert_non_null(greeter);
    assert_non_null(history);

    amxc_var_init(&args);
    amxc_var_init(&ret);

    history_size = amxd_object_get_instance_count(history);
    assert_int_not_equal(history_size, 0);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(bool, &args, "force", true);
    assert_int_equal(amxd_object_invoke_function(history, "clear", &args, &ret), amxd_status_ok);
    assert_int_equal(UINT32(&ret), history_size);

    handle_events();

    assert_int_equal(amxd_object_get_instance_count(history), 0);

    amxc_var_clean(&args);
    amxc_var_clean(&ret);
}
