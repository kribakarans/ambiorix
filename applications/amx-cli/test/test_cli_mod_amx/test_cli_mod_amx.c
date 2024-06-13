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

#include "tty_mock.h"
#include "common_mock.h"
#include "test_cli_mod_amx.h"

int test_cli_mod_amx_setup(UNUSED void** state) {
    cli_app_t* amx_cli = amx_cli_get_data();
    amxt_tty_open(&amx_cli->tty, fileno(stdin));

    amxc_var_init(&amx_cli->aliases);
    amxc_var_set_type(&amx_cli->aliases, AMXC_VAR_ID_HTABLE);

    amx_cli->shared_object = NULL;
    amx_cli->module = NULL;

    amxp_sigmngr_add_signal(amx_cli->tty->sigmngr, "tty:docomplete");
    amxp_slot_connect(amx_cli->tty->sigmngr, "tty:docomplete", NULL, test_complete_cb, NULL);

    return 0;
}

int test_cli_mod_amx_teardown(UNUSED void** state) {
    cli_app_t* amx_cli = amx_cli_get_data();

    amxm_close_all();
    if(amx_cli->tty) {
        amx_cli->tty->priv = NULL;
    }
    amxc_var_clean(&amx_cli->aliases);
    amxt_tty_hide_prompt(amx_cli->tty);
    amxt_tty_close(&amx_cli->tty);
    free(amx_cli->shared_object);
    free(amx_cli->module);

    return 0;
}

void test_can_invoke_help(UNUSED void** state) {
    amxm_shared_object_t* so = amxm_get_so("self");

    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "");

    cmd_rv = amxm_so_execute_function(so, "amx", "help", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_complete_help_command(UNUSED void** state) {
    amxm_shared_object_t* so = amxm_get_so("self");
    int cmd_rv = 0;
    amxc_var_t* cmd_parts = NULL;
    amxc_var_t* ret = NULL;
    amxc_var_t tty_args;
    amxc_var_t check_var;

    amxc_var_init(&tty_args);
    amxc_var_init(&check_var);

    amxc_var_new(&ret);
    amxc_var_set_type(ret, AMXC_VAR_ID_LIST);
    amxt_cli_build_args(&tty_args, "p");
    cmd_parts = GET_ARG(&tty_args, "cmd");
    cmd_rv = amxm_so_execute_function(so, "amx", "__complete_help", cmd_parts, ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_set_type(&check_var, AMXC_VAR_ID_LIST);
    amxc_var_add(cstring_t, &check_var, "prompt");
    expect_check(test_complete_cb, data, test_check_completion_list, &check_var);
    handle_events();

    amxc_var_clean(&tty_args);
    amxc_var_clean(&check_var);
}

void test_can_describe(UNUSED void** state) {
    amxm_shared_object_t* so = amxm_get_so("self");
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "");
    cmd_rv = amxm_so_execute_function(so, "amx", "__describe", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);
    assert_int_equal(amxc_var_type_of(&ret), AMXC_VAR_ID_CSTRING);
    assert_string_equal(amxc_var_constcast(cstring_t, &ret), "Ambiorix Interactive Command Line Control.");

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_add_variable(UNUSED void** state) {
    amxm_shared_object_t* so = amxm_get_so("self");
    int cmd_rv = 0;
    amxc_var_t* variable = NULL;
    amxt_tty_t* tty = amx_cli_get_tty();

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "myvariable = 'Some Value'");
    cmd_rv = amxm_so_execute_function(so, "amx", "variable", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    variable = amxt_tty_get_config(tty, "myvariable");
    assert_non_null(variable);
    assert_int_equal(amxc_var_type_of(variable), AMXC_VAR_ID_CSTRING);
    assert_string_equal(amxc_var_constcast(cstring_t, variable), "Some Value");

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_add_list_variable(UNUSED void** state) {
    amxm_shared_object_t* so = amxm_get_so("self");
    int cmd_rv = 0;
    amxc_var_t* variable = NULL;
    amxt_tty_t* tty = amx_cli_get_tty();

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "lvariable = [1,10,20]");
    cmd_rv = amxm_so_execute_function(so, "amx", "variable", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    variable = amxt_tty_get_config(tty, "lvariable");
    assert_non_null(variable);
    assert_int_equal(amxc_var_type_of(variable), AMXC_VAR_ID_LIST);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_add_table_variable(UNUSED void** state) {
    amxm_shared_object_t* so = amxm_get_so("self");
    int cmd_rv = 0;
    amxc_var_t* variable = NULL;
    amxt_tty_t* tty = amx_cli_get_tty();

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "tvariable = { p1 = 1, p2 = 10, p3 = 20}");
    cmd_rv = amxm_so_execute_function(so, "amx", "variable", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    variable = amxt_tty_get_config(tty, "tvariable");
    assert_non_null(variable);
    assert_int_equal(amxc_var_type_of(variable), AMXC_VAR_ID_HTABLE);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_dump_variables(UNUSED void** state) {
    amxm_shared_object_t* so = amxm_get_so("self");
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "");
    cmd_rv = amxm_so_execute_function(so, "amx", "variable", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_variable_dump_fails_if_not_found(UNUSED void** state) {
    amxm_shared_object_t* so = amxm_get_so("self");
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "Non-Existing");
    cmd_rv = amxm_so_execute_function(so, "amx", "variable", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_dump_single_variable(UNUSED void** state) {
    amxm_shared_object_t* so = amxm_get_so("self");
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "myvariable");
    cmd_rv = amxm_so_execute_function(so, "amx", "variable", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_get_list_value(UNUSED void** state) {
    amxm_shared_object_t* so = amxm_get_so("self");
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "lvariable.1");
    cmd_rv = amxm_so_execute_function(so, "amx", "variable", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_get_table_value(UNUSED void** state) {
    amxm_shared_object_t* so = amxm_get_so("self");
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "tvariable.p2");
    cmd_rv = amxm_so_execute_function(so, "amx", "variable", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_complete_variable(UNUSED void** state) {
    amxm_shared_object_t* so = amxm_get_so("self");
    int cmd_rv = 0;
    amxc_var_t* cmd_parts = NULL;
    amxc_var_t* ret = NULL;
    amxc_var_t tty_args;
    amxc_var_t check_var;

    amxc_var_init(&tty_args);
    amxc_var_init(&check_var);

    amxc_var_new(&ret);
    amxc_var_set_type(ret, AMXC_VAR_ID_LIST);
    amxt_cli_build_args(&tty_args, "my");
    cmd_parts = GET_ARG(&tty_args, "cmd");
    cmd_rv = amxm_so_execute_function(so, "amx", "__complete_variable", cmd_parts, ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_set_type(&check_var, AMXC_VAR_ID_LIST);
    amxc_var_add(cstring_t, &check_var, "myvariable");
    expect_check(test_complete_cb, data, test_check_completion_list, &check_var);
    handle_events();

    amxc_var_new(&ret);
    amxc_var_set_type(ret, AMXC_VAR_ID_LIST);
    amxt_cli_build_args(&tty_args, "tvariable.p");
    cmd_parts = GET_ARG(&tty_args, "cmd");
    cmd_rv = amxm_so_execute_function(so, "amx", "__complete_variable", cmd_parts, ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_set_type(&check_var, AMXC_VAR_ID_LIST);
    amxc_var_add(cstring_t, &check_var, "tvariable.p1");
    amxc_var_add(cstring_t, &check_var, "tvariable.p2");
    amxc_var_add(cstring_t, &check_var, "tvariable.p3");
    expect_check(test_complete_cb, data, test_check_completion_list, &check_var);
    handle_events();

    amxc_var_new(&ret);
    amxc_var_set_type(ret, AMXC_VAR_ID_LIST);
    amxt_cli_build_args(&tty_args, "lvariable.");
    cmd_parts = GET_ARG(&tty_args, "cmd");
    cmd_rv = amxm_so_execute_function(so, "amx", "__complete_variable", cmd_parts, ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_set_type(&check_var, AMXC_VAR_ID_LIST);
    expect_check(test_complete_cb, data, test_check_completion_list, &check_var);
    handle_events();

    amxc_var_new(&ret);
    amxc_var_set_type(ret, AMXC_VAR_ID_LIST);
    amxt_cli_build_args(&tty_args, "lvariable. myvar");
    cmd_parts = GET_ARG(&tty_args, "cmd");
    cmd_rv = amxm_so_execute_function(so, "amx", "__complete_variable", cmd_parts, ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_set_type(&check_var, AMXC_VAR_ID_LIST);
    expect_check(test_complete_cb, data, test_check_completion_list, &check_var);
    handle_events();

    amxc_var_clean(&tty_args);
    amxc_var_clean(&check_var);
}

void test_can_delete_variable(UNUSED void** state) {
    amxm_shared_object_t* so = amxm_get_so("self");
    int cmd_rv = 0;
    amxc_var_t* variable = NULL;
    amxt_tty_t* tty = amx_cli_get_tty();

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "myvariable=");
    cmd_rv = amxm_so_execute_function(so, "amx", "variable", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    variable = amxt_tty_get_config(tty, "myvariable");
    assert_null(variable);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_delete_list_item(UNUSED void** state) {
    amxm_shared_object_t* so = amxm_get_so("self");
    int cmd_rv = 0;
    amxc_var_t* variable = NULL;
    amxt_tty_t* tty = amx_cli_get_tty();

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "lvariable.1=");
    cmd_rv = amxm_so_execute_function(so, "amx", "variable", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);
    variable = GETP_ARG(&tty->config, "lvariable");
    amxc_var_dump(variable, STDOUT_FILENO);

    variable = GETP_ARG(&tty->config, "lvariable.2");
    assert_null(variable);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_delete_table_item(UNUSED void** state) {
    amxm_shared_object_t* so = amxm_get_so("self");
    int cmd_rv = 0;
    amxc_var_t* variable = NULL;
    amxt_tty_t* tty = amx_cli_get_tty();

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "tvariable.p1=");
    cmd_rv = amxm_so_execute_function(so, "amx", "variable", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);
    variable = GETP_ARG(&tty->config, "tvariable");
    amxc_var_dump(variable, STDOUT_FILENO);

    variable = GETP_ARG(&tty->config, "tvariable.p1");
    assert_null(variable);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_set_list_item(UNUSED void** state) {
    amxm_shared_object_t* so = amxm_get_so("self");
    int cmd_rv = 0;
    amxc_var_t* variable = NULL;
    amxt_tty_t* tty = amx_cli_get_tty();

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "lvariable.2=999");
    cmd_rv = amxm_so_execute_function(so, "amx", "variable", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);
    variable = GETP_ARG(&tty->config, "lvariable");
    amxc_var_dump(variable, STDOUT_FILENO);

    variable = GETP_ARG(&tty->config, "lvariable.2");
    assert_non_null(variable);
    assert_int_equal(amxc_var_dyncast(uint32_t, variable), 999);

    amxt_cli_build_args(&tty_args, "lvariable.99=1000");
    cmd_rv = amxm_so_execute_function(so, "amx", "variable", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);
    variable = GETP_ARG(&tty->config, "lvariable");
    amxc_var_dump(variable, STDOUT_FILENO);

    variable = GETP_ARG(&tty->config, "lvariable.3");
    assert_non_null(variable);
    assert_int_equal(amxc_var_dyncast(uint32_t, variable), 1000);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_set_table_item(UNUSED void** state) {
    amxm_shared_object_t* so = amxm_get_so("self");
    int cmd_rv = 0;
    amxc_var_t* variable = NULL;
    amxt_tty_t* tty = amx_cli_get_tty();

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "tvariable.p4=666");
    cmd_rv = amxm_so_execute_function(so, "amx", "variable", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);
    variable = GETP_ARG(&tty->config, "tvariable");
    amxc_var_dump(variable, STDOUT_FILENO);

    variable = GETP_ARG(&tty->config, "tvariable.p4");
    assert_non_null(variable);
    assert_int_equal(amxc_var_dyncast(uint32_t, variable), 666);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_set_fails_when_invalid_variable_name(UNUSED void** state) {
    amxm_shared_object_t* so = amxm_get_so("self");
    int cmd_rv = 0;
    amxc_var_t* variable = NULL;
    amxt_tty_t* tty = amx_cli_get_tty();

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "12%Invalid=999");
    cmd_rv = amxm_so_execute_function(so, "amx", "variable", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);
    variable = GETP_ARG(&tty->config, "12%Invalid");
    assert_null(variable);

    amxt_cli_build_args(&tty_args, "$Test$=999");
    cmd_rv = amxm_so_execute_function(so, "amx", "variable", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);
    variable = GETP_ARG(&tty->config, "$Test$");
    assert_null(variable);

    amxt_cli_build_args(&tty_args, "$Test$.part#1=999");
    cmd_rv = amxm_so_execute_function(so, "amx", "variable", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);
    variable = GETP_ARG(&tty->config, "$Test$.part#1");
    assert_null(variable);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_set_fails_when_name_omitted(UNUSED void** state) {
    amxm_shared_object_t* so = amxm_get_so("self");
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "=999");
    cmd_rv = amxm_so_execute_function(so, "amx", "variable", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_set_fails_on_composite_when_not_found(UNUSED void** state) {
    amxm_shared_object_t* so = amxm_get_so("self");
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "not-existing.sub-part=999");
    cmd_rv = amxm_so_execute_function(so, "amx", "variable", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_build_composite_variable(UNUSED void** state) {
    amxm_shared_object_t* so = amxm_get_so("self");
    int cmd_rv = 0;
    amxc_var_t* variable = NULL;
    amxt_tty_t* tty = amx_cli_get_tty();

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "cvar={ p1 = ['a','b','c'], p2 = { key1=1, key2=false}, p3=3}");
    cmd_rv = amxm_so_execute_function(so, "amx", "variable", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    variable = GETP_ARG(&tty->config, "cvar");
    assert_non_null(variable);
    amxc_var_dump(variable, STDOUT_FILENO);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_dump_composite_variable_part(UNUSED void** state) {
    amxm_shared_object_t* so = amxm_get_so("self");
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "cvar.p2.key1");
    cmd_rv = amxm_so_execute_function(so, "amx", "variable", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_add_alias(UNUSED void** state) {
    amxm_shared_object_t* so = amxm_get_so("self");
    int cmd_rv = 0;
    amxc_var_t* alias = NULL;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "myalias 'history show'");
    cmd_rv = amxm_so_execute_function(so, "amx", "alias", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    alias = GET_ARG(amx_cli_get_aliases(), "myalias");
    assert_non_null(alias);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_add_fails_when_empty_or_invalid_alias_name(UNUSED void** state) {
    amxm_shared_object_t* so = amxm_get_so("self");
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "'' 'history show'");
    cmd_rv = amxm_so_execute_function(so, "amx", "alias", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxt_cli_build_args(&tty_args, "&data 'history show'");
    cmd_rv = amxm_so_execute_function(so, "amx", "alias", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_dump_aliases(UNUSED void** state) {
    amxm_shared_object_t* so = amxm_get_so("self");
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "");
    cmd_rv = amxm_so_execute_function(so, "amx", "alias", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_complete_alias(UNUSED void** state) {
    amxm_shared_object_t* so = amxm_get_so("self");
    int cmd_rv = 0;
    amxc_var_t* cmd_parts = NULL;
    amxc_var_t* ret = NULL;
    amxc_var_t tty_args;
    amxc_var_t check_var;

    amxc_var_init(&tty_args);
    amxc_var_init(&check_var);

    amxc_var_new(&ret);
    amxc_var_set_type(ret, AMXC_VAR_ID_LIST);
    amxt_cli_build_args(&tty_args, "my");
    cmd_parts = GET_ARG(&tty_args, "cmd");
    cmd_rv = amxm_so_execute_function(so, "amx", "__complete_alias", cmd_parts, ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_set_type(&check_var, AMXC_VAR_ID_LIST);
    amxc_var_add(cstring_t, &check_var, "myalias");
    expect_check(test_complete_cb, data, test_check_completion_list, &check_var);
    handle_events();

    amxc_var_clean(&tty_args);
    amxc_var_clean(&check_var);
}

void test_can_delete_alias(UNUSED void** state) {
    amxm_shared_object_t* so = amxm_get_so("self");
    int cmd_rv = 0;
    amxc_var_t* alias = NULL;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "myalias");
    cmd_rv = amxm_so_execute_function(so, "amx", "alias", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    alias = GET_ARG(amx_cli_get_aliases(), "myalias");
    assert_null(alias);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_invoke_exit(UNUSED void** state) {
    amxm_shared_object_t* so = amxm_get_so("self");
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "");
    cmd_rv = amxm_so_execute_function(so, "amx", "exit", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_switch_silent_mode(UNUSED void** state) {
    amxm_shared_object_t* so = amxm_get_so("self");
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "yes");
    cmd_rv = amxm_so_execute_function(so, "amx", "silent", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    amxt_cli_build_args(&tty_args, "false");
    cmd_rv = amxm_so_execute_function(so, "amx", "silent", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_set_silent_mode_fails_with_invalid_value(UNUSED void** state) {
    amxm_shared_object_t* so = amxm_get_so("self");
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "[0,1,2]");
    cmd_rv = amxm_so_execute_function(so, "amx", "silent", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxt_cli_build_args(&tty_args, "Text");
    cmd_rv = amxm_so_execute_function(so, "amx", "silent", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxt_cli_build_args(&tty_args, "1024");
    cmd_rv = amxm_so_execute_function(so, "amx", "silent", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxt_cli_build_args(&tty_args, "");
    cmd_rv = amxm_so_execute_function(so, "amx", "silent", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_toggle_log(UNUSED void** state) {
    amxm_shared_object_t* so = amxm_get_so("self");
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "-o true");
    cmd_rv = amxm_so_execute_function(so, "amx", "log", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    amxt_cli_build_args(&tty_args, "-m yes");
    cmd_rv = amxm_so_execute_function(so, "amx", "log", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    amxt_cli_build_args(&tty_args, "-om false");
    cmd_rv = amxm_so_execute_function(so, "amx", "log", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_set_log_fails_with_invalid_value(UNUSED void** state) {
    amxm_shared_object_t* so = amxm_get_so("self");
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "[0,1,2]");
    cmd_rv = amxm_so_execute_function(so, "amx", "log", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxt_cli_build_args(&tty_args, "Text");
    cmd_rv = amxm_so_execute_function(so, "amx", "log", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxt_cli_build_args(&tty_args, "1024");
    cmd_rv = amxm_so_execute_function(so, "amx", "log", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxt_cli_build_args(&tty_args, "");
    cmd_rv = amxm_so_execute_function(so, "amx", "log", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_set_log_fails_without_options(UNUSED void** state) {
    amxm_shared_object_t* so = amxm_get_so("self");
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "false");
    cmd_rv = amxm_so_execute_function(so, "amx", "log", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_set_log_fails_with_invalid_options(UNUSED void** state) {
    amxm_shared_object_t* so = amxm_get_so("self");
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "-q true");
    cmd_rv = amxm_so_execute_function(so, "amx", "log", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_set_prompt(UNUSED void** state) {
    amxm_shared_object_t* so = amxm_get_so("self");
    int cmd_rv = 0;
    amxt_tty_t* tty = amx_cli_get_tty();
    char* p = NULL;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "$(NONE) Test ${lvariable} ->");
    cmd_rv = amxm_so_execute_function(so, "amx", "prompt", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    p = amxt_prompt_get(amxt_tty_get_prompt(tty));
    assert_string_equal(p, " Test 1,20,999,1000 -> ");
    free(p);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

