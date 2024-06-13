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
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdlib.h>
#include <stdio.h>
#include <setjmp.h>
#include <stdarg.h>
#include <cmocka.h>
#include <string.h>

#include "tty_mock.h"
#include "common_mock.h"
#include "amx_cli_parser.h"
#include "amx_cli_history.h"
#include "test_cli_mod_modules.h"

int test_cli_mod_modules_setup(UNUSED void** state) {
    cli_app_t* amx_cli = amx_cli_get_data();
    amxt_tty_open(&amx_cli->tty, fileno(stdin));

    amxc_var_init(&amx_cli->aliases);
    amxc_var_set_type(&amx_cli->aliases, AMXC_VAR_ID_HTABLE);

    amx_cli->shared_object = NULL;
    amx_cli->module = NULL;

    amxp_sigmngr_add_signal(amx_cli->tty->sigmngr, "tty:docomplete");
    amxp_slot_connect(amx_cli->tty->sigmngr, "tty:docomplete", NULL, test_complete_cb, NULL);
    amxp_slot_connect(amx_cli->tty->sigmngr, "tty:newline", NULL, amx_cli_slot_new_line, NULL);

    return 0;
}

int test_cli_mod_modules_teardown(UNUSED void** state) {
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

    cmd_rv = amxm_so_execute_function(so, "addon", "help", &tty_args, &ret);
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
    amxt_cli_build_args(&tty_args, "l");
    cmd_parts = GET_ARG(&tty_args, "cmd");
    cmd_rv = amxm_so_execute_function(so, "addon", "__complete_help", cmd_parts, ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_set_type(&check_var, AMXC_VAR_ID_LIST);
    amxc_var_add(cstring_t, &check_var, "load");
    amxc_var_add(cstring_t, &check_var, "list");
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
    cmd_rv = amxm_so_execute_function(so, "addon", "__describe", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);
    assert_int_equal(amxc_var_type_of(&ret), AMXC_VAR_ID_CSTRING);
    assert_string_equal(amxc_var_constcast(cstring_t, &ret), "loads & unloads add-ons - adds or removes functionality");

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_load_module_fails_if_no_alias_specified(UNUSED void** state) {
    amxm_shared_object_t* so = amxm_get_so("self");
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "");
    cmd_rv = amxm_so_execute_function(so, "addon", "load", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_load_module_fails_if_no_file_specified(UNUSED void** state) {
    amxm_shared_object_t* so = amxm_get_so("self");
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "test");
    cmd_rv = amxm_so_execute_function(so, "addon", "load", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_load_module(UNUSED void** state) {
    amxm_shared_object_t* so = amxm_get_so("self");
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "test ../module/mod-test-cli.so");
    cmd_rv = amxm_so_execute_function(so, "addon", "load", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    amxt_cli_build_args(&tty_args, "same ../module/mod-test-cli.so");
    cmd_rv = amxm_so_execute_function(so, "addon", "load", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    so = amxm_get_so("self");
    assert_non_null(so);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_complete_load_command(UNUSED void** state) {
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
    amxt_cli_build_args(&tty_args, "");
    cmd_parts = GET_ARG(&tty_args, "cmd");
    cmd_rv = amxm_so_execute_function(so, "addon", "__complete_load", cmd_parts, ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_set_type(&check_var, AMXC_VAR_ID_LIST);
    expect_check(test_complete_cb, data, test_check_completion_list, &check_var);
    handle_events();

    amxc_var_new(&ret);
    amxc_var_set_type(ret, AMXC_VAR_ID_LIST);
    amxt_cli_build_args(&tty_args, "test ../module/mod-test-");
    cmd_parts = GET_ARG(&tty_args, "cmd");
    cmd_rv = amxm_so_execute_function(so, "addon", "__complete_load", cmd_parts, ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_set_type(&check_var, AMXC_VAR_ID_LIST);
    amxc_var_add(cstring_t, &check_var, "../module/mod-test-cli.so");
    expect_check(test_complete_cb, data, test_check_completion_list, &check_var);
    handle_events();

    amxc_var_clean(&tty_args);
    amxc_var_clean(&check_var);
}

void test_load_module_fails_if_load_fails(UNUSED void** state) {
    amxm_shared_object_t* so = amxm_get_so("self");
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "test2 not_existing.so");
    cmd_rv = amxm_so_execute_function(so, "addon", "load", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_select_module_fails_if_invalid_name(UNUSED void** state) {
    amxm_shared_object_t* so = amxm_get_so("self");
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "fake");
    cmd_rv = amxm_so_execute_function(so, "addon", "select", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_select_module(UNUSED void** state) {
    amxm_shared_object_t* so = amxm_get_so("self");
    cli_app_t* cli = amx_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "test");
    cmd_rv = amxm_so_execute_function(so, "addon", "select", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    assert_non_null(cli->shared_object);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_select_sub_module_fails_if_invalid_name(UNUSED void** state) {
    amxm_shared_object_t* so = amxm_get_so("self");
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "test echo");
    cmd_rv = amxm_so_execute_function(so, "addon", "select", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_select_sub_module(UNUSED void** state) {
    amxm_shared_object_t* so = amxm_get_so("self");
    cli_app_t* cli = amx_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "test parser");
    cmd_rv = amxm_so_execute_function(so, "addon", "select", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    assert_non_null(cli->shared_object);
    assert_non_null(cli->module);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_complete_select_command(UNUSED void** state) {
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
    amxt_cli_build_args(&tty_args, "t");
    cmd_parts = GET_ARG(&tty_args, "cmd");
    cmd_rv = amxm_so_execute_function(so, "addon", "__complete_select", cmd_parts, ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_set_type(&check_var, AMXC_VAR_ID_LIST);
    amxc_var_add(cstring_t, &check_var, "test");
    expect_check(test_complete_cb, data, test_check_completion_list, &check_var);
    handle_events();

    amxc_var_new(&ret);
    amxc_var_set_type(ret, AMXC_VAR_ID_LIST);
    amxt_cli_build_args(&tty_args, "test ");
    cmd_parts = GET_ARG(&tty_args, "cmd");
    cmd_rv = amxm_so_execute_function(so, "addon", "__complete_select", cmd_parts, ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_set_type(&check_var, AMXC_VAR_ID_LIST);
    amxc_var_add(cstring_t, &check_var, "parser");
    expect_check(test_complete_cb, data, test_check_completion_list, &check_var);
    handle_events();

    amxc_var_clean(&tty_args);
    amxc_var_clean(&check_var);
}

void test_can_list_modules(UNUSED void** state) {
    amxm_shared_object_t* so = amxm_get_so("self");
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "");
    cmd_rv = amxm_so_execute_function(so, "addon", "list", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_select_module_selects_self_if_no_name_specified(UNUSED void** state) {
    amxm_shared_object_t* so = amxm_get_so("self");
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "");
    cmd_rv = amxm_so_execute_function(so, "addon", "select", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_remove_module_fails_when_invalid_name(UNUSED void** state) {
    amxm_shared_object_t* so = amxm_get_so("self");
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "dummy");
    cmd_rv = amxm_so_execute_function(so, "addon", "remove", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_remove_module_fails_when_no_name(UNUSED void** state) {
    amxm_shared_object_t* so = amxm_get_so("self");
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "");
    cmd_rv = amxm_so_execute_function(so, "addon", "remove", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_complete_remove_command(UNUSED void** state) {
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
    amxt_cli_build_args(&tty_args, "t");
    cmd_parts = GET_ARG(&tty_args, "cmd");
    cmd_rv = amxm_so_execute_function(so, "addon", "__complete_remove", cmd_parts, ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_set_type(&check_var, AMXC_VAR_ID_LIST);
    amxc_var_add(cstring_t, &check_var, "test");
    expect_check(test_complete_cb, data, test_check_completion_list, &check_var);
    handle_events();

    amxc_var_clean(&tty_args);
    amxc_var_clean(&check_var);
}

void test_can_remove_module(UNUSED void** state) {
    amxm_shared_object_t* so = amxm_get_so("self");
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "test");
    cmd_rv = amxm_so_execute_function(so, "addon", "select", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    amxt_cli_build_args(&tty_args, "test");
    cmd_rv = amxm_so_execute_function(so, "addon", "remove", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    amxt_cli_build_args(&tty_args, "test");
    cmd_rv = amxm_so_execute_function(so, "addon", "remove", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxt_cli_build_args(&tty_args, "same");
    cmd_rv = amxm_so_execute_function(so, "addon", "remove", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_list_modules_if_non_loaded(UNUSED void** state) {
    amxm_shared_object_t* so = amxm_get_so("self");
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "");
    cmd_rv = amxm_so_execute_function(so, "addon", "list", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}
