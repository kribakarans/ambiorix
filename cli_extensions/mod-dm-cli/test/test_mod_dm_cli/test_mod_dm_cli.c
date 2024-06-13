/****************************************************************************
**
** SPDX-License-Identifier: BSD-2-Clause-Patent
**
** SPDX-FileCopyrightText: Copyright (c) 2022 SoftAtHome
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
#include "test_mod_dm_cli.h"

int test_mod_dm_cli_setup(UNUSED void** state) {
    dm_cli_t* dm_cli = dm_cli_get_data();
    dm_cli->so = (amxm_shared_object_t*) calloc(1, sizeof(amxm_shared_object_t));
    amxc_llist_init(&dm_cli->so->amxm_module_llist);
    strncpy(dm_cli->so->name, "test_shared_object", AMXM_MODULE_NAME_LENGTH);
    strncpy(dm_cli->so->file, "test_shared_object.so", AMXM_MODULE_NAME_LENGTH);

    amxd_dm_init(&dm_cli->dm);
    amxo_parser_init(&dm_cli->parser);
    assert_int_equal(amxt_tty_open(&dm_cli->tty, fileno(stdin)), 0);

    amxp_sigmngr_add_signal(dm_cli->tty->sigmngr, "tty:docomplete");
    amxp_slot_connect(dm_cli->tty->sigmngr, "tty:docomplete", NULL, test_complete_cb, NULL);

    mod_dm_cli_start(dm_cli->so);

    return 0;
}

int test_mod_dm_cli_teardown(UNUSED void** state) {
    dm_cli_t* dm_cli = dm_cli_get_data();
    mod_dm_cli_stop(dm_cli->so);

    amxt_tty_close(&dm_cli->tty);
    amxo_parser_clean(&dm_cli->parser);

    amxc_llist_clean(&dm_cli->so->amxm_module_llist, amxm_test_so_remove_mod);
    free(dm_cli->so);
    amxd_dm_clean(&dm_cli->dm);

    return 0;
}

void test_can_invoke_help(UNUSED void** state) {
    dm_cli_t* dm_cli = dm_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "");

    cmd_rv = amxm_so_execute_function(dm_cli->so, "dm", "help", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_complete_help_command(UNUSED void** state) {
    dm_cli_t* dm_cli = dm_cli_get_data();
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
    cmd_rv = amxm_so_execute_function(dm_cli->so, "dm", "__complete_help", cmd_parts, ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_set_type(&check_var, AMXC_VAR_ID_LIST);
    amxc_var_add(cstring_t, &check_var, "load");
    expect_check(test_complete_cb, data, test_check_completion_list, &check_var);
    handle_events();

    amxc_var_clean(&tty_args);
    amxc_var_clean(&check_var);
}

void test_can_describe(UNUSED void** state) {
    dm_cli_t* dm_cli = dm_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "");
    cmd_rv = amxm_so_execute_function(dm_cli->so, "dm", "__describe", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);
    assert_int_equal(amxc_var_type_of(&ret), AMXC_VAR_ID_CSTRING);
    assert_string_equal(amxc_var_constcast(cstring_t, &ret), "Data Model cli.");

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_load_fails_with_invalid_options(UNUSED void** state) {
    dm_cli_t* dm_cli = dm_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "-d ./test.odl");
    cmd_rv = amxm_so_execute_function(dm_cli->so, "dm", "load", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_load_fails_with_too_many_args(UNUSED void** state) {
    dm_cli_t* dm_cli = dm_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "./test.odl extra arguments");
    cmd_rv = amxm_so_execute_function(dm_cli->so, "dm", "load", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_load_data_model(UNUSED void** state) {
    dm_cli_t* dm_cli = dm_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "./test.odl");
    cmd_rv = amxm_so_execute_function(dm_cli->so, "dm", "load", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_complete_load_command(UNUSED void** state) {
    dm_cli_t* dm_cli = dm_cli_get_data();
    int cmd_rv = 0;
    amxc_var_t* cmd_parts = NULL;
    amxc_var_t* ret = NULL;
    amxc_var_t tty_args;
    amxc_var_t check_var;

    amxc_var_init(&tty_args);
    amxc_var_init(&check_var);

    amxc_var_new(&ret);
    amxc_var_set_type(ret, AMXC_VAR_ID_LIST);
    amxt_cli_build_args(&tty_args, "./test.");
    cmd_parts = GET_ARG(&tty_args, "cmd");
    cmd_rv = amxm_so_execute_function(dm_cli->so, "dm", "__complete_load", cmd_parts, ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_set_type(&check_var, AMXC_VAR_ID_LIST);
    amxc_var_add(cstring_t, &check_var, "./test.odl");
    expect_check(test_complete_cb, data, test_check_completion_list, &check_var);
    handle_events();

    amxc_var_clean(&tty_args);
    amxc_var_clean(&check_var);
}

void test_can_save_data_model(UNUSED void** state) {
    dm_cli_t* dm_cli = dm_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "./saved.odl");
    cmd_rv = amxm_so_execute_function(dm_cli->so, "dm", "save", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_save_fails_if_file_can_not_be_created(UNUSED void** state) {
    dm_cli_t* dm_cli = dm_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "./not-exising-dir/saved.odl");
    cmd_rv = amxm_so_execute_function(dm_cli->so, "dm", "save", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_save_fails_if_object_not_found(UNUSED void** state) {
    dm_cli_t* dm_cli = dm_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "./saved.odl DummyObject");
    cmd_rv = amxm_so_execute_function(dm_cli->so, "dm", "save", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_save_fails_if_no_file_name(UNUSED void** state) {
    dm_cli_t* dm_cli = dm_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "");
    cmd_rv = amxm_so_execute_function(dm_cli->so, "dm", "save", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_save_fails_if_too_many_arguments(UNUSED void** state) {
    dm_cli_t* dm_cli = dm_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "./saved.odl Greeter. extra arguments");
    cmd_rv = amxm_so_execute_function(dm_cli->so, "dm", "save", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_reset_fails_if_too_many_arguments(UNUSED void** state) {
    dm_cli_t* dm_cli = dm_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "extra arguments");
    cmd_rv = amxm_so_execute_function(dm_cli->so, "dm", "reset", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_reset_data_model(UNUSED void** state) {
    dm_cli_t* dm_cli = dm_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "");
    cmd_rv = amxm_so_execute_function(dm_cli->so, "dm", "reset", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}