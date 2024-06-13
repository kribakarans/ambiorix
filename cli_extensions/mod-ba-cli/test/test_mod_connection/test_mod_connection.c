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

#include "common_mock.h"
#include "tty_mock.h"
#include "dummy_backend.h"
#include "test_mod_connection.h"

static amxp_connection_t* cur_con = NULL;

static void test_mod_connection_added(UNUSED const char* const sig_name,
                                      const amxc_var_t* const data,
                                      UNUSED void* const priv) {
    printf("TEST\n");
    if(amxc_var_type_of(data) != AMXC_VAR_ID_FD) {
        goto leave;
    }

    cur_con = amxp_connection_get(amxc_var_constcast(fd_t, data));

leave:
    return;
}

int test_mod_connection_setup(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();

    ba_cli->so = (amxm_shared_object_t*) calloc(1, sizeof(amxm_shared_object_t));
    amxc_llist_init(&ba_cli->so->amxm_module_llist);
    strncpy(ba_cli->so->name, "test_shared_object", AMXM_MODULE_NAME_LENGTH);
    strncpy(ba_cli->so->file, "test_shared_object.so", AMXM_MODULE_NAME_LENGTH);

    assert_int_equal(amxt_tty_open(&ba_cli->tty, fileno(stdin)), 0);

    amxp_sigmngr_add_signal(NULL, "connection-added");
    amxp_slot_connect(NULL, "connection-added", NULL, test_mod_connection_added, NULL);

    amxp_sigmngr_add_signal(ba_cli->tty->sigmngr, "tty:docomplete");
    amxp_slot_connect(ba_cli->tty->sigmngr, "tty:docomplete", NULL, test_complete_cb, NULL);

    mod_connection_start(ba_cli->so);

    assert_int_equal(test_register_dummy_be(), 0);

    return 0;
}

int test_mod_connection_teardown(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();

    mod_connection_stop(ba_cli->so);

    amxt_tty_close(&ba_cli->tty);

    amxc_llist_clean(&ba_cli->so->amxm_module_llist, amxm_test_so_remove_mod);
    free(ba_cli->so);

    test_unregister_dummy_be();

    return 0;
}

void test_can_invoke_help(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "");

    cmd_rv = amxm_so_execute_function(ba_cli->so, "connection", "help", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_complete_help_command(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;
    amxc_var_t* cmd_parts = NULL;
    amxc_var_t* ret = NULL;
    amxc_var_t tty_args;
    amxc_var_t check_var;

    amxc_var_init(&tty_args);
    amxc_var_init(&check_var);

    amxc_var_new(&ret);
    amxc_var_set_type(ret, AMXC_VAR_ID_LIST);
    amxt_cli_build_args(&tty_args, "o");
    cmd_parts = GET_ARG(&tty_args, "cmd");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "connection", "__complete_help", cmd_parts, ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_set_type(&check_var, AMXC_VAR_ID_LIST);
    amxc_var_add(cstring_t, &check_var, "open");
    expect_check(test_complete_cb, data, test_check_completion_list, &check_var);
    handle_events();

    amxc_var_clean(&tty_args);
    amxc_var_clean(&check_var);
}

void test_can_describe(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "connection", "__describe", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);
    assert_int_equal(amxc_var_type_of(&ret), AMXC_VAR_ID_CSTRING);
    assert_string_equal(amxc_var_constcast(cstring_t, &ret), "Manage connections")
    ;
    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_list_fails_if_no_open_connections(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "connection", "list", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_complete_open_command(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;
    amxc_var_t* cmd_parts = NULL;
    amxc_var_t* ret = NULL;
    amxc_var_t tty_args;
    amxc_var_t check_var;

    amxc_var_init(&tty_args);
    amxc_var_init(&check_var);

    amxc_var_new(&ret);
    amxc_var_set_type(ret, AMXC_VAR_ID_LIST);
    amxt_cli_build_args(&tty_args, "dum");
    cmd_parts = GET_ARG(&tty_args, "cmd");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "connection", "__complete_open", cmd_parts, ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_set_type(&check_var, AMXC_VAR_ID_LIST);
    amxc_var_add(cstring_t, &check_var, "dummy:");
    expect_check(test_complete_cb, data, test_check_completion_list, &check_var);
    handle_events();

    amxc_var_new(&ret);
    amxc_var_set_type(ret, AMXC_VAR_ID_LIST);
    amxt_cli_build_args(&tty_args, "dummy: test");
    cmd_parts = GET_ARG(&tty_args, "cmd");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "connection", "__complete_open", cmd_parts, ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_set_type(&check_var, AMXC_VAR_ID_LIST);
    expect_check(test_complete_cb, data, test_check_completion_list, &check_var);
    handle_events();

    amxc_var_clean(&tty_args);
    amxc_var_clean(&check_var);
}

void test_can_open_connection(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;
    amxc_var_t* connection = NULL;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "dummy:/var/run/test.sock");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "connection", "open", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    handle_events();
    assert_non_null(cur_con);
    connection = amxt_tty_claim_config(ba_cli->tty, "connection");
    assert_non_null(amxc_var_constcast(cstring_t, connection));
    assert_string_equal(amxc_var_constcast(cstring_t, connection), "dummy:/var/run/test.sock");

    cur_con = NULL;
    amxt_cli_build_args(&tty_args, "dummy:/var/run/test2.sock");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "connection", "open", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);
    assert_string_equal(amxc_var_constcast(cstring_t, connection), "dummy:/var/run/test.sock");

    handle_events();
    assert_non_null(cur_con);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_read_data(UNUSED void** state) {
    amxb_bus_ctx_t* bus_ctx = NULL;

    handle_events();
    assert_non_null(cur_con);
    bus_ctx = amxb_find_uri("dummy:/var/run/test.sock");

    test_write_data(bus_ctx, "hello", 5);
    cur_con->reader(cur_con->fd, cur_con->priv);
}

void test_can_open_uri_only_once(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "dummy:/var/run/test.sock");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "connection", "open", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_open_fails_if_too_many_args(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "dummy:/var/run/test.sock extra arguments");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "connection", "open", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_open_fails_for_unsupported_uri(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "ne:/var/run/fake.sock");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "connection", "open", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_list_open_connections(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "connection", "list", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_list_fails_if_too_many_args(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "extra arguments");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "connection", "list", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_select_any_connection(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;
    amxc_var_t* connection = NULL;
    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    connection = amxt_tty_claim_config(ba_cli->tty, "connection");

    amxt_cli_build_args(&tty_args, "*");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "connection", "select", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);
    assert_string_equal(amxc_var_constcast(cstring_t, connection), "*");

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_select_connection(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;
    amxc_var_t* connection = NULL;
    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    connection = amxt_tty_claim_config(ba_cli->tty, "connection");

    amxt_cli_build_args(&tty_args, "dummy:/var/run/test2.sock");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "connection", "select", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);
    assert_string_equal(amxc_var_constcast(cstring_t, connection), "dummy:/var/run/test2.sock");

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_select_fails_if_too_many_args(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "dummy:/var/run/test.sock extra arguments");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "connection", "select", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_select_fails_if_connection_uri_is_not_opened(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "dummy:/var/run/test3.sock");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "connection", "select", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_set_access(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "dummy:/var/run/test.sock protected");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "connection", "access", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    amxt_cli_build_args(&tty_args, "dummy:/var/run/test.sock public");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "connection", "access", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_set_access_fails_if_too_many_args(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "dummy:/var/run/test.sock protected dada");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "connection", "access", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_set_access_fails_if_uri_not_opened(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "dummy:/var/run/test3.sock protected");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "connection", "access", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_set_access_fails_if_no_access_provided(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "dummy:/var/run/test.sock");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "connection", "access", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_set_access_fails_if_invalid_access_method(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "dummy:/var/run/test.sock invalid");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "connection", "access", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_complete_close_command(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;
    amxc_var_t* cmd_parts = NULL;
    amxc_var_t* ret = NULL;
    amxc_var_t tty_args;
    amxc_var_t check_var;

    amxc_var_init(&tty_args);
    amxc_var_init(&check_var);

    amxc_var_new(&ret);
    amxc_var_set_type(ret, AMXC_VAR_ID_LIST);
    amxt_cli_build_args(&tty_args, "dum");
    cmd_parts = GET_ARG(&tty_args, "cmd");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "connection", "__complete_close", cmd_parts, ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_set_type(&check_var, AMXC_VAR_ID_LIST);
    amxc_var_add(cstring_t, &check_var, "dummy:/var/run/test.sock");
    amxc_var_add(cstring_t, &check_var, "dummy:/var/run/test2.sock");
    expect_check(test_complete_cb, data, test_check_completion_list, &check_var);
    handle_events();

    amxc_var_new(&ret);
    amxc_var_set_type(ret, AMXC_VAR_ID_LIST);
    amxt_cli_build_args(&tty_args, "dummy:/ test");
    cmd_parts = GET_ARG(&tty_args, "cmd");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "connection", "__complete_close", cmd_parts, ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_set_type(&check_var, AMXC_VAR_ID_LIST);
    expect_check(test_complete_cb, data, test_check_completion_list, &check_var);
    handle_events();

    amxc_var_clean(&tty_args);
    amxc_var_clean(&check_var);
}

void test_close_fails_for_unsupported_uri(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "ne:/var/run/fake.sock");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "connection", "close", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_close_fails_if_too_many_args(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "dummy:/var/run/test.sock extra arguments");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "connection", "close", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_close_connection(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "dummy:/var/run/test.sock");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "connection", "close", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_close_fails_on_closed_connection(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "dummy:/var/run/test.sock");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "connection", "close", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_listen_fails_when_ba_error(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "dummy:/var/run/invalid.sock");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "connection", "listen", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_listen_fails_if_too_many_args(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "dummy:/var/run/dummy_listen.sock extra data");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "connection", "listen", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_listen_fails_if_already_listening(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "dummy:/var/run/dummy_listen.sock");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "connection", "listen", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    amxt_cli_build_args(&tty_args, "dummy:/var/run/dummy_listen.sock");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "connection", "listen", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}
