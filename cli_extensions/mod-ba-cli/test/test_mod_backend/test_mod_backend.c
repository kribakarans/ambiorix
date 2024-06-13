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
#include "test_mod_backend.h"

int test_mod_backend_setup(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    ba_cli->so = (amxm_shared_object_t*) calloc(1, sizeof(amxm_shared_object_t));
    amxc_llist_init(&ba_cli->so->amxm_module_llist);
    strncpy(ba_cli->so->name, "test_shared_object", AMXM_MODULE_NAME_LENGTH);
    strncpy(ba_cli->so->file, "test_shared_object.so", AMXM_MODULE_NAME_LENGTH);

    assert_int_equal(amxt_tty_open(&ba_cli->tty, fileno(stdin)), 0);

    amxp_sigmngr_add_signal(ba_cli->tty->sigmngr, "tty:docomplete");
    amxp_slot_connect(ba_cli->tty->sigmngr, "tty:docomplete", NULL, test_complete_cb, NULL);

    mod_backend_start(ba_cli->so);

    return 0;
}

int test_mod_backend_teardown(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    mod_backend_stop(ba_cli->so);

    amxt_tty_close(&ba_cli->tty);

    amxc_llist_clean(&ba_cli->so->amxm_module_llist, amxm_test_so_remove_mod);
    free(ba_cli->so);

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

    cmd_rv = amxm_so_execute_function(ba_cli->so, "backend", "help", &tty_args, &ret);
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
    amxt_cli_build_args(&tty_args, "r");
    cmd_parts = GET_ARG(&tty_args, "cmd");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "backend", "__complete_help", cmd_parts, ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_set_type(&check_var, AMXC_VAR_ID_LIST);
    amxc_var_add(cstring_t, &check_var, "remove");
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
    cmd_rv = amxm_so_execute_function(ba_cli->so, "backend", "__describe", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);
    assert_int_equal(amxc_var_type_of(&ret), AMXC_VAR_ID_CSTRING);
    assert_string_equal(amxc_var_constcast(cstring_t, &ret), "Manage backends")
    ;
    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_load_backend(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "/usr/bin/mods/amxb/mod-amxb-pcb.so");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "backend", "add", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    amxt_cli_build_args(&tty_args, "/usr/bin/mods/amxb/mod-amxb-ubus.so");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "backend", "add", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_load_backend_fails_if_too_many_args(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "/usr/bin/mods/amxb/mod-amxb-ubus.so second arg");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "backend", "add", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxt_cli_build_args(&tty_args, "/usr/bin/mods/amxb/ second arg");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "backend", "autoload", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_load_backend_fails_if_invalid_path(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "/usr/lib/fake/");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "backend", "autoload", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_load_backend_fails_if_invalid_file(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "/usr/lib/libamxo.so");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "backend", "add", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxt_cli_build_args(&tty_args, "/usr/lib/x86_64-linux-gnu/libamxo.so");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "backend", "add", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_complete_add_command_file_arg(UNUSED void** state) {
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
    amxt_cli_build_args(&tty_args, "/usr/bin/mods/amxb/mod-amxb-");
    cmd_parts = GET_ARG(&tty_args, "cmd");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "backend", "__complete_add", cmd_parts, ret);
    assert_int_equal(cmd_rv, 0);

    amxt_cli_build_args(&tty_args, "/usr/bin/mods/amxb/mod-amxb-");
    cmd_parts = GET_ARG(&tty_args, "cmd");
    amxc_var_set_type(&check_var, AMXC_VAR_ID_LIST);
    amxt_cmd_complete_path("test_func", cmd_parts, &check_var);
    expect_check(test_complete_cb, data, test_check_completion_list, &check_var);
    handle_events();

    amxc_var_clean(&tty_args);
    amxc_var_clean(&check_var);
}

void test_can_list_loaded_backend(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "backend", "list", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_list_fails_if_too_many_arguments(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "ubus pcb");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "backend", "list", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_remove_backend(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "pcb");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "backend", "remove", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_remove_backend_fails_if_not_found(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "pcb");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "backend", "remove", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_remove_backend_fails_if_too_many_args(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "/usr/bin/mods/amxb/mod-amxb-ubus.so second arg");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "backend", "remove", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_complete_remove_command(UNUSED void** state) {
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
    amxt_cli_build_args(&tty_args, "u");
    cmd_parts = GET_ARG(&tty_args, "cmd");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "backend", "__complete_remove", cmd_parts, ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_set_type(&check_var, AMXC_VAR_ID_LIST);
    amxc_var_add(cstring_t, &check_var, "ubus");
    expect_check(test_complete_cb, data, test_check_completion_list, &check_var);
    handle_events();

    amxc_var_clean(&tty_args);
    amxc_var_clean(&check_var);
}

void test_list_fails_if_no_backends_loaded(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "ubus");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "backend", "remove", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    amxt_cli_build_args(&tty_args, "");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "backend", "list", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_auto_load_backend(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "/usr/bin/mods/amxb/");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "backend", "autoload", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    // disabled as libdl allocates static memory which is never freed.
    // this causes valgrind to report memory leaks
    //amxt_cli_build_args(&tty_args, "/usr/lib/");
    //cmd_rv = amxm_so_execute_function(ba_cli->so, "backend", "autoload", &tty_args, &ret);
    //assert_int_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}
