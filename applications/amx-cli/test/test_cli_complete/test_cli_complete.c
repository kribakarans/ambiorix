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
#include "test_cli_complete.h"

int test_cli_complete_setup(UNUSED void** state) {
    cli_app_t* amx_cli = amx_cli_get_data();
    amxt_tty_open(&amx_cli->tty, -1);
    assert_int_equal(amx_cli_init(amx_cli, "test-complete", false), 0);
    amxp_slot_connect(amx_cli->tty->sigmngr, "tty:docomplete", NULL, test_complete_cb, NULL);
    return 0;
}

int test_cli_complete_teardown(UNUSED void** state) {
    cli_app_t* amx_cli = amx_cli_get_data();
    amx_cli_clean(amx_cli);
    return 0;
}

void test_can_trigger_complete(UNUSED void** state) {
    amxt_tty_t* tty = amx_cli_get_tty();
    amxc_var_t check_var;

    amxc_var_t tty_args;
    amxc_var_init(&tty_args);
    amxc_var_init(&check_var);

    amxt_cli_build_args(&tty_args, "");
    amxt_il_insert_block(amxt_tty_il(tty), "", 0);
    amxp_sigmngr_trigger_signal(tty->sigmngr, "tty:complete", &tty_args);

    amxc_var_set_type(&check_var, AMXC_VAR_ID_LIST);
    amxc_var_add(cstring_t, &check_var, "!record ");
    amxc_var_add(cstring_t, &check_var, "!");
    amxc_var_add(cstring_t, &check_var, "!history ");
    amxc_var_add(cstring_t, &check_var, "!addon ");
    amxc_var_add(cstring_t, &check_var, "!help ");
    expect_check(test_complete_cb, data, test_check_completion_list, &check_var);
    handle_events();

    amxt_il_reset(amxt_tty_il(tty));

    amxc_var_clean(&tty_args);
    amxc_var_clean(&check_var);
}

void test_can_complete_bang(UNUSED void** state) {
    amxt_tty_t* tty = amx_cli_get_tty();
    amxc_var_t check_var;

    amxc_var_t tty_args;
    amxc_var_init(&tty_args);
    amxc_var_init(&check_var);

    amxt_cli_build_args(&tty_args, "!");
    amxt_il_insert_block(amxt_tty_il(tty), "!", 1);
    amxp_sigmngr_trigger_signal(tty->sigmngr, "tty:complete", &tty_args);

    amxc_var_set_type(&check_var, AMXC_VAR_ID_LIST);
    amxc_var_add(cstring_t, &check_var, "!record ");
    amxc_var_add(cstring_t, &check_var, "!amx ");
    amxc_var_add(cstring_t, &check_var, "!history ");
    amxc_var_add(cstring_t, &check_var, "!addon ");
    amxc_var_add(cstring_t, &check_var, "!help ");
    expect_check(test_complete_cb, data, test_check_completion_list, &check_var);
    handle_events();

    amxt_il_reset(amxt_tty_il(tty));

    amxc_var_clean(&tty_args);
    amxc_var_clean(&check_var);
}

void test_complete_submodules(UNUSED void** state) {
    amxt_tty_t* tty = amx_cli_get_tty();
    amxc_var_t check_var;

    amxc_var_t tty_args;
    amxc_var_init(&tty_args);
    amxc_var_init(&check_var);

    amxt_cli_build_args(&tty_args, "!addon l");
    amxt_il_insert_block(amxt_tty_il(tty), "!addon l", 8);
    amxp_sigmngr_trigger_signal(tty->sigmngr, "tty:complete", &tty_args);

    amxc_var_set_type(&check_var, AMXC_VAR_ID_LIST);
    amxc_var_add(cstring_t, &check_var, "list");
    amxc_var_add(cstring_t, &check_var, "load");
    expect_check(test_complete_cb, data, test_check_completion_list, &check_var);
    handle_events();

    amxt_il_reset(amxt_tty_il(tty));

    amxc_var_clean(&tty_args);
    amxc_var_clean(&check_var);
}

void test_complete_prints_string(UNUSED void** state) {
    amxt_tty_t* tty = amx_cli_get_tty();
    amxc_var_t check_var;

    amxc_var_t tty_args;
    amxc_var_init(&tty_args);
    amxc_var_init(&check_var);

    amxt_cli_build_args(&tty_args, "!addon load ");
    amxt_il_insert_block(amxt_tty_il(tty), "!addon load ", 12);
    amxp_sigmngr_trigger_signal(tty->sigmngr, "tty:complete", &tty_args);

    amxc_var_set_type(&check_var, AMXC_VAR_ID_LIST);
    expect_check(test_complete_cb, data, test_check_completion_list, &check_var);
    handle_events();

    amxt_il_reset(amxt_tty_il(tty));

    amxc_var_clean(&tty_args);
    amxc_var_clean(&check_var);
}

void test_complete_takes_aliasses_into_acount(UNUSED void** state) {
    amxm_shared_object_t* so = amxm_get_so("self");
    amxt_tty_t* tty = amx_cli_get_tty();
    amxc_var_t check_var;
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);
    amxc_var_init(&check_var);

    amxt_cli_build_args(&tty_args, "test-alias '!help;!help addon'");
    cmd_rv = amxm_so_execute_function(so, "amx", "alias", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    amxt_cli_build_args(&tty_args, "tes");
    amxt_il_insert_block(amxt_tty_il(tty), "tes", 3);
    amxp_sigmngr_trigger_signal(tty->sigmngr, "tty:complete", &tty_args);

    amxc_var_set_type(&check_var, AMXC_VAR_ID_LIST);
    amxc_var_add(cstring_t, &check_var, "test-alias");
    expect_check(test_complete_cb, data, test_check_completion_list, &check_var);
    handle_events();

    amxt_il_reset(amxt_tty_il(tty));

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
    amxc_var_clean(&check_var);
}

void test_complete_help_modules(UNUSED void** state) {
    amxt_tty_t* tty = amx_cli_get_tty();
    amxc_var_t check_var;

    amxc_var_t tty_args;
    amxc_var_init(&tty_args);
    amxc_var_init(&check_var);

    amxt_cli_build_args(&tty_args, "!help am");
    amxt_il_insert_block(amxt_tty_il(tty), "!help am", 8);
    amxp_sigmngr_trigger_signal(tty->sigmngr, "tty:complete", &tty_args);

    amxc_var_set_type(&check_var, AMXC_VAR_ID_LIST);
    amxc_var_add(cstring_t, &check_var, "amx");
    expect_check(test_complete_cb, data, test_check_completion_list, &check_var);
    handle_events();

    amxt_il_reset(amxt_tty_il(tty));

    amxc_var_clean(&tty_args);
    amxc_var_clean(&check_var);
}

void test_complete_help_submodules(UNUSED void** state) {
    amxm_shared_object_t* so = amxm_get_so("self");
    amxt_tty_t* tty = amx_cli_get_tty();
    amxc_var_t check_var;
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);
    amxc_var_init(&check_var);

    amxt_cli_build_args(&tty_args, "!help amx l");
    amxt_il_insert_block(amxt_tty_il(tty), "!help amx l", 11);
    amxp_sigmngr_trigger_signal(tty->sigmngr, "tty:complete", &tty_args);

    amxc_var_set_type(&check_var, AMXC_VAR_ID_LIST);
    amxc_var_add(cstring_t, &check_var, "log");
    expect_check(test_complete_cb, data, test_check_completion_list, &check_var);
    handle_events();

    amxt_il_reset(amxt_tty_il(tty));

    amxt_cli_build_args(&tty_args, "");
    cmd_rv = amxm_so_execute_function(so, "help", "__execute", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
    amxc_var_clean(&check_var);
}