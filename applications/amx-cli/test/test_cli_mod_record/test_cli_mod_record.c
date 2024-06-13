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
#include "test_cli_mod_record.h"

int test_cli_mod_record_setup(UNUSED void** state) {
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

int test_cli_mod_record_teardown(UNUSED void** state) {
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

    cmd_rv = amxm_so_execute_function(so, "record", "help", &tty_args, &ret);
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
    cmd_rv = amxm_so_execute_function(so, "record", "__complete_help", cmd_parts, ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_set_type(&check_var, AMXC_VAR_ID_LIST);
    amxc_var_add(cstring_t, &check_var, "play");
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
    cmd_rv = amxm_so_execute_function(so, "record", "__describe", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);
    assert_int_equal(amxc_var_type_of(&ret), AMXC_VAR_ID_CSTRING);
    assert_string_equal(amxc_var_constcast(cstring_t, &ret), "record and playback cli commands");

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_start_recording_fails_if_too_many_args(UNUSED void** state) {
    amxm_shared_object_t* so = amxm_get_so("self");
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "./test_record.rec extra args");
    cmd_rv = amxm_so_execute_function(so, "record", "start", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_start_recording_fails_if_no_file_name(UNUSED void** state) {
    amxm_shared_object_t* so = amxm_get_so("self");
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "");
    cmd_rv = amxm_so_execute_function(so, "record", "start", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_start_recording_fails_if_file_can_not_be_opened(UNUSED void** state) {
    amxm_shared_object_t* so = amxm_get_so("self");
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "/");
    cmd_rv = amxm_so_execute_function(so, "record", "start", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_start_recording(UNUSED void** state) {
    amxm_shared_object_t* so = amxm_get_so("self");
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "./test_record.rec");
    cmd_rv = amxm_so_execute_function(so, "record", "start", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);
    handle_events();

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_start_recording_fails_if_already_started(UNUSED void** state) {
    amxm_shared_object_t* so = amxm_get_so("self");
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "./test_record2.rec");
    cmd_rv = amxm_so_execute_function(so, "record", "start", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_recording_writes_to_file(UNUSED void** state) {
    amxt_tty_t* tty = amx_cli_get_tty();
    amxc_var_t cmd_data;
    amxc_var_t* txt = NULL;

    amxc_var_init(&cmd_data);
    amxc_var_set_type(&cmd_data, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(amxt_tty_t, &cmd_data, "tty", tty);
    txt = amxc_var_add_key(cstring_t, &cmd_data, "text", "!help");
    amxp_sigmngr_trigger_signal(tty->sigmngr, "tty:newline", &cmd_data);

    amxc_var_set(cstring_t, txt, "!help record");
    amxp_sigmngr_trigger_signal(tty->sigmngr, "tty:newline", &cmd_data);

    amxc_var_set(cstring_t, txt, "");
    amxp_sigmngr_trigger_signal(tty->sigmngr, "tty:newline", &cmd_data);

    amxc_var_clean(&cmd_data);
}

void test_stop_recording_fails_if_too_many_args(UNUSED void** state) {
    amxm_shared_object_t* so = amxm_get_so("self");
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "./test_record.rec");
    cmd_rv = amxm_so_execute_function(so, "record", "stop", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_stop_recording(UNUSED void** state) {
    amxm_shared_object_t* so = amxm_get_so("self");
    int cmd_rv = 0;
    FILE* rec_file = NULL;
    char* line = NULL;
    size_t len = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "");
    cmd_rv = amxm_so_execute_function(so, "record", "stop", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);
    handle_events();

    rec_file = fopen("./test_record.rec", "r");
    assert_non_null(rec_file);

    getline(&line, &len, rec_file);
    assert_non_null(line);
    assert_string_equal(line, "!help\n");
    free(line);
    line = NULL;

    getline(&line, &len, rec_file);
    assert_non_null(line);
    assert_string_equal(line, "!help record\n");
    free(line);
    line = NULL;

    fclose(rec_file);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_stop_recording_fails_if_not_started(UNUSED void** state) {
    amxm_shared_object_t* so = amxm_get_so("self");
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "");
    cmd_rv = amxm_so_execute_function(so, "record", "stop", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_complete_record(UNUSED void** state) {
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
    amxt_cli_build_args(&tty_args, "./test_rec");
    cmd_parts = GET_ARG(&tty_args, "cmd");
    cmd_rv = amxm_so_execute_function(so, "record", "__complete_start", cmd_parts, ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_set_type(&check_var, AMXC_VAR_ID_LIST);
    amxc_var_add(cstring_t, &check_var, "./test_record.rec");
    expect_check(test_complete_cb, data, test_check_completion_list, &check_var);
    handle_events();

    amxc_var_clean(&tty_args);
    amxc_var_clean(&check_var);
}

void test_can_play_recording(UNUSED void** state) {
    amxm_shared_object_t* so = amxm_get_so("self");
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "./test_record.rec");
    cmd_rv = amxm_so_execute_function(so, "record", "play", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_play_recording_fails_when_no_file_specified(UNUSED void** state) {
    amxm_shared_object_t* so = amxm_get_so("self");
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "");
    cmd_rv = amxm_so_execute_function(so, "record", "play", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_play_recording_fails_when_too_many_args(UNUSED void** state) {
    amxm_shared_object_t* so = amxm_get_so("self");
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "file1.rec file2.rec");
    cmd_rv = amxm_so_execute_function(so, "record", "play", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_play_recording_fails_file_can_not_be_opened(UNUSED void** state) {
    amxm_shared_object_t* so = amxm_get_so("self");
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "./not_existing.rec");
    cmd_rv = amxm_so_execute_function(so, "record", "play", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_play_recording_fails_file_while_recording(UNUSED void** state) {
    amxm_shared_object_t* so = amxm_get_so("self");
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "./test_record.rec");
    cmd_rv = amxm_so_execute_function(so, "record", "start", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);
    handle_events();

    amxt_cli_build_args(&tty_args, "./test_record.rec");
    cmd_rv = amxm_so_execute_function(so, "record", "play", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxt_cli_build_args(&tty_args, "");
    cmd_rv = amxm_so_execute_function(so, "record", "stop", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);
    handle_events();

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_play_recording_with_comments_shows_comments(UNUSED void** state) {
    amxm_shared_object_t* so = amxm_get_so("self");
    int cmd_rv = 0;
    amxc_var_t* myvar = NULL;
    amxt_tty_t* tty = amx_cli_get_tty();

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    myvar = amxt_tty_claim_config(tty, "MyVar");
    amxc_var_set(cstring_t, myvar, "Hello World");

    amxt_cli_build_args(&tty_args, "./comments.rec");
    cmd_rv = amxm_so_execute_function(so, "record", "play", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}