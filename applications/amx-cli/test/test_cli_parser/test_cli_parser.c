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
#include "amx_cli_parser.h"
#include "test_cli_parser.h"

int test_cli_parser_setup(UNUSED void** state) {
    cli_app_t* amx_cli = amx_cli_get_data();
    amxt_tty_open(&amx_cli->tty, fileno(stdin));

    amxc_var_init(&amx_cli->aliases);
    amxc_var_set_type(&amx_cli->aliases, AMXC_VAR_ID_HTABLE);

    setenv("AMXRT_PREFIX_PATH", "./", 1);
    setenv("AMXRT_PLUGIN_DIR", "plugin", 1);
    setenv("AMXRT_CFG_DIR", "cfg", 1);

    amx_cli->shared_object = NULL;
    amx_cli->module = NULL;

    amxp_sigmngr_add_signal(amx_cli->tty->sigmngr, "tty:newline");
    amxp_sigmngr_add_signal(amx_cli->tty->sigmngr, "tty:docomplete");
    amxp_slot_connect(amx_cli->tty->sigmngr, "tty:docomplete", NULL, test_complete_cb, NULL);
    amxp_slot_connect(amx_cli->tty->sigmngr, "tty:newline", NULL, amx_cli_slot_new_line, NULL);

    return 0;
}

int test_cli_parser_teardown(UNUSED void** state) {
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

void test_cli_parser_can_handle_command(UNUSED void** state) {
    amxt_tty_t* tty = amx_cli_get_tty();
    amxc_var_t cmd_data;

    amxc_var_init(&cmd_data);
    amxc_var_set_type(&cmd_data, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(amxt_tty_t, &cmd_data, "tty", tty);
    amxc_var_add_key(cstring_t, &cmd_data, "text", "!help");

    amxp_sigmngr_trigger_signal(tty->sigmngr, "tty:newline", &cmd_data);

    amxc_var_clean(&cmd_data);
}

void test_cli_parser_dumps_comments(UNUSED void** state) {
    amxt_tty_t* tty = amx_cli_get_tty();
    amxc_var_t cmd_data;
    amxc_var_t* txt = NULL;

    amxc_var_init(&cmd_data);
    amxc_var_set_type(&cmd_data, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(amxt_tty_t, &cmd_data, "tty", tty);
    txt = amxc_var_add_key(cstring_t, &cmd_data, "text", "# This is a comment");
    amxp_sigmngr_trigger_signal(tty->sigmngr, "tty:newline", &cmd_data);

    amxc_var_set(cstring_t, txt, "#");
    amxp_sigmngr_trigger_signal(tty->sigmngr, "tty:newline", &cmd_data);

    amxc_var_set(cstring_t, txt, "# ");
    amxp_sigmngr_trigger_signal(tty->sigmngr, "tty:newline", &cmd_data);

    amxc_var_clean(&cmd_data);
}

void test_cli_parser_skips_empty_lines(UNUSED void** state) {
    amxt_tty_t* tty = amx_cli_get_tty();
    amxc_var_t cmd_data;
    amxc_var_t* txt = NULL;

    amxc_var_init(&cmd_data);
    amxc_var_set_type(&cmd_data, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(amxt_tty_t, &cmd_data, "tty", tty);
    txt = amxc_var_add_key(cstring_t, &cmd_data, "text", "");
    amxp_sigmngr_trigger_signal(tty->sigmngr, "tty:newline", &cmd_data);

    amxc_var_set(cstring_t, txt, " \t\n  ");
    amxp_sigmngr_trigger_signal(tty->sigmngr, "tty:newline", &cmd_data);

    amxc_var_clean(&cmd_data);
}

void test_cli_parser_does_syntax_check(UNUSED void** state) {
    amxt_tty_t* tty = amx_cli_get_tty();
    amxc_var_t cmd_data;
    amxc_var_t* txt = NULL;

    amxc_var_init(&cmd_data);
    amxc_var_set_type(&cmd_data, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(amxt_tty_t, &cmd_data, "tty", tty);
    txt = amxc_var_add_key(cstring_t, &cmd_data, "text", "This is `quoted");
    amxp_sigmngr_trigger_signal(tty->sigmngr, "tty:newline", &cmd_data);

    amxc_var_set(cstring_t, txt, "Missing square bracket ]");
    amxp_sigmngr_trigger_signal(tty->sigmngr, "tty:newline", &cmd_data);

    amxc_var_set(cstring_t, txt, "{Missing square bracket ");
    amxp_sigmngr_trigger_signal(tty->sigmngr, "tty:newline", &cmd_data);

    amxc_var_clean(&cmd_data);
}

void test_cli_parser_can_execute_aliases(UNUSED void** state) {
    amxt_tty_t* tty = amx_cli_get_tty();
    amxc_var_t cmd_data;
    amxc_var_t* txt = NULL;

    amxc_var_init(&cmd_data);
    amxc_var_set_type(&cmd_data, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(amxt_tty_t, &cmd_data, "tty", tty);
    txt = amxc_var_add_key(cstring_t, &cmd_data, "text", "!amx alias myalias '!history show; !help'");
    amxp_sigmngr_trigger_signal(tty->sigmngr, "tty:newline", &cmd_data);

    amxc_var_set(cstring_t, txt, "myalias record play");
    amxp_sigmngr_trigger_signal(tty->sigmngr, "tty:newline", &cmd_data);

    amxc_var_clean(&cmd_data);
}

void test_cli_parser_prints_error_on_invalid_command(UNUSED void** state) {
    amxt_tty_t* tty = amx_cli_get_tty();
    amxc_var_t cmd_data;

    amxc_var_init(&cmd_data);
    amxc_var_set_type(&cmd_data, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(amxt_tty_t, &cmd_data, "tty", tty);
    amxc_var_add_key(cstring_t, &cmd_data, "text", "!amx invalid print");
    amxp_sigmngr_trigger_signal(tty->sigmngr, "tty:newline", &cmd_data);

    amxc_var_clean(&cmd_data);
}

void test_cli_parser_prints_command_parts_when_dbg_enabled(UNUSED void** state) {
    amxt_tty_t* tty = amx_cli_get_tty();
    amxc_var_t cmd_data;
    amxc_var_t* tty_dbg = amxt_tty_claim_config(tty, "tty-dbg");

    amxc_var_set(bool, tty_dbg, true);
    amxc_var_init(&cmd_data);
    amxc_var_set_type(&cmd_data, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(amxt_tty_t, &cmd_data, "tty", tty);
    amxc_var_add_key(cstring_t, &cmd_data, "text", "myalias record play");
    amxp_sigmngr_trigger_signal(tty->sigmngr, "tty:newline", &cmd_data);

    amxc_var_set(bool, tty_dbg, false);

    amxc_var_clean(&cmd_data);
}