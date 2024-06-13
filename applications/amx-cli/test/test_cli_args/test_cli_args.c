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
#include <getopt.h>

#include "tty_mock.h"
#include "common_mock.h"
#include "test_cli_args.h"

int test_cli_args_setup(UNUSED void** state) {
    cli_app_t* amx_cli = amx_cli_get_data();
    amxt_tty_open(&amx_cli->tty, -1);
    return 0;
}

int test_cli_args_teardown(UNUSED void** state) {
    cli_app_t* amx_cli = amx_cli_get_data();
    amxt_tty_close(&amx_cli->tty);
    return 0;
}

void test_cli_can_print_usage(UNUSED void** state) {
    cli_app_t* amx_cli = amx_cli_get_data();
    int argc = 2;
    char* argv[] = { "amx-cli", "-h"};
    amxc_string_t cmds;

    amxc_string_init(&cmds, 0);

    assert_int_equal(amx_cli_args_parse(amx_cli, argc, argv, &cmds), -1);
    assert_string_equal(amxc_string_get(&cmds, 0), "");

    optind = 0;
    argv[1] = "--help";
    amxc_string_reset(&cmds);
    assert_int_equal(amx_cli_args_parse(amx_cli, argc, argv, &cmds), -1);
    assert_string_equal(amxc_string_get(&cmds, 0), "");

    amxc_string_clean(&cmds);
}

void test_cli_can_run_help(UNUSED void** state) {
    cli_app_t* amx_cli = amx_cli_get_data();
    int argc = 3;
    char* argv[] = { "amx-cli", "-H"};
    amxc_string_t cmds;

    optind = 0;
    amxc_string_init(&cmds, 0);

    assert_int_equal(amx_cli_args_parse(amx_cli, argc, argv, &cmds), -1);
    assert_string_equal(amxc_string_get(&cmds, 0), "help;");
    printf("Startup commands: %s\n", amxc_string_get(&cmds, 0));

    optind = 0;
    argv[1] = "--HELP";
    amxc_string_reset(&cmds);
    assert_int_equal(amx_cli_args_parse(amx_cli, argc, argv, &cmds), -1);
    assert_string_equal(amxc_string_get(&cmds, 0), "help;");

    amxc_string_clean(&cmds);
}

void test_cli_can_set_user(UNUSED void** state) {
    cli_app_t* amx_cli = amx_cli_get_data();
    int argc = 3;
    char* argv[] = { "pcb-cli", "-u", "operator"};
    amxc_string_t cmds;

    optind = 0;
    amxc_string_init(&cmds, 0);

    assert_int_equal(amx_cli_args_parse(amx_cli, argc, argv, &cmds), argc);
    assert_string_equal(amxc_string_get(&cmds, 0),
                        "!amx variable acl-enabled = true;!amx variable role = operator;");
    printf("Startup commands: %s\n", amxc_string_get(&cmds, 0));

    optind = 0;
    argv[1] = "--user";
    amxc_string_reset(&cmds);
    assert_int_equal(amx_cli_args_parse(amx_cli, argc, argv, &cmds), argc);
    assert_string_equal(amxc_string_get(&cmds, 0),
                        "!amx variable acl-enabled = true;!amx variable role = operator;");

    amxc_string_clean(&cmds);
}

void test_cli_can_set_output_format_json(UNUSED void** state) {
    cli_app_t* amx_cli = amx_cli_get_data();
    int argc = 2;
    char* argv[] = { "pcb-cli", "-j"};
    amxc_string_t cmds;

    optind = 0;
    amxc_string_init(&cmds, 0);

    assert_int_equal(amx_cli_args_parse(amx_cli, argc, argv, &cmds), argc);
    assert_string_equal(amxc_string_get(&cmds, 0), "!amx variable output-format = json;");
    printf("Startup commands: %s\n", amxc_string_get(&cmds, 0));

    optind = 0;
    argv[1] = "--json";
    amxc_string_reset(&cmds);
    assert_int_equal(amx_cli_args_parse(amx_cli, argc, argv, &cmds), argc);
    assert_string_equal(amxc_string_get(&cmds, 0), "!amx variable output-format = json;");

    amxc_string_clean(&cmds);
}

void test_cli_can_set_init_script(UNUSED void** state) {
    cli_app_t* amx_cli = amx_cli_get_data();
    int argc = 3;
    char* argv[] = { "pcb-cli", "-s", "/etc/amx/cli/ubus-cli.init"};
    amxc_var_t* script = NULL;
    amxc_string_t cmds;

    optind = 0;
    amxc_string_init(&cmds, 0);

    assert_int_equal(amx_cli_args_parse(amx_cli, argc, argv, &cmds), argc);

    script = amxt_tty_claim_config(amx_cli->tty, "init-script");
    assert_string_equal(amxc_var_constcast(cstring_t, script), "/etc/amx/cli/ubus-cli.init");

    amxc_var_set(cstring_t, script, "/etc/amx/cli/pcb-cli.init");
    optind = 0;
    argv[1] = "--script";
    amxc_string_reset(&cmds);
    assert_int_equal(amx_cli_args_parse(amx_cli, argc, argv, &cmds), argc);
    script = amxt_tty_claim_config(amx_cli->tty, "init-script");
    assert_string_equal(amxc_var_constcast(cstring_t, script), "/etc/amx/cli/ubus-cli.init");

    amxc_string_clean(&cmds);
}

void test_cli_cannot_pass_invalid_argument(UNUSED void** state) {
    cli_app_t* amx_cli = amx_cli_get_data();
    int argc = 2;
    char* argv[] = { "pcb-cli", "-y"};
    amxc_string_t cmds;

    optind = 0;
    amxc_string_init(&cmds, 0);

    assert_int_equal(amx_cli_args_parse(amx_cli, argc, argv, &cmds), -1);
    assert_string_equal(amxc_string_get(&cmds, 0), "");

    amxc_string_clean(&cmds);
}

void test_cli_can_pass_option_and_command(UNUSED void** state) {
    cli_app_t* amx_cli = amx_cli_get_data();
    int argc = 3;
    char* argv[] = { "pcb-cli", "-j", "Greeter.?"};
    amxc_string_t cmds;

    optind = 0;
    amxc_string_init(&cmds, 0);

    assert_int_equal(amx_cli_args_parse(amx_cli, argc, argv, &cmds), 2);
    assert_string_equal(amxc_string_get(&cmds, 0), "!amx variable output-format = json;");
    printf("Startup commands: %s\n", amxc_string_get(&cmds, 0));

    optind = 0;
    argv[1] = "--json";
    amxc_string_reset(&cmds);
    assert_int_equal(amx_cli_args_parse(amx_cli, argc, argv, &cmds), 2);
    assert_string_equal(amxc_string_get(&cmds, 0), "!amx variable output-format = json;");

    amxc_string_clean(&cmds);
}
