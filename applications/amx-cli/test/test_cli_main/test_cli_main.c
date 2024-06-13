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
#include "test_cli_main.h"

void test_cli_can_run_init_script(UNUSED void** state) {
    cli_app_t* amx_cli = amx_cli_get_data();
    amxt_tty_t* tty = NULL;
    amxc_var_t* script = NULL;
    char cwd[128];

    amxt_tty_open(&amx_cli->tty, -1);
    tty = amx_cli_get_tty();

    getcwd(cwd, 128);
    setenv("AMX_PREFIX", cwd, true);

    script = amxt_tty_claim_config(tty, "init-script");
    assert_int_equal(amx_cli_init(amx_cli, "test", false), 0);

    amxt_tty_silent(tty, false);
    amxc_var_set(cstring_t, script, "./etc/amx/cli/test");
    amx_cli_run_script(amx_cli, false);
    amxt_tty_silent(tty, false);
    amxc_var_set(cstring_t, script, "./etc/amx/cli/test2");
    amx_cli_run_script(amx_cli, true);
    amxt_tty_silent(tty, true);
    amxc_var_set(cstring_t, script, "./etc/amx/cli/test");
    amx_cli_run_script(amx_cli, false);
    amxt_tty_silent(tty, true);
    amxc_var_set(cstring_t, script, "./etc/amx/cli/test2");
    amx_cli_run_script(amx_cli, true);
    amxt_tty_silent(tty, true);
    amxc_var_set(cstring_t, script, "./etc/amx/cli/test3");
    amx_cli_run_script(amx_cli, true);

    amx_cli_configure_self_modules(amx_cli);

    amx_cli_clean(amx_cli);
}

void test_cli_init_clean(UNUSED void** state) {
    cli_app_t* amx_cli = amx_cli_get_data();

    amxt_tty_open(&amx_cli->tty, -1);
    assert_int_equal(amx_cli_init(amx_cli, "test", false), 0);

    amx_cli_clean(amx_cli);
}

void test_cli_can_configure_self_mods(UNUSED void** state) {
    cli_app_t* amx_cli = amx_cli_get_data();
    char cwd[128];

    amxt_tty_open(&amx_cli->tty, -1);

    getcwd(cwd, 128);
    setenv("AMX_PREFIX", cwd, true);

    assert_int_equal(amx_cli_init(amx_cli, "test", false), 0);

    amx_cli_configure_self_modules(amx_cli);

    amx_cli_clean(amx_cli);
}

void test_cli_can_remove_self(UNUSED void** state) {
    cli_app_t* amx_cli = amx_cli_get_data();

    amxt_tty_open(&amx_cli->tty, -1);
    assert_int_equal(amx_cli_init(amx_cli, "no_self", false), 0);

    amx_cli_configure_self_modules(amx_cli);

    amx_cli_clean(amx_cli);
}
