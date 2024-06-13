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

#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>
#include <fcntl.h>

#include <amxc/amxc_macros.h>

#include "tty_mock.h"

// TTY Mocking
///////////////////////////////////////////////////////////////////////////////
static char input_data[128] = "";

static void test_tty_resolve(amxc_string_t* txt, void* priv) {
    amxt_tty_t* tty = (amxt_tty_t*) priv;
    amxc_ts_t now;
    char time[64];
    amxc_var_t* var_time = NULL;

    amxc_ts_now(&now);
    amxc_ts_format_precision(&now, time, 64, 0);
    var_time = amxc_var_get_key(&tty->config, "time", AMXC_VAR_FLAG_DEFAULT);
    amxc_var_set(cstring_t, var_time, time);

    amxc_string_resolve(txt, &tty->config);
}

static int amxt_tty_init_config(amxt_tty_t* const tty) {
    int retval = -1;
    amxc_ts_t now;
    amxc_var_t* color = NULL;
    char time[64];

    when_failed(amxc_var_init(&tty->config), exit);
    when_failed(amxc_var_set_type(&tty->config, AMXC_VAR_ID_HTABLE), exit);

    color = amxc_var_add_key(amxc_htable_t, &tty->config, "color", NULL);
    amxc_var_add_key(cstring_t, color, "green", AMXT_TTY_BRIGHT_GREEN);
    amxc_var_add_key(cstring_t, color, "yellow", AMXT_TTY_BRIGHT_YELLOW);
    amxc_var_add_key(cstring_t, color, "blue", AMXT_TTY_BRIGHT_BLUE);
    amxc_var_add_key(cstring_t, color, "white", AMXT_TTY_BRIGHT_WHITE);
    amxc_var_add_key(cstring_t, color, "red", AMXT_TTY_BRIGHT_RED);
    amxc_var_add_key(cstring_t, color, "reset", AMXT_TTY_RESET);
    amxc_var_add_key(cstring_t, color, "bg-red", AMXT_TTY_BG_RED);
    amxc_var_add_key(cstring_t, color, "bg-green", AMXT_TTY_BG_GREEN);
    amxc_var_add_key(cstring_t, color, "bg-black", AMXT_TTY_BG_BLACK);

    amxc_ts_now(&now);
    amxc_ts_format_precision(&now, time, 64, 0);
    amxc_var_add_key(cstring_t, &tty->config, "time", time);

    retval = 0;
exit:
    return retval;
}

ssize_t __wrap_read(UNUSED int fd, void* buf, size_t count) {
    size_t length = strlen(input_data);
    ssize_t bytes = count < length ? count : length;
    memcpy(buf, input_data, bytes);
    return bytes;
}

ssize_t __wrap_write(UNUSED int fd, UNUSED void* buf, size_t count) {
    ssize_t bytes = count;
    return bytes;
}

int __wrap_amxt_tty_open(amxt_tty_t** tty, UNUSED int fd) {
    int retval = -1;

    *tty = (amxt_tty_t*) calloc(1, sizeof(amxt_tty_t));
    when_null(*tty, exit);

    when_failed(amxt_il_init(&(*tty)->il_buffer, 64), exit);
    when_failed(amxt_hist_init(&(*tty)->history), exit);
    when_failed(amxt_prompt_init(&(*tty)->prompt), exit);
    when_failed(amxt_prompt_set_resolver(&(*tty)->prompt,
                                         test_tty_resolve,
                                         *tty), exit);
    when_failed(amxt_tty_init_config(*tty), exit);

    (*tty)->tty_fd = STDOUT_FILENO;

    retval = 0;

exit:
    if((tty != NULL) && (retval != 0)) {
        amxt_tty_close(tty);
    }
    return retval;
}

int __wrap_amxt_tty_close(amxt_tty_t** tty) {
    int retval = -1;

    when_null(tty, exit);
    when_null(*tty, exit);

    amxt_tty_writef(*tty, AMXT_TTY_RESET);

    amxc_var_clean(&(*tty)->config);
    amxt_il_clean(&(*tty)->il_buffer);
    amxt_hist_clean(&(*tty)->history);
    amxt_prompt_clean(&(*tty)->prompt);

    free(*tty);
    *tty = NULL;
    retval = 0;

exit:
    return retval;
}

///////////////////////////////////////////////////////////////////////////////

// Test implementation of ba_cli_main.c
///////////////////////////////////////////////////////////////////////////////
static ba_cli_t ba_cli;

ba_cli_t* ba_cli_get_data(void) {
    return &ba_cli;
}

amxm_shared_object_t* ba_cli_get_so(void) {
    return ba_cli.so;
}

amxt_tty_t* ba_cli_get_tty(void) {
    return ba_cli.tty;
}
///////////////////////////////////////////////////////////////////////////////

void amxt_cli_build_args(amxc_var_t* args, const char* cmd) {
    amxc_var_t* cmd_parts = NULL;
    const char* reason = NULL;
    char* txt = strdup(cmd);
    size_t length = strlen(txt);
    amxc_string_split_status_t status = AMXC_STRING_SPLIT_OK;

    amxc_var_set_type(args, AMXC_VAR_ID_HTABLE);
    cmd_parts = amxc_var_add_key(amxc_llist_t, args, "cmd", NULL);

    amxc_var_add_key(amxt_tty_t, args, "tty", ba_cli_get_tty());
    amxc_var_add_key(cstring_t, args, "input", txt);
    status = amxt_cmd_parse_line(txt, length, cmd_parts, &reason);
    assert_int_equal(status, AMXC_STRING_SPLIT_OK);
    amxt_cmd_triml(cmd_parts, ' ');

    free(txt);
}
