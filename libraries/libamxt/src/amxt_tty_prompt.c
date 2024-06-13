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

#include <sys/resource.h>

#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>

#include <amxc/amxc.h>
#include <amxp/amxp.h>

#include <amxt/amxt_tty.h>
#include <amxt/amxt_ctrl.h>
#include <amxt/amxt_variant.h>


#include "amxt_priv.h"

static const char* escapes[] = {
    AMXT_TTY_BLACK,
    AMXT_TTY_RED,
    AMXT_TTY_GREEN,
    AMXT_TTY_YELLOW,
    AMXT_TTY_BLUE,
    AMXT_TTY_MAGENTA,
    AMXT_TTY_CYAN,
    AMXT_TTY_WHITE,
    AMXT_TTY_BRIGHT_BLACK,
    AMXT_TTY_BRIGHT_RED,
    AMXT_TTY_BRIGHT_GREEN,
    AMXT_TTY_BRIGHT_YELLOW,
    AMXT_TTY_BRIGHT_BLUE,
    AMXT_TTY_BRIGHT_MAGENTA,
    AMXT_TTY_BRIGHT_CYAN,
    AMXT_TTY_BRIGHT_WHITE,
    AMXT_TTY_BG_BLACK,
    AMXT_TTY_BG_RED,
    AMXT_TTY_BG_GREEN,
    AMXT_TTY_BG_YELLOW,
    AMXT_TTY_BG_BLUE,
    AMXT_TTY_BG_MAGENTA,
    AMXT_TTY_BG_CYAN,
    AMXT_TTY_BG_WHITE,
    AMXT_TTY_RESET,
    AMXT_TTY_MOVE_UP,
    AMXT_TTY_MOVE_DOWN,
    AMXT_TTY_MOVE_LEFT,
    AMXT_TTY_MOVE_RIGHT,
    AMXT_TTY_SET_COLUMN,
    AMXT_TTY_SET_POS,
    AMXT_TTY_GET_POS,
    AMXT_TTY_LINE_CLEAR,
    NULL
};

amxt_prompt_t* amxt_tty_get_prompt(amxt_tty_t* const tty) {
    return tty == NULL ? NULL : &tty->prompt;
}

int amxt_tty_set_prompt(amxt_tty_t* const tty, const char* prompt) {
    int retval = -1;
    when_null(tty, exit);

    when_failed(amxt_prompt_set(&tty->prompt, prompt), exit);

    amxt_tty_line_clear(tty, amxt_clear_line_all);
    amxt_tty_set_cursor_column(tty, 0);

    retval = 0;

exit:
    return retval;
}

int amxt_tty_show_prompt(const amxt_tty_t* const tty) {
    int retval = -1;
    bool dbg_info = false;

    when_null(tty, exit);
    dbg_info = GET_BOOL(&tty->config, "tty-dbg");

    if(tty->interactive) {
        amxt_tty_line_clear(tty, amxt_clear_line_all);
        amxt_tty_set_cursor_column(tty, 0);

        if(amxt_prompt_length(&tty->prompt) > 0) {
            char* prompt = amxt_prompt_get(&tty->prompt);
            amxt_tty_write_raw(tty, prompt, strlen(prompt));
            if(dbg_info) {
                amxt_tty_hide_prompt(tty);
                amxt_tty_write_raw(tty, prompt, strlen(prompt));
            }
            free(prompt);
        }
    }

    retval = 0;

exit:
    return retval;
}

int amxt_tty_hide_prompt(const amxt_tty_t* const tty) {
    int retval = -1;
    char* prompt = NULL;
    char* new_line = NULL;

    when_null(tty, exit);

    if(amxt_prompt_length(&tty->prompt) == 0) {
        goto exit;
    }

    amxt_tty_line_clear(tty, amxt_clear_line_all);
    prompt = amxt_prompt_get(&tty->prompt);
    new_line = strchr(prompt, '\n');
    while(new_line != NULL) {
        amxt_tty_cursor_move(tty, 0, -1);
        amxt_tty_line_clear(tty, amxt_clear_line_all);
        new_line = strchr(new_line + 1, '\n');
    }
    amxt_tty_set_cursor_column(tty, 0);
    free(prompt);

    retval = 0;

exit:
    return retval;
}

int amxt_tty_prompt_get_last_line_length(const amxt_tty_t* const tty) {
    char* prompt = NULL;
    char* new_line = NULL;
    char* last_line = NULL;
    int len = 0;
    int ctrls = 0;

    when_null(tty, exit);

    if(amxt_prompt_length(&tty->prompt) == 0) {
        goto exit;
    }

    prompt = amxt_prompt_get(&tty->prompt);
    last_line = prompt;
    new_line = strchr(prompt, '\n');
    while(new_line != NULL) {
        last_line = new_line + 1;
        new_line = strchr(new_line + 1, '\n');
    }
    len = strlen(last_line);
    for(int i = 0; i < len; i++) {
        for(int j = 0; escapes[j] != NULL; j++) {
            int l = strlen(escapes[j]);
            if(strncmp(last_line + i, escapes[j], l) == 0) {
                i += l;
                ctrls += l;
            }
        }
    }
    free(prompt);

exit:
    return len - ctrls;
}

