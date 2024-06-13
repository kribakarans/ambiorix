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
#include <string.h>
#include <syslog.h>

#include <amxc/amxc.h>
#include <amxp/amxp.h>
#include <amxt/amxt_tty.h>
#include <amxt/amxt_log.h>


#include "amxt_priv.h"

static void amxt_log_remove_ctrl_sequences(amxc_string_t* text) {
    const char* ctrl[] = {
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
        AMXT_TTY_RESET,
        AMXT_TTY_MOVE_UP,
        AMXT_TTY_MOVE_DOWN,
        AMXT_TTY_MOVE_LEFT,
        AMXT_TTY_MOVE_RIGHT,
        AMXT_TTY_SET_COLUMN,
        AMXT_TTY_LINE_CLEAR,
        NULL
    };
    uint32_t index = 0;
    while(ctrl[index]) {
        amxc_string_replace(text, ctrl[index], "", UINT32_MAX);
        index++;
    }
}

static void amxt_log_slot_newline(UNUSED const char* const sig_name,
                                  const amxc_var_t* const data,
                                  UNUSED void* priv) {
    const char* line = GET_CHAR(data, "text");
    syslog(LOG_DAEMON | LOG_DEBUG, "> %s", line);
}

static void amxt_log_slot_output(UNUSED const char* const sig_name,
                                 const amxc_var_t* const data,
                                 UNUSED void* priv) {
    amxc_string_t log_text;
    amxc_llist_t lines;
    const char* text = amxc_var_constcast(cstring_t, data);
    amxc_llist_init(&lines);
    amxc_string_init(&log_text, strlen(text));
    amxc_string_setf(&log_text, "%s", text);
    amxt_log_remove_ctrl_sequences(&log_text);
    amxc_string_split_to_llist(&log_text, &lines, '\n');
    amxc_llist_for_each(it, (&lines)) {
        amxc_string_t* line = amxc_string_from_llist_it(it);
        syslog(LOG_DAEMON | LOG_DEBUG, "< %s", amxc_string_get(line, 0));
        amxc_string_delete(&line);
    }
    amxc_string_clean(&log_text);
    amxc_llist_clean(&lines, amxc_string_list_it_free);
}

static void amxt_log_slot(UNUSED const char* const sig_name,
                          const amxc_var_t* const data,
                          UNUSED void* priv) {

    amxc_var_log(data);
}

void amxt_log_open(amxt_tty_t* tty, const char* id) {
    when_str_empty(id, exit);
    when_null(tty, exit);

    openlog(id, 0, LOG_USER);

exit:
    return;
}

void amxt_log_enable(amxt_tty_t* tty, uint32_t flags, bool enable) {
    when_null(tty, exit);

    if((flags & AMXT_LOG_INPUT) != 0) {
        amxp_slot_disconnect(amxt_tty_sigmngr(tty), "tty:newline",
                             amxt_log_slot_newline);
        if(enable) {
            amxp_slot_connect(amxt_tty_sigmngr(tty), "tty:newline",
                              NULL, amxt_log_slot_newline, NULL);
        }
    }

    if((flags & AMXT_LOG_OUTPUT) != 0) {
        amxp_slot_disconnect(amxt_tty_sigmngr(tty), "tty:output",
                             amxt_log_slot_output);
        if(enable) {
            amxp_slot_connect(amxt_tty_sigmngr(tty), "tty:output",
                              NULL, amxt_log_slot_output, NULL);
        }
    }

    if((flags & AMXT_LOG_MSG) != 0) {
        amxp_slot_disconnect(amxt_tty_sigmngr(tty), "tty:log",
                             amxt_log_slot);
        if(enable) {
            amxp_slot_connect(amxt_tty_sigmngr(tty), "tty:log",
                              NULL, amxt_log_slot, NULL);
        }
    }

exit:
    return;
}

void amxt_log(amxt_tty_t* tty, const char* msg) {
    amxc_var_t data;
    amxc_var_init(&data);

    when_str_empty(msg, exit);
    when_null(tty, exit);

    amxc_var_set(cstring_t, &data, msg);
    amxp_sigmngr_trigger_signal(amxt_tty_sigmngr(tty), "tty:log", &data);

exit:
    amxc_var_clean(&data);
    return;
}

void amxt_log_close(amxt_tty_t* tty) {
    when_null(tty, exit);

    amxp_slot_disconnect(amxt_tty_sigmngr(tty), "tty:newline", amxt_log_slot_newline);
    amxp_slot_disconnect(amxt_tty_sigmngr(tty), "tty:output", amxt_log_slot_output);
    amxp_slot_disconnect(amxt_tty_sigmngr(tty), "tty:log", amxt_log_slot);
    closelog();

exit:
    return;
}