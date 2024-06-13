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

#include <sys/resource.h>

#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>

#include <amxc/amxc.h>
#include <amxp/amxp.h>

#include <amxt/amxt_tty.h>
#include <amxt/amxt_ctrl.h>
#include <amxt/amxt_variant.h>


#include "amxt_priv.h"

// array of callback functions for the ctrl keys
static amxt_ctrl_key_handler_t ctrl_handlers[] = {
    amxt_ctrl_key_backspace_del,   // amxt_key_backspace
    amxt_ctrl_key_backspace_del,   // amxt_key_delete
    amxt_ctrl_key_left_right,      // amxt_key_left
    amxt_ctrl_key_left_right,      // amxt_key_right
    amxt_ctrl_key_home_end,        // amxt_key_home
    amxt_ctrl_key_home_end,        // amxt_key_end
    amxt_ctrl_key_up,              // amxt_key_up
    amxt_ctrl_key_down,            // amxt_key_down
    amxt_ctrl_key_insert,          // amxt_key_insert
    amxt_ctrl_key_noop,            // amxt_key_page_up
    amxt_ctrl_key_noop,            // amxt_key_page_down
    amxt_ctrl_key_tab,             // amxt_key_tab
    amxt_ctrl_key_new_line,        // amxt_key_newlizne
    amxt_ctrl_key_noop,            // amxt_key_eof
    amxt_ctrl_key_noop,            // amxt_ctrl_key_left
    amxt_ctrl_key_noop,            // amxt_ctrl_key_right
    amxt_ctrl_key_noop,            // amxt_ctrl_key_home
    amxt_ctrl_key_noop,            // amxt_ctrl_key_end
    amxt_ctrl_key_noop,            // amxt_ctrl_key_up
    amxt_ctrl_key_noop,            // amxt_ctrl_key_down
    amxt_ctrl_key_noop,            // amxt_key_shift_left
    amxt_ctrl_key_noop,            // amxt_key_shift_right
    amxt_ctrl_key_noop,            // amxt_key_shift_down
    amxt_ctrl_key_noop,            // amxt_key_f1
    amxt_ctrl_key_noop,            // amxt_key_f2
    amxt_ctrl_key_noop,            // amxt_key_f3
    amxt_ctrl_key_noop,            // amxt_key_f4
    amxt_ctrl_key_noop,            // amxt_key_escape

};

// handle a normal key stroke
static void amxt_handle_key_stroke(amxt_tty_t* const tty, const char* buf) {
    amxt_il_t* il = &tty->il_buffer;
    amxt_il_insert_block(il, buf, 1);

    amxt_tty_write_raw(tty,
                       amxt_il_text(il, amxt_il_text_after_cursor, -1),
                       amxt_il_text_length(il, amxt_il_text_after_cursor, -1));
    amxt_tty_cursor_move(tty,
                         -amxt_il_text_length(il, amxt_il_text_after_cursor, 0),
                         0);
}

// handle a ctrl key stroke
static void amxt_handle_ctrl_key_stroke(amxt_tty_t* const tty,
                                        const amxt_ctrl_key_sequence_t* const ctrl_seq) {
    amxt_ctrl_key_t key = ctrl_seq->key;

    if(ctrl_handlers[key](tty, key)) {
        amxt_tty_write_raw(tty,
                           ctrl_seq->seq,
                           ctrl_seq->seqlen);
    }
}

static bool amxt_is_special_key(const char* buf,
                                ssize_t len,
                                uint32_t* flags,
                                ssize_t* consumed) {
    (*flags) = 0;
    (*consumed) = 0;
    if(len >= 2) {
        if(buf[0] == 0x1b) {
            (*consumed)++;
            if(buf[1] == 0x5b) {
                (*consumed)++;
                (*flags) |= AMXT_TTY_EXTENDED_KEY;
            } else if(buf[1] == 0x4f) {
                (*consumed)++;
                (*flags) |= AMXT_TTY_EXTENDED_KEY | AMXT_TTY_CTRL_KEY;
            } else if(buf[1] == 0x1b) {
                (*consumed)++;
                (*flags) |= AMXT_TTY_EXTENDED_KEY | AMXT_TTY_ALT_KEY;
            } else {
                (*flags) |= AMXT_TTY_ALT_KEY;
            }
        }
    } else {
        if(buf[0] < 0x20) {
            (*flags) |= AMXT_TTY_CTRL_KEY;
        }
    }

    return ((*flags) != 0);
}

void amxt_tty_set_ctrl_key_cb(amxt_ctrl_key_t key, amxt_ctrl_key_handler_t cb) {
    when_null(cb, exit);
    when_true(key > amxt_key_eof, exit);

    ctrl_handlers[key] = cb;

exit:
    return;
}

ssize_t amxt_tty_read(amxt_tty_t* const tty) {
    ssize_t n = 0;
    char buf[32];

    when_null(tty, exit);
    memset(&buf, 0, sizeof(buf));

    n = amxt_read(tty->tty_fd, buf, sizeof(buf));

    // loop over input buffer and handle key strokes
    for(ssize_t buf_pos = 0; buf_pos < n; buf_pos++) {
        size_t len_left = n - buf_pos;
        amxt_ctrl_key_sequence_t* ctrl_seq = amxt_is_ctrl_sequence(buf + buf_pos);

        if(ctrl_seq) {
            buf_pos += (ctrl_seq->seqlen - 1);
            amxt_handle_ctrl_key_stroke(tty, ctrl_seq);
        } else {
            uint32_t flags = 0;
            ssize_t consumed = 0;
            if(amxt_is_special_key(buf + buf_pos, len_left, &flags, &consumed)) {
                buf_pos += consumed;
                // TODO call cb function
                continue;
            }
            amxt_handle_key_stroke(tty, buf + buf_pos);
        }
    }

exit:
    return n;
}

void amxt_tty_trigger_cmd(amxt_tty_t* const tty,
                          amxc_string_t* cmd,
                          bool add_history) {
    amxt_il_t* il = NULL;
    const char* text = NULL;
    amxc_var_t data;

    amxc_var_init(&data);
    amxc_var_set_type(&data, AMXC_VAR_ID_HTABLE);

    when_null(tty, exit);
    when_null(cmd, exit);

    il = amxt_tty_il(tty);
    text = amxc_string_get(cmd, 0);

    if((amxc_string_text_length(cmd) > 0) && add_history) {
        amxt_hist_t* history = amxt_tty_history(tty);
        if(amxt_hist_get_pos(history) != 0) {
            amxt_hist_add(amxt_tty_history(tty), text);
        } else {
            if(amxt_hist_get_current(history) == NULL) {
                amxt_hist_add(amxt_tty_history(tty), text);
            } else if(strcmp(text, amxt_hist_get_current(history)) != 0) {
                amxt_hist_add(amxt_tty_history(tty), text);
            }
        }
    }

    amxt_hist_set_pos(amxt_tty_history(tty), 0);

    amxc_string_trim(cmd, NULL);
    amxt_tty_resolve(cmd, (void*) tty);
    text = amxc_string_get(cmd, 0);

    amxc_var_add_key(amxt_tty_t, &data, "tty", tty);
    amxc_var_add_key(cstring_t, &data, "text", text);

    amxt_il_reset(il);
    amxt_tty_writef(tty, "${color.reset}");
    amxt_tty_write(tty, "\n", 1);
    amxp_sigmngr_trigger_signal(amxt_tty_sigmngr(tty), "tty:newline", &data);
    amxt_tty_writef(tty, "${color.reset}");

exit:
    amxc_var_clean(&data);
    return;
}
