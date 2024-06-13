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

#include <string.h>
#include <stdbool.h>
#include <stdint.h>

#include <amxc/amxc.h>
#include <amxp/amxp.h>

#include <amxt/amxt_tty.h>
#include <amxt/amxt_ctrl.h>
#include <amxt/amxt_variant.h>

#include <amxt_priv.h>

// array of known control key sequences
static amxt_ctrl_key_sequence_t control_key_sequence[] = {
    {{0x7F}, 1, amxt_key_backspace },
    {{0x08}, 1, amxt_key_backspace },
    {{0x1b, 0x5b, 0x33, 0x7e}, 4, amxt_key_delete },
    {{0x1b, 0x5b, 0x44}, 3, amxt_key_left },
    {{0x1b, 0x4f, 0x44}, 3, amxt_key_left },
    {{0x1b, 0x5b, 0x31, 0x3b, 0x35, 0x44}, 6, amxt_key_ctrl_left },
    {{0x1b, 0x5b, 0x31, 0x3b, 0x32, 0x44}, 6, amxt_key_shift_left },
    {{0x1b, 0x5b, 0x43}, 3, amxt_key_right },
    {{0x1b, 0x4f, 0x43}, 3, amxt_key_right },
    {{0x1b, 0x5b, 0x31, 0x3b, 0x35, 0x43}, 6, amxt_key_ctrl_right },
    {{0x1b, 0x5b, 0x31, 0x3b, 0x32, 0x43}, 6, amxt_key_shift_right },
    {{0x1b, 0x5b, 0x48}, 3, amxt_key_home },
    {{0x1b, 0x5b, 0x31, 0x7e}, 4, amxt_key_home },
    {{0x1b, 0x4f, 0x48}, 3, amxt_key_ctrl_home },
    {{0x1b, 0x5b, 0x31, 0x3b, 0x35, 0x48}, 6, amxt_key_ctrl_home },
    {{0x1b, 0x5b, 0x46}, 3, amxt_key_end },
    {{0x1b, 0x5b, 0x34, 0x7e}, 4, amxt_key_end },
    {{0x1b, 0x4f, 0x46}, 3, amxt_key_ctrl_end },
    {{0x1b, 0x5b, 0x31, 0x3b, 0x35, 0x46}, 6, amxt_key_ctrl_end },
    {{0x1b, 0x5b, 0x41}, 3, amxt_key_up },
    {{0x1b, 0x4f, 0x41}, 3, amxt_key_up },
    {{0x1b, 0x5b, 0x31, 0x3b, 0x35, 0x41}, 6, amxt_key_ctrl_up },
    {{0x1b, 0x5b, 0x31, 0x3b, 0x32, 0x41}, 6, amxt_key_shift_up },
    {{0x1b, 0x5b, 0x42}, 3, amxt_key_down },
    {{0x1b, 0x4f, 0x42}, 3, amxt_key_down },
    {{0x1b, 0x5b, 0x31, 0x3b, 0x35, 0x42}, 6, amxt_key_ctrl_down },
    {{0x1b, 0x5b, 0x31, 0x3b, 0x32, 0x42}, 6, amxt_key_shift_down },
    {{0x1b, 0x5b, 0x32, 0x7e}, 4, amxt_key_insert },
    {{0x1b, 0x5b, 0x35, 0x7e}, 4, amxt_key_page_up },
    {{0x1b, 0x5b, 0x36, 0x7e}, 4, amxt_key_page_down },
    {{0x1b, 0x4f, 0x50}, 3, amxt_key_f1 },
    {{0x1b, 0x4f, 0x51}, 3, amxt_key_f2 },
    {{0x1b, 0x4f, 0x52}, 3, amxt_key_f3 },
    {{0x1b, 0x4f, 0x53}, 3, amxt_key_f4 },
    {{0x09}, 1, amxt_key_tab },
    {{0x0a}, 1, amxt_key_newline },
    {{0x04}, 1, amxt_key_eof },
    {{0x0d}, 1, amxt_key_newline }
};

static int control_key_sequence_len =
    sizeof(control_key_sequence) / sizeof(amxt_ctrl_key_sequence_t);

// check if the provided buffer contains a ctrl key sequence
amxt_ctrl_key_sequence_t* amxt_is_ctrl_sequence(const char* buf) {
    int ctrl_key_seq_index = 0;

    for(ctrl_key_seq_index = 0;
        ctrl_key_seq_index < control_key_sequence_len;
        ctrl_key_seq_index++) {
        if(!memcmp(control_key_sequence[ctrl_key_seq_index].seq,
                   buf,
                   control_key_sequence[ctrl_key_seq_index].seqlen)) {
            break;
        }
    }

    // return control key sequence
    if(ctrl_key_seq_index == control_key_sequence_len) {
        return NULL;
    } else {
        return &control_key_sequence[ctrl_key_seq_index];
    }
}

// ignore ctrl-key and do nothing
bool amxt_ctrl_key_noop(UNUSED amxt_tty_t* const tty,
                        UNUSED const amxt_ctrl_key_t key) {
    return false;
}

// handle left and right
// move input line buffer cursor left or right
// move tty cursor left or right (just write the ctrl key sequence to tty)
bool amxt_ctrl_key_left_right(amxt_tty_t* const tty,
                              const amxt_ctrl_key_t key) {
    amxt_il_t* il = amxt_tty_il(tty);
    int width = amxt_tty_get_width();
    int extra = amxt_tty_prompt_get_last_line_length(tty);
    int cur_pos = amxt_il_cursor_pos(il);
    int new_pos = 0;

    if(key == amxt_key_left) {
        new_pos = amxt_il_move_cursor(il, -1);
        if((width != 0) && ((new_pos + extra + 1) % width == 0)) {
            amxt_tty_cursor_move(tty, width, -1);
            return false;
        }
    } else {
        new_pos = amxt_il_move_cursor(il, 1);
        if((width != 0) && ((new_pos + extra) % width == 0)) {
            amxt_tty_cursor_move(tty, -width, 1);
            return false;
        }
    }

    return cur_pos != new_pos;
}

// handle backspace and del
bool amxt_ctrl_key_backspace_del(amxt_tty_t* const tty,
                                 const amxt_ctrl_key_t key) {
    amxt_il_t* il = amxt_tty_il(tty);
    int text_len = amxt_il_text_length(il, amxt_il_no_flags, 0);
    int current_pos = amxt_il_cursor_pos(il);
    int width = amxt_tty_get_width();
    int extra = amxt_tty_prompt_get_last_line_length(tty);
    int lines = 0;

    // up date the input line buffer according to key stroke
    if(key == amxt_key_backspace) {
        if(current_pos == 0) {
            goto exit;
        }
        amxt_il_remove_char(il, amxt_il_no_flags);
    } else {
        if((text_len - current_pos) == 0) {
            goto exit;
        }
        amxt_il_remove_char(il, amxt_il_keep_cursor_pos);
    }

    while(current_pos + extra >= width) {
        current_pos -= width;
        lines -= 1;
    }

    // move the tty cursor to beginning of input space
    amxt_tty_cursor_move(tty, -current_pos, lines);
    // write the content of the input buffer
    amxt_tty_write_raw(tty,
                       amxt_il_text(il, amxt_il_no_flags, 0),
                       amxt_il_text_length(il, amxt_il_no_flags, 0));

    // followed by a space
    amxt_tty_write_raw(tty, " ", 1);

    lines = 0;
    while(text_len + extra > width) {
        text_len -= width;
        lines -= 1;
    }

    amxt_tty_cursor_move(tty, -text_len, lines);
    current_pos = amxt_il_cursor_pos(il);
    lines = 0;
    while(current_pos + extra > width) {
        current_pos -= width;
        lines += 1;
    }

    amxt_tty_cursor_move(tty, current_pos, lines);

exit:
    // do not write the ctrl key sequence, all handled
    return false;
}

// handle home and end
bool amxt_ctrl_key_home_end(amxt_tty_t* const tty,
                            const amxt_ctrl_key_t key) {
    amxt_il_t* il = amxt_tty_il(tty);
    int width = amxt_tty_get_width();
    int current_pos = amxt_il_cursor_pos(il);
    int cursor_pos = current_pos;
    int text_len = amxt_il_text_length(il, amxt_il_no_flags, 0);
    int extra = amxt_tty_prompt_get_last_line_length(tty);

    // move to begin
    while(cursor_pos + extra >= width) {
        cursor_pos -= width;
        amxt_tty_cursor_move(tty, 0, -1);
    }
    amxt_tty_cursor_move(tty, -cursor_pos, 0);
    amxt_il_move_cursor(il, -current_pos);

    // move the input line cursor and the tty cursor according to key stroke
    if(key == amxt_key_end) {
        // move to the end of input line
        amxt_tty_write_raw(tty,
                           amxt_il_text(il, amxt_il_no_flags, 0),
                           amxt_il_text_length(il, amxt_il_no_flags, 0));
        amxt_il_move_cursor(il, text_len);
    }

    // do not write the ctrl key sequence, all handled
    return false;
}

// handle insert key
bool amxt_ctrl_key_insert(amxt_tty_t* const tty,
                          UNUSED const amxt_ctrl_key_t key) {
    amxt_il_t* il = amxt_tty_il(tty);
    amxc_string_flags_t flags = amxc_string_insert;

    if(amxt_il_mode(il) == amxc_string_insert) {
        flags = amxc_string_overwrite;
    }
    // toggle the input line mode
    amxt_il_set_mode(il, flags);

    // do not write the ctrl key sequence, all handled
    return false;
}

// handle enter key
bool amxt_ctrl_key_new_line(amxt_tty_t* const tty,
                            UNUSED const amxt_ctrl_key_t key) {
    amxt_il_t* il = amxt_tty_il(tty);
    amxt_tty_trigger_cmd(tty, &il->buffer, true);
    amxt_tty_show_prompt(tty);

    // do not write the ctrl key sequence, all handled
    return false;
}

bool amxt_ctrl_key_down(amxt_tty_t* const tty,
                        UNUSED const amxt_ctrl_key_t key) {
    amxt_hist_t* hist = amxt_tty_history(tty);
    amxt_il_t* il = amxt_tty_il(tty);
    const char* txt = NULL;
    int length = 0;
    int il_length = amxt_il_text_length(il, amxt_il_no_flags, 0);

    int current_pos = amxt_il_cursor_pos(il);
    int width = amxt_tty_get_width();
    int extra = amxt_tty_prompt_get_last_line_length(tty);
    int lines = 0;

    if(il_length != 0) {
        txt = amxt_il_text(il, amxt_il_no_flags, 0);
        amxt_hist_update(hist, txt);
    }

    while(current_pos + extra >= width) {
        current_pos -= width;
        lines -= 1;
    }

    // move the tty cursor to beginning of input space
    amxt_tty_cursor_move(tty, -current_pos, lines);
    amxt_tty_line_clear(tty, amxt_clear_line_cursor_to_end);
    current_pos = il_length - width + extra;
    while(current_pos > 0) {
        amxt_tty_cursor_move(tty, 0, 1);
        amxt_tty_line_clear(tty, amxt_clear_line_all);
        current_pos -= width;
    }
    current_pos = il_length - width;
    while(current_pos > 0) {
        amxt_tty_cursor_move(tty, 0, -1);
        current_pos -= width;
    }

    amxt_il_reset(il);
    txt = amxt_hist_get_prev(hist);
    if(txt != NULL) {
        length = strlen(txt);
        amxt_tty_write_raw(tty, txt, length);
        amxt_il_insert_block(il, txt, length);
    }

    // do not write the ctrl key sequence, all handled
    return false;
}

bool amxt_ctrl_key_up(amxt_tty_t* const tty,
                      UNUSED const amxt_ctrl_key_t key) {
    amxt_hist_t* hist = amxt_tty_history(tty);
    amxt_il_t* il = amxt_tty_il(tty);
    const char* txt = NULL;
    int il_length = amxt_il_text_length(il, amxt_il_no_flags, 0);

    int current_pos = amxt_il_cursor_pos(il);
    int width = amxt_tty_get_width();
    int extra = amxt_tty_prompt_get_last_line_length(tty);
    int lines = 0;

    if(il_length != 0) {
        txt = amxt_il_text(il, amxt_il_no_flags, 0);
        if(amxt_hist_get_pos(hist) == 0) {
            const char* hist_txt = amxt_hist_get_current(hist);
            int hist_length = hist_txt == NULL ? 0 : strlen(hist_txt);
            int min = il_length < hist_length ? il_length : hist_length;
            if((hist_txt == NULL) || (strncmp(txt, hist_txt, min) != 0)) {
                amxt_hist_add(hist, txt);
            }
        } else {
            amxt_hist_update(hist, txt);
        }
        txt = amxt_hist_get_next(hist);
    } else {
        txt = amxt_hist_get_current(hist);
    }

    while(current_pos + extra >= width) {
        current_pos -= width;
        lines -= 1;
    }

    // move the tty cursor to beginning of input space
    amxt_tty_cursor_move(tty, -current_pos, lines);
    amxt_tty_line_clear(tty, amxt_clear_line_cursor_to_end);
    current_pos = il_length - width + extra;
    while(current_pos > 0) {
        amxt_tty_cursor_move(tty, 0, 1);
        amxt_tty_line_clear(tty, amxt_clear_line_all);
        current_pos -= width;
    }
    current_pos = il_length - width;
    while(current_pos > 0) {
        amxt_tty_cursor_move(tty, 0, -1);
        current_pos -= width;
    }

    if(txt != NULL) {
        amxt_il_reset(il);
        amxt_tty_write_raw(tty, txt, strlen(txt));
        amxt_il_insert_block(il, txt, strlen(txt));
    } else {
        amxt_tty_write_raw(tty, amxt_il_text(il, amxt_il_no_flags, 0), il_length);
    }

    // do not write the ctrl key sequence, all handled
    return false;
}

// handle tab key
bool amxt_ctrl_key_tab(amxt_tty_t* const tty,
                       UNUSED const amxt_ctrl_key_t key) {
    amxt_il_t* il = amxt_tty_il(tty);
    const char* text = amxt_il_text(il, amxt_il_no_flags, 0);
    amxp_signal_mngr_t* sigmngr = amxt_tty_sigmngr(tty);
    amxc_var_t data;

    amxc_var_init(&data);
    amxc_var_set_type(&data, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(amxt_tty_t, &data, "tty", tty);
    amxc_var_add_key(cstring_t, &data, "text", text);

    amxp_sigmngr_trigger_signal(sigmngr, "tty:complete", &data);
    amxc_var_clean(&data);

    // do not write the ctrl key sequence, all handled
    return false;
}
