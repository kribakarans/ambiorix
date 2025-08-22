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

#if !defined(__AMX_TTY_TYPES_H__)
#define __AMX_TTY_TYPES_H__

#ifdef __cplusplus
extern "C"
{
#endif


#define AMXT_TTY_BLACK      "\033[30m"
#define AMXT_TTY_RED        "\033[31m"
#define AMXT_TTY_GREEN      "\033[32m"
#define AMXT_TTY_YELLOW     "\033[33m"
#define AMXT_TTY_BLUE       "\033[34m"
#define AMXT_TTY_MAGENTA    "\033[35m"
#define AMXT_TTY_CYAN       "\033[36m"
#define AMXT_TTY_WHITE      "\033[37m"

#define AMXT_TTY_BRIGHT_BLACK      "\033[30;1m"
#define AMXT_TTY_BRIGHT_RED        "\033[31;1m"
#define AMXT_TTY_BRIGHT_GREEN      "\033[32;1m"
#define AMXT_TTY_BRIGHT_YELLOW     "\033[33;1m"
#define AMXT_TTY_BRIGHT_BLUE       "\033[34;1m"
#define AMXT_TTY_BRIGHT_MAGENTA    "\033[35;1m"
#define AMXT_TTY_BRIGHT_CYAN       "\033[36;1m"
#define AMXT_TTY_BRIGHT_WHITE      "\033[37;1m"

#define AMXT_TTY_BG_BLACK          "\033[40;1m"
#define AMXT_TTY_BG_RED            "\033[41;1m"
#define AMXT_TTY_BG_GREEN          "\033[42;1m"
#define AMXT_TTY_BG_YELLOW         "\033[43;1m"
#define AMXT_TTY_BG_BLUE           "\033[44;1m"
#define AMXT_TTY_BG_MAGENTA        "\033[45;1m"
#define AMXT_TTY_BG_CYAN           "\033[46;1m"
#define AMXT_TTY_BG_WHITE          "\033[47;1m"

#define AMXT_TTY_RESET      "\033[0m"

#define AMXT_TTY_MOVE_UP     "\033[%dA"
#define AMXT_TTY_MOVE_DOWN   "\033[%dB"
#define AMXT_TTY_MOVE_LEFT   "\033[%dD"
#define AMXT_TTY_MOVE_RIGHT  "\033[%dC"

#define AMXT_TTY_SET_COLUMN  "\033[%dG"
#define AMXT_TTY_SET_POS     "\033[%d;%dH"
#define AMXT_TTY_GET_POS     "\033[6n"

#define AMXT_TTY_LINE_CLEAR  "\033[%dK"

#define AMXT_TTY_EXTENDED_KEY 0x01
#define AMXT_TTY_CTRL_KEY     0x02
#define AMXT_TTY_ALT_KEY      0x04

typedef struct _amxt_tty {
    amxt_il_t il_buffer;
    int tty_fd;
    bool silent;
    struct termios orig_termios;
    struct termios termios;
    amxp_signal_mngr_t* sigmngr;
    amxt_hist_t history;
    amxt_prompt_t prompt;
    void* el_priv;
    void* priv;
    amxc_var_t config;
    bool interactive;
} amxt_tty_t;

typedef enum _amxt_ctrl_key {
    amxt_key_backspace,
    amxt_key_delete,
    amxt_key_left,
    amxt_key_right,
    amxt_key_home,
    amxt_key_end,
    amxt_key_up,
    amxt_key_down,
    amxt_key_insert,
    amxt_key_page_up,
    amxt_key_page_down,
    amxt_key_tab,
    amxt_key_newline,
    amxt_key_eof,
    amxt_key_ctrl_left,
    amxt_key_ctrl_right,
    amxt_key_ctrl_home,
    amxt_key_ctrl_end,
    amxt_key_ctrl_up,
    amxt_key_ctrl_down,
    amxt_key_shift_left,
    amxt_key_shift_right,
    amxt_key_shift_up,
    amxt_key_shift_down,
    amxt_key_f1,
    amxt_key_f2,
    amxt_key_f3,
    amxt_key_f4,
    amxt_key_escape,
} amxt_ctrl_key_t;

typedef enum _amxt_tty_clear_line {
    amxt_clear_line_cursor_to_end,
    amxt_clear_line_cursor_to_start,
    amxt_clear_line_all,
} amxt_tty_clear_line_t;

typedef struct _amxt_ctrl_key_sequence {
    char seq[10];
    int seqlen;
    amxt_ctrl_key_t key;
} amxt_ctrl_key_sequence_t;

#define GET_TTY(a) amxc_var_constcast(amxt_tty_t, GET_ARG(a, "tty"))

typedef bool (* amxt_ctrl_key_handler_t) (amxt_tty_t* const tty,
                                          const amxt_ctrl_key_t ctrl_key);

#ifdef __cplusplus
}
#endif

#endif // __TTY_TYPES_H__