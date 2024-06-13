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

#if !defined(__AMX_TTY_H__)
#define __AMX_TTY_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <termios.h>
#include <sys/types.h>

#ifndef __AMXC_STRING_H__
#error "include <amxc/amxc_string.h> before <amxt/amxt_tty.h>"
#endif

#ifndef __AMXP_SIGNAL_H__
#error "include <amxp/amxp_signal.h> before <amxt/amxt_tty.h>"
#endif

#include <amxt/amxt_il.h>
#include <amxt/amxt_history.h>
#include <amxt/amxt_prompt.h>
#include <amxt/amxt_tty_types.h>
#include <amxt/amxt_tty_prompt.h>
#include <amxt/amxt_tty_input.h>
#include <amxt/amxt_tty_output.h>
#include <amxt/amxt_tty_config.h>

int amxt_tty_open(amxt_tty_t** tty, int fd);
int amxt_tty_close(amxt_tty_t** tty);

int amxt_tty_fd(const amxt_tty_t* const tty);
int amxt_tty_silent(amxt_tty_t* const tty, bool silent);

amxt_il_t* amxt_tty_il(amxt_tty_t* const tty);
amxp_signal_mngr_t* amxt_tty_sigmngr(amxt_tty_t* const tty);
amxt_hist_t* amxt_tty_history(amxt_tty_t* const tty);

int amxt_tty_cursor_move(const amxt_tty_t* const tty,
                         const int hdelta,
                         const int vdelta);
int amxt_tty_set_cursor_column(const amxt_tty_t* const tty,
                               const int col);
int amxt_tty_set_cursor_pos(const amxt_tty_t* const tty,
                            const int col,
                            const int row);
int amxt_tty_get_cursor_column(const amxt_tty_t* const tty);
int amxt_tty_get_cursor_row(const amxt_tty_t* const tty);

int amxt_tty_line_clear(const amxt_tty_t* const tty,
                        const amxt_tty_clear_line_t code);

int amxt_tty_get_width(void);
int amxt_tty_get_height(void);

bool amxt_is_valid_name(const char* name);

ssize_t amxt_read(int fd, char* buf, size_t bufsize);

#ifdef __cplusplus
}
#endif

#endif // __TTY_H__

