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
#include <sys/types.h>
#include <sys/stat.h>

#include <amxc/amxc.h>
#include <amxp/amxp.h>

#include <amxt/amxt_tty.h>
#include <amxt/amxt_ctrl.h>
#include <amxt/amxt_variant.h>


#include "amxt_priv.h"

static int amxt_tty_init_signals(amxt_tty_t* const tty) {
    int retval = -1;

    when_failed(amxp_sigmngr_new(&tty->sigmngr), exit);
    when_failed(amxp_sigmngr_add_signal(tty->sigmngr, "tty:newline"), exit);
    when_failed(amxp_sigmngr_add_signal(tty->sigmngr, "tty:output"), exit);
    when_failed(amxp_sigmngr_add_signal(tty->sigmngr, "tty:close"), exit);
    when_failed(amxp_sigmngr_add_signal(tty->sigmngr, "tty:complete"), exit);
    when_failed(amxp_sigmngr_add_signal(tty->sigmngr, "tty:cmd-done"), exit);
    when_failed(amxp_sigmngr_add_signal(tty->sigmngr, "tty:log"), exit);

    retval = 0;

exit:
    return retval;
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

static int amxd_tty_try(int fd) {
    int out_fd = -1;
    char buffer[256];

    when_false(isatty(fd), exit);

    if(!ttyname_r(fd, buffer, sizeof(buffer))) {
        do {
            out_fd = open(buffer, O_RDWR | O_NOCTTY);
        } while(out_fd == -1 && errno == EINTR);
    }

exit:
    return out_fd;
}

static int amxt_tty_get_fd(void) {
    int fd = -1;
    char buffer[256];
    char* path = NULL;

    if(isatty(fileno(stderr))) {
        fd = amxd_tty_try(fileno(stderr));
    }
    when_true(fd != -1, exit);

    if(isatty(fileno(stdout))) {
        fd = amxd_tty_try(fileno(stdout));
    }
    when_true(fd != -1, exit);

    if(isatty(fileno(stdin))) {
        fd = amxd_tty_try(fileno(stdin));
    }
    when_true(fd != -1, exit);

    buffer[0] = '\0';
    path = ctermid(buffer);
    if((path != NULL) && (*path != 0)) {
        do {
            fd = open(path, O_RDWR | O_NOCTTY);
        } while(fd == -1 && errno == EINTR);
    }

exit:
    return fd;
}


void amxt_tty_resolve(amxc_string_t* txt, void* priv) {
    amxt_tty_t* tty = (amxt_tty_t*) priv;
    amxc_ts_t now;
    char time[64];
    amxc_var_t* var_time = NULL;

    amxc_ts_now(&now);
    amxc_ts_format_precision(&now, time, 64, 0);
    var_time = amxc_var_get_key(&tty->config, "time", AMXC_VAR_FLAG_DEFAULT);
    amxc_var_set(cstring_t, var_time, time);

    amxc_string_resolve_env(txt);
    amxc_string_resolve_var(txt, &tty->config);
}

int amxt_tty_open(amxt_tty_t** tty, int fd) {
    int retval = -1;
    bool interactive = false;
    int flags = 0;

    when_null(tty, exit);

    if(fd == -1) {
        fd = amxt_tty_get_fd();
    }

    if(fd == -1) {
        fd = STDIN_FILENO;
    }

    *tty = (amxt_tty_t*) calloc(1, sizeof(amxt_tty_t));
    when_null(*tty, exit);

    when_failed(amxt_il_init(&(*tty)->il_buffer, 64), exit);
    when_failed(amxt_hist_init(&(*tty)->history), exit);
    when_failed(amxt_prompt_init(&(*tty)->prompt), exit);
    when_failed(amxt_prompt_set_resolver(&(*tty)->prompt,
                                         amxt_tty_resolve,
                                         *tty), exit);
    when_failed(amxt_tty_init_signals(*tty), exit);
    when_failed(amxt_tty_init_config(*tty), exit);

    if(isatty(fd) != 0) {
        tcgetattr(fd, &(*tty)->termios);
        memcpy(&(*tty)->orig_termios, &(*tty)->termios, sizeof(struct termios));
        (*tty)->termios.c_lflag &= ~ICANON;
        (*tty)->termios.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL);
        tcsetattr(fd, TCSANOW, &(*tty)->termios);
        interactive = true;
    }
    (*tty)->tty_fd = fd;
    (*tty)->interactive = interactive;

    flags = fcntl(fd, F_GETFL);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    retval = 0;

exit:
    if((tty != NULL) && (retval != 0)) {
        amxt_tty_close(tty);
    }
    return retval;
}

int amxt_tty_close(amxt_tty_t** tty) {
    int retval = -1;

    when_null(tty, exit);
    when_null(*tty, exit);

    if(isatty((*tty)->tty_fd) == 1) {
        tcsetattr((*tty)->tty_fd, TCSANOW, &(*tty)->orig_termios);
    }

    amxc_var_clean(&(*tty)->config);
    amxt_il_clean(&(*tty)->il_buffer);
    amxt_hist_clean(&(*tty)->history);
    amxp_sigmngr_delete(&(*tty)->sigmngr);
    amxt_prompt_clean(&(*tty)->prompt);

    free(*tty);
    *tty = NULL;
    retval = 0;

exit:
    return retval;
}

int amxt_tty_fd(const amxt_tty_t* const tty) {
    return tty == NULL ? -1 : tty->tty_fd;
}

int amxt_tty_silent(amxt_tty_t* tty, bool silent) {
    int retval = -1;
    when_null(tty, exit);

    tty->silent = silent;

    retval = 0;

exit:
    return retval;
}

amxt_il_t* amxt_tty_il(amxt_tty_t* const tty) {
    return tty == NULL ? NULL : &tty->il_buffer;
}

amxp_signal_mngr_t* amxt_tty_sigmngr(amxt_tty_t* const tty) {
    return tty == NULL ? NULL : tty->sigmngr;
}

amxt_hist_t* amxt_tty_history(amxt_tty_t* const tty) {
    return tty == NULL ? NULL : &tty->history;
}

int amxt_tty_cursor_move(const amxt_tty_t* const tty,
                         const int hdelta,
                         const int vdelta) {
    int retval = -1;
    int width = amxt_tty_get_width();
    int calc_vdelta = vdelta;
    int calc_hdelta = hdelta;

    when_null(tty, exit);

    if((abs(calc_hdelta) > width) && (calc_hdelta < 0)) {
        calc_vdelta = (abs(hdelta) / width) * -1;
        calc_hdelta = (abs(hdelta) - (calc_vdelta * width)) * -1;
    }

    if(calc_hdelta > 0) {
        amxt_tty_writef(tty, AMXT_TTY_MOVE_RIGHT, calc_hdelta);
    } else if(calc_hdelta < 0) {
        amxt_tty_writef(tty, AMXT_TTY_MOVE_LEFT, -calc_hdelta);
    }

    if(calc_vdelta > 0) {
        amxt_tty_writef(tty, AMXT_TTY_MOVE_DOWN, calc_vdelta);
    } else if(calc_vdelta < 0) {
        amxt_tty_writef(tty, AMXT_TTY_MOVE_UP, -calc_vdelta);
    }

    retval = 0;

exit:
    return retval;
}

int amxt_tty_set_cursor_column(const amxt_tty_t* const tty,
                               const int col) {
    int retval = -1;

    when_null(tty, exit);
    amxt_tty_writef(tty, AMXT_TTY_SET_COLUMN, col);

    retval = 0;

exit:
    return retval;
}

int amxt_tty_set_cursor_pos(const amxt_tty_t* const tty,
                            const int col,
                            const int row) {
    int retval = -1;

    when_null(tty, exit);
    amxt_tty_writef(tty, AMXT_TTY_SET_POS, col, row);

    retval = 0;

exit:
    return retval;
}

int amxt_tty_get_cursor_column(const amxt_tty_t* const tty) {
    int retval = -1;
    ssize_t n = 0;
    char buf[32];
    char* x = NULL;
    char* y = NULL;

    when_null(tty, exit);
    when_true(tty->silent, exit);

    amxt_tty_writef(tty, AMXT_TTY_GET_POS);
    n = read(tty->tty_fd, buf, sizeof(buf) - 1);
    when_true(n <= 4, exit);
    when_true(buf[n - 1] != 'R', exit);

    buf[n - 1] = 0;

    x = buf + 2;
    y = strchr(x, ';');
    y[0] = 0;
    y++;

    retval = atoi(x);

exit:
    return retval;
}

int amxt_tty_get_cursor_row(const amxt_tty_t* const tty) {
    int retval = -1;
    ssize_t n = 0;
    char buf[32];
    char* x = NULL;
    char* y = NULL;

    when_null(tty, exit);
    when_true(tty->silent, exit);

    amxt_tty_writef(tty, AMXT_TTY_GET_POS);
    n = read(tty->tty_fd, buf, sizeof(buf) - 1);
    when_true(n <= 4, exit);
    when_true(buf[n - 1] != 'R', exit);

    buf[n - 1] = 0;

    x = buf + 2;
    y = strchr(x, ';');
    y[0] = 0;
    y++;

    retval = atoi(y);

exit:
    return retval;
}

int amxt_tty_line_clear(const amxt_tty_t* const tty,
                        const amxt_tty_clear_line_t code) {
    int retval = -1;

    when_null(tty, exit);
    amxt_tty_writef(tty, AMXT_TTY_LINE_CLEAR, code);

    retval = 0;

exit:
    return retval;
}

int amxt_tty_get_width(void) {
    struct winsize w;
    if(ioctl(0, TIOCGWINSZ, &w) != -1) {
        return w.ws_col == 0 ? 80 : w.ws_col;
    } else {
        return 80;
    }
}

int amxt_tty_get_height(void) {
    struct winsize w;
    if(ioctl(0, TIOCGWINSZ, &w) != -1) {
        return w.ws_row == 0 ? 24 : w.ws_row;
    } else {
        return 24;
    }
}

bool amxt_is_valid_name(const char* name) {
    bool retval = false;
    when_str_empty(name, exit);

    for(int i = 0; name[i] != 0; i++) {
        if(isalnum(name[i]) == 0) {
            if((name[i] != '_') && (name[i] != '-')) {
                goto exit;
            }
        }
    }

    retval = true;

exit:
    return retval;
}

ssize_t amxt_read(int fd, char* buf, size_t bufsize) {
    ssize_t n = 0;
    size_t used_bytes = 0;
    size_t max_used_bytes = bufsize - 1;

    memset(buf, 0, bufsize);

    // read into buffer
    n = read(fd, buf, max_used_bytes);
    when_true_status(n <= 0, exit, used_bytes = n);
    used_bytes = n;

    // When using the serial interface control key sequence don't come all at
    // once, multiple reads are needed.
    // Before reading again, just wait a short time, otherwise there are
    // no bytes
    // Only wait for more when it is a start of an escape sequence
    while(n > 0 && buf[0] == 0x1b) {
        usleep(1000); // wait 1 msecs before reading again
        n = read(fd, buf + used_bytes, max_used_bytes - used_bytes);
        if(n >= 0) {
            used_bytes += n;
        } else {
            if(errno != EAGAIN) {
                used_bytes = n;
                goto exit;
            }
        }
    }
    buf[used_bytes] = 0;

exit:
    return used_bytes;
}
