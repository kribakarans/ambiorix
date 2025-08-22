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

#include <amxc/amxc.h>
#include <amxp/amxp.h>

#include <amxt/amxt_tty.h>
#include <amxt/amxt_ctrl.h>
#include <amxt/amxt_variant.h>


#include "amxt_priv.h"

#define NR_OF_BYTES_LINE  16

ssize_t amxt_tty_write_raw(const amxt_tty_t* const tty,
                           const char* buf,
                           const size_t n) {
    ssize_t ssize = 0;

    when_null(tty, exit);
    when_null(buf, exit);
    when_true(n == 0, exit);

    if(!tty->silent) {
        int flags = fcntl(STDOUT_FILENO, F_GETFL);
        // make sure that the write is done blocking.
        // this will ensure that the full buffer is written before continuing
        fcntl(STDOUT_FILENO, F_SETFL, flags & ~O_NONBLOCK);
        ssize = write(STDOUT_FILENO, buf, n);
        fcntl(STDOUT_FILENO, F_SETFL, flags);
    }

exit:
    return ssize;
}

ssize_t amxt_tty_write(const amxt_tty_t* const tty, const char* buf, const size_t n) {
    ssize_t ssize = 0;
    amxc_string_t text;

    amxc_string_init(&text, n + 1);

    when_null(tty, exit);
    when_null(buf, exit);
    when_true(n == 0, exit);

    amxc_string_append(&text, buf, n);
    amxt_tty_resolve(&text, (void*) tty);
    ssize = amxt_tty_write_raw(tty,
                               amxc_string_get(&text, 0),
                               amxc_string_text_length(&text));

    if(ssize != 0) {
        amxc_var_t data;
        amxc_var_init(&data);
        amxc_var_push(amxc_string_t, &data, &text);
        amxp_sigmngr_trigger_signal(tty->sigmngr, "tty:output", &data);
        amxc_var_clean(&data);
    }

exit:
    amxc_string_clean(&text);
    return ssize;
}

ssize_t amxt_tty_vwritef(const amxt_tty_t* tty,
                         const char* fmt,
                         va_list args) {
    ssize_t retval = -1;
    ssize_t size_needed = 0;
    ssize_t bytes_written = 0;
    char* buffer = NULL;
    va_list copy;

    when_null(tty, exit);
    when_null(fmt, exit);

    va_copy(copy, args);
    size_needed = vsnprintf(NULL, 0, fmt, args);

    buffer = (char*) malloc(size_needed + 1);
    size_needed = vsnprintf(buffer, size_needed + 1, fmt, copy);

    bytes_written = amxt_tty_write(tty, buffer, size_needed);
    free(buffer);

    when_true(bytes_written != size_needed, exit);

    retval = bytes_written;

exit:
    return retval;
}

ssize_t amxt_tty_writef(const amxt_tty_t* tty, const char* fmt, ...) {
    ssize_t retval = -1;
    va_list args;

    when_null(tty, exit);
    when_null(fmt, exit);

    va_start(args, fmt);
    retval = amxt_tty_vwritef(tty, fmt, args);
    va_end(args);

exit:
    return retval;
}

ssize_t amxt_tty_errorf(amxt_tty_t* tty, const char* fmt, ...) {
    ssize_t retval = -1;
    va_list args;

    when_null(tty, exit);
    when_null(fmt, exit);

    amxt_tty_writef(tty, "${color.red}ERROR: ${color.reset}");

    va_start(args, fmt);
    retval = amxt_tty_vwritef(tty, fmt, args);
    va_end(args);

exit:
    return retval;
}

ssize_t amxt_tty_messagef(const amxt_tty_t* tty, const char* fmt, ...) {
    ssize_t retval = -1;
    va_list args;

    when_null(tty, exit);
    when_null(fmt, exit);

    amxt_tty_writef(tty, "${color.green}");
    va_start(args, fmt);
    retval = amxt_tty_vwritef(tty, fmt, args);
    va_end(args);
    amxt_tty_writef(tty, "${color.reset}");

exit:
    return retval;
}

void amxt_tty_hex_dump(const amxt_tty_t* tty, void* buf, int len) {
    int i;
    unsigned char buff[17];
    unsigned char* pc = (unsigned char*) buf;

    for(i = 0; i < len; i++) {
        if((i % NR_OF_BYTES_LINE) == 0) {
            if(i != 0) {
                amxt_tty_writef(tty, "  %s\n", buff);
            }
            amxt_tty_writef(tty, "  %04x ", i);
        }

        amxt_tty_writef(tty, " %02x", pc[i]);

        if((pc[i] < 0x20) || (pc[i] > 0x7e)) {
            buff[i % NR_OF_BYTES_LINE] = '.';
        } else {
            buff[i % NR_OF_BYTES_LINE] = pc[i];
        }

        buff[(i % NR_OF_BYTES_LINE) + 1] = '\0';
    }

    while((i % NR_OF_BYTES_LINE) != 0) {
        amxt_tty_writef(tty, "   ");
        i++;
    }

    amxt_tty_writef(tty, "  %s\n", buff);
}
