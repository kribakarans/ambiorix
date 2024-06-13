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

#include <signal.h>
#include <string.h>

#include <event2/event.h>

#include <amxc/amxc_string.h>
#include <amxc/amxc_variant.h>
#include <amxp/amxp_signal.h>
#include <amxp/amxp_slot.h>
#include <amxt/amxt_tty.h>

#define TTY_UNUSED __attribute__((unused))

static amxt_tty_t* tty = NULL;

static void slot_handle_line(TTY_UNUSED const char* const sig_name,
                             const amxc_var_t* const data) {

    const char* txt = amxc_var_constcast(cstring_t, amxc_var_get_key(data, "text", AMXC_VAR_FLAG_DEFAULT));
    amxt_tty_write(tty, txt, strlen(txt));
}

static void tty_read_cb(TTY_UNUSED evutil_socket_t fd, TTY_UNUSED short flags, TTY_UNUSED void* arg) {
    amxt_tty_read(tty);
}

static void signal_cb(TTY_UNUSED evutil_socket_t fd, TTY_UNUSED short event, void* arg) {
    struct event_base* base = arg;
    event_base_loopbreak(base);
}

int main(void) {
    int ret = 0;
    struct event* signal_int = NULL;
    struct event* tty_input = NULL;

    struct event_base* base = event_base_new();
    if(base == NULL) {
        exit(1);
    }

    if(amxt_tty_open(&tty, fileno(stdin)) != 0) {
        exit(2);
    }

    amxt_tty_set_prompt(tty, "Example tty> ");
    if(amxp_slot_connect(amxt_tty_sigmngr(tty), "tty:newline", slot_handle_line) != 0) {
        amxt_tty_close(&tty);
        printf("\n");
        exit(3);
    }

    signal_int = evsignal_new(base, SIGINT, signal_cb, base);
    event_add(signal_int, NULL);

    tty_input = event_new(base, amxt_tty_fd(tty), EV_READ | EV_PERSIST, tty_read_cb, NULL);
    event_add(tty_input, NULL);

    event_base_dispatch(base);

    event_del(signal_int);
    event_del(tty_input);
    event_base_free(base);

    free(signal_int);
    free(tty_input);

    amxt_tty_close(&tty);

    return ret;
}
