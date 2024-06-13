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

#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

#include <event2/event.h>

#include "amx_cli.h"
#include "amx_cli_eventloop.h"

static struct event_config* cfg = NULL;
static struct event_base* base = NULL;

static struct event* signal_int = NULL;
static struct event* signal_term = NULL;
static struct event* signal_alarm = NULL;
static struct event* tty_input = NULL;
static struct event* amxp_sig = NULL;

static void tty_signal_cb(UNUSED evutil_socket_t fd,
                          UNUSED short event,
                          UNUSED void* arg) {
    event_base_loopbreak(base);
}


static void tty_return(UNUSED evutil_socket_t fd,
                       UNUSED short event,
                       UNUSED void* arg) {
    amxt_tty_t* tty_arg = (amxt_tty_t*) arg;
    char* prompt = amxt_prompt_get(&tty_arg->prompt);

    amxt_tty_write(tty_arg, "\n", 1);
    amxt_tty_write_raw(tty_arg, prompt, strlen(prompt));
    amxt_il_reset(amxt_tty_il(tty_arg));
    free(prompt);
}

static void tty_signal_timers(UNUSED evutil_socket_t fd,
                              UNUSED short event,
                              UNUSED void* arg) {
    amxp_timers_calculate();
    amxp_timers_check();
}

static void tty_connection_read_cb(UNUSED evutil_socket_t fd,
                                   UNUSED short flags,
                                   void* arg) {
    amxp_connection_t* con = (amxp_connection_t*) arg;
    con->reader(fd, con->priv);
}

static void amxp_signal_read_cb(UNUSED evutil_socket_t fd,
                                UNUSED short flags,
                                UNUSED void* arg) {
    amxp_signal_read();
}

static void tty_read_cb(UNUSED evutil_socket_t fd,
                        UNUSED short flags,
                        void* arg) {
    amxt_tty_t* tty_arg = (amxt_tty_t*) arg;
    amxt_tty_read(tty_arg);
}

static void amx_cli_slot_add_fd(UNUSED const char* const sig_name,
                                const amxc_var_t* const data,
                                UNUSED void* const priv) {
    amxp_connection_t* con = NULL;

    if(amxc_var_type_of(data) != AMXC_VAR_ID_FD) {
        goto leave;
    }

    con = amxp_connection_get(amxc_var_constcast(fd_t, data));
    if(con == NULL) {
        goto leave;
    }

    con->el_data = event_new(base,
                             con->fd,
                             EV_READ | EV_PERSIST,
                             tty_connection_read_cb,
                             con);
    event_add((struct event*) con->el_data, NULL);

leave:
    return;
}

static void amx_cli_slot_remove_fd(UNUSED const char* const sig_name,
                                   const amxc_var_t* const data,
                                   UNUSED void* const priv) {
    amxp_connection_t* con = NULL;

    if(amxc_var_type_of(data) != AMXC_VAR_ID_FD) {
        goto leave;
    }

    con = amxp_connection_get(amxc_var_constcast(fd_t, data));
    if(con == NULL) {
        goto leave;
    }

    if(con->el_data != NULL) {
        event_del((struct event*) con->el_data);
        free(con->el_data);
        con->el_data = NULL;
    }

leave:
    return;
}

int amx_cli_el_create(amxt_tty_t* tty) {
    int retval = -1;

    cfg = event_config_new();
    event_config_avoid_method(cfg, "epoll");

    base = event_base_new_with_config(cfg);
    if(base == NULL) {
        goto exit;
    }

    tty_input = event_new(base,
                          amxt_tty_fd(tty),
                          EV_READ | EV_PERSIST,
                          tty_read_cb,
                          tty);
    event_add(tty_input, NULL);

    amxp_sig = event_new(base,
                         amxp_signal_fd(),
                         EV_READ | EV_PERSIST,
                         amxp_signal_read_cb,
                         NULL);
    event_add(amxp_sig, NULL);

    amxp_slot_connect(NULL, "connection-added", NULL, amx_cli_slot_add_fd, NULL);
    amxp_slot_connect(NULL, "connection-deleted", NULL, amx_cli_slot_remove_fd, NULL);
    amxp_slot_connect(NULL, "listen-added", NULL, amx_cli_slot_add_fd, NULL);
    amxp_slot_connect(NULL, "listen-deleted", NULL, amx_cli_slot_remove_fd, NULL);

    retval = 0;
exit:
    return retval;
}

int amx_cli_add_sig_handlers(amxt_tty_t* tty) {
    signal_int = evsignal_new(base, SIGINT, tty_return, tty);
    event_add(signal_int, NULL);

    signal_term = evsignal_new(base, SIGTERM, tty_signal_cb, NULL);
    event_add(signal_term, NULL);

    signal_alarm = evsignal_new(base, SIGALRM, tty_signal_timers, NULL);
    event_add(signal_alarm, NULL);

    amxp_sigmngr_add_signal(tty->sigmngr, "tty:record-start");

    return 0;
}

int amx_cli_el_start(UNUSED amxt_tty_t* tty) {
    event_base_dispatch(base);

    return 0;
}

int amx_cli_el_stop(UNUSED amxt_tty_t* tty) {
    event_base_loopbreak(base);

    return 0;
}

int amx_cli_el_delete(UNUSED amxt_tty_t* tty) {
    if(signal_int != NULL) {
        event_del(signal_int);
    }
    if(signal_term != NULL) {
        event_del(signal_term);
    }
    if(signal_alarm != NULL) {
        event_del(signal_alarm);
    }
    if(tty_input != NULL) {
        event_del(tty_input);
    }
    if(amxp_sig != NULL) {
        event_del(amxp_sig);
    }
    if(base != NULL) {
        event_base_free(base);
    }
    if(cfg != NULL) {
        event_config_free(cfg);
    }

    free(signal_int);
    signal_int = NULL;
    free(signal_term);
    signal_term = NULL;
    free(signal_alarm);
    signal_alarm = NULL;
    free(tty_input);
    tty_input = NULL;
    free(amxp_sig);
    amxp_sig = NULL;

    return 0;
}
