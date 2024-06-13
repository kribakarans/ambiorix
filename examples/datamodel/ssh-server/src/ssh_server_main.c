/****************************************************************************
**
** Copyright (c) 2020 SoftAtHome
**
** Redistribution and use in source and binary forms, with or
** without modification, are permitted provided that the following
** conditions are met:
**
** 1. Redistributions of source code must retain the above copyright
** notice, this list of conditions and the following disclaimer.
**
** 2. Redistributions in binary form must reproduce the above
** copyright notice, this list of conditions and the following
** disclaimer in the documentation and/or other materials provided
** with the distribution.
**
** Subject to the terms and conditions of this license, each
** copyright holder and contributor hereby grants to those receiving
** rights under this license a perpetual, worldwide, non-exclusive,
** no-charge, royalty-free, irrevocable (except for failure to
** satisfy the conditions of this license) patent license to make,
** have made, use, offer to sell, sell, import, and otherwise
** transfer this software, where such license applies only to those
** patent claims, already acquired or hereafter acquired, licensable
** by such copyright holder or contributor that are necessarily
** infringed by:
**
** (a) their Contribution(s) (the licensed copyrights of copyright
** holders and non-copyrightable additions of contributors, in
** source or binary form) alone; or
**
** (b) combination of their Contribution(s) with the work of
** authorship to which such Contribution(s) was added by such
** copyright holder or contributor, if, at the time the Contribution
** is added, such addition causes such combination to be necessarily
** infringed. The patent license shall not apply to any other
** combinations which include the Contribution.
**
** Except as expressly stated above, no rights or licenses from any
** copyright holder or contributor is granted under this license,
** whether expressly, by implication, estoppel or otherwise.
**
** DISCLAIMER
**
** THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
** CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
** INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
** MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
** DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR
** CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
** SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
** LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
** USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
** AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
** LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
** ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
** POSSIBILITY OF SUCH DAMAGE.
**
****************************************************************************/

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>
#include <sys/inotify.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "dm_ssh_server.h"

typedef struct _ssh_server {
    amxd_dm_t* dm;
    amxo_parser_t* parser;
    amxp_timer_t* timer;
} ssh_server_t;

static ssh_server_t app;

static int ssh_server_check_sessions(UNUSED amxd_object_t* templ,
                                     amxd_object_t* instance,
                                     UNUSED void* priv) {
    amxp_proc_ctrl_t* dropbear_ctrl = (amxp_proc_ctrl_t*) instance->priv;
    size_t current_sessions = 0;

    current_sessions = amxp_proc_ctrl_get_child_pids(dropbear_ctrl);
    ssh_server_update_sessions(instance, current_sessions);

    return 0;
}

static void ssh_server_check(UNUSED amxp_timer_t* const timer,
                             UNUSED void* data) {
    amxd_object_t* servers = amxd_dm_findf(app.dm, "SSH.Server");
    amxd_object_for_all(servers,
                        "[ Status == 'Running' ].",
                        ssh_server_check_sessions,
                        NULL);
}

void ssh_server_start_monitor(void) {
    amxc_var_t* child_mon = GET_ARG(&app.parser->config, "dropbear-child-monitor");
    bool is_enabled = GETP_BOOL(child_mon, "enable");
    uint32_t interval = amxc_var_dyncast(uint32_t, GET_ARG(child_mon, "interval"));

    if(is_enabled) {
        amxp_timer_set_interval(app.timer, interval);

        if(amxp_timer_get_state(app.timer) != amxp_timer_running) {
            amxp_timer_start(app.timer, interval);
        }
    } else {
        amxp_timer_stop(app.timer);
    }
}

amxd_dm_t* ssh_server_get_dm(void) {
    return app.dm;
}

amxc_var_t* ssh_server_get_config(void) {
    return &app.parser->config;
}

amxo_parser_t* ssh_server_get_parser(void) {
    return app.parser;
}

int _ssh_server_main(int reason,
                     amxd_dm_t* dm,
                     amxo_parser_t* parser) {

    switch(reason) {
    case 0:     // START
        app.dm = dm;
        app.parser = parser;
        amxp_timer_new(&app.timer, ssh_server_check, NULL);
        ssh_server_uci_import(dm, parser);
        break;
    case 1:     // STOP
        ssh_server_uci_export(dm, parser);
        amxp_timer_delete(&app.timer);
        app.dm = NULL;
        app.parser = parser;
        break;
    }

    return 0;
}
