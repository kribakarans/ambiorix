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

#include <stdlib.h>
#include <string.h>

#include "dm_ssh_server.h"

#define UNKNOWN_TIME "0001-01-01T00:00:00Z"

int ssh_server_update_status(amxd_object_t* server, const char* status) {
    amxd_trans_t transaction;
    int retval = 0;
    amxc_ts_t now;
    amxp_proc_ctrl_t* dropbear_ctrl = (amxp_proc_ctrl_t*) server->priv;

    amxd_trans_init(&transaction);
    amxd_trans_set_attr(&transaction, amxd_tattr_change_ro, true);
    amxd_trans_select_object(&transaction, server);

    if(strcmp(status, "Disabled") == 0) {
        char* current_status = NULL;
        current_status = amxd_object_get_value(cstring_t, server, "Status", NULL);
        if(strcmp(current_status, "Running") == 0) {
            amxd_trans_set_value(cstring_t, &transaction, "Status", status);
        }
        amxd_trans_set_value(bool, &transaction, "Enable", false);
        free(current_status);
    } else {
        amxd_trans_set_value(cstring_t, &transaction, "Status", status);
    }

    if(strcmp(status, "Running") == 0) {
        amxc_ts_now(&now);
        amxd_trans_set_value(amxc_ts_t, &transaction, "ActivationDate", &now);
        amxd_trans_set_value(uint32_t, &transaction,
                             "PID", amxp_subproc_get_pid(dropbear_ctrl->proc));
    } else {
        amxc_ts_parse(&now, UNKNOWN_TIME, strlen(UNKNOWN_TIME));
        amxd_trans_set_value(amxc_ts_t, &transaction, "ActivationDate", &now);
        amxd_trans_set_value(uint32_t, &transaction, "PID", 0);
        amxd_trans_set_value(uint32_t, &transaction, "ActiveSessions", 0);
    }

    retval = amxd_trans_apply(&transaction, ssh_server_get_dm());

    amxd_trans_clean(&transaction);
    return retval;
}

int ssh_server_update_sessions(amxd_object_t* server, uint32_t sessions) {
    amxd_trans_t transaction;
    int retval = 0;

    amxd_trans_init(&transaction);
    amxd_trans_set_attr(&transaction, amxd_tattr_change_ro, true);
    amxd_trans_select_object(&transaction, server);
    amxd_trans_set_value(uint32_t, &transaction, "ActiveSessions", sessions);
    retval = amxd_trans_apply(&transaction, ssh_server_get_dm());

    amxd_trans_clean(&transaction);
    return retval;
}
