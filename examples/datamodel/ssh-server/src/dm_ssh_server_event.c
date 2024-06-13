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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include "dm_ssh_server.h"

#define ssh_server_start ssh_server_enable
static int ssh_server_enable(UNUSED amxd_object_t* templ,
                             amxd_object_t* server,
                             UNUSED void* priv) {
    int retval = 0;
    uint32_t time = 0;
    char* status = NULL;
    amxp_proc_ctrl_t* dropbear_ctrl = (amxp_proc_ctrl_t*) server->priv;

    amxc_var_t settings;
    amxc_var_init(&settings);

    ssh_server_fetch_settings(server, &settings);
    time = amxd_object_get_value(uint32_t, server, "ActivationDuration", NULL);
    status = amxd_object_get_value(cstring_t, server, "Status", NULL);
    if((status == NULL) || (strcmp(status, "Running") != 0)) {
        retval = amxp_proc_ctrl_start(dropbear_ctrl, time, &settings);
        if(retval == 0) {
            ssh_server_update_status(server, "Running");
            ssh_server_start_monitor();
        } else {
            ssh_server_update_status(server, "Error");
        }
    }

    free(status);
    amxc_var_clean(&settings);

    return retval;
}

#define ssh_server_stop ssh_server_disable
static int ssh_server_disable(UNUSED amxd_object_t* templ,
                              amxd_object_t* server,
                              UNUSED void* priv) {
    amxp_proc_ctrl_t* dropbear_ctrl = (amxp_proc_ctrl_t*) server->priv;
    const char* status = (const char*) priv;

    int retval = amxp_proc_ctrl_stop(dropbear_ctrl);
    if(retval == 0) {
        ssh_server_update_status(server, status);
    }
    return 0;
}

#define ssh_server_proc_stopped ssh_server_proc_disable
static void ssh_server_proc_disable(const char* const event_name,
                                    const amxc_var_t* const event_data,
                                    UNUSED void* const priv) {
    uint32_t pid = amxc_var_dyncast(uint32_t, event_data);
    amxd_dm_t* dm = ssh_server_get_dm();
    amxd_object_t* server = NULL;
    const char* status = "Disabled";

    if(strcmp(event_name, "proc:stopped") == 0) {
        status = "Stopped";
    }

    server = amxd_dm_findf(dm, "SSH.Server.[ PID == %d ].", pid);
    if(server != NULL) {
        ssh_server_update_status(server, status);
    }
}

int ssh_server_proc_initialize(amxd_object_t* templ,
                               amxd_object_t* instance,
                               void* priv) {
    bool* is_enabled = (bool*) priv;
    bool instance_enabled = false;
    amxp_proc_ctrl_t* dropbear_ctrl = NULL;
    int retval = 0;

    if(instance->priv == NULL) {
        retval = amxp_proc_ctrl_new(&dropbear_ctrl, dropbear_ctrl_build_cmd);
        when_failed(retval, leave);

        instance->priv = dropbear_ctrl;
    }

    instance_enabled = amxd_object_get_value(bool, instance, "Enable", NULL);
    if(*is_enabled && instance_enabled) {
        ssh_server_start(templ, instance, NULL);
    }

leave:
    return retval;
}

void _print_event(const char* const event_name,
                  const amxc_var_t* const event_data,
                  UNUSED void* const priv) {
    printf("Event received - %s\n", event_name);
    if(event_data) {
        printf("Signal data = \n");
        fflush(stdout);
        amxc_var_dump(event_data, STDOUT_FILENO);
    }
}

void _app_start(UNUSED const char* const event_name,
                UNUSED const amxc_var_t* const event_data,
                UNUSED void* const priv) {
    amxd_dm_t* dm = ssh_server_get_dm();
    amxd_object_t* ssh = amxd_dm_get_object(dm, "SSH");
    amxd_object_t* servers = amxd_object_get_child(ssh, "Server");

    bool is_enabled = amxd_object_get_value(bool, ssh, "Enable", NULL);
    amxc_var_t args;
    amxc_var_t ret;

    amxc_var_init(&args);
    amxc_var_init(&ret);

    amxp_sigmngr_add_signal(NULL, "proc:disable");
    amxp_sigmngr_add_signal(NULL, "proc:stopped");

    amxp_slot_connect(NULL, "proc:disable", NULL, ssh_server_proc_disable, NULL);
    amxp_slot_connect(NULL, "proc:stopped", NULL, ssh_server_proc_stopped, NULL);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxd_object_invoke_function(ssh, "load", &args, &ret);

    amxd_object_for_all(servers, "*", ssh_server_proc_initialize, &is_enabled);

    amxc_var_clean(&args);
    amxc_var_clean(&ret);
}

void _ssh_toggle(UNUSED const char* const event_name,
                 const amxc_var_t* const event_data,
                 UNUSED void* const priv) {
    amxd_object_t* ssh = amxd_dm_signal_get_object(ssh_server_get_dm(), event_data);
    amxd_object_t* servers = amxd_object_get_child(ssh, "Server");
    bool enable = GETP_BOOL(event_data, "parameters.Enable.to");
    amxd_instance_cb_t fn = ssh_server_disable;
    const char* filter = "[Status == 'Running'].";
    const char* status = "Stopped";

    if(enable) {
        fn = ssh_server_enable;
        filter = "[Enable == true].";
        status = NULL;
    }

    amxd_object_for_all(servers, filter, fn, (void*) status);
    return;
}

void _ssh_server_added(UNUSED const char* const event_name,
                       const amxc_var_t* const event_data,
                       UNUSED void* const priv) {
    amxd_object_t* ssh_servers = amxd_dm_signal_get_object(ssh_server_get_dm(), event_data);
    amxd_object_t* ssh = amxd_object_get_parent(ssh_servers);
    amxd_object_t* server = NULL;
    uint32_t index = GET_UINT32(event_data, "index");
    bool is_enabled = amxd_object_get_value(bool, ssh, "Enable", NULL);

    server = amxd_object_get_instance(ssh_servers, NULL, index);
    if(server != NULL) {
        ssh_server_proc_initialize(ssh_servers, server, &is_enabled);
    }
}

void _ssh_server_enable_changed(UNUSED const char* const event_name,
                                const amxc_var_t* const event_data,
                                UNUSED void* const priv) {
    amxd_object_t* server = amxd_dm_signal_get_object(ssh_server_get_dm(), event_data);
    amxd_object_t* ssh_servers = amxd_object_get_parent(server);
    amxd_object_t* ssh = amxd_object_get_parent(ssh_servers);
    bool server_is_enabled = GETP_BOOL(event_data, "parameters.Enable.to");
    bool ssh_is_enabled = amxd_object_get_value(bool, ssh, "Enable", NULL);

    if((server != NULL) && ssh_is_enabled) {
        if(server_is_enabled) {
            ssh_server_enable(ssh_servers, server, NULL);
        } else {
            ssh_server_disable(ssh_servers, server, (void*) "Disabled");
        }
    }
}

void _ssh_server_duration_changed(UNUSED const char* const event_name,
                                  const amxc_var_t* const event_data,
                                  UNUSED void* const priv) {
    amxd_object_t* server = amxd_dm_signal_get_object(ssh_server_get_dm(), event_data);
    uint32_t time = GETP_UINT32(event_data, "parameters.ActivationDuration.to");

    if(server != NULL) {
        amxp_proc_ctrl_t* dropbear_ctrl = (amxp_proc_ctrl_t*) server->priv;
        amxp_proc_ctrl_set_active_duration(dropbear_ctrl, time);
    }
}

void _ssh_server_settings_changed(UNUSED const char* const event_name,
                                  const amxc_var_t* const event_data,
                                  UNUSED void* const priv) {
    amxd_object_t* server = amxd_dm_signal_get_object(ssh_server_get_dm(), event_data);
    char* status = amxd_object_get_value(cstring_t, server, "Status", NULL);
    amxc_var_t* config = ssh_server_get_config();

    if(GETP_BOOL(config, "ssh-server.auto-restart")) {
        if((status != NULL) && (strcmp(status, "Running") == 0)) {
            ssh_server_stop(NULL, server, (void*) "Stopped");
            ssh_server_start(NULL, server, NULL);
        }
    }
    free(status);
}