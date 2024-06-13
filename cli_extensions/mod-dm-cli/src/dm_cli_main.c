/****************************************************************************
**
** SPDX-License-Identifier: BSD-2-Clause-Patent
**
** SPDX-FileCopyrightText: Copyright (c) 2022 SoftAtHome
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

#include "dm_cli_priv.h"
#include "mod_dm_cli.h"

typedef struct _dm_cli {
    amxm_shared_object_t* so;
    amxt_tty_t* tty;
    amxd_dm_t dm;
    amxc_llist_t entry_points;
    amxo_parser_t parser;
} dm_cli_t;

static dm_cli_t dm_cli;

static void dm_cli_slot_add_fd(UNUSED const char* const sig_name,
                               const amxc_var_t* const data,
                               UNUSED void* const priv) {
    amxo_connection_t* con = NULL;

    if(amxc_var_type_of(data) != AMXC_VAR_ID_FD) {
        goto leave;
    }

    con = amxo_connection_get(&dm_cli.parser, amxc_var_constcast(fd_t, data));
    if(con == NULL) {
        goto leave;
    }

    if((con->type == AMXO_BUS) || (con->type == AMXO_LISTEN)) {
        amxb_bus_ctx_t* bus_ctx = (amxb_bus_ctx_t*) con->priv;
        amxb_register(bus_ctx, &dm_cli.dm);
    }

leave:
    return;
}

static int dm_cli_init(UNUSED const char* function_name,
                       amxc_var_t* args,
                       UNUSED amxc_var_t* ret) {
    amxt_tty_t* tty = GET_TTY(args);
    int retval = -1;

    dm_cli.tty = tty;

    amxd_dm_init(&dm_cli.dm);
    amxc_llist_init(&dm_cli.entry_points);
    amxo_parser_init(&dm_cli.parser);
    mod_dm_cli_parser_config_init(&dm_cli.parser);

    dm_cli_register_dm(&dm_cli.dm);

    amxp_slot_connect(NULL, "connection-added", NULL, dm_cli_slot_add_fd, NULL);
    amxp_slot_connect(NULL, "listen-added", NULL, dm_cli_slot_add_fd, NULL);

    return retval;
}

static int dm_cli_exit(UNUSED const char* function_name,
                       UNUSED amxc_var_t* args,
                       UNUSED amxc_var_t* ret) {
    amxp_slot_disconnect(NULL, "connection-added", dm_cli_slot_add_fd);
    amxp_slot_disconnect(NULL, "listen-added", dm_cli_slot_add_fd);

    dm_cli_move_entry_points(dm_cli.parser.entry_points, &dm_cli.entry_points);
    amxo_parser_rinvoke_entry_points(&dm_cli.parser, &dm_cli.dm, AMXO_STOP);

    amxd_dm_clean(&dm_cli.dm);
    amxo_parser_clean(&dm_cli.parser);
    return 0;
}

static AMXM_CONSTRUCTOR dm_cli_start(void) {
    dm_cli.so = amxm_so_get_current();
    amxm_module_t* mod = NULL;

    amxm_module_register(&mod, dm_cli.so, "__shared_object");
    amxm_module_add_function(mod, "init", dm_cli_init);
    amxm_module_add_function(mod, "exit", dm_cli_exit);

    mod_dm_cli_start(dm_cli.so);

    return 0;
}

static AMXM_DESTRUCTOR dm_cli_stop(void) {
    mod_dm_cli_stop(dm_cli.so);

    dm_cli.so = NULL;
    dm_cli.tty = NULL;

    return 0;
}

amxm_shared_object_t* dm_cli_get_so(void) {
    return dm_cli.so;
}

amxo_parser_t* dm_cli_get_parser(void) {
    return &dm_cli.parser;
}

amxt_tty_t* dm_cli_get_tty(void) {
    return dm_cli.tty;
}

amxd_dm_t* dm_cli_get_dm(void) {
    return &dm_cli.dm;
}

amxc_llist_t* dm_cli_get_entry_points(void) {
    return &dm_cli.entry_points;
}

void dm_cli_move_entry_points(amxc_llist_t* dest, amxc_llist_t* src) {
    when_null(dest, exit);
    when_null(src, exit);
    amxc_llist_for_each(it, src) {
        amxc_llist_append(dest, it);
    }

exit:
    return;
}

int dm_cli_register_dm(amxd_dm_t* dm) {
    int retval = -1;

    amxc_llist_for_each(it, amxp_connection_get_connections()) {
        amxo_connection_t* con = amxc_llist_it_get_data(it, amxo_connection_t, it);
        amxb_bus_ctx_t* bus_ctx = (amxb_bus_ctx_t*) con->priv;
        if(con->type != AMXO_BUS) {
            continue;
        }
        when_failed(amxb_register(bus_ctx, dm), exit);
    }

    amxc_llist_for_each(it, amxp_connection_get_listeners()) {
        amxo_connection_t* con = amxc_llist_it_get_data(it, amxo_connection_t, it);
        amxb_bus_ctx_t* bus_ctx = (amxb_bus_ctx_t*) con->priv;
        when_failed(amxb_register(bus_ctx, dm), exit);
    }

    retval = 0;

exit:
    return retval;
}
