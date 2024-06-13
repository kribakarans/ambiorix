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

#include <string.h>

#include "ba_cli_priv.h"

#include "mod_pcb_cli_cmd.h"
#include "mod_pcb_cli_common.h"

static int mod_pcb_cli_list_impl(const char* path) {
    amxt_tty_t* tty = ba_cli_get_tty();
    amxd_path_t dm_path;
    const char* pf = NULL;
    amxd_path_init(&dm_path, path);

    amxt_tty_writef(tty, "${color.green}%s${color.reset}", amxd_path_get(&dm_path, AMXD_OBJECT_TERMINATE));
    pf = amxd_path_get_param(&dm_path);
    if(pf != NULL) {
        amxt_tty_writef(tty, "%s\n", pf);
    } else {
        amxt_tty_writef(tty, "\n");
    }

    amxd_path_clean(&dm_path);

    return 0;
}

static void mod_pcb_cli_list_cb(UNUSED const amxb_bus_ctx_t* bus_ctx,
                                const amxc_var_t* const data,
                                UNUSED void* priv) {
    amxt_tty_t* tty = ba_cli_get_tty();

    if(data == NULL) {
        return;
    } else {
        if(tty->interactive) {
            amxt_tty_hide_prompt(tty);
        }
        amxc_var_for_each(var_path, data) {
            const char* str_path = amxc_var_constcast(cstring_t, var_path);
            mod_pcb_cli_list_impl(str_path);
        }
        if(tty->interactive) {
            amxt_tty_show_prompt(tty);
        }
    }
}

static int mod_pcb_cli_list(amxb_bus_ctx_t* bus_ctx,
                            const char* path,
                            amxc_var_t* options) {
    int rv = -1;
    amxt_tty_t* tty = ba_cli_get_tty();
    amxd_path_t dm_path;
    uint32_t flags = AMXB_FLAG_OBJECTS | AMXB_FLAG_INSTANCES;
    amxc_var_t resolved;

    amxc_var_init(&resolved);
    amxd_path_init(&dm_path, path);

    if(!GET_BOOL(options, "r") && !GET_BOOL(options, "recursive")) {
        flags |= AMXB_FLAG_FIRST_LVL;
    }

    if(GET_BOOL(options, "n") || GET_BOOL(options, "named")) {
        flags |= AMXB_FLAG_NAMED;
    }

    if(GET_BOOL(options, "p") || GET_BOOL(options, "parameters")) {
        flags |= AMXB_FLAG_PARAMETERS;
    }

    if(GET_BOOL(options, "f") || GET_BOOL(options, "functions")) {
        flags |= AMXB_FLAG_FUNCTIONS;
    }

    if(amxd_path_is_search_path(&dm_path)) {
        if((flags & ~(AMXB_FLAG_OBJECTS | AMXB_FLAG_INSTANCES)) != 0) {
            amxt_tty_writef(tty, "${color.red}Warning:${color.reset} "
                            "Options on search paths are ignored.\n");
        }
        rv = amxb_resolve(bus_ctx, &dm_path, &resolved);
        when_failed(rv, exit);
        mod_pcb_cli_output_list(tty, &resolved);
    } else {
        if(tty->interactive) {
            amxt_tty_show_prompt(tty);
        }
        rv = amxb_list(bus_ctx, path,
                       flags,
                       mod_pcb_cli_list_cb,
                       (amxc_var_t*) options);
        if(tty->interactive) {
            amxt_tty_hide_prompt(tty);
        }
    }

exit:
    amxc_var_clean(&resolved);
    amxd_path_clean(&dm_path);
    return rv;
}

static void mod_pcb_cli_list_add_object(UNUSED const amxb_bus_ctx_t* bus_ctx,
                                        const amxc_var_t* const data,
                                        void* priv) {
    amxc_set_t* set = (amxc_set_t*) priv;
    when_null(data, exit);
    amxc_var_for_each(var_path, data) {
        const char* str_path = amxc_var_constcast(cstring_t, var_path);
        amxc_set_add_flag(set, str_path);
    }

exit:
    return;
}

static int mod_pcb_cli_list_all(amxb_bus_ctx_t* bus_ctx,
                                UNUSED const amxc_var_t* args,
                                void* priv) {
    amxc_set_t* set = (amxc_set_t*) priv;

    amxb_list(bus_ctx, "", AMXB_FLAG_OBJECTS |
              AMXB_FLAG_INSTANCES |
              AMXB_FLAG_FIRST_LVL |
              AMXB_FLAG_EXISTS, mod_pcb_cli_list_add_object, set);

    return 0;
}

int mod_pcb_cli_cmd_list(UNUSED const char* function_name,
                         amxc_var_t* args,
                         UNUSED amxc_var_t* ret) {
    amxc_var_t* options = NULL;
    char* input_path = NULL;
    amxb_bus_ctx_t* bus_ctx = NULL;
    int rv = 0;
    amxc_set_t* set = NULL;

    amxc_var_new(&options);

    rv = mod_pcb_cli_cmd_parse(args, PCB_LIST, NULL, &input_path, options, NULL);
    when_failed(rv, exit);

    bus_ctx = mod_pcb_cli_get_bus_ctx(input_path);
    if(bus_ctx == NULL) {
        amxc_set_new(&set, true);
        amxb_be_for_all_connections(mod_pcb_cli_list_all, NULL, set);
        amxc_llist_for_each(it, &set->list) {
            amxc_flag_t* f = amxc_container_of(it, amxc_flag_t, it);
            mod_pcb_cli_list_impl(f->flag);
        }
    } else {
        mod_pcb_cli_list(bus_ctx, (input_path == NULL) || (*input_path == 0)? "":input_path, options);
    }

exit:
    amxc_set_delete(&set);
    amxc_var_delete(&options);
    free(input_path);
    return rv;
}
