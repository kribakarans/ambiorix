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
#include <stdio.h>

#include "ba_cli_priv.h"

#include "mod_pcb_cli_cmd.h"
#include "mod_pcb_cli_common.h"

static void mod_pcb_cli_write_obj_attrs(amxc_var_t* object) {
    amxt_tty_t* tty = ba_cli_get_tty();
    amxt_tty_writef(tty, "${color.blue}");

    if(GET_BOOL(object, "is_multi_instance")) {
        amxt_tty_writef(tty, "M");
    } else {
        amxt_tty_writef(tty, "${color.reset}.${color.blue}");
    }

    if(GET_BOOL(object, "access")) {
        amxt_tty_writef(tty, "AD");
    } else {
        amxt_tty_writef(tty, "${color.reset}..${color.blue}");
    }

    amxt_tty_writef(tty, " ${color.reset}");
}

static void mod_pcb_cli_write_param_attrs(amxc_var_t* param) {
    amxt_tty_t* tty = ba_cli_get_tty();
    amxt_tty_writef(tty, "${color.reset}.${color.blue}");

    if(GET_BOOL(param, "access")) {
        amxt_tty_writef(tty, "RW");
    } else {
        amxt_tty_writef(tty, "R.");
    }

    amxt_tty_writef(tty, " ${color.reset}");
}

static void mod_pcb_cli_write_func_attrs(amxc_var_t* func) {
    amxt_tty_t* tty = ba_cli_get_tty();
    uint32_t type = GET_UINT32(func, "command_type");
    amxt_tty_writef(tty, "${color.reset}..${color.blue}");
    switch(type) {
    case 0:
        amxt_tty_writef(tty, "U");
        break;
    case 1:
        amxt_tty_writef(tty, "S");
        break;
    case 2:
        amxt_tty_writef(tty, "A");
        break;
    }

    amxt_tty_writef(tty, " ${color.reset}");
}

static void mod_pcb_cli_write_obj_params(const char* base_path, amxc_var_t* params) {
    amxt_tty_t* tty = ba_cli_get_tty();
    when_null(params, exit);

    amxc_var_for_each(param, params) {
        const char* name = GET_CHAR(param, "param_name");
        mod_pcb_cli_write_param_attrs(param);
        amxt_tty_writef(tty, "(${color.blue}%-12.12s${color.reset}) ",
                        amxc_var_get_type_name_from_id(GET_UINT32(param, "type")));
        amxt_tty_writef(tty, "${color.green}%s${color.reset}%s\n", base_path, name);
    }

exit:
    return;
}

static void mod_pcb_cli_write_obj_funcs(const char* base_path, amxc_var_t* funcs) {
    amxt_tty_t* tty = ba_cli_get_tty();
    when_null(funcs, exit);

    amxc_var_for_each(func, funcs) {
        const char* name = GET_CHAR(func, "command_name");
        mod_pcb_cli_write_func_attrs(func);
        amxt_tty_writef(tty, "(${color.blue}%-12.12s${color.reset}) ", "Command");
        amxt_tty_writef(tty, "${color.green}%s${color.reset}%s\n", base_path, name);
    }

exit:
    return;
}

static void mod_pcb_cli_write_obj_events(const char* base_path, amxc_var_t* events) {
    amxt_tty_t* tty = ba_cli_get_tty();
    when_null(events, exit);

    amxc_var_for_each(event, events) {
        const char* name = amxc_var_key(event);
        amxt_tty_write(tty, "... ", 4);
        amxt_tty_writef(tty, "(${color.blue}%-12.12s${color.reset}) ", "Event");
        amxt_tty_writef(tty, "${color.green}%s${color.reset}%s", base_path, name);
        if(amxc_var_type_of(event) == AMXC_VAR_ID_LIST) {
            const char* sep = "";
            amxt_tty_writef(tty, " [");
            amxc_var_for_each(param, event) {
                const char* param_name = GET_CHAR(param, NULL);
                amxt_tty_writef(tty, "%s%s", sep, param_name);
                sep = ",";
            }
            amxt_tty_writef(tty, "]");
        }
        amxt_tty_writef(tty, "\n");
    }

exit:
    return;
}

static void mod_pcb_cli_write_object(amxc_var_t* object,
                                     const char* base_path) {
    amxc_var_t* parameters = GET_ARG(object, "supported_params");
    amxc_var_t* functions = GET_ARG(object, "supported_commands");
    amxc_var_t* events = GET_ARG(object, "supported_events");

    amxt_tty_t* tty = ba_cli_get_tty();

    mod_pcb_cli_write_obj_attrs(object);

    amxt_tty_writef(tty, "(${color.blue}%-12.12s${color.reset}) ", "Object");
    amxt_tty_writef(tty, "${color.green}%s${color.reset}\n", base_path);
    mod_pcb_cli_write_obj_params(base_path, parameters);
    mod_pcb_cli_write_obj_funcs(base_path, functions);
    mod_pcb_cli_write_obj_events(base_path, events);

    return;
}

static void mod_pcb_cli_write_sdm(amxc_var_t* result) {
    amxc_var_t* objects = GETI_ARG(result, 0);
    const amxc_htable_t* ho = amxc_var_constcast(amxc_htable_t, objects);
    amxc_array_t* paths = amxc_htable_get_sorted_keys(ho);
    uint32_t size = amxc_array_size(paths);

    for(uint32_t i = 0; i < size; i++) {
        amxc_htable_it_t* it = amxc_htable_get(ho, (const char*) amxc_array_get_data_at(paths, i));
        const char* base_path = amxc_htable_it_get_key(it);
        amxc_var_t* object = amxc_var_from_htable_it(it);
        mod_pcb_cli_write_object(object, base_path);
    }

    amxc_array_delete(&paths, NULL);
}

int mod_pcb_cli_cmd_gsdm(UNUSED const char* function_name,
                         amxc_var_t* args,
                         UNUSED amxc_var_t* ret) {
    amxc_var_t options;
    amxc_var_t data;
    char* input_path = NULL;
    amxb_bus_ctx_t* bus_ctx = NULL;
    int rv = 0;
    int flags = 0;
    amxt_tty_t* tty = ba_cli_get_tty();

    amxc_var_init(&options);
    amxc_var_init(&data);

    rv = mod_pcb_cli_cmd_parse(args, PCB_GSDM, NULL, &input_path, &options, NULL);
    when_failed(rv, exit);

    bus_ctx = mod_pcb_cli_get_bus_ctx(input_path);
    when_null(bus_ctx, exit);

    if(GET_BOOL(&options, "p") || GET_BOOL(&options, "parameters")) {
        flags |= AMXB_FLAG_PARAMETERS;
    }

    if(GET_BOOL(&options, "f") || GET_BOOL(&options, "functions")) {
        flags |= AMXB_FLAG_FUNCTIONS;
    }

    if(GET_BOOL(&options, "e") || GET_BOOL(&options, "events")) {
        flags |= AMXB_FLAG_EVENTS;
    }

    if(GET_BOOL(&options, "l") || GET_BOOL(&options, "first_lvl_only")) {
        flags |= AMXB_FLAG_FIRST_LVL;
    }

    rv = amxb_get_supported(bus_ctx, input_path, flags, &data, 5);
    if(rv != amxd_status_ok) {
        amxt_tty_errorf(tty, "gsdm %s failed (%d - %s)\n",
                        input_path, rv, amxd_status_string((amxd_status_t) rv));
        goto exit;
    }

    if(!mod_pcb_cli_output_json(tty, &data)) {
        mod_pcb_cli_write_sdm(&data);
    }

exit:
    amxc_var_clean(&options);
    amxc_var_clean(&data);
    free(input_path);
    return rv;
}
