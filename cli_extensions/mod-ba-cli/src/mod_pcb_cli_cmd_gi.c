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

static void mod_pcb_cli_write_keys(const char* base_path, amxc_var_t* params) {
    amxt_tty_t* tty = ba_cli_get_tty();
    when_null(params, exit);

    amxc_var_for_each(param, params) {
        const char* key = amxc_var_key(param);
        char* value = amxc_var_dyncast(cstring_t, param);
        if((amxc_var_type_of(param) == AMXC_VAR_ID_CSTRING) ||
           (amxc_var_type_of(param) == AMXC_VAR_ID_CSV_STRING) ||
           (amxc_var_type_of(param) == AMXC_VAR_ID_SSV_STRING)) {
            amxt_tty_writef(tty, "${color.green}%s${color.white}%s${color.reset}"
                            "=\"${color.red}%s${color.reset}\"\n",
                            base_path, key, value);
        } else {
            amxt_tty_writef(tty, "${color.green}%s${color.white}%s${color.reset}"
                            "=${color.red}%s${color.reset}\n",
                            base_path, key, value);
        }
        free(value);
    }

exit:
    return;
}

static void mod_pcb_cli_write_instances(amxc_var_t* result) {
    amxc_var_t* objects = GETI_ARG(result, 0);
    const amxc_htable_t* ho = amxc_var_constcast(amxc_htable_t, objects);
    amxc_array_t* paths = amxc_htable_get_sorted_keys(ho);
    uint32_t size = amxc_array_size(paths);
    amxt_tty_t* tty = ba_cli_get_tty();

    for(uint32_t i = 0; i < size; i++) {
        amxc_htable_it_t* it = amxc_htable_get(ho, (const char*) amxc_array_get_data_at(paths, i));
        const char* base_path = amxc_htable_it_get_key(it);
        amxc_var_t* keys = amxc_var_from_htable_it(it);
        amxt_tty_writef(tty, "${color.green}%s${color.reset}\n", base_path);
        mod_pcb_cli_write_keys(base_path, keys);
    }

    amxc_array_delete(&paths, NULL);
}

int mod_pcb_cli_cmd_gi(UNUSED const char* function_name,
                       amxc_var_t* args,
                       UNUSED amxc_var_t* ret) {
    amxc_var_t options;
    amxc_var_t data;
    char* input_path = NULL;
    amxb_bus_ctx_t* bus_ctx = NULL;
    int rv = 0;
    int depth = -1;
    amxt_tty_t* tty = ba_cli_get_tty();

    amxc_var_init(&options);
    amxc_var_init(&data);

    rv = mod_pcb_cli_cmd_parse(args, PCB_GI, NULL, &input_path, &options, NULL);
    when_failed(rv, exit);

    bus_ctx = mod_pcb_cli_get_bus_ctx(input_path);
    when_null(bus_ctx, exit);

    if(GET_BOOL(&options, "l") || GET_BOOL(&options, "first_lvl_only")) {
        depth = 0;
    }

    rv = amxb_get_instances(bus_ctx, input_path, depth, &data, 5);
    if(rv != amxd_status_ok) {
        amxt_tty_errorf(tty, "gi %s failed (%d - %s)\n",
                        input_path, rv, amxd_status_string((amxd_status_t) rv));
        goto exit;
    }

    if(!mod_pcb_cli_output_json(tty, &data)) {
        mod_pcb_cli_write_instances(&data);
    }

exit:
    amxc_var_clean(&options);
    amxc_var_clean(&data);
    free(input_path);
    return rv;
}
