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

static void mod_pcb_cli_dump(amxt_tty_t* tty,
                             const char* key,
                             amxc_var_t* data) {
    const amxc_htable_t* params = NULL;
    amxc_array_t* names = NULL;
    size_t count = 0;
    amxc_string_t escaped;
    bool less = GET_BOOL(amxt_tty_get_config(tty, "less"), NULL);

    amxc_string_init(&escaped, 0);
    params = amxc_var_constcast(amxc_htable_t, data);
    names = amxc_htable_get_sorted_keys(params);
    count = amxc_array_size(names);

    for(size_t i = 0; i < count; i++) {
        const char* name = (const char*) amxc_array_get_data_at(names, i);
        amxc_var_t* param = amxc_var_from_htable_it(amxc_htable_get(params, name));
        if(name[0] == '%') {
            continue;
        }
        if(amxc_var_type_of(param) == AMXC_VAR_ID_HTABLE) {
            uint32_t code = GET_UINT32(param, "error_code");
            amxt_tty_errorf(tty, "%s%s (%d - %s)\n",
                            key, name, code, amxd_status_string((amxd_status_t) code));
        } else if(amxc_var_type_of(param) == AMXC_VAR_ID_CSTRING) {
            const char* value = amxc_var_constcast(cstring_t, param);
            amxc_string_setf(&escaped, "%s", value);
            amxc_string_esc(&escaped);
            if(less) {
                amxt_tty_writef(tty, "%s\n", amxc_string_get(&escaped, 0));
            } else {
                amxt_tty_writef(tty, "${color.green}%s${color.reset}%s=\"%s\"\n",
                                key, name, amxc_string_get(&escaped, 0));
            }
        } else {
            char* value = amxc_var_dyncast(cstring_t, param);
            if(less) {
                amxt_tty_writef(tty, "%s\n", value);
            } else {
                amxt_tty_writef(tty, "${color.green}%s${color.reset}%s=%s\n", key, name, value);
            }
            free(value);
        }
    }

    amxc_string_clean(&escaped);
    amxc_array_delete(&names, NULL);
}

bool mod_pcb_cli_output_json(amxt_tty_t* tty, amxc_var_t* data) {
    bool rv = false;
    amxc_var_t* output_fmt = amxt_tty_get_config(tty, "output-format");

    if(output_fmt != NULL) {
        const char* fmt = GET_CHAR(output_fmt, NULL);
        if((fmt != NULL) && (strcmp(fmt, "json") == 0)) {
            const char* txt = NULL;
            amxc_var_cast(data, AMXC_VAR_ID_JSON);
            txt = amxc_var_constcast(jstring_t, data);
            amxt_tty_write_raw(tty, txt, strlen(txt));
            amxt_tty_write_raw(tty, "\n", 1);
            rv = true;
        }
    }

    return rv;
}

void mod_pcb_cli_output_flat(amxt_tty_t* tty, amxc_var_t* data, bool params_only) {
    const amxc_htable_t* table = NULL;
    amxc_array_t* keys = NULL;
    size_t count = 0;
    amxc_var_t* d = NULL;
    bool less = GET_BOOL(amxt_tty_get_config(tty, "less"), NULL);

    when_true(mod_pcb_cli_output_json(tty, data), exit);

    if(amxc_var_type_of(data) == AMXC_VAR_ID_LIST) {
        d = GETI_ARG(data, 0);
    } else {
        d = data;
    }

    table = amxc_var_constcast(amxc_htable_t, d);
    keys = amxc_htable_get_sorted_keys(table);
    count = amxc_array_size(keys);
    if(count == 0) {
        if(!less) {
            amxt_tty_writef(tty, "${color.red}No data found${color.reset}\n");
        }
    } else {
        for(size_t i = 0; i < count; i++) {
            const char* key = (const char*) amxc_array_get_data_at(keys, i);
            amxc_var_t* value = GET_ARG(d, key);
            if(!params_only && !less) {
                amxt_tty_writef(tty, "${color.green}%s${color.reset}\n", key);
            }
            mod_pcb_cli_dump(tty, key, value);
        }
    }

    amxc_array_delete(&keys, NULL);

exit:
    return;
}

void mod_pcb_cli_output_list(amxt_tty_t* tty, amxc_var_t* data) {
    const amxc_llist_t* list = NULL;

    when_true(mod_pcb_cli_output_json(tty, data), exit);

    list = amxc_var_constcast(amxc_llist_t, data);
    amxc_llist_for_each(it, list) {
        amxc_var_t* value = amxc_var_from_llist_it(it);
        const char* txt = amxc_var_constcast(cstring_t, value);
        amxt_tty_writef(tty, "${color.green}%s${color.reset}\n", txt);
    }

exit:
    return;
}

void mod_pcb_cli_output_changed_event(amxt_tty_t* tty, const amxc_var_t* data) {
    const char* event = GET_CHAR(data, "notification");
    const char* path = GET_CHAR(data, "path");
    amxc_var_t* params = GET_ARG(data, "parameters");
    const amxc_htable_t* tparams = amxc_var_constcast(amxc_htable_t, params);

    amxc_htable_for_each(hit, tparams) {
        const char* param = amxc_htable_it_get_key(hit);
        amxc_var_t* val = amxc_var_from_htable_it(hit);
        char* from = amxc_var_dyncast(cstring_t, GET_ARG(val, "from"));
        char* to = amxc_var_dyncast(cstring_t, GET_ARG(val, "to"));
        amxt_tty_writef(tty,
                        "<${color.blue}%19.19s${color.reset}> "
                        "${color.green}%s${color.reset}%s = "
                        "${color.red}%s${color.reset} -> "
                        "${color.green}%s${color.reset}\n",
                        event, path, param, from, to);
        event = "";
        free(from);
        free(to);
    }
}

void mod_pcb_cli_output_pi_event(amxt_tty_t* tty, const amxc_var_t* data) {
    const char* event = GET_CHAR(data, "notification");
    const char* path = GET_CHAR(data, "path");
    amxc_var_t* params = GET_ARG(data, "parameters");
    const amxc_htable_t* tparams = amxc_var_constcast(amxc_htable_t, params);

    amxc_htable_for_each(hit, tparams) {
        const char* param = amxc_htable_it_get_key(hit);
        amxc_var_t* val = amxc_var_from_htable_it(hit);
        char* txt = amxc_var_dyncast(cstring_t, val);
        amxt_tty_writef(tty,
                        "<${color.blue}%19.19s${color.reset}> "
                        "${color.green}%s${color.reset}%s = %s\n",
                        event, path, param, txt);
        event = "";
        free(txt);
    }
}

void mod_pcb_cli_output_instance_add_event(amxt_tty_t* tty, const amxc_var_t* data) {
    const char* event = GET_CHAR(data, "notification");
    const char* path = GET_CHAR(data, "path");
    uint32_t index = amxc_var_dyncast(uint32_t, GET_ARG(data, "index"));
    amxc_var_t* params = GET_ARG(data, "parameters");
    const amxc_htable_t* tparams = amxc_var_constcast(amxc_htable_t, params);

    amxc_htable_for_each(hit, tparams) {
        const char* param = amxc_htable_it_get_key(hit);
        amxc_var_t* val = amxc_var_from_htable_it(hit);
        char* txt = amxc_var_dyncast(cstring_t, val);
        amxt_tty_writef(tty,
                        "<${color.blue}%19.19s${color.reset}> "
                        "${color.green}%s${color.blue}%d.${color.reset}%s = %s\n",
                        event, path, index, param, txt);
        event = "";
        free(txt);
    }
}

void mod_pcb_cli_output_instance_del_event(amxt_tty_t* tty, const amxc_var_t* data) {
    const char* event = GET_CHAR(data, "notification");
    const char* path = GET_CHAR(data, "path");
    uint32_t index = amxc_var_dyncast(uint32_t, GET_ARG(data, "index"));

    amxt_tty_writef(tty,
                    "<${color.blue}%19.19s${color.reset}> "
                    "${color.red}%s%d.${color.reset}\n",
                    event, path, index);
}

void mod_pcb_cli_output_add_event(amxt_tty_t* tty, const amxc_var_t* data) {
    const char* event = GET_CHAR(data, "notification");
    const char* path = GET_CHAR(data, "path");

    amxt_tty_writef(tty,
                    "<${color.blue}%19.19s${color.reset}> "
                    "${color.green}%s${color.reset}\n", event, path);
}

void mod_pcb_cli_output_del_event(amxt_tty_t* tty, const amxc_var_t* data) {
    const char* event = GET_CHAR(data, "notification");
    const char* path = GET_CHAR(data, "path");

    amxt_tty_writef(tty,
                    "<${color.blue}%19.19s${color.reset}> "
                    "${color.red}%s${color.reset}\n", event, path);
}

void mod_pcb_cli_output_event(amxt_tty_t* tty, const amxc_var_t* data) {
    const char* event = GET_CHAR(data, "notification");
    if(strcmp(event, "dm:object-changed") == 0) {
        mod_pcb_cli_output_changed_event(tty, data);
    } else if(strcmp(event, "dm:instance-added") == 0) {
        mod_pcb_cli_output_instance_add_event(tty, data);
    } else if(strcmp(event, "dm:instance-removed") == 0) {
        mod_pcb_cli_output_instance_del_event(tty, data);
    } else if(strcmp(event, "dm:object-added") == 0) {
        mod_pcb_cli_output_add_event(tty, data);
    } else if(strcmp(event, "dm:object-removed") == 0) {
        mod_pcb_cli_output_del_event(tty, data);
    } else if(strcmp(event, "dm:periodic-inform") == 0) {
        mod_pcb_cli_output_pi_event(tty, data);
    } else {
        amxc_var_dump(data, STDOUT_FILENO);
    }
}