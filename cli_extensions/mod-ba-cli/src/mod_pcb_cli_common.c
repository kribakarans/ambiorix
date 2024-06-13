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

static uint32_t mod_pcb_cli_get_cmd_index(const char* cmd) {
    uint32_t index = 0;
    amxt_cmd_help_t* cmds = mod_pcb_cli_get_help(0);

    for(index = 0; index <= PCB_SUBSCRIBE; index++) {
        if(strcmp(cmds[index].cmd, cmd) == 0) {
            break;
        }
    }

    return index;
}

static bool mod_pcb_cli_event_allowed(amxc_var_t* data, const char* path) {
    amxc_var_t* acls = NULL;
    char* file = mod_pcb_cli_get_acl_file();
    bool allowed = false;
    amxb_bus_ctx_t* bus_ctx = mod_pcb_cli_get_bus_ctx(NULL);

    if(!mod_pcb_cli_acl_enabled()) {
        allowed = true;
        goto exit;
    }

    when_str_empty(file, exit);

    acls = amxa_parse_files(file);
    when_null(acls, exit);
    amxa_resolve_search_paths(bus_ctx, acls, path);

    amxa_filter_notif(data, acls);

    allowed = !GET_BOOL(data, "filter-all");

exit:
    free(file);
    amxc_var_delete(&acls);
    return allowed;
}

amxb_bus_ctx_t* mod_pcb_cli_get_bus_ctx(const char* input_path) {
    char* fixed_part = NULL;
    amxb_bus_ctx_t* bus_ctx = NULL;
    amxd_path_t path;
    amxt_tty_t* tty = ba_cli_get_tty();
    amxc_var_t* connection = amxt_tty_get_config(tty, "connection");
    const char* con_name = amxc_var_constcast(cstring_t, connection);

    if((con_name != NULL) && (strcmp(con_name, "*") != 0)) {
        bus_ctx = amxb_find_uri(con_name);
        if(bus_ctx != NULL) {
            goto exit;
        }
        amxc_var_set(cstring_t, connection, "*");
    }

    if((input_path != NULL) && (*input_path != 0)) {
        amxd_path_init(&path, input_path);
        fixed_part = amxd_path_get_fixed_part(&path, false);

        bus_ctx = amxb_be_who_has(fixed_part);

        amxd_path_clean(&path);
        free(fixed_part);
    }

exit:
    return bus_ctx;
}

const char* mod_pcb_cli_human_type_name(uint32_t type_id) {
    const char* type_names[] = {
        "void", "string", "int8", "int16", "int32",
        "int64", "uint8", "uint16", "uint32", "uint64",
        "float", "double", "bool", "list", "table",
        "fd", "datetime", "string", "string", "any"
    };

    if(type_id > AMXC_VAR_ID_ANY) {
        const char* name = amxc_var_get_type_name_from_id(type_id);
        if(name == NULL) {
            return "unknown";
        }
        return name;
    } else {
        return type_names[type_id];
    }
}

amxc_var_t* mod_pcb_cli_search(amxc_var_t* args, const char* needle) {
    amxc_var_t* ret = NULL;
    amxc_var_for_each(arg, args) {
        const char* str_arg = amxc_var_constcast(cstring_t, arg);
        if(strcmp(str_arg, needle) == 0) {
            ret = arg;
            break;
        }
    }

    return ret;
}

void mod_pcb_cli_event_cb(UNUSED const char* const spath,
                          const amxc_var_t* const data,
                          UNUSED void* const priv) {
    amxt_tty_t* tty = ba_cli_get_tty();
    amxt_il_t* il = amxt_tty_il(tty);
    amxc_var_t* raw_event = amxt_tty_claim_config(tty, "raw-event");
    const char* txt = amxt_il_text(il, amxt_il_no_flags, 0);
    size_t len = amxt_il_text_length(il, amxt_il_no_flags, 0);
    amxc_var_t filtered_data;
    amxc_ts_t ts;
    char buf[32];

    const char* path = GET_CHAR(data, "path");
    const char* event = GET_CHAR(data, "notification");

    amxc_var_init(&filtered_data);
    amxc_var_copy(&filtered_data, data);

    if(!mod_pcb_cli_event_allowed(&filtered_data, path)) {
        goto exit;
    }

    amxt_tty_hide_prompt(tty);
    amxt_tty_writef(tty, "${color.reset}\n");

    amxc_ts_now(&ts);
    amxc_ts_format_precision(&ts, buf, 31, 0);
    amxt_tty_writef(tty, "[%s] Event %s received from %s\n", buf, event, path);

    if(amxc_var_dyncast(bool, raw_event)) {
        amxc_var_dump(&filtered_data, STDOUT_FILENO);
    } else {
        mod_pcb_cli_output_event(tty, &filtered_data);
    }
    amxt_tty_show_prompt(tty);
    amxt_tty_write_raw(tty, txt, len);
exit:
    amxc_var_clean(&filtered_data);
    return;
}

int mod_pcb_cli_cmd_complete_common(const char* function_name,
                                    amxc_var_t* args,
                                    amxc_var_t* ret) {
    uint32_t index = mod_pcb_cli_get_cmd_index(function_name + 11);
    pcb_cli_cmd_flags_t* opts = mod_pcb_cli_get_cmd_flags(index);
    amxt_cmd_help_t* help = mod_pcb_cli_get_help(index);
    uint32_t flags = AMXB_FLAG_OBJECTS | AMXB_FLAG_INSTANCES | AMXB_FLAG_FIRST_LVL;

    flags |= (opts->cmd_flags & CMD_FUNC_PATH) != 0 ? AMXB_FLAG_FUNCTIONS : 0;
    if(index != PCB_INVOKE) {
        flags |= (opts->cmd_flags & CMD_PARAM_PATH) != 0 ? AMXB_FLAG_PARAMETERS : 0;
    }
    mod_pcb_cli_cmd_complete(args, flags, help->options, ret);

    return 0;
}

char* mod_pcb_cli_get_acl_file(void) {
    char* file = NULL;
    amxt_tty_t* tty = ba_cli_get_tty();
    amxc_string_t acl_file;
    amxc_var_t* role = amxt_tty_get_config(tty, "role");
    amxc_var_t* acl_dir = amxt_tty_get_config(tty, "acl-dir");

    amxc_string_init(&acl_file, 0);
    if(role != NULL) {
        amxc_string_setf(&acl_file, "%s/merged/%s.json", GET_CHAR(acl_dir, NULL),
                         GET_CHAR(role, NULL));
        file = amxc_string_take_buffer(&acl_file);
    }

    amxc_string_clean(&acl_file);
    return file;
}

bool mod_pcb_cli_acl_enabled(void) {
    amxt_tty_t* tty = ba_cli_get_tty();
    amxc_var_t* acl_enabled = amxt_tty_get_config(tty, "acl-enabled");
    return amxc_var_constcast(bool, acl_enabled);
}

bool mod_pcb_cli_verify_params(amxb_bus_ctx_t* ctx,
                               amxc_var_t* acls,
                               const char* obj_path,
                               amxc_var_t* params) {
    bool allowed = false;
    amxc_var_for_each(var, params) {
        const char* param = amxc_var_key(var);
        allowed = amxa_is_set_allowed(ctx, acls, obj_path, param);
        if(!allowed) {
            goto exit;
        }
    }

exit:
    return allowed;
}
