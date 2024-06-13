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

#include "amx_cli.h"
#include "amx_cli_parser.h"

#include "amx_cli_eventloop.h"

static void amxt_cli_dbg(const amxt_tty_t* const tty, amxc_var_t* cmd_parts) {
    amxc_var_for_each(part, cmd_parts) {
        const char* p = amxc_var_constcast(cstring_t, part);
        amxt_tty_writef(tty, "${color.bg-red}${color.white}%s${color.reset} ", p);
    }
    amxt_tty_writef(tty, "\n");
}

static void amx_cli_call(const char* so,
                         const char* module,
                         const char* function,
                         amxc_var_t* args) {
    amxc_var_t ret;
    amxt_tty_t* tty = amxc_var_constcast(amxt_tty_t, GET_ARG(args, "tty"));
    amxp_signal_mngr_t* sigmngr = amxt_tty_sigmngr(tty);
    amxc_var_t* rv_var = amxt_tty_claim_config(tty, "rv");
    amxc_var_t* input = GET_ARG(args, "input");
    int cmd_rv = 0;
    amxc_var_init(&ret);

    cmd_rv = amxm_execute_function(so, module, function, args, &ret);
    amxc_var_set(int32_t, rv_var, cmd_rv);
    if(cmd_rv == 0) {
        if(amxc_var_type_of(&ret) != AMXC_VAR_ID_NULL) {
            amxc_var_dump(&ret, STDOUT_FILENO);
        }
        amxp_sigmngr_trigger_signal(sigmngr, "tty:cmd-done", input);
    }

    amxc_var_clean(&ret);
}

static void amx_cli_exec_alias(amxt_tty_t* tty, const char* alias, amxc_var_t* cmd_parts) {
    amxc_llist_t cmds;
    amxc_string_t str_alias;
    amxc_string_t args;

    amxc_string_init(&args, 0);
    amxc_string_init(&str_alias, 0);
    amxc_llist_init(&cmds);

    amxc_string_setf(&str_alias, "%s", alias);
    amxc_string_split_to_llist(&str_alias, &cmds, ';');
    amxc_string_join_var(&args, cmd_parts, "");

    amxc_llist_for_each(it, (&cmds)) {
        amxc_string_t* cmd = amxc_string_from_llist_it(it);
        if(amxc_llist_it_get_next(it) == NULL) {
            if(!amxc_string_is_empty(&args)) {
                amxc_string_appendf(cmd, " %s", amxc_string_get(&args, 0));
            }
        }
        amxt_tty_writef(tty, "> %s", amxc_string_get(cmd, 0));
        amxt_tty_trigger_cmd(tty, cmd, false);
    }

    amxc_llist_clean(&cmds, amxc_string_list_it_free);
    amxc_string_clean(&str_alias);
    amxc_string_clean(&args);
}

static void amx_cli_dispatch_cmd(amxc_var_t* cmd_data) {
    amxc_var_t* var_tty = GET_ARG(cmd_data, "tty");
    amxc_var_t* cmd_parts = GET_ARG(cmd_data, "cmd");
    amxt_tty_t* tty = amxc_var_constcast(amxt_tty_t, var_tty);

    char* part = NULL;
    char* mod = NULL;
    char* func = NULL;
    const char* so = NULL;

    amxt_cmd_triml(cmd_parts, ' ');
    part = amxc_cli_take_cmd(cmd_parts);
    when_null(part, exit);

    if(part[0] == '!') {
        so = "self";
        mod = strdup(part + 1);
        free(part);
        part = NULL;
        when_null(mod, exit);
    } else {
        const char* alias = amx_cli_get_alias(part);
        if(alias != NULL) {
            free(part);
            amx_cli_exec_alias(tty, alias, cmd_parts);
            part = NULL;
            goto exit;
        }
        so = amx_cli_get_shared_object();
        mod = part;
        part = NULL;
    }

    if(amxm_get_module(so, mod) == NULL) {
        amxt_cmd_prepend_part(cmd_parts, mod);
        free(mod);
        mod = amx_cli_get_module() == NULL ? NULL : strdup(amx_cli_get_module());
    }

    if(mod == NULL) {
        amxt_tty_writef(tty, "${color.red}Invalid command${color.reset}\n");
        goto exit;
    }

    amxt_cmd_triml(cmd_parts, ' ');
    func = amxt_cmd_pop_part(cmd_parts);
    if(!amxm_has_function(so, mod, func)) {
        amxt_cmd_prepend_part(cmd_parts, func);
        free(func);
        func = strdup("__execute");
    }

    if(amxm_has_function(so, mod, func)) {
        amxt_cmd_trim(cmd_parts, ' ');
        amx_cli_call(so, mod, func, cmd_data);
    } else {
        amxt_tty_writef(tty, "${color.red}Invalid command${color.reset}\n");
        goto exit;
    }

exit:
    free(func);
    free(mod);
    return;
}

void amx_cli_slot_new_line(UNUSED const char* const sig_name,
                           const amxc_var_t* const data,
                           UNUSED void* priv) {
    amxc_var_t* var_txt = GET_ARG(data, "text");
    amxc_var_t* var_tty = GET_ARG(data, "tty");
    char* txt = amxc_var_dyncast(cstring_t, var_txt);
    amxc_string_split_status_t status = AMXC_STRING_SPLIT_OK;
    const char* reason = NULL;

    size_t length = strlen(txt);
    amxt_tty_t* tty = amxc_var_constcast(amxt_tty_t, var_tty);
    bool dbg_info = GET_BOOL(&tty->config, "tty-dbg");

    amxc_var_t args;
    amxc_var_t* cmd_parts = NULL;

    amxc_var_init(&args);
    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);

    when_str_empty(txt, exit);
    if(txt[0] == '#') {
        if(txt[1] != 0) {
            amxt_tty_writef(tty, "${color.reset}%s${color.reset}\n", txt + 1);
        } else {
            amxt_tty_writef(tty, "\n");
        }
        goto exit;
    }

    cmd_parts = amxc_var_add_key(amxc_htable_t, &args, "cmd", NULL);
    amxc_var_add_key(amxt_tty_t, &args, "tty", tty);
    amxc_var_add_key(cstring_t, &args, "input", txt);
    status = amxt_cmd_parse_line(txt, length, cmd_parts, &reason);
    amxt_cmd_triml(cmd_parts, ' ');
    if(amxc_llist_is_empty(&cmd_parts->data.vl)) {
        goto exit;
    }

    if(status != AMXC_STRING_SPLIT_OK) {
        amxt_tty_errorf(tty, "%s\n", reason);
        goto exit;
    }

    if(dbg_info) {
        amxt_cli_dbg(tty, cmd_parts);
    }

    amx_cli_dispatch_cmd(&args);

exit:
    free(txt);
    amxc_var_clean(&args);
}
