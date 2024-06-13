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
#include <ctype.h>

#include "ba_cli_priv.h"

#include "mod_pcb_cli_cmd.h"
#include "mod_pcb_cli_common.h"

static int mod_pcb_cli_path_validation(const char* input_path,
                                       uint32_t cmd_flags) {
    int retval = -1;
    amxd_path_t path;
    amxt_tty_t* tty = ba_cli_get_tty();
    bool allow_search_path = (cmd_flags & CMD_SEARCH_PATH) != 0;
    bool allow_param_func = (cmd_flags & (CMD_PARAM_PATH | CMD_FUNC_PATH)) != 0;

    amxd_path_init(&path, input_path);
    if((input_path == NULL) || (*input_path == 0)) {
        if((cmd_flags & CMD_EMPTY_PATH) != 0) {
            retval = 0;
        }
        goto exit;
    }

    if(amxd_path_is_search_path(&path) && !allow_search_path) {
        amxt_tty_errorf(tty,
                        "Invalid path [%s] - search path not allowed\n",
                        input_path);
        goto exit;
    }
    if(amxd_path_get_param(&path) && !allow_param_func) {
        amxt_tty_errorf(tty,
                        "Invalid path [%s] - parameter/function path not allowed\n",
                        input_path);
        goto exit;
    }

    retval = 0;

exit:
    amxd_path_clean(&path);
    return retval;
}

char* mod_pcb_cli_build_path(amxc_var_t* args) {
    amxc_string_t path;
    char* part = NULL;
    bool absolute = false;
    int braces = 0;
    amxt_tty_t* tty = ba_cli_get_tty();
    amxc_var_t* cur_path = amxt_tty_get_config(tty, "path");
    const char* str_cur_path = amxc_var_constcast(cstring_t, cur_path);
    amxc_string_init(&path, 64);

    part = amxt_cmd_pop_part(args);
    while(part != NULL) {
        if(part[0] == 0) {
            if(braces == 0) {
                free(part);
                break;
            } else {
                amxc_string_appendf(&path, " ");
            }
        }
        if((part[1] == 0) && (ispunct(part[0]) != 0)) {
            if(part[0] == '[') {
                braces++;
            } else if(part[0] == ']') {
                braces--;
            } else if(braces == 0) {
                if((part[0] == '=') || (part[0] == '?') ||
                   ( part[0] == '(') || ( part[0] == '{')) {
                    amxt_cmd_prepend_part(args, part);
                    free(part);
                    break;
                }
                if(part[0] == '+') {
                    char* next_part = amxt_cmd_pop_part(args);
                    amxt_cmd_prepend_part(args, next_part);
                    if((next_part == NULL) || (next_part[0] != '.')) {
                        amxt_cmd_prepend_part(args, part);
                        free(next_part);
                        free(part);
                        break;
                    }
                    free(next_part);
                }
                if((part[0] == '-') && amxt_cmd_is_empty(args)) {
                    amxt_cmd_prepend_part(args, part);
                    free(part);
                    break;
                }
            }
        }
        if(amxc_string_is_empty(&path) && (part[0] == '.')) {
            absolute = true;
        } else {
            amxc_string_appendf(&path, "%s", part);
        }
        free(part);
        part = amxt_cmd_pop_part(args);
    }

    if((str_cur_path != NULL) && !absolute) {
        amxc_string_prependf(&path, "%s", str_cur_path);
    }
    part = amxc_string_take_buffer(&path);

    amxc_string_clean(&path);
    return part;
}

int mod_pcb_cli_cmd_parse(amxc_var_t* args,
                          uint32_t cmd_index,
                          amxb_bus_ctx_t** bus_ctx,
                          char** input_path,
                          amxc_var_t* cmd_opts,
                          amxc_var_t* values) {
    int rv = 0;
    amxt_tty_t* tty = GET_TTY(args);
    amxc_var_t* cmd = GET_ARG(args, "cmd");
    pcb_cli_cmd_flags_t* opt = mod_pcb_cli_get_cmd_flags(cmd_index);
    amxt_cmd_help_t* help = mod_pcb_cli_get_help(cmd_index);

    if(cmd_opts != NULL) {
        rv = amxt_cmd_parse_options(tty, cmd, cmd_opts, help->options);
        when_failed(rv, exit);
    }

    *input_path = mod_pcb_cli_build_path(cmd);

    rv = mod_pcb_cli_path_validation(*input_path, opt->cmd_flags);
    when_failed(rv, exit);

    if(values != NULL) {
        rv = amxt_cmd_parse_values(tty, cmd, opt->value_flags, values);
        when_failed(rv, exit);
    }

    if(((opt->cmd_flags & CMD_MORE) == 0) && !amxt_cmd_is_empty(cmd)) {
        amxt_cmd_error_excess(tty, cmd, help->usage);
        rv = -1;
        goto exit;
    }

    if(bus_ctx != NULL) {
        *bus_ctx = mod_pcb_cli_get_bus_ctx(*input_path);
        if(*bus_ctx == NULL) {
            rv = -1;
            amxt_tty_errorf(tty, "%s not found\n", *input_path);
            goto exit;
        }
    }

exit:
    return rv;
}
