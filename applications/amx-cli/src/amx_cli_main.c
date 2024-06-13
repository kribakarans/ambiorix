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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>

#include "amx_cli.h"
#include "amx_cli_eventloop.h"
#include "amx_cli_parser.h"
#include "amx_cli_prompt.h"
#include "amx_cli_ctrl.h"
#include "version.h"

const char* logo =
    "\n"
    "\n"
    "=============================================================================\n"
    "\n"
    "                A                                                            \n"
    "               AAA                                                           \n"
    "              A:::A                                                          \n"
    "             A:::::A                                                         \n"
    "            A:::::::A                                                        \n"
    "           A:::::::::A              mmmmmmm    mmmmmmm   xxxxxxx      xxxxxxx\n"
    "          A:::::A:::::A           mm:::::::m  m:::::::mm  x:::::x    x:::::x \n"
    "         A:::::A A:::::A         m::::::::::mm::::::::::m  x:::::x  x:::::x  \n"
    "        A:::::A   A:::::A        m::::::::::::::::::::::m   x:::::xx:::::x   \n"
    "       A:::::A     A:::::A       m:::::mmm::::::mmm:::::m    x::::::::::x    \n"
    "      A:::::AAAAAAAAA:::::A      m::::m   m::::m   m::::m     x::::::::x     \n"
    "     A:::::::::::::::::::::A     m::::m   m::::m   m::::m     x::::::::x     \n"
    "    A:::::AAAAAAAAAAAAA:::::A    m::::m   m::::m   m::::m    x::::::::::x    \n"
    "   A:::::A             A:::::A   m::::m   m::::m   m::::m   x:::::xx:::::x   \n"
    "  A:::::A               A:::::A  m::::m   m::::m   m::::m  x:::::x  x:::::x  \n"
    " A:::::A                 A:::::A m::::m   m::::m   m::::m x:::::x    x:::::x \n"
    "AAAAAAA                   AAAAAAAmmmmmm   mmmmmm   mmmmmmxxxxxxx      xxxxxxx\n"
    "\n"
    "=============================================================================\n"
    "\n"
    "\n";

static amxc_var_t* amx_cli_read_config(const char* name) {
    int read_length = 0;
    amxc_string_t file_name;
    int fd = -1;
    amxc_var_t* var = NULL;
    variant_json_t* reader = NULL;
    char* prefix = getenv("AMX_PREFIX");

    amxc_string_init(&file_name, 0);
    if(prefix == NULL) {
        amxc_string_setf(&file_name, "/etc/amx/cli/%s.conf", name);
    } else {
        amxc_string_setf(&file_name, "%s/etc/amx/cli/%s.conf", prefix, name);
    }

    fd = open(amxc_string_get(&file_name, 0), O_RDONLY);
    if(fd == -1) {
        goto exit;
    }

    amxj_reader_new(&reader);

    read_length = amxj_read(reader, fd);
    while(read_length > 0) {
        read_length = amxj_read(reader, fd);
    }

    var = amxj_reader_result(reader);
    amxj_reader_delete(&reader);
    close(fd);

exit:
    amxc_string_clean(&file_name);
    return var;
}

static void amx_cli_move(amxc_var_t* dest, amxc_var_t* source) {
    if(amxc_var_type_of(source) != AMXC_VAR_ID_HTABLE) {
        goto exit;
    }
    amxc_htable_for_each(it, (&source->data.vm)) {
        amxc_var_t* sv = amxc_var_from_htable_it(it);
        const char* key = amxc_htable_it_get_key(it);
        amxc_var_set_key(dest, key, sv, AMXC_VAR_FLAG_DEFAULT);
    }

exit:
    return;
}

static void amx_cli_print_init(amxt_tty_t* tty, amxc_var_t* config) {
    const char* start = "2020";
    char current[64];
    amxc_ts_t now;

    amxc_ts_now(&now);
    amxc_ts_format(&now, current, 64);
    current[4] = 0;

    if(!GET_BOOL(config, "no-logo")) {
        amxt_tty_writef(tty, "%s", logo);
    }
    if(strncmp(start, current, 4) == 0) {
        amxt_tty_writef(tty, "Copyright (c) %s SoftAtHome\n", start);
    } else {
        amxt_tty_writef(tty, "Copyright (c) %s - %s SoftAtHome\n", start, current);
    }
    amxt_tty_writef(tty, "${color.green}amxcli version : ${color.reset}");
    amxt_tty_writef(tty, "%d.%d.%d\n\n", VERSION_MAJOR, VERSION_MINOR, VERSION_BUILD);
}

static void amx_cli_configure_module(amxm_module_t* mod, amxc_var_t* conf) {
    const amxc_htable_t* tmod_conf = amxc_var_constcast(amxc_htable_t, conf);
    if(mod == NULL) {
        goto exit;
    }
    amxc_htable_for_each(it, tmod_conf) {
        const char* key = amxc_htable_it_get_key(it);
        amxc_var_t* val = amxc_var_from_htable_it(it);
        if(strncmp(key, "no-", 3) != 0) {
            continue;
        }
        if(amxc_var_dyncast(bool, val)) {
            amxm_module_remove_function(mod, key + 3);
        }
    }

exit:
    return;
}

int amx_cli_init(cli_app_t* cli, const char* name, bool silent) {
    int retval = 0;
    amxc_var_t* config_var = NULL;
    bool automated = GET_BOOL(amxt_tty_get_config(cli->tty, "automated"), NULL);

    config_var = amx_cli_read_config(name);
    amx_cli_move(&cli->tty->config, config_var);
    amxc_var_delete(&config_var);
    config_var = &cli->tty->config;
    amxc_var_add_key(int32_t, config_var, "rv", 0);

    amxp_sigmngr_add_signal(cli->tty->sigmngr, "tty:docomplete");

    if(GET_BOOL(config_var, "no-colors") || silent || automated) {
        amxc_var_t* color = GET_ARG(config_var, "color");
        amxc_var_delete(&color);
    }
    if(!silent && !automated) {
        amx_cli_print_init(cli->tty, &cli->tty->config);
    }

    amxc_var_init(&cli->aliases);
    amxc_var_set_type(&cli->aliases, AMXC_VAR_ID_HTABLE);

    cli->shared_object = NULL;
    cli->module = NULL;

    amxp_slot_connect(amxt_tty_sigmngr(cli->tty), "tty:newline",
                      NULL, amx_cli_slot_new_line, NULL);
    amxp_slot_connect(amxt_tty_sigmngr(cli->tty), "tty:complete",
                      NULL, amx_cli_slot_complete, NULL);
    amxp_slot_connect(amxt_tty_sigmngr(cli->tty), "tty:docomplete",
                      NULL, amx_cli_slot_docomplete, cli->tty);

    amxt_tty_set_ctrl_key_cb(amxt_key_eof, amxt_ctrl_key_eof);

    return retval;
}

void amx_cli_clean(cli_app_t* cli) {
    if(cli->tty != NULL) {
        cli->tty->priv = NULL;
    }
    amxc_var_clean(&cli->aliases);
    amxt_log_close(cli->tty);
    if((cli->tty != NULL) && cli->tty->interactive) {
        amxt_tty_hide_prompt(cli->tty);
        amxt_tty_writef(cli->tty, "\n${color.reset}");
    }
    amxt_tty_close(&cli->tty);
    free(cli->shared_object);
    free(cli->module);
}

void amx_cli_run_script(cli_app_t* cli,
                        bool silent) {
    int open_flags = O_RDONLY;
    const char* file_name = GET_CHAR(amxt_tty_get_config(cli->tty, "init-script"), NULL);
    int fd = -1;
    char buf[1];
    amxt_il_t* il = amxt_tty_il(cli->tty);
    bool tty_silent = cli->tty->silent;

    fd = open(file_name, open_flags);

    if(fd == -1) {
        amxt_tty_show_prompt(cli->tty);
        goto exit;
    }

    while(read(fd, buf, 1) > 0) {
        if(buf[0] == '\n') {
            const char* line = amxt_il_text(il, amxt_il_no_flags, 0);
            size_t len = amxt_il_text_length(il, amxt_il_no_flags, 0);
            if(len == 0) {
                continue;
            }
            if(!silent && tty_silent) {
                if((line != NULL) && (line[0] == '#')) {
                    amxt_tty_silent(cli->tty, false);
                    amxt_tty_write(cli->tty, line + 1, len - 1);
                    amxt_tty_write(cli->tty, "\n", 1);
                    amxt_tty_silent(cli->tty, true);
                }
            } else {
                amxt_tty_write_raw(cli->tty, line, len);
            }
            amxt_ctrl_key_new_line(cli->tty, amxt_key_newline);
            if((tty_silent != cli->tty->silent) && cli->tty->silent) {
                amxt_tty_silent(cli->tty, false);
                amxt_tty_write_raw(cli->tty, "\n", 1);
                amxt_tty_silent(cli->tty, true);
            }
            tty_silent = cli->tty->silent;
        } else {
            amxt_il_insert_block(il, buf, 1);
        }
    }

exit:
    return;
}

void amx_cli_configure_self_modules(cli_app_t* cli) {
    amxc_var_t* config_var = &cli->tty->config;
    amxc_var_t* self = GET_ARG(config_var, "self");
    const amxc_htable_t* tself = amxc_var_constcast(amxc_htable_t, self);
    amxm_shared_object_t* so = amxm_get_so("self");

    if(GET_BOOL(config_var, "no-self")) {
        amxm_close_so("self");
        goto exit;
    }

    amxc_htable_for_each(it, tself) {
        const char* key = amxc_htable_it_get_key(it);
        amxc_var_t* val = amxc_var_from_htable_it(it);
        amxm_module_t* mod = NULL;
        if(strncmp(key, "no-mod-", 7) == 0) {
            mod = amxm_so_get_module(so, key + 7);
            if(mod && amxc_var_dyncast(bool, val)) {
                amxm_module_deregister(&mod);
            }
        } else if(strncmp(key, "mod-", 4) == 0) {
            mod = amxm_so_get_module(so, key + 4);
            amx_cli_configure_module(mod, val);
        }
    }

    if(GET_BOOL(config_var, "no-self-config")) {
        amxc_var_t* var = GET_ARG(config_var, "no-self-config");
        amxc_var_delete(&var);
        var = GET_ARG(config_var, "no-self");
        amxc_var_delete(&var);
        amxc_var_delete(&self);
    }

exit:
    return;
}

char* amxc_cli_take_cmd(amxc_var_t* cmd_parts) {
    amxc_string_t helper;
    char* part = NULL;
    amxc_string_init(&helper, 32);

    do {
        free(part);
        part = amxt_cmd_pop_part(cmd_parts);
        if(part != NULL) {
            if(part[0] == 0) {
                amxt_cmd_prepend_part(cmd_parts, " ");
                break;
            }
            if((strlen(part) == 1) && (ispunct(part[0]) != 0)) {
                if((part[0] != '-') && (part[0] != '_')) {
                    if(amxc_string_is_empty(&helper)) {
                        amxc_string_appendf(&helper, "%s", part);
                    } else {
                        amxt_cmd_prepend_part(cmd_parts, part);
                    }
                    break;
                }
            }
            amxc_string_appendf(&helper, "%s", part);
        }
    } while(part != NULL);
    free(part);

    if(amxc_string_is_empty(&helper)) {
        part = NULL;
    } else {
        part = amxc_string_take_buffer(&helper);
    }

    amxc_string_clean(&helper);
    return part;
}