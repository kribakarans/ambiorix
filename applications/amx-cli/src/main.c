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

#include "amx_cli.h"
#include "amx_cli_eventloop.h"
#include "amx_cli_parser.h"
#include "amx_cli_prompt.h"
#include "amx_cli_history.h"

static cli_app_t cli;

static void amx_cli_read_line(UNUSED const amxc_var_t* const data,
                              UNUSED void* const priv) {
    amxt_il_t* il = amxt_tty_il(cli.tty);
    bool automated = GET_BOOL(amxt_tty_get_config(cli.tty, "automated"), NULL);

    char ch = 0;
    ssize_t size = 0;
    fcntl(STDIN_FILENO, F_SETFL, fcntl(STDIN_FILENO, F_GETFL) | O_NONBLOCK);

    amxt_il_reset(il);
    size = read(STDIN_FILENO, &ch, 1);
    while(size > 0) {
        if(ch == '\n') {
            if(automated) {
                amxt_tty_writef(cli.tty, "> %s", amxc_string_get(&il->buffer, 0));
            }
            amxt_tty_trigger_cmd(cli.tty, &il->buffer, false);
            amxt_il_reset(il);
            while(amxp_signal_read() == 0) {
            }
            amxt_tty_show_prompt(cli.tty);
        } else {
            if(!automated) {
                amxt_tty_write(cli.tty, &ch, 1);
            }
            amxt_il_insert_block(il, &ch, 1);
        }
        size = read(STDIN_FILENO, &ch, 1);
    }

    if(automated) {
        amxt_il_reset(il);
        amxt_il_insert_block(il, "!amx exit", 9);
        amxt_tty_trigger_cmd(cli.tty, &il->buffer, false);
        while(amxp_signal_read() == 0) {
        }
    }
}

static void amx_cli_run(amxc_string_t* cmd) {
    amxc_llist_t cmds;
    bool less = GET_BOOL(amxt_tty_get_config(cli.tty, "less"), NULL);
    amxc_llist_init(&cmds);

    amxc_string_split_to_llist(cmd, &cmds, ';');
    amxc_llist_for_each(it, &cmds) {
        amxc_string_t* c = amxc_container_of(it, amxc_string_t, it);
        if(!cli.tty->silent && !less) {
            amxt_tty_writef(cli.tty, "> %s", amxc_string_get(c, 0));
        }

        amxt_tty_trigger_cmd(cli.tty, c, false);
    }

    amxc_llist_clean(&cmds, amxc_string_list_it_free);
    fflush(stdout);
}

static void amx_cli_execute(int start, int argc, char* argv[]) {
    amxc_string_t cmd;
    const char* sep = "";

    amxc_string_init(&cmd, 0);

    for(int i = start; i < argc; i++) {
        amxc_string_appendf(&cmd, "%s%s", sep, argv[i]);
        sep = " ";
    }

    amx_cli_run(&cmd);
    amxc_string_clean(&cmd);
}

static void amx_cli_build_file_name(char* name) {
    amxc_string_t file_name;
    amxc_var_t* script = NULL;

    amxc_string_init(&file_name, 0);
    amxc_string_setf(&file_name, "/etc/amx/cli/%s.init", name);

    script = amxt_tty_claim_config(cli.tty, "init-script");
    amxc_var_push(cstring_t, script, amxc_string_take_buffer(&file_name));

    amxc_string_clean(&file_name);
}

static void amx_cli_stop_all(void) {
    const amxc_llist_t* shared_objects = amxm_get_so_list();
    amxc_var_t args;
    amxc_var_t ret;

    amxc_var_init(&args);
    amxc_var_init(&ret);

    amxc_llist_for_each_reverse(it, shared_objects) {
        amxm_shared_object_t* so = amxc_container_of(it, amxm_shared_object_t, it);
        amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
        amxc_var_add_key(amxt_tty_t, &args, "tty", cli.tty);
        amxm_so_execute_function(so, "__shared_object", "exit", &args, &ret);
    }

    amxc_var_clean(&args);
    amxc_var_clean(&ret);
}

const char* amx_cli_get_shared_object(void) {
    return cli.shared_object;
}

const char* amx_cli_get_module(void) {
    return cli.module;
}

amxc_var_t* amx_cli_get_aliases(void) {
    return &cli.aliases;
}

amxt_tty_t* amx_cli_get_tty(void) {
    return cli.tty;
}

const char* amx_cli_get_alias(const char* alias) {
    amxc_var_t* var_alias = amxc_var_get_key(&cli.aliases, alias, AMXC_VAR_FLAG_DEFAULT);
    return amxc_var_constcast(cstring_t, var_alias);
}

void amx_cli_set_shared_object(const char* name) {
    free(cli.shared_object);
    cli.shared_object = name == NULL ? NULL : strdup(name);
    amx_cli_update_prompt(cli.tty);
}

void amx_cli_set_module(const char* name) {
    free(cli.module);
    cli.module = name == NULL ? NULL : strdup(name);
    amx_cli_update_prompt(cli.tty);
}

void amx_cli_set_alias(const char* alias, const char* cmd) {
    amxc_var_t* var_alias = amxc_var_get_key(&cli.aliases, alias, AMXC_VAR_FLAG_DEFAULT);
    if(var_alias == NULL) {
        amxc_var_add_key(cstring_t, &cli.aliases, alias, cmd);
    } else {
        amxc_var_set(cstring_t, var_alias, cmd);
    }
}

int main(int argc, char* argv[]) {
    int retval = 0;
    int start = 1;
    bool automated = false;
    amxc_string_t cmds;

    amxc_string_init(&cmds, 0);

    if(amxt_tty_open(&cli.tty, -1) != 0) {
        retval = 1;
        goto exit;
    }

    amx_cli_build_file_name(basename(argv[0]));
    start = amx_cli_args_parse(&cli, argc, argv, &cmds);
    when_true_status(start == -1 && amxc_string_is_empty(&cmds), exit, retval = 5);
    automated = GET_BOOL(amxt_tty_get_config(cli.tty, "automated"), NULL);

    retval = amx_cli_init(&cli, basename(argv[0]), automated);
    when_failed(retval, exit);

    when_failed_status(amx_cli_el_create(cli.tty), exit, retval = 3);

    if(cli.tty->interactive) {
        amx_cli_update_prompt(cli.tty);
    }
    amxt_tty_silent(cli.tty, automated);
    amx_cli_run_script(&cli, automated);
    amxt_tty_silent(cli.tty, false);

    amxt_log_open(cli.tty, basename(argv[0]));
    amxt_log_enable(cli.tty, AMXT_LOG_INPUT | AMXT_LOG_MSG, true);
    amxt_log(cli.tty, "-- START --");

    if(start != -1) {
        amxt_tty_silent(cli.tty, !amxc_string_is_empty(&cmds));
        amx_cli_run(&cmds);
        amxt_tty_silent(cli.tty, false);
    } else {
        amx_cli_run(&cmds);
        goto exit;
    }

    if(automated) {
        amxc_var_t* color = GET_ARG(&cli.tty->config, "color");
        amxc_var_delete(&color);
        amx_cli_execute(start, argc, argv);
    }

    amxp_sigmngr_deferred_call(NULL, amx_cli_read_line, NULL, NULL);

    amx_cli_history_load(&cli, argv[0]);
    amx_cli_configure_self_modules(&cli);

    amx_cli_add_sig_handlers(cli.tty);
    when_failed_status(amx_cli_el_start(cli.tty), exit, retval = 4);
    amxt_log(cli.tty, "-- STOP --");

    amx_cli_history_save(&cli, argv[0]);

exit:
    fflush(stdout);
    amx_cli_stop_all();
    amxm_close_all();
    amx_cli_el_delete(cli.tty);
    amx_cli_clean(&cli);
    amxc_string_clean(&cmds);
    return retval;
}
