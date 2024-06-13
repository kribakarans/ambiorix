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

#include "amx_cli.h"

#include "amx_cli_parser.h"
#include "amx_cli_history.h"

#define MOD "history"
#define MOD_DESC "Can display, clear, save and load the command history"

static amxt_cmd_help_t help[] = {
    {
        .cmd = "help",
        .usage = "help [<CMD>]",
        .brief = "Prints help",
        .desc = "Use 'help <CMD>' to get more information about the <CMD>.",
        .options = NULL
    },
    {
        .cmd = "show",
        .usage = "show",
        .brief = "Shows command history.",
        .desc = "Print all commands in the commad history.\n"
            "Most recent first, the oldest last\n",
        .options = NULL
    },
    {
        .cmd = "clear",
        .usage = "clear",
        .brief = "clear command history.",
        .desc = "If the command history was saved to a file it can be restored "
            "with '!history load <FILE>'",
        .options = NULL
    },
    {
        .cmd = "save",
        .usage = "save <FILE>",
        .brief = "Saves command history to a file.",
        .desc = "Use '!history load <FILE>' to restore the command history at any point.",
        .options = NULL
    },
    {
        .cmd = "load",
        .usage = "load <FILE>",
        .brief = "Loads command history from a file.",
        .desc = "This will overwrite the current command history.",
        .options = NULL
    },
    { NULL, NULL, NULL, NULL, NULL },
};

static int mod_history_cmd_help(UNUSED const char* function_name,
                                amxc_var_t* args,
                                UNUSED amxc_var_t* ret) {
    amxt_tty_t* tty = GET_TTY(args);
    amxc_var_t* var_cmd = GET_ARG(args, "cmd");
    char* cmd = amxt_cmd_pop_word(var_cmd);

    amxt_cmd_print_help(tty, help, cmd);

    free(cmd);
    return 0;
}

static int mod_history_cmd_show(UNUSED const char* function_name,
                                amxc_var_t* args,
                                UNUSED amxc_var_t* ret) {
    amxt_tty_t* tty = GET_TTY(args);
    amxt_hist_t* hist = amxt_tty_history(tty);
    const char* item = NULL;
    int index = 1;
    int current = amxt_hist_get_pos(hist);

    amxt_hist_set_pos(hist, 0);
    item = amxt_hist_get_current(hist);
    while(item) {
        amxt_tty_writef(tty,
                        "${color.blue}%d${color.white} - %s${color.reset}\n",
                        index,
                        item);
        item = amxt_hist_get_next(hist);
        index++;
    }

    amxt_hist_set_pos(hist, current);
    return 0;
}

static int mod_history_cmd_clear(UNUSED const char* function_name,
                                 amxc_var_t* args,
                                 UNUSED amxc_var_t* ret) {
    amxt_tty_t* tty = GET_TTY(args);
    amxt_hist_t* hist = amxt_tty_history(tty);

    amxt_hist_clean(hist);

    return 0;
}

static int mod_history_cmd_save(UNUSED const char* function_name,
                                amxc_var_t* args,
                                UNUSED amxc_var_t* ret) {
    amxt_tty_t* tty = GET_TTY(args);
    amxc_var_t* var_cmd = GET_ARG(args, "cmd");
    amxt_hist_t* hist = amxt_tty_history(tty);
    char* file = amxt_cmd_pop_word(var_cmd);
    int retval = 1;

    if(file == NULL) {
        amxt_tty_errorf(tty, "No file name specified\n");
        goto exit;
    }

    if(amxt_hist_save(hist, file) != 0) {
        amxt_tty_errorf(tty, "Failed to save history to %s\n", file);
        goto exit;
    }

    retval = 0;

exit:
    free(file);
    return retval;
}

static int mod_history_cmd_load(UNUSED const char* function_name,
                                amxc_var_t* args,
                                UNUSED amxc_var_t* ret) {
    amxt_tty_t* tty = GET_TTY(args);
    amxc_var_t* var_args = GET_ARG(args, "cmd");
    amxt_hist_t* hist = amxt_tty_history(tty);
    amxc_string_t file;
    int retval = 1;

    amxc_string_init(&file, 0);
    amxc_string_join_var_until(&file, var_args, "", " ", true);

    if(amxc_string_is_empty(&file)) {
        amxt_tty_errorf(tty, "No file name specified\n");
        goto exit;
    }

    if(amxt_hist_load(hist, amxc_string_get(&file, 0)) != 0) {
        amxt_tty_errorf(tty, "Failed to load history to %s\n", amxc_string_get(&file, 0));
        goto exit;
    }

    retval = 0;

exit:
    amxc_string_clean(&file);
    return retval;
}

static int mod_history_complete_cmd_help(UNUSED const char* function_name,
                                         amxc_var_t* args,
                                         amxc_var_t* ret) {
    amxt_tty_t* tty = amx_cli_get_tty();
    amxt_cmd_complete_help(args, help, ret);
    amxp_sigmngr_emit_signal(tty->sigmngr, "tty:docomplete", ret);
    amxc_var_delete(&ret);
    return 0;
}

static int mod_history_complete_file(const char* function_name,
                                     amxc_var_t* args,
                                     amxc_var_t* ret) {
    amxt_tty_t* tty = amx_cli_get_tty();
    amxt_cmd_complete_path(function_name, args, ret);
    amxp_sigmngr_emit_signal(tty->sigmngr, "tty:docomplete", ret);
    amxc_var_delete(&ret);
    return 0;
}

static int mod_history_describe(UNUSED const char* function_name,
                                UNUSED amxc_var_t* args,
                                amxc_var_t* ret) {
    amxc_var_set(cstring_t, ret, MOD_DESC);
    return 0;
}

static AMXM_CONSTRUCTOR mod_history_init(void) {
    amxm_module_t* mod = NULL;
    amxm_shared_object_t* so = amxm_get_so("self");

    if(so == NULL) {
        printf("No self\n");
        return 1;
    }

    if(amxm_module_register(&mod, so, MOD) != 0) {
        printf("Couldnt make module\n");
        return 1;
    }

    // implementations
    amxm_module_add_function(mod, "help", mod_history_cmd_help);
    amxm_module_add_function(mod, "show", mod_history_cmd_show);
    amxm_module_add_function(mod, "clear", mod_history_cmd_clear);
    amxm_module_add_function(mod, "save", mod_history_cmd_save);
    amxm_module_add_function(mod, "load", mod_history_cmd_load);

    // completion functions
    amxm_module_add_function(mod, "__complete_help", mod_history_complete_cmd_help);
    amxm_module_add_function(mod, "__complete_load", mod_history_complete_file);
    amxm_module_add_function(mod, "__complete_save", mod_history_complete_file);

    // description
    amxm_module_add_function(mod, "__describe", mod_history_describe);

    return 0;
}

static AMXM_DESTRUCTOR mod_history_cleanup(void) {
    return 0;
}


void amx_cli_history_load(cli_app_t* cli, const char* name) {
    amxc_string_t file_name;
    amxt_hist_t* history = amxt_tty_history(cli->tty);

    amxc_string_init(&file_name, 0);
    amxc_string_setf(&file_name, "/tmp/%s.history", name);
    amxt_hist_load(history, amxc_string_get(&file_name, 0));

    amxc_string_clean(&file_name);
    return;
}

void amx_cli_history_save(cli_app_t* cli, const char* name) {
    amxc_string_t file_name;
    amxt_hist_t* history = amxt_tty_history(cli->tty);

    amxc_string_init(&file_name, 0);
    amxc_string_setf(&file_name, "/tmp/%s.history", name);
    amxt_hist_save(history, amxc_string_get(&file_name, 0));

    amxc_string_clean(&file_name);
    return;
}