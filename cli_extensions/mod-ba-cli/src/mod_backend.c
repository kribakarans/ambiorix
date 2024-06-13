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

#include "mod_backend.h"

#define MOD "backend"
#define MOD_DESC "Manage backends"

static amxt_cmd_help_t help[] = {
    {
        .cmd = "help",
        .usage = "help [<CMD>]",
        .brief = "Print this help",
        .desc = "Prints some help about the commands in this module.\n"
            "For more information about the supported commands use 'help <CMD>'",
        .options = NULL
    },
    {
        .cmd = "add",
        .usage = "add <BACKEND SO>",
        .brief = "Adds a bus back-end.",
        .desc = "",
        .options = NULL
    },
    {
        .cmd = "remove",
        .usage = "remove <NAME>",
        .brief = "Removes a bus back-end.",
        .desc = "",
        .options = NULL
    },
    {
        .cmd = "autoload <PATH>",
        .usage = "autoload",
        .brief = "Load all available back-ends.",
        .desc = "",
        .options = NULL
    },
    {
        .cmd = "list",
        .usage = "list",
        .brief = "Lists all loaded back-ends.",
        .desc = "",
        .options = NULL
    },
    { NULL, NULL, NULL, NULL, NULL },
};

static void mod_backend_update_config(amxt_tty_t* tty) {
    amxc_array_t* names = amxb_be_list();
    size_t count = amxc_array_size(names);
    amxc_string_t be_uris;
    amxc_string_init(&be_uris, 0);

    for(size_t i = 0; i < count; i++) {
        const char* name = (const char*) amxc_array_get_data_at(names, i);
        amxc_var_t* uris = NULL;
        amxc_string_setf(&be_uris, "%s.uris", name);
        uris = GETP_ARG(&tty->config, amxc_string_get(&be_uris, 0));
        amxc_var_delete(&uris);
    }

    amxb_set_config(&tty->config);

    amxc_string_clean(&be_uris);
    amxc_array_delete(&names, NULL);
}

static int mod_backend_cmd_help(UNUSED const char* function_name,
                                amxc_var_t* args,
                                UNUSED amxc_var_t* ret) {
    amxt_tty_t* tty = GET_TTY(args);
    amxc_var_t* var_cmd = GET_ARG(args, "cmd");
    char* cmd = amxt_cmd_pop_word(var_cmd);

    amxt_cmd_print_help(tty, help, cmd);

    free(cmd);
    return 0;
}

static int mod_backend_cmd_add(UNUSED const char* function_name,
                               amxc_var_t* args,
                               UNUSED amxc_var_t* ret) {
    amxt_tty_t* tty = GET_TTY(args);
    amxc_var_t* var_cmd = GET_ARG(args, "cmd");
    char* so = amxt_cmd_pop_word(var_cmd);
    int rv = 0;

    if(!amxt_cmd_is_empty(var_cmd)) {
        amxt_cmd_error_excess(tty, var_cmd, help[1].cmd);
        rv = -1;
        goto exit;
    }

    rv = amxb_be_load(so);
    if(rv != 0) {
        amxt_tty_errorf(tty, "Failed to load %s (%d)\n", so, rv);
    } else {
        amxt_tty_messagef(tty, "%s loaded\n", so);
        mod_backend_update_config(tty);
    }

exit:
    free(so);
    return rv;
}

static int mod_backend_cmd_remove(UNUSED const char* function_name,
                                  amxc_var_t* args,
                                  UNUSED amxc_var_t* ret) {
    amxt_tty_t* tty = GET_TTY(args);
    amxc_var_t* var_cmd = GET_ARG(args, "cmd");
    char* name = amxt_cmd_pop_word(var_cmd);
    int rv = 0;

    if(!amxt_cmd_is_empty(var_cmd)) {
        amxt_cmd_error_excess(tty, var_cmd, help[2].cmd);
        rv = -1;
        goto exit;
    }

    rv = amxb_be_remove(name);
    if(rv != 0) {
        amxt_tty_errorf(tty, "Failed to remove %s (%d)\n", name, rv);
    } else {
        amxt_tty_messagef(tty, "%s removed\n", name);
    }

exit:
    free(name);
    return rv;
}

static int mod_backend_load(const char* name, void* priv) {
    amxt_tty_t* tty = (amxt_tty_t*) priv;

    int rv = amxb_be_load(name);
    if(rv != 0) {
        amxt_tty_errorf(tty, "Failed to load %s (%d)\n", name, rv);
    } else {
        amxt_tty_messagef(tty, "%s loaded\n", name);
    }
    return 0;
}

static int mod_backend_cmd_autoload(UNUSED const char* function_name,
                                    amxc_var_t* args,
                                    UNUSED amxc_var_t* ret) {
    amxt_tty_t* tty = GET_TTY(args);
    amxc_var_t* var_cmd = GET_ARG(args, "cmd");
    char* path = amxt_cmd_pop_word(var_cmd);
    int rv = 0;

    if(!amxt_cmd_is_empty(var_cmd)) {
        amxt_cmd_error_excess(tty, var_cmd, help[3].cmd);
        rv = -1;
        goto exit;
    }

    rv = amxp_dir_scan(path, "d_name matches '.*\\.so'", false, mod_backend_load, tty);
    if(rv != 0) {
        amxt_tty_errorf(tty, "Failed to scan dir %s (%d)\n", path, rv);
    }

    mod_backend_update_config(tty);

exit:
    free(path);
    return rv;
}

static int mod_backend_cmd_list(UNUSED const char* function_name,
                                amxc_var_t* args,
                                UNUSED amxc_var_t* ret) {
    amxt_tty_t* tty = GET_TTY(args);
    amxc_array_t* names = amxb_be_list();
    size_t count = amxc_array_size(names);
    amxc_var_t* var_cmd = GET_ARG(args, "cmd");
    int rv = 0;

    if(!amxt_cmd_is_empty(var_cmd)) {
        amxt_cmd_error_excess(tty, var_cmd, help[4].cmd);
        rv = -1;
        goto exit;
    }

    if(count == 0) {
        amxt_tty_writef(tty, "No bus back-ends added\n");
        rv = -1;
        goto exit;
    }
    amxt_tty_writef(tty, "\n");
    amxt_tty_writef(tty, "${color.white}|   Name   ");
    amxt_tty_writef(tty, "|  Version  ");
    amxt_tty_writef(tty, "|              Description              |${color.reset}\n");
    amxt_tty_writef(tty, "${color.white}-----------");
    amxt_tty_writef(tty, "------------");
    amxt_tty_writef(tty, "-----------------------------------------${color.reset}\n");

    for(size_t i = 0; i < count; i++) {
        const char* name = (const char*) amxc_array_get_data_at(names, i);
        const amxb_be_info_t* info = amxb_be_get_info(name);
        amxt_tty_writef(tty, "${color.white}|${color.reset} %-*.*s ", 8, 8, info->name);
        amxt_tty_writef(tty, "${color.white}|${color.reset} %2.2d.%2.2d.%2.2d  ",
                        info->be_version->major,
                        info->be_version->minor,
                        info->be_version->build);
        amxt_tty_writef(tty, "${color.white}|${color.reset} %-*.*s ", 37, 37, info->description);
        amxt_tty_writef(tty, "${color.white}|${color.reset}\n");
    }

exit:
    amxc_array_delete(&names, NULL);
    return rv;
}

static int mod_backend_describe(UNUSED const char* function_name,
                                UNUSED amxc_var_t* args,
                                amxc_var_t* ret) {
    amxc_var_set(cstring_t, ret, MOD_DESC);
    return 0;
}


static int mod_backend_complete_cmd_help(UNUSED const char* function_name,
                                         amxc_var_t* args,
                                         amxc_var_t* ret) {
    amxt_tty_t* tty = ba_cli_get_tty();
    amxt_cmd_complete_help(args, help, ret);
    amxp_sigmngr_emit_signal(tty->sigmngr, "tty:docomplete", ret);
    amxc_var_delete(&ret);
    return 0;
}

static int mod_backend_complete_cmd_add(UNUSED const char* function_name,
                                        amxc_var_t* args,
                                        amxc_var_t* ret) {
    amxt_tty_t* tty = ba_cli_get_tty();
    amxt_cmd_complete_path(function_name, args, ret);
    amxp_sigmngr_emit_signal(tty->sigmngr, "tty:docomplete", ret);
    amxc_var_delete(&ret);
    return 0;
}

static int mod_backend_complete_cmd_remove(UNUSED const char* function_name,
                                           amxc_var_t* args,
                                           amxc_var_t* ret) {
    amxt_tty_t* tty = ba_cli_get_tty();
    int words = amxt_cmd_count_words(args);
    amxc_array_t* names = amxb_be_list();
    size_t count = amxc_array_size(names);
    char* arg = amxt_cmd_pop_word(args);
    size_t len_arg = arg == NULL ? 0 : strlen(arg);

    if(words <= 1) {
        for(size_t i = 0; i < count; i++) {
            const char* name = (const char*) amxc_array_get_data_at(names, i);
            if((len_arg == 0) || (strncmp(name, arg, len_arg) == 0)) {
                amxc_var_add(cstring_t, ret, name);
            }
        }
    }

    amxp_sigmngr_emit_signal(tty->sigmngr, "tty:docomplete", ret);
    amxc_var_delete(&ret);
    amxc_array_delete(&names, NULL);
    free(arg);
    return 0;
}

int PRIVATE mod_backend_start(amxm_shared_object_t* me) {
    amxm_module_t* mod = NULL;

    amxm_module_register(&mod, me, MOD);
    // backend commands
    amxm_module_add_function(mod, "help", mod_backend_cmd_help);
    amxm_module_add_function(mod, "add", mod_backend_cmd_add);
    amxm_module_add_function(mod, "remove", mod_backend_cmd_remove);
    amxm_module_add_function(mod, "list", mod_backend_cmd_list);
    amxm_module_add_function(mod, "autoload", mod_backend_cmd_autoload);

    // backend describe
    amxm_module_add_function(mod, "__describe", mod_backend_describe);

    // backend tab completion functions
    amxm_module_add_function(mod, "__complete_help", mod_backend_complete_cmd_help);
    amxm_module_add_function(mod, "__complete_add", mod_backend_complete_cmd_add);
    amxm_module_add_function(mod, "__complete_autoload", mod_backend_complete_cmd_add);
    amxm_module_add_function(mod, "__complete_remove", mod_backend_complete_cmd_remove);

    return 0;
}

int PRIVATE mod_backend_stop(UNUSED amxm_shared_object_t* me) {
    amxb_be_remove_all();

    return 0;
}