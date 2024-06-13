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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "amx_cli.h"

#include "amx_cli_parser.h"

#define MOD "addon"
#define MOD_DESC "loads & unloads add-ons - adds or removes functionality"

static amxt_cmd_help_t help[] = {
    {
        .cmd = "help",
        .usage = "help [<CMD>]",
        .brief = "Prints help",
        .desc = "Use `help <CMD>` to get more information about the <CMD>.",
        .options = NULL
    },
    {
        .cmd = "load",
        .usage = "load <ALIAS> <ADDON>",
        .brief = "loads an add-on shared object.",
        .desc = "An add-on adds commands to the command line interface.\n"
            "The <ALIAS> is a name that can be freely chosen.\n"
            "The <ADDON> must be a valid Ambiorix Command Line Interface shared object.",
        .options = NULL
    },
    {
        .cmd = "remove",
        .usage = "remove <ALIAS>",
        .brief = "Removes an add-on shared-object.",
        .desc = "Unloads the Ambiorix Command Line Interface shared object which is "
            "referenced by <ALIAS>.\n"
            "If the add-on is the current active add-on, it will be unselected and"
            "no other add-on will be selected as the active add-on.\n"
            "Use '!addon select <ALIAS>' to select another add-on as active add-on.",
        .options = NULL
    },
    {
        .cmd = "select",
        .usage = "select <ALIAS> [<MODULE>]",
        .brief = "Selects an add-on as the active add-on.",
        .desc = "Sets <ALIAS> as the active add-on. Optionally a <MODULE> of the add-on "
            "can be selected as well.",
        .options = NULL
    },
    {
        .cmd = "list",
        .usage = "list",
        .brief = "Lists all loaded add-on",
        .desc = "Prints the list of all currently loaded add-ons.",
        .options = NULL
    },
    { NULL, NULL, NULL, NULL, NULL },
};

static void mod_addon_so_init(amxm_shared_object_t* so,
                              UNUSED const char* so_file,
                              const char* so_name,
                              amxc_var_t* args) {
    amxt_tty_t* tty = GET_TTY(args);
    amxc_var_t ret;
    size_t mod_count = amxm_so_count_modules(so);
    char* mod_name = NULL;
    size_t public_mods = 0;
    size_t pub_index = 0;

    amxc_var_init(&ret);

    amxt_tty_messagef(tty, "Loading successful\n");
    if(amxm_has_function(amx_cli_get_shared_object(), amx_cli_get_module(), "__deactivate")) {
        amxm_execute_function(so_name, mod_name, "__deactivate", args, &ret);
    }

    amx_cli_set_shared_object(so_name);

    for(size_t index = 0; index < mod_count; index++) {
        mod_name = amxm_so_probe(so, index);
        if(strncmp(mod_name, "__", 2) == 0) {
            free(mod_name);
            mod_name = NULL;
            continue;
        }
        amxt_tty_writef(tty, "%s %s\n", so_name, mod_name);
        public_mods++;
        pub_index = index;
        free(mod_name);
        mod_name = NULL;
    }

    amxm_so_execute_function(so, "__shared_object", "init", args, &ret);

    if(public_mods == 1) {
        mod_name = amxm_so_probe(so, pub_index);
    } else {
        amxm_so_execute_function(so, "__shared_object", "default", args, &ret);
        mod_name = amxc_var_dyncast(cstring_t, &ret);
    }

    if(mod_name != NULL) {
        amx_cli_set_module(mod_name);
        amxm_so_execute_function(so, mod_name, "__activate", args, &ret);
    }

    amxc_var_clean(&ret);
    free(mod_name);
    return;
}

static int mod_addon_cmd_help(UNUSED const char* function_name,
                              amxc_var_t* args,
                              UNUSED amxc_var_t* ret) {
    amxt_tty_t* tty = GET_TTY(args);
    amxc_var_t* var_cmd = GET_ARG(args, "cmd");
    char* cmd = amxt_cmd_pop_word(var_cmd);

    amxt_cmd_print_help(tty, help, cmd);

    free(cmd);
    return 0;
}

static int mod_addon_cmd_load(UNUSED const char* function_name,
                              amxc_var_t* args,
                              UNUSED amxc_var_t* ret) {
    amxt_tty_t* tty = GET_TTY(args);
    amxc_var_t* var_cmd = GET_ARG(args, "cmd");
    int retval = 1;
    amxm_shared_object_t* so = NULL;

    char* name = amxt_cmd_pop_word(var_cmd);
    char* file = amxt_cmd_pop_word(var_cmd);

    if(name == NULL) {
        amxt_tty_errorf(tty, "No name specified\n");
        goto exit;
    }

    if(file == NULL) {
        amxt_tty_errorf(tty, "No file specified\n");
        goto exit;
    }

    amxt_tty_writef(tty, "Loading shared object %s\n", file);
    retval = amxm_so_open(&so, name, file);
    if(retval == 0) {
        mod_addon_so_init(so, file, name, args);
    } else {
        amxt_tty_errorf(tty, "Loading failed\n");
    }
exit:
    free(name);
    free(file);
    return retval;
}

static int mod_addon_cmd_remove(UNUSED const char* function_name,
                                amxc_var_t* args,
                                UNUSED amxc_var_t* ret) {
    amxt_tty_t* tty = GET_TTY(args);
    amxc_var_t* var_cmd = GET_ARG(args, "cmd");
    int retval = 1;
    const char* current_so = amx_cli_get_shared_object();
    amxm_shared_object_t* so = NULL;
    char* name = amxt_cmd_pop_word(var_cmd);

    if(name == NULL) {
        amxt_tty_errorf(tty, "No file name specified\n");
        goto exit;
    }

    so = amxm_get_so(name);
    if(so == 0) {
        amxt_tty_errorf(tty, "Add-on %s not found\n", name);
        goto exit;
    }

    amxt_tty_writef(tty, "Removing shared object %s (%s)\n", name, so->file);

    amxc_var_set(amxt_tty_t, args, tty);
    amxm_so_execute_function(so, "__shared_object", "exit", args, ret);

    if(amxm_close_so(name) != 0) {
        amxt_tty_errorf(tty, "Failed to close %s (%s)\n", name, so->file);
        goto exit;
    } else {
        amxt_tty_messagef(tty, "Removed %s\n", name);
    }

    if((current_so != NULL) &&
       ( strcmp(current_so, name) == 0)) {
        amx_cli_set_module(NULL);
        amx_cli_set_shared_object(NULL);
    }
    retval = 0;

exit:
    free(name);
    return retval;
}

static int mod_addon_cmd_select(UNUSED const char* function_name,
                                amxc_var_t* args,
                                UNUSED amxc_var_t* ret) {
    amxt_tty_t* tty = GET_TTY(args);
    amxc_var_t* var_cmd = GET_ARG(args, "cmd");
    int retval = 1;
    char* so_name = NULL;
    char* mod_name = NULL;
    amxm_shared_object_t* so = NULL;

    so_name = amxt_cmd_pop_word(var_cmd);
    mod_name = amxt_cmd_pop_word(var_cmd);

    if(so_name == NULL) {
        amx_cli_set_shared_object(NULL);
        amx_cli_set_module(NULL);
        retval = 0;
        goto exit;
    }

    so = amxm_get_so(so_name);
    if(so == NULL) {
        amxt_tty_errorf(tty, "shared object %s not found\n", so_name);
        goto exit;
    }

    if(mod_name == NULL) {
        amx_cli_set_shared_object(so_name);
        amx_cli_set_module(NULL);
        retval = 0;
        goto exit;
    } else {
        amxm_module_t* mod = amxm_get_module(so_name, mod_name);

        if(mod == NULL) {
            amxt_tty_errorf(tty,
                            "shared object %s does not contain module %s\n",
                            so_name,
                            mod_name);
            goto exit;
        }
    }

    if(amxm_has_function(amx_cli_get_shared_object(), amx_cli_get_module(), "__deactivate")) {
        amxm_execute_function(so_name, mod_name, "__deactivate", args, ret);
    }
    amx_cli_set_shared_object(so_name);
    amx_cli_set_module(mod_name);
    amxm_execute_function(so_name, mod_name, "__activate", args, ret);

    retval = 0;

exit:
    free(so_name);
    free(mod_name);
    return retval;
}

static int mod_addon_cmd_list(UNUSED const char* function_name,
                              UNUSED amxc_var_t* args,
                              UNUSED amxc_var_t* ret) {
    amxt_tty_t* tty = GET_TTY(args);
    uint32_t count = 0;

    const amxc_llist_t* shared_objects = amxm_get_so_list();
    amxt_tty_writef(tty, "\n");
    amxc_llist_for_each(it, shared_objects) {
        amxm_shared_object_t* so = amxc_llist_it_get_data(it, amxm_shared_object_t, it);
        if(strcmp(so->name, "self") == 0) {
            continue;
        }
        amxt_tty_writef(tty, "${color.white}%s${color.reset} - ", so->name);
        amxt_tty_writef(tty, "%s\n", so->file);
        count++;
    }

    if(count == 0) {
        amxt_tty_writef(tty, "No add-ons loaded\n");
    }

    return 0;
}

static int mod_addon_complete_cmd_load(const char* function_name,
                                       amxc_var_t* args,
                                       amxc_var_t* ret) {
    amxt_tty_t* tty = amx_cli_get_tty();
    int words = amxt_cmd_count_words(args);

    if(words < 2) {
        amxc_string_t txt;
        amxc_string_init(&txt, 64);
        amxc_string_setf(&txt, "${color.reset}%s <ALIAS> <ADDON>", function_name + 11);
        amxc_var_set(cstring_t, ret, amxc_string_get(&txt, 0));
        amxc_string_clean(&txt);
    } else {
        free(amxt_cmd_pop_word(args));
        amxt_cmd_complete_path(function_name, args, ret);
    }
    amxp_sigmngr_emit_signal(tty->sigmngr, "tty:docomplete", ret);
    amxc_var_delete(&ret);
    return 0;
}

static void mod_addon_complete_addon(amxc_var_t* words, const char* start) {
    const amxc_llist_t* shared_objects = amxm_get_so_list();
    size_t len = start == NULL ? 0 : strlen(start);

    amxc_llist_for_each(it, shared_objects) {
        amxm_shared_object_t* so = amxc_llist_it_get_data(it, amxm_shared_object_t, it);
        if(strcmp(so->name, "self") == 0) {
            continue;
        }
        if((start == NULL) || (strncmp(start, so->name, len) == 0)) {
            amxc_var_add(cstring_t, words, so->name);
        }
    }
}

static void mod_addon_complete_module(amxc_var_t* words,
                                      const char* so_name,
                                      const char* start) {
    amxm_shared_object_t* so = amxm_get_so(so_name);
    size_t len = start == NULL ? 0 : strlen(start);
    size_t mod_count = amxm_so_count_modules(so);

    for(size_t index = 0; index < mod_count; index++) {
        char* mod = amxm_so_probe(so, index);
        if(strncmp(mod, "__", 2) == 0) {
            free(mod);
            continue;
        }
        if((start == NULL) || (strncmp(start, mod, len) == 0)) {
            amxc_var_add(cstring_t, words, mod);
        }
        free(mod);
    }
}

static int mod_addon_complete_cmd_remove(UNUSED const char* function_name,
                                         amxc_var_t* args,
                                         amxc_var_t* ret) {
    amxt_tty_t* tty = amx_cli_get_tty();
    int words = amxt_cmd_count_words(args);
    char* so_name = amxt_cmd_pop_word(args);

    switch(words) {
    case 0:
    case 1:
        mod_addon_complete_addon(ret, so_name);
        break;
    }

    amxp_sigmngr_emit_signal(tty->sigmngr, "tty:docomplete", ret);
    amxc_var_delete(&ret);
    free(so_name);
    return 0;
}

static int mod_addon_complete_cmd_select(UNUSED const char* function_name,
                                         amxc_var_t* args,
                                         amxc_var_t* ret) {
    amxt_tty_t* tty = amx_cli_get_tty();
    int words = amxt_cmd_count_words(args);
    char* so_name = NULL;

    amxt_cmd_triml(args, ' ');
    so_name = amxt_cmd_pop_part(args);

    switch(words) {
    case 0:
    case 1:
        mod_addon_complete_addon(ret, so_name);
        break;
    case 2: {
        char* mod_name = NULL;
        amxt_cmd_triml(args, ' ');
        mod_name = amxt_cmd_pop_part(args);
        mod_addon_complete_module(ret, so_name, mod_name);
        free(mod_name);
    }
    break;
    }

    amxp_sigmngr_emit_signal(tty->sigmngr, "tty:docomplete", ret);
    amxc_var_delete(&ret);
    free(so_name);
    return 0;
}

static int mod_addon_complete_cmd_help(UNUSED const char* function_name,
                                       amxc_var_t* args,
                                       amxc_var_t* ret) {
    amxt_tty_t* tty = amx_cli_get_tty();
    amxt_cmd_complete_help(args, help, ret);
    amxp_sigmngr_emit_signal(tty->sigmngr, "tty:docomplete", ret);
    amxc_var_delete(&ret);
    return 0;
}

static int mod_addon_describe(UNUSED const char* function_name,
                              UNUSED amxc_var_t* args,
                              amxc_var_t* ret) {
    amxc_var_set(cstring_t, ret, MOD_DESC);
    return 0;
}

static AMXM_CONSTRUCTOR mod_addon_init(void) {
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

    amxm_module_add_function(mod, "help", mod_addon_cmd_help);
    amxm_module_add_function(mod, "load", mod_addon_cmd_load);
    amxm_module_add_function(mod, "remove", mod_addon_cmd_remove);
    amxm_module_add_function(mod, "select", mod_addon_cmd_select);
    amxm_module_add_function(mod, "list", mod_addon_cmd_list);

    // completion functions
    amxm_module_add_function(mod, "__complete_load", mod_addon_complete_cmd_load);
    amxm_module_add_function(mod, "__complete_remove", mod_addon_complete_cmd_remove);
    amxm_module_add_function(mod, "__complete_select", mod_addon_complete_cmd_select);
    amxm_module_add_function(mod, "__complete_help", mod_addon_complete_cmd_help);

    // description
    amxm_module_add_function(mod, "__describe", mod_addon_describe);

    return 0;
}

static AMXM_DESTRUCTOR mod_addon_cleanup(void) {
    return 0;
}
