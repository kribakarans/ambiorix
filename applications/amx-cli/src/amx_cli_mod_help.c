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


#define MOD "help"
#define MOD_DESC "Shows help"

static void mod_help_print_mod(amxt_tty_t* tty,
                               amxm_shared_object_t* so,
                               amxc_var_t* args,
                               const char* indent) {
    amxc_var_t desc;
    size_t mod_count = amxm_so_count_modules(so);

    amxc_var_init(&desc);
    for(size_t index = 0; index < mod_count; index++) {
        char* name = amxm_so_probe(so, index);
        int rv = 0;
        if(strncmp(name, "__", 2) == 0) {
            free(name);
            continue;
        }
        amxt_cmd_triml(args, ' ');
        rv = amxm_so_execute_function(so, name, "__describe", args, &desc);
        if((rv == 0) &&
           ( amxc_var_type_of(&desc) == AMXC_VAR_ID_CSTRING)) {
            amxt_tty_writef(tty,
                            "%s${color.white}%s${color.reset} - %s\n",
                            indent,
                            name,
                            amxc_var_constcast(cstring_t, &desc));
        } else {
            amxt_tty_writef(tty,
                            "%s${color.white}%s${color.reset}\n",
                            indent,
                            name);
        }
        free(name);
    }
    amxc_var_clean(&desc);
}

static void mod_help_print_alias(amxt_tty_t* tty) {
    amxc_var_t* aliases = amx_cli_get_aliases();
    const amxc_htable_t* taliases = amxc_var_constcast(amxc_htable_t, aliases);
    amxc_array_t* keys = amxc_htable_get_sorted_keys(taliases);
    size_t count = amxc_array_size(keys);

    for(size_t i = 0; i < count; i++) {
        amxc_array_it_t* it = amxc_array_get_at(keys, i);
        const char* key = (const char*) amxc_array_it_get_data(it);
        const char* val = GET_CHAR(aliases, key);
        amxt_tty_writef(tty, "\t${color.white}%s${color.reset} = %s\n", key, val);
    }

    amxc_array_delete(&keys, NULL);
}

static void mod_help_print_so(amxt_tty_t* tty, amxc_var_t* args) {
    const amxc_llist_t* shared_objects = amxm_get_so_list();
    amxm_module_t* mod = amxm_get_module("self", "addon");

    if(mod == NULL) {
        return;
    }

    amxt_tty_writef(tty, "Available addons: \n");
    amxc_llist_for_each(it, shared_objects) {
        amxm_shared_object_t* so = amxc_llist_it_get_data(it, amxm_shared_object_t, it);
        if(strcmp(so->name, "self") == 0) {
            continue;
        }
        amxt_tty_writef(tty,
                        "\t "
                        "${color.white}%s${color.reset}"
                        " - %s\n",
                        so->name,
                        so->file);
        mod_help_print_mod(tty, so, args, "\t\t");
    }

    amxt_tty_writef(tty, "\n");
    amxt_tty_writef(tty,
                    "Select addon with ${color.white}"
                    "!addon select <ADDON> [<MODULE>]"
                    "${color.white}\n");
}

static void mod_help_complete_add_addons(const char* start,
                                         amxc_var_t* words) {
    const amxc_llist_t* so_list = amxm_get_so_list();
    uint32_t len = start == NULL ? 0 : strlen(start);
    amxc_llist_for_each(it, so_list) {
        amxm_shared_object_t* so = amxc_llist_it_get_data(it, amxm_shared_object_t, it);
        if(strcmp(so->name, "self") == 0) {
            continue;
        }
        if(strncmp(so->name, "__", 2) == 0) {
            continue;
        }
        if((start == NULL) || (strncmp(start, so->name, len) == 0)) {
            amxc_var_add(cstring_t, words, so->name);
        }
    }
}

static void mod_help_complete_add_mods(amxm_shared_object_t* so,
                                       const char* start,
                                       amxc_var_t* words) {
    size_t mod_count = amxm_so_count_modules(so);
    uint32_t len = start == NULL ? 0 : strlen(start);
    for(size_t index = 0; index < mod_count; index++) {
        char* mod_name = amxm_so_probe(so, index);
        if(strncmp(mod_name, "__", 2) == 0) {
            free(mod_name);
            continue;
        }
        if((start == NULL) || (strncmp(start, mod_name, len) == 0)) {
            amxc_var_add(cstring_t, words, mod_name);
        }
        free(mod_name);
    }
}

static int mod_help_execute(UNUSED const char* function_name,
                            amxc_var_t* args,
                            amxc_var_t* ret) {
    amxm_shared_object_t* so = amxm_get_so("self");
    amxt_tty_t* tty = GET_TTY(args);
    amxc_var_t* var_cmd = GET_ARG(args, "cmd");
    int retval = -1;

    char* mod = amxt_cmd_pop_word(var_cmd);

    if(mod == NULL) {
        amxt_tty_writef(tty, "amx modules:\n");
        amxt_tty_writef(tty, "\tUse ! prefix to execute amx modules commands\n\n");
        mod_help_print_mod(tty, so, args, "\t");
        amxt_tty_writef(tty, "\naliases:\n");
        mod_help_print_alias(tty);
        amxt_tty_writef(tty, "\n");
        mod_help_print_so(tty, args);
    } else {
        if(amxm_so_get_module(so, mod) != NULL) {
            amxt_cmd_triml(var_cmd, ' ');
            amxm_so_execute_function(so, mod, "help", args, ret);
        } else {
            so = amxm_get_so(mod);
            if(so == NULL) {
                amxt_tty_errorf(tty, "Not found [%s]\n", mod);
                goto exit;
            }
            free(mod);
            mod = amxt_cmd_pop_word(var_cmd);
            if(mod == NULL) {
                mod_help_print_mod(tty, so, args, "\t");
            } else {
                amxt_cmd_triml(var_cmd, ' ');
                amxm_so_execute_function(so, mod, "help", args, ret);
            }
        }
    }

    retval = 0;

exit:
    free(mod);
    return retval;
}

static int mod_help_complete(UNUSED const char* function_name,
                             amxc_var_t* args,
                             amxc_var_t* ret) {
    amxm_shared_object_t* so = amxm_get_so("self");
    uint32_t count = amxt_cmd_count_words(args);
    char* word = amxt_cmd_pop_word(args);
    amxt_tty_t* tty = amx_cli_get_tty();

    switch(count) {
    case 0:     // self modules or addons
    case 1:     // self modules or addons
        mod_help_complete_add_mods(so, word, ret);
        mod_help_complete_add_addons(word, ret);
        break;
    case 2:     // self <MOD> functions or <ADDON> modules
        if(amxm_so_get_module(so, word) != NULL) {
            char* mod_name = word;
            amxm_module_t* mod = amxm_so_get_module(so, mod_name);
            word = amxt_cmd_pop_word(args);
            amx_cli_complete_add_funcs(mod, word, ret);
            free(mod_name);
        } else {
            char* so_name = word;
            word = amxt_cmd_pop_word(args);
            so = amxm_get_so(so_name);
            mod_help_complete_add_mods(so, word, ret);
            free(so_name);
        }
        break;
    case 3: {
        char* so_name = word;
        char* mod_name = amxt_cmd_pop_word(args);
        amxm_module_t* mod = NULL;
        word = amxt_cmd_pop_word(args);
        so = amxm_get_so(so_name);
        mod = amxm_so_get_module(so, mod_name);
        amx_cli_complete_add_funcs(mod, word, ret);
        free(so_name);
        free(mod_name);
    }
    break;
    }

    amxp_sigmngr_emit_signal(tty->sigmngr, "tty:docomplete", ret);

    amxc_var_delete(&ret);
    free(word);
    return 0;
}

static int mod_help_describe(UNUSED const char* function_name,
                             UNUSED amxc_var_t* args,
                             amxc_var_t* ret) {

    amxc_var_set(cstring_t, ret, MOD_DESC);
    return 0;
}

static AMXM_CONSTRUCTOR mod_help_init(void) {
    amxm_module_t* mod = NULL;
    amxm_shared_object_t* so = amxm_get_so("self");

    if(so == NULL) {
        printf("No self\n");
        return 1;
    }

    if(amxm_module_register(&mod, so, MOD) != 0) {
        printf("Couldn't make module\n");
        return 1;
    }

    // implementations
    amxm_module_add_function(mod, "__execute", mod_help_execute);

    // completion functions
    amxm_module_add_function(mod, "__complete", mod_help_complete);

    // description
    amxm_module_add_function(mod, "__describe", mod_help_describe);

    return 0;
}
