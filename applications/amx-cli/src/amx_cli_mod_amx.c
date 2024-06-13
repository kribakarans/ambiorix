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
#include "amx_cli_eventloop.h"

#define MOD "amx"
#define MOD_DESC \
    "Ambiorix Interactive Command Line Control."

#define CMD_HELP          0
#define CMD_EXIT          1
#define CMD_SILENT        2
#define CMD_LOG           3
#define CMD_PROMPT        4
#define CMD_ALIAS         5
#define CMD_VARIABLE_DUMP 6
#define CMD_VARiABLE_SET  7

static const char* cmd_log_opts[] = {
    "o", "output",
    "m", "msg",
    NULL
};

static amxt_cmd_help_t help[] = {
    {
        .cmd = "help",
        .usage = "help [<CMD>]",
        .brief = "Prints help",
        .desc = "Use 'help <CMD>' to get more information about the <CMD>.",
        .options = NULL
    },
    {
        .cmd = "exit",
        .usage = "exit",
        .brief = "Exits Ambiorix Command Line Interface.",
        .desc = "Exit the application",
        .options = NULL
    },
    {
        .cmd = "silent",
        .usage = "silent true|false",
        .brief = "Sets cli silent",
        .desc = "When set to true no output is printed.",
        .options = NULL
    },
    {
        .cmd = "log",
        .usage = "log [<OPTIONS>] true|false",
        .brief = "Enables or disables logging",
        .desc = "Enables or disables logging.\n"
            "Available options:\n"
            "\t-o --output Enables/disables output logging.\n"
            "\t-m --msg    Enables/disables messages logging.\n",
        .options = cmd_log_opts
    },
    {
        .cmd = "prompt",
        .usage = "prompt <TEXT>",
        .brief = "Changes the prompt.",
        .desc = "<TEXT> can be any text.\n"
            "Environment variables can be used '$(<ENV VAR>)'.\n"
            "Internal variables can be used '${<VAR>}'.",
        .options = NULL
    },
    {
        .cmd = "alias",
        .usage = "alias [<ALIAS> [<CMD>]]",
        .brief = "Defines an alias.",
        .desc = "<ALIAS> the alias name.\n"
            "<CMD> the command.\n"
            "Without arguments prints all aliases.\n"
            "Without <CMD> prints the alias.\n"
            "Defines an alias, an alias is a short cut to a command."
            "Multiple commands can be set, separated with ';'.",
        .options = NULL
    },
    {
        .cmd = "variable",
        .usage = "variable [<VARIABLE>]",
        .brief = "Prints variable(s) value.",
        .desc = "Whithout any arguments prints all variables.\n"
            "With variable name prints the value of that variable.\n",
        .options = NULL
    },
    {
        .cmd = "variable",
        .usage = "variable <VARIABLE> = <VALUE>",
        .brief = "Creates variable or changes a variable value.",
        .desc = "The value can be:\n"
            "An array, example [ 1,2,3 ]\n"
            "A table, example { key1 = 1, key2 = 2, key3 = 3 }\n"
            "Or any primitive value.\n"
            "Values in tables or arrays can be any primitive value or "
            "any composite value.\n"
            "It is recommended to put strings between double or single quotes.\n"
            "Numbers (integers) can be noted in hexadecimal notation when"
            "prefixed with 0x or octal notation when staterd with 0.\n"
            "Date/time must be noted in RFC3399 compliant notation.\n",
        .options = NULL
    },
    { NULL, NULL, NULL, NULL, NULL },
};

static void mod_amx_dump_aliases(amxt_tty_t* tty) {
    amxc_var_t* aliases = amx_cli_get_aliases();
    amxc_array_t* keys = amxc_htable_get_sorted_keys(&aliases->data.vm);
    size_t count = amxc_array_size(keys);

    for(size_t index = 0; index < count; index++) {
        amxc_array_it_t* it = amxc_array_get_at(keys, index);
        const char* alias = (const char*) amxc_array_it_get_data(it);
        const char* cmds = GET_CHAR(aliases, alias);
        amxt_tty_writef(tty, "${color.white}%s${color.reset} = %s\n", alias, cmds);
    }

    amxc_array_delete(&keys, NULL);
}

static void mod_amx_dump_variable(amxt_tty_t* tty, amxc_var_t* variables) {
    const amxc_htable_t* table = amxc_var_constcast(amxc_htable_t, variables);
    amxc_array_t* names = amxc_htable_get_sorted_keys(table);
    size_t count = amxc_array_size(names);

    for(size_t i = 0; i < count; i++) {
        const char* name = (const char*) amxc_array_get_data_at(names, i);
        amxc_var_t* variable = GET_ARG(variables, name);
        amxt_tty_writef(tty, "${color.green}%s = ${color.reset}", name);
        fflush(stdout);
        amxc_var_dump(variable, STDOUT_FILENO);
        amxt_tty_writef(tty, "${color.reset}");
    }

    amxc_array_delete(&names, NULL);
}

static amxc_var_t* mod_amx_search_variable(amxc_string_t* full_name,
                                           amxc_string_t* name,
                                           amxc_var_t* root,
                                           amxc_var_t* parts) {
    char* part = NULL;
    amxc_var_t* var = root;

    amxt_cmd_triml(parts, ' ');
    part = amxt_cmd_pop_part(parts);
    while(part != NULL && part[0] != '=') {
        if(part[0] == '.') {
            if(!amxt_is_valid_name(amxc_string_get(name, 0))) {
                var = NULL;
                goto exit;
            }
            var = amxc_var_get_path(var, amxc_string_get(name, 0), AMXC_VAR_FLAG_DEFAULT);
            if(var == NULL) {
                goto exit;
            }
            amxc_string_appendf(full_name, "%s.", amxc_string_get(name, 0));
            amxc_string_reset(name);
        } else {
            amxc_string_appendf(name, "%s", part);
        }
        free(part);
        amxt_cmd_triml(parts, ' ');
        part = amxt_cmd_pop_part(parts);
    }

    if(((part != NULL) && (part[0] == '=')) || (!amxc_string_is_empty(name))) {
        if(!amxt_is_valid_name(amxc_string_get(name, 0))) {
            var = NULL;
            goto exit;
        }
        amxc_var_t* tmp = amxc_var_get_path(var,
                                            amxc_string_get(name, 0),
                                            AMXC_VAR_FLAG_DEFAULT);
        if(tmp != NULL) {
            amxc_string_appendf(full_name, "%s", amxc_string_get(name, 0));
            amxc_string_reset(name);
            var = tmp;
        }
        if(part != NULL) {
            amxt_cmd_prepend_part(parts, part);
        }
    }

exit:
    free(part);
    return var;
}

static amxc_var_t* mod_amx_get_variable(amxc_string_t* full_name,
                                        amxc_string_t* name,
                                        amxc_var_t* root,
                                        amxc_var_t* parts) {
    amxc_var_t* var = mod_amx_search_variable(full_name, name, root, parts);

    if(amxc_string_text_length(name) != 0) {
        amxc_var_t* temp = NULL;
        switch(amxc_var_type_of(var)) {
        case AMXC_VAR_ID_LIST: {
            int64_t index = atoll(amxc_string_get(name, 0));
            int64_t size = amxc_llist_size(amxc_var_constcast(amxc_llist_t, var));
            amxc_var_new(&temp);
            amxc_var_set_index(var, index > size ? -1 : index, temp, AMXC_VAR_FLAG_DEFAULT);
        }
        break;
        case AMXC_VAR_ID_HTABLE:
            temp = GET_ARG(var, amxc_string_get(name, 0));
            if(temp == NULL) {
                amxc_var_new(&temp);
                amxc_var_set_key(var, amxc_string_get(name, 0), temp, AMXC_VAR_FLAG_DEFAULT);
            }

            amxc_string_appendf(full_name, "%s", amxc_string_get(name, 0));
            break;
        }
        var = temp;
        amxc_string_reset(name);
    }

    return var;
}

static int mod_amx_cmd_help(UNUSED const char* function_name,
                            amxc_var_t* args,
                            UNUSED amxc_var_t* ret) {
    amxt_tty_t* tty = GET_TTY(args);
    amxc_var_t* var_cmd = GET_ARG(args, "cmd");
    char* cmd = amxt_cmd_pop_word(var_cmd);

    amxt_cmd_print_help(tty, help, cmd);

    free(cmd);
    return 0;
}

static int mod_amx_cmd_exit(UNUSED const char* function_name,
                            amxc_var_t* args,
                            UNUSED amxc_var_t* ret) {
    amxt_tty_t* tty = GET_TTY(args);
    amx_cli_el_stop(tty);
    return 0;
}

static int mod_amx_cmd_silent(UNUSED const char* function_name,
                              amxc_var_t* args,
                              UNUSED amxc_var_t* ret) {
    amxt_tty_t* tty = GET_TTY(args);
    amxc_var_t* var_cmd = GET_ARG(args, "cmd");
    amxc_var_t flag;
    int rv = 0;

    amxc_var_init(&flag);
    rv = amxt_cmd_parse_values(tty, var_cmd, AMXT_VP_PRIMITIVE, &flag);
    if(rv != 0) {
        amxt_tty_errorf(tty, "Invalid value\n");
        rv = -1;
        goto exit;
    }

    if(amxc_var_type_of(&flag) != AMXC_VAR_ID_BOOL) {
        amxt_tty_errorf(tty, "Invalid value\n");
        rv = -1;
        goto exit;
    }

    amxt_tty_silent(tty, amxc_var_constcast(bool, &flag));

exit:
    amxc_var_clean(&flag);
    return rv;
}

static int mod_amx_cmd_log(UNUSED const char* function_name,
                           amxc_var_t* args,
                           UNUSED amxc_var_t* ret) {
    amxt_tty_t* tty = GET_TTY(args);
    amxc_var_t* var_cmd = GET_ARG(args, "cmd");
    int rv = -1;
    amxc_var_t options;
    amxc_var_t boolean;
    uint32_t flags = 0;
    amxc_var_init(&options);
    amxc_var_init(&boolean);

    rv = amxt_cmd_parse_options(tty, var_cmd, &options, help[CMD_LOG].options);
    when_failed(rv, exit);

    rv = amxt_cmd_parse_values(tty, var_cmd, AMXT_VP_PRIMITIVE, &boolean);
    if(rv != 0) {
        goto exit;
    }

    if(amxc_var_is_null(&boolean)) {
        amxt_tty_errorf(tty, "Missing argument\n");
        rv = -1;
        goto exit;
    }

    flags |= (GET_BOOL(&options, "o") || GET_BOOL(&options, "output")) ? AMXT_LOG_OUTPUT : 0;
    flags |= (GET_BOOL(&options, "m") || GET_BOOL(&options, "msg")) ? AMXT_LOG_MSG : 0;

    if(flags == 0) {
        amxt_tty_errorf(tty, "At least one option must be specified\n");
        rv = -1;
        goto exit;
    }

    amxt_log_enable(tty, flags, amxc_var_dyncast(bool, &boolean));

exit:
    amxc_var_clean(&options);
    amxc_var_clean(&boolean);
    return rv;
}

static int mod_amx_cmd_prompt(UNUSED const char* function_name,
                              amxc_var_t* args,
                              UNUSED amxc_var_t* ret) {
    amxt_tty_t* tty = GET_TTY(args);
    amxc_var_t* var_cmd = GET_ARG(args, "cmd");
    amxc_string_t prompt;
    const char* sep = "";
    char* word = amxt_cmd_pop_word(var_cmd);

    amxc_string_init(&prompt, 0);
    while(word) {
        amxc_string_appendf(&prompt, "%s%s", sep, word);
        sep = " ";
        free(word);
        word = amxt_cmd_pop_word(var_cmd);
    }
    amxc_string_appendf(&prompt, " ");

    amxt_tty_set_prompt(tty, amxc_string_get(&prompt, 0));

    free(word);
    amxc_string_clean(&prompt);
    return 0;
}

static int mod_amx_cmd_alias(UNUSED const char* function_name,
                             amxc_var_t* args,
                             UNUSED amxc_var_t* ret) {
    amxt_tty_t* tty = GET_TTY(args);
    amxc_var_t* var_cmd = GET_ARG(args, "cmd");
    char* word = NULL;
    char* alias = NULL;
    const char* sep = "";
    amxc_string_t cmd;
    int retval = -1;

    amxc_string_init(&cmd, 0);

    if(amxt_cmd_is_empty(var_cmd)) {
        mod_amx_dump_aliases(tty);
        retval = 0;
        goto exit;
    }

    alias = amxt_cmd_pop_word(var_cmd);
    if((alias == NULL) || (*alias == 0) || !amxt_is_valid_name(alias)) {
        amxt_tty_errorf(tty, "Invalid alias name [%s]\n", alias);
        goto exit;
    }

    word = amxt_cmd_pop_word(var_cmd);
    while(word != NULL) {
        amxc_string_appendf(&cmd, "%s%s", sep, word);
        free(word);
        sep = " ";
        word = amxt_cmd_pop_word(var_cmd);
    }
    free(word);

    if(amxc_string_is_empty(&cmd)) {
        amxc_var_t* aliases = amx_cli_get_aliases();
        amxc_var_t* a = GET_ARG(aliases, alias);
        amxc_var_delete(&a);
    } else {
        amx_cli_set_alias(alias, amxc_string_get(&cmd, 0));
    }

    retval = 0;

exit:
    amxc_string_clean(&cmd);
    free(alias);
    return retval;
}

static int mod_amx_cmd_variable(UNUSED const char* function_name,
                                amxc_var_t* args,
                                UNUSED amxc_var_t* ret) {
    amxt_tty_t* tty = GET_TTY(args);
    amxc_var_t* var_cmd = GET_ARG(args, "cmd");
    amxc_string_t var_name;
    amxc_string_t name;
    amxc_var_t* option = &tty->config;
    amxc_var_t temp;
    int retval = -1;
    char* part = NULL;

    amxc_string_init(&var_name, 0);
    amxc_string_init(&name, 0);
    amxc_var_init(&temp);

    // no arguments - dump all variables
    if(amxt_cmd_is_empty(var_cmd)) {
        mod_amx_dump_variable(tty, option);
        amxt_tty_writef(tty, "\n");
        retval = 0;
        goto exit;
    }

    option = mod_amx_get_variable(&var_name, &name, option, var_cmd);
    if(option == NULL) {
        amxt_tty_errorf(tty, "Variable not found or invalid name [%s] \n", amxc_string_get(&var_name, 0));
        goto exit;
    }

    // only variable name - dump variable
    if(amxt_cmd_is_empty(var_cmd)) {
        if(amxc_var_is_null(option)) {
            amxc_var_delete(&option);
            amxt_tty_errorf(tty, "Variable not found [%s]\n", amxc_string_get(&var_name, 0));
            goto exit;
        }
        amxt_tty_writef(tty, "${color.white}%s${color.reset} = ", amxc_string_get(&var_name, 0));
        amxc_var_dump(option, STDOUT_FILENO);
        retval = 0;
        goto exit;
    }

    // more arguments - <var> = <value>
    amxt_cmd_triml(var_cmd, ' ');
    part = amxt_cmd_pop_part(var_cmd);
    free(part);
    // no value, delete
    if(amxt_cmd_is_empty(var_cmd)) {
        amxc_var_delete(&option);
        amxt_tty_messagef(tty, "Variable [%s] removed\n", amxc_string_get(&var_name, 0));
        retval = 0;
        goto exit;
    }

    amxt_cmd_triml(var_cmd, ' ');
    amxc_var_set_type(option, AMXC_VAR_ID_NULL);
    amxt_cmd_parse_values(tty, var_cmd,
                          AMXT_VP_ARRAY | AMXT_VP_TABLE |
                          AMXT_VP_COMPOSITE | AMXT_VP_PRIMITIVE,
                          option);
    amxp_sigmngr_trigger_signal(NULL, "config:changed", NULL);

    retval = 0;
exit:
    amxc_var_clean(&temp);
    amxc_string_clean(&name);
    amxc_string_clean(&var_name);
    return retval;
}

static int mod_amx_complete_cmd_help(UNUSED const char* function_name,
                                     amxc_var_t* args,
                                     amxc_var_t* ret) {
    amxt_tty_t* tty = amx_cli_get_tty();
    amxt_cmd_complete_help(args, help, ret);
    amxp_sigmngr_emit_signal(tty->sigmngr, "tty:docomplete", ret);
    amxc_var_delete(&ret);
    return 0;
}

int mod_amx_complete_cmd_variable(UNUSED const char* function_name,
                                  amxc_var_t* args,
                                  amxc_var_t* words) {
    amxc_string_t var_name;
    amxc_string_t name;
    amxt_tty_t* tty = amx_cli_get_tty();
    amxc_var_t* var = NULL;

    amxc_string_init(&var_name, 0);
    amxc_string_init(&name, 0);

    var = mod_amx_search_variable(&var_name, &name, &tty->config, args);

    switch(amxc_var_type_of(var)) {
    case AMXC_VAR_ID_LIST:
        break;
    case AMXC_VAR_ID_HTABLE: {
        const amxc_htable_t* tvars = amxc_var_constcast(amxc_htable_t, var);
        size_t len = amxc_string_text_length(&name);
        size_t pos = amxc_string_text_length(&var_name);
        const char* txt = amxc_string_get(&name, 0);
        amxc_htable_for_each(it, tvars) {
            const char* key = amxc_htable_it_get_key(it);
            if(( txt == NULL) || ( strncmp(txt, key, len) == 0)) {
                amxc_string_appendf(&var_name, "%s", key);
                amxc_var_add(cstring_t, words, amxc_string_get(&var_name, 0));
                amxc_string_remove_at(&var_name, pos, strlen(key));
            }
        }
    }
    break;
    }
    amxp_sigmngr_emit_signal(tty->sigmngr, "tty:docomplete", words);

    amxc_var_delete(&words);
    amxc_string_clean(&name);
    amxc_string_clean(&var_name);
    return 0;
}

static int mod_amx_complete_cmd_alias(UNUSED const char* function_name,
                                      amxc_var_t* args,
                                      amxc_var_t* words) {
    amxc_string_t alias_name;
    char* part = NULL;
    amxt_tty_t* tty = amx_cli_get_tty();

    amxc_string_init(&alias_name, 0);

    amxt_cmd_triml(args, ' ');
    part = amxt_cmd_pop_part(args);
    while(part != NULL) {
        amxc_string_appendf(&alias_name, "%s", part);
        free(part);
        amxt_cmd_triml(args, ' ');
        part = amxt_cmd_pop_part(args);
    }

    if(part == NULL) {
        amxc_var_t* aliases = amx_cli_get_aliases();
        amxc_array_t* keys = amxc_htable_get_sorted_keys(&aliases->data.vm);
        size_t count = amxc_array_size(keys);
        const char* txt = amxc_string_get(&alias_name, 0);
        size_t len = amxc_string_text_length(&alias_name);

        for(size_t index = 0; index < count; index++) {
            amxc_array_it_t* it = amxc_array_get_at(keys, index);
            const char* alias = (const char*) amxc_array_it_get_data(it);
            if(len == strlen(alias)) {
                continue;
            }
            if((txt == NULL) || (strncmp(txt, alias, len) == 0)) {
                amxc_var_add(cstring_t, words, alias);
            }
        }

        amxc_array_delete(&keys, NULL);
    }
    amxp_sigmngr_emit_signal(tty->sigmngr, "tty:docomplete", words);

    amxc_var_delete(&words);
    free(part);
    amxc_string_clean(&alias_name);
    return 0;
}

static int mod_amx_describe(UNUSED const char* function_name,
                            UNUSED amxc_var_t* args,
                            amxc_var_t* ret) {
    amxc_var_set(cstring_t, ret, MOD_DESC);
    return 0;
}

static AMXM_CONSTRUCTOR mod_amx_init(void) {
    amxm_module_t* mod = NULL;
    amxm_shared_object_t* so = amxm_get_so("self");

    if(so == NULL) {
        printf("No self\n");
        return 1;
    }

    if(amxm_module_register(&mod, so, MOD) != 0) {
        printf("Couldnt create module\n");
        return 1;
    }

    amxp_sigmngr_add_signal(NULL, "config:changed");

    amxm_module_add_function(mod, "help", mod_amx_cmd_help);
    amxm_module_add_function(mod, "exit", mod_amx_cmd_exit);
    amxm_module_add_function(mod, "silent", mod_amx_cmd_silent);
    amxm_module_add_function(mod, "log", mod_amx_cmd_log);
    amxm_module_add_function(mod, "prompt", mod_amx_cmd_prompt);
    amxm_module_add_function(mod, "alias", mod_amx_cmd_alias);
    amxm_module_add_function(mod, "variable", mod_amx_cmd_variable);

    // completion functions
    amxm_module_add_function(mod, "__complete_help", mod_amx_complete_cmd_help);
    amxm_module_add_function(mod, "__complete_variable", mod_amx_complete_cmd_variable);
    amxm_module_add_function(mod, "__complete_alias", mod_amx_complete_cmd_alias);

    // description
    amxm_module_add_function(mod, "__describe", mod_amx_describe);

    return 0;
}

static AMXM_DESTRUCTOR mod_record_cleanup(void) {
    return 0;
}
