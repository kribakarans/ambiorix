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

#include <amxc/amxc.h>
#include <amxp/amxp.h>
#include <amxt/amxt_tty.h>
#include <amxt/amxt_variant.h>
#include <amxt/amxt_cmd.h>
#include <amxm/amxm.h>

#include <amxc/amxc_macros.h>

#define MOD "parser"
#define MOD_DESC "Parser shows some common cli functionalities"

#define CONSTRUCTOR __attribute__((constructor))
#define DESTRUCTOR __attribute__((destructor))

static amxt_cmd_help_t help[] = {
    {
        .cmd = "help",
        .usage = "help [<CMD>]",
        .brief = "Print this help",
        .desc = "Prints some help about the commands in this module.\n"
            "For more information about the supported commands use 'help <CMD>'"
            "This module supports:\n"
            "\tpecho\n"
            "\twecho\n",
        .options = NULL
    },
    {
        .cmd = "pecho",
        .usage = "pecho <TEXT>",
        .brief = "echo all command parts and return the number of parts",
        .desc = "A command can have arguments, this command prints all the parts of\n"
            "the arguments.\n"
            "A command part is either a text or a symbol.\n"
            "Spaces are skipped.\n",
        .options = NULL
    },
    {
        .cmd = "wecho",
        .usage = "wecho <TEXT>",
        .brief = "echo all command words and return the number of words",
        .desc = "A command can have arguments, this command prints all the words of\n"
            "arguments. Words are separated by spaces, leading and trailing spaces\n"
            "are not included.\n"
            "When a \" is encounter the word ends with the next \".\n"
            "Text between brackest [] or {} or () is also considered as one word,\n"
            "brackets are always included.",
        .options = NULL
    },
    { NULL, NULL, NULL, NULL, NULL },
};

typedef struct _cli_example {
    amxm_shared_object_t* me;
    amxt_tty_t* tty;
    amxc_var_t contacts;
    amxc_llist_t headers;
} cli_example_t;

static cli_example_t cli;

static amxt_tty_t* cli_example_get_tty(void) {
    return cli.tty;
}

static int mod_parser_cmd_help(UNUSED const char* function_name,
                               amxc_var_t* args,
                               UNUSED amxc_var_t* ret) {
    amxt_tty_t* tty = GET_TTY(args);
    amxc_var_t* var_cmd = GET_ARG(args, "cmd");
    char* cmd = amxt_cmd_pop_word(var_cmd);

    amxt_cmd_print_help(tty, help, cmd);

    free(cmd);
    return 0;
}

static int mod_parser_cmd_pecho(UNUSED const char* function_name,
                                amxc_var_t* args,
                                amxc_var_t* ret) {
    amxt_tty_t* tty = GET_TTY(args);
    amxc_var_t* cmd_parts = GET_ARG(args, "cmd");
    uint32_t count_parts = 0;

    char* txt = amxt_cmd_pop_part(cmd_parts);
    while(txt != NULL) {
        count_parts++;
        amxt_tty_writef(tty, "%s\n", txt);
        free(txt);
        txt = amxt_cmd_pop_part(cmd_parts);
    }
    amxt_tty_writef(tty, "\n");

    amxc_var_set(uint32_t, ret, count_parts);
    return 0;
}

static int mod_parser_cmd_wecho(UNUSED const char* function_name,
                                amxc_var_t* args,
                                amxc_var_t* ret) {
    amxt_tty_t* tty = GET_TTY(args);
    amxc_var_t* cmd_parts = GET_ARG(args, "cmd");
    uint32_t count_words = 0;

    char* word = amxt_cmd_pop_word(cmd_parts);
    while(word != NULL) {
        count_words++;
        amxt_tty_writef(tty, "%s\n", word);
        free(word);
        word = amxt_cmd_pop_word(cmd_parts);
    }
    amxt_tty_writef(tty, "\n");

    amxc_var_set(uint32_t, ret, count_words);
    return 0;
}

static int mod_parser_describe(UNUSED const char* function_name,
                               UNUSED amxc_var_t* args,
                               amxc_var_t* ret) {
    amxc_var_set(cstring_t, ret, MOD_DESC);
    return 0;
}

static int mod_parser_complete_cmd_help(UNUSED const char* function_name,
                                        amxc_var_t* args,
                                        amxc_var_t* ret) {
    amxt_tty_t* tty = cli_example_get_tty();

    amxt_cmd_complete_help(args, help, ret);
    amxp_sigmngr_emit_signal(tty->sigmngr, "tty:docomplete", ret);
    amxc_var_delete(&ret);

    return 0;
}

static int mod_parser_complete_echo(const char* function_name,
                                    UNUSED amxc_var_t* args,
                                    amxc_var_t* ret) {
    amxt_tty_t* tty = cli_example_get_tty();
    amxc_string_t txt;

    amxc_string_init(&txt, 64);
    amxc_string_setf(&txt, "${color.reset}%s <TEXT>", function_name + 11);
    amxc_var_set(cstring_t, ret, amxc_string_get(&txt, 0));
    amxc_string_clean(&txt);

    amxp_sigmngr_emit_signal(tty->sigmngr, "tty:docomplete", ret);
    amxc_var_delete(&ret);
    return 0;
}

static int CONSTRUCTOR mod_parser_start(void) {
    amxm_module_t* mod = NULL;
    cli.me = amxm_so_get_current();

    // parser commands
    amxm_module_register(&mod, cli.me, MOD);
    amxm_module_add_function(mod, "help", mod_parser_cmd_help);
    amxm_module_add_function(mod, "pecho", mod_parser_cmd_pecho);
    amxm_module_add_function(mod, "wecho", mod_parser_cmd_wecho);

    // parser tab completion functions
    amxm_module_add_function(mod, "__complete_help", mod_parser_complete_cmd_help);
    amxm_module_add_function(mod, "__complete_pecho", mod_parser_complete_echo);
    amxm_module_add_function(mod, "__complete_wecho", mod_parser_complete_echo);

    // parser describe
    amxm_module_add_function(mod, "__describe", mod_parser_describe);

    amxm_module_register(&mod, cli.me, "__dummy");

    return 0;
}