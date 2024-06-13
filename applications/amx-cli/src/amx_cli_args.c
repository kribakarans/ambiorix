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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>

#include "amx_cli.h"

static void amx_cli_print_usage(char* argv[]) {
    printf("%s [OPTIONS] [COMMANDS]\n", argv[0]);

    printf("\n");
    printf("Options:\n");
    printf("\n");
    printf("\t-h          --help           Print usage help and exits.\n");
    printf("\t-H          --HELP           Shows available commands and exits.\n");
    printf("\t-u <role>   --user <role>    Enable ACL checking and use specified role.\n");
    printf("\t-j          --json           Set output format to JSON.\n");
    printf("\t-s <file>   --script <file>  Sets the initialization script.\n");
    printf("\t-a          --automated      Do not go in interactive mode.\n");
    printf("\t-l          --less           Do not repeat commands, only print values or json.\n");
    printf("\t--                           Indicates end of cli options.\n");
    printf("\n");
    printf("Use command '-H' to see available list of commands.\n");
}


int amx_cli_args_parse(cli_app_t* cli, int argc, char** argv, amxc_string_t* cmds) {
    int c;
    amxc_var_t* script = amxt_tty_claim_config(cli->tty, "init-script");
    amxc_var_t* automated = amxt_tty_claim_config(cli->tty, "automated");
    amxc_var_t* less = amxt_tty_claim_config(cli->tty, "less");
    amxc_var_set(bool, automated, false);
    amxc_var_set(bool, less, false);

    while(1) {
        int option_index = 0;

        static struct option long_options[] = {
            {"help", no_argument, 0, 'h' },
            {"HELP", no_argument, 0, 'H' },
            {"user", required_argument, 0, 'u' },
            {"json", no_argument, 0, 'j' },
            {"script", required_argument, 0, 's' },
            {"less", no_argument, 0, 'l'},
            {"automated", no_argument, 0, 'a' },
            {0, 0, 0, 0 }
        };

        c = getopt_long(argc, argv, "hHu:js:al-",
                        long_options, &option_index);
        if((c == -1) || (c == '-')) {
            break;
        }

        switch(c) {
        case 'h':
            amx_cli_print_usage(argv);
            amxc_string_reset(cmds);
            return -1;

        case 'H':
            amxc_string_setf(cmds, "help;");
            return -1;

        case 'u':
            amxc_string_appendf(cmds, "!amx variable acl-enabled = true;");
            amxc_string_appendf(cmds, "!amx variable role = %s;", optarg);
            break;

        case 'j':
            amxc_string_appendf(cmds, "!amx variable output-format = json;");
            break;

        case 's':
            amxc_var_set(cstring_t, script, optarg);
            break;

        case 'l':
            amxc_var_set(bool, less, true);
            break;

        case 'a':
            amxc_var_set(bool, automated, true);
            break;

        default:
            amxc_string_reset(cmds);
            printf("Argument not recognized - 0x%x %c \n", c, c);
            return -1;
        }
    }

    if(((argc - optind) >= 1) || GET_BOOL(automated, NULL)) {
        amxc_var_set(bool, automated, true);
        cli->tty->interactive = false;
    }

    return optind;
}
