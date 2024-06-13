/****************************************************************************
**
** SPDX-License-Identifier: BSD-2-Clause-Patent
**
** SPDX-FileCopyrightText: Copyright (c) 2022 SoftAtHome
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

#include "amxo_xml_to_assert.h"
#include "amxo_xml_to.h"

static void args_parser_option(amxc_var_t* config, const char* option) {
    amxc_string_t str_option;
    amxc_llist_t options;
    amxc_string_t* name = NULL;
    amxc_string_t* value = NULL;
    amxc_var_t* var_option = NULL;

    amxc_llist_init(&options);
    amxc_string_init(&str_option, 0);
    amxc_string_set(&str_option, option);
    amxc_string_split_to_llist(&str_option, &options, '=');
    when_true(amxc_llist_is_empty(&options), leave);
    when_true(amxc_llist_size(&options) != 2, leave);

    name = amxc_string_from_llist_it(amxc_llist_get_first(&options));
    value = amxc_string_from_llist_it(amxc_llist_get_last(&options));

    amxc_string_trim(name, NULL);
    amxc_string_trim(value, NULL);

    var_option = GET_ARG(config, amxc_string_get(name, 0));
    if(var_option == NULL) {
        amxc_var_add_key(cstring_t,
                         config,
                         amxc_string_get(name, 0),
                         amxc_string_get(value, 0));
    } else {
        amxc_var_set(cstring_t, var_option, amxc_string_get(value, 0));
    }

leave:
    amxc_string_clean(&str_option);
    amxc_llist_clean(&options, amxc_string_list_it_free);
    return;
}

static void print_usage_option(const char* so,
                               const char* lo,
                               const char* args,
                               const char* description) {
    int pre_length = 4 + 2 + 4 + strlen(lo);
    printf("    %s    %s", so, lo);
    if(args != NULL) {
        pre_length += 3 + strlen(args);
        printf(" <%s>", args);
    }
    for(int i = 35 - pre_length; i > 0; i--) {
        printf(" ");
    }
    printf("%s\n", description);
}

void amxo_xml_print_usage(UNUSED int argc, char* argv[]) {
    printf("%s [OPTIONS] <xml files>\n", argv[0]);

    printf("\n");
    printf("Options:\n");
    printf("\n");
    print_usage_option("-h", "--help", NULL, "Print usage help");
    print_usage_option("-x", "--xsl", "xsl file", "Sets xsl file for convertion");
    print_usage_option("-o", "--option", "name=value", "Adds a configuration option");
    printf("\n");
}

void amxo_xml_print_error(const char* fmt, ...) {
    va_list args;

    fprintf(stderr, "ERROR -- ");

    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
}

int amxo_xml_args_parse_cmd(amxc_var_t* config, int argc, char** argv) {
    int c;

    while(1) {
        int option_index = 0;

        static struct option long_options[] = {
            {"help", no_argument, 0, 'h' },
            {"xsl", required_argument, 0, 'x' },
            {"option", required_argument, 0, 'o' },
            {0, 0, 0, 0 }
        };

        c = getopt_long(argc, argv, "hx:o:", long_options, &option_index);
        if(c == -1) {
            break;
        }

        switch(c) {
        case 'x': {
            amxc_var_t* xsl = GET_ARG(config, "xsl");
            if(xsl == NULL) {
                amxc_var_add_key(cstring_t, config, "xsl", optarg);
            } else {
                amxc_var_set(cstring_t, xsl, optarg);
            }
        }
        break;

        case 'o':
            args_parser_option(config, optarg);
            break;

        case 'h': {
            return -1;
        }
        break;

        default:
            amxo_xml_print_error("Argument not recognized - 0%x %c \n", c, c);
            return -1;
        }
    }

    return optind;
}
