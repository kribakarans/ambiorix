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
#include <errno.h>

#include "utils.h"
#include "colors.h"

static amxo_hooks_t ocg_hooks = {
    .it = { .next = NULL, .prev = NULL, .llist = NULL },
    .comment = ocg_comment_parse,
    .start = NULL,
    .end = NULL,
    .start_include = NULL,
    .end_include = NULL,
    .set_config = NULL,
    .start_section = NULL,
    .end_section = ocg_config_changed,
    .create_object = NULL,
    .add_instance = NULL,
    .select_object = NULL,
    .end_object = NULL,
    .add_param = NULL,
    .set_param = NULL,
    .end_param = NULL,
    .add_func = NULL,
    .add_func_arg = NULL,
    .end_func = NULL,
    .add_mib = NULL,
    .set_counter = NULL,
    .set_action_cb = NULL,
};

int main(int argc, char* argv[]) {
    int retval = 0;
    int index = 0;
    amxc_var_t config;
    amxo_parser_t parser;
    amxc_var_t* incodls = NULL;

    amxo_parser_init(&parser);
    amxc_var_init(&config);

    amxo_parser_set_hooks(&parser, &ocg_hooks);

    index = ocg_parse_arguments(&parser, &config, argc, argv);
    if(index == -1) {
        retval = 1;
        goto exit;
    }

    if(GET_BOOL(&config, "reset") && (GET_ARG(&config, "include-odls") != NULL)) {
        ocg_error(&config, "Options -r and -i are mutually exclusive\n");
        goto exit;
    }

    if(index >= argc) {
        ocg_error(&config, "Missing input files or directories\n");
        ocg_usage(argc, argv);
        retval = 1;
        goto exit;
    }

    retval = ocg_apply_config(&parser, &config);
    if(retval != 0) {
        goto exit;
    }
    retval = ocg_config_load(&parser);
    if(retval != 0) {
        goto exit;
    }
    ocg_config_changed(&parser, 0);

    ocg_message(&parser.config, "Collecting files ...");
    while(index < argc) {
        retval = ocg_add(&parser, argv[index++]);
        if(retval != 0) {
            goto exit;
        }
    }

    incodls = GET_ARG(&parser.config, "include-odls");
    if((incodls != NULL) && (amxc_var_type_of(incodls) == AMXC_VAR_ID_LIST)) {
        amxc_var_for_each(file, incodls) {
            retval = ocg_add_include(&parser, amxc_var_constcast(cstring_t, file));
            if(retval != 0) {
                goto exit;
            }
        }
    }
    ocg_message(&parser.config, "");
    ocg_message(&parser.config, "Building include tree ...");
    ocg_build_include_tree(&parser.config);
    ocg_dump_include_tree(&parser.config, NULL, 0);
    ocg_dump_files_list(&parser.config);

    ocg_message(&parser.config, "");
    ocg_message(&parser.config, "Run generators ...");
    retval = ocg_run(&parser);

exit:
    ocg_config_remove_generators(&parser);
    amxc_var_clean(&config);
    amxo_parser_clean(&parser);
    amxo_resolver_import_close_all();
    return retval;
}
