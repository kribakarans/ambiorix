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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>

#include <amxc/amxc.h>
#include <amxp/amxp.h>
#include <amxt/amxt_tty.h>
#include <amxt/amxt_cmd.h>

#include "amxt_priv.h"

static void amxt_cmd_build_path_file(amxc_var_t* parts,
                                     amxc_string_t* path,
                                     amxc_string_t* file) {
    // clean-up
    for(uint32_t count = amxt_cmd_count_separators(parts, ' ');
        count > 0;
        count--) {
        amxt_cmd_remove_until(parts, " ");
    }

    for(uint32_t count = amxt_cmd_count_separators(parts, '/');
        count > 0;
        count--) {
        amxc_string_join_var_until(path, parts, "", "/", true);
        amxc_string_append(path, "/", 1);
    }

    amxc_string_join_var(file, parts, "");

    if(amxc_string_is_empty(path)) {
        amxc_string_setf(path, "./");
    }
}

static void amxt_cmd_add_complete_options(const char* option,
                                          amxc_var_t* used_options,
                                          const char* options[],
                                          amxc_var_t* completed) {
    uint32_t index = 0;
    uint32_t len = option == NULL ? 0 : strlen(option);
    amxc_string_t comp;
    amxc_string_init(&comp, 16);
    while(options[index] != NULL) {
        uint32_t ol = strlen(options[index]);
        if(ol == 1) {
            index++;
            continue;
        }
        if(GET_ARG(used_options, options[index]) != NULL) {
            index++;
            continue;
        }
        amxc_string_setf(&comp, "--%s", options[index]);

        if(len > 0) {
            if(strncmp(option, options[index], len) == 0) {
                amxc_var_add(cstring_t, completed, amxc_string_get(&comp, 0));
            }
        } else {
            amxc_var_add(cstring_t, completed, amxc_string_get(&comp, 0));
        }
        index++;
    }
    amxc_string_clean(&comp);
}

int amxt_cmd_complete_path(UNUSED const char* const function_name,
                           amxc_var_t* parts,
                           amxc_var_t* completed) {
    DIR* dp;
    struct dirent* ep;
    amxc_string_t path;
    amxc_string_t filename;
    amxc_string_t comp_word;

    amxc_string_init(&path, 128);
    amxc_string_init(&filename, 64);
    amxc_string_init(&comp_word, 128);

    when_null(parts, exit);
    when_null(completed, exit);
    when_true(amxc_var_type_of(parts) != AMXC_VAR_ID_LIST, exit);
    when_true(amxc_var_type_of(completed) != AMXC_VAR_ID_LIST, exit);

    amxt_cmd_build_path_file(parts, &path, &filename);

    dp = opendir(amxc_string_get(&path, 0));
    when_null(dp, exit);

    for(ep = readdir(dp); ep; ep = readdir(dp)) {
        if((strcmp(ep->d_name, ".") == 0) ||
           ( strcmp(ep->d_name, "..") == 0)) {
            continue;
        }
        if(ep->d_type == DT_DIR) {
            amxc_string_setf(&comp_word, "%s%s/", amxc_string_get(&path, 0), ep->d_name);
        } else {
            amxc_string_setf(&comp_word, "%s%s", amxc_string_get(&path, 0), ep->d_name);
        }
        if(amxc_string_text_length(&filename) == 0) {
            amxc_var_add(cstring_t, completed, amxc_string_get(&comp_word, 0));
            continue;
        }
        if(strncmp(ep->d_name,
                   amxc_string_get(&filename, 0),
                   amxc_string_text_length(&filename)) == 0) {

            amxc_var_add(cstring_t, completed, amxc_string_get(&comp_word, 0));
        }
    }
    closedir(dp);

exit:
    amxc_string_clean(&comp_word);
    amxc_string_clean(&filename);
    amxc_string_clean(&path);
    return 0;
}

int amxt_cmd_complete_option(amxc_var_t* parts,
                             const char* options[],
                             amxc_var_t* completed) {
    bool stop = false;
    int option_type = 0;
    amxc_string_t option;
    const amxc_llist_t* lparts = amxc_var_constcast(amxc_llist_t, parts);
    amxc_var_t used_options;
    bool value = false;

    amxc_string_init(&option, 64);
    amxc_var_init(&used_options);

    when_null(parts, exit);
    when_null(options, exit);
    when_null(completed, exit);

    amxt_cmd_triml(parts, ' ');
    amxc_llist_for_each_reverse(it, lparts) {
        amxc_var_t* vpart = amxc_var_from_llist_it(it);
        const char* part = amxc_var_constcast(cstring_t, vpart);

        switch(part[0]) {
        case '=':
            value = true;
            stop = true;
            break;
        case '-':
            option_type++;
            break;
        case ' ':
            stop = true;
            break;
        default:
            if(option_type != 0) {
                while(option_type > 0) {
                    option_type--;
                    amxc_string_prepend(&option, "-", 1);
                }
            }
            amxc_string_prepend(&option, part, strlen(part));
            break;
        }
        if(stop) {
            break;
        }
    }

    if(((option_type > 0) && (option_type <= 2)) || amxt_cmd_is_empty(parts)) {
        const char* last = amxc_string_get(&option, 0);
        amxt_cmd_get_options(parts, &used_options, NULL);
        amxt_cmd_add_complete_options(last, &used_options, options, completed);
    } else {
        amxt_cmd_get_options(parts, &used_options, NULL);
    }

    if(value) {
        option_type = 4;
    } else if(option_type > 2) {
        option_type = 3;
    }

exit:
    amxc_string_clean(&option);
    amxc_var_clean(&used_options);
    return option_type;
}

void amxt_cmd_complete_help(amxc_var_t* parts,
                            amxt_cmd_help_t* help,
                            amxc_var_t* completed) {
    char* cmd = NULL;
    int len = 0;

    when_null(help, exit);
    when_null(completed, exit);

    cmd = amxt_cmd_take_last_word(parts);
    len = cmd == NULL ? 0 : strlen(cmd);

    for(int i = 0; help[i].cmd != NULL; i++) {
        if((cmd == NULL) || (strncmp(cmd, help[i].cmd, len) == 0)) {
            amxc_var_add(cstring_t, completed, help[i].cmd);
        }
    }

exit:
    free(cmd);
    return;
}
