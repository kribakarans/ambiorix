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


bool amxt_cmd_is_empty(amxc_var_t* parts) {
    bool empty = true;

    when_null(parts, exit);
    when_true(amxc_var_type_of(parts) != AMXC_VAR_ID_LIST, exit);

    empty = amxc_llist_is_empty(&parts->data.vl);

exit:
    return empty;
}

void amxt_cmd_remove_until(amxc_var_t* parts, const char* marker) {
    char* word = NULL;

    when_null(parts, exit);
    when_str_empty(marker, exit);
    when_true(amxc_var_type_of(parts) != AMXC_VAR_ID_LIST, exit);

    amxc_var_for_each(part, parts) {
        word = amxc_var_take(cstring_t, part);
        amxc_var_delete(&part);
        if(strcmp(word, marker) == 0) {
            free(word);
            word = NULL;
            break;
        }
        free(word);
        word = NULL;
    }

exit:
    return;
}

void amxt_cmd_triml(amxc_var_t* parts, const char sep) {
    when_null(parts, exit);
    when_true(amxc_var_type_of(parts) != AMXC_VAR_ID_LIST, exit);

    amxc_var_for_each(part, parts) {
        const char* word = amxc_var_constcast(cstring_t, part);
        if((strlen(word) == 1) && (word[0] == sep)) {
            amxc_var_delete(&part);
        }
        break;
    }

exit:
    return;

}
void amxt_cmd_trimr(amxc_var_t* parts, const char sep) {
    when_null(parts, exit);
    when_true(amxc_var_type_of(parts) != AMXC_VAR_ID_LIST, exit);

    amxc_var_for_each_reverse(part, parts) {
        const char* word = amxc_var_constcast(cstring_t, part);
        if((strlen(word) == 1) && (word[0] == sep)) {
            amxc_var_delete(&part);
        }
        break;
    }

exit:
    return;

}

void amxt_cmd_trim(amxc_var_t* parts, const char sep) {
    amxt_cmd_triml(parts, sep);
    amxt_cmd_trimr(parts, sep);
}

uint32_t amxt_cmd_count_separators(amxc_var_t* parts, const char sep) {
    uint32_t count = 0;

    when_null(parts, exit);
    when_true(amxc_var_type_of(parts) != AMXC_VAR_ID_LIST, exit);

    amxc_var_for_each(part, parts) {
        const char* word = amxc_var_constcast(cstring_t, part);
        if((strlen(word) == 1) && (word[0] == sep)) {
            count++;
        }
    }

exit:
    return count;
}

int amxt_cmd_index(const char* cmd, amxt_cmd_help_t* help) {
    int len = 0;
    int index = -1;

    when_null(cmd, exit);
    when_null(help, exit);

    len = strlen(cmd);
    for(index = 0; help[index].cmd != NULL; index++) {
        if(strncmp(cmd, help[index].cmd, len) == 0) {
            break;
        }
    }

    if(help[index].cmd == NULL) {
        index = -1;
    }

exit:
    return index;
}

void amxt_cmd_print_help(amxt_tty_t* tty,
                         amxt_cmd_help_t* help,
                         const char* cmd) {
    int len = cmd == NULL ? 0 : strlen(cmd);

    when_null(tty, exit);
    when_null(help, exit);

    amxt_tty_writef(tty, "\n");
    for(int i = 0; help[i].cmd != NULL; i++) {
        if((cmd == NULL) || (strncmp(cmd, help[i].cmd, len) == 0)) {
            if(cmd != NULL) {
                amxt_tty_writef(tty, "%s\n", help[i].brief);
                amxt_tty_writef(tty, "Usage: %s\n\n", help[i].usage);
                amxt_tty_writef(tty, "%s\n", help[i].desc);
            } else {
                amxt_tty_writef(tty, "${color.white}%s${color.reset}\n\t%s\n\n",
                                help[i].usage, help[i].brief);
            }
        }
    }

exit:
    return;
}

void amxt_cmd_error_excess(amxt_tty_t* tty,
                           amxc_var_t* args,
                           const char* usage) {
    char* input = amxt_cmd_take_all(args);

    when_null(tty, exit);
    when_null(args, exit);

    amxt_tty_errorf(tty, "Too many arguments - [%s]\n", input);
    if(usage != NULL) {
        amxt_tty_messagef(tty, "Usage: %s\n", usage);
    }

exit:
    free(input);
}