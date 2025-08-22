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


char* amxt_cmd_pop_part(amxc_var_t* parts) {
    char* txt = NULL;
    uint32_t size = 0;
    amxc_var_t* part = NULL;

    when_null(parts, exit);
    when_true(amxc_var_type_of(parts) != AMXC_VAR_ID_LIST, exit);
    when_true(amxc_llist_is_empty(&parts->data.vl), exit);

    part = amxc_var_from_llist_it(amxc_llist_get_first(&parts->data.vl));
    txt = amxc_var_take(cstring_t, part);
    size = strlen(txt);
    if((size == 1) && isspace(txt[0])) {
        txt[0] = 0;
    }

    amxc_var_delete(&part);

exit:
    return txt;
}

char* amxt_cmd_pop_parts_until(amxc_var_t* parts, const char separators[]) {
    char* word = NULL;
    amxc_string_t txt;
    size_t sep_count = separators == NULL ? 0 : strlen(separators);

    amxc_string_init(&txt, 0);
    when_null(parts, exit);
    when_true(amxc_var_type_of(parts) != AMXC_VAR_ID_LIST, exit);

    amxc_var_for_each(part, parts) {
        word = amxc_var_take(cstring_t, part);
        if(strlen(word) == 1) {
            for(size_t i = 0; i < sep_count; i++) {
                if(separators[i] == word[0]) {
                    free(word);
                    amxc_var_delete(&part);
                    goto exit;
                }
            }
        }
        amxc_string_appendf(&txt, "%s", word);
        free(word);
        word = NULL;
        amxc_var_delete(&part);
    }

exit:
    amxc_string_trim(&txt, NULL);
    word = amxc_string_take_buffer(&txt);
    amxc_string_clean(&txt);
    return word;
}


char* amxt_cmd_take_last_part(amxc_var_t* parts) {
    char* txt = NULL;
    uint32_t size = 0;
    amxc_var_t* part = NULL;

    when_null(parts, exit);
    when_true(amxc_var_type_of(parts) != AMXC_VAR_ID_LIST, exit);
    when_true(amxc_llist_is_empty(&parts->data.vl), exit);

    part = amxc_var_from_llist_it(amxc_llist_get_last(&parts->data.vl));
    txt = amxc_var_take(cstring_t, part);
    size = strlen(txt);
    if((size == 1) && isspace(txt[0])) {
        txt[0] = 0;
    }

    amxc_var_delete(&part);

exit:
    return txt;
}

uint32_t amxt_cmd_last_part_size(amxc_var_t* parts) {
    uint32_t size = 0;
    const char* txt = NULL;
    amxc_var_t* part = NULL;

    when_null(parts, exit);
    when_true(amxc_var_type_of(parts) != AMXC_VAR_ID_LIST, exit);
    when_true(amxc_llist_is_empty(&parts->data.vl), exit);

    part = amxc_var_from_llist_it(amxc_llist_get_last(&parts->data.vl));
    txt = amxc_var_constcast(cstring_t, part);
    size = strlen(txt);
    if((size == 1) && isspace(txt[0])) {
        size = 0;
    }

exit:
    return size;
}

uint32_t amxt_cmd_count_parts(amxc_var_t* parts) {
    uint32_t size = 0;

    when_null(parts, exit);
    when_true(amxc_var_type_of(parts) != AMXC_VAR_ID_LIST, exit);
    when_true(amxc_llist_is_empty(&parts->data.vl), exit);

    size = amxc_llist_size(&parts->data.vl);

exit:
    return size;
}

int amxt_cmd_prepend_part(amxc_var_t* parts, const char* word) {
    int retval = 0;
    amxc_var_t* new_word = NULL;

    when_null(parts, exit);
    when_true(amxc_var_type_of(parts) != AMXC_VAR_ID_LIST, exit);
    when_true(word == NULL || *word == 0, exit);

    amxc_var_new(&new_word);
    amxc_var_set(cstring_t, new_word, word);

    amxc_var_set_index(parts, 0, new_word, AMXC_VAR_FLAG_DEFAULT);

    retval = 0;

exit:
    return retval;
}

int amxt_cmd_append_part(amxc_var_t* parts, const char* word) {
    int retval = 0;

    when_null(parts, exit);
    when_true(amxc_var_type_of(parts) != AMXC_VAR_ID_LIST, exit);
    when_true(word == NULL || *word == 0, exit);

    amxc_var_add(cstring_t, parts, word);

    retval = 0;

exit:
    return retval;
}
