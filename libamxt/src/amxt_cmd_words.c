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


char* amxt_cmd_pop_word(amxc_var_t* parts) {
    amxc_string_t word;
    bool done = false;
    char* txt = NULL;
    int brackets = 0;

    amxc_string_init(&word, 0);
    when_null(parts, exit);
    when_true(amxc_var_type_of(parts) != AMXC_VAR_ID_LIST, exit);
    amxt_cmd_triml(parts, ' ');

    amxc_var_for_each(part, parts) {
        const char* str_part = amxc_var_constcast(cstring_t, part);
        if(strlen(str_part) == 1) {
            switch(str_part[0]) {
            case '"':
            case '\'':
                amxc_var_delete(&part);
                continue;
                break;
            case '[':
            case '{':
            case '(':
                brackets++;
                break;
            case ']':
            case '}':
            case ')':
                brackets--;
                break;
            case ' ':
                if(brackets == 0) {
                    done = true;
                }
                break;
            }
        }
        if(done) {
            amxc_var_delete(&part);
            break;
        }
        amxc_string_appendf(&word, "%s", str_part);
        amxc_var_delete(&part);
    }

exit:
    txt = amxc_string_take_buffer(&word);
    amxc_string_clean(&word);
    return txt;
}

char* amxt_cmd_take_last_word(amxc_var_t* parts) {
    amxc_string_t word;
    bool done = false;
    char* txt = NULL;
    int brackets = 0;

    amxc_string_init(&word, 0);
    when_null(parts, exit);
    when_true(amxc_var_type_of(parts) != AMXC_VAR_ID_LIST, exit);

    amxc_var_for_each_reverse(part, parts) {
        const char* str_part = amxc_var_constcast(cstring_t, part);
        if(strlen(str_part) == 1) {
            switch(str_part[0]) {
            case '"':
            case '\'':
                amxc_var_delete(&part);
                continue;
                break;
            case '[':
            case '{':
            case '(':
                if(brackets == 0) {
                    done = true;
                } else {
                    brackets--;
                }
                break;
            case ']':
            case '}':
            case ')':
                brackets++;
                break;
            case ' ':
                if(brackets == 0) {
                    done = true;
                }
                break;
            }
        }
        if(done) {
            amxc_var_delete(&part);
            break;
        }
        amxc_string_prependf(&word, "%s", str_part);
        amxc_var_delete(&part);
    }

exit:
    txt = amxc_string_take_buffer(&word);
    amxc_string_clean(&word);
    return txt;
}

uint32_t amxt_cmd_last_word_size(amxc_var_t* parts) {
    uint32_t size = 0;
    amxc_string_t word;
    bool done = false;
    int brackets = 0;

    amxc_string_init(&word, 0);
    when_null(parts, exit);
    when_true(amxc_var_type_of(parts) != AMXC_VAR_ID_LIST, exit);

    amxc_var_for_each_reverse(part, parts) {
        const char* str_part = amxc_var_constcast(cstring_t, part);
        if(strlen(str_part) == 1) {
            switch(str_part[0]) {
            case '"':
            case '\'':
                continue;
                break;
            case '[':
            case '{':
            case '(':
                if(brackets == 0) {
                    done = true;
                } else {
                    brackets--;
                }
                break;
            case ']':
            case '}':
            case ')':
                brackets++;
                break;
            case ' ':
                if(brackets == 0) {
                    done = true;
                }
                break;
            }
        }
        if(done) {
            break;
        }
        amxc_string_appendf(&word, "%s", str_part);
    }

exit:
    size = amxc_string_text_length(&word);
    amxc_string_clean(&word);
    return size;
}

uint32_t amxt_cmd_count_words(amxc_var_t* parts) {
    int brackets = 0;
    uint32_t count = 0;

    when_null(parts, exit);
    when_true(amxc_var_type_of(parts) != AMXC_VAR_ID_LIST, exit);
    amxt_cmd_triml(parts, ' ');
    when_true(amxc_llist_is_empty(&parts->data.vl), exit);

    count = 1;
    amxc_var_for_each(part, parts) {
        const char* str_part = amxc_var_constcast(cstring_t, part);
        if(strlen(str_part) == 1) {
            switch(str_part[0]) {
            case '[':
            case '{':
            case '(':
                brackets++;
                break;
            case ']':
            case '}':
            case ')':
                brackets--;
                break;
            case ' ':
                if(brackets == 0) {
                    count++;
                }
                break;
            }
        }
    }

exit:
    return count;
}
