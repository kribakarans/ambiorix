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
#include <stdarg.h>
#include <string.h>
#include <ctype.h>

#include <amxc/amxc_variant.h>
#include <amxc/amxc_string.h>
#include <amxc/amxc_utils.h>
#include <amxc/amxc_macros.h>

typedef void (* amxc_string_replace_cb_t) (amxc_string_t* const string,
                                           size_t pos,
                                           size_t length,
                                           const char* txt,
                                           const void* priv);

static void amxc_string_resolve_replace_env(amxc_string_t* const string,
                                            size_t pos,
                                            size_t length,
                                            const char* txt,
                                            UNUSED const void* priv) {
    char* value = getenv(txt);
    amxc_string_remove_at(string, pos, length);
    if(value) {
        amxc_string_insert_at(string, pos, value, strlen(value));
    }
}

static void amxc_string_resolve_replace_var(amxc_string_t* const string,
                                            size_t pos,
                                            size_t length,
                                            const char* txt,
                                            const void* priv) {
    amxc_var_t* data = (amxc_var_t*) priv;
    char* value = amxc_var_dyncast(cstring_t,
                                   amxc_var_get_path(data,
                                                     txt,
                                                     AMXC_VAR_FLAG_DEFAULT));
    amxc_string_remove_at(string, pos, length);
    if(value) {
        amxc_string_insert_at(string, pos, value, strlen(value));
    }
    free(value);

}

static int amxc_string_generic_resolve(amxc_string_t* const string,
                                       const char* start_string,
                                       const char* end_string,
                                       amxc_string_replace_cb_t fn,
                                       const void* priv) {
    int retval = 0;
    size_t start_length = strlen(start_string);
    size_t end_length = strlen(end_string);
    size_t start = 0;
    size_t end = 0;

    for(size_t i = 0; i < string->last_used;) {
        if(strncmp(string->buffer + i, start_string, start_length) != 0) {
            i++;
            continue;
        }
        if((i > 0) && (string->buffer[i - 1] == '\\')) {
            i++;
            continue;
        }
        start = i;
        end = 0;
        i++;
        while(i + end_length <= string->last_used) {
            if(strncmp(string->buffer + i, end_string, end_length) == 0) {
                end = i + end_length;
                string->buffer[i] = 0;
                break;
            }
            i++;
        }
        if(i + end_length > string->last_used) {
            break;
        }
        fn(string,
           start,
           (end - start),
           string->buffer + start + start_length,
           priv);
        retval++;
        i = start;
    }

    return retval;
}

int amxc_string_resolve_env(amxc_string_t* const string) {
    int retval = 0;

    when_null(string, exit);
    when_true(amxc_string_is_empty(string), exit);

    retval = amxc_string_generic_resolve(string,
                                         "$(",
                                         ")",
                                         amxc_string_resolve_replace_env,
                                         NULL);

exit:
    return retval;
}

int amxc_string_resolve_var(amxc_string_t* const string,
                            const amxc_var_t* const data) {
    int retval = 0;

    when_null(string, exit);
    when_true(amxc_string_is_empty(string), exit);
    when_null(data, exit);
    when_true(amxc_var_type_of(data) != AMXC_VAR_ID_HTABLE, exit);

    retval = amxc_string_generic_resolve(string,
                                         "${",
                                         "}",
                                         amxc_string_resolve_replace_var,
                                         data);

exit:
    return retval;
}

int amxc_string_resolve_esc(amxc_string_t* const string) {
    int retval = 0;
    amxc_string_t resolved;
    size_t length = 0;
    char* buffer = NULL;

    amxc_string_init(&resolved, amxc_string_buffer_length(string));
    for(uint32_t i = 0; i < amxc_string_text_length(string); i++) {
        if(string->buffer[i] != '\\') {
            amxc_string_append(&resolved, string->buffer + i, 1);
            continue;
        }
        if(i + 1 >= amxc_string_text_length(string)) {
            amxc_string_append(&resolved, string->buffer, 1);
            break;
        }
        switch(string->buffer[i + 1]) {
        case 'n':
            amxc_string_append(&resolved, "\n", 1);
            i++;
            retval++;
            break;
        case 't':
            amxc_string_append(&resolved, "\t", 1);
            i++;
            retval++;
            break;
        default:
            amxc_string_append(&resolved, string->buffer + i + 1, 1);
            i++;
            retval++;
            break;
        }
    }

    length = amxc_string_buffer_length(&resolved);
    buffer = amxc_string_take_buffer(&resolved);
    amxc_string_push_buffer(string, buffer, length);

    amxc_string_clean(&resolved);
    return retval;
}

int amxc_string_esc(amxc_string_t* const string) {
    int retval = 0;

    retval += amxc_string_replace(string, "\\", "\\\\", UINT32_MAX);
    retval += amxc_string_replace(string, "(", "\\(", UINT32_MAX);
    retval += amxc_string_replace(string, ")", "\\)", UINT32_MAX);
    retval += amxc_string_replace(string, "{", "\\{", UINT32_MAX);
    retval += amxc_string_replace(string, "}", "\\}", UINT32_MAX);
    retval += amxc_string_replace(string, "\"", "\\\"", UINT32_MAX);
    retval += amxc_string_replace(string, "'", "\\'", UINT32_MAX);
    retval += amxc_string_replace(string, "\n", "\\n", UINT32_MAX);
    retval += amxc_string_replace(string, "\t", "\\t", UINT32_MAX);

    return retval;
}

int amxc_string_resolve(amxc_string_t* const string,
                        const amxc_var_t* const data) {
    int changes = 0;
    int total = 0;
    do {
        total += changes;
        changes = 0;
        changes += amxc_string_resolve_env(string);
        changes += amxc_string_resolve_var(string, data);
    } while(changes > 0);

    total += amxc_string_resolve_esc(string);

    return total;
}

int amxc_string_set_resolved(amxc_string_t* string,
                             const char* text,
                             const amxc_var_t* const data) {
    int retval = 0;
    size_t length = 0;
    size_t i = 0;

    when_null(text, exit);
    when_true(*text == 0, exit);
    when_null(string, exit);

    amxc_string_reset(string);
    length = strlen(text);
    for(i = 0; i < length; i++) {
        if(text[i] == '$') {
            break;
        }
    }

    if(i < length) {
        amxc_string_appendf(string, "%s", text);
        retval = amxc_string_resolve(string, data);
        if(retval == 0) {
            amxc_string_reset(string);
        }
    }

exit:
    return retval;
}

int amxc_string_new_resolved(amxc_string_t** string,
                             const char* text,
                             const amxc_var_t* const data) {
    int retval = -1;

    when_null(string, exit);
    when_failed(amxc_string_new(string, 0), exit);

    retval = amxc_string_set_resolved(*string, text, data);
    if(retval == 0) {
        amxc_string_delete(string);
    }

exit:
    return retval;
}

amxc_llist_it_t* amxc_llist_add_string(amxc_llist_t* const llist,
                                       const char* text) {
    amxc_llist_it_t* it = NULL;
    amxc_string_t* string = NULL;

    when_null(llist, exit);
    when_null(text, exit);

    when_failed(amxc_string_new(&string, 0), exit);
    when_failed(amxc_string_append(string, text, strlen(text)), exit);
    amxc_llist_append(llist, &string->it);

    it = &string->it;

exit:
    if(it == NULL) {
        amxc_string_delete(&string);
    }
    return it;
}

void amxc_string_list_it_free(amxc_llist_it_t* it) {
    amxc_string_t* part = amxc_string_from_llist_it(it);
    amxc_string_delete(&part);
}
