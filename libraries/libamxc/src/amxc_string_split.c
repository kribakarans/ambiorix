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
#include <string.h>
#include <ctype.h>

#include <amxc/amxc_common.h>
#include <amxc/amxc_variant.h>
#include <amxc/amxc_string_split.h>
#include <amxc/amxc_utils.h>
#include <amxc/amxc_macros.h>

/**
   @file
   @brief
   Ambiorix string API implementation
 */

typedef struct _string_word_flags {
    bool start_quote;
    bool between_double_quotes;
    bool between_single_quotes;
    bool escape;
    int round_brackets;
    int curly_brackets;
    int square_brackets;
} amxc_string_word_flags_t;

typedef int (* amxc_string_create_part_t) (const amxc_string_t* const string,
                                           amxc_llist_t* const list,
                                           const size_t start_pos,
                                           const size_t length);

typedef bool (* amxc_string_check_delimiter_t) (amxc_llist_t* list,
                                                const char delimiter);

static void amxc_trim_llist(amxc_llist_t* const list) {
    amxc_llist_for_each_reverse(it, list) {
        amxc_string_t* part = amxc_string_from_llist_it(it);
        if(amxc_string_text_length(part) != 1) {
            break;
        }
        if(isspace(part->buffer[0]) == 0) {
            break;
        }
        amxc_string_delete(&part);
    }

    while(true) {
        amxc_llist_it_t* first = amxc_llist_get_first(list);
        amxc_llist_it_t* last = amxc_llist_get_last(list);

        if((first != NULL) && (last != NULL)) {
            amxc_string_t* fpart = amxc_string_from_llist_it(first);
            amxc_string_t* lpart = amxc_string_from_llist_it(last);

            if((amxc_string_text_length(fpart) == 1) &&
               ( amxc_string_text_length(lpart) == 1)) {
                if((fpart->buffer[0] == '[') &&
                   ( lpart->buffer[0] == ']')) {
                    amxc_string_delete(&fpart);
                    amxc_string_delete(&lpart);
                    continue;
                }
            }
        }
        break;
    }
}

static int amxc_string_create_part(const amxc_string_t* const string,
                                   amxc_llist_t* const list,
                                   const size_t start_pos,
                                   const size_t length) {
    int retval = -1;
    amxc_string_t* part = NULL;
    char* buffer = NULL;

    buffer = amxc_string_dup(string, start_pos, length);
    when_null(buffer, exit);
    when_failed(amxc_string_new(&part, 0), exit);
    if((length == 1) && isspace(buffer[0])) {
        amxc_string_set_at(part, 0, buffer, 1, amxc_string_no_flags);
        free(buffer);
    } else {
        when_failed(amxc_string_push_buffer(part, buffer, length + 1), exit);
    }
    amxc_llist_append(list, &part->it);

    retval = 0;

exit:
    if(retval != 0) {
        free(buffer);
        amxc_string_delete(&part);
    }
    return retval;
}

static bool amxc_string_split_update_status(const amxc_string_t* const string,
                                            size_t i,
                                            amxc_string_word_flags_t* flags) {
    bool skip = false;
    if(string->buffer[i] == '\\') {
        flags->escape = true;
        skip = true;
    }
    flags->start_quote = false;
    if(!flags->between_single_quotes && (string->buffer[i] == '"')) {
        flags->between_double_quotes = !flags->between_double_quotes;
        flags->start_quote = flags->between_double_quotes;
    }
    if(!flags->between_double_quotes && (string->buffer[i] == '\'')) {
        flags->between_single_quotes = !flags->between_single_quotes;
        flags->start_quote = flags->between_single_quotes;
    }
    if(!(flags->between_double_quotes || flags->between_single_quotes)) {
        switch(string->buffer[i]) {
        case '(':
            flags->round_brackets++;
            break;
        case ')':
            flags->round_brackets--;
            break;
        case '{':
            flags->curly_brackets++;
            break;
        case '}':
            flags->curly_brackets--;
            break;
        case '[':
            flags->square_brackets++;
            break;
        case ']':
            flags->square_brackets--;
            break;
        }
    }

    return skip;
}

static amxc_string_split_status_t
amxc_string_split_word_is_valid(amxc_string_word_flags_t* flags,
                                const char** reason) {
    amxc_string_split_status_t retval = AMXC_STRING_SPLIT_OK;
    const char* msg = "";

    if(flags->between_double_quotes) {
        retval = AMXC_ERROR_STRING_MISSING_DQUOTE;
        msg = "Missing closing double quote - \"";
        goto exit;
    }
    if(flags->between_single_quotes) {
        retval = AMXC_ERROR_STRING_MISSING_SQUOTE;
        msg = "Missing closing single quote - '";
        goto exit;
    }
    if(flags->round_brackets > 0) {
        retval = AMXC_ERROR_STRING_MISSING_RBRACKET;
        msg = "Missing closing round bracket - )";
        goto exit;
    }
    if(flags->round_brackets < 0) {
        retval = AMXC_ERROR_STRING_MISSING_RBRACKET;
        msg = "Missing open round bracket - (";
        goto exit;
    }
    if(flags->curly_brackets > 0) {
        retval = AMXC_ERROR_STRING_MISSING_CBRACKET;
        msg = "Missing closing curly bracket - }";
        goto exit;
    }
    if(flags->curly_brackets < 0) {
        retval = AMXC_ERROR_STRING_MISSING_CBRACKET;
        msg = "Missing opening curly bracket - {";
        goto exit;
    }
    if(flags->square_brackets > 0) {
        retval = AMXC_ERROR_STRING_MISSING_SBRACKET;
        msg = "Missing closing square bracket - ]";
        goto exit;
    }
    if(flags->square_brackets < 0) {
        retval = AMXC_ERROR_STRING_MISSING_SBRACKET;
        msg = "Missing opening square bracket - [";
        goto exit;
    }

exit:
    if(reason != NULL) {
        *reason = msg;
    }
    return retval;
}

static bool amxc_need_to_add_delimiter(amxc_llist_t* list,
                                       const char delimiter) {
    bool retval = false;
    amxc_llist_it_t* it = amxc_llist_get_last(list);
    amxc_string_t* str_part = NULL;
    const char* part = NULL;

    if(it == NULL) {
        retval = (isspace(delimiter) == 0);
        goto exit;
    }

    str_part = amxc_string_from_llist_it(it);
    part = amxc_string_get(str_part, 0);

    retval = true;

    if(amxc_string_text_length(str_part) == 1) {
        if(isspace(part[0]) != 0) {
            if((isspace(delimiter) != 0) && (delimiter != '\n')) {
                retval = false;
            }
        }
    }

exit:
    return retval;
}

static amxc_string_split_status_t
amxc_string_split_words_internal(const amxc_string_t* const string,
                                 amxc_llist_t* list,
                                 amxc_string_create_part_t create,
                                 amxc_string_check_delimiter_t check,
                                 const char** reason) {
    amxc_string_word_flags_t flags;
    size_t start_pos = 0;
    size_t i = 0;
    amxc_string_split_status_t retval = AMXC_ERROR_STRING_SPLIT_INVALID_INPUT;

    flags.start_quote = false;
    flags.between_double_quotes = false;
    flags.between_single_quotes = false;
    flags.escape = false;
    flags.round_brackets = 0;
    flags.curly_brackets = 0;
    flags.square_brackets = 0;

    for(i = 0; i < string->last_used; i++) {
        if(flags.escape == false) {
            if(amxc_string_split_update_status(string, i, &flags) == true) {
                continue;
            }
        }

        flags.escape = false;

        if(((flags.between_double_quotes == false) &&
            (flags.between_single_quotes == false)) ||
           ( flags.start_quote == true)) {
            if(isspace(string->buffer[i])) {
                if(i - start_pos > 0) {
                    when_failed(create(string, list, start_pos, i - start_pos), exit);
                }
                if(check(list, string->buffer[i])) {
                    when_failed(create(string, list, i, 1), exit);
                }
                start_pos = i + 1;
                continue;
            }
            if(ispunct(string->buffer[i])) {
                if(i - start_pos > 0) {
                    when_failed(create(string, list, start_pos, i - start_pos), exit);
                }
                if(check(list, string->buffer[i])) {
                    when_failed(create(string, list, i, 1), exit);
                }
                start_pos = i + 1;
                continue;
            }
        }
    }

    if(i - start_pos != 0) {
        when_failed(create(string, list, start_pos, i - start_pos), exit);
    }

    retval = amxc_string_split_word_is_valid(&flags, reason);

exit:
    return retval;
}

static amxc_string_split_status_t
amxc_build_csv_var_list(amxc_llist_t* all, amxc_var_t* csv_list) {
    amxc_string_split_status_t retval = AMXC_ERROR_STRING_SPLIT_INVALID_INPUT;
    bool quotes = false;
    bool sqbrackets = false;
    bool add_empty = true;
    bool last_is_comma = false;
    amxc_string_t csv_part;

    amxc_var_set_type(csv_list, AMXC_VAR_ID_LIST);

    amxc_string_init(&csv_part, 0);
    amxc_llist_for_each(it, all) {
        amxc_string_t* part = amxc_string_from_llist_it(it);
        const char* txt_part = amxc_string_get(part, 0);
        last_is_comma = false;
        if(amxc_string_text_length(part) == 1) {
            switch(txt_part[0]) {
            case '"':
            case '\'':
                amxc_string_append(&csv_part, txt_part, amxc_string_text_length(part));
                quotes = !quotes;
                break;
            case '[':
                if(amxc_string_is_empty(&csv_part)) {
                    csv_list = amxc_var_add(amxc_llist_t, csv_list, NULL);
                    sqbrackets = !sqbrackets;
                } else {
                    amxc_string_append(&csv_part, txt_part, amxc_string_text_length(part));
                }
                break;
            case ']':
                if(sqbrackets) {
                    if(amxc_string_text_length(&csv_part) > 0) {
                        amxc_var_t* item = amxc_var_add_new(csv_list);
                        amxc_string_trim(&csv_part, NULL);
                        amxc_var_push(cstring_t, item, amxc_string_take_buffer(&csv_part));
                    }
                    if(csv_list != NULL) {
                        csv_list = amxc_container_of(csv_list->lit.llist, amxc_var_t, data);
                    }
                    sqbrackets = !sqbrackets;
                    add_empty = false;
                } else {
                    amxc_string_append(&csv_part, txt_part, amxc_string_text_length(part));
                }
                break;
            case ',':
                if(quotes) {
                    amxc_string_append(&csv_part, txt_part, amxc_string_text_length(part));
                } else {
                    if(amxc_string_text_length(&csv_part) > 0) {
                        amxc_var_t* item = amxc_var_add_new(csv_list);
                        amxc_string_trim(&csv_part, NULL);
                        amxc_var_push(cstring_t, item, amxc_string_take_buffer(&csv_part));
                    } else if(add_empty) {
                        amxc_var_t* item = amxc_var_add_new(csv_list);
                        amxc_var_set(cstring_t, item, "");
                    }
                    add_empty = true;
                }
                last_is_comma = true;
                break;
            case ' ':
                amxc_string_append(&csv_part, txt_part, amxc_string_text_length(part));
                break;
            default:
                amxc_string_append(&csv_part, txt_part, amxc_string_text_length(part));
                break;
            }
        } else {
            amxc_string_append(&csv_part, txt_part, amxc_string_text_length(part));
        }
    }
    if(amxc_string_text_length(&csv_part) > 0) {
        amxc_var_t* item = amxc_var_add_new(csv_list);
        amxc_string_trim(&csv_part, NULL);
        amxc_var_push(cstring_t, item, amxc_string_take_buffer(&csv_part));
    } else if(last_is_comma && add_empty) {
        amxc_var_add(cstring_t, csv_list, "");
    }
    amxc_string_clean(&csv_part);

    retval = AMXC_STRING_SPLIT_OK;

    return retval;
}

static amxc_string_split_status_t
amxc_build_ssv_var_list(amxc_llist_t* all, amxc_var_t* ssv_list) {
    amxc_string_split_status_t retval = AMXC_ERROR_STRING_SPLIT_INVALID_INPUT;
    bool quotes = false;
    bool sqbrackets = false;
    amxc_string_t csv_part;

    amxc_var_set_type(ssv_list, AMXC_VAR_ID_LIST);

    amxc_string_init(&csv_part, 0);
    amxc_llist_for_each(it, all) {
        amxc_string_t* part = amxc_string_from_llist_it(it);
        const char* txt_part = amxc_string_get(part, 0);
        if(amxc_string_text_length(part) == 1) {
            switch(txt_part[0]) {
            case '"':
            case '\'':
                amxc_string_append(&csv_part, txt_part, amxc_string_text_length(part));
                quotes = !quotes;
                break;
            case '[':
                ssv_list = amxc_var_add(amxc_llist_t, ssv_list, NULL);
                sqbrackets = !sqbrackets;
                break;
            case ']':
                if(amxc_string_text_length(&csv_part) > 0) {
                    amxc_var_t* item = amxc_var_add_new(ssv_list);
                    amxc_var_push(cstring_t, item, amxc_string_take_buffer(&csv_part));
                }
                if(ssv_list != NULL) {
                    ssv_list = amxc_container_of(ssv_list->lit.llist, amxc_var_t, data);
                }
                sqbrackets = !sqbrackets;
                break;
            case ' ':
                if(quotes) {
                    amxc_string_append(&csv_part, txt_part, amxc_string_text_length(part));
                } else {
                    if(amxc_string_text_length(&csv_part) > 0) {
                        amxc_var_t* item = amxc_var_add_new(ssv_list);
                        amxc_var_push(cstring_t, item, amxc_string_take_buffer(&csv_part));
                    }
                    amxc_string_reset(&csv_part);
                }
                break;
            default:
                amxc_string_append(&csv_part, txt_part, amxc_string_text_length(part));
                break;
            }
        } else {
            amxc_string_append(&csv_part, txt_part, amxc_string_text_length(part));
        }
    }
    if(amxc_string_text_length(&csv_part) > 0) {
        amxc_var_t* item = amxc_var_add_new(ssv_list);
        amxc_var_push(cstring_t, item, amxc_string_take_buffer(&csv_part));
    }
    amxc_string_clean(&csv_part);

    retval = AMXC_STRING_SPLIT_OK;

    return retval;
}

amxc_string_split_status_t
amxc_string_split_word(const amxc_string_t* const string,
                       amxc_llist_t* list,
                       const char** reason) {
    amxc_string_split_status_t retval = AMXC_ERROR_STRING_SPLIT_INVALID_INPUT;

    when_null(list, exit);
    when_null(string, exit);

    retval = amxc_string_split_words_internal(string,
                                              list,
                                              amxc_string_create_part,
                                              amxc_need_to_add_delimiter,
                                              reason);
    if(retval != 0) {
        amxc_llist_clean(list, amxc_string_list_it_free);
    }

exit:
    return retval;
}

amxc_string_split_status_t
amxc_string_split(const amxc_string_t* const string,
                  amxc_var_t* var,
                  amxc_string_split_builder_t fn,
                  const char** reason) {
    amxc_string_split_status_t retval = AMXC_ERROR_STRING_SPLIT_INVALID_INPUT;
    amxc_llist_t all_parts;

    amxc_llist_init(&all_parts);
    when_null(string, exit);
    when_null(var, exit);

    retval = amxc_string_split_words_internal(string,
                                              &all_parts,
                                              amxc_string_create_part,
                                              amxc_need_to_add_delimiter,
                                              reason);

    if(fn != NULL) {
        fn(&all_parts, var);
    } else {
        amxc_var_set_type(var, AMXC_VAR_ID_LIST);
        amxc_llist_for_each(it, (&all_parts)) {
            amxc_string_t* part = amxc_string_from_llist_it(it);
            amxc_var_add(cstring_t, var, amxc_string_get(part, 0));
            amxc_string_delete(&part);
        }
    }

exit:
    amxc_llist_clean(&all_parts, amxc_string_list_it_free);
    return retval;
}

amxc_string_split_status_t
amxc_string_csv_to_var(const amxc_string_t* const string,
                       amxc_var_t* var,
                       const char** reason) {
    return amxc_string_split(string, var, amxc_build_csv_var_list, reason);
}

amxc_string_split_status_t
amxc_string_ssv_to_var(const amxc_string_t* const string,
                       amxc_var_t* var,
                       const char** reason) {
    return amxc_string_split(string, var, amxc_build_ssv_var_list, reason);
}

amxc_string_split_status_t
amxc_string_split_to_llist(const amxc_string_t* const string,
                           amxc_llist_t* list,
                           const char separator) {
    amxc_string_split_status_t retval = AMXC_ERROR_STRING_SPLIT_INVALID_INPUT;
    amxc_string_t* current = NULL;
    amxc_llist_t parts_list;
    bool in_sbrackets = false;

    amxc_llist_init(&parts_list);
    when_null(string, exit);
    when_null(list, exit);
    when_true(isalnum(separator) != 0, exit);
    when_true(separator == '[' || separator == ']', exit);

    retval = amxc_string_split_word(string, &parts_list, NULL);
    when_failed(retval, exit);
    amxc_trim_llist(&parts_list);

    amxc_llist_for_each(it, (&parts_list)) {
        amxc_string_t* part = amxc_string_from_llist_it(it);
        const char* txt_part = amxc_string_get(part, 0);
        amxc_llist_append(list, &part->it);
        if(amxc_string_text_length(part) == 1) {
            if((separator == txt_part[0]) && !in_sbrackets) {
                amxc_string_reset(part);
                if(amxc_llist_it_get_previous(it) != NULL) {
                    current = part;
                }
                continue;
            }
            if(txt_part[0] == '[') {
                if((amxc_string_text_length(current) > 0) && (isspace(separator) == 0)) {
                    amxc_string_append(current, txt_part, amxc_string_text_length(part));
                    amxc_string_delete(&part);
                    continue;
                } else {
                    if(amxc_string_is_empty(current)) {
                        amxc_string_delete(&current);
                    }
                    current = part;
                    in_sbrackets = !in_sbrackets;
                    continue;
                }
            }
            if((txt_part[0] == ']') && in_sbrackets) {
                amxc_string_append(current, txt_part, amxc_string_text_length(part));
                amxc_string_delete(&part);
                in_sbrackets = !in_sbrackets;
                current = NULL;
                continue;
            }
            if(isspace(txt_part[0]) && !in_sbrackets) {
                if(!amxc_string_is_empty(current)) {
                    amxc_string_append(current, txt_part, amxc_string_text_length(part));
                }
                amxc_string_delete(&part);
                continue;
            }
        }
        if(current == NULL) {
            current = part;
        } else {
            amxc_string_append(current, txt_part, amxc_string_text_length(part));
            amxc_string_delete(&part);
        }
    }

exit:
    amxc_llist_clean(&parts_list, amxc_string_list_it_free);
    return retval;
}

amxc_string_t* amxc_string_get_from_llist(const amxc_llist_t* const llist,
                                          const unsigned int index) {
    amxc_string_t* retval = NULL;
    amxc_llist_it_t* it = NULL;

    when_null(llist, exit);

    it = amxc_llist_get_at(llist, index);
    when_null(it, exit);

    retval = amxc_string_from_llist_it(it);
exit:
    return retval;
}

const char* amxc_string_get_text_from_llist(const amxc_llist_t* const llist,
                                            const unsigned int index) {
    const char* retval = NULL;
    amxc_string_t* var_str = NULL;

    var_str = amxc_string_get_from_llist(llist, index);
    when_null(var_str, exit);

    retval = amxc_string_get(var_str, 0);
exit:
    return retval;
}
