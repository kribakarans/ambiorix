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
#include <amxc/amxc_macros.h>

/**
   @file
   @brief
   Ambiorix string API implementation
 */


static const char* const s_supported_format_placeholders[] = { "%s", "%d", "%lld", "%ld", "%i",
    "%lli", "%li", "%u", "%llu", "%lu", "%x", "%llx", "%lx", "%%", "%c", "%f", "%F", "%X"};

static int amxc_string_realloc(amxc_string_t* string, const size_t length) {
    char* new_buffer = NULL;
    int retval = -1;

    if(length == 0) {
        free(string->buffer);
        string->buffer = NULL;
        string->length = 0;
        retval = 0;
    } else if(string->buffer != NULL) {
        new_buffer = (char*) realloc(string->buffer, sizeof(char) * length + 1);
    } else {
        new_buffer = (char*) calloc(length + 1, sizeof(char));
    }
    if(new_buffer != NULL) {
        string->buffer = new_buffer;
        string->length = length;
        string->last_used = string->last_used >= length ? length - 1 : string->last_used;
        string->buffer[string->last_used] = 0;
        retval = 0;
    }

    return retval;
}

/**
 * If input starts with a placeholder (e.g. "%ihi"), return null-terminated placeholder (e.g. "%i").
 * Otherwise return NULL.
 */
static const char* s_get_format_placeholder(const char* input) {
    size_t nb_supported = 0;
    when_null(input, error);
    nb_supported = sizeof(s_supported_format_placeholders) / sizeof(s_supported_format_placeholders[0]);
    for(size_t i = 0; i < nb_supported; i++) {
        const char* const candidate = s_supported_format_placeholders[i];
        if(0 == strncmp(candidate, input, strlen(candidate))) {
            return candidate;
        }
    }
error:
    return NULL;
}

int amxc_string_new(amxc_string_t** string, const size_t length) {
    int retval = -1;
    when_null(string, exit);

    /* allocate the array structure */
    *string = (amxc_string_t*) calloc(1, sizeof(amxc_string_t));
    when_null(*string, exit);

    /* set the number of items in the array */
    (*string)->length = length;
    (*string)->last_used = 0;

    /* if no buffer needs to pre-allocated, leave */
    if(length == 0) {
        retval = 0;
        goto exit;
    }

    /* allocate the buffer */
    amxc_string_realloc(*string, length);
    when_null(*string, exit);

    retval = 0;

exit:
    if((retval != 0) && (string != NULL)) {
        free(*string);
        *string = NULL;
    }
    return retval;
}

void amxc_string_delete(amxc_string_t** string) {
    when_null(string, exit);
    when_null((*string), exit);

    amxc_llist_it_take(&(*string)->it);
    free((*string)->buffer);
    free(*string);
    *string = NULL;

exit:
    return;
}

int amxc_string_init(amxc_string_t* const string, const size_t length) {
    int retval = -1;
    when_null(string, exit);

    string->buffer = NULL;
    string->length = 0;
    string->last_used = 0;

    amxc_llist_it_init(&string->it);

    // if no items need to be pre-allocated, leave
    if(length == 0) {
        retval = 0;
        goto exit;
    }

    amxc_string_realloc(string, length);
    when_null(string->buffer, exit);
    string->length = length;

    retval = 0;

exit:
    return retval;
}

void amxc_string_clean(amxc_string_t* const string) {
    when_null(string, exit);

    amxc_llist_it_take(&string->it);

    free(string->buffer);
    string->buffer = NULL;
    string->last_used = 0;
    string->length = 0;

exit:
    return;
}

void amxc_string_reset(amxc_string_t* const string) {
    when_null(string, exit);

    if(string->buffer) {
        string->buffer[0] = 0;
    }
    string->last_used = 0;

exit:
    return;
}

int amxc_string_copy(amxc_string_t* const dest,
                     const amxc_string_t* const src) {
    int retval = -1;
    when_null(dest, exit);
    when_null(src, exit);

    amxc_string_reset(dest);

    if(src->length == 0) {
        dest->last_used = 0;
        retval = 0;
        goto exit;
    }

    amxc_string_realloc(dest, src->length);
    when_null(dest->buffer, exit);
    memcpy(dest->buffer, src->buffer, src->length);
    dest->last_used = src->last_used;

    retval = 0;

exit:
    return retval;
}

int amxc_string_grow(amxc_string_t* const string, const size_t length) {
    int retval = -1;
    size_t old_length = 0;
    when_null(string, exit);

    if(length == 0) {
        retval = 0;
        goto exit;
    }

    old_length = string->length;
    when_failed(amxc_string_realloc(string, old_length + length), exit);
    when_null(string->buffer, exit);
    memset(string->buffer + old_length, 0, length);
    retval = 0;

exit:
    return retval;
}

int amxc_string_shrink(amxc_string_t* const string, const size_t length) {
    int retval = -1;
    when_null(string, exit);
    when_true(length > string->length, exit); // out of range

    if(length == 0) {
        retval = 0;
        goto exit;
    }

    retval = amxc_string_realloc(string, string->length - length);

exit:
    return retval;
}

int amxc_string_set_at(amxc_string_t* const string,
                       const size_t pos,
                       const char* const text,
                       const size_t length,
                       const amxc_string_flags_t flags) {
    int retval = -1;
    when_null(string, exit);
    when_null(text, exit);
    when_true(length == 0, exit);
    when_true(pos > string->last_used, exit);

    if((flags & amxc_string_overwrite) == amxc_string_overwrite) {
        if(pos + length > string->length) {
            when_failed(amxc_string_realloc(string,
                                            pos + length), exit);
            when_null(string->buffer, exit);
        }
        string->last_used = pos + length > string->last_used ? pos + length : string->last_used;
    } else {
        if(length + string->last_used >= string->length) {
            when_failed(amxc_string_realloc(string,
                                            length + string->last_used + 1), exit);
            when_null(string->buffer, exit);
        }
        memmove(string->buffer + pos + length,
                string->buffer + pos,
                string->last_used - pos);
        string->last_used += length;
    }

    memcpy(string->buffer + pos, text, length);
    string->buffer[string->last_used] = 0;
    retval = 0;

exit:
    return retval;
}

int amxc_string_remove_at(amxc_string_t* const string,
                          const size_t pos,
                          size_t length) {
    int retval = -1;
    size_t bytes_to_move = 0;
    when_null(string, exit);
    when_null(string->buffer, exit);
    when_true(length == 0, exit);
    when_true(pos > string->last_used, exit);

    if((length == SIZE_MAX) ||
       ( pos + length > string->last_used)) {
        length = string->last_used - pos;
    }

    bytes_to_move = string->last_used - (pos + length);
    memmove(string->buffer + pos, string->buffer + pos + length, bytes_to_move);
    string->last_used -= length;
    string->buffer[string->last_used] = 0;
    retval = 0;

exit:
    return retval;
}

const char* amxc_string_get(const amxc_string_t* const string,
                            const size_t offset) {
    const char* text = NULL;
    when_null(string, exit);
    when_true(string->buffer != NULL && offset > string->last_used, exit);

    if(string->buffer == NULL) {
        text = "";
    } else {
        string->buffer[string->last_used] = 0;
        text = string->buffer + offset;
    }

exit:
    return text;
}

char* amxc_string_take_buffer(amxc_string_t* const string) {
    char* buffer = NULL;
    when_null(string, exit);

    if(string->buffer != NULL) {
        string->buffer[string->last_used] = 0;
    }
    buffer = string->buffer;
    string->buffer = NULL;
    string->last_used = 0;
    string->length = 0;

exit:
    return buffer;
}

int amxc_string_push_buffer(amxc_string_t* const string,
                            char* buffer,
                            size_t length) {
    int retval = -1;
    char* original = NULL;
    when_null(string, exit);

    original = string->buffer;

    if(buffer != NULL) {
        when_true(length < strlen(buffer) + 1, exit);
        string->buffer = buffer;
        string->last_used = strlen(buffer);
        string->length = length;
    } else {
        string->buffer = NULL;
        string->last_used = 0;
        string->length = 0;
    }

    free(original);

    retval = 0;

exit:
    return retval;
}

char* amxc_string_dup(const amxc_string_t* const string,
                      const size_t start,
                      size_t length) {

    char* text = NULL;
    when_null(string, exit);
    when_true(start > string->last_used, exit);
    when_true(length == 0, exit);

    if((length == SIZE_MAX) ||
       ( start + length > string->last_used)) {
        length = string->last_used - start;
    }

    text = (char*) calloc(length + 1, sizeof(char));
    when_null(text, exit);
    memcpy(text, string->buffer + start, length);
    text[length] = 0;

exit:
    return text;
}

void amxc_string_triml(amxc_string_t* const string, amxc_string_is_char_fn_t fn) {
    uint32_t pos = 0;
    when_null(string, exit);
    when_true(string->last_used == 0, exit);

    if(fn == NULL) {
        fn = isspace;
    }

    while(pos <= string->last_used &&
          fn(string->buffer[pos]) != 0) {
        pos++;
    }

    if(pos >= string->last_used) {
        string->last_used = 0;
        string->buffer[0] = 0;
        goto exit;
    }

    if(pos > 0) {
        memmove(string->buffer, string->buffer + pos, string->last_used - pos);
        string->last_used -= pos;
    }
    string->buffer[string->last_used] = 0;

exit:
    return;
}

void amxc_string_trimr(amxc_string_t* const string, amxc_string_is_char_fn_t fn) {
    when_null(string, exit);
    when_true(string->last_used == 0, exit);

    if(fn == NULL) {
        fn = isspace;
    }

    while(string->last_used > 0 &&
          fn(string->buffer[string->last_used - 1]) != 0) {
        string->last_used--;
    }
    string->buffer[string->last_used] = 0;

exit:
    return;
}

void amxc_string_trim(amxc_string_t* const string, amxc_string_is_char_fn_t fn) {
    amxc_string_trimr(string, fn);
    amxc_string_triml(string, fn);
}

int amxc_string_vsetf(amxc_string_t* const string,
                      const char* fmt,
                      va_list args) {
    int retval = -1;

    when_null(string, exit);
    when_null(fmt, exit);

    amxc_string_reset(string);
    retval = amxc_string_vappendf(string, fmt, args);

exit:
    return retval;
}

int amxc_string_setf(amxc_string_t* const string, const char* fmt, ...) {
    va_list args;
    int retval = -1;
    when_null(string, exit);
    when_null(fmt, exit);

    va_start(args, fmt);
    retval = amxc_string_vsetf(string, fmt, args);
    va_end(args);

exit:
    return retval;
}

int amxc_string_vsetf_checked(amxc_string_t* const string,
                              amxc_string_is_safe_cb_t is_safe_cb,
                              const char* fmt,
                              va_list args) {
    int retval = -1;

    when_null(string, exit);
    when_null(fmt, exit);

    amxc_string_reset(string);
    retval = amxc_string_vappendf_checked(string, is_safe_cb, fmt, args);

exit:
    return retval;
}

int amxc_string_setf_checked(amxc_string_t* target_string,
                             amxc_string_is_safe_cb_t is_safe_cb,
                             const char* fmt, ...) {
    va_list args;
    int retval = -1;
    when_null(target_string, exit);
    when_null(fmt, exit);

    va_start(args, fmt);
    retval = amxc_string_vsetf_checked(target_string, is_safe_cb, fmt, args);
    va_end(args);

exit:
    return retval;
}

int amxc_string_vappendf(amxc_string_t* const string,
                         const char* fmt,
                         va_list args) {

    int retval = -1;
    int size_needed = 0;
    va_list copy;

    when_null(string, exit);
    when_null(fmt, exit);

    va_copy(copy, args);
    size_needed = vsnprintf(NULL, 0, fmt, args) + 1;

    if(string->length < string->last_used + size_needed) {
        size_t grow = (string->last_used + size_needed - string->length);
        when_failed(amxc_string_grow(string, grow), exit);
    }

    size_needed = vsnprintf(string->buffer + string->last_used,
                            size_needed,
                            fmt,
                            copy);
    string->buffer[string->length] = 0;

    string->last_used += size_needed;

    retval = 0;

exit:
    return retval;
}

int amxc_string_appendf(amxc_string_t* const string, const char* fmt, ...) {
    va_list args;
    int retval = -1;
    when_null(string, exit);
    when_null(fmt, exit);

    va_start(args, fmt);
    retval = amxc_string_vappendf(string, fmt, args);
    va_end(args);

exit:
    return retval;
}

/** @return whether the actual placeholder was "%%"" */
static bool s_replace_percentage(amxc_string_t* string, const char* actual_placeholder, int* status) {
    if(0 == strcmp(actual_placeholder, "%%")) {
        *status = amxc_string_append(string, "%", 1);
        return true;
    } else {
        return false;
    }
}

/** @return whether the actual placeholder was the searched placeholder */
#define REPLACE_PLACEHOLDER(string, actual_placeholder, status, args, searched_placeholder, type) \
    (0 == strcmp(actual_placeholder, searched_placeholder) \
        ? status = amxc_string_appendf(string, actual_placeholder, va_arg(args, type)), true \
        : false)

int amxc_string_vappendf_checked(amxc_string_t* string, amxc_string_is_safe_cb_t is_safe_cb,
                                 const char* fmt, va_list args) {

    const char* pos = fmt;
    int status = -1;
    when_null(string, error);
    when_null(fmt, error);
    while(*pos != '\0') {
        size_t len_pos_old = 0;
        size_t len_new_fixed = 0;
        const char* placeholder = NULL;
        const char* placeholder_in_pos = strchr(pos, '%');
        bool placeholder_handled = false;

        // If no "%" left, add all the rest:
        if(placeholder_in_pos == NULL) {
            status = amxc_string_append(string, pos, strlen(pos));
            when_failed(status, error);
            return 0;
        }

        // Add the fixed part, i.e. until "%":
        len_new_fixed = placeholder_in_pos - pos;
        if(len_new_fixed != 0) {
            status = amxc_string_append(string, pos, len_new_fixed);
            when_failed(status, error);
        }

        // Identify placeholder (e.g. "%i"):
        placeholder = s_get_format_placeholder(placeholder_in_pos);
        if(placeholder == NULL) {
            goto error; // unsupported placeholder.
        }
        len_pos_old = amxc_string_text_length(string);

        // Add replacement
        // Note: Unfortunately, we cannot make this more clean by splitting off functions
        //   because "If [the va_list] is passed to a function that uses va_arg(ap,type), then
        //   the value of ap is undefined after the return of that function." (man va_arg(3))
        //   and because getting an item from a va_list requires hardcoding its type.
        placeholder_handled = REPLACE_PLACEHOLDER(string, placeholder, status, args, "%s", const char*)
            || REPLACE_PLACEHOLDER(string, placeholder, status, args, "%d", int)
            || REPLACE_PLACEHOLDER(string, placeholder, status, args, "%lld", long long int)
            || REPLACE_PLACEHOLDER(string, placeholder, status, args, "%ld", long int)
            || REPLACE_PLACEHOLDER(string, placeholder, status, args, "%i", int)
            || REPLACE_PLACEHOLDER(string, placeholder, status, args, "%lli", long long int)
            || REPLACE_PLACEHOLDER(string, placeholder, status, args, "%li", long int)
            || REPLACE_PLACEHOLDER(string, placeholder, status, args, "%u", unsigned int)
            || REPLACE_PLACEHOLDER(string, placeholder, status, args, "%llu", long long unsigned int)
            || REPLACE_PLACEHOLDER(string, placeholder, status, args, "%lu", long unsigned int)
            || REPLACE_PLACEHOLDER(string, placeholder, status, args, "%x", unsigned int)
            || REPLACE_PLACEHOLDER(string, placeholder, status, args, "%llx", long long unsigned int)
            || REPLACE_PLACEHOLDER(string, placeholder, status, args, "%lx", long unsigned int)
            || REPLACE_PLACEHOLDER(string, placeholder, status, args, "%c", int) // unsigned char promoted to int
            || REPLACE_PLACEHOLDER(string, placeholder, status, args, "%f", double)
            || REPLACE_PLACEHOLDER(string, placeholder, status, args, "%F", double)
            || REPLACE_PLACEHOLDER(string, placeholder, status, args, "%X", unsigned int)
            || s_replace_percentage(string, placeholder, &status);

        when_false(placeholder_handled, error);

        when_failed(status, error);

        // Check if added string safe:
        if((is_safe_cb != NULL) && !is_safe_cb(amxc_string_get(string, len_pos_old))) {
            goto error;
        }

        pos += len_new_fixed + strlen(placeholder);
    }
    return 0;

error:
    amxc_string_clean(string);
    return -1;
}

int amxc_string_appendf_checked(amxc_string_t* target_string, amxc_string_is_safe_cb_t is_safe_cb,
                                const char* fmt, ...) {
    va_list args;
    int retval = -1;
    when_null(target_string, exit);
    when_null(fmt, exit);

    va_start(args, fmt);
    retval = amxc_string_vappendf_checked(target_string, is_safe_cb, fmt, args);
    va_end(args);

exit:
    return retval;
}

int amxc_string_vprependf(amxc_string_t* const string,
                          const char* fmt,
                          va_list args) {

    int retval = -1;
    int size_needed = 0;
    char first_char = 0;
    va_list copy;

    when_null(string, exit);
    when_null(fmt, exit);

    va_copy(copy, args);
    size_needed = vsnprintf(NULL, 0, fmt, args) + 1;

    if(string->length < string->last_used + size_needed) {
        size_t grow = (string->last_used + size_needed - string->length);
        when_failed(amxc_string_grow(string, grow), exit);
    }
    first_char = string->buffer[0];

    if(string->last_used > 0) {
        memmove(string->buffer + size_needed - 1,
                string->buffer,
                string->last_used);
    }

    size_needed = vsnprintf(string->buffer,
                            size_needed,
                            fmt,
                            copy);
    string->buffer[size_needed] = first_char;
    string->last_used += size_needed;

    retval = 0;

exit:
    return retval;
}

int amxc_string_prependf(amxc_string_t* const string, const char* fmt, ...) {
    va_list args;
    int retval = -1;
    when_null(string, exit);
    when_null(fmt, exit);

    va_start(args, fmt);
    retval = amxc_string_vprependf(string, fmt, args);
    va_end(args);

exit:
    return retval;
}

bool amxc_string_is_numeric(const amxc_string_t* const string) {
    bool retval = false;
    char* data = NULL;

    when_true(amxc_string_is_empty(string), exit);

    data = string->buffer;
    while((*data) != '\0') {
        if(isdigit(*data) == 0) {
            goto exit;
        }
        data++;
    }

    retval = true;
exit:
    return retval;
}

int amxc_string_search(const amxc_string_t* const string,
                       const char* needle,
                       uint32_t start_pos) {
    int retval = -1;
    size_t needle_len = 0;
    const char* needle_loc = NULL;

    when_null(string, exit);
    when_null(string->buffer, exit);
    when_true(string->last_used == 0, exit);
    when_true(needle == NULL || *needle == 0, exit);

    needle_len = strlen(needle);
    when_true(start_pos + needle_len > string->last_used, exit);

    needle_loc = strstr(string->buffer + start_pos, needle);
    if(needle_loc != NULL) {
        retval = needle_loc - string->buffer;
    }

exit:
    return retval;
}

int amxc_string_replace(amxc_string_t* const string,
                        const char* needle,
                        const char* newstr,
                        uint32_t max) {
    int retval = 0;
    int pos = 0;
    size_t needle_len = 0;
    size_t newstr_len = 0;

    when_null(string, exit);
    when_null(string->buffer, exit);
    when_true(string->last_used == 0, exit);
    when_true(needle == NULL || *needle == 0, exit);
    when_null(newstr, exit);

    needle_len = strlen(needle);
    newstr_len = strlen(newstr);

    when_true(needle_len > string->last_used, exit);

    pos = amxc_string_search(string, needle, pos);
    while(pos != -1 && max > 0) {
        amxc_string_remove_at(string, pos, needle_len);
        if(newstr_len != 0) {
            amxc_string_insert_at(string, pos, newstr, newstr_len);
        }
        retval++;
        if(max != UINT32_MAX) {
            max--;
        }
        pos = amxc_string_search(string, needle, pos + newstr_len);
    }

exit:
    return retval;
}

size_t amxc_string_set(amxc_string_t* const string, const char* data) {
    size_t retval = 0;

    when_null(string, exit);
    amxc_string_reset(string);
    when_null(data, exit);

    retval = strlen(data);
    if(amxc_string_insert_at(string, 0, data, retval) != 0) {
        retval = 0;
    }

exit:
    return retval;
}

int amxc_string_to_upper(amxc_string_t* const string) {
    int retval = -1;

    when_null(string, exit);

    for(uint32_t i = 0; i <= string->last_used; i++) {
        string->buffer[i] = toupper(string->buffer[i]);
    }
    retval = 0;

exit:
    return retval;
}

int amxc_string_to_lower(amxc_string_t* const string) {
    int retval = -1;

    when_null(string, exit);

    for(uint32_t i = 0; i <= string->last_used; i++) {
        string->buffer[i] = tolower(string->buffer[i]);
    }
    retval = 0;

exit:
    return retval;
}

int amxc_string_bytes_2_hex_binary(amxc_string_t* const string,
                                   const char bytes[],
                                   const uint32_t len,
                                   const char* sep) {
    int retval = -1;
    const char* s = "";

    when_null(string, exit);

    amxc_string_reset(string);

    when_null(bytes, exit);
    when_true(len == 0, exit);

    for(uint32_t i = 0; i < len; i++) {
        retval = amxc_string_appendf(string, "%s%2.2X", s, (unsigned char) bytes[i]);
        if(retval != 0) {
            amxc_string_reset(string);
            goto exit;
        }
        if(sep != NULL) {
            s = sep;
        }
    }

    retval = 0;

exit:
    return retval;
}

int amxc_string_hex_binary_2_bytes(const amxc_string_t* const string,
                                   char** bytes,
                                   uint32_t* len,
                                   const char* sep) {
    int retval = -1;
    uint32_t str_len = 0;
    uint32_t pos = 0;
    uint32_t sep_count = 0;
    const char* hex_binary = NULL;
    uint32_t sep_len = sep == NULL ? 0 : strlen(sep);
    char* buffer = NULL;

    when_true(amxc_string_is_empty(string), exit);
    when_null(bytes, exit);
    when_null(len, exit);

    str_len = amxc_string_text_length(string);
    *len = (str_len + 1) >> 1;
    buffer = (char*) calloc(1, *len);

    when_null(buffer, exit);
    hex_binary = amxc_string_get(string, 0);

    for(uint32_t i = 0; i < str_len; i++) {
        int shift = 0;
        if((sep != NULL) && (sep_len != 0) &&
           ( strncmp(hex_binary + i, sep, sep_len) == 0)) {
            sep_count++;
            continue;
        }
        if(((i - sep_count) % 2 == 0) && ((i + 1) != str_len)) {
            shift = 4;
        }
        if((hex_binary[i] >= '0') && (hex_binary[i] <= '9')) {
            buffer[pos] |= (hex_binary[i] - '0') << shift;
        } else if((hex_binary[i] >= 'A') && (hex_binary[i] <= 'F')) {
            buffer[pos] |= (hex_binary[i] - 'A' + 10) << shift;
        } else if((hex_binary[i] >= 'a') && (hex_binary[i] <= 'f')) {
            buffer[pos] |= (hex_binary[i] - 'a' + 10) << shift;
        } else {
            // invalid character
            goto exit;
        }
        if((i - sep_count) % 2 != 0) {
            pos++;
        }
    }

    if(sep_count != 0) {
        char* tmp = NULL;
        *len -= (((sep_len * sep_count) + 1) >> 1);
        *bytes = buffer;
        tmp = (char*) realloc(buffer, *len);
        if(tmp != NULL) {
            *bytes = tmp;
        }
    } else {
        *bytes = buffer;
    }
    retval = 0;

exit:
    if(retval != 0) {
        free(buffer);
        if(bytes != NULL) {
            *bytes = NULL;
        }
        if(len != NULL) {
            *len = 0;
        }
    }
    return retval;
}

