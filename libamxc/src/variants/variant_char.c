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
#include <limits.h>
#include <ctype.h>
#include <errno.h>

#include <amxc/amxc_string_split.h>
#include <amxc_variant_priv.h>

static const char* variant_char_validate_number(const amxc_var_t* const src, int* retval) {
    const char* buffer = NULL;
    *retval = -1;
    when_true((src->data.s == NULL) || (*(src->data.s) == 0), exit);

    buffer = src->data.s;
    // skip whitespaces
    while(isspace(*buffer)) {
        buffer++;
    }

    when_true(!isdigit(*buffer) && *buffer != '+' && *buffer != '-', exit);
    *retval = 0;

exit:
    return buffer;
}

static int variant_char_to_signed_int(amxc_var_t* const dest,
                                      const amxc_var_t* const src) {
    int retval = -1;
    amxc_var_t intermediate;
    const char* buffer = NULL;
    char* endptr = NULL;

    intermediate.type_id = AMXC_VAR_ID_INT64;
    intermediate.data.i64 = 0;

    buffer = variant_char_validate_number(src, &retval);
    when_true(retval != 0, exit);

    retval = -1;
    errno = 0;
    intermediate.data.i64 = strtoll(buffer, &endptr, 0);

    when_true((errno == ERANGE && (intermediate.data.i64 == LLONG_MIN ||
                                   intermediate.data.i64 == LLONG_MAX)) ||
              (errno != 0 && intermediate.data.i64 == 0), exit);
    when_true(endptr == buffer || *endptr != '\0', exit);

    retval = amxc_var_convert(dest, &intermediate, dest->type_id);

exit:
    return retval;
}

static int variant_char_to_unsigned_int(amxc_var_t* const dest,
                                        const amxc_var_t* const src) {
    int retval = -1;
    amxc_var_t intermediate;
    const char* buffer = NULL;
    char* endptr = NULL;

    intermediate.type_id = AMXC_VAR_ID_UINT64;
    intermediate.data.ui64 = 0;

    buffer = variant_char_validate_number(src, &retval);
    when_true(retval != 0, exit);

    retval = -1;
    errno = 0;
    intermediate.data.ui64 = llabs(strtoll(buffer, &endptr, 0));

    when_true((errno == ERANGE && (intermediate.data.ui64 == 0 ||
                                   intermediate.data.ui64 == ULLONG_MAX)) ||
              (errno != 0 && intermediate.data.ui64 == 0), exit);
    when_true(endptr == buffer || *endptr != '\0', exit);

    retval = amxc_var_convert(dest, &intermediate, dest->type_id);

exit:
    return retval;
}

static int variant_char_to_double(amxc_var_t* const dest,
                                  const amxc_var_t* const src) {
    int retval = -1;
    const char* buffer = NULL;
    char* endptr = NULL;

    buffer = variant_char_validate_number(src, &retval);
    when_true(retval != 0, exit);

    retval = -1;
    errno = 0;
    dest->data.d = strtod(buffer, &endptr);

    if(((errno == ERANGE) && (dest->data.d == 0)) ||
       (( errno != 0) && ( dest->data.d == 0)) ||
       (endptr == buffer) ||
       (*endptr != '\0')) {
        goto exit;
    }

    retval = 0;

exit:
    return retval;
}

static int variant_char_to_float(amxc_var_t* const dest,
                                 const amxc_var_t* const src) {
    int retval = -1;
    const char* buffer = NULL;
    char* endptr = NULL;

    buffer = variant_char_validate_number(src, &retval);
    when_true(retval != 0, exit);

    retval = -1;
    errno = 0;
    dest->data.f = strtof(buffer, &endptr);

    if(((errno == ERANGE) && (dest->data.f == 0)) ||
       (( errno != 0) && ( dest->data.f == 0)) ||
       (endptr == buffer) ||
       (*endptr != '\0')) {
        goto exit;
    }

    retval = 0;

exit:
    return retval;
}

static int variant_char_to_bool(amxc_var_t* const dest,
                                const amxc_var_t* const src) {
    int retval = -1;
    char* lower_src = NULL;
    int src_len = 0;
    int src_pos = 0;
    const char true_values[4][10] = { "true", "yes", "1", "on" };
    const char false_values[4][10] = { "false", "no", "0", "off" };

    when_true((src->data.s == NULL) || (*(src->data.s) == 0), exit);

    src_len = strlen(src->data.s) + 1;
    lower_src = (char*) calloc(1, src_len);
    when_null(lower_src, exit);

    for(int i = 0; i < src_len; i++) {
        if(isspace(*(src->data.s + i))) {
            // skip white spaces
            continue;
        }
        lower_src[src_pos] = tolower(*(src->data.s + i));
        src_pos++;
    }

    for(int index = 0; index < 4; index++) {
        if(strcmp(lower_src, true_values[index]) == 0) {
            dest->data.b = true;
            retval = 0;
            break;
        } else if(strcmp(lower_src, false_values[index]) == 0) {
            dest->data.b = false;
            retval = 0;
            break;
        }
    }

    free(lower_src);

exit:
    return retval;
}

static int variant_char_to_list(amxc_var_t* const dest,
                                const amxc_var_t* const src) {
    amxc_string_t str;
    int retval = 0;

    amxc_string_init(&str, 0);
    amxc_var_set_type(dest, AMXC_VAR_ID_LIST);
    when_null(src->data.s, exit);

    if(*(src->data.s) != 0) {
        amxc_string_push_buffer(&str, src->data.s, strlen(src->data.s) + 1);
        if(src->type_id == AMXC_VAR_ID_SSV_STRING) {
            retval = amxc_string_ssv_to_var(&str, dest, NULL);
        } else {
            retval = amxc_string_csv_to_var(&str, dest, NULL);
        }
        amxc_string_take_buffer(&str);
    } else {
        retval = 0;
    }

exit:
    amxc_string_clean(&str);
    return retval;
}

static int variant_char_to_htable(amxc_var_t* const dest,
                                  const amxc_var_t* const src) {
    char* temp = NULL;
    int retval = 0;
    char* element = NULL;
    int length = 0;

    amxc_var_set_type(dest, AMXC_VAR_ID_HTABLE);
    when_true(src->data.s == NULL || src->data.s == 0, exit);

    length = strlen(src->data.s) + 1;
    temp = (char*) calloc(1, length);
    when_null(temp, exit);
    memcpy(temp, src->data.s, length);

    element = strtok(temp, ",");
    while(element) {
        amxc_var_t* var = NULL;
        char* key = NULL;
        char* data = NULL;
        when_failed(amxc_var_new(&var), exit);

        var->type_id = AMXC_VAR_ID_CSTRING;
        key = element;
        while(*key) {
            if(*key == ':') {
                *key = 0;
                data = key + 1;
                break;
            }
            key++;
        }
        key = element;
        if(data != NULL) {
            length = strlen(data) + 1;
            var->data.s = (char*) calloc(1, length);
            if(var->data.s == NULL) {
                amxc_var_delete(&var);
                amxc_htable_clean(&dest->data.vm, variant_htable_it_free);
                goto exit;
            }
            memcpy(var->data.s, data, length);
        }
        amxc_htable_insert(&dest->data.vm, key, &var->hit);
        element = strtok(NULL, ",");
    }

    retval = 0;

exit:
    free(temp);
    return retval;
}

static int variant_char_to_ts(amxc_var_t* const dest,
                              const amxc_var_t* const src) {

    int retval = -1;
    when_null(dest, exit);
    when_null(src, exit);
    when_null(src->data.s, exit);

    retval = amxc_ts_parse(&dest->data.ts, src->data.s, strlen(src->data.s));

exit:
    return retval;
}

static int variant_char_copy(amxc_var_t* const dest,
                             const amxc_var_t* const src) {
    int retval = -1;
    if(src->data.s != NULL) {
        int length = strlen(src->data.s) + 1;
        dest->data.s = (char*) calloc(1, length);
        when_null(dest->data.s, exit);
        memcpy(dest->data.s, src->data.s, length);
    }
    retval = 0;

exit:
    return retval;
}

static int variant_char_move(amxc_var_t* const dest,
                             amxc_var_t* const src) {
    dest->data.s = src->data.s;
    src->data.s = NULL;

    return 0;
}

static void variant_char_delete(amxc_var_t* const var) {
    free(var->data.s);
    var->data.s = NULL;
}

static int variant_char_auto_convert(amxc_var_t* const dest,
                                     const amxc_var_t* const src) {
    const char* str_src = src->data.s;
    int retval = -1;
    int src_pos = 0;
    int src_len = 0;
    when_true(str_src == NULL, exit);

    src_len = strlen(str_src);
    if(src_len == 0) {
        retval = 0;
        dest->type_id = AMXC_VAR_ID_CSTRING;
        goto exit;
    }

    for(int i = 0; i < src_len; i++) {
        if(isspace(*(src->data.s + i)) == 0) {
            break;
        }
        // skip white spaces
        src_pos++;
    }

    switch(str_src[src_pos]) {
    case 't':
    case 'T':
    case 'y':
    case 'Y':
    case 'f':
    case 'F':
    case 'n':
    case 'N':
    case 'o':
    case 'O':
        dest->type_id = AMXC_VAR_ID_BOOL;
        retval = variant_char_to_bool(dest, src);
        break;
    case '+':
    case '-':
        dest->type_id = AMXC_VAR_ID_INT32;
        retval = variant_char_to_signed_int(dest, src);
        when_true(retval == 0, exit);
        dest->type_id = AMXC_VAR_ID_INT64;
        retval = variant_char_to_signed_int(dest, src);
        when_true(retval == 0, exit);
        dest->type_id = AMXC_VAR_ID_DOUBLE;
        retval = variant_char_to_double(dest, src);
        break;
    default:
        dest->type_id = AMXC_VAR_ID_UINT32;
        retval = variant_char_to_unsigned_int(dest, src);
        when_true(retval == 0, exit);
        dest->type_id = AMXC_VAR_ID_UINT64;
        retval = variant_char_to_unsigned_int(dest, src);
        when_true(retval == 0, exit);
        dest->type_id = AMXC_VAR_ID_DOUBLE;
        retval = variant_char_to_double(dest, src);
    }
    when_true(retval == 0, exit);

    dest->type_id = AMXC_VAR_ID_TIMESTAMP;
    retval = variant_char_to_ts(dest, src);
    when_true(retval == 0, exit);

    dest->type_id = AMXC_VAR_ID_CSTRING;
    retval = variant_char_copy(dest, src);

exit:
    return retval;
}

static int variant_char_convert_to(amxc_var_t* const dest,
                                   const amxc_var_t* const src) {
    int retval = -1;

    amxc_var_convert_fn_t convfn[AMXC_VAR_ID_CUSTOM_BASE] = {
        amxc_var_default_convert_to_null,       // null
        variant_char_copy,                      // c string
        variant_char_to_signed_int,             // int8
        variant_char_to_signed_int,             // int16
        variant_char_to_signed_int,             // int32
        variant_char_to_signed_int,             // int64
        variant_char_to_unsigned_int,           // uint8
        variant_char_to_unsigned_int,           // uint16
        variant_char_to_unsigned_int,           // uint32
        variant_char_to_unsigned_int,           // uint64
        variant_char_to_float,                  // float
        variant_char_to_double,                 // double
        variant_char_to_bool,                   // bool
        variant_char_to_list,                   // linked list
        variant_char_to_htable,                 // hash table
        NULL,                                   // file descriptor
        variant_char_to_ts,                     // timestamp
        variant_char_copy,                      // comma separated values string
        variant_char_copy,                      // space separated values string
        variant_char_auto_convert,              // any type (auto detect)
    };

    if(dest->type_id >= AMXC_VAR_ID_CUSTOM_BASE) {
        goto exit;
    }

    if(convfn[dest->type_id] != NULL) {
        retval = convfn[dest->type_id](dest, src);
    }

exit:
    return retval;
}

static int variant_char_compare(const amxc_var_t* const lval,
                                const amxc_var_t* const rval,
                                int* const result) {
    *result = strcmp(lval->data.s == NULL ? "" : lval->data.s,
                     rval->data.s == NULL ? "" : rval->data.s);
    return 0;
}

static int variant_char_add_value(amxc_var_t* const dest,
                                  const amxc_var_t* const value) {
    int retval = -1;

    when_false(dest != NULL
               && value != NULL
               && value->type_id == AMXC_VAR_ID_CSTRING
               && dest->type_id == dest->type_id,
               exit);

    if((value->data.s == NULL) || (value->data.s[0] == 0)) {
        retval = 0;
        goto exit;
    }

    if(dest->data.s == NULL) {
        retval = variant_char_copy(dest, value);
    } else {
        size_t cur_len = strlen(dest->data.s);
        size_t val_len = strlen(value->data.s);
        int new_len = cur_len + val_len + 1;
        char* new_str = (char*) calloc(new_len, sizeof(char));
        when_null(new_str, exit);
        strcpy(new_str, dest->data.s);
        memcpy(new_str + cur_len, value->data.s, val_len);
        free(dest->data.s);
        dest->data.s = new_str;
        retval = 0;
    }

exit:
    return retval;
}

static amxc_var_type_t amxc_variant_char = {
    .init = NULL,
    .del = variant_char_delete,
    .copy = variant_char_copy,
    .move = variant_char_move,
    .convert_from = NULL,
    .convert_to = variant_char_convert_to,
    .compare = variant_char_compare,
    .get_key = NULL,
    .set_key = NULL,
    .get_index = NULL,
    .set_index = NULL,
    .add_value = variant_char_add_value,
    .type_id = 0,
    .hit = { .ait = NULL, .key = NULL, .next = NULL },
    .name = AMXC_VAR_NAME_CSTRING
};

static amxc_var_type_t amxc_variant_csv_char = {
    .init = NULL,
    .del = variant_char_delete,
    .copy = variant_char_copy,
    .move = variant_char_move,
    .convert_from = NULL,
    .convert_to = variant_char_convert_to,
    .compare = variant_char_compare,
    .get_key = NULL,
    .set_key = NULL,
    .get_index = NULL,
    .set_index = NULL,
    .add_value = NULL,
    .type_id = 0,
    .hit = { .ait = NULL, .key = NULL, .next = NULL },
    .name = AMXC_VAR_NAME_CSV_STRING
};

static amxc_var_type_t amxc_variant_ssv_char = {
    .init = NULL,
    .del = variant_char_delete,
    .copy = variant_char_copy,
    .move = variant_char_move,
    .convert_from = NULL,
    .convert_to = variant_char_convert_to,
    .compare = variant_char_compare,
    .get_key = NULL,
    .set_key = NULL,
    .get_index = NULL,
    .set_index = NULL,
    .add_value = NULL,
    .type_id = 0,
    .hit = { .ait = NULL, .key = NULL, .next = NULL },
    .name = AMXC_VAR_NAME_SSV_STRING
};

CONSTRUCTOR static void amxc_var_char_init(void) {
    amxc_var_add_type(&amxc_variant_char, AMXC_VAR_ID_CSTRING);
    amxc_var_add_type(&amxc_variant_csv_char, AMXC_VAR_ID_CSV_STRING);
    amxc_var_add_type(&amxc_variant_ssv_char, AMXC_VAR_ID_SSV_STRING);
}

DESTRUCTOR static void amxc_var_char_cleanup(void) {
    amxc_var_remove_type(&amxc_variant_char);
    amxc_var_remove_type(&amxc_variant_csv_char);
    amxc_var_remove_type(&amxc_variant_ssv_char);
}

static int amxc_var_set_data(amxc_var_t* const var, const char* const val) {
    int retval = -1;
    int length = 0;

    length = strlen(val) + 1;
    var->data.s = (char*) calloc(1, length);
    when_null(var->data.s, exit);
    memcpy(var->data.s, val, length);
    retval = 0;

exit:
    if(retval != 0) {
        amxc_var_set_type(var, AMXC_VAR_ID_NULL);
    }
    return retval;
}

int amxc_var_set_cstring_t(amxc_var_t* const var, const char* const val) {
    int retval = -1;
    when_null(var, exit);
    when_null(val, exit);
    when_failed(amxc_var_set_type(var, AMXC_VAR_ID_CSTRING), exit);

    retval = amxc_var_set_data(var, val);

exit:
    return retval;
}

int amxc_var_set_csv_string_t(amxc_var_t* const var, const char* const val) {
    int retval = -1;
    when_null(var, exit);
    when_null(val, exit);
    when_failed(amxc_var_set_type(var, AMXC_VAR_ID_CSV_STRING), exit);

    retval = amxc_var_set_data(var, val);

exit:
    return retval;
}

int amxc_var_set_ssv_string_t(amxc_var_t* const var, const char* const val) {
    int retval = -1;
    when_null(var, exit);
    when_null(val, exit);
    when_failed(amxc_var_set_type(var, AMXC_VAR_ID_SSV_STRING), exit);

    retval = amxc_var_set_data(var, val);

exit:
    return retval;
}

cstring_t amxc_var_get_cstring_t(const amxc_var_t* const var) {
    char* retval = NULL;
    amxc_var_t variant;
    when_null(var, exit);

    amxc_var_init(&variant);
    when_failed(amxc_var_convert(&variant, var, AMXC_VAR_ID_CSTRING), exit);
    retval = variant.data.s != NULL ? variant.data.s : strdup("");
    variant.data.s = NULL;
    amxc_var_clean(&variant);

exit:
    return retval;
}

const cstring_t amxc_var_get_const_cstring_t(const amxc_var_t* const var) {
    const char* retval = NULL;
    when_null(var, exit);
    when_true(var->type_id != AMXC_VAR_ID_CSTRING &&
              var->type_id != AMXC_VAR_ID_CSV_STRING &&
              var->type_id != AMXC_VAR_ID_SSV_STRING, exit);

    retval = var->data.s == NULL ? "" : var->data.s;

exit:
    return retval;
}

cstring_t amxc_var_take_cstring_t(amxc_var_t* const var) {
    char* retval = NULL;
    when_null(var, exit);
    when_true(var->type_id != AMXC_VAR_ID_CSTRING &&
              var->type_id != AMXC_VAR_ID_CSV_STRING &&
              var->type_id != AMXC_VAR_ID_SSV_STRING, exit);

    retval = var->data.s;

    var->data.s = NULL;
    var->type_id = AMXC_VAR_ID_NULL;

exit:
    return retval;
}

int amxc_var_push_cstring_t(amxc_var_t* const var, char* val) {
    int retval = -1;

    when_null(var, exit);
    amxc_var_clean(var);

    var->type_id = AMXC_VAR_ID_CSTRING;
    var->data.s = val;

    retval = 0;

exit:
    return retval;
}

int amxc_var_push_csv_string_t(amxc_var_t* const var, char* val) {
    int retval = -1;

    retval = amxc_var_push_cstring_t(var, val);
    if(retval == 0) {
        var->type_id = AMXC_VAR_ID_CSV_STRING;
    }

    return retval;
}

int amxc_var_push_ssv_string_t(amxc_var_t* const var, char* val) {
    int retval = -1;

    retval = amxc_var_push_cstring_t(var, val);
    if(retval == 0) {
        var->type_id = AMXC_VAR_ID_SSV_STRING;
    }

    return retval;
}

amxc_var_t* amxc_var_add_new_cstring_t(amxc_var_t* const var, const char* const val) {
    amxc_var_t* subvar = NULL;

    when_null(var, exit);
    subvar = amxc_var_add_new(var);
    when_null(subvar, exit);

    if(amxc_var_set_cstring_t(subvar, val) != 0) {
        amxc_var_delete(&subvar);
    }

exit:
    return subvar;
}

amxc_var_t* amxc_var_add_new_csv_string_t(amxc_var_t* const var, const char* const val) {
    amxc_var_t* subvar = NULL;

    when_null(var, exit);
    subvar = amxc_var_add_new(var);
    when_null(subvar, exit);

    if(amxc_var_set_csv_string_t(subvar, val) != 0) {
        amxc_var_delete(&subvar);
    }

exit:
    return subvar;
}

amxc_var_t* amxc_var_add_new_ssv_string_t(amxc_var_t* const var, const char* const val) {
    amxc_var_t* subvar = NULL;

    when_null(var, exit);
    subvar = amxc_var_add_new(var);
    when_null(subvar, exit);

    if(amxc_var_set_csv_string_t(subvar, val) != 0) {
        amxc_var_delete(&subvar);
    }

exit:
    return subvar;
}

amxc_var_t* amxc_var_add_new_key_cstring_t(amxc_var_t* const var,
                                           const char* key,
                                           const char* const val) {
    amxc_var_t* subvar = NULL;

    when_null(var, exit);
    subvar = amxc_var_add_new_key(var, key);
    when_null(subvar, exit);

    if(amxc_var_set_cstring_t(subvar, val) != 0) {
        amxc_var_delete(&subvar);
    }

exit:
    return subvar;
}

amxc_var_t* amxc_var_add_new_key_csv_string_t(amxc_var_t* const var,
                                              const char* key,
                                              const char* const val) {
    amxc_var_t* subvar = NULL;

    when_null(var, exit);
    subvar = amxc_var_add_new_key(var, key);
    when_null(subvar, exit);

    if(amxc_var_set_csv_string_t(subvar, val) != 0) {
        amxc_var_delete(&subvar);
    }

exit:
    return subvar;
}

amxc_var_t* amxc_var_add_new_key_ssv_string_t(amxc_var_t* const var,
                                              const char* key,
                                              const char* const val) {
    amxc_var_t* subvar = NULL;

    when_null(var, exit);
    subvar = amxc_var_add_new_key(var, key);
    when_null(subvar, exit);

    if(amxc_var_set_ssv_string_t(subvar, val) != 0) {
        amxc_var_delete(&subvar);
    }

exit:
    return subvar;
}
