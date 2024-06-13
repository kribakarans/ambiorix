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
#include <errno.h>
#include <string.h>
#include <time.h>

#include <amxc/amxc.h>
#include <amxp/amxp_cron.h>
#include <amxc/amxc_macros.h>

#include "amxp_cron_parser_priv.h"

static const char* const MONTHS_ARR[] = {
    "FOO", "JAN", "FEB", "MAR", "APR",
    "MAY", "JUN", "JUL", "AUG", "SEP",
    "OCT", "NOV", "DEC"
};

static const char* const DAYS_ARR[] = {
    "SUN", "MON", "TUE", "WED",
    "THU", "FRI", "SAT"
};

static const char* const DAYS_ARR_FULL[] = {
    "SUNDAY", "MONDAY", "TUESDAY", "WEDNESDAY",
    "THURSDAY", "FRIDAY", "SATURDAY"
};

#define CRON_MONTHS_ARR_LEN 13
#define CRON_DAYS_ARR_LEN 7

static void cron_set_bit(uint8_t* rbyte, int idx) {
    uint8_t j = (uint8_t) (idx / 8);
    uint8_t k = (uint8_t) (idx % 8);

    rbyte[j] |= (1 << k);
}

static void cron_del_bit(uint8_t* rbyte, int idx) {
    uint8_t j = (uint8_t) (idx / 8);
    uint8_t k = (uint8_t) (idx % 8);

    rbyte[j] &= ~(1 << k);
}

static bool has_char(const char* str, char ch) {
    size_t i = 0;
    size_t len = 0;
    bool rv = false;

    len = strlen(str);

    for(i = 0; i < len; i++) {
        if(str[i] == ch) {
            rv = true;
            break;
        }
    }

    return rv;
}

static uint32_t parse_uint(const char* str, bool* invalid) {
    char* endptr = NULL;
    int64_t value = 0;

    errno = 0;
    *invalid = false;
    if(str[0] == 0) {
        *invalid = true;
    } else {
        value = strtol(str, &endptr, 10);
        if((errno == ERANGE) || (*endptr != '\0') || (value < 0) || (value > INT32_MAX)) {
            *invalid = true;
            value = 0;
        } else {
            *invalid = false;
        }
    }
    return (uint32_t) value;
}

static void replace_ordinals(amxc_string_t* value,
                             const char* const* arr,
                             uint32_t arr_len) {
    char* cur = NULL;
    amxc_var_t num;
    amxc_var_init(&num);
    for(uint32_t i = 0; i < arr_len; i++) {
        amxc_var_set(uint32_t, &num, i);
        cur = amxc_var_dyncast(cstring_t, &num);
        amxc_string_replace(value, arr[i], cur, UINT32_MAX);
        free(cur);
    }
    amxc_var_clean(&num);
}

static int split_string(amxc_llist_t* parts,
                        char* str,
                        const char sep,
                        uint32_t expected_len) {
    uint32_t len = 0;
    int rv = -1;
    amxc_string_t strfield;
    amxc_string_init(&strfield, 0);

    amxc_string_push_buffer(&strfield, str, strlen(str) + 1);
    amxc_string_split_to_llist(&strfield, parts, sep);

    len = amxc_llist_size(parts);
    when_false(len == expected_len, exit);

    rv = 0;

exit:
    if(rv != 0) {
        amxc_llist_clean(parts, amxc_string_list_it_free);
    }

    amxc_string_take_buffer(&strfield);
    amxc_string_clean(&strfield);
    return rv;
}

static uint32_t* get_range(char* field,
                           uint32_t min,
                           uint32_t max,
                           const char** error) {
    size_t len = 0;
    uint32_t* res = (uint32_t*) calloc(2, sizeof(uint32_t));
    bool invalid = true;

    when_null(res, exit);

    if((strlen(field) == 1) && (field[0] == '*')) {
        res[0] = min;
        res[1] = max - 1;
    } else if(!has_char(field, '-')) {
        uint32_t val = parse_uint(field, &invalid);
        when_true_status(invalid, exit, *error = "Invalid value (1)");
        res[0] = val;
        res[1] = val;
    } else {
        amxc_llist_t parts;
        amxc_llist_init(&parts);
        when_failed_status(split_string(&parts, field, '-', 2), exit, *error = "Specified range requires two fields");
        len = 0;
        amxc_llist_for_each(it, &parts) {
            amxc_string_t* strpart = amxc_string_from_llist_it(it);
            amxc_string_trim(strpart, NULL);
            res[len] = parse_uint(amxc_string_get(strpart, 0), &invalid);
            if(invalid) {
                *error = "Invalid value (2)";
                break;
            }
            len++;
        }
        amxc_llist_clean(&parts, amxc_string_list_it_free);
        when_true(invalid, exit);
    }

    invalid = true;
    when_true_status(res[0] >= max || res[1] >= max, exit, *error = "Specified range exceeds maximum");
    when_true_status(res[0] < min || res[1] < min, exit, *error = "Specified range is less than minimum");
    when_true_status(res[0] > res[1], exit, *error = "Specified range start exceeds range end");

    invalid = false;
    *error = NULL;

exit:
    if(invalid && (res != NULL)) {
        free(res);
        res = NULL;
    }

    return res;
}

static uint32_t* get_range_increment(char* field,
                                     uint32_t min,
                                     uint32_t max,
                                     uint32_t* increment,
                                     const char** error) {
    amxc_llist_it_t* it = NULL;
    amxc_string_t* strpart = NULL;
    amxc_llist_t parts;
    bool invalid = true;
    uint32_t* range = NULL;

    amxc_llist_init(&parts);
    when_failed_status(split_string(&parts, field, '/', 2), exit, *error = "Incrementer must have two fields");

    it = amxc_llist_get_first(&parts);
    strpart = amxc_string_from_llist_it(it);
    range = get_range(strpart->buffer, min, max, error);
    when_null(range, exit);
    if(*error != NULL) {
        free(range);
        range = NULL;
        goto exit;
    }
    if(!has_char(amxc_string_get(strpart, 0), '-')) {
        range[1] = max - 1;
    }

    it = amxc_llist_it_get_next(it);
    strpart = amxc_string_from_llist_it(it);
    *increment = parse_uint(amxc_string_get(strpart, 0), &invalid);
    when_true_status(invalid, exit, *error = "Invalid value (3)");

exit:
    amxc_llist_clean(&parts, amxc_string_list_it_free);
    return range;
}

uint8_t cron_get_bit(const uint8_t* rbyte, int idx) {
    uint8_t j = (uint8_t) (idx / 8);
    uint8_t k = (uint8_t) (idx % 8);

    if(rbyte[j] & (1 << k)) {
        return 1;
    } else {
        return 0;
    }
}

int amxp_cron_reset(amxp_cron_expr_t* cron_expr) {
    int retval = -1;
    when_null(cron_expr, exit);
    memset(cron_expr, 0, sizeof(amxp_cron_expr_t));

exit:
    return retval;
}

int amxp_cron_set_hits(amxc_var_t* value,
                       uint8_t* target,
                       uint32_t min,
                       uint32_t max,
                       const char** error) {
    amxc_var_t fields;
    uint32_t delta = 1;
    uint32_t* range = NULL;
    char* field_expr = NULL;
    int rv = -1;

    amxc_var_init(&fields);
    amxc_var_set(csv_string_t, &fields, GET_CHAR(value, NULL));
    amxc_var_cast(&fields, AMXC_VAR_ID_LIST);

    amxc_var_for_each(field, &fields) {
        field_expr = amxc_var_take(cstring_t, field);
        if(!has_char(field_expr, '/')) {
            range = get_range(field_expr, min, max, error);
            when_null(range, exit);
            when_not_null_status(*error, exit, free(range));
        } else {
            range = get_range_increment(field_expr, min, max, &delta, error);
            when_null(range, exit);
            when_not_null_status(*error, exit, free(range));
            if(delta == 0) {
                *error = "Incrementer may not be zero";
                free(range);
                goto exit;
            }
        }

        for(size_t i = range[0]; i <= range[1]; i += delta) {
            cron_set_bit(target, i);
        }
        free(range);
        free(field_expr);
        field_expr = NULL;
    }

    rv = 0;

exit:
    free(field_expr);
    amxc_var_clean(&fields);
    return rv;
}

int amxp_cron_set_months(amxc_var_t* value,
                         uint8_t* target,
                         uint32_t min,
                         uint32_t max,
                         const char** error) {
    int rv = -1;
    amxc_string_t str_value;
    char* v = amxc_var_take(cstring_t, value);
    amxc_string_init(&str_value, 0);

    amxc_string_push_buffer(&str_value, v, strlen(v) + 1);
    amxc_string_to_upper(&str_value);
    replace_ordinals(&str_value, MONTHS_ARR, CRON_MONTHS_ARR_LEN);
    amxc_var_set(cstring_t, value, amxc_string_get(&str_value, 0));
    rv = amxp_cron_set_hits(value, target, min, max, error);

    /* ... and then rotate it to the front of the months */
    for(uint32_t i = 1; i <= max; i++) {
        if(cron_get_bit(target, i)) {
            cron_set_bit(target, i - 1);
            cron_del_bit(target, i);
        }
    }

    amxc_string_clean(&str_value);
    return rv;
}

int amxp_cron_set_days_of_week(amxc_var_t* value,
                               uint8_t* target,
                               uint32_t min,
                               uint32_t max,
                               const char** error) {
    int rv = -1;
    amxc_string_t str_value;
    char* v = amxc_var_take(cstring_t, value);

    amxc_string_init(&str_value, 0);

    amxc_string_push_buffer(&str_value, v, strlen(v) + 1);
    amxc_string_to_upper(&str_value);

    if((amxc_string_text_length(&str_value) == 1) && (str_value.buffer[0] == '?')) {
        str_value.buffer[0] = '*';
    }

    replace_ordinals(&str_value, DAYS_ARR_FULL, CRON_DAYS_ARR_LEN);
    replace_ordinals(&str_value, DAYS_ARR, CRON_DAYS_ARR_LEN);
    amxc_var_set(cstring_t, value, amxc_string_get(&str_value, 0));

    rv = amxp_cron_set_hits(value, target, min, max, error);

    if(cron_get_bit(target, 7)) {
        // Sunday can be represented as 0 or 7
        cron_set_bit(target, 0);
        cron_del_bit(target, 7);
    }

    amxc_string_clean(&str_value);
    return rv;
}

int amxp_cron_set_days_of_month(amxc_var_t* value,
                                uint8_t* target,
                                uint32_t min,
                                uint32_t max,
                                const char** error) {
    const char* field = GET_CHAR(value, NULL);

    if((strlen(field) == 1) && (field[0] == '?')) {
        amxc_var_set(cstring_t, value, "*");
    }

    return amxp_cron_set_hits(value, target, min, max, error);
}
