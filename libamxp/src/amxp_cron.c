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
#include <ctype.h>

#include <amxc/amxc.h>
#include <amxp/amxp_cron.h>
#include <amxc/amxc_macros.h>

#include "amxp_cron_parser_priv.h"

#define CRON_MAX_SECONDS 60
#define CRON_MAX_MINUTES 60
#define CRON_MAX_HOURS 24
#define CRON_MAX_DAYS_OF_WEEK 8
#define CRON_MAX_DAYS_OF_MONTH 32
#define CRON_MAX_MONTHS 13

#define CRON_CF_SECOND 0
#define CRON_CF_MINUTE 1
#define CRON_CF_HOUR_OF_DAY 2
#define CRON_CF_DAY_OF_WEEK 3
#define CRON_CF_DAY_OF_MONTH 4
#define CRON_CF_MONTH 5
#define CRON_CF_YEAR 6

#define CRON_CF_ARR_LEN 7

static int32_t amxp_cron_next_bit(const uint8_t* bits,
                                  int32_t from_index,
                                  int32_t to_index,
                                  bool forwards,
                                  bool* notfound) {
    int32_t rv = 0;

    if(forwards) {
        for(int32_t i = from_index; i < to_index; i++) {
            if(cron_get_bit(bits, i)) {
                rv = i;
                goto exit;
            }
        }
    } else {
        for(int32_t i = from_index; i >= to_index; i--) {
            if(cron_get_bit(bits, i)) {
                rv = i;
                goto exit;
            }
        }
    }

    *notfound = true;

exit:
    return rv;
}

static void push_to_fields_arr(int* arr, int fi) {
    when_true(arr == NULL || fi == -1, exit);

    for(int i = 0; i < CRON_CF_ARR_LEN; i++) {
        when_true(arr[i] == fi, exit);
    }
    for(int i = 0; i < CRON_CF_ARR_LEN; i++) {
        if(arr[i] == -1) {
            arr[i] = fi;
            break;
        }
    }

exit:
    return;
}

static int last_day_of_month(int month, int year) {
    struct tm cal;
    struct tm* calctm = NULL;
    time_t t;
    memset(&cal, 0, sizeof(cal));
    cal.tm_mon = month + 1;
    cal.tm_year = year;
    t = mktime(&cal);
    calctm = gmtime(&t);
    return calctm != NULL? calctm->tm_mday:31;
}

static int amxp_cron_reset_min(struct tm* calendar, int field) {
    int rv = 1;
    when_true(field == -1, exit);

    switch(field) {
    case CRON_CF_SECOND:
        calendar->tm_sec = 0;
        break;
    case CRON_CF_MINUTE:
        calendar->tm_min = 0;
        break;
    case CRON_CF_HOUR_OF_DAY:
        calendar->tm_hour = 0;
        break;
    case CRON_CF_DAY_OF_WEEK:
        calendar->tm_wday = 0;
        break;
    case CRON_CF_DAY_OF_MONTH:
        calendar->tm_mday = 1;
        break;
    case CRON_CF_MONTH:
        calendar->tm_mon = 0;
        break;
    case CRON_CF_YEAR:
        calendar->tm_year = 0;
        break;
    }
    rv = timegm(calendar) == -1? 1:0;

exit:
    return rv;
}

static int amxp_cron_reset_max(struct tm* calendar, int field) {
    int rv = 1;
    when_true(field == -1, exit);

    switch(field) {
    case CRON_CF_SECOND:
        calendar->tm_sec = 59;
        break;
    case CRON_CF_MINUTE:
        calendar->tm_min = 59;
        break;
    case CRON_CF_HOUR_OF_DAY:
        calendar->tm_hour = 23;
        break;
    case CRON_CF_DAY_OF_WEEK:
        calendar->tm_wday = 6;
        break;
    case CRON_CF_DAY_OF_MONTH:
        calendar->tm_mday = last_day_of_month(calendar->tm_mon, calendar->tm_year);
        break;
    case CRON_CF_MONTH:
        calendar->tm_mon = 11;
        break;
    }
    rv = timegm(calendar) == -1? 1:0;

exit:
    return rv;
}

static int amxp_cron_reset_all(struct tm* calendar, int* fields, bool minimum) {
    int res = 0;

    for(int i = 0; i < CRON_CF_ARR_LEN; i++) {
        if(fields[i] != -1) {
            res = minimum? amxp_cron_reset_min(calendar, fields[i]):amxp_cron_reset_max(calendar, fields[i]);
            when_failed(res, exit);
        }
    }

exit:
    return res;
}

static int amxp_cron_set_field(struct tm* calendar, int field, int val, bool add) {
    int rv = 1;
    when_true(field == -1, exit);

    switch(field) {
    case CRON_CF_SECOND:
        calendar->tm_sec = add? calendar->tm_sec + val:val;
        break;
    case CRON_CF_MINUTE:
        calendar->tm_min = add? calendar->tm_min + val:val;
        break;
    case CRON_CF_HOUR_OF_DAY:
        calendar->tm_hour = add? calendar->tm_hour + val:val;
        break;
    case CRON_CF_DAY_OF_WEEK:
        if(add) {
            /* mkgmtime ignores this field */
            calendar->tm_mday = calendar->tm_mday + val;
        } else {
            calendar->tm_wday = val;
        }
        break;
    case CRON_CF_DAY_OF_MONTH:
        calendar->tm_mday = add? calendar->tm_mday + val:val;
        break;
    case CRON_CF_MONTH:
        calendar->tm_mon = add? calendar->tm_mon + val:val;
        break;
    case CRON_CF_YEAR:
        calendar->tm_year = add? calendar->tm_year + val:val;
        break;
    }
    rv = timegm(calendar) == -1? 1:0;

exit:
    return rv;
}

static uint32_t amxp_cron_find_next(const uint8_t* bits,
                                    int32_t max,
                                    int32_t value,
                                    struct tm* calendar,
                                    uint32_t field,
                                    uint32_t next_field,
                                    int* lower_orders,
                                    bool forward,
                                    int* res_out) {
    bool notfound = false;
    int err = 0;
    int32_t next_value = amxp_cron_next_bit(bits, value, forward? max:0, forward, &notfound);

    *res_out = 1;

    /* roll over if needed */
    if(notfound) {
        err = amxp_cron_set_field(calendar, next_field, forward? 1:-1, true);
        when_failed_status(err, exit, next_value = 0);
        if(forward) {
            err = amxp_cron_reset_min(calendar, field);
        } else {
            err = amxp_cron_reset_max(calendar, field);
        }
        when_failed_status(err, exit, next_value = 0);
        notfound = 0;
        next_value = amxp_cron_next_bit(bits, forward? 0:max - 1, forward? max:value, forward, &notfound);
    }

    if(notfound || (next_value != value)) {
        err = amxp_cron_set_field(calendar, field, next_value, false);
        when_failed_status(err, exit, next_value = 0);
        err = amxp_cron_reset_all(calendar, lower_orders, forward);
        when_failed_status(err, exit, next_value = 0);
    }

    *res_out = 0;

exit:
    return next_value;
}

static unsigned int amxp_cron_find_next_day(struct tm* calendar,
                                            const uint8_t* days_of_month,
                                            unsigned int day_of_month,
                                            const uint8_t* days_of_week,
                                            unsigned int day_of_week,
                                            int* resets,
                                            bool forward,
                                            int* res_out) {
    int err;
    unsigned int count = 0;
    unsigned int max = 366;

    *res_out = 1;
    while((!cron_get_bit(days_of_month, day_of_month) ||
           !cron_get_bit(days_of_week, day_of_week)) &&
          count++ < max) {
        err = amxp_cron_set_field(calendar, CRON_CF_DAY_OF_MONTH, forward? 1:-1, true);
        when_failed(err, exit);
        day_of_month = calendar->tm_mday;
        day_of_week = calendar->tm_wday;
        amxp_cron_reset_all(calendar, resets, forward);
    }

    *res_out = 0;

exit:
    return day_of_month;
}

static int amxp_cron_calc_next(const amxp_cron_expr_t* expr, struct tm* calendar, unsigned int dot, bool forwards) {
    int i;
    int res = 0;
    int* resets = NULL;
    int* empty_list = NULL;
    unsigned int second = 0;
    unsigned int update_second = 0;
    unsigned int minute = 0;
    unsigned int update_minute = 0;
    unsigned int hour = 0;
    unsigned int update_hour = 0;
    unsigned int day_of_week = 0;
    unsigned int day_of_month = 0;
    unsigned int update_day_of_month = 0;
    unsigned int month = 0;
    unsigned int update_month = 0;

    resets = (int*) calloc(CRON_CF_ARR_LEN, sizeof(int));
    when_null(resets, return_result);
    empty_list = (int*) calloc(CRON_CF_ARR_LEN, sizeof(int));
    when_null(empty_list, return_result);
    for(i = 0; i < CRON_CF_ARR_LEN; i++) {
        resets[i] = -1;
        empty_list[i] = -1;
    }

    second = calendar->tm_sec;
    update_second = amxp_cron_find_next(expr->seconds, CRON_MAX_SECONDS, second, calendar,
                                        CRON_CF_SECOND, CRON_CF_MINUTE, empty_list, forwards, &res);
    when_failed(res, return_result);
    if(second == update_second) {
        push_to_fields_arr(resets, CRON_CF_SECOND);
    }

    minute = calendar->tm_min;
    update_minute = amxp_cron_find_next(expr->minutes, CRON_MAX_MINUTES, minute, calendar,
                                        CRON_CF_MINUTE, CRON_CF_HOUR_OF_DAY, resets, forwards, &res);
    when_failed(res, return_result);
    if(minute == update_minute) {
        push_to_fields_arr(resets, CRON_CF_MINUTE);
    } else {
        res = amxp_cron_calc_next(expr, calendar, dot, forwards);
        when_failed(res, return_result);
    }

    hour = calendar->tm_hour;
    update_hour = amxp_cron_find_next(expr->hours, CRON_MAX_HOURS, hour, calendar,
                                      CRON_CF_HOUR_OF_DAY, CRON_CF_DAY_OF_WEEK, resets, forwards, &res);
    when_failed(res, return_result);
    if(hour == update_hour) {
        push_to_fields_arr(resets, CRON_CF_HOUR_OF_DAY);
    } else {
        res = amxp_cron_calc_next(expr, calendar, dot, forwards);
        when_failed(res, return_result);
    }

    day_of_week = calendar->tm_wday;
    day_of_month = calendar->tm_mday;
    update_day_of_month = amxp_cron_find_next_day(calendar, expr->days_of_month, day_of_month,
                                                  expr->days_of_week, day_of_week, resets, forwards, &res);
    when_failed(res, return_result);
    if(day_of_month == update_day_of_month) {
        push_to_fields_arr(resets, CRON_CF_DAY_OF_MONTH);
    } else {
        res = amxp_cron_calc_next(expr, calendar, dot, forwards);
        when_failed(res, return_result);
    }

    month = calendar->tm_mon; /*day already adds one if no day in same month is found*/
    update_month = amxp_cron_find_next(expr->months, CRON_MAX_MONTHS, month, calendar,
                                       CRON_CF_MONTH, CRON_CF_YEAR, resets, forwards, &res);
    when_failed(res, return_result);
    if(month != update_month) {
        if(forwards) {
            when_true_status(calendar->tm_year - dot > 4, return_result, res = -1);
        } else {
            when_true_status(dot - calendar->tm_year > 4, return_result, res = -1);
        }
        res = amxp_cron_calc_next(expr, calendar, dot, forwards);
        when_failed(res, return_result);
    }

return_result:
    if((resets == NULL) || (empty_list == NULL)) {
        res = -1;
    }
    free(resets);
    free(empty_list);
    return res;
}

static void amxp_cron_remove_spaces(amxc_string_t* result, const char* days_of_week) {
    size_t pos = 0;
    amxc_string_set(result, days_of_week);
    amxc_string_trim(result, NULL);

    pos = amxc_string_text_length(result);

    while(pos > 0) {
        if(isspace(result->buffer[pos - 1]) != 0) {
            amxc_string_remove_at(result, pos - 1, 1);
            continue;
        }
        pos--;
    }
}

int amxp_cron_new(amxp_cron_expr_t** cron_expr) {
    int retval = -1;
    when_null(cron_expr, exit);

    *cron_expr = (amxp_cron_expr_t*) calloc(1, sizeof(amxp_cron_expr_t));
    when_null(*cron_expr, exit);

    retval = amxp_cron_init(*cron_expr);

exit:
    return retval;
}

void amxp_cron_delete(amxp_cron_expr_t** cron_expr) {
    when_null(cron_expr, exit);
    when_null(*cron_expr, exit);

    amxp_cron_clean(*cron_expr);

    free(*cron_expr);
    *cron_expr = NULL;

exit:
    return;
}

int amxp_cron_init(amxp_cron_expr_t* cron_expr) {
    int retval = -1;
    when_null(cron_expr, exit);

    amxp_cron_parse_expr(cron_expr, "* * * * * *", NULL);
    retval = 0;

exit:
    return retval;
}

void amxp_cron_clean(amxp_cron_expr_t* cron_expr) {
    when_null(cron_expr, exit);

    amxp_cron_parse_expr(cron_expr, "* * * * * *", NULL);

exit:
    return;
}

int amxp_cron_parse_expr(amxp_cron_expr_t* target,
                         const char* expression,
                         const char** error) {
    const char* err_local = NULL;
    size_t len = 0;
    int rv = -1;
    amxc_var_t fields;
    static amxp_cron_hits_t hits[] = {
        { amxp_cron_set_hits, offsetof(amxp_cron_expr_t, seconds), 0, CRON_MAX_SECONDS },
        { amxp_cron_set_hits, offsetof(amxp_cron_expr_t, minutes), 0, CRON_MAX_MINUTES },
        { amxp_cron_set_hits, offsetof(amxp_cron_expr_t, hours), 0, CRON_MAX_HOURS },
        { amxp_cron_set_days_of_month, offsetof(amxp_cron_expr_t, days_of_month), 1, CRON_MAX_DAYS_OF_MONTH },
        { amxp_cron_set_months, offsetof(amxp_cron_expr_t, months), 1, CRON_MAX_MONTHS },
        { amxp_cron_set_days_of_week, offsetof(amxp_cron_expr_t, days_of_week), 0, CRON_MAX_DAYS_OF_WEEK },
    };

    if(error == NULL) {
        error = &err_local;
    }
    *error = NULL;

    amxc_var_init(&fields);

    when_null_status(expression, exit, *error = "Invalid NULL expression");
    when_null_status(target, exit, *error = "Invalid NULL target");
    amxp_cron_reset(target);

    amxc_var_set(ssv_string_t, &fields, expression);
    amxc_var_cast(&fields, AMXC_VAR_ID_LIST);
    len = amxc_llist_size(amxc_var_constcast(amxc_llist_t, &fields));
    when_false_status(len == 6, exit, *error = "Invalid number of fields, expression must consist of 6 fields");

    len = 0;
    amxc_var_for_each(field, &fields) {
        uint8_t* target_field = (uint8_t*) (((char*) (target)) + hits[len].offset);
        rv = hits[len].fn(field, target_field, hits[len].min, hits[len].max, error);
        when_failed(rv, exit);
        len++;
    }

exit:
    amxc_var_clean(&fields);
    return rv;
}

int amxp_cron_build_weekly(amxp_cron_expr_t* target,
                           const char* time,
                           const char* days_of_week) {
    int rv = -1;
    amxc_string_t expr;
    amxc_string_t strtime;
    amxc_string_t* time_part = NULL;
    amxc_llist_t parts;
    int len = 0;
    amxc_llist_it_t* it = NULL;

    amxc_string_init(&strtime, 0);
    amxc_llist_init(&parts);
    amxc_string_init(&expr, 0);

    when_null(target, exit);
    when_null(time, exit);
    when_str_empty(days_of_week, exit);
    amxp_cron_remove_spaces(&strtime, days_of_week);

    amxc_string_setf(&expr, "* * %s", amxc_string_get(&strtime, 0));
    amxc_string_set(&strtime, time);
    if(amxc_string_is_empty(&strtime)) {
        amxc_string_prependf(&expr, "0 0 0 ");
    } else {
        amxc_string_split_to_llist(&strtime, &parts, ':');
        len = amxc_llist_size(&parts);
        when_true(len < 2 || len > 3, exit);

        it = amxc_llist_take_first(&parts);
        time_part = amxc_string_from_llist_it(it);
        amxc_string_prependf(&expr, "%s ", amxc_string_get(time_part, 0));
        amxc_string_delete(&time_part);

        it = amxc_llist_take_first(&parts);
        time_part = amxc_string_from_llist_it(it);
        amxc_string_prependf(&expr, "%s ", amxc_string_get(time_part, 0));
        amxc_string_delete(&time_part);

        it = amxc_llist_take_first(&parts);
        if(it == NULL) {
            amxc_string_prependf(&expr, "0 ");
        } else {
            time_part = amxc_string_from_llist_it(it);
            amxc_string_prependf(&expr, "%s ", amxc_string_get(time_part, 0));
            amxc_string_delete(&time_part);
        }
    }
    rv = amxp_cron_parse_expr(target, amxc_string_get(&expr, 0), NULL);

exit:
    amxc_llist_clean(&parts, amxc_string_list_it_free);
    amxc_string_clean(&strtime);
    amxc_string_clean(&expr);
    return rv;
}

int amxp_cron_prev(const amxp_cron_expr_t* expr, const amxc_ts_t* ref, amxc_ts_t* next) {
    int rv = -1;
    struct tm calval;
    struct tm* calendar = NULL;
    time_t date = 0;
    time_t original = 0;
    time_t calculated = 0;
    int res = 0;

    memset(&calval, 0, sizeof(struct tm));

    when_null(expr, exit);
    when_null(next, exit);
    when_null(ref, exit);

    date = ref->sec + (ref->offset * 60);
    calendar = gmtime_r(&date, &calval);
    when_null(calendar, exit);
    original = timegm(calendar);
    when_true(original == -1, exit);

    /* calculate the previous occurrence */
    res = amxp_cron_calc_next(expr, calendar, calendar->tm_year, false);
    when_failed(res, exit);
    calculated = timegm(calendar);
    when_true(calculated == -1, exit);

    if(calculated == original) {
        /* We arrived at the original timestamp - round up to the next whole second and try again... */
        res = amxp_cron_set_field(calendar, CRON_CF_SECOND, -1, true);
        when_failed(res, exit);
        res = amxp_cron_calc_next(expr, calendar, calendar->tm_year, false);
        when_failed(res, exit)
    }

    next->sec = timegm(calendar) - (ref->offset * 60);
    next->offset = ref->offset;
    rv = 0;

exit:
    return rv;
}

int amxp_cron_next(const amxp_cron_expr_t* expr, const amxc_ts_t* ref, amxc_ts_t* next) {
    int rv = -1;
    struct tm calval;
    struct tm* calendar = NULL;
    time_t date = 0;
    time_t original = 0;
    time_t calculated = 0;
    int res = 0;

    memset(&calval, 0, sizeof(struct tm));

    when_null(expr, exit);
    when_null(next, exit);
    when_null(ref, exit);

    date = ref->sec + (ref->offset * 60);
    calendar = gmtime_r(&date, &calval);
    when_null(calendar, exit);
    original = timegm(calendar);
    when_true(original == -1, exit);

    res = amxp_cron_calc_next(expr, calendar, calendar->tm_year, true);
    when_failed(res, exit);
    calculated = timegm(calendar);
    when_true(calculated == -1, exit);

    if(calculated == original) {
        /* We arrived at the original timestamp - round up to the next whole second and try again... */
        res = amxp_cron_set_field(calendar, CRON_CF_SECOND, 1, true);
        when_failed(res, exit);
        res = amxp_cron_calc_next(expr, calendar, calendar->tm_year, true);
        when_failed(res, exit)
    }

    next->sec = timegm(calendar) - (ref->offset * 60);
    next->offset = ref->offset;
    rv = 0;

exit:
    return rv;
}

int64_t amxp_cron_time_until_next(const amxp_cron_expr_t* expr, bool local) {
    int64_t seconds = -1;
    amxc_ts_t now;
    amxc_ts_t next = { 0, 0, 0 };

    when_null(expr, exit);
    amxc_ts_now(&now);
    if(local) {
        amxc_ts_to_local(&now);
    }

    when_failed(amxp_cron_next(expr, &now, &next), exit);
    seconds = next.sec - now.sec;

exit:
    return seconds;
}