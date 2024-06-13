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
#include <sys/time.h>
#include <sys/resource.h>

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <inttypes.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <cmocka.h>

#include <amxc/amxc_macros.h>
#include <amxc/amxc.h>
#include <amxp/amxp_cron.h>

#include "test_cron.h"

void test_cron_expr_parser(UNUSED void** state) {
    amxp_cron_expr_t cron_expr;
    amxp_cron_init(&cron_expr);

    assert_int_equal(amxp_cron_parse_expr(&cron_expr, "* * * * * *", NULL), 0);
    assert_int_equal(amxp_cron_parse_expr(&cron_expr, "* * * ? * *", NULL), 0);
    assert_int_equal(amxp_cron_parse_expr(&cron_expr, "* * * * * ?", NULL), 0);
    assert_int_equal(amxp_cron_parse_expr(&cron_expr, "* * * 1/10 JAN,JUN,JUL ?", NULL), 0);
    assert_int_equal(amxp_cron_parse_expr(&cron_expr, "* * * ? JAN,JUN,JUL MON,WED,FRI", NULL), 0);
    assert_int_equal(amxp_cron_parse_expr(&cron_expr, "0 10-12 10/10 * * *", NULL), 0);
    assert_int_equal(amxp_cron_parse_expr(&cron_expr, "0 10-12 10/10 1-5/1 * *", NULL), 0);
    assert_int_equal(amxp_cron_parse_expr(&cron_expr, "0 0,10,20,30,40,50 12 * * *", NULL), 0);
    assert_int_equal(amxp_cron_parse_expr(&cron_expr, "* * 10/10 * * 0", NULL), 0);
    assert_int_equal(amxp_cron_parse_expr(&cron_expr, "* * 10/10 * * 7", NULL), 0);
    assert_int_equal(amxp_cron_parse_expr(&cron_expr, "0 0 12 ? * SAT,SUN", NULL), 0);

    amxp_cron_clean(&cron_expr);
}

void test_cron_expr_build_weekly(UNUSED void** state) {
    amxp_cron_expr_t cron_expr;
    amxp_cron_init(&cron_expr);

    assert_int_equal(amxp_cron_build_weekly(&cron_expr, "15:15", "MONDAY"), 0);
    assert_int_equal(amxp_cron_build_weekly(&cron_expr, "12:00", "MONDAY,TUESDAY,wednesday,thursday,friday"), 0);
    assert_int_equal(amxp_cron_build_weekly(&cron_expr, "16:15:20", "monday-friday"), 0);
    assert_int_equal(amxp_cron_build_weekly(&cron_expr, "", "monday-friday"), 0);

    amxp_cron_clean(&cron_expr);
}

void test_cron_expr_parser_invalid_expression(UNUSED void** state) {
    amxp_cron_expr_t cron_expr;
    const char* error = NULL;
    amxp_cron_init(&cron_expr);

    assert_int_not_equal(amxp_cron_parse_expr(&cron_expr, "Invalid expression", &error), 0);
    assert_non_null(error);

    error = NULL;
    assert_int_not_equal(amxp_cron_parse_expr(&cron_expr, "* * *", &error), 0);
    assert_non_null(error);

    error = NULL;
    assert_int_not_equal(amxp_cron_parse_expr(NULL, "* * *", &error), 0);
    assert_non_null(error);

    error = NULL;
    assert_int_not_equal(amxp_cron_parse_expr(&cron_expr, NULL, &error), 0);
    assert_non_null(error);

    amxp_cron_clean(&cron_expr);
}

void test_cron_expr_parser_invalid_increment(UNUSED void** state) {
    amxp_cron_expr_t cron_expr;
    const char* error = NULL;
    amxp_cron_init(&cron_expr);

    assert_int_not_equal(amxp_cron_parse_expr(&cron_expr, "0 10-12 10/0 * * *", &error), 0);
    assert_non_null(error);

    error = NULL;
    assert_int_not_equal(amxp_cron_parse_expr(&cron_expr, "0 10-12 10/AB * * *", &error), 0);
    assert_non_null(error);

    error = NULL;
    assert_int_not_equal(amxp_cron_parse_expr(&cron_expr, "0 10-12 10/2/3 * * *", &error), 0);
    assert_non_null(error);

    error = NULL;
    assert_int_not_equal(amxp_cron_parse_expr(&cron_expr, "0 10/-12 10 * * *", &error), 0);
    assert_non_null(error);

    amxp_cron_clean(&cron_expr);
}

void test_cron_expr_parser_invalid_range(UNUSED void** state) {
    amxp_cron_expr_t* cron_expr = NULL;
    const char* error = NULL;
    amxp_cron_new(&cron_expr);
    assert_non_null(cron_expr);

    error = NULL;
    assert_int_not_equal(amxp_cron_parse_expr(cron_expr, "0 30-12 10 * * *", &error), 0);
    assert_non_null(error);

    error = NULL;
    assert_int_not_equal(amxp_cron_parse_expr(cron_expr, "0 8-40 30-40 * * *", &error), 0);
    assert_non_null(error);

    error = NULL;
    assert_int_not_equal(amxp_cron_parse_expr(cron_expr, "0 12-10 10/2 * * *", &error), 0);
    assert_non_null(error);

    error = NULL;
    assert_int_not_equal(amxp_cron_parse_expr(cron_expr, "0 5-Z 10/2 * * *", &error), 0);
    assert_non_null(error);

    error = NULL;
    assert_int_not_equal(amxp_cron_parse_expr(cron_expr, "0 A-10 10/2 * * *", &error), 0);
    assert_non_null(error);

    error = NULL;
    assert_int_not_equal(amxp_cron_parse_expr(cron_expr, "0 A-B 10/2 * * *", &error), 0);
    assert_non_null(error);

    error = NULL;
    assert_int_not_equal(amxp_cron_parse_expr(cron_expr, "0 10-12-14 10/2 * * *", &error), 0);
    assert_non_null(error);

    error = NULL;
    assert_int_not_equal(amxp_cron_parse_expr(cron_expr, "-5 10-12 10/2 * * *", &error), 0);
    assert_non_null(error);

    error = NULL;
    assert_int_not_equal(amxp_cron_parse_expr(cron_expr, "0 10-12 10/10 0-5/1 * *", &error), 0);
    assert_non_null(error);

    amxp_cron_delete(&cron_expr);
}

void test_cron_expr_can_calculate_next_second(UNUSED void** state) {
    amxp_cron_expr_t* cron_expr = NULL;
    amxc_ts_t start = { 0, 0, 0 };
    amxc_ts_t next = { 0, 0, 0 };
    char str_ts[40];

    amxp_cron_new(&cron_expr);
    assert_non_null(cron_expr);

    assert_int_equal(amxp_cron_parse_expr(cron_expr, "* 0 12 1 JAN-DEC/2 *", NULL), 0);
    assert_non_null(cron_expr);

    amxc_ts_parse(&start, "2023-05-18T10:07:24Z", 20);
    amxc_ts_format(&start, str_ts, 40);
    printf("%s\n", str_ts);

    assert_int_equal(amxp_cron_next(cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-07-01T12:00:00Z");

    start = next;
    assert_int_equal(amxp_cron_next(cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-07-01T12:00:01Z");

    start = next;
    assert_int_equal(amxp_cron_next(cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-07-01T12:00:02Z");

    start = next;
    assert_int_equal(amxp_cron_next(cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-07-01T12:00:03Z");

    start = next;
    assert_int_equal(amxp_cron_next(cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-07-01T12:00:04Z");

    start = next;
    assert_int_equal(amxp_cron_next(cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-07-01T12:00:05Z");

    amxp_cron_delete(&cron_expr);
}

void test_cron_expr_can_calculate_prev_second(UNUSED void** state) {
    amxp_cron_expr_t* cron_expr = NULL;
    amxc_ts_t start = { 0, 0, 0 };
    amxc_ts_t next = { 0, 0, 0 };
    char str_ts[40];

    amxp_cron_new(&cron_expr);
    assert_non_null(cron_expr);

    assert_int_equal(amxp_cron_parse_expr(cron_expr, "* 0 12 1 JAN-DEC/2 *", NULL), 0);
    assert_non_null(cron_expr);

    amxc_ts_parse(&start, "2023-05-18T10:07:24Z", 20);
    amxc_ts_format(&start, str_ts, 40);
    printf("%s\n", str_ts);

    assert_int_equal(amxp_cron_prev(cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-05-01T12:00:59Z");

    start = next;
    assert_int_equal(amxp_cron_prev(cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-05-01T12:00:58Z");

    start = next;
    assert_int_equal(amxp_cron_prev(cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-05-01T12:00:57Z");

    start = next;
    assert_int_equal(amxp_cron_prev(cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-05-01T12:00:56Z");

    start = next;
    assert_int_equal(amxp_cron_prev(cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-05-01T12:00:55Z");

    start = next;
    assert_int_equal(amxp_cron_prev(cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-05-01T12:00:54Z");

    amxp_cron_delete(&cron_expr);
}

void test_cron_expr_can_calculate_next_minutes(UNUSED void** state) {
    amxp_cron_expr_t cron_expr;
    amxc_ts_t start = { 0, 0, 0 };
    amxc_ts_t next = { 0, 0, 0 };
    char str_ts[40];

    amxp_cron_init(&cron_expr);

    assert_int_equal(amxp_cron_parse_expr(&cron_expr, "0 0,10,20,30,40,50 * * * *", NULL), 0);

    amxc_ts_parse(&start, "2023-05-18T10:07:24Z", 20);
    amxc_ts_format(&start, str_ts, 40);
    printf("%s\n", str_ts);

    assert_int_equal(amxp_cron_next(&cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-05-18T10:10:00Z");

    start = next;
    assert_int_equal(amxp_cron_next(&cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-05-18T10:20:00Z");

    start = next;
    assert_int_equal(amxp_cron_next(&cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-05-18T10:30:00Z");

    start = next;
    assert_int_equal(amxp_cron_next(&cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-05-18T10:40:00Z");

    start = next;
    assert_int_equal(amxp_cron_next(&cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-05-18T10:50:00Z");

    start = next;
    assert_int_equal(amxp_cron_next(&cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-05-18T11:00:00Z");

    amxp_cron_clean(&cron_expr);
}

void test_cron_expr_can_calculate_prev_minutes(UNUSED void** state) {
    amxp_cron_expr_t cron_expr;
    amxc_ts_t start = { 0, 0, 0 };
    amxc_ts_t next = { 0, 0, 0 };
    char str_ts[40];

    amxp_cron_init(&cron_expr);

    assert_int_equal(amxp_cron_parse_expr(&cron_expr, "0 0,10,20,30,40,50 * * * *", NULL), 0);

    amxc_ts_parse(&start, "2023-05-18T10:07:24Z", 20);
    amxc_ts_format(&start, str_ts, 40);
    printf("%s\n", str_ts);

    assert_int_equal(amxp_cron_prev(&cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-05-18T10:00:00Z");

    start = next;
    assert_int_equal(amxp_cron_prev(&cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-05-18T09:50:00Z");

    start = next;
    assert_int_equal(amxp_cron_prev(&cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-05-18T09:40:00Z");

    start = next;
    assert_int_equal(amxp_cron_prev(&cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-05-18T09:30:00Z");

    start = next;
    assert_int_equal(amxp_cron_prev(&cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-05-18T09:20:00Z");

    start = next;
    assert_int_equal(amxp_cron_prev(&cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-05-18T09:10:00Z");

    amxp_cron_clean(&cron_expr);
}

void test_cron_expr_can_calculate_next_hours(UNUSED void** state) {
    amxp_cron_expr_t cron_expr;
    amxc_ts_t start = { 0, 0, 0 };
    amxc_ts_t next = { 0, 0, 0 };
    char str_ts[40];

    amxp_cron_init(&cron_expr);

    assert_int_equal(amxp_cron_parse_expr(&cron_expr, "0 15 10,12,14 * * *", NULL), 0);

    amxc_ts_parse(&start, "2023-05-18T10:07:24Z", 20);
    amxc_ts_format(&start, str_ts, 40);
    printf("%s\n", str_ts);

    assert_int_equal(amxp_cron_next(&cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-05-18T10:15:00Z");

    start = next;
    assert_int_equal(amxp_cron_next(&cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-05-18T12:15:00Z");

    start = next;
    assert_int_equal(amxp_cron_next(&cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-05-18T14:15:00Z");

    start = next;
    assert_int_equal(amxp_cron_next(&cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-05-19T10:15:00Z");

    printf("=== USING LOCAL TIME ===\n");
    amxc_ts_parse(&start, "2023-05-19T12:25:00+02:00", 25);
    amxc_ts_format(&start, str_ts, 40);
    printf("%s\n", str_ts);

    assert_int_equal(amxp_cron_next(&cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-05-19T14:15:00+02:00");

    start = next;
    assert_int_equal(amxp_cron_next(&cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-05-20T10:15:00+02:00");

    amxp_cron_clean(&cron_expr);
}

void test_cron_expr_can_calculate_prev_hours(UNUSED void** state) {
    amxp_cron_expr_t cron_expr;
    amxc_ts_t start = { 0, 0, 0 };
    amxc_ts_t next = { 0, 0, 0 };
    char str_ts[40];

    amxp_cron_init(&cron_expr);

    assert_int_equal(amxp_cron_parse_expr(&cron_expr, "0 15 10,12,14 * * *", NULL), 0);

    amxc_ts_parse(&start, "2023-05-17T14:15:00Z", 20);
    amxc_ts_format(&start, str_ts, 40);
    printf("%s\n", str_ts);

    assert_int_equal(amxp_cron_prev(&cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-05-17T12:15:00Z");

    start = next;
    assert_int_equal(amxp_cron_prev(&cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-05-17T10:15:00Z");

    start = next;
    assert_int_equal(amxp_cron_prev(&cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-05-16T14:15:00Z");

    start = next;
    assert_int_equal(amxp_cron_prev(&cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-05-16T12:15:00Z");

    printf("=== USING LOCAL TIME ===\n");
    amxc_ts_parse(&start, "2023-05-19T12:25:00+02:00", 25);
    amxc_ts_format(&start, str_ts, 40);
    printf("%s\n", str_ts);

    assert_int_equal(amxp_cron_prev(&cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-05-19T12:15:00+02:00");

    start = next;
    assert_int_equal(amxp_cron_prev(&cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-05-19T10:15:00+02:00");

    amxp_cron_clean(&cron_expr);
}

void test_cron_expr_can_calculate_next_day(UNUSED void** state) {
    amxp_cron_expr_t* cron_expr = NULL;
    amxc_ts_t start = { 0, 0, 0 };
    amxc_ts_t next = { 0, 0, 0 };
    char str_ts[40];

    amxp_cron_new(&cron_expr);
    assert_non_null(cron_expr);

    assert_int_equal(amxp_cron_parse_expr(cron_expr, "0 0 12 1-31/4 * *", NULL), 0);
    assert_non_null(cron_expr);

    amxc_ts_parse(&start, "2023-05-18T10:07:24Z", 20);
    amxc_ts_format(&start, str_ts, 40);
    printf("%s\n", str_ts);

    assert_int_equal(amxp_cron_next(cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-05-21T12:00:00Z");

    start = next;
    assert_int_equal(amxp_cron_next(cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-05-25T12:00:00Z");

    start = next;
    assert_int_equal(amxp_cron_next(cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-05-29T12:00:00Z");

    start = next;
    assert_int_equal(amxp_cron_next(cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-06-01T12:00:00Z");

    start = next;
    assert_int_equal(amxp_cron_next(cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-06-05T12:00:00Z");

    start = next;
    assert_int_equal(amxp_cron_next(cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-06-09T12:00:00Z");

    amxp_cron_delete(&cron_expr);
}

void test_cron_expr_can_calculate_prev_day(UNUSED void** state) {
    amxp_cron_expr_t* cron_expr = NULL;
    amxc_ts_t start = { 0, 0, 0 };
    amxc_ts_t next = { 0, 0, 0 };
    char str_ts[40];

    amxp_cron_new(&cron_expr);
    assert_non_null(cron_expr);

    assert_int_equal(amxp_cron_parse_expr(cron_expr, "0 0 12 1-31/4 * *", NULL), 0);
    assert_non_null(cron_expr);

    amxc_ts_parse(&start, "2023-05-18T10:07:24Z", 20);
    amxc_ts_format(&start, str_ts, 40);
    printf("%s\n", str_ts);

    assert_int_equal(amxp_cron_prev(cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-05-17T12:00:00Z");

    start = next;
    assert_int_equal(amxp_cron_prev(cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-05-13T12:00:00Z");

    start = next;
    assert_int_equal(amxp_cron_prev(cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-05-09T12:00:00Z");

    start = next;
    assert_int_equal(amxp_cron_prev(cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-05-05T12:00:00Z");

    start = next;
    assert_int_equal(amxp_cron_prev(cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-05-01T12:00:00Z");

    start = next;
    assert_int_equal(amxp_cron_prev(cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-04-29T12:00:00Z");

    amxp_cron_delete(&cron_expr);
}

void test_cron_expr_can_calculate_next_day_of_week(UNUSED void** state) {
    amxp_cron_expr_t* cron_expr = NULL;
    amxc_ts_t start = { 0, 0, 0 };
    amxc_ts_t next = { 0, 0, 0 };
    char str_ts[40];

    amxp_cron_new(&cron_expr);
    assert_non_null(cron_expr);

    assert_int_equal(amxp_cron_parse_expr(cron_expr, "0 0 12 ? * SAT,SUN", NULL), 0);
    assert_non_null(cron_expr);

    amxc_ts_parse(&start, "2023-05-18T10:07:24Z", 20);
    amxc_ts_format(&start, str_ts, 40);
    printf("%s\n", str_ts);

    assert_int_equal(amxp_cron_next(cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-05-20T12:00:00Z");

    start = next;
    assert_int_equal(amxp_cron_next(cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-05-21T12:00:00Z");

    start = next;
    assert_int_equal(amxp_cron_next(cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-05-27T12:00:00Z");

    start = next;
    assert_int_equal(amxp_cron_next(cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-05-28T12:00:00Z");

    start = next;
    assert_int_equal(amxp_cron_next(cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-06-03T12:00:00Z");

    start = next;
    assert_int_equal(amxp_cron_next(cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-06-04T12:00:00Z");

    amxp_cron_delete(&cron_expr);
}

void test_cron_expr_can_calculate_prev_day_of_week(UNUSED void** state) {
    amxp_cron_expr_t* cron_expr = NULL;
    amxc_ts_t start = { 0, 0, 0 };
    amxc_ts_t next = { 0, 0, 0 };
    char str_ts[40];

    amxp_cron_new(&cron_expr);
    assert_non_null(cron_expr);

    assert_int_equal(amxp_cron_parse_expr(cron_expr, "0 0 12 ? * SAT,SUN", NULL), 0);
    assert_non_null(cron_expr);

    amxc_ts_parse(&start, "2023-05-18T10:07:24Z", 20);
    amxc_ts_format(&start, str_ts, 40);
    printf("%s\n", str_ts);

    assert_int_equal(amxp_cron_prev(cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-05-14T12:00:00Z");

    start = next;
    assert_int_equal(amxp_cron_prev(cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-05-13T12:00:00Z");

    start = next;
    assert_int_equal(amxp_cron_prev(cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-05-07T12:00:00Z");

    start = next;
    assert_int_equal(amxp_cron_prev(cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-05-06T12:00:00Z");

    start = next;
    assert_int_equal(amxp_cron_prev(cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-04-30T12:00:00Z");

    start = next;
    assert_int_equal(amxp_cron_prev(cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-04-29T12:00:00Z");

    amxp_cron_delete(&cron_expr);
}

void test_cron_expr_can_calculate_next_month(UNUSED void** state) {
    amxp_cron_expr_t* cron_expr = NULL;
    amxc_ts_t start = { 0, 0, 0 };
    amxc_ts_t next = { 0, 0, 0 };
    char str_ts[40];

    amxp_cron_new(&cron_expr);
    assert_non_null(cron_expr);

    assert_int_equal(amxp_cron_parse_expr(cron_expr, "0 0 12 1 JAN-DEC/2 *", NULL), 0);
    assert_non_null(cron_expr);

    amxc_ts_parse(&start, "2023-05-18T10:07:24Z", 20);
    amxc_ts_format(&start, str_ts, 40);
    printf("%s\n", str_ts);

    assert_int_equal(amxp_cron_next(cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-07-01T12:00:00Z");

    start = next;
    assert_int_equal(amxp_cron_next(cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-09-01T12:00:00Z");

    start = next;
    assert_int_equal(amxp_cron_next(cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-11-01T12:00:00Z");

    start = next;
    assert_int_equal(amxp_cron_next(cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2024-01-01T12:00:00Z");

    start = next;
    assert_int_equal(amxp_cron_next(cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2024-03-01T12:00:00Z");

    start = next;
    assert_int_equal(amxp_cron_next(cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2024-05-01T12:00:00Z");

    start = next;
    assert_int_equal(amxp_cron_next(cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2024-07-01T12:00:00Z");

    start = next;
    assert_int_equal(amxp_cron_next(cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2024-09-01T12:00:00Z");

    amxp_cron_delete(&cron_expr);
}

void test_cron_expr_can_calculate_prev_month(UNUSED void** state) {
    amxp_cron_expr_t* cron_expr = NULL;
    amxc_ts_t start = { 0, 0, 0 };
    amxc_ts_t next = { 0, 0, 0 };
    char str_ts[40];

    amxp_cron_new(&cron_expr);
    assert_non_null(cron_expr);

    assert_int_equal(amxp_cron_parse_expr(cron_expr, "0 0 12 1 JAN-DEC/2 *", NULL), 0);
    assert_non_null(cron_expr);

    amxc_ts_parse(&start, "2023-05-18T10:07:24Z", 20);
    amxc_ts_format(&start, str_ts, 40);
    printf("%s\n", str_ts);

    assert_int_equal(amxp_cron_prev(cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-05-01T12:00:00Z");

    start = next;
    assert_int_equal(amxp_cron_prev(cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-03-01T12:00:00Z");

    start = next;
    assert_int_equal(amxp_cron_prev(cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-01-01T12:00:00Z");

    start = next;
    assert_int_equal(amxp_cron_prev(cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2022-11-01T12:00:00Z");

    start = next;
    assert_int_equal(amxp_cron_prev(cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2022-09-01T12:00:00Z");

    start = next;
    assert_int_equal(amxp_cron_prev(cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2022-07-01T12:00:00Z");

    start = next;
    assert_int_equal(amxp_cron_prev(cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2022-05-01T12:00:00Z");

    start = next;
    assert_int_equal(amxp_cron_prev(cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2022-03-01T12:00:00Z");

    amxp_cron_delete(&cron_expr);
}

void test_cron_expr_can_calculate_first_monday_of_month(UNUSED void** state) {
    amxp_cron_expr_t* cron_expr = NULL;
    amxc_ts_t start = { 0, 0, 0 };
    amxc_ts_t next = { 0, 0, 0 };
    char str_ts[40];

    amxp_cron_new(&cron_expr);
    assert_non_null(cron_expr);

    assert_int_equal(amxp_cron_parse_expr(cron_expr, "0 0 0 1-7 JAN-DEC MON", NULL), 0);
    assert_non_null(cron_expr);

    amxc_ts_parse(&start, "2023-05-18T10:07:24Z", 20);
    amxc_ts_format(&start, str_ts, 40);
    printf("%s\n", str_ts);

    assert_int_equal(amxp_cron_next(cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-06-05T00:00:00Z");

    start = next;
    assert_int_equal(amxp_cron_next(cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-07-03T00:00:00Z");

    start = next;
    assert_int_equal(amxp_cron_next(cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-08-07T00:00:00Z");

    start = next;
    assert_int_equal(amxp_cron_next(cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-09-04T00:00:00Z");

    start = next;
    assert_int_equal(amxp_cron_next(cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-10-02T00:00:00Z");

    start = next;
    assert_int_equal(amxp_cron_next(cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-11-06T00:00:00Z");

    amxp_cron_delete(&cron_expr);
}

void test_cron_expr_weekly(UNUSED void** state) {
    amxp_cron_expr_t* cron_expr = NULL;
    amxc_ts_t start = { 0, 0, 0 };
    amxc_ts_t next = { 0, 0, 0 };
    char str_ts[40];

    amxp_cron_new(&cron_expr);
    assert_non_null(cron_expr);

    amxc_ts_parse(&start, "2023-05-18T10:07:24Z", 20);
    amxc_ts_format(&start, str_ts, 40);
    printf("%s\n", str_ts);

    amxp_cron_build_weekly(cron_expr, "18:00", "monday,tuesday,thursday,friday");
    assert_int_equal(amxp_cron_next(cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-05-18T18:00:00Z");

    start = next;
    assert_int_equal(amxp_cron_next(cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-05-19T18:00:00Z");

    start = next;
    assert_int_equal(amxp_cron_next(cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-05-22T18:00:00Z");

    start = next;
    assert_int_equal(amxp_cron_next(cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-05-23T18:00:00Z");

    start = next;
    assert_int_equal(amxp_cron_next(cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-05-25T18:00:00Z");

    start = next;
    assert_int_equal(amxp_cron_next(cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-05-26T18:00:00Z");

    start = next;
    assert_int_equal(amxp_cron_next(cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-05-29T18:00:00Z");

    amxp_cron_delete(&cron_expr);
}

void test_cron_expr_next_empty(UNUSED void** state) {
    amxp_cron_expr_t* cron_expr = NULL;
    amxc_ts_t start = { 0, 0, 0 };
    amxc_ts_t next = { 0, 0, 0 };
    char str_ts[40];

    amxp_cron_new(&cron_expr);
    assert_non_null(cron_expr);

    amxc_ts_parse(&start, "2023-05-18T10:07:24Z", 20);
    amxc_ts_format(&start, str_ts, 40);
    printf("%s\n", str_ts);

    assert_int_equal(amxp_cron_next(cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-05-18T10:07:25Z");

    start = next;
    assert_int_equal(amxp_cron_next(cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-05-18T10:07:26Z");

    start = next;
    assert_int_equal(amxp_cron_next(cron_expr, &start, &next), 0);
    amxc_ts_format(&next, str_ts, 40);
    printf("%s\n", str_ts);
    assert_string_equal(str_ts, "2023-05-18T10:07:27Z");

    assert_int_equal(amxp_cron_time_until_next(cron_expr, false), 1);
    assert_int_equal(amxp_cron_time_until_next(cron_expr, true), 1);

    amxp_cron_delete(&cron_expr);
}

void test_cron_expr_next_invalid(UNUSED void** state) {
    amxp_cron_expr_t* cron_expr = NULL;
    amxc_ts_t start = { 0, 0, 0 };
    amxc_ts_t next = { 0, 0, 0 };

    amxp_cron_new(&cron_expr);
    assert_non_null(cron_expr);

    assert_int_not_equal(amxp_cron_next(NULL, &start, &next), 0);

    assert_int_equal(amxp_cron_parse_expr(cron_expr, "* 0 12 1 JAN-DEC/2 *", NULL), 0);
    assert_non_null(cron_expr);
    assert_int_not_equal(amxp_cron_next(cron_expr, NULL, &next), 0);
    assert_int_not_equal(amxp_cron_next(cron_expr, &start, NULL), 0);

    start.sec = -1;
    assert_int_not_equal(amxp_cron_next(cron_expr, &start, NULL), 0);

    amxp_cron_delete(&cron_expr);
}