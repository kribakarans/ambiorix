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

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <setjmp.h>
#include <stdarg.h>
#include <cmocka.h>
#include <amxc/amxc_timestamp.h>

#include "test_amxc_timestamp.h"

#include <amxc/amxc_macros.h>
void test_amxc_ts_now(UNUSED void** state) {
    amxc_ts_t ts1, ts2;

    assert_int_equal(amxc_ts_now(&ts1), 0);
    assert_int_not_equal(ts1.sec, 0);
    assert_int_not_equal(amxc_ts_now(NULL), 0);

    struct timespec waittime = {0, 300 * 1000 * 1000L};
    while(nanosleep(&waittime, NULL) != 0) {
    }
    assert_int_equal(amxc_ts_now(&ts2), 0);
    assert_true(amxc_ts_compare(&ts2, &ts1) > 0);

    // The POSIX standard guarantees that at least 300 000 000 nanoseconds
    // have passed between the calls, so the diff should exceed that
    int64_t diff_us = ts2.nsec - ts1.nsec;
    int64_t diff = (ts2.sec - ts1.sec) * 1000 * 1000 * 1000L + diff_us;
    assert_true(diff > 300 * 1000 * 1000L);
}

void test_amxc_ts_parse_valid(UNUSED void** state) {
    amxc_ts_t ts;
    const char* formats[] = {
        "1970-07-28T15:45:00Z",
        "0001-01-01T00:00:00Z",
        "2020-02-29T16:16:16+02:00",
        "2020-02-29T16:16:16.123+02:00",
        "2020-02-29T16:16:16-01:15",
        "2020-02-29T16:16:16.123456-01:15",
        "2000-02-28T23:14:00Z",
        "1970-01-01T00:00:00Z",
        "1970-01-01t00:00:00Z",
        "1970-01-01 00:00:00Z",
        "1970-01-01T00:00:00z",
        NULL
    };

    const int64_t timestamps[] = {
        18027900,
        -62135596800,
        1582985776,
        1582985776,
        1582997476,
        1582997476,
        951779640,
        0,
        0,
        0,
        0,
    };

    for(int i = 0; formats[i] != NULL; i++) {
        assert_int_equal(amxc_ts_parse(&ts, formats[i], strlen(formats[i])), 0);
        assert_int_equal(ts.sec, timestamps[i]);
    }
}

void test_amxc_ts_parse_invalid(UNUSED void** state) {
    amxc_ts_t ts;
    const char* formats[] = {
        "1970-14-28T15:45:00Z",
        "0001-01-32T00:00:00Z",
        "2020-02-30T16:16:16+02:00",
        "2000-02-31T16:16:16+02:00",
        "0000-02-29T16:16:16.123+02:00",
        "2019-02-29T16:16:16.123+02:00",
        "1984-04-31T00:00:00Z",
        "1984-04-30T26:00:00Z",
        "1984-04-30T13:70:00Z",
        "1984-04-30T13:10:70Z",
        "1984-04-30T13:12:11.9999999999Z",
        "1984-04-30T13:12:11.999999999+24:00",
        "1984-0A-30T13:10:70Z",
        "1984-A0-30T12:10:70Z",
        "Q984-01-30T12:10:70Z",
        "1Q84-01-30T12:10:70Z",
        "19Q4-01-30T12:10:70Z",
        "198Q-01-30T12:10:70Z",
        "184-01-30T10:10:10.9999999-11:00",
        "1984-01-30Z10:10:20.9999999-11:00",
        "1984-01-30T10:10:30Q-11:00",
        "2000.02-28T23:14:00Z",
        "2000-02/28T23:14:00Z",
        "2000-02-28T23.14:00Z",
        "2000-02-28T23:14-00Z",
        "2000-02-28T23:14:00,123Z",
        "2000-00-28T23:14:00.123Z",
        "2000-01-01T24:00:00.000Z",
        "2000-01-01T23:60:00.000Z",
        "2000-01-01T23:00:60.000Z",
        NULL
    };

    for(int i = 0; formats[i] != NULL; i++) {
        printf("Checking [%s]\n", formats[i]);
        assert_int_not_equal(amxc_ts_parse(&ts, formats[i], strlen(formats[i])), 0);
    }

    assert_int_not_equal(amxc_ts_parse(NULL, formats[0], strlen(formats[0])), 0);
    assert_int_not_equal(amxc_ts_parse(&ts, NULL, strlen(formats[0])), 0);
    assert_int_not_equal(amxc_ts_parse(&ts, formats[0], 10), 0);
}

void test_amxc_ts_format_valid(UNUSED void** state) {
    amxc_ts_t ts;
    char str_ts[40];
    const char* formats[] = {
        "1970-07-28T15:45:00Z",
        "0001-01-01T00:00:00Z",
        "2020-02-29T16:16:16+02:00",
        "2020-02-29T16:16:16-01:15",
        "2000-02-28T23:14:00Z",
        "1970-01-01T00:00:00Z",
        "2017-11-11T11:11:11.123+02:00",
        "2017-11-11T11:11:11.123456Z",
        "1994-10-01T00:00:00.123456789-02:30",
        NULL
    };

    for(int i = 0; formats[i] != NULL; i++) {
        printf("Checking [%s]\n", formats[i]);
        assert_int_equal(amxc_ts_parse(&ts, formats[i], strlen(formats[i])), 0);
        assert_int_equal(amxc_ts_format(&ts, str_ts, 40), strlen(formats[i]));
        assert_string_equal(str_ts, formats[i]);
    }
}

void test_amxc_ts_format_invalid(UNUSED void** state) {
    amxc_ts_t ts;
    char str_ts[40];

    assert_int_equal(amxc_ts_parse(&ts, "1970-07-28T15:45:00Z", strlen("1970-07-28T15:45:00Z")), 0);

    assert_int_equal(amxc_ts_format(&ts, NULL, 0), 0);
    assert_int_equal(amxc_ts_format(&ts, str_ts, 0), 0);
    assert_int_equal(amxc_ts_format(&ts, str_ts, 19), 0);
    assert_int_equal(amxc_ts_format(NULL, str_ts, 40), 0);

    assert_int_equal(amxc_ts_format_precision(&ts, str_ts, 40, -1), 0);
    assert_int_equal(amxc_ts_format_precision(&ts, str_ts, 40, 10), 0);

    assert_int_equal(amxc_ts_format_precision(&ts, NULL, 0, 3), 0);
    assert_int_equal(amxc_ts_format_precision(&ts, str_ts, 0, 6), 0);
    assert_int_equal(amxc_ts_format_precision(&ts, str_ts, 19, 9), 0);
    assert_int_equal(amxc_ts_format_precision(NULL, str_ts, 40, 2), 0);

}

void test_amxc_ts_format_precision_valid(UNUSED void** state) {
    amxc_ts_t ts;
    char str_ts[40];
    const char* formats[] = {
        "1970-07-28T15:45:00Z",
        "0001-01-01T00:00:00Z",
        "2020-02-29T16:16:16+02:00",
        "2020-02-29T16:16:16-01:15",
        "2000-02-28T23:14:00Z",
        "1970-01-01T00:00:00Z",
        "2017-11-11T11:11:11.123+02:00",
        "2017-11-11T11:11:11.123456Z",
        "1994-10-01T00:00:00.123456789-02:30",
        NULL
    };

    for(int i = 0; formats[i] != NULL; i++) {
        assert_int_equal(amxc_ts_parse(&ts, formats[i], strlen(formats[i])), 0);
        assert_int_not_equal(amxc_ts_format_precision(&ts, str_ts, 40, 3), 0);
        assert_int_not_equal(amxc_ts_format_precision(&ts, str_ts, 40, 4), 0);
        assert_int_not_equal(amxc_ts_format_precision(&ts, str_ts, 40, 6), 0);
        assert_int_not_equal(amxc_ts_format_precision(&ts, str_ts, 40, 8), 0);
        assert_int_not_equal(amxc_ts_format_precision(&ts, str_ts, 40, 9), 0);
    }
}

void test_amxc_ts_is_valid(UNUSED void** state) {
    char str_ts[40];

    amxc_ts_t ts;
    ts.nsec = 0;
    ts.sec = 0;
    ts.offset = 0;

    assert_true(amxc_ts_is_valid(&ts));

    ts.sec = INT64_C(-62135596800) - 1;
    assert_false(amxc_ts_is_valid(&ts));
    ts.sec = INT64_C(253402300799) + 1;
    assert_false(amxc_ts_is_valid(&ts));

    ts.sec = 0;
    ts.nsec = -1;
    assert_false(amxc_ts_is_valid(&ts));
    ts.nsec = 1999999999;
    assert_false(amxc_ts_is_valid(&ts));
    assert_int_equal(amxc_ts_format(&ts, str_ts, 40), 0);
    assert_int_equal(amxc_ts_format_precision(&ts, str_ts, 40, 3), 0);

    ts.nsec = 0;
    ts.offset = -1440;
    assert_false(amxc_ts_is_valid(&ts));
    ts.offset = 1440;
    assert_false(amxc_ts_is_valid(&ts));

    assert_false(amxc_ts_is_valid(NULL));
}

void test_amxc_ts_compare(UNUSED void** state) {
    amxc_ts_t ts_a;
    amxc_ts_t ts_b;

    assert_int_equal(amxc_ts_parse(&ts_a, "1970-07-28T15:45:00Z", strlen("1970-07-28T15:45:00Z")), 0);
    assert_int_equal(amxc_ts_parse(&ts_b, "1970-08-28T15:45:00Z", strlen("1970-08-28T15:45:00Z")), 0);

    assert_true(amxc_ts_compare(&ts_a, &ts_b) < 0);
    assert_true(amxc_ts_compare(&ts_b, &ts_a) > 0);
    assert_true(amxc_ts_compare(&ts_a, &ts_a) == 0);

    assert_int_equal(amxc_ts_parse(&ts_a, "1970-07-28T15:45:00.123Z", strlen("1970-07-28T15:45:00Z.123")), 0);
    assert_int_equal(amxc_ts_parse(&ts_b, "1970-07-28T15:45:00.456Z", strlen("1970-07-28T15:45:00Z.456")), 0);

    assert_true(amxc_ts_compare(&ts_a, &ts_b) < 0);
    assert_true(amxc_ts_compare(&ts_b, &ts_a) > 0);
    assert_true(amxc_ts_compare(&ts_a, &ts_a) == 0);

    assert_true(amxc_ts_compare(NULL, &ts_a) == 0);
    assert_true(amxc_ts_compare(&ts_a, NULL) == 0);
}

void test_amxc_ts_to_tm(UNUSED void** state) {
    amxc_ts_t ts;
    struct tm tm;

    assert_int_equal(amxc_ts_parse(&ts, "2020-06-17T15:35:22+02:00", strlen("2020-06-17T15:35:22+02:00")), 0);
    assert_int_equal(amxc_ts_to_tm_utc(&ts, &tm), 0);
    assert_int_equal(tm.tm_hour, 13);
    assert_int_equal(tm.tm_min, 35);
    assert_int_equal(tm.tm_sec, 22);
    assert_int_equal(tm.tm_mday, 17);
    assert_int_equal(tm.tm_mon, 5);
    assert_int_equal(tm.tm_year, 120);

    assert_int_equal(amxc_ts_to_tm_local(&ts, &tm), 0);
    assert_int_equal(tm.tm_hour, 15);
    assert_int_equal(tm.tm_min, 35);
    assert_int_equal(tm.tm_sec, 22);
    assert_int_equal(tm.tm_mday, 17);
    assert_int_equal(tm.tm_mon, 5);
    assert_int_equal(tm.tm_year, 120);

    assert_int_not_equal(amxc_ts_to_tm_utc(NULL, &tm), 0);
    assert_int_not_equal(amxc_ts_to_tm_utc(&ts, NULL), 0);

    ts.offset = 1440;
    assert_int_not_equal(amxc_ts_to_tm_utc(&ts, &tm), 0);
}

void test_amxc_ts_to_local(UNUSED void** state) {
    amxc_ts_t ts;
    char* current_tz = getenv("TZ");
    char str_ts[40];
    time_t rawtime;
    struct tm* timeinfo;  // get date and time info

    time(&rawtime);
    timeinfo = localtime(&rawtime);

    setenv("TZ", "Europe/Brussels", true);
    assert_int_equal(amxc_ts_parse(&ts, "2020-06-17T15:35:22Z", strlen("2020-06-17T15:35:22Z")), 0);
    assert_int_equal(ts.offset, 0);
    assert_int_equal(amxc_ts_to_local(&ts), 0);
    if(timeinfo->tm_isdst == 0) {
        assert_int_equal(ts.offset, 60);
        assert_int_equal(amxc_ts_format(&ts, str_ts, 40), strlen("2020-06-17T16:35:22+01:00"));
        assert_string_equal(str_ts, "2020-06-17T16:35:22+01:00");
    } else {
        assert_int_equal(ts.offset, 120);
        assert_int_equal(amxc_ts_format(&ts, str_ts, 40), strlen("2020-06-17T17:35:22+02:00"));
        assert_string_equal(str_ts, "2020-06-17T17:35:22+02:00");
    }

    assert_int_not_equal(amxc_ts_to_local(NULL), 0);

    if(current_tz != NULL) {
        setenv("TZ", current_tz, true);
    } else {
        unsetenv("TZ");
    }
}

void test_amxc_ts_from_tm(UNUSED void** state) {
    amxc_ts_t ts;
    time_t rawtime;
    struct tm* timeinfo = NULL;  // get date and time info

    time(&rawtime);
    timeinfo = localtime(&rawtime);

    assert_int_equal(amxc_ts_from_tm(&ts, timeinfo), 0);
    assert_int_equal(rawtime, ts.sec);
}
