/****************************************************************************
**
** SPDX-License-Identifier: BSD-2-Clause-Patent
**
** SPDX-FileCopyrightText: Copyright (c) 2023 SoftAtHome
**
** Redistribution and use in source and binary forms, with or
** without modification, are permitted provided that the following
** conditions are met:
**
** 1. Redistributions of source code must retain the above copyright
** notice, this list of conditions and the following disclaimer.
**
** 2. Redistributions in binary form must reproduce the above
** copyright notice, this list of conditions and the following
** disclaimer in the documentation and/or other materials provided
** with the distribution.
**
** Subject to the terms and conditions of this license, each
** copyright holder and contributor hereby grants to those receiving
** rights under this license a perpetual, worldwide, non-exclusive,
** no-charge, royalty-free, irrevocable (except for failure to
** satisfy the conditions of this license) patent license to make,
** have made, use, offer to sell, sell, import, and otherwise
** transfer this software, where such license applies only to those
** patent claims, already acquired or hereafter acquired, licensable
** by such copyright holder or contributor that are necessarily
** infringed by:
**
** (a) their Contribution(s) (the licensed copyrights of copyright
** holders and non-copyrightable additions of contributors, in
** source or binary form) alone; or
**
** (b) combination of their Contribution(s) with the work of
** authorship to which such Contribution(s) was added by such
** copyright holder or contributor, if, at the time the Contribution
** is added, such addition causes such combination to be necessarily
** infringed. The patent license shall not apply to any other
** combinations which include the Contribution.
**
** Except as expressly stated above, no rights or licenses from any
** copyright holder or contributor is granted under this license,
** whether expressly, by implication, estoppel or otherwise.
**
** DISCLAIMER
**
** THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
** CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
** INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
** MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
** DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR
** CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
** SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
** LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
** USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
** AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
** LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
** ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
** POSSIBILITY OF SUCH DAMAGE.
**
****************************************************************************/

#include "test_amxut_timer.h"
#include <stdlib.h> // Needed for cmocka
#include <setjmp.h> // Needed for cmocka
#include <stdarg.h> // Needed for cmocka
#include <cmocka.h>
#include <amxut/amxut_timer.h>
#include <amxut/amxut_clock_priv.h>
#include <amxc/amxc.h>
#include <amxc/amxc_macros.h>
#include <amxp/amxp_timer.h>
#include <amxp/amxp_signal.h>
#include <amxp/amxp_slot.h>

#include <debug/sahtrace.h>
#include <string.h>

/**
 * @file This file tests the *fake* timer, not the real timer.
 */

/** @implements amxp_timer_cb_t */
static void s_timer_cb(UNUSED amxp_timer_t* timer, void* priv) {
    int32_t* cb_called_counter = priv;
    (*cb_called_counter)++;
}

/** @implements amxp_slot_fn_t */
static void s_signal_cb(UNUSED const char* const sig_name, UNUSED const amxc_var_t* const data, void* const priv) {
    int32_t* cb_called_counter = priv;
    (*cb_called_counter)++;
}

/** @implements amxp_deferred_fn_t */
static void s_deferred_cb(UNUSED const amxc_var_t* const data, void* const priv) {
    int32_t* cb_called_counter = priv;
    (*cb_called_counter)++;
}

/** @implements amxp_timer_cb_t */
static void s_eventful_timer_cb(UNUSED amxp_timer_t* timer, void* priv) {
    int32_t* nb_times_deferred_called = priv;
    amxp_sigmngr_emit_signal(NULL, "dummy", NULL);
    amxp_sigmngr_deferred_call(NULL, s_deferred_cb, NULL, nb_times_deferred_called);
}

typedef struct {
    amxp_timer_t* timer[3];
    int32_t nb_times_cb_called[3];
} timers_t;

static void s_timers_init(timers_t* timers) {
    for(size_t i = 0; i < 3; i++) {
        timers->nb_times_cb_called[i] = 0;
        timers->timer[i] = NULL;
        amxp_timer_new(&timers->timer[i], s_timer_cb, &timers->nb_times_cb_called[i]);
    }

    amxp_timer_start(timers->timer[0], 1000);
    amxp_timer_start(timers->timer[1], 1500);
    amxp_timer_start(timers->timer[2], 400);
}

static void s_timers_cleanup(timers_t* timers) {
    for(size_t i = 0; i < 3; i++) {
        amxp_timer_delete(&timers->timer[i]);
    }
}

void amxut_timer_go_to_future_ms__normal_case(UNUSED void** state) {
    // GIVEN a running timer
    int32_t nb_times_timer_called = 0;
    amxp_timer_t* timer = NULL;
    amxp_timer_new(&timer, s_timer_cb, &nb_times_timer_called);
    amxp_timer_start(timer, 1000);
    assert_int_equal(0, nb_times_timer_called);

    // WHEN timetraveling exactly as long as the timer is waiting
    amxut_timer_go_to_future_ms(1000);

    // THEN the timer callback got called
    assert_int_equal(1, nb_times_timer_called);

    amxp_timer_delete(&timer);
}

void amxut_timer_go_to_future_ms__all_at_once(UNUSED void** state) {
    // GIVEN multiple running timers
    timers_t timers;
    s_timers_init(&timers);

    // WHEN timetraveling past all timers
    amxut_timer_go_to_future_ms(4000);

    // THEN all timers callback got called
    assert_int_equal(1, timers.nb_times_cb_called[0]);
    assert_int_equal(1, timers.nb_times_cb_called[1]);
    assert_int_equal(1, timers.nb_times_cb_called[2]);

    s_timers_cleanup(&timers);
}

void amxut_timer_go_to_future_ms__one_at_a_time(UNUSED void** state) {
    // GIVEN multiple running timers
    timers_t timers;
    s_timers_init(&timers);

    // WHEN timetraveling past the earliest timer of 400ms:
    amxut_timer_go_to_future_ms(600); // total time traveled: 600ms.

    // THEN the 400ms timer got called
    assert_int_equal(0, timers.nb_times_cb_called[0]);
    assert_int_equal(0, timers.nb_times_cb_called[1]);
    assert_int_equal(1, timers.nb_times_cb_called[2]); // <-- the 400ms timer

    // WHEN timetraveling 500ms
    amxut_timer_go_to_future_ms(500); // total time traveled: 1100ms.

    // THEN it detected we passed the 1000ms timer
    //      Note that it must remember that we already went 200ms past the 400ms-timer.
    assert_int_equal(1, timers.nb_times_cb_called[0]); // <-- the 1000ms timer
    assert_int_equal(0, timers.nb_times_cb_called[1]); // (must stay the same)
    assert_int_equal(1, timers.nb_times_cb_called[2]); // (must stay the same)

    // WHEN timetraveling 400ms to the future
    amxut_timer_go_to_future_ms(400);                  // total time traveled: 1500ms.
    // THEN it detected we passed the 1500ms timer
    assert_int_equal(1, timers.nb_times_cb_called[0]); // (must stay the same)
    assert_int_equal(1, timers.nb_times_cb_called[1]); // <-- the 1500ms timer
    assert_int_equal(1, timers.nb_times_cb_called[2]); // (must stay the same)

    s_timers_cleanup(&timers);
}

void amxut_timer_go_to_future_ms__no_timers(UNUSED void** state) {
    // GIVEN no timers created

    // WHEN timetraveling a lot
    amxut_timer_go_to_future_ms(1000);
    amxut_timer_go_to_future_ms(10000);
    amxut_timer_go_to_future_ms(100000);
    amxut_timer_go_to_future_ms(1000000);

    // THEN nothing happens
}

void amxut_timer_go_to_future_ms__big_timer(UNUSED void** state) {
    // GIVEN a big timer
    unsigned int one_week_in_ms = 7 * 24 * 60 * 60 * 1000;
    int32_t nb_times_timer_called = 0;
    amxp_timer_t* timer = NULL;
    amxp_timer_new(&timer, s_timer_cb, &nb_times_timer_called);
    amxp_timer_start(timer, one_week_in_ms);

    // WHEN timetraveling one week
    amxut_timer_go_to_future_ms(one_week_in_ms);

    // THEN the CI did not timeout.
    //      (and also the timer timed out)
    assert_int_equal(1, nb_times_timer_called);
}

void amxut_timer_go_to_future_ms__step_by_step(UNUSED void** state) {
    // GIVEN a running timer
    int32_t nb_times_timer_called = 0;
    amxp_timer_t* timer = NULL;
    amxp_timer_new(&timer, s_timer_cb, &nb_times_timer_called);
    amxp_timer_start(timer, 1000);

    // WHEN timetraveling many small steps that does not reach the timer
    amxut_timer_go_to_future_ms(100); // total: 100ms
    amxut_timer_go_to_future_ms(10);  // total: 110ms
    amxut_timer_go_to_future_ms(10);  // total: 120ms
    amxut_timer_go_to_future_ms(10);  // total: 130ms
    amxut_timer_go_to_future_ms(10);  // total: 140ms
    amxut_timer_go_to_future_ms(50);  // total: 190ms
    amxut_timer_go_to_future_ms(500); // total: 690ms
    amxut_timer_go_to_future_ms(300); // total: 990ms

    // THEN no timer got triggered
    assert_int_equal(0, nb_times_timer_called);

    // WHEN timetraveling a teeny tiny bit, the last drop to trigger the timer
    amxut_timer_go_to_future_ms(15);  // total: 1050ms

    // THEN the timer got triggered
    assert_int_equal(1, nb_times_timer_called);
}

void amxut_timer_go_to_future_ms__timetravel_before_timer_start(UNUSED void** state) {
    // GIVEN a timer that is not running
    int32_t nb_times_timer_called = 0;
    amxp_timer_t* timer = NULL;
    amxp_timer_new(&timer, s_timer_cb, &nb_times_timer_called);

    // WHEN timetraveling 5 seconds
    amxut_timer_go_to_future_ms(5000);

    // THEN a timer that starts afterwards, is not already 5 seconds "used".
    amxp_timer_start(timer, 6000);
    amxut_timer_go_to_future_ms(1000);
    assert_int_equal(0, nb_times_timer_called);

    amxp_timer_delete(&timer);
}

void amxut_timer_go_to_future_ms__can_trigger_events(UNUSED void** state) {
    // GIVEN a dummy signal
    int32_t nb_times_signal_called = 0;
    amxp_sigmngr_add_signal(NULL, "dummy");
    amxp_slot_connect(NULL, "dummy", NULL, s_signal_cb, &nb_times_signal_called);
    amxp_sigmngr_emit_signal(NULL, "dummy", NULL);
    assert_int_equal(0, nb_times_signal_called);

    // GIVEN a deferred function
    int32_t nb_times_deferred_called = 0;
    amxp_sigmngr_deferred_call(NULL, s_deferred_cb, NULL, &nb_times_deferred_called);
    assert_int_equal(0, nb_times_deferred_called);

    // WHEN timetraveling 0 seconds
    amxut_timer_go_to_future_ms(0);

    // THEN signal and deferred function should have been called
    assert_int_equal(1, nb_times_signal_called);
    assert_int_equal(1, nb_times_deferred_called);

    amxp_slot_disconnect(NULL, "dummy", s_signal_cb);
}

void amxut_timer_go_to_future_ms__can_trigger_events_from_timer(UNUSED void** state) {
    // GIVEN a dummy signal
    int32_t nb_times_signal_called = 0;
    amxp_sigmngr_add_signal(NULL, "dummy");
    amxp_slot_connect(NULL, "dummy", NULL, s_signal_cb, &nb_times_signal_called);
    assert_int_equal(0, nb_times_signal_called);

    // AND GIVEN a deferred function
    int32_t nb_times_deferred_called = 0;

    // AND GIVEN a running timer
    amxp_timer_t* timer = NULL;
    amxp_timer_new(&timer, s_eventful_timer_cb, &nb_times_deferred_called);
    amxp_timer_start(timer, 1000);

    // WHEN timetraveling 0 seconds
    amxut_timer_go_to_future_ms(1000);

    // THEN signal and deferred function should have been called
    assert_int_equal(1, nb_times_signal_called);
    assert_int_equal(1, nb_times_deferred_called);

    amxp_slot_disconnect(NULL, "dummy", s_signal_cb);
}

static time_t s_seconds_since_epoch(void) {
    amxc_ts_t time_amx = {};
    struct tm time_tm = {};
    amxc_ts_now(&time_amx);
    char buffer[123] = {};
    amxc_ts_format(&time_amx, buffer, sizeof(buffer));
    assert_int_equal(0, amxc_ts_to_tm_utc(&time_amx, &time_tm));
    return mktime(&time_tm);
}

void amxut_timer_go_to_future_ms__affects_clock(UNUSED void** state) {
    // GIVEN the current clock time
    amxut_timer_go_to_future_ms(0); // force clock does not move on its own.
    time_t timestamp1 = s_seconds_since_epoch();

    // WHEN timetraveling 700 seconds
    amxut_timer_go_to_future_ms(700 * 1000);

    // THEN the clock time is 700 seconds later
    time_t timestamp2 = s_seconds_since_epoch();
    time_t diff = timestamp2 - timestamp1;
    assert_int_equal(diff, 700);
}

/** @implements amxp_timer_cb_t */
static void s_timer_remember_timestamp_cb(UNUSED amxp_timer_t* timer, void* priv) {
    time_t* target_timestamp = priv;
    *target_timestamp = s_seconds_since_epoch();
}

/** @implements amxp_timer_cb_t */
static void s_timer_remember_amxc_timestamp_cb(UNUSED amxp_timer_t* timer, void* priv) {
    amxc_ts_t* target_timestamp = priv;
    amxc_ts_now(target_timestamp);
}

void amxut_timer_go_to_future_ms__affects_clock_observed_by_timers(UNUSED void** state) {
    // GIVEN a timer after 50 seconds, and one after 70 seconds
    amxut_timer_go_to_future_ms(0); // force clock does not move on its own.
    time_t timestamp_start = s_seconds_since_epoch();
    time_t timestamp1 = {0};
    time_t timestamp2 = {0};
    amxp_timer_t* timer1 = NULL;
    amxp_timer_t* timer2 = NULL;
    amxp_timer_new(&timer1, s_timer_remember_timestamp_cb, &timestamp1);
    amxp_timer_new(&timer2, s_timer_remember_timestamp_cb, &timestamp2);
    amxp_timer_start(timer1, 50 * 1000);
    amxp_timer_start(timer2, 70 * 1000);

    // WHEN timetraveling 100 seconds
    amxut_timer_go_to_future_ms(100 * 1000);

    // THEN the clock observed by the first timer was at 50 seconds
    assert_int_equal(timestamp1 - timestamp_start, 50);
    // THEN the clock observed by the second timer was at 70 seconds
    assert_int_equal(timestamp2 - timestamp_start, 70);
    // THEN the clock now is at 100 seconds
    assert_int_equal(s_seconds_since_epoch() - timestamp_start, 100);

    // cleanup
    amxp_timer_delete(&timer1);
    amxp_timer_delete(&timer2);
}

/** @implements amxp_timer_cb_t */
static void s_timer_now_cb(UNUSED amxp_timer_t* timer, void* priv) {
    amxc_ts_t* time = (amxc_ts_t*) priv;
    amxc_ts_t time2;
    amxc_ts_now(&time2);
    assert_int_equal(time2.sec - time->sec, 10);
    assert_int_equal(time2.nsec - time->nsec, 0);
}

void amxut_timer_go_to_future_ms__now(UNUSED void** state) {
    // GIVEN a timer after 10 seconds
    amxc_ts_t time;
    amxp_timer_t* timer1 = NULL;
    amxut_timer_go_to_future_ms(0); // force clock does not move on its own.
    amxc_ts_now(&time);
    amxp_timer_new(&timer1, s_timer_now_cb, &time);
    amxp_timer_start(timer1, 10 * 1000);

    // WHEN timetraveling 10 seconds in smaller then seconds steps
    // THEN the clock in the callback will be exactly 10 seconds after start
    amxut_timer_go_to_future_ms(9900);
    amxut_timer_go_to_future_ms(100);

    // cleanup
    amxp_timer_delete(&timer1);
}

static void s_assert_time_eq(amxc_ts_t* timestamp, const char* expected) {
    char text[64] = {};
    amxc_ts_format(timestamp, text, sizeof(text));
    assert_string_equal(expected, text);
}

static void s_assert_is_now(const char* datetime_str) {
    amxc_ts_t now;
    assert_int_equal(0, amxc_ts_now(&now));
    s_assert_time_eq(&now, datetime_str);
}

static void s_go_to_datetime_unchecked(const char* datetime_str) {
    amxc_ts_t datetime;
    int status = amxc_ts_parse(&datetime, datetime_str, strlen(datetime_str));
    if(status != 0) {
        fail_msg("Cannot parse time '%s'", datetime_str);
    }
    amxut_timer_go_to_datetime(&datetime);
}

static void s_go_to_datetime(const char* datetime_str) {
    s_go_to_datetime_unchecked(datetime_str);
    s_assert_is_now(datetime_str);
}

void amxut_timer_go_to_datetime__future(UNUSED void** state) {
    // GIVEN the clock at a certain time
    s_go_to_datetime("2020-01-01T00:00:00Z");

    // WHEN going to the future
    s_go_to_datetime("9999-01-02T03:04:05Z");

    // THEN we are in the future
    s_assert_is_now("9999-01-02T03:04:05Z");
}

void amxut_timer_go_to_datetime__past(UNUSED void** state) {
    // GIVEN the clock at a certain time
    s_go_to_datetime("2026-12-31T23:59:59Z");

    // WHEN going to the past
    s_go_to_datetime("2025-12-31T23:59:59Z");

    // THEN we are in the past
    s_assert_is_now("2025-12-31T23:59:59Z");
}

void amxut_timer_go_to_datetime__future_with_timer(UNUSED void** state) {
    // GIVEN the clock at a certain time, and a timer
    // clock:
    s_go_to_datetime("2020-01-01T00:00:05Z");
    // timer:
    amxc_ts_t time_callback_called = {};
    amxp_timer_t* timer = NULL;
    amxp_timer_new(&timer, s_timer_remember_amxc_timestamp_cb, &time_callback_called);
    amxp_timer_start(timer, 7 * 60 * 60 * 1000);

    // WHEN going to the future
    s_go_to_datetime("2987-01-02T03:04:05Z");

    // THEN the timer is called at the correct time
    s_assert_time_eq(&time_callback_called, "2020-01-01T07:00:05Z");

    // cleanup:
    amxp_timer_delete(&timer);
}

void amxut_timer_go_to_datetime__past_with_timer(UNUSED void** state) {
    // GIVEN the clock at a certain time, and a timer
    // clock:
    s_go_to_datetime("2027-12-31T23:59:59Z");
    // timer:
    int32_t nb_times_timer_called = 0;
    amxp_timer_t* timer = NULL;
    amxp_timer_new(&timer, s_timer_cb, &nb_times_timer_called);
    amxp_timer_start(timer, 10 * 1000);

    // WHEN going to the past
    s_go_to_datetime("2024-12-31T23:59:59Z");

    // THEN the timer is not called
    assert_int_equal(nb_times_timer_called, 0);

    // cleanup:
    amxp_timer_delete(&timer);
}

void amxut_timer_go_to_datetime__future_subsecond(UNUSED void** state) {
    // GIVEN the clock at a non-round-second time, and two short timers
    s_go_to_datetime_unchecked("2021-02-03T04:05:06.01Z");
    // 20ms timer:
    amxp_timer_t* timer1 = NULL;
    int nb_times_timer1_called = 0;
    amxp_timer_new(&timer1, s_timer_cb, &nb_times_timer1_called);
    amxp_timer_start(timer1, 20);
    // 60ms timer:
    amxp_timer_t* timer2 = NULL;
    int nb_times_timer2_called = 0;
    amxp_timer_new(&timer2, s_timer_cb, &nb_times_timer2_called);
    amxp_timer_start(timer2, 80);

    // WHEN going to the future by 70ms
    s_go_to_datetime_unchecked("2021-02-03T04:05:06.08Z");

    // THEN the timer of 20ms is called, but the timer of 80ms is not
    assert_int_equal(nb_times_timer1_called, 1);
    assert_int_equal(nb_times_timer2_called, 0);
    // AND THEN the current time is correct (including the sub-second part)
    struct timespec timespec = {};
    amxc_ts_t now = {};
    amxc_ts_now(&now);
    amxut_clock_priv_amxc_ts_to_timespec(&now, &timespec);
    assert_int_equal(timespec.tv_sec, 1612325106);
    assert_int_equal(timespec.tv_nsec, 80 * 1000000);

    // cleanup:
    amxp_timer_delete(&timer1);
}