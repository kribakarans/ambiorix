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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE // for RTLD_NEXT. Must be before includes.
#endif
#include "amxut/amxut_timer.h"
#include "amxut/amxut_clock_priv.h"
#include "amxut/amxut_bus.h"
#include <dlfcn.h>
#include <amxc/amxc.h>
#include <stdbool.h>
#include <amxp/amxp_timer.h>
#include <sys/time.h>
#include <time.h>
#include <stddef.h>

#include <unistd.h> // needed for cmocka
#include <setjmp.h> // needed for cmocka
#include <stdarg.h> // needed for cmocka
#include <cmocka.h>

static struct itimerval s_timer_count_down;

/**
 * On some platforms it must be `__itimer_which_t` and others don't have it.
 * so try to make it work for both.
 */
#if defined __USE_GNU && !defined __cplusplus
typedef enum __itimer_which __itimer_which_t;
#else
typedef int __itimer_which_t;
#endif

typedef int (* getitimer_t) (int which, struct itimerval* curr_value);
typedef int (* setitimer_t) (int which, const struct itimerval* new_value,
                             struct itimerval* old_value);

/**
 * The mocked version of libc's `getitimer(2)`
 */
int getitimer(__itimer_which_t which, struct itimerval* curr_value) {
    if(which != ITIMER_REAL) {
        getitimer_t real_getitimer = (getitimer_t) dlsym(RTLD_NEXT, "getitimer");
        return real_getitimer(which, curr_value);
    }

    *curr_value = s_timer_count_down;
    return 0;
}

/**
 * The mocked version of libc's `setitimer(2)`
 */
int setitimer(__itimer_which_t which, const struct itimerval* new_value, struct itimerval* old_value) {
    if(which != ITIMER_REAL) {
        setitimer_t real_setitimer = (setitimer_t) dlsym(RTLD_NEXT, "setitimer");
        return real_setitimer(which, new_value, old_value);
    }
    if(new_value == NULL) {
        return -1;
    }
    if(old_value != NULL) {
        *old_value = s_timer_count_down;
    }
    s_timer_count_down = *new_value;
    return 0;
}

static void s_timeval_from_ms(struct timeval* tgt_timeval, uint64_t ms) {
    tgt_timeval->tv_sec = ms / 1000;
    tgt_timeval->tv_usec = (ms % 1000) * 1000;
}

static uint64_t s_ms_from_timeval(const struct timeval* timeval) {
    return timeval->tv_sec * 1000 + timeval->tv_usec / 1000;
}

/** Takes smallest timespan of two given timespans */
static void s_minTime(struct timeval* tgt_time, struct timeval* src_time1, struct timeval* src_time2) {
    int cmp_val = timercmp(src_time1, src_time2, <);
    if(cmp_val != 0) {
        *tgt_time = *src_time1;
    } else {
        *tgt_time = *src_time2;
    }
}

void amxut_timer_go_to_future_ms(uint64_t ms) {
    amxut_bus_handle_events();
    amxp_timers_calculate();
    amxp_timers_check();
    amxp_timers_calculate();
    amxut_bus_handle_events();

    struct timeval todo;
    s_timeval_from_ms(&todo, ms);

    struct timeval zero;
    zero.tv_sec = 0;
    zero.tv_usec = 0;

    // Example: let's say ambiorix's timer called `setitimer(50 milliseconds)`.
    // And let's say the user called `amxut_timer_go_to_future_ms(800 milliseconds)`.
    // Then this loop timetravels 50 milliseconds first, and give the timer the chance to call its
    // callbacks after those first 50 milliseconds, and gives the timer a chance to call
    // `setitimer()` again.
    // The loop keeps doing that until we ran out of our 800 milliseconds.
    while(timercmp(&todo, &zero, >) && timercmp(&s_timer_count_down.it_value, &zero, >)) {
        struct timeval min;
        s_minTime(&min, &todo, &s_timer_count_down.it_value);

        timersub(&s_timer_count_down.it_value, &min, &s_timer_count_down.it_value);
        timersub(&todo, &min, &todo);
        amxut_clock_priv_isolated_go_to_future_ms(s_ms_from_timeval(&min));

        amxp_timers_calculate();
        amxp_timers_check();
        amxp_timers_calculate();
        amxut_bus_handle_events();
    }
    amxut_clock_priv_isolated_go_to_future_ms(s_ms_from_timeval(&todo));
}

static uint64_t s_time_diff_in_ms(const amxc_ts_t* earlier_timestamp, const amxc_ts_t* later_timestamp) {
    struct timeval later_timeval = {};
    struct timespec later_timespec = {};
    struct timeval earlier_timeval = {};
    struct timespec earlier_timespec = {};
    struct timeval difference = {};
    assert_non_null(earlier_timestamp);
    assert_non_null(later_timestamp);

    assert_int_equal(0, amxut_clock_priv_amxc_ts_to_timespec(earlier_timestamp, &earlier_timespec));
    TIMESPEC_TO_TIMEVAL(&earlier_timeval, &earlier_timespec);
    assert_int_equal(0, amxut_clock_priv_amxc_ts_to_timespec(later_timestamp, &later_timespec));
    TIMESPEC_TO_TIMEVAL(&later_timeval, &later_timespec);

    timersub(&later_timeval, &earlier_timeval, &difference);

    // Check for overflow
    if(difference.tv_sec >= (time_t) ((UINT64_MAX / 1000) - 2)) {
        fail_msg("Timetraveling further than supported.");
    }

    return difference.tv_sec * 1000 + difference.tv_usec / 1000;
}

void amxut_timer_go_to_datetime(amxc_ts_t* goto_datetime) {
    amxc_ts_t now_amx;
    assert_non_null(goto_datetime);

    assert_int_equal(0, amxc_ts_now(&now_amx));
    bool is_in_future = amxc_ts_compare(&now_amx, goto_datetime) == -1;

    if(is_in_future) {
        amxut_timer_go_to_future_ms(s_time_diff_in_ms(&now_amx, goto_datetime));
    } else {
        amxut_clock_priv_isolated_set_realtime(goto_datetime);
    }
}