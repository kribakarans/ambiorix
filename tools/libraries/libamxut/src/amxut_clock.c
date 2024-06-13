/****************************************************************************
**
** SPDX-License-Identifier: BSD-2-Clause-Patent
**
** SPDX-FileCopyrightText: Copyright (c) 2024 SoftAtHome
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
#include "amxut/amxut_clock_priv.h"
#include <stdio.h>
#include <dlfcn.h>
#include <time.h>
#include <stdbool.h>
#include <string.h>

#include <unistd.h> // needed for cmocka
#include <setjmp.h> // needed for cmocka
#include <stdarg.h> // needed for cmocka
#include <cmocka.h>

#define NSEC_IN_SEC 1000000000

static bool s_is_intercepting = false;

/** The `CLOCK_MONOTONIC` time */
static struct timespec s_monotonic_clock = {0, 0};
/** The `CLOCK_REALTIME` time */
static struct timespec s_realtime_clock = {0, 0};

typedef int (* clock_gettime_t) (clockid_t __clock_id, struct timespec* __tp);

/**
 * Call libc's clock_gettime() without mocking
 */
static int s_libc_clock_gettime(clockid_t __clock_id, struct timespec* __tp) {
    clock_gettime_t libc_clock_gettime = (clock_gettime_t) dlsym(RTLD_NEXT, "clock_gettime");
    return libc_clock_gettime(__clock_id, __tp);
}

/**
 * The mocked version of libc's `clock_gettime(2)`
 */
int clock_gettime (clockid_t __clock_id, struct timespec* __tp) {
    if(!s_is_intercepting || ((__clock_id != CLOCK_MONOTONIC) && (__clock_id != CLOCK_REALTIME))) {
        return s_libc_clock_gettime(__clock_id, __tp);
    } else {
        if(__clock_id == CLOCK_MONOTONIC) {
            memcpy(__tp, &s_monotonic_clock, sizeof(struct timespec));
            return 0;
        } else if(__clock_id == CLOCK_REALTIME) {
            memcpy(__tp, &s_realtime_clock, sizeof(struct timespec));
            return 0;
        }
        return -1;
    }
}

static void s_init(void) {
    when_true(s_is_intercepting, exit);
    s_libc_clock_gettime(CLOCK_MONOTONIC, &s_monotonic_clock);
    s_libc_clock_gettime(CLOCK_REALTIME, &s_realtime_clock);
    s_is_intercepting = true;
exit:
    return;
}

static void s_add_to_clock(struct timespec* clock, time_t sec, long nsec) {
    clock->tv_nsec += nsec;
    if(clock->tv_nsec >= NSEC_IN_SEC) {
        clock->tv_sec++;
        clock->tv_nsec -= NSEC_IN_SEC;
    }
    clock->tv_sec += sec;
}

void amxut_clock_priv_isolated_go_to_future_ms(uint64_t ms) {
    time_t sec = ms / 1000;
    uint32_t nanosec = (ms - (sec * 1000)) * 1000000;
    s_init();
    s_add_to_clock(&s_monotonic_clock, sec, nanosec);
    s_add_to_clock(&s_realtime_clock, sec, nanosec);
}

void amxut_clock_priv_isolated_set_realtime(amxc_ts_t* datetime) {
    struct timespec datetime_timespec = {};
    assert_non_null(datetime);
    s_init();
    assert_int_equal(0, amxut_clock_priv_amxc_ts_to_timespec(datetime, &datetime_timespec));

    s_realtime_clock = datetime_timespec;
}


int amxut_clock_priv_amxc_ts_to_timespec(const amxc_ts_t* source_timestamp, struct timespec* target_timespec) {
    when_null(source_timestamp, error);
    when_null(target_timespec, error);

    // User of amxut_clock_priv_amxc_ts_to_timespec() might assume amxut_clock_priv_amxc_ts_to_timespec() initializes target_timespec
    // so user might not initializes target_timespec.
    // "Implementation may add other members to struct timespec." (https://en.cppreference.com/w/c/chrono/timespec)
    // So initialize those members.
    memset(target_timespec, 0, sizeof(struct timespec));

    target_timespec->tv_sec = source_timestamp->sec;
    target_timespec->tv_nsec = source_timestamp->nsec;

    return 0;
error:
    return -1;
}
