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

#include "test_amxut_clock.h"
#include <stdlib.h> // Needed for cmocka
#include <setjmp.h> // Needed for cmocka
#include <stdarg.h> // Needed for cmocka
#include <cmocka.h>
#include <amxut/amxut_clock_priv.h>
#include <amxc/amxc.h>
#include <amxc/amxc_macros.h>

#include <debug/sahtrace.h>
#include <string.h>

static void s_testhelper_amxc_ts_to_timespec(const char* datetime, int64_t expected_sec, int32_t expected_nanosec) {
    amxc_ts_t ts;
    struct timespec timespec;
    assert_int_equal(0, amxc_ts_parse(&ts, datetime, strlen(datetime)));
    assert_int_equal(0, amxut_clock_priv_amxc_ts_to_timespec(&ts, &timespec));
    assert_int_equal(timespec.tv_sec, expected_sec);
    assert_int_equal(timespec.tv_nsec, expected_nanosec);
}

void test_amxut_clock_private_amxc_ts_to_timespec(UNUSED void** state) {
    amxc_ts_t ts;
    amxc_ts_now(&ts);
    struct timespec timespec;

    // Normal case:
    s_testhelper_amxc_ts_to_timespec("2025-04-01T11:05:00Z", 1743505500, 0);
    // A long time ago and microsecond precision:
    s_testhelper_amxc_ts_to_timespec("1702-03-04T05:06:07.089123Z", -8451888833, 89123000);
    // Far in the future and nanosecond precision:
    s_testhelper_amxc_ts_to_timespec("9876-12-31T23:59:59.000000123Z", 249520867199, 123);

    // Invalid argument:
    assert_int_equal(-1, amxut_clock_priv_amxc_ts_to_timespec(NULL, &timespec));
    // Invalid argument:
    assert_int_equal(-1, amxut_clock_priv_amxc_ts_to_timespec(&ts, NULL));
}