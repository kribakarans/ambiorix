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
#include <sys/signalfd.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>


#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <fcntl.h>
#include <cmocka.h>

#include <amxc/amxc.h>
#include <amxc/amxc_timestamp.h>
#include <amxp/amxp_timer.h>

#include "test_timer.h"

#include <amxc/amxc_macros.h>

static amxp_timer_t* t1 = NULL;
static amxp_timer_t* t2 = NULL;

static void timer_delete_timers_cb(UNUSED amxp_timer_t* timer, UNUSED void* priv) {
    amxp_timer_delete(&t1);
    amxp_timer_delete(&t2);
}

static void timer_delete_add_timers_cb(UNUSED amxp_timer_t* timer, UNUSED void* priv) {
    amxp_timer_delete(&t2);
    amxp_timer_new(&t2, timer_delete_timers_cb, NULL);
    amxp_timer_start(t1, 1000);
}

static void timer_callback(amxp_timer_t* timer, void* priv) {
    check_expected(timer);
    check_expected(priv);

    assert_ptr_not_equal(timer, NULL);
}

static void read_sigalrm(void) {
    sigset_t mask;
    int sfd;
    struct signalfd_siginfo fdsi;
    ssize_t s;

    sigemptyset(&mask);
    sigaddset(&mask, SIGALRM);

    sigprocmask(SIG_BLOCK, &mask, NULL);

    sfd = signalfd(-1, &mask, 0);
    s = read(sfd, &fdsi, sizeof(struct signalfd_siginfo));
    assert_int_equal(s, sizeof(struct signalfd_siginfo));
    if(fdsi.ssi_signo == SIGALRM) {
        printf("Got SIGALRM\n");
    } else {
        printf("Read unexpected signal\n");
    }
}

void test_can_create_timer(UNUSED void** state) {
    amxp_timer_t* timer = NULL;

    assert_int_not_equal(amxp_timer_new(NULL, NULL, NULL), 0);
    amxp_timer_delete(NULL);

    assert_int_equal(amxp_timer_new(&timer, NULL, NULL), 0);
    assert_ptr_not_equal(timer, NULL);
    assert_int_equal(timer->state, amxp_timer_off);
    assert_ptr_equal(timer->cb, NULL);
    assert_ptr_equal(timer->priv, NULL);

    assert_int_not_equal(amxp_timer_new(&timer, NULL, NULL), 0);

    amxp_timer_delete(&timer);
    assert_ptr_equal(timer, NULL);
    amxp_timer_delete(&timer);
}

void test_can_start_timers(UNUSED void** state) {
    amxp_timer_t* timer1 = NULL;
    amxp_timer_t* timer2 = NULL;
    amxc_ts_t ts1;
    amxc_ts_t ts2;

    assert_int_equal(amxp_timer_new(&timer1, NULL, NULL), 0);
    assert_ptr_not_equal(timer1, NULL);
    assert_int_equal(amxp_timer_new(&timer2, NULL, NULL), 0);
    assert_ptr_not_equal(timer2, NULL);

    assert_int_equal(amxp_timer_start(timer1, 1000), 0);
    assert_int_equal(amxp_timer_get_state(timer1), amxp_timer_running);
    amxp_timers_check();
    assert_int_equal(amxp_timer_get_state(timer1), amxp_timer_running);

    assert_int_equal(amxp_timer_start(timer2, 3000), 0);
    assert_int_equal(amxp_timer_get_state(timer2), amxp_timer_running);
    amxp_timers_check();
    assert_int_equal(amxp_timer_get_state(timer2), amxp_timer_running);


    amxc_ts_now(&ts1);
    read_sigalrm();
    amxc_ts_now(&ts2);
    amxp_timers_calculate();
    amxp_timers_check();
    assert_int_equal(ts2.sec - ts1.sec, 1);
    assert_int_equal(amxp_timer_get_state(timer1), amxp_timer_off);
    assert_int_equal(amxp_timer_get_state(timer2), amxp_timer_running);

    read_sigalrm();
    amxc_ts_now(&ts2);
    amxp_timers_calculate();
    amxp_timers_check();
    assert_int_equal(ts2.sec - ts1.sec, 3);
    assert_int_equal(amxp_timer_get_state(timer1), amxp_timer_off);
    assert_int_equal(amxp_timer_get_state(timer2), amxp_timer_off);

    assert_int_not_equal(amxp_timer_start(NULL, 1000), 0);

    amxp_timer_delete(&timer1);
    amxp_timer_delete(&timer2);
}

void test_timer_callback_is_called(UNUSED void** state) {
    amxp_timer_t* timer1 = NULL;

    assert_int_equal(amxp_timer_new(&timer1, timer_callback, NULL), 0);
    assert_ptr_not_equal(timer1, NULL);

    assert_int_equal(amxp_timer_start(timer1, 500), 0);
    assert_int_equal(amxp_timer_get_state(timer1), amxp_timer_running);

    expect_any(timer_callback, timer);
    expect_any(timer_callback, priv);

    read_sigalrm();

    amxp_timers_calculate();
    amxp_timers_check();

    amxp_timer_delete(&timer1);
}

void test_can_start_interval_timer(UNUSED void** state) {
    amxp_timer_t* timer1 = NULL;
    amxp_timer_t* timer2 = NULL;
    int count = 11;
    int remaining = 0;

    assert_int_equal(amxp_timer_new(&timer1, NULL, NULL), 0);
    assert_ptr_not_equal(timer1, NULL);
    assert_int_equal(amxp_timer_new(&timer2, NULL, NULL), 0);
    assert_ptr_not_equal(timer2, NULL);

    assert_int_equal(amxp_timer_set_interval(timer1, 1000), 0);
    assert_int_equal(amxp_timer_start(timer1, 1000), 0);
    assert_int_equal(amxp_timer_get_state(timer1), amxp_timer_running);
    amxp_timers_check();
    assert_int_equal(amxp_timer_get_state(timer1), amxp_timer_running);

    assert_int_equal(amxp_timer_start(timer2, 10200), 0);
    assert_int_equal(amxp_timer_get_state(timer2), amxp_timer_running);
    amxp_timers_check();
    assert_int_equal(amxp_timer_get_state(timer2), amxp_timer_running);

    while(amxp_timer_get_state(timer2) != amxp_timer_off) {
        read_sigalrm();
        amxp_timers_calculate();
        amxp_timers_check();
        count--;
        if(count > 0) {
            remaining = amxp_timer_remaining_time(timer2);
            assert_true((remaining / 1000) <= (count - 1));
        }
    }

    assert_int_equal(count, 0);

    assert_int_equal(amxp_timer_get_state(timer1), amxp_timer_running);
    assert_int_equal(amxp_timer_stop(timer1), 0);
    assert_int_equal(amxp_timer_get_state(timer1), amxp_timer_off);

    assert_int_not_equal(amxp_timer_set_interval(NULL, 1000), 0);
    assert_int_equal(amxp_timer_remaining_time(NULL), 0);
    assert_int_not_equal(amxp_timer_stop(NULL), 0);

    amxp_timer_delete(&timer1);
    amxp_timer_delete(&timer2);
}

void test_can_restart_timer(UNUSED void** state) {
    amxc_ts_t start_time;
    amxc_ts_t end_time;

    amxp_timer_t* timer = NULL;
    amxp_timer_new(&timer, NULL, NULL);
    amxp_timer_start(timer, 3000);
    sleep(1);
    amxc_ts_now(&start_time);
    amxp_timer_start(timer, 3000);
    read_sigalrm();
    amxc_ts_now(&end_time);
    assert_int_equal(end_time.sec - start_time.sec, 3);

    amxp_timer_delete(&timer);
}

void test_timer_with_0_timeout_test1(UNUSED void** state) {
    amxc_ts_t start_time;
    amxc_ts_t end_time;
    amxp_timer_t* timer1 = NULL;
    amxp_timer_t* timer2 = NULL;

    amxp_timer_new(&timer1, timer_callback, NULL);
    amxp_timer_new(&timer2, NULL, NULL);

    expect_any(timer_callback, timer);
    expect_any(timer_callback, priv);

    amxp_timer_start(timer1, 0);
    amxp_timer_start(timer2, 3000);
    assert_int_equal(amxp_timer_get_state(timer1), amxp_timer_running);
    assert_int_equal(amxp_timer_get_state(timer2), amxp_timer_running);
    amxc_ts_now(&start_time);
    read_sigalrm();
    amxc_ts_now(&end_time);
    amxp_timers_calculate();
    amxp_timers_check();
    assert_int_equal(amxp_timer_get_state(timer1), amxp_timer_off);
    assert_int_equal(amxp_timer_get_state(timer2), amxp_timer_running);
    assert_int_equal(end_time.sec - start_time.sec, 0);

    amxp_timer_delete(&timer1);
    amxp_timer_delete(&timer2);
}

void test_timer_with_0_timeout_test2(UNUSED void** state) {
    amxc_ts_t start_time;
    amxc_ts_t end_time;
    amxp_timer_t* timer1 = NULL;
    amxp_timer_t* timer2 = NULL;

    amxp_timer_new(&timer1, timer_callback, NULL);
    amxp_timer_new(&timer2, NULL, NULL);

    expect_any(timer_callback, timer);
    expect_any(timer_callback, priv);

    amxp_timer_start(timer2, 3000);
    amxp_timer_start(timer1, 0);
    assert_int_equal(amxp_timer_get_state(timer1), amxp_timer_running);
    assert_int_equal(amxp_timer_get_state(timer2), amxp_timer_running);
    amxc_ts_now(&start_time);
    read_sigalrm();
    amxc_ts_now(&end_time);
    amxp_timers_calculate();
    amxp_timers_check();
    assert_int_equal(amxp_timer_get_state(timer1), amxp_timer_off);
    assert_int_equal(amxp_timer_get_state(timer2), amxp_timer_running);
    assert_int_equal(end_time.sec - start_time.sec, 0);

    amxp_timer_delete(&timer1);
    amxp_timer_delete(&timer2);
}

void test_timer_can_delete_timers_in_callback(UNUSED void** state) {
    amxp_timer_new(&t1, timer_delete_timers_cb, NULL);
    amxp_timer_new(&t2, timer_delete_timers_cb, NULL);

    amxp_timer_start(t1, 3000);
    amxp_timer_start(t2, 10000);

    assert_int_equal(amxp_timer_get_state(t1), amxp_timer_running);
    assert_int_equal(amxp_timer_get_state(t2), amxp_timer_running);

    read_sigalrm();
    amxp_timers_calculate();
    amxp_timers_check();
}

void test_timer_can_delete_add_timers_in_callback(UNUSED void** state) {
    amxp_timer_new(&t1, timer_delete_add_timers_cb, NULL);
    amxp_timer_new(&t2, NULL, NULL);

    amxp_timer_start(t1, 1000);

    assert_int_equal(amxp_timer_get_state(t1), amxp_timer_running);

    read_sigalrm();
    amxp_timers_calculate();
    amxp_timers_check();

    read_sigalrm();
    amxp_timers_calculate();
    amxp_timers_check();
}
