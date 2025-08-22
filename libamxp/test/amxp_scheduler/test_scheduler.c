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
#include <sys/signalfd.h>
#include <signal.h>

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
#include <amxp/amxp_scheduler.h>

#include "test_scheduler.h"

static int32_t trigger_counter = 0;

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
        printf("GOT SIGALRM\n");
        amxp_timers_calculate();
        amxp_timers_check();
    } else {
        printf("Read unexpected signal\n");
    }
}

static void handle_events(void) {
    while(amxp_signal_read() == 0) {
    }
}

static void check_scheduler(amxp_scheduler_t* scheduler) {
    int64_t previous = 0;
    bool first = true;
    char str_ts[40];

    trigger_counter = 0;
    amxc_llist_iterate(it, &scheduler->ordered_items) {
        amxp_scheduler_item_t* item = amxc_container_of(it, amxp_scheduler_item_t, lit);

        amxc_ts_format(&item->next, str_ts, 40);
        printf("scheduler item %s - next = %s\n", amxc_htable_it_get_key(&item->hit), str_ts);

        if((item->next.sec == previous) || (previous == 0)) {
            if(first) {
                trigger_counter++;
            }
        } else {
            first = false;
        }
        assert_true(item->next.sec >= previous);
        previous = item->next.sec;
    }
}

static void check_schedule_trigger(const char* const sig_name,
                                   const amxc_var_t* const data,
                                   void* const priv) {
    const char* expected_id = (const char*) priv;
    char str_ts[40];
    amxc_ts_t ts;

    amxc_ts_now(&ts);
    amxc_ts_format(&ts, str_ts, 40);

    assert_non_null(GET_CHAR(data, "id"));
    assert_string_equal(GET_CHAR(data, "id"), expected_id);

    printf("Got trigger: %s from %s at %s\n", sig_name, expected_id, str_ts);

    trigger_counter--;
}

static void dump_schedule_trigger(const char* const sig_name,
                                  const amxc_var_t* const data,
                                  UNUSED void* const priv) {
    printf("Signal = %s\n", sig_name);
    fflush(stdout);
    amxc_var_dump(data, STDERR_FILENO);
}

static void check_start_stop_trigger(const char* const sig_name,
                                     const amxc_var_t* const data,
                                     void* const priv) {
    const char* expected_id = (const char*) priv;
    char str_ts[40];
    amxc_ts_t ts;

    amxc_ts_now(&ts);
    amxc_ts_format(&ts, str_ts, 40);

    check_expected(sig_name);
    assert_non_null(GET_CHAR(data, "id"));
    assert_string_equal(GET_CHAR(data, "id"), expected_id);

    printf("Got trigger: %s from %s at %s\n", sig_name, expected_id, str_ts);

    trigger_counter--;
}

static void delete_schedule(UNUSED const char* const sig_name,
                            UNUSED const amxc_var_t* const data,
                            void* const priv) {
    amxp_scheduler_t* scheduler = (amxp_scheduler_t*) priv;
    assert_non_null(scheduler);
    assert_int_equal(amxp_scheduler_remove_item(scheduler, "test1"), 0);
}

void test_can_add_schedules(UNUSED void** state) {
    amxp_scheduler_t* scheduler = NULL;

    assert_int_equal(amxp_scheduler_new(&scheduler), 0);
    assert_non_null(scheduler);
    assert_true(scheduler->sigmngr.enabled);
    assert_true(scheduler->timer->state != amxp_timer_running);

    assert_int_equal(amxp_scheduler_set_cron_item(scheduler, "test1", "0/15 * * * * *", 0), 0);
    assert_int_equal(amxp_scheduler_set_cron_item(scheduler, "test2", "0/5 * * * * *", 0), 0);
    assert_int_equal(amxp_scheduler_set_cron_item(scheduler, "test3", "0/10 * * * * *", 0), 0);
    assert_int_equal(amxp_scheduler_set_cron_begin_end_item(scheduler, "test3A", "0/10 * * * * *", "0/20 * * * * *"), 0);
    assert_int_equal(amxp_scheduler_set_weekly_item(scheduler, "test4", "23:00", "saturday,sunday", 0), 0);
    assert_int_equal(amxp_scheduler_set_weekly_item(scheduler, "test5", NULL, "monday-friday", 0), 0);
    assert_int_equal(amxp_scheduler_set_weekly_begin_end_item(scheduler, "test6", NULL, NULL, "monday-friday"), 0);
    assert_int_equal(amxp_scheduler_set_weekly_item(scheduler, "test7", NULL, "monday-friday", 7200), 0);

    assert_true(scheduler->timer->state == amxp_timer_running);

    assert_int_equal(amxc_llist_size(&scheduler->ordered_items), 8);
    assert_int_equal(amxc_htable_size(&scheduler->items), 8);

    check_scheduler(scheduler);
    assert_non_null(amxp_scheduler_get_sigmngr(scheduler));

    amxp_scheduler_delete(&scheduler);
    assert_null(scheduler);
    assert_null(amxp_scheduler_get_sigmngr(scheduler));
}

void test_can_remove_schedules(UNUSED void** state) {
    amxp_scheduler_t* scheduler = NULL;

    assert_int_equal(amxp_scheduler_new(&scheduler), 0);
    assert_non_null(scheduler);
    assert_true(scheduler->sigmngr.enabled);

    assert_int_equal(amxp_scheduler_set_cron_item(scheduler, "test1", "0/15 * * * * *", 0), 0);
    assert_int_equal(amxp_scheduler_set_cron_item(scheduler, "test2", "0/5 * * * * *", 0), 0);
    assert_int_equal(amxp_scheduler_set_cron_item(scheduler, "test3", "0/10 * * * * *", 0), 0);
    assert_int_equal(amxp_scheduler_set_weekly_item(scheduler, "test4", "23:00", "saturday,sunday", 0), 0);

    assert_int_equal(amxc_llist_size(&scheduler->ordered_items), 4);
    assert_int_equal(amxc_htable_size(&scheduler->items), 4);

    assert_int_equal(amxp_scheduler_remove_item(scheduler, "test1"), 0);
    assert_int_equal(amxp_scheduler_remove_item(scheduler, "test4"), 0);

    assert_int_equal(amxc_llist_size(&scheduler->ordered_items), 2);
    assert_int_equal(amxc_htable_size(&scheduler->items), 2);

    check_scheduler(scheduler);
    amxp_scheduler_delete(&scheduler);
    assert_null(scheduler);
}

void test_scheduler_triggers_signals(UNUSED void** state) {
    amxp_scheduler_t* scheduler = NULL;

    assert_int_equal(amxp_scheduler_new(&scheduler), 0);
    assert_non_null(scheduler);
    assert_true(scheduler->sigmngr.enabled);

    assert_non_null(scheduler->timer);
    assert_int_equal(amxp_scheduler_set_cron_item(scheduler, "test1", "0/15 * * * * *", 0), 0);
    assert_int_equal(amxp_scheduler_set_cron_item(scheduler, "test2", "0/5 * * * * *", 0), 0);
    assert_int_equal(amxp_scheduler_set_cron_item(scheduler, "test3", "0/10 * * * * *", 0), 0);
    assert_int_equal(amxp_scheduler_set_weekly_item(scheduler, "test4", "23:00", "saturday,sunday", 0), 0);
    assert_int_equal(amxp_scheduler_set_weekly_begin_end_item(scheduler, "test5", "23:00", "23:59", "saturday,sunday"), 0);

    amxp_scheduler_connect(scheduler, "test1", check_schedule_trigger, (void*) "test1");
    amxp_scheduler_connect(scheduler, "test2", check_schedule_trigger, (void*) "test2");
    amxp_scheduler_connect(scheduler, "test3", check_schedule_trigger, (void*) "test3");
    amxp_scheduler_connect(scheduler, "test4", check_schedule_trigger, (void*) "test4");
    amxp_scheduler_connect(scheduler, "test5", check_schedule_trigger, (void*) "test5");
    amxp_scheduler_connect(scheduler, NULL, dump_schedule_trigger, NULL);

    amxp_timers_calculate();
    amxp_timers_check();
    assert_int_equal(scheduler->timer->state, amxp_timer_running);

    check_scheduler(scheduler);
    printf("Expecting %d triggers\n", trigger_counter);
    read_sigalrm();
    handle_events();
    assert_int_equal(trigger_counter, 0);

    check_scheduler(scheduler);
    printf("Expecting %d triggers\n", trigger_counter);
    read_sigalrm();
    handle_events();
    assert_int_equal(trigger_counter, 0);

    check_scheduler(scheduler);
    printf("Expecting %d triggers\n", trigger_counter);
    read_sigalrm();
    handle_events();
    assert_int_equal(trigger_counter, 0);

    check_scheduler(scheduler);
    printf("Expecting %d triggers\n", trigger_counter);
    read_sigalrm();
    handle_events();
    assert_int_equal(trigger_counter, 0);

    check_scheduler(scheduler);
    printf("Expecting %d triggers\n", trigger_counter);
    read_sigalrm();
    handle_events();
    assert_int_equal(trigger_counter, 0);

    amxp_scheduler_delete(&scheduler);
    assert_null(scheduler);
}

void test_scheduler_using_local_time(UNUSED void** state) {
    amxp_scheduler_t* scheduler = NULL;

    assert_int_equal(amxp_scheduler_new(&scheduler), 0);
    assert_non_null(scheduler);
    assert_true(scheduler->sigmngr.enabled);

    assert_non_null(scheduler->timer);
    assert_int_equal(amxp_scheduler_set_cron_item(scheduler, "test1", "0/15 * * * * *", 0), 0);
    assert_int_equal(amxp_scheduler_set_cron_item(scheduler, "test2", "0/5 * * * * *", 0), 0);
    assert_int_equal(amxp_scheduler_use_local_time(scheduler, true), 0);
    assert_int_equal(amxp_scheduler_set_cron_item(scheduler, "test3", "0/10 * * * * *", 0), 0);
    assert_int_equal(amxp_scheduler_set_weekly_item(scheduler, "test4", "23:00", "saturday", 0), 0);
    assert_int_equal(amxp_scheduler_set_weekly_begin_end_item(scheduler, "test5", "23:00", "23:59", "saturday,sunday"), 0);
    assert_int_equal(amxp_scheduler_set_cron_begin_end_item(scheduler, "test6", "0 0/15 * * * *", "0 0/1 * * * *"), 0);

    amxp_scheduler_connect(scheduler, "test1", check_schedule_trigger, (void*) "test1");
    amxp_scheduler_connect(scheduler, "test2", check_schedule_trigger, (void*) "test2");
    amxp_scheduler_connect(scheduler, "test3", check_schedule_trigger, (void*) "test3");
    amxp_scheduler_connect(scheduler, "test4", check_schedule_trigger, (void*) "test4");

    amxp_timers_calculate();
    amxp_timers_check();
    assert_int_equal(scheduler->timer->state, amxp_timer_running);

    check_scheduler(scheduler);
    printf("Expecting %d triggers\n", trigger_counter);
    read_sigalrm();
    handle_events();
    assert_int_equal(trigger_counter, 0);

    check_scheduler(scheduler);
    printf("Expecting %d triggers\n", trigger_counter);
    read_sigalrm();
    handle_events();
    assert_int_equal(trigger_counter, 0);

    check_scheduler(scheduler);
    printf("Expecting %d triggers\n", trigger_counter);
    read_sigalrm();
    handle_events();
    assert_int_equal(trigger_counter, 0);

    check_scheduler(scheduler);
    printf("Expecting %d triggers\n", trigger_counter);
    read_sigalrm();
    handle_events();
    assert_int_equal(trigger_counter, 0);

    check_scheduler(scheduler);
    printf("Expecting %d triggers\n", trigger_counter);
    read_sigalrm();
    handle_events();
    assert_int_equal(trigger_counter, 0);

    amxp_scheduler_delete(&scheduler);
    assert_null(scheduler);
}

void test_disabled_scheduler_does_not_trigger_signals(UNUSED void** state) {
    amxp_scheduler_t* scheduler = NULL;
    amxp_timer_t* timer = NULL;

    assert_int_equal(amxp_scheduler_new(&scheduler), 0);
    assert_non_null(scheduler);
    assert_true(scheduler->sigmngr.enabled);

    assert_non_null(scheduler->timer);
    assert_int_equal(amxp_scheduler_set_cron_item(scheduler, "test1", "0/15 * * * * *", 0), 0);
    assert_int_equal(amxp_scheduler_set_cron_item(scheduler, "test2", "0/5 * * * * *", 0), 0);
    assert_int_equal(amxp_scheduler_set_cron_item(scheduler, "test3", "0/10 * * * * *", 0), 0);
    assert_int_equal(amxp_scheduler_set_weekly_item(scheduler, "test4", "23:00", "saturday,sunday", 0), 0);
    assert_int_equal(amxp_scheduler_set_weekly_begin_end_item(scheduler, "test5", "23:00", "23:59", "saturday,sunday"), 0);

    amxp_scheduler_connect(scheduler, "test1", check_schedule_trigger, (void*) "test1");
    amxp_scheduler_connect(scheduler, "test2", check_schedule_trigger, (void*) "test2");
    amxp_scheduler_connect(scheduler, "test3", check_schedule_trigger, (void*) "test3");
    amxp_scheduler_connect(scheduler, "test4", check_schedule_trigger, (void*) "test4");
    amxp_scheduler_connect(scheduler, "test5", check_schedule_trigger, (void*) "test5");

    amxp_timers_calculate();
    amxp_timers_check();
    assert_int_equal(scheduler->timer->state, amxp_timer_running);
    amxp_scheduler_enable(scheduler, false);
    amxp_timers_calculate();
    amxp_timers_check();
    assert_int_equal(scheduler->timer->state, amxp_timer_off);
    amxp_scheduler_update(scheduler);

    amxp_timer_new(&timer, NULL, NULL);
    check_scheduler(scheduler);
    printf("Expecting %d triggers if scheduler was enabled\n", trigger_counter);
    amxp_timer_start(timer, 20000);
    read_sigalrm();
    handle_events();
    assert_int_not_equal(trigger_counter, 0);
    amxp_timer_delete(&timer);

    amxp_scheduler_enable(scheduler, true);
    amxp_timers_calculate();
    amxp_timers_check();
    assert_int_equal(scheduler->timer->state, amxp_timer_running);
    check_scheduler(scheduler);
    printf("Scheduler is enabled again - expecting %d triggers\n", trigger_counter);
    read_sigalrm();
    handle_events();
    assert_int_equal(trigger_counter, 0);

    amxp_scheduler_delete(&scheduler);
    assert_null(scheduler);
}

void test_scheduler_can_trigger_start_stop(UNUSED void** state) {
    amxp_scheduler_t* scheduler = NULL;

    assert_int_equal(amxp_scheduler_new(&scheduler), 0);
    assert_non_null(scheduler);
    assert_true(scheduler->sigmngr.enabled);

    assert_non_null(scheduler->timer);
    trigger_counter = 2;

    assert_int_equal(amxp_scheduler_set_cron_item(scheduler, "test1", "0/5 * * * * *", 3), 0);
    expect_string(check_start_stop_trigger, sig_name, "start:test1");
    expect_string(check_start_stop_trigger, sig_name, "stop:test1");

    amxp_scheduler_connect(scheduler, "test1", check_start_stop_trigger, (void*) "test1");

    amxp_timers_calculate();
    amxp_timers_check();
    assert_int_equal(scheduler->timer->state, amxp_timer_running);

    handle_events();

    if(trigger_counter == 2) {
        read_sigalrm();
        handle_events();
    }

    read_sigalrm();
    handle_events();
    assert_int_equal(trigger_counter, 0);

    amxp_scheduler_delete(&scheduler);
    assert_null(scheduler);
}

void test_scheduler_can_remove_schedule_in_callback(UNUSED void** state) {
    amxp_scheduler_t* scheduler = NULL;

    assert_int_equal(amxp_scheduler_new(&scheduler), 0);
    assert_non_null(scheduler);
    assert_true(scheduler->sigmngr.enabled);

    assert_non_null(scheduler->timer);
    trigger_counter = 2;

    assert_int_equal(amxp_scheduler_set_cron_item(scheduler, "test1", "0/5 * * * * *", 3), 0);

    amxp_scheduler_connect(scheduler, "test1", delete_schedule, (void*) scheduler);

    amxp_timers_calculate();
    amxp_timers_check();
    assert_int_equal(scheduler->timer->state, amxp_timer_running);

    read_sigalrm();
    handle_events();

    amxp_scheduler_delete(&scheduler);
    assert_null(scheduler);
}

void test_scheduler_adding_running_triggers_start_duration(UNUSED void** state) {
    amxp_scheduler_t* scheduler = NULL;

    assert_int_equal(amxp_scheduler_new(&scheduler), 0);
    assert_non_null(scheduler);
    assert_true(scheduler->sigmngr.enabled);

    assert_non_null(scheduler->timer);

    sleep(5);

    assert_int_equal(amxp_scheduler_set_cron_item(scheduler, "test1", "0 * * * * *", 59), 0);
    amxp_scheduler_connect(scheduler, "test1", check_start_stop_trigger, (void*) "test1");
    amxp_scheduler_connect(scheduler, NULL, dump_schedule_trigger, NULL);

    trigger_counter = 2;
    expect_string(check_start_stop_trigger, sig_name, "start:test1");
    handle_events();
    assert_int_equal(trigger_counter, 1);

    amxp_timers_calculate();
    amxp_timers_check();
    assert_int_equal(scheduler->timer->state, amxp_timer_running);

    expect_string(check_start_stop_trigger, sig_name, "stop:test1");
    printf("Wait for SIGALRM\n");
    read_sigalrm();
    printf("SIGALRM -> Handle events\n");
    handle_events();
    assert_int_equal(trigger_counter, 0);

    amxp_scheduler_delete(&scheduler);
    assert_null(scheduler);
}

void test_scheduler_adding_running_triggers_start_end(UNUSED void** state) {
    amxp_scheduler_t* scheduler = NULL;

    assert_int_equal(amxp_scheduler_new(&scheduler), 0);
    assert_non_null(scheduler);
    assert_true(scheduler->sigmngr.enabled);

    assert_non_null(scheduler->timer);
    sleep(2);

    assert_int_equal(amxp_scheduler_set_cron_begin_end_item(scheduler, "test1",
                                                            "0 * * * * *",
                                                            "59 * * * * *"), 0);

    amxp_scheduler_connect(scheduler, "test1", check_start_stop_trigger, (void*) "test1");
    amxp_scheduler_connect(scheduler, NULL, dump_schedule_trigger, NULL);

    trigger_counter = 2;
    expect_string(check_start_stop_trigger, sig_name, "start:test1");
    handle_events();
    assert_int_equal(trigger_counter, 1);

    amxp_timers_calculate();
    amxp_timers_check();
    assert_int_equal(scheduler->timer->state, amxp_timer_running);
    expect_string(check_start_stop_trigger, sig_name, "stop:test1");

    read_sigalrm();
    handle_events();
    assert_int_equal(trigger_counter, 0);

    amxp_timers_calculate();
    amxp_timers_check();

    trigger_counter = 2;
    expect_string(check_start_stop_trigger, sig_name, "start:test1");
    read_sigalrm();
    handle_events();
    assert_int_equal(trigger_counter, 1);

    amxp_timers_calculate();
    amxp_timers_check();

    expect_string(check_start_stop_trigger, sig_name, "stop:test1");
    read_sigalrm();
    handle_events();
    assert_int_equal(trigger_counter, 0);

    amxp_scheduler_delete(&scheduler);
    assert_null(scheduler);
}

void test_scheduler_can_disable_running_items(UNUSED void** state) {
    amxp_scheduler_t* scheduler = NULL;

    assert_int_equal(amxp_scheduler_new(&scheduler), 0);
    assert_non_null(scheduler);
    assert_true(scheduler->sigmngr.enabled);

    assert_non_null(scheduler->timer);
    sleep(3);

    assert_int_equal(amxp_scheduler_set_cron_begin_end_item(scheduler, "test1",
                                                            "0 * * * * *",
                                                            "59 * * * * *"), 0);
    expect_string(check_start_stop_trigger, sig_name, "start:test1");

    amxp_scheduler_connect(scheduler, "test1", check_start_stop_trigger, (void*) "test1");
    amxp_scheduler_connect(scheduler, NULL, dump_schedule_trigger, NULL);

    trigger_counter = 4;
    handle_events();
    assert_int_equal(trigger_counter, 3);

    amxp_timers_calculate();
    amxp_timers_check();
    assert_int_equal(scheduler->timer->state, amxp_timer_running);

    assert_int_equal(amxp_scheduler_enable_item(scheduler, "test1", false), 0);
    expect_string(check_start_stop_trigger, sig_name, "stop:test1");

    handle_events();
    assert_int_equal(trigger_counter, 2);

    assert_int_equal(amxp_scheduler_enable_item(scheduler, "test1", true), 0);
    expect_string(check_start_stop_trigger, sig_name, "start:test1");

    handle_events();
    assert_int_equal(trigger_counter, 1);

    expect_string(check_start_stop_trigger, sig_name, "stop:test1");
    read_sigalrm();
    handle_events();
    assert_int_equal(trigger_counter, 0);

    amxp_scheduler_delete(&scheduler);
    assert_null(scheduler);
}

void test_scheduler_can_disable_items(UNUSED void** state) {
    amxp_scheduler_t* scheduler = NULL;

    assert_int_equal(amxp_scheduler_new(&scheduler), 0);
    assert_non_null(scheduler);
    assert_true(scheduler->sigmngr.enabled);

    assert_non_null(scheduler->timer);
    assert_int_equal(amxp_scheduler_set_cron_item(scheduler, "test1", "0/15 * * * * *", 0), 0);
    assert_int_equal(amxp_scheduler_set_cron_item(scheduler, "test2", "0/5 * * * * *", 0), 0);
    assert_int_equal(amxp_scheduler_set_cron_item(scheduler, "test3", "0/10 * * * * *", 0), 0);
    assert_int_equal(amxp_scheduler_set_weekly_item(scheduler, "test4", "23:00", "saturday,sunday", 0), 0);

    amxp_scheduler_connect(scheduler, "test1", check_schedule_trigger, (void*) "test1");
    amxp_scheduler_connect(scheduler, "test2", check_schedule_trigger, (void*) "test2");
    amxp_scheduler_connect(scheduler, "test3", check_schedule_trigger, (void*) "test3");
    amxp_scheduler_connect(scheduler, "test4", check_schedule_trigger, (void*) "test4");

    amxp_timers_calculate();
    amxp_timers_check();
    assert_int_equal(scheduler->timer->state, amxp_timer_running);

    amxp_scheduler_enable_item(scheduler, "test1", false);
    amxp_scheduler_enable_item(scheduler, "test3", false);
    amxp_scheduler_enable_item(scheduler, "test4", false);

    check_scheduler(scheduler);
    printf("Expecting %d triggers if all items are enabled\n", trigger_counter);
    trigger_counter = 1;
    read_sigalrm();
    handle_events();
    assert_int_equal(trigger_counter, 0);

    check_scheduler(scheduler);
    printf("Expecting %d triggers if all items are enabled\n", trigger_counter);
    trigger_counter = 1;
    read_sigalrm();
    handle_events();
    assert_int_equal(trigger_counter, 0);

    check_scheduler(scheduler);
    printf("Expecting %d triggers if all items are enabled\n", trigger_counter);
    trigger_counter = 1;
    read_sigalrm();
    handle_events();
    assert_int_equal(trigger_counter, 0);

    amxp_scheduler_delete(&scheduler);
    assert_null(scheduler);
}

void test_scheduler_add_invalid_item_fails(UNUSED void** state) {
    amxp_scheduler_t* scheduler = NULL;

    assert_int_equal(amxp_scheduler_new(&scheduler), 0);
    assert_non_null(scheduler);

    assert_int_not_equal(amxp_scheduler_set_cron_item(scheduler, "test1", "0/15 *  * * *", 0), 0);
    assert_int_not_equal(amxp_scheduler_set_cron_item(scheduler, "test1", "Invalid", 0), 0);
    assert_int_not_equal(amxp_scheduler_set_cron_item(scheduler, "test1", "0 0 15 * * WEEKDAY", 0), 0);
    assert_int_not_equal(amxp_scheduler_set_cron_begin_end_item(scheduler, "test1", "0 0 15 * * WEEKDAY", "* * * * * *"), 0);
    assert_int_not_equal(amxp_scheduler_set_cron_begin_end_item(scheduler, "test1", "* * * * * *", "0 0 15 * * WEEKDAY"), 0);
    assert_int_not_equal(amxp_scheduler_set_weekly_item(scheduler, "test1", "99:10:99", "WEEKDAYS", 0), 0);

    assert_int_not_equal(amxp_scheduler_set_cron_item(scheduler, NULL, "0/15 * * * * *", 0), 0);
    assert_int_not_equal(amxp_scheduler_set_cron_item(scheduler, "", "0/15 * * * * *", 0), 0);
    assert_int_not_equal(amxp_scheduler_set_cron_item(scheduler, "test1", NULL, 0), 0);
    assert_int_not_equal(amxp_scheduler_set_cron_item(scheduler, "test1", "", 0), 0);
    assert_int_not_equal(amxp_scheduler_set_cron_item(NULL, "test1", "* * * * * *", 0), 0);
    assert_int_not_equal(amxp_scheduler_set_cron_begin_end_item(scheduler, "", "0 0 15 * * *", "* * * * * *"), 0);
    assert_int_not_equal(amxp_scheduler_set_cron_begin_end_item(scheduler, NULL, "0 0 15 * * *", "* * * * * *"), 0);

    assert_int_not_equal(amxp_scheduler_set_weekly_item(scheduler, NULL, "15:00:00", "sunday", 0), 0);
    assert_int_not_equal(amxp_scheduler_set_weekly_item(NULL, "test1", "15:00:00", "sunday", 0), 0);
    assert_int_not_equal(amxp_scheduler_set_weekly_item(scheduler, "", "15:00:00", "sunday", 0), 0);
    assert_int_not_equal(amxp_scheduler_set_weekly_item(scheduler, "test1", "15:00", "", 0), 0);
    assert_int_not_equal(amxp_scheduler_set_weekly_item(scheduler, "test1", "15:00", NULL, 0), 0);
    assert_int_not_equal(amxp_scheduler_set_weekly_begin_end_item(scheduler, NULL, "15:00:00", "16:00", "sunday"), 0);
    assert_int_not_equal(amxp_scheduler_set_weekly_begin_end_item(NULL, "test1", "15:00:00", "16:00", "sunday"), 0);
    assert_int_not_equal(amxp_scheduler_set_weekly_begin_end_item(scheduler, "", "15:00:00", "16:00", "sunday"), 0);
    assert_int_not_equal(amxp_scheduler_set_weekly_begin_end_item(scheduler, "test1", "15:00:00", "16:00", ""), 0);
    assert_int_not_equal(amxp_scheduler_set_weekly_begin_end_item(scheduler, "test1", "15:00:00", "16:00", NULL), 0);
    assert_int_not_equal(amxp_scheduler_set_weekly_begin_end_item(scheduler, "test1", "15:00:00", "16:00", "WEEKDAY"), 0);
    assert_int_not_equal(amxp_scheduler_set_weekly_begin_end_item(scheduler, "test1", "15:00:00", "INVALID", "sunday"), 0);
    assert_int_not_equal(amxp_scheduler_set_weekly_begin_end_item(scheduler, "test1", "INVALID", "16:00", "sunday"), 0);

    assert_int_equal(amxp_scheduler_set_cron_item(scheduler, "test1", "0/15 * * * * *", 0), 0);
    assert_int_equal(amxp_scheduler_set_cron_item(scheduler, "test1", "0 0/15 * * * *", 0), 0);
    assert_int_equal(amxp_scheduler_remove_item(scheduler, "test2"), 0);
    assert_int_equal(amxp_scheduler_remove_item(scheduler, "test1"), 0);

    amxp_timers_calculate();
    amxp_timers_check();
    assert_int_not_equal(scheduler->timer->state, amxp_timer_running);

    amxp_scheduler_delete(&scheduler);
    assert_null(scheduler);
}