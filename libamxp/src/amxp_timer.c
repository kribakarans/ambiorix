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

#include <amxc/amxc.h>
#include <amxc/amxc_macros.h>
#include <amxp/amxp.h>

static amxc_llist_t timers;
static struct timeval current;
static bool timers_enabled = true;

static void amxp_timer_free_it(amxc_llist_it_t* it) {
    amxp_timer_t* timer = amxc_llist_it_get_data(it, amxp_timer_t, it);
    free(timer);
}

static struct timeval amxp_timer_get_elapsed_time(void) {
    struct itimerval ti;
    struct timeval elapsed = { 0, 0 };

    /* get the elapsed period */
    if(!timerisset(&current)) {
        return elapsed;
    }

    getitimer(ITIMER_REAL, &ti);
    if(timerisset(&ti.it_value)) {
        timersub(&current, &ti.it_value, &elapsed);
    } else {
        elapsed = current;
    }

    return elapsed;
}

static void amxp_timer_update_current(struct timeval* elapsed) {
    timersub(&current, elapsed, &current);

    if(current.tv_sec < 0) {
        timerclear(&current);
    }
}

static void amxp_timer_start_timer(amxp_timer_t* timer, struct timeval* smallest) {
    timer->state = amxp_timer_running;
    // *INDENT-OFF*
    if(!timerisset(smallest) || timercmp(smallest, &timer->timer.it_value, >)) {
        (*smallest) = timer->timer.it_value;
    }
    // *INDENT-ON*
}

static bool amxp_timer_update(amxp_timer_t* timer,
                              struct timeval* smallest,
                              struct timeval* elapsed) {
    timersub(&timer->timer.it_value, elapsed, &timer->timer.it_value);
    if(!((timer->timer.it_value.tv_sec < 0) ||
         !timerisset(&timer->timer.it_value))) {

        // *INDENT-OFF*
        if(!timerisset(smallest) ||
           timercmp(smallest, &timer->timer.it_value, >)) {
            (*smallest) = timer->timer.it_value;
        }
        // *INDENT-ON*
        return true;
    }

    if(timer->state != amxp_timer_expired) {
        timer->state = amxp_timer_expired;
    }

    if(timerisset(&timer->timer.it_interval)) {
        timer->timer.it_value = timer->timer.it_interval;
        // *INDENT-OFF*
        if(!timerisset(smallest) ||
           timercmp(smallest, &timer->timer.it_value, >)) {
            (*smallest) = timer->timer.it_value;
        }
        // *INDENT-ON*
        return true;
    }

    return false;
}

void amxp_timers_calculate(void) {
    struct timeval elapsed = { 0, 0 };
    bool active_timer = false;
    struct itimerval ti;
    struct timeval smallest;

    elapsed = amxp_timer_get_elapsed_time();

    timerclear(&smallest);
    amxp_timer_update_current(&elapsed);

    amxc_llist_for_each(it, (&timers)) {
        amxp_timer_t* timer = amxc_llist_it_get_data(it, amxp_timer_t, it);
        if(timer->state == amxp_timer_deleted) {
            continue;
        }
        if(timer->state == amxp_timer_off) {
            continue;
        }
        if(timer->state == amxp_timer_started) {
            amxp_timer_start_timer(timer, &smallest);
            active_timer = true;
            continue;
        }

        active_timer |= amxp_timer_update(timer, &smallest, &elapsed);
    }

    timerclear(&ti.it_interval);
    current = smallest;
    if(active_timer) {
        ti.it_value = current;
    } else {
        ti.it_value.tv_sec = 0;
        ti.it_value.tv_usec = 0;
    }
    setitimer(ITIMER_REAL, &ti, NULL);
}

void amxp_timers_check(void) {
    static uint32_t recursive = 0;
    amxp_timer_t* timer = NULL;
    amxc_llist_it_t* it = NULL;

    recursive++;
    when_true(!timers_enabled, exit);

    it = amxc_llist_get_first(&timers);
    // do not use amxc_llist_for_each here.
    // it is possible that in the callback function a new timer is added.
    // this new timer must be taken into account as well.
    // new timers are always added to the end of the list.
    while(it) {
        timer = amxc_llist_it_get_data(it, amxp_timer_t, it);
        if((timer->state == amxp_timer_deleted) && (recursive == 1)) {
            it = amxc_llist_it_get_next(&timer->it);
            amxc_llist_it_clean(&timer->it, amxp_timer_free_it);
            continue;
        }

        if(timer->state == amxp_timer_expired) {
            if(timerisset(&timer->timer.it_interval)) {
                timer->state = amxp_timer_running;
            } else {
                timer->state = amxp_timer_off;
            }
            if(timer->cb) {
                amxp_timers_enable(false);
                timer->cb(timer, timer->priv);
                amxp_timers_enable(true);
            }
        }

        it = amxc_llist_it_get_next(&timer->it);
    }

exit:
    recursive--;
    return;
}

void amxp_timers_enable(bool enable) {
    timers_enabled = enable;
}

int amxp_timer_new(amxp_timer_t** timer, amxp_timer_cb_t cb, void* priv) {
    int retval = -1;

    when_null(timer, exit);
    when_not_null(*timer, exit);

    *timer = (amxp_timer_t*) calloc(1, sizeof(amxp_timer_t));
    when_null(*timer, exit);
    (*timer)->cb = cb;
    (*timer)->priv = priv;
    amxc_llist_append(&timers, &(*timer)->it);

    retval = 0;

exit:
    return retval;
}

void amxp_timer_delete(amxp_timer_t** timer) {
    when_null(timer, exit);
    when_null(*timer, exit);

    amxp_timer_stop(*timer);
    (*timer)->state = amxp_timer_deleted;
    *timer = NULL;

exit:
    return;
}

int amxp_timer_set_interval(amxp_timer_t* timer, unsigned int msec) {
    int retval = -1;

    when_null(timer, exit);

    if(msec == 0) {
        // this is the absolute minimum value for a timer.
        // if the value is 0 setitimer has no effect as when set to zero
        // the timer is stopped (and will never trigger SIGALRM)
        // see man page of setitimer
        msec = 1;
    }

    timer->timer.it_interval.tv_sec = msec / 1000;
    timer->timer.it_interval.tv_usec = (msec % 1000) * 1000;

    retval = 0;

exit:
    return retval;
}

unsigned int amxp_timer_remaining_time(amxp_timer_t* timer) {
    unsigned int retval = 0;

    when_null(timer, exit);
    when_true(timer->state != amxp_timer_running &&
              timer->state != amxp_timer_started,
              exit);

    retval = timer->timer.it_value.tv_sec * 1000 +
        timer->timer.it_value.tv_usec / 1000;

exit:
    return retval;
}

int amxp_timer_start(amxp_timer_t* timer, unsigned int timeout_msec) {
    int retval = -1;
    when_null(timer, exit);
    when_true(timer->state == amxp_timer_deleted, exit);

    if(timeout_msec == 0) {
        // this is the absolute minimum value for a timer.
        // if the value is 0 setitimer has no effect as when set to zero
        // the timer is stopped (and will never trigger SIGALRM)
        // see man page of setitimer
        timeout_msec = 1;
    }
    timer->timer.it_value.tv_sec = timeout_msec / 1000;
    timer->timer.it_value.tv_usec = (timeout_msec % 1000) * 1000;
    timer->state = amxp_timer_started;

    amxp_timers_calculate();

    retval = 0;
exit:
    return retval;
}

int amxp_timer_stop(amxp_timer_t* timer) {
    int retval = -1;
    when_null(timer, exit);
    when_true(timer->state == amxp_timer_deleted, exit);

    timer->state = amxp_timer_off;

    amxp_timers_calculate();

    retval = 0;

exit:
    return retval;
}

amxp_timer_state_t amxp_timer_get_state(amxp_timer_t* timer) {
    return timer == NULL ? amxp_timer_off : timer->state;
}

CONSTRUCTOR_LVL(101) static void amxp_timers_init(void) {
    amxc_llist_init(&timers);
}

DESTRUCTOR_LVL(101) static void amxp_timers_cleanup(void) {
    amxc_llist_clean(&timers, amxp_timer_free_it);
}