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

#include <amxc/amxc.h>
#include <amxp/amxp_scheduler.h>
#include <amxc/amxc_macros.h>

static void amxp_schedule_item_delete(amxc_llist_it_t* it) {
    amxp_scheduler_item_t* item = amxc_container_of(it, amxp_scheduler_item_t, lit);

    amxp_cron_clean(&item->cron);
    amxp_timer_delete(&item->timer);
    amxc_htable_it_clean(&item->hit, NULL);
    free(item);
}

static int amxp_scheduler_compare_items(amxc_llist_it_t* it1, amxc_llist_it_t* it2) {
    amxp_scheduler_item_t* item1 = amxc_container_of(it1, amxp_scheduler_item_t, lit);
    amxp_scheduler_item_t* item2 = amxc_container_of(it2, amxp_scheduler_item_t, lit);

    return item1->next.sec - item2->next.sec;
}

static void amxp_scheduler_reset_timer(amxp_scheduler_t* scheduler) {
    amxc_llist_it_t* it = NULL;
    amxp_scheduler_item_t* item = NULL;
    uint64_t next = 0;

    amxc_llist_sort(&scheduler->ordered_items, amxp_scheduler_compare_items);
    it = amxc_llist_get_first(&scheduler->ordered_items);
    if(it == NULL) {
        amxp_timer_stop(scheduler->timer);
        goto exit;
    }

    item = amxc_container_of(it, amxp_scheduler_item_t, lit);
    next = amxp_cron_time_until_next(&item->cron, scheduler->use_local_time);

    if(scheduler->sigmngr.enabled) {
        amxp_timer_start(scheduler->timer, next * 1000);
    }

exit:
    return;
}

static void amxp_scheduler_emit(amxp_scheduler_t* scheduler,
                                amxp_scheduler_item_t* item,
                                const char* signal,
                                uint32_t duration,
                                bool trigger) {
    amxc_var_t data;
    amxc_string_t strsignal;
    amxp_signal_t* s = NULL;
    const char* id = amxc_htable_it_get_key(&item->hit);
    amxc_var_init(&data);
    amxc_var_set_type(&data, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &data, "id", id);
    amxc_string_init(&strsignal, 0);

    amxc_string_setf(&strsignal, "%s:%s", signal, id);

    if(duration != 0) {
        amxc_var_add_key(uint32_t, &data, "duration", duration);
    }

    amxc_var_add_key(cstring_t, &data, "reason", signal);

    s = amxp_sigmngr_find_signal(&scheduler->sigmngr, amxc_string_get(&strsignal, 0));
    when_null(s, exit);
    if(trigger) {
        if(!s->triggered) {
            amxp_sigmngr_trigger_signal(&scheduler->sigmngr, amxc_string_get(&strsignal, 0), &data);
        }
    } else {
        amxp_sigmngr_emit_signal(&scheduler->sigmngr, amxc_string_get(&strsignal, 0), &data);
    }

exit:
    amxc_string_clean(&strsignal);
    amxc_var_clean(&data);
}


static void amxp_scheduler_item_stop(UNUSED amxp_timer_t* timer, void* priv) {
    amxp_scheduler_item_t* item = (amxp_scheduler_item_t*) priv;
    amxp_scheduler_t* scheduler = amxc_container_of(item->lit.llist, amxp_scheduler_t, ordered_items);

    amxp_timer_delete(&item->timer);
    amxp_scheduler_emit(scheduler, item, "stop", 0, false);
}

static void amxp_scheduler_check_item(amxp_scheduler_t* scheduler,
                                      amxp_scheduler_item_t* item) {
    amxc_ts_t now;
    amxc_ts_t prev = { 0, 0, 0};
    uint32_t duration = 0;
    amxc_ts_now(&now);

    when_false(scheduler->sigmngr.enabled, exit);
    when_false(item->enabled, exit);
    if((item->duration == 0) && !item->end_time_is_set) {
        if((item->timer != NULL) && (item->timer->state == amxp_timer_running)) {
            amxp_scheduler_emit(scheduler, item, "stop", 0, false);
            amxp_timer_delete(&item->timer);
        }
        goto exit;
    }

    if(scheduler->use_local_time) {
        amxc_ts_to_local(&now);
    }

    duration = item->duration;
    amxp_cron_prev(&item->cron, &now, &prev);
    if((duration == 0) && item->end_time_is_set) {
        amxc_ts_t end = { 0, 0, 0};
        amxp_cron_next(&item->end_cron, &prev, &end);
        duration = end.sec - prev.sec;
    }

    prev.sec += duration;
    if(prev.sec > now.sec) {
        if(item->timer == NULL) {
            amxp_timer_new(&item->timer, amxp_scheduler_item_stop, item);
        }
        if(item->timer->state != amxp_timer_running) {
            amxp_scheduler_emit(scheduler, item, "start", prev.sec - now.sec, false);
        }
        amxp_timer_start(item->timer, (prev.sec - now.sec) * 1000);
    } else {
        if((item->timer != NULL) && (item->timer->state == amxp_timer_running)) {
            amxp_scheduler_emit(scheduler, item, "stop", 0, false);
            amxp_timer_delete(&item->timer);
        }
    }

exit:
    return;
}

static void amxp_scheduler_trigger(amxp_timer_t* timer, void* priv) {
    amxp_scheduler_t* scheduler = (amxp_scheduler_t*) priv;
    amxc_llist_it_t* it = amxc_llist_get_first(&scheduler->ordered_items);
    amxp_scheduler_item_t* item = amxc_container_of(it, amxp_scheduler_item_t, lit);
    amxc_ts_t now;
    uint32_t duration = 0;

    when_false(timer == scheduler->timer, exit);
    amxc_ts_now(&now);

    if(scheduler->use_local_time) {
        amxc_ts_to_local(&now);
    }

    while(it != NULL && item->next.sec <= now.sec) {
        if(item->enabled) {
            duration = item->duration;
            if((duration == 0) && item->end_time_is_set) {
                amxc_ts_t end = { 0, 0, 0};
                amxp_cron_next(&item->end_cron, &now, &end);
                duration = end.sec - now.sec;
            }
            if(duration == 0) {
                amxp_scheduler_emit(scheduler, item, "trigger", 0, false);
            } else {
                amxp_scheduler_emit(scheduler, item, "start", duration, false);
                amxp_timer_new(&item->timer, amxp_scheduler_item_stop, item);
                amxp_timer_start(item->timer, duration * 1000);
            }
        }
        amxp_cron_next(&item->cron, &now, &item->next);
        it = amxc_llist_it_get_next(it);
        if(it != NULL) {
            item = amxc_container_of(it, amxp_scheduler_item_t, lit);
        }
    }

    amxp_scheduler_reset_timer(scheduler);
exit:
    return;
}

static void amxp_scheduler_add_signal(amxp_scheduler_t* scheduler, const char* signal, const char* id) {
    amxc_string_t strsignal;
    amxc_string_init(&strsignal, 0);

    amxc_string_setf(&strsignal, "%s:%s", signal, id);
    amxp_sigmngr_add_signal(&scheduler->sigmngr, amxc_string_get(&strsignal, 0));

    amxc_string_clean(&strsignal);
}

static void amxp_scheduler_remove_signal(amxp_scheduler_t* scheduler, const char* signal, const char* id) {
    amxc_string_t strsignal;
    amxp_signal_t* s = NULL;
    amxc_string_init(&strsignal, 0);

    amxc_string_setf(&strsignal, "%s:%s", signal, id);
    s = amxp_sigmngr_find_signal(&scheduler->sigmngr, amxc_string_get(&strsignal, 0));
    if(s != NULL) {
        if(s->triggered) {
            amxp_sigmngr_remove_signal(&scheduler->sigmngr, amxc_string_get(&strsignal, 0));
        } else {
            amxp_signal_delete(&s);
        }
    }

    amxc_string_clean(&strsignal);
}

static amxp_scheduler_item_t* amxp_scheduler_create_or_fetch(amxp_scheduler_t* scheduler,
                                                             const char* id,
                                                             uint32_t duration) {
    amxp_scheduler_item_t* item = NULL;
    amxc_htable_it_t* hit = NULL;
    bool enabled = true;

    when_null(scheduler, exit);
    when_str_empty(id, exit);

    hit = amxc_htable_get(&scheduler->items, id);
    if(hit != NULL) {
        item = amxc_container_of(hit, amxp_scheduler_item_t, hit);
        enabled = item != NULL? item->enabled:true;
    } else {
        item = (amxp_scheduler_item_t*) calloc(1, sizeof(amxp_scheduler_item_t));
    }
    when_null(item, exit);

    item->duration = duration;
    item->enabled = enabled;

exit:
    return item;
}

static void amxp_scheduler_insert(amxp_scheduler_t* scheduler,
                                  const char* id,
                                  amxp_scheduler_item_t* item) {

    amxc_ts_t now;

    amxc_ts_now(&now);
    if(scheduler->use_local_time) {
        amxc_ts_to_local(&now);
    }

    amxp_cron_next(&item->cron, &now, &item->next);
    amxc_llist_prepend(&scheduler->ordered_items, &item->lit);
    amxc_htable_insert(&scheduler->items, id, &item->hit);

    amxp_scheduler_add_signal(scheduler, "trigger", id);
    amxp_scheduler_add_signal(scheduler, "start", id);
    amxp_scheduler_add_signal(scheduler, "stop", id);

    amxp_scheduler_check_item(scheduler, item);
    amxp_scheduler_reset_timer(scheduler);
}

int amxp_scheduler_new(amxp_scheduler_t** scheduler) {
    int rv = -1;

    when_null(scheduler, exit);
    *scheduler = (amxp_scheduler_t*) calloc(1, sizeof(amxp_scheduler_t));
    when_null(*scheduler, exit);

    rv = amxp_scheduler_init(*scheduler);

exit:
    return rv;
}

void amxp_scheduler_delete(amxp_scheduler_t** scheduler) {
    when_null(scheduler, exit);
    when_null(*scheduler, exit);

    amxp_scheduler_clean(*scheduler);
    free(*scheduler);
    *scheduler = NULL;

exit:
    return;
}

int amxp_scheduler_init(amxp_scheduler_t* scheduler) {
    int rv = -1;

    when_null(scheduler, exit);

    amxp_sigmngr_init(&scheduler->sigmngr);
    amxp_sigmngr_enable(&scheduler->sigmngr, true);

    scheduler->use_local_time = false;
    scheduler->timer = NULL;
    amxp_timer_new(&scheduler->timer, amxp_scheduler_trigger, scheduler);
    amxc_htable_init(&scheduler->items, 5);
    amxc_llist_init(&scheduler->ordered_items);

    rv = 0;

exit:
    return rv;
}

void amxp_scheduler_clean(amxp_scheduler_t* scheduler) {
    when_null(scheduler, exit);
    amxp_sigmngr_clean(&scheduler->sigmngr);
    amxp_timer_delete(&scheduler->timer);
    amxc_llist_for_each(it, &scheduler->ordered_items) {
        amxp_scheduler_item_t* item = amxc_container_of(it, amxp_scheduler_item_t, lit);
        if((item->timer != NULL) && (item->timer->state == amxp_timer_running)) {
            amxp_scheduler_emit(scheduler, item, "stop", 0, true);
        }
    }
    amxc_llist_clean(&scheduler->ordered_items, amxp_schedule_item_delete);
    amxc_htable_clean(&scheduler->items, NULL); // items are freed when cleaning ordered list.

exit:
    return;
}

int amxp_scheduler_enable(amxp_scheduler_t* scheduler, bool enable) {
    int rv = -1;

    when_null(scheduler, exit);
    when_true_status(scheduler->sigmngr.enabled == enable, exit, rv = 0);

    amxp_sigmngr_enable(&scheduler->sigmngr, enable);
    if(enable) {
        amxp_scheduler_update(scheduler);
        amxp_scheduler_reset_timer(scheduler);
    }
    if(!enable) {
        amxp_scheduler_update(scheduler);
        amxp_timer_stop(scheduler->timer);
    }

    rv = 0;

exit:
    return rv;
}

int amxp_scheduler_use_local_time(amxp_scheduler_t* scheduler, bool use_local_time) {
    int rv = -1;

    when_null(scheduler, exit);

    when_true_status(use_local_time == scheduler->use_local_time, exit, rv = 0);
    scheduler->use_local_time = use_local_time;
    amxp_scheduler_update(scheduler);

    rv = 0;

exit:
    return rv;
}

int amxp_scheduler_update(amxp_scheduler_t* scheduler) {
    int rv = -1;
    amxc_ts_t now;
    amxp_scheduler_item_t* item = NULL;

    amxc_ts_now(&now);
    when_null(scheduler, exit);

    if(scheduler->use_local_time) {
        amxc_ts_to_local(&now);
    }

    amxc_llist_for_each(item_it, &scheduler->ordered_items) {
        item = amxc_container_of(item_it, amxp_scheduler_item_t, lit);
        amxp_cron_next(&item->cron, &now, &item->next);
        if(scheduler->sigmngr.enabled) {
            amxp_scheduler_check_item(scheduler, item);
        } else {
            amxp_timer_delete(&item->timer);
        }
    }

    amxp_scheduler_reset_timer(scheduler);

    rv = 0;

exit:
    return rv;
}

int amxp_scheduler_connect(amxp_scheduler_t* scheduler,
                           const char* id,
                           amxp_slot_fn_t fn,
                           void* priv) {

    int rv = -1;
    amxc_string_t signal;
    amxc_htable_it_t* hit = NULL;
    amxp_scheduler_item_t* item = NULL;

    amxc_string_init(&signal, 0);
    when_null(scheduler, exit);

    if((id == NULL) || (*id == 0)) {
        // connect to all signals
        rv = amxp_slot_connect(&scheduler->sigmngr, "*", NULL, fn, priv);
        goto exit;
    }

    hit = amxc_htable_get(&scheduler->items, id);
    when_null(hit, exit);
    item = amxc_container_of(hit, amxp_scheduler_item_t, hit);
    when_null(item, exit);

    amxc_string_setf(&signal, "start:%s", id);
    rv = amxp_slot_connect(&scheduler->sigmngr, amxc_string_get(&signal, 0), NULL, fn, priv);
    when_failed(rv, exit);
    amxc_string_setf(&signal, "stop:%s", id);
    rv = amxp_slot_connect(&scheduler->sigmngr, amxc_string_get(&signal, 0), NULL, fn, priv);
    when_failed(rv, exit);
    amxc_string_setf(&signal, "trigger:%s", id);
    rv = amxp_slot_connect(&scheduler->sigmngr, amxc_string_get(&signal, 0), NULL, fn, priv);

exit:
    amxc_string_clean(&signal);
    return rv;
}

int amxp_scheduler_disconnect(amxp_scheduler_t* scheduler,
                              const char* id,
                              amxp_slot_fn_t fn) {

    int rv = -1;
    amxc_string_t signal;
    amxc_htable_it_t* hit = NULL;
    amxp_scheduler_item_t* item = NULL;

    amxc_string_init(&signal, 0);
    when_null(scheduler, exit);

    if((id == NULL) || (*id == 0)) {
        // connect to all signals
        amxp_slot_disconnect_all(fn);
        rv = 0;
        goto exit;
    }

    hit = amxc_htable_get(&scheduler->items, id);
    when_null(hit, exit);
    item = amxc_container_of(hit, amxp_scheduler_item_t, hit);
    when_null(item, exit);

    amxc_string_setf(&signal, "start:%s", id);
    rv = amxp_slot_disconnect(&scheduler->sigmngr, amxc_string_get(&signal, 0), fn);
    when_failed(rv, exit);
    amxc_string_setf(&signal, "stop:%s", id);
    rv = amxp_slot_disconnect(&scheduler->sigmngr, amxc_string_get(&signal, 0), fn);
    when_failed(rv, exit);
    amxc_string_setf(&signal, "trigger:%s", id);
    rv = amxp_slot_disconnect(&scheduler->sigmngr, amxc_string_get(&signal, 0), fn);

exit:
    amxc_string_clean(&signal);
    return rv;
}

int amxp_scheduler_set_cron_item(amxp_scheduler_t* scheduler,
                                 const char* id,
                                 const char* cron_expr,
                                 uint32_t duration) {
    int rv = -1;
    amxp_scheduler_item_t* item = NULL;

    when_str_empty(cron_expr, exit);

    item = amxp_scheduler_create_or_fetch(scheduler, id, duration);
    when_null(item, exit);

    item->end_time_is_set = false;

    rv = amxp_cron_parse_expr(&item->cron, cron_expr, NULL);
    when_failed(rv, exit);

    amxp_scheduler_insert(scheduler, id, item);

exit:
    if((rv != 0) && (item != NULL)) {
        amxc_llist_it_clean(&item->lit, amxp_schedule_item_delete);
    }
    return rv;
}

int amxp_scheduler_set_cron_begin_end_item(amxp_scheduler_t* scheduler,
                                           const char* id,
                                           const char* cron_begin,
                                           const char* cron_end) {
    int rv = -1;
    amxp_scheduler_item_t* item = NULL;

    when_str_empty(cron_begin, exit);
    when_str_empty(cron_end, exit);

    item = amxp_scheduler_create_or_fetch(scheduler, id, 0);
    when_null(item, exit);

    item->end_time_is_set = true;

    rv = amxp_cron_parse_expr(&item->cron, cron_begin, NULL);
    when_failed(rv, exit);
    rv = amxp_cron_parse_expr(&item->end_cron, cron_end, NULL);
    when_failed(rv, exit);

    amxp_scheduler_insert(scheduler, id, item);

exit:
    if((rv != 0) && (item != NULL)) {
        amxc_llist_it_clean(&item->lit, amxp_schedule_item_delete);
    }
    return rv;
}

int amxp_scheduler_set_weekly_item(amxp_scheduler_t* scheduler,
                                   const char* id,
                                   const char* time,
                                   const char* days_of_week,
                                   uint32_t duration) {
    int rv = -1;
    amxp_scheduler_item_t* item = NULL;

    when_str_empty(days_of_week, exit);

    if((time == NULL) || (*time == 0)) {
        time = "00:00";
    }

    item = amxp_scheduler_create_or_fetch(scheduler, id, duration);
    when_null(item, exit);

    item->end_time_is_set = false;

    rv = amxp_cron_build_weekly(&item->cron, time, days_of_week);
    when_failed(rv, exit);

    amxp_scheduler_insert(scheduler, id, item);

exit:
    if((rv != 0) && (item != NULL)) {
        amxc_llist_it_clean(&item->lit, amxp_schedule_item_delete);
    }
    return rv;
}

int amxp_scheduler_set_weekly_begin_end_item(amxp_scheduler_t* scheduler,
                                             const char* id,
                                             const char* start_time,
                                             const char* end_time,
                                             const char* days_of_week) {
    int rv = -1;
    amxp_scheduler_item_t* item = NULL;

    when_str_empty(days_of_week, exit);

    if((start_time == NULL) || (*start_time == 0)) {
        start_time = "00:00";
    }

    if((end_time == NULL) || (*end_time == 0)) {
        end_time = "23:59";
    }

    item = amxp_scheduler_create_or_fetch(scheduler, id, 0);
    when_null(item, exit);

    item->end_time_is_set = true;

    rv = amxp_cron_build_weekly(&item->cron, start_time, days_of_week);
    when_failed(rv, exit);
    rv = amxp_cron_build_weekly(&item->end_cron, end_time, days_of_week);
    when_failed(rv, exit);

    amxp_scheduler_insert(scheduler, id, item);

exit:
    if((rv != 0) && (item != NULL)) {
        amxc_llist_it_clean(&item->lit, amxp_schedule_item_delete);
    }
    return rv;
}

int amxp_scheduler_remove_item(amxp_scheduler_t* scheduler,
                               const char* id) {

    int rv = -1;
    amxc_htable_it_t* hit = NULL;
    amxp_scheduler_item_t* item = NULL;

    when_null(scheduler, exit);
    when_str_empty(id, exit);

    hit = amxc_htable_get(&scheduler->items, id);
    when_null_status(hit, exit, rv = 0);
    item = amxc_container_of(hit, amxp_scheduler_item_t, hit);

    amxc_htable_it_take(hit);
    if((item->timer != NULL) && (item->timer->state == amxp_timer_running)) {
        amxp_timer_stop(item->timer);
        amxp_scheduler_emit(scheduler, item, "stop", 0, true);
    }

    amxp_scheduler_remove_signal(scheduler, "start", id);
    amxp_scheduler_remove_signal(scheduler, "stop", id);
    amxp_scheduler_remove_signal(scheduler, "trigger", id);

    amxc_llist_it_clean(&item->lit, amxp_schedule_item_delete);
    amxp_scheduler_reset_timer(scheduler);

    rv = 0;

exit:
    return rv;
}

int amxp_scheduler_enable_item(amxp_scheduler_t* scheduler,
                               const char* id,
                               bool enable) {
    int rv = -1;
    amxc_htable_it_t* hit = NULL;
    amxp_scheduler_item_t* item = NULL;

    when_null(scheduler, exit);
    when_str_empty(id, exit);

    hit = amxc_htable_get(&scheduler->items, id);
    when_null(hit, exit);
    item = amxc_container_of(hit, amxp_scheduler_item_t, hit);
    when_true_status(enable == item->enabled, exit, rv = 0);

    item->enabled = enable;
    if(!enable) {
        if((item->timer != NULL) && (item->timer->state == amxp_timer_running)) {
            amxp_scheduler_emit(scheduler, item, "stop", 0, false);
            amxp_timer_delete(&item->timer);
        }
    } else {
        amxp_scheduler_check_item(scheduler, item);
        amxp_scheduler_reset_timer(scheduler);
    }

    rv = 0;

exit:
    return rv;
}

amxp_signal_mngr_t* amxp_scheduler_get_sigmngr(amxp_scheduler_t* scheduler) {
    amxp_signal_mngr_t* sigmngr = NULL;
    when_null(scheduler, exit);

    sigmngr = &scheduler->sigmngr;

exit:
    return sigmngr;
}