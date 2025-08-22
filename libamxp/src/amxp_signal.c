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
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>

#include <amxc/amxc.h>
#include <amxp/amxp.h>

#include "amxp_signal_priv.h"

typedef struct _signal_ctrl {
    int sigpipe[2];
    amxp_signal_t* sigall;
    amxc_llist_t sigmngrs;
    amxc_llist_t pending_sigmngrs;
    pthread_mutex_t mutex;
} signal_ctrl_t;

typedef struct _signal_queue_item {
    char* sig_name;
    amxc_var_t sig_data;
    amxc_lqueue_it_t it;
    amxp_signal_mngr_t* sig_mngr;
    amxp_deferred_fn_t fn;
    void* priv;
} signal_queue_item_t;

static signal_ctrl_t amxp_sigctrl;
static amxp_signal_mngr_t amxp_sigmngr;

static int amxp_signal_queue_lock(void) {
    return pthread_mutex_lock(&amxp_sigctrl.mutex);
}

static int amxp_signal_queue_unlock(void) {
    return pthread_mutex_unlock(&amxp_sigctrl.mutex);
}

void amxp_free_slots(amxc_llist_it_t* it) {
    amxp_slot_t* slot = amxc_llist_it_get_data(it, amxp_slot_t, it);
    amxc_llist_it_take(it);
    amxp_expr_delete(&slot->expr);
    free(slot->regexp);
    free(slot);
}

static void amxp_free_signals(UNUSED const char* key,
                              amxc_htable_it_t* it) {
    amxp_signal_t* signal = amxc_htable_it_get_data(it, amxp_signal_t, hit);
    amxp_signal_disconnect_all(signal);
    free(signal);
}

static void amxp_free_queued_signals(amxc_lqueue_it_t* it) {
    signal_queue_item_t* item = amxc_llist_it_get_data(it, signal_queue_item_t, it);
    amxc_var_clean(&item->sig_data);
    free(item->sig_name);
    free(item);
}

static int amxp_signal_queue(const amxp_signal_t* const signal,
                             const amxc_var_t* const data) {
    int retval = -1;
    signal_queue_item_t* item = (signal_queue_item_t*) calloc(1, sizeof(signal_queue_item_t));
    when_null(item, exit);
    item->sig_name = (char*) calloc(1, strlen(signal->name) + 1);
    when_null(item->sig_name, exit);

    amxc_var_init(&item->sig_data);
    if(data != NULL) {
        when_failed(amxc_var_copy(&item->sig_data, data), exit);
    }
    strcpy(item->sig_name, signal->name);
    amxc_lqueue_add(&signal->mngr->signal_queue, &item->it);

    if(!signal->mngr->suspended) {
        amxc_llist_append(&amxp_sigctrl.pending_sigmngrs, &signal->mngr->it);
    }

    retval = 0;

exit:
    if((retval != 0) && (item != NULL)) {
        free(item->sig_name);
        amxc_var_clean(&item->sig_data);
        free(item);
    }
    return retval;
}

static int amxp_deferred_queue(amxp_signal_mngr_t* sigmngr,
                               amxp_deferred_fn_t fn,
                               const amxc_var_t* const data,
                               void* priv) {
    int retval = -1;
    signal_queue_item_t* item = (signal_queue_item_t*) calloc(1, sizeof(signal_queue_item_t));
    when_null(item, exit);

    amxc_var_init(&item->sig_data);
    if(data != NULL) {
        when_failed(amxc_var_copy(&item->sig_data, data), exit);
    }
    item->fn = fn;
    item->priv = priv;
    amxc_lqueue_add(&sigmngr->signal_queue, &item->it);

    if(!sigmngr->suspended) {
        amxc_llist_append(&amxp_sigctrl.pending_sigmngrs, &sigmngr->it);
    }

    retval = 0;

exit:
    if((retval != 0) && (item != NULL)) {
        amxc_var_clean(&item->sig_data);
        free(item);
    }
    return retval;
}

static signal_queue_item_t* amxp_signal_dequeue(void) {
    signal_queue_item_t* item = NULL;
    amxp_signal_mngr_t* sig_mngr = NULL;
    amxc_lqueue_it_t* sig_it = NULL;

    amxc_llist_it_t* it = amxc_llist_get_first(&amxp_sigctrl.pending_sigmngrs);
    when_null(it, exit);

    sig_mngr = amxc_llist_it_get_data(it, amxp_signal_mngr_t, it);
    amxc_llist_append(&amxp_sigctrl.pending_sigmngrs, &sig_mngr->it);

    sig_it = amxc_lqueue_remove(&sig_mngr->signal_queue);
    item = amxc_llist_it_get_data(sig_it, signal_queue_item_t, it);

    item->sig_mngr = sig_mngr;

    if(amxc_lqueue_is_empty(&sig_mngr->signal_queue)) {
        amxc_llist_append(&amxp_sigctrl.sigmngrs, it);
    }

exit:
    return item;
}

static int amxp_signal_create_pipe(void) {
    int flags = 0;
    int retval = pipe(amxp_sigctrl.sigpipe);
    when_true(retval != 0, exit);

    flags = fcntl(amxp_sigctrl.sigpipe[0], F_GETFL, 0);
    when_true(flags < 0, exit);
    when_true(fcntl(amxp_sigctrl.sigpipe[0], F_SETFL, flags | O_NONBLOCK) < 0, exit);
    when_true(fcntl(amxp_sigctrl.sigpipe[0], F_SETFD, amxp_sigctrl.sigpipe[0] | FD_CLOEXEC) < 0, exit);
    when_true(fcntl(amxp_sigctrl.sigpipe[1], F_SETFD, amxp_sigctrl.sigpipe[1] | FD_CLOEXEC) < 0, exit);

    retval = 0;

exit:
    if(retval != 0) {
        if(amxp_sigctrl.sigpipe[0] != -1) {
            close(amxp_sigctrl.sigpipe[0]);
            close(amxp_sigctrl.sigpipe[1]);
        }
        amxp_sigctrl.sigpipe[0] = -1;
        amxp_sigctrl.sigpipe[1] = -1;
    }
    return retval;
}

static void amxp_slot_trigger(const amxp_slot_t* const slot,
                              const char* name,
                              const amxc_var_t* const data) {
    if(slot->expr != NULL) {
        amxp_expr_status_t status = amxp_expr_status_ok;
        if((data == NULL) || amxp_expr_eval_var(slot->expr, data, &status)) {
            slot->fn(name, data, slot->priv);
        }
    } else {
        slot->fn(name, data, slot->priv);
    }
}

static void amxp_sigmngr_trigger_regexp(amxp_signal_mngr_t* sig_mngr,
                                        const char* name,
                                        const amxc_var_t* const data) {
    amxp_signal_t* signal = amxp_sigmngr_find_signal(sig_mngr, name);
    if(signal != NULL) {
        signal->triggered = true;
    }

    sig_mngr->triggered = true;
    amxc_llist_for_each(it, (&sig_mngr->regexp_slots)) {
        regex_t regexp;
        amxp_slot_t* slot = amxc_llist_it_get_data(it, amxp_slot_t, it);
        if(slot->deleted) {
            continue;
        }
        regcomp(&regexp, slot->regexp, REG_NOSUB | REG_EXTENDED);
        if(regexec(&regexp, name, 0, NULL, 0) == 0) {
            amxp_slot_trigger(slot, name, data);
        }
        regfree(&regexp);
        if(sig_mngr->deleted || !sig_mngr->enabled) {
            break;
        }
    }

    if(signal != NULL) {
        signal->triggered = false;
    }
    sig_mngr->triggered = false;
}

static void amxp_signal_garbage_collect(amxp_signal_t* signal) {
    when_null(signal, exit);

    if(signal->mngr == NULL) {
        amxc_htable_it_clean(&signal->hit, amxp_free_signals);
    } else {
        amxc_llist_for_each(it, (&signal->slots)) {
            amxp_slot_t* slot = amxc_llist_it_get_data(it, amxp_slot_t, it);
            if(slot->deleted) {
                amxc_llist_it_clean(it, amxp_free_slots);
            }
        }
    }

exit:
    return;
}

static void amxp_sigmngr_garbage_collect(amxp_signal_mngr_t* sig_mngr) {
    when_null(sig_mngr, exit);

    if(sig_mngr->deleted && (sig_mngr != &amxp_sigmngr)) {
        amxp_sigmngr_delete(&sig_mngr);
    } else {
        sig_mngr->deleted = false;
        amxc_htable_for_each(hit, &sig_mngr->signals) {
            amxp_signal_t* sig = amxc_container_of(hit, amxp_signal_t, hit);
            amxp_signal_garbage_collect(sig);
        }
        amxc_llist_for_each(it, &sig_mngr->regexp_slots) {
            amxp_slot_t* slot = amxc_llist_it_get_data(it, amxp_slot_t, it);
            if(slot->deleted) {
                amxc_llist_it_clean(it, amxp_free_slots);
            }
        }
    }

exit:
    return;
}

amxp_signal_mngr_t* amxp_get_sigmngr(amxp_signal_mngr_t* sig_mngr) {
    return (sig_mngr == NULL) ? &amxp_sigmngr : sig_mngr;
}

void amxp_get_sigmngrs(amxc_llist_t** sigmngrs,
                       amxc_llist_t** pending_sigmngrs) {
    *sigmngrs = &amxp_sigctrl.sigmngrs;
    *pending_sigmngrs = &amxp_sigctrl.pending_sigmngrs;
}

const amxc_htable_t* amxp_get_signals(const amxp_signal_mngr_t* sig_mngr) {
    sig_mngr = (sig_mngr == NULL) ? &amxp_sigmngr : sig_mngr;
    return &sig_mngr->signals;
}

int amxp_sigmngr_new(amxp_signal_mngr_t** sig_mngr) {
    int retval = -1;
    when_null(sig_mngr, exit);

    *sig_mngr = (amxp_signal_mngr_t*) calloc(1, sizeof(amxp_signal_mngr_t));
    when_null(sig_mngr, exit);

    retval = amxp_sigmngr_init((*sig_mngr));

exit:
    if((retval != 0) &&
       (sig_mngr != NULL) &&
       (*sig_mngr != NULL)) {
        free(*sig_mngr);
        *sig_mngr = NULL;
    }
    return retval;
}

int amxp_sigmngr_delete(amxp_signal_mngr_t** sig_mngr) {
    int retval = -1;

    when_null(sig_mngr, exit);
    when_null(*sig_mngr, exit);

    if((*sig_mngr)->triggered) {
        (*sig_mngr)->deleted = true;
        amxc_htable_for_each(hit, &(*sig_mngr)->signals) {
            amxp_signal_t* sig = amxc_container_of(hit, amxp_signal_t, hit);
            if(sig != amxp_sigctrl.sigall) {
                sig->mngr = NULL;
            }
        }
    } else {
        amxp_sigmngr_clean((*sig_mngr));
        if(*sig_mngr != &amxp_sigmngr) {
            free(*sig_mngr);
        }
    }

    *sig_mngr = NULL;
    retval = 0;

exit:
    return retval;
}

int amxp_sigmngr_init(amxp_signal_mngr_t* sig_mngr) {
    int retval = -1;
    when_null(sig_mngr, exit);

    amxp_signal_queue_lock();

    amxc_llist_it_init(&sig_mngr->it);
    amxc_lqueue_init(&sig_mngr->signal_queue);
    when_false_status(amxc_htable_init(&sig_mngr->signals, 20) == 0, exit, amxp_signal_queue_unlock());
    amxc_llist_init(&sig_mngr->regexp_slots);
    amxc_llist_append(&amxp_sigctrl.sigmngrs, &sig_mngr->it);
    sig_mngr->enabled = true;
    sig_mngr->deleted = false;
    sig_mngr->triggered = false;
    sig_mngr->suspended = false;

    amxp_signal_queue_unlock();

    retval = 0;

exit:
    if((retval != 0) &&
       (sig_mngr != NULL)) {
        amxc_htable_clean(&sig_mngr->signals, NULL);
    }
    return retval;
}

int amxp_sigmngr_clean(amxp_signal_mngr_t* sig_mngr) {
    int retval = -1;
    amxc_llist_it_t* it = NULL;
    char buffer[1];

    when_null(sig_mngr, exit);

    amxp_signal_queue_lock();

    amxc_llist_it_take(&sig_mngr->it);
    it = amxc_lqueue_remove(&sig_mngr->signal_queue);
    while(it) {
        amxp_free_queued_signals(it);
        when_true_status(read(amxp_sigctrl.sigpipe[0], buffer, 1) == -1, exit, amxp_signal_queue_unlock());
        it = amxc_lqueue_remove(&sig_mngr->signal_queue);
    }
    amxc_llist_clean(&sig_mngr->regexp_slots, amxp_free_slots);
    amxc_htable_clean(&sig_mngr->signals, amxp_free_signals);

    amxp_signal_queue_unlock();

    retval = 0;

exit:

    return retval;
}

int amxp_sigmngr_add_signal(amxp_signal_mngr_t* const sig_mngr,
                            const char* name) {
    int retval = -1;
    amxp_signal_t* signal = NULL;
    amxp_signal_mngr_t* mngr = (sig_mngr == NULL) ? &amxp_sigmngr : sig_mngr;

    when_null(name, exit);
    when_true(*name == 0, exit)

    retval = amxp_signal_new(mngr, &signal, name);

exit:
    return retval;
}

int amxp_sigmngr_remove_signal(amxp_signal_mngr_t* const sig_mngr,
                               const char* name) {
    int retval = -1;
    amxp_signal_t* signal = NULL;
    amxp_signal_mngr_t* mngr = (sig_mngr == NULL) ? &amxp_sigmngr : sig_mngr;
    amxc_htable_it_t* hit = NULL;

    amxp_signal_queue_lock();

    when_null(name, exit);
    when_true(*name == 0, exit)

    hit = amxc_htable_get(&mngr->signals, name);
    when_null(hit, exit);

    signal = amxc_htable_it_get_data(hit, amxp_signal_t, hit);
    amxc_htable_it_clean(hit, NULL);
    amxp_signal_disconnect_all(signal);
    signal->mngr = NULL;

    retval = 0;

exit:
    amxp_signal_queue_unlock();
    return retval;
}

amxp_signal_t* amxp_sigmngr_find_signal(const amxp_signal_mngr_t* const sig_mngr,
                                        const char* name) {
    amxp_signal_t* signal = NULL;
    amxc_htable_it_t* hit = NULL;
    const amxp_signal_mngr_t* mngr = (sig_mngr == NULL) ? &amxp_sigmngr : sig_mngr;

    when_null(name, exit);
    when_true(*name == 0, exit)

    hit = amxc_htable_get(&mngr->signals, name);
    when_null(hit, exit);
    signal = amxc_htable_it_get_data(hit, amxp_signal_t, hit);

exit:
    return signal;
}

void amxp_sigmngr_trigger_signal(amxp_signal_mngr_t* const sig_mngr,
                                 const char* name,
                                 const amxc_var_t* const data) {
    amxp_signal_t* signal = NULL;
    amxp_signal_mngr_t* mngr = (sig_mngr == NULL) ? &amxp_sigmngr : sig_mngr;

    when_null(name, exit);
    when_true(*name == 0, exit);
    when_true(mngr->suspended, exit);

    signal = amxp_sigmngr_find_signal(mngr, name);
    if(signal != NULL) {
        amxp_signal_trigger(signal, data);
    } else {
        amxp_sigmngr_trigger_regexp(mngr, name, data);
        amxp_sigmngr_garbage_collect(mngr);
    }

exit:
    return;
}

int amxp_sigmngr_emit_signal(const amxp_signal_mngr_t* const sig_mngr,
                             const char* name,
                             const amxc_var_t* const data) {

    int retval = -1;
    amxp_signal_t* signal = NULL;
    const amxp_signal_mngr_t* mngr = (sig_mngr == NULL) ? &amxp_sigmngr : sig_mngr;
    amxc_htable_it_t* hit = NULL;

    when_null(name, exit);
    when_true(*name == 0, exit)

    hit = amxc_htable_get(&mngr->signals, name);
    when_null(hit, exit);

    signal = amxc_htable_it_get_data(hit, amxp_signal_t, hit);
    retval = amxp_signal_emit(signal, data);

exit:
    return retval;
}

int amxp_sigmngr_deferred_call(amxp_signal_mngr_t* const sig_mngr,
                               amxp_deferred_fn_t fn,
                               const amxc_var_t* const data,
                               void* priv) {
    int retval = -1;
    int write_length = 0;
    amxp_signal_mngr_t* mngr = (sig_mngr == NULL) ? &amxp_sigmngr : sig_mngr;

    when_null(fn, exit);

    amxp_signal_queue_lock();

    if(!mngr->suspended) {
        write_length = write(amxp_sigctrl.sigpipe[1], "S", 1);
        when_true_status(write_length != 1, exit, amxp_signal_queue_unlock());
    }

    retval = amxp_deferred_queue(mngr, fn, data, priv);

    amxp_signal_queue_unlock();

exit:
    return retval;
}

int amxp_sigmngr_enable(amxp_signal_mngr_t* const sig_mngr,
                        bool enable) {
    int retval = 0;
    amxp_signal_mngr_t* mngr = (sig_mngr == NULL) ? &amxp_sigmngr : sig_mngr;

    mngr->enabled = enable;

    return retval;
}

int amxp_sigmngr_suspend(amxp_signal_mngr_t* const sig_mngr) {
    int retval = -1;
    char buffer[1];
    amxp_signal_mngr_t* mngr = (sig_mngr == NULL) ? &amxp_sigmngr : sig_mngr;

    when_true(mngr->suspended, exit);

    amxp_signal_queue_lock();

    amxc_llist_iterate(it, &mngr->signal_queue) {
        when_true_status(read(amxp_sigctrl.sigpipe[0], buffer, 1) == -1, exit, amxp_signal_queue_unlock());
    }

    amxc_llist_append(&amxp_sigctrl.sigmngrs, &mngr->it);
    mngr->suspended = true;

    amxp_signal_queue_unlock();

    retval = 0;

exit:
    return retval;
}

int amxp_sigmngr_resume(amxp_signal_mngr_t* const sig_mngr) {
    int retval = -1;
    int write_length = 0;
    amxp_signal_mngr_t* mngr = (sig_mngr == NULL) ? &amxp_sigmngr : sig_mngr;

    when_false(mngr->suspended, exit);
    mngr->suspended = false;

    amxp_signal_queue_lock();

    amxc_llist_iterate(it, &mngr->signal_queue) {
        write_length = write(amxp_sigctrl.sigpipe[1], "S", 1);
        when_true_status(write_length != 1, exit, amxp_signal_queue_unlock());
    }

    amxc_llist_append(&amxp_sigctrl.pending_sigmngrs, &mngr->it);

    amxp_signal_queue_unlock();

    retval = 0;

exit:
    return retval;
}

int amxp_signal_new(amxp_signal_mngr_t* sig_mngr,
                    amxp_signal_t** signal,
                    const char* name) {
    int retval = -1;
    amxc_htable_it_t* hit = NULL;
    when_null(signal, exit);
    when_not_null(*signal, exit);
    when_null(name, exit);
    when_true(*name == 0, exit)

    sig_mngr = (sig_mngr == NULL) ? &amxp_sigmngr : sig_mngr;
    when_null(sig_mngr->it.llist, exit);

    hit = amxc_htable_get(&sig_mngr->signals, name);
    when_not_null(hit, exit);

    *signal = (amxp_signal_t*) calloc(1, sizeof(amxp_signal_t));
    when_null(*signal, exit);
    (*signal)->mngr = sig_mngr;

    amxp_signal_queue_lock();

    amxc_htable_it_init(&(*signal)->hit);
    amxc_llist_init(&(*signal)->slots);
    if(amxc_htable_insert(&sig_mngr->signals, name, &(*signal)->hit) == 0) {
        const char* n = amxc_htable_it_get_key(&(*signal)->hit);
        when_null_status(n, exit, amxp_signal_queue_unlock());
        (*signal)->name = n;
        amxc_llist_for_each(it, (&amxp_sigctrl.sigall->slots)) {
            amxp_slot_t* slot = amxc_llist_it_get_data(it, amxp_slot_t, it);
            if(slot->deleted) {
                continue;
            }
            amxp_slot_connect(sig_mngr,
                              name,
                              slot->expr == NULL ? NULL : slot->expr->expression,
                              slot->fn,
                              slot->priv);
        }

        retval = 0;
    }

    amxp_signal_queue_unlock();

exit:
    return retval;
}

int amxp_signal_delete(amxp_signal_t** const signal) {
    int retval = -1;
    when_null(signal, exit);
    when_null(*signal, exit);

    amxp_signal_queue_lock();

    if(!(*signal)->triggered) {
        amxc_htable_it_clean(&(*signal)->hit, amxp_free_signals);
    } else {
        (*signal)->mngr = NULL;
    }
    *signal = NULL;

    amxp_signal_queue_unlock();

    retval = 0;

exit:
    return retval;
}

void amxp_signal_trigger(amxp_signal_t* const signal,
                         const amxc_var_t* const data) {
    amxp_signal_mngr_t* sig_mngr = NULL;
    char* sig_name = NULL;
    static uint32_t recurse = 0;

    when_null(signal, exit);
    when_null(signal->mngr, exit);
    sig_mngr = signal->mngr;
    when_false(sig_mngr->enabled, exit);
    when_true(sig_mngr->deleted, exit);
    when_true(sig_mngr->suspended, exit);

    recurse++;
    sig_name = strdup(signal->name);
    sig_mngr->triggered = true;
    signal->triggered = true;
    amxc_llist_for_each(it, (&signal->slots)) {
        amxp_slot_t* slot = amxc_llist_it_get_data(it, amxp_slot_t, it);
        // slots that are marked for deletion should not be called anymore
        if(slot->deleted) {
            continue;
        }
        // always call the remaining slots (if not marked as deleted), even
        // if the signal is removed (signal->mngr == NULL)
        amxp_slot_trigger(slot, sig_name, data);

    }
    signal->triggered = false;
    sig_mngr->triggered = false;

    amxp_sigmngr_trigger_regexp(sig_mngr, sig_name, data);
    recurse--;

    if(recurse == 0) {
        // it is safe now to clean-up memory
        // garbage collect all deleted slots or the signal
        amxp_signal_garbage_collect(signal);
    }

    free(sig_name);

exit:
    if(recurse == 0) {
        // it is safe now to clean-up memory
        // garbage collect all deleted slots, signals or the signal manager
        amxp_sigmngr_garbage_collect(sig_mngr);
    }
    return;
}

int amxp_signal_emit(const amxp_signal_t* const signal,
                     const amxc_var_t* const data) {
    int retval = -1;
    int write_length = 0;
    amxp_signal_mngr_t* sig_mngr = NULL;
    when_null(signal, exit);
    when_null(signal->mngr, exit);
    sig_mngr = signal->mngr;

    when_false(sig_mngr->enabled, exit);
    when_true(sig_mngr->deleted, exit);

    amxp_signal_queue_lock();

    if(!sig_mngr->suspended) {
        write_length = write(amxp_sigctrl.sigpipe[1], "S", 1);
        when_true_status(write_length != 1, exit, amxp_signal_queue_unlock());
    }

    retval = amxp_signal_queue(signal, data);

    amxp_signal_queue_unlock();

exit:
    return retval;
}

int amxp_signal_read(void) {
    int retval = -1;
    int read_length = 0;
    char buffer[1];
    signal_queue_item_t* item = NULL;
    amxc_htable_it_t* hit = NULL;
    amxp_signal_t* signal = NULL;

    amxp_signal_queue_lock();

    read_length = read(amxp_sigctrl.sigpipe[0], buffer, 1);
    when_true_status(read_length < 1, exit, amxp_signal_queue_unlock());
    item = amxp_signal_dequeue();
    when_null_status(item, exit, amxp_signal_queue_unlock());

    amxp_signal_queue_unlock();

    if(item->sig_name != NULL) {
        hit = amxc_htable_get(&item->sig_mngr->signals, item->sig_name);
        signal = amxc_container_of(hit, amxp_signal_t, hit);
        when_null(signal, exit);
        amxp_signal_trigger(signal, &item->sig_data);
    } else if(item->fn != NULL) {
        item->fn(&item->sig_data, item->priv);
    }

    retval = 0;

exit:
    if(item != NULL) {
        amxc_var_clean(&item->sig_data);
        free(item->sig_name);
        free(item);
    }
    return retval;
}

int amxp_signal_disconnect_all(amxp_signal_t* const signal) {
    int retval = -1;
    when_null(signal, exit);

    amxc_llist_clean(&signal->slots, amxp_free_slots);
    retval = 0;

exit:
    return retval;
}

const char* amxp_signal_name(const amxp_signal_t* const signal) {
    return signal ? signal->name : NULL;
}

bool amxp_signal_has_slots(const amxp_signal_t* const signal) {
    bool retval = false;

    when_null(signal, exit);
    retval = !amxc_llist_is_empty(&signal->slots);
    when_false(retval, exit);

    retval = false;
    amxc_llist_iterate(it, &signal->slots) {
        amxp_slot_t* slot = amxc_container_of(it, amxp_slot_t, it);
        if(!slot->deleted) {
            retval = true;
            break;
        }
    }

exit:
    return retval;
}

int amxp_signal_fd(void) {
    return amxp_sigctrl.sigpipe[0];
}

CONSTRUCTOR_LVL(101) static void amxp_signals_init(void) {
    amxp_signal_create_pipe();
    amxc_llist_init(&amxp_sigctrl.sigmngrs);
    amxc_lqueue_init(&amxp_sigctrl.pending_sigmngrs);
    amxp_sigmngr_init(&amxp_sigmngr);
    amxp_signal_new(&amxp_sigmngr, &amxp_sigctrl.sigall, "*");
    pthread_mutex_init(&amxp_sigctrl.mutex, NULL);

    amxp_sigmngr_add_signal(NULL, "connection-added");
    amxp_sigmngr_add_signal(NULL, "connection-wait-write");
    amxp_sigmngr_add_signal(NULL, "listen-added");
    amxp_sigmngr_add_signal(NULL, "listen-deleted");
    amxp_sigmngr_add_signal(NULL, "connection-deleted");
}

DESTRUCTOR_LVL(101) static void amxp_signals_cleanup(void) {
    amxp_sigmngr_clean(&amxp_sigmngr);
    if(amxp_sigctrl.sigpipe[0] != -1) {
        close(amxp_sigctrl.sigpipe[0]);
    }
    if(amxp_sigctrl.sigpipe[1] != -1) {
        close(amxp_sigctrl.sigpipe[1]);
    }
    pthread_mutex_destroy(&amxp_sigctrl.mutex);
}
