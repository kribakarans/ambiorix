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
#include <string.h>

#include <amxc/amxc.h>
#include <amxp/amxp_expression.h>

#include <amxp_signal_priv.h>

static amxp_slot_t* amxp_slot_find(const amxp_signal_t* const sig,
                                   amxp_slot_fn_t fn,
                                   amxp_slot_t* start) {
    amxp_slot_t* slot = start;
    amxc_llist_it_t* it = slot == NULL ? amxc_llist_get_first(&sig->slots) :
        amxc_llist_it_get_next(&slot->it);

    while(it != NULL) {
        slot = amxc_llist_it_get_data(it, amxp_slot_t, it);
        if(slot->fn == fn) {
            goto exit;
        }
        it = amxc_llist_it_get_next(&slot->it);
    }

    slot = NULL;

exit:
    return slot;
}

static amxp_signal_t* amxp_slot_find_signal(const amxp_signal_mngr_t* const sig_mngr,
                                            const char* const sig_name) {
    amxc_htable_it_t* hit = NULL;
    const amxc_htable_t* signals = amxp_get_signals(sig_mngr);
    amxp_signal_t* sig = NULL;

    hit = amxc_htable_get(signals, sig_name);
    when_null(hit, exit);

    sig = amxc_htable_it_get_data(hit, amxp_signal_t, hit);

exit:
    return sig;
}

static amxp_slot_t* amxp_slot_new(amxp_slot_fn_t fn,
                                  const char* regexp,
                                  const char* expression,
                                  void* const priv) {
    int retval = -1;
    amxp_slot_t* slot = (amxp_slot_t*) calloc(1, sizeof(amxp_slot_t));
    when_null(slot, exit);
    slot->fn = fn;
    slot->priv = priv;
    slot->regexp = regexp == NULL ? NULL : strdup(regexp);
    if(expression != NULL) {
        when_failed(amxp_expr_new(&slot->expr, expression), exit);
    }
    retval = 0;

exit:
    if((retval != 0) && (slot != NULL)) {
        amxp_expr_delete(&slot->expr);
        free(slot->regexp);
        free(slot);
        slot = NULL;
    }
    return slot;
}

static int amxp_slot_connect_impl(amxp_signal_t* sig,
                                  amxp_slot_fn_t fn,
                                  const char* expression,
                                  void* const priv) {
    int retval = -1;
    amxp_slot_t* slot = NULL;

    slot = amxp_slot_find(sig, fn, NULL);
    if(slot != NULL) {
        if((expression == NULL) && (slot->expr == NULL) && (priv == NULL)) {
            if(slot->deleted) {
                slot->deleted = false;
            }
            retval = 0;
            goto exit;
        }
    }

    slot = amxp_slot_new(fn, NULL, expression, priv);
    when_null(slot, exit);
    amxc_llist_append(&sig->slots, &slot->it);

    retval = 0;

exit:
    return retval;
}

static int amxp_slot_connnect_all_of(amxp_signal_mngr_t* const sigmngr,
                                     amxp_slot_fn_t fn,
                                     const char* const regexp_str,
                                     const char* expression,
                                     void* const priv) {
    int retval = -1;
    bool use_reg_exp = false;
    const amxc_htable_t* signals = amxp_get_signals(sigmngr);

    if((regexp_str != NULL) && (regexp_str[0] != 0)) {
        regex_t regexp;
        retval = regcomp(&regexp, regexp_str, REG_NOSUB | REG_EXTENDED);
        if(retval != 0) {
            goto exit;
        }
        regfree(&regexp);
        use_reg_exp = true;
    }

    if(use_reg_exp) {
        amxp_slot_t* slot = amxp_slot_new(fn, regexp_str, expression, priv);
        if(slot == NULL) {
            retval = -1;
            goto exit;
        }
        amxc_llist_append(&sigmngr->regexp_slots, &slot->it);
        retval = 0;
    } else {
        amxc_htable_for_each(it, signals) {
            amxp_signal_t* sig = amxc_htable_it_get_data(it, amxp_signal_t, hit);
            retval = amxp_slot_connect_impl(sig, fn, expression, priv);
            when_failed(retval, exit);
        }
    }

exit:
    return retval;
}

static int amxp_slot_connnect_all_sigmngrs(const amxc_llist_t* const sigmngrs,
                                           amxp_slot_fn_t fn,
                                           const char* const regexp,
                                           const char* expression,
                                           void* const priv) {
    int retval = -1;

    amxc_llist_for_each(it, sigmngrs) {
        amxp_signal_mngr_t* sigmngr = amxc_llist_it_get_data(it,
                                                             amxp_signal_mngr_t,
                                                             it);
        when_failed(amxp_slot_connnect_all_of(sigmngr,
                                              fn,
                                              regexp,
                                              expression,
                                              priv), exit);
    }

    retval = 0;

exit:
    return retval;
}

static void amxp_slot_delete_all(amxp_signal_t* sig,
                                 amxp_slot_t* slot,
                                 amxp_slot_fn_t fn) {
    while(slot != NULL) {
        slot->deleted = true;
        slot = amxp_slot_find(sig, fn, slot);
    }
}

static void amxp_slot_disconnnect_all_of(const amxp_signal_mngr_t* const sigmngr,
                                         amxp_slot_fn_t fn) {
    const amxc_htable_t* signals = amxp_get_signals(sigmngr);
    amxc_llist_it_t* next = NULL;
    amxc_llist_it_t* regexp_it = NULL;
    amxc_htable_for_each(it, signals) {
        amxp_slot_t* slot = NULL;
        amxp_signal_t* sig = NULL;
        sig = amxc_htable_it_get_data(it, amxp_signal_t, hit);
        slot = amxp_slot_find(sig, fn, NULL);
        amxp_slot_delete_all(sig, slot, fn);
    }

    regexp_it = amxc_llist_get_first(&sigmngr->regexp_slots);
    while(regexp_it) {
        amxp_slot_t* slot = NULL;
        next = amxc_llist_it_get_next(regexp_it);
        slot = amxc_llist_it_get_data(regexp_it, amxp_slot_t, it);
        if(slot->fn == fn) {
            slot->deleted = true;
        }
        regexp_it = next;
    }
}

static void amxp_slot_disconnect_all_sgmngrs(const amxc_llist_t* const sigmngrs,
                                             amxp_slot_fn_t fn) {

    amxc_llist_for_each(it, sigmngrs) {
        amxp_signal_mngr_t* sigmngr = amxc_llist_it_get_data(it,
                                                             amxp_signal_mngr_t,
                                                             it);
        amxp_slot_disconnnect_all_of(sigmngr, fn);
    }
}

static int amxp_slot_disconnect_name(amxp_signal_mngr_t* sig_mngr,
                                     const char* const sig_name,
                                     amxp_slot_fn_t fn) {
    int retval = -1;
    amxp_signal_t* sig = NULL;
    amxp_slot_t* slot = NULL;
    sig_mngr = amxp_get_sigmngr(sig_mngr);

    sig = amxp_slot_find_signal(sig_mngr, sig_name);
    if(sig != NULL) {
        slot = amxp_slot_find(sig, fn, NULL);
    }
    if((sig != NULL) && (slot != NULL)) {
        amxp_slot_delete_all(sig, slot, fn);
        retval = 0;
    } else {
        amxc_llist_it_t* it = amxc_llist_get_first(&sig_mngr->regexp_slots);
        amxc_llist_it_t* next = NULL;
        while(it) {
            regex_t regexp;
            slot = amxc_llist_it_get_data(it, amxp_slot_t, it);
            next = amxc_llist_it_get_next(it);
            regcomp(&regexp, slot->regexp, REG_NOSUB | REG_EXTENDED);
            if((slot->fn == fn) &&
               ( regexec(&regexp, sig_name, 0, NULL, 0) == 0)) {
                slot->deleted = true;
                retval = 0;
            }
            regfree(&regexp);
            it = next;
        }
    }

    return retval;
}

int amxp_slot_connect(amxp_signal_mngr_t* const sig_mngr,
                      const char* const sig_name,
                      const char* const expression,
                      amxp_slot_fn_t fn,
                      void* const priv) {
    int retval = -1;
    amxp_signal_t* sig = NULL;

    when_null(sig_name, exit);
    when_true(*sig_name == 0, exit);
    when_null(fn, exit);

    if(strcmp(sig_name, "*") == 0) {
        if(sig_mngr == NULL) {
            retval = amxp_slot_connect_all(NULL, expression, fn, priv);
        } else {
            retval = amxp_slot_connnect_all_of(sig_mngr, fn, NULL, expression, priv);
        }
        goto exit;
    }

    sig = amxp_slot_find_signal(sig_mngr, sig_name);
    when_null(sig, exit);

    retval = amxp_slot_connect_impl(sig, fn, expression, priv);

exit:
    return retval;
}

int amxp_slot_connect_filtered(amxp_signal_mngr_t* const sig_mngr,
                               const char* const sig_reg_exp,
                               const char* const expression,
                               amxp_slot_fn_t fn,
                               void* const priv) {
    int retval = -1;
    amxp_signal_mngr_t* mngr = NULL;
    when_null(sig_reg_exp, exit);
    when_true(*sig_reg_exp == 0, exit);
    when_null(fn, exit);

    mngr = amxp_get_sigmngr(sig_mngr);
    when_null(mngr, exit);
    retval = amxp_slot_connnect_all_of(mngr,
                                       fn,
                                       sig_reg_exp,
                                       expression,
                                       priv);

exit:
    return retval;
}

int amxp_slot_connect_all(const char* sig_reg_exp,
                          const char* const expression,
                          amxp_slot_fn_t fn,
                          void* const priv) {
    int retval = -1;
    amxc_llist_t* sigmngrs = NULL;
    amxc_llist_t* pending_sigmngrs = NULL;

    when_null(fn, exit);

    amxp_get_sigmngrs(&sigmngrs, &pending_sigmngrs);
    when_failed(amxp_slot_connnect_all_sigmngrs(sigmngrs,
                                                fn,
                                                sig_reg_exp,
                                                expression,
                                                priv), exit);
    when_failed(amxp_slot_connnect_all_sigmngrs(pending_sigmngrs,
                                                fn,
                                                sig_reg_exp,
                                                expression,
                                                priv), exit);
    retval = 0;

exit:
    return retval;
}

int amxp_slot_disconnect(amxp_signal_mngr_t* const sig_mngr,
                         const char* const sig_name,
                         amxp_slot_fn_t fn) {
    int retval = -1;

    when_null(sig_name, exit);
    when_true(*sig_name == 0, exit);
    when_null(fn, exit);

    if(strcmp(sig_name, "*") == 0) {
        if(sig_mngr == NULL) {
            amxp_slot_disconnect_all(fn);
        } else {
            amxp_slot_disconnnect_all_of(sig_mngr, fn);
        }
        retval = 0;
        goto exit;
    }

    retval = amxp_slot_disconnect_name(sig_mngr, sig_name, fn);

exit:
    return retval;
}

int amxp_slot_disconnect_with_priv(amxp_signal_mngr_t* sig_mngr,
                                   amxp_slot_fn_t fn,
                                   void* priv) {
    return amxp_slot_disconnect_signal_with_priv(sig_mngr, NULL, fn, priv);
}

int amxp_slot_disconnect_signal_with_priv(amxp_signal_mngr_t* sig_mngr,
                                          const char* sig_name,
                                          amxp_slot_fn_t fn,
                                          void* priv) {
    int retval = -1;
    amxc_llist_it_t* slot_it = NULL;
    amxc_llist_it_t* next = NULL;
    const amxc_htable_t* signals = NULL;
    sig_mngr = amxp_get_sigmngr(sig_mngr);
    signals = amxp_get_signals(sig_mngr);

    amxc_htable_for_each(it, signals) {
        amxp_signal_t* sig = amxc_htable_it_get_data(it, amxp_signal_t, hit);
        if((sig_name != NULL) && (strcmp(sig_name, sig->name) != 0)) {
            continue;
        }
        slot_it = amxc_llist_get_first(&sig->slots);
        while(slot_it != NULL) {
            amxp_slot_t* slot = NULL;
            next = amxc_llist_it_get_next(slot_it);
            slot = amxc_llist_it_get_data(slot_it, amxp_slot_t, it);
            if(((slot->fn == fn) || (fn == NULL)) &&
               ( slot->priv == priv)) {
                slot->deleted = true;
            }
            slot_it = next;
        }
    }

    if(sig_name == NULL) {
        slot_it = amxc_llist_get_first(&sig_mngr->regexp_slots);
        while(slot_it != NULL) {
            amxp_slot_t* slot = NULL;
            next = amxc_llist_it_get_next(slot_it);
            slot = amxc_llist_it_get_data(slot_it, amxp_slot_t, it);
            if(((slot->fn == fn) || (fn == NULL)) &&
               ( slot->priv == priv)) {
                amxc_llist_it_clean(slot_it, amxp_free_slots);
            }
            slot_it = next;
        }
    }

    retval = 0;

    return retval;
}

void amxp_slot_disconnect_all(amxp_slot_fn_t fn) {
    amxc_llist_t* sigmngrs = NULL;
    amxc_llist_t* pending_sigmngrs = NULL;

    when_null(fn, exit);

    amxp_get_sigmngrs(&sigmngrs, &pending_sigmngrs);
    amxp_slot_disconnect_all_sgmngrs(sigmngrs, fn);
    amxp_slot_disconnect_all_sgmngrs(pending_sigmngrs, fn);

exit:
    return;
}
