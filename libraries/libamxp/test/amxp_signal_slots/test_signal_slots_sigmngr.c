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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <cmocka.h>

#include <amxc/amxc_variant.h>
#include <amxc/amxc_lqueue.h>

#include <amxp/amxp_signal.h>
#include <amxp/amxp_syssig.h>
#include <amxp/amxp_slot.h>
#include <amxp_signal_priv.h>

#include "test_signal_slots_sigmngr.h"

#include <amxc/amxc_macros.h>
static const char* expected_sig_name = NULL;
static int count1 = 0;
static int count2 = 0;

amxp_signal_mngr_t* my_sigmngr = NULL;

static void test_slot_delete_sigmngr(UNUSED const char* const sig_name,
                                     UNUSED const amxc_var_t* const data,
                                     UNUSED void* const priv) {
    amxp_sigmngr_delete(&my_sigmngr);
}

static void test_delete_sigmngr_and_trigger_slot(UNUSED const char* const sig_name,
                                                 UNUSED const amxc_var_t* const data,
                                                 UNUSED void* const priv) {
    amxp_sigmngr_delete(&my_sigmngr);
    amxp_sigmngr_trigger_signal(my_sigmngr, "test:signal2", NULL);
}

static void test_slot_check_deleted_sigmngr(UNUSED const char* const sig_name,
                                            UNUSED const amxc_var_t* const data,
                                            UNUSED void* const priv) {
    amxp_sigmngr_delete(&my_sigmngr);
}

static void test_slot1(const char* const sig_name,
                       const amxc_var_t* const data,
                       UNUSED void* const priv) {
    if(expected_sig_name != NULL) {
        assert_ptr_not_equal(data, NULL);
        const char* txt = amxc_var_constcast(cstring_t, data);
        assert_int_equal(amxc_var_type_of(data), AMXC_VAR_ID_CSTRING);
        assert_ptr_not_equal(txt, NULL);
        assert_string_equal(sig_name, expected_sig_name);
        assert_string_equal(txt, expected_sig_name);
    } else {
        if(data != NULL) {
            assert_true(amxc_var_is_null(data));
        }
    }
    count1++;
}

static void test_slot2(const char* const sig_name,
                       const amxc_var_t* const data,
                       UNUSED void* const priv) {
    if(expected_sig_name != NULL) {
        assert_ptr_not_equal(data, NULL);
        const char* txt = amxc_var_constcast(cstring_t, data);
        assert_int_equal(amxc_var_type_of(data), AMXC_VAR_ID_CSTRING);
        assert_ptr_not_equal(txt, NULL);
        assert_string_equal(sig_name, expected_sig_name);
        assert_string_equal(txt, expected_sig_name);
    } else {
        if(data != NULL) {
            assert_true(amxc_var_is_null(data));
        }
    }

    count2++;
}

static void test_delete_signal_slot(const char* const sig_name,
                                    UNUSED const amxc_var_t* const data,
                                    UNUSED void* const priv) {
    amxp_signal_t* sig = amxp_sigmngr_find_signal(NULL, sig_name);
    amxp_signal_delete(&sig);
}

static void test_delete_signal_slot2(const char* const sig_name,
                                     UNUSED const amxc_var_t* const data,
                                     UNUSED void* const priv) {
    amxp_signal_t* sig = amxp_sigmngr_find_signal(NULL, sig_name);
    amxp_signal_delete(&sig);
}

static void test_slot_disconnect_all(UNUSED const char* const sig_name,
                                     UNUSED const amxc_var_t* const data,
                                     UNUSED void* const priv) {
    amxp_slot_disconnect_all(test_slot_disconnect_all);
    amxp_slot_disconnect_all(test_slot1);
    amxp_slot_disconnect_all(test_slot2);
}

static void test_slot_remove_signal(const char* const sig_name,
                                    UNUSED const amxc_var_t* const data,
                                    UNUSED void* const priv) {
    amxp_signal_mngr_t* local_sigmngr = (amxp_signal_mngr_t*) priv;
    amxp_signal_t* sig1 = amxp_sigmngr_find_signal(local_sigmngr, sig_name);

    assert_non_null(sig1);
    amxp_sigmngr_remove_signal(local_sigmngr, sig_name);
}

static void test_deferred_func(UNUSED const amxc_var_t* const data,
                               void* const priv) {
    check_expected(priv);
}

static void test_deferred_func_remove_sigmngr(UNUSED const amxc_var_t* const data,
                                              void* const priv) {
    check_expected(priv);
    amxp_sigmngr_delete(&my_sigmngr);
}

static void handle_events(void) {
    printf("Handling events ");
    while(amxp_signal_read() == 0) {
        printf(".");
    }
    printf("\n");
}

void test_sigmngr_new_delete(UNUSED void** state) {
    amxp_signal_mngr_t* local_sigmngr = NULL;
    const amxc_htable_t* lsigs = NULL;
    const amxc_htable_t* gsigs = NULL;
    amxp_signal_t* sig1 = NULL;

    assert_int_not_equal(amxp_sigmngr_new(NULL), 0);
    assert_int_not_equal(amxp_sigmngr_delete(NULL), 0);
    assert_int_not_equal(amxp_sigmngr_delete(&local_sigmngr), 0);

    assert_int_equal(amxp_sigmngr_new(&local_sigmngr), 0);
    assert_ptr_not_equal(local_sigmngr, NULL);

    lsigs = amxp_get_signals(local_sigmngr);
    gsigs = amxp_get_signals(NULL);

    assert_ptr_not_equal(lsigs, gsigs);
    assert_int_equal(amxc_htable_size(lsigs), 0);
    assert_int_equal(amxc_htable_size(gsigs), 6);

    assert_int_equal(amxp_signal_new(local_sigmngr, &sig1, "test:signal1"), 0);
    assert_int_equal(amxc_htable_size(lsigs), 1);
    assert_int_equal(amxc_htable_size(gsigs), 6);

    assert_int_equal(amxp_sigmngr_delete(&local_sigmngr), 0);
    assert_ptr_equal(local_sigmngr, NULL);
}

void test_sigmngr_delete_pending_sigs(UNUSED void** state) {
    amxp_signal_mngr_t* local_sigmngr = NULL;
    amxp_signal_t* sig1 = NULL;
    amxp_signal_t* sig2 = NULL;
    amxp_signal_t* sig3 = NULL;

    assert_int_equal(amxp_sigmngr_new(&local_sigmngr), 0);
    assert_ptr_not_equal(local_sigmngr, NULL);
    assert_int_equal(amxp_signal_new(local_sigmngr, &sig1, "test:signal1"), 0);
    assert_int_equal(amxp_signal_new(local_sigmngr, &sig2, "test:signal2"), 0);
    assert_int_equal(amxp_signal_new(local_sigmngr, &sig3, "test:signal3"), 0);

    assert_int_equal(amxp_slot_connect(local_sigmngr, "test:signal1", NULL, test_slot1, NULL), 0);
    assert_int_equal(amxp_slot_connect(local_sigmngr, "test:signal1", NULL, test_slot2, NULL), 0);
    assert_int_equal(amxp_slot_connect(local_sigmngr, "test:signal2", NULL, test_slot1, NULL), 0);
    assert_int_equal(amxp_slot_connect(local_sigmngr, "test:signal3", NULL, test_slot2, NULL), 0);

    assert_int_equal(amxp_signal_emit(sig1, NULL), 0);
    assert_int_equal(amxp_signal_emit(sig2, NULL), 0);
    assert_int_equal(amxp_signal_emit(sig3, NULL), 0);

    assert_int_equal(amxp_sigmngr_delete(&local_sigmngr), 0);
    assert_ptr_equal(local_sigmngr, NULL);

    assert_int_not_equal(amxp_signal_read(), 0);
}

void test_sigmngr_trigger(UNUSED void** state) {
    amxp_signal_mngr_t* local_sigmngr = NULL;
    amxp_signal_t* sig1 = NULL;
    amxp_signal_t* sig2 = NULL;
    amxp_signal_t* sig3 = NULL;

    assert_int_equal(amxp_sigmngr_new(&local_sigmngr), 0);
    assert_ptr_not_equal(local_sigmngr, NULL);
    assert_int_equal(amxp_signal_new(local_sigmngr, &sig1, "test:signal1"), 0);
    assert_int_equal(amxp_signal_new(local_sigmngr, &sig2, "test:signal2"), 0);
    assert_int_equal(amxp_signal_new(NULL, &sig3, "test:signal3"), 0);

    assert_int_equal(amxp_slot_connect(local_sigmngr, "test:signal1", NULL, test_slot1, NULL), 0);
    assert_int_equal(amxp_slot_connect(local_sigmngr, "test:signal1", NULL, test_slot2, NULL), 0);
    assert_int_equal(amxp_slot_connect(local_sigmngr, "test:signal2", NULL, test_slot1, NULL), 0);
    assert_int_not_equal(amxp_slot_connect(local_sigmngr, "test:signal3", NULL, test_slot2, NULL), 0);
    assert_int_equal(amxp_slot_connect(NULL, "test:signal3", NULL, test_slot2, NULL), 0);

    amxp_sigmngr_trigger_signal(local_sigmngr, NULL, NULL);
    amxp_sigmngr_trigger_signal(local_sigmngr, "", NULL);
    amxp_sigmngr_trigger_signal(local_sigmngr, "not-existing", NULL);

    count1 = 0;
    count2 = 0;

    amxp_sigmngr_trigger_signal(local_sigmngr, "test:signal1", NULL);
    assert_int_equal(count1, 1);
    assert_int_equal(count2, 1);

    amxp_sigmngr_trigger_signal(local_sigmngr, "test:signal2", NULL);
    assert_int_equal(count1, 2);
    assert_int_equal(count2, 1);

    amxp_sigmngr_trigger_signal(NULL, "test:signal3", NULL);
    assert_int_equal(count1, 2);
    assert_int_equal(count2, 2);

    count1 = 0;
    count2 = 0;

    amxp_signal_trigger(sig1, NULL);
    assert_int_equal(count1, 1);
    assert_int_equal(count2, 1);

    amxp_signal_trigger(sig2, NULL);
    assert_int_equal(count1, 2);
    assert_int_equal(count2, 1);

    amxp_signal_trigger(sig3, NULL);
    assert_int_equal(count1, 2);
    assert_int_equal(count2, 2);

    assert_int_equal(amxp_sigmngr_delete(&local_sigmngr), 0);
    assert_ptr_equal(local_sigmngr, NULL);

    amxp_signal_trigger(sig3, NULL);
    assert_int_equal(count1, 2);
    assert_int_equal(count2, 3);

    amxp_signal_delete(&sig3);
}

void test_sigmngr_emit(UNUSED void** state) {
    amxp_signal_mngr_t* local_sigmngr = NULL;
    amxp_signal_t* sig1 = NULL;
    amxp_signal_t* sig2 = NULL;
    amxp_signal_t* sig3 = NULL;
    amxc_var_t var;

    amxc_var_init(&var);

    assert_int_equal(amxp_sigmngr_new(&local_sigmngr), 0);
    assert_ptr_not_equal(local_sigmngr, NULL);
    assert_int_equal(amxp_signal_new(local_sigmngr, &sig1, "test:signal1"), 0);
    assert_int_equal(amxp_signal_new(local_sigmngr, &sig2, "test:signal2"), 0);
    assert_int_equal(amxp_signal_new(NULL, &sig3, "test:signal3"), 0);

    assert_int_equal(amxp_slot_connect(local_sigmngr, "test:signal1", NULL, test_slot1, NULL), 0);
    assert_int_equal(amxp_slot_connect(local_sigmngr, "test:signal1", NULL, test_slot2, NULL), 0);
    assert_int_equal(amxp_slot_connect(local_sigmngr, "test:signal2", NULL, test_slot1, NULL), 0);
    assert_int_not_equal(amxp_slot_connect(local_sigmngr, "test:signal3", NULL, test_slot2, NULL), 0);
    assert_int_equal(amxp_slot_connect(NULL, "test:signal3", NULL, test_slot2, NULL), 0);

    count1 = 0;
    count2 = 0;

    assert_int_not_equal(amxp_signal_fd(), -1);

    assert_int_not_equal(amxp_signal_emit(NULL, NULL), 0);
    assert_int_equal(count1, 0);
    assert_int_equal(count2, 0);
    assert_int_not_equal(amxp_signal_read(), 0);

    expected_sig_name = NULL;
    assert_int_equal(amxp_sigmngr_emit_signal(local_sigmngr, "test:signal1", NULL), 0);
    assert_int_equal(count1, 0);
    assert_int_equal(count2, 0);
    assert_int_equal(amxp_signal_read(), 0);
    assert_int_equal(count1, 1);
    assert_int_equal(count2, 1);

    expected_sig_name = amxp_signal_name(sig1);
    amxc_var_set_cstring_t(&var, expected_sig_name);
    assert_int_equal(amxp_sigmngr_emit_signal(local_sigmngr, "test:signal1", &var), 0);
    assert_int_equal(count1, 1);
    assert_int_equal(count2, 1);
    assert_int_equal(amxp_signal_read(), 0);
    assert_int_equal(count1, 2);
    assert_int_equal(count2, 2);

    expected_sig_name = amxp_signal_name(sig2);
    amxc_var_set_cstring_t(&var, expected_sig_name);
    assert_int_equal(amxp_sigmngr_emit_signal(local_sigmngr, "test:signal2", &var), 0);
    assert_int_equal(count1, 2);
    assert_int_equal(count2, 2);
    assert_int_equal(amxp_signal_read(), 0);
    assert_int_equal(count1, 3);
    assert_int_equal(count2, 2);

    expected_sig_name = amxp_signal_name(sig3);
    amxc_var_set_cstring_t(&var, expected_sig_name);
    assert_int_not_equal(amxp_sigmngr_emit_signal(local_sigmngr, "test:signal3", &var), 0);
    assert_int_equal(amxp_sigmngr_emit_signal(NULL, "test:signal3", &var), 0);
    assert_int_equal(count1, 3);
    assert_int_equal(count2, 2);
    assert_int_equal(amxp_signal_read(), 0);
    assert_int_equal(count1, 3);
    assert_int_equal(count2, 3);

    assert_int_not_equal(amxp_sigmngr_emit_signal(local_sigmngr, NULL, NULL), 0);
    assert_int_not_equal(amxp_sigmngr_emit_signal(local_sigmngr, "", NULL), 0);

    assert_int_equal(amxp_sigmngr_emit_signal(local_sigmngr, "test:signal1", NULL), 0);
    assert_int_equal(amxp_sigmngr_emit_signal(local_sigmngr, "test:signal1", &var), 0);
    assert_int_equal(amxp_sigmngr_emit_signal(local_sigmngr, "test:signal2", &var), 0);
    assert_int_equal(amxp_sigmngr_emit_signal(NULL, "test:signal3", &var), 0);

    amxp_signal_delete(&sig1);
    amxp_signal_delete(&sig2);
    amxp_signal_delete(&sig3);

    assert_int_equal(count1, 3);
    assert_int_equal(count2, 3);
    assert_int_not_equal(amxp_signal_read(), 0);
    assert_int_equal(count1, 3);
    assert_int_equal(count2, 3);

    assert_int_equal(amxp_sigmngr_delete(&local_sigmngr), 0);
    assert_ptr_equal(local_sigmngr, NULL);

    assert_int_not_equal(amxp_signal_read(), 0);

    amxc_var_clean(&var);
}

void test_sigmngr_suspend_resume(UNUSED void** state) {
    amxp_signal_mngr_t* local_sigmngr = NULL;
    amxp_signal_t* sig1 = NULL;
    amxc_var_t var;

    amxc_var_init(&var);

    assert_int_equal(amxp_sigmngr_new(&local_sigmngr), 0);
    assert_ptr_not_equal(local_sigmngr, NULL);
    assert_int_equal(amxp_signal_new(local_sigmngr, &sig1, "test:signal1"), 0);

    assert_int_equal(amxp_slot_connect(local_sigmngr, "test:signal1", NULL, test_slot1, NULL), 0);

    count1 = 0;

    assert_int_not_equal(amxp_signal_fd(), -1);

    expected_sig_name = NULL;
    assert_int_equal(amxp_sigmngr_emit_signal(local_sigmngr, "test:signal1", NULL), 0);
    assert_int_equal(count1, 0);
    assert_int_equal(amxp_signal_read(), 0);
    assert_int_equal(count1, 1);

    expected_sig_name = NULL;
    assert_int_equal(amxp_sigmngr_suspend(local_sigmngr), 0);
    assert_int_equal(amxp_sigmngr_emit_signal(local_sigmngr, "test:signal1", NULL), 0);
    assert_int_not_equal(amxp_signal_read(), 0);
    assert_int_equal(count1, 1);
    expected_sig_name = NULL;
    assert_int_equal(amxp_sigmngr_resume(local_sigmngr), 0);
    assert_int_equal(amxp_signal_read(), 0);
    assert_int_equal(count1, 2);

    assert_int_equal(amxp_sigmngr_delete(&local_sigmngr), 0);
    assert_ptr_equal(local_sigmngr, NULL);

    amxc_var_clean(&var);
}

void test_sigmngr_connect_all(UNUSED void** state) {
    amxc_var_t var;
    amxp_signal_mngr_t* local_sigmngr = NULL;
    amxp_signal_t* sig1 = NULL;
    amxp_signal_t* sig2 = NULL;
    amxp_signal_t* sig3 = NULL;

    amxc_var_init(&var);

    assert_int_equal(amxp_sigmngr_new(&local_sigmngr), 0);
    assert_ptr_not_equal(local_sigmngr, NULL);
    assert_int_equal(amxp_signal_new(local_sigmngr, &sig1, "test:signal1"), 0);
    assert_int_equal(amxp_signal_new(local_sigmngr, &sig2, "test:signal2"), 0);
    assert_int_equal(amxp_signal_new(NULL, &sig3, "test:signal3"), 0);

    assert_int_equal(amxp_slot_connect(local_sigmngr, "*", NULL, test_slot1, NULL), 0);
    assert_int_equal(amxp_slot_connect(NULL, "test:signal3", NULL, test_slot2, NULL), 0);

    count1 = 0;
    count2 = 0;

    expected_sig_name = amxp_signal_name(sig1);
    amxc_var_set_cstring_t(&var, expected_sig_name);
    amxp_signal_trigger(sig1, &var);
    assert_int_equal(count1, 1);
    assert_int_equal(count2, 0);

    expected_sig_name = amxp_signal_name(sig2);
    amxc_var_set_cstring_t(&var, expected_sig_name);
    amxp_signal_trigger(sig2, &var);
    assert_int_equal(count1, 2);
    assert_int_equal(count2, 0);

    expected_sig_name = amxp_signal_name(sig3);
    amxc_var_set_cstring_t(&var, expected_sig_name);
    amxp_signal_trigger(sig3, &var);
    assert_int_equal(count1, 2);
    assert_int_equal(count2, 1);

    assert_int_equal(amxp_sigmngr_delete(&local_sigmngr), 0);
    assert_ptr_equal(local_sigmngr, NULL);
    amxp_signal_delete(&sig3);
    amxc_var_clean(&var);
}

void test_sigmngr_connect_all2(UNUSED void** state) {
    amxc_var_t var;
    amxp_signal_mngr_t* local_sigmngr = NULL;
    amxp_signal_t* sig1 = NULL;
    amxp_signal_t* sig2 = NULL;
    amxp_signal_t* sig3 = NULL;

    amxc_var_init(&var);

    assert_int_equal(amxp_sigmngr_new(&local_sigmngr), 0);
    assert_ptr_not_equal(local_sigmngr, NULL);
    assert_int_equal(amxp_signal_new(local_sigmngr, &sig1, "test:signal1"), 0);
    assert_int_equal(amxp_signal_new(local_sigmngr, &sig2, "test:signal2"), 0);
    assert_int_equal(amxp_signal_new(NULL, &sig3, "test:signal3"), 0);

    assert_int_equal(amxp_slot_connect(NULL, "*", NULL, test_slot1, NULL), 0);

    count1 = 0;
    count2 = 0;

    expected_sig_name = amxp_signal_name(sig1);
    amxc_var_set_cstring_t(&var, expected_sig_name);
    amxp_signal_trigger(sig1, &var);
    assert_int_equal(count1, 1);
    assert_int_equal(count2, 0);

    expected_sig_name = amxp_signal_name(sig2);
    amxc_var_set_cstring_t(&var, expected_sig_name);
    amxp_signal_trigger(sig2, &var);
    assert_int_equal(count1, 2);
    assert_int_equal(count2, 0);

    expected_sig_name = amxp_signal_name(sig3);
    amxc_var_set_cstring_t(&var, expected_sig_name);
    amxp_signal_trigger(sig3, &var);
    assert_int_equal(count1, 3);
    assert_int_equal(count2, 0);

    assert_int_equal(amxp_sigmngr_delete(&local_sigmngr), 0);
    assert_ptr_equal(local_sigmngr, NULL);
    amxp_signal_delete(&sig3);
    amxc_var_clean(&var);
}

void test_sigmngr_disconnect_all_1(UNUSED void** state) {
    amxc_var_t var;
    amxp_signal_mngr_t* local_sigmngr = NULL;
    amxp_signal_t* sig1 = NULL;
    amxp_signal_t* sig2 = NULL;
    amxp_signal_t* sig3 = NULL;

    amxc_var_init(&var);

    assert_int_equal(amxp_sigmngr_new(&local_sigmngr), 0);
    assert_ptr_not_equal(local_sigmngr, NULL);
    assert_int_equal(amxp_signal_new(local_sigmngr, &sig1, "test:signal1"), 0);
    assert_int_equal(amxp_signal_new(local_sigmngr, &sig2, "test:signal2"), 0);
    assert_int_equal(amxp_signal_new(NULL, &sig3, "test:signal3"), 0);

    assert_int_equal(amxp_slot_connect(local_sigmngr, "test:signal1", NULL, test_slot1, NULL), 0);
    assert_int_equal(amxp_slot_connect(local_sigmngr, "test:signal2", NULL, test_slot1, NULL), 0);
    assert_int_equal(amxp_slot_connect(NULL, "test:signal3", NULL, test_slot1, NULL), 0);
    assert_int_equal(amxp_slot_connect(local_sigmngr, "test:signal1", NULL, test_slot2, NULL), 0);
    assert_int_equal(amxp_slot_connect(local_sigmngr, "test:signal2", NULL, test_slot2, NULL), 0);
    assert_int_equal(amxp_slot_connect(NULL, "test:signal3", NULL, test_slot2, NULL), 0);

    count1 = 0;
    count2 = 0;

    expected_sig_name = amxp_signal_name(sig1);
    amxc_var_set_cstring_t(&var, expected_sig_name);
    amxp_signal_trigger(sig1, &var);
    assert_int_equal(count1, 1);
    assert_int_equal(count2, 1);

    expected_sig_name = amxp_signal_name(sig2);
    amxc_var_set_cstring_t(&var, expected_sig_name);
    amxp_signal_trigger(sig2, &var);
    assert_int_equal(count1, 2);
    assert_int_equal(count2, 2);

    expected_sig_name = amxp_signal_name(sig3);
    amxc_var_set_cstring_t(&var, expected_sig_name);
    amxp_signal_trigger(sig3, &var);
    assert_int_equal(count1, 3);
    assert_int_equal(count2, 3);

    assert_int_equal(amxp_slot_disconnect(local_sigmngr, "*", test_slot1), 0);

    expected_sig_name = amxp_signal_name(sig1);
    amxc_var_set_cstring_t(&var, expected_sig_name);
    amxp_signal_trigger(sig1, &var);
    assert_int_equal(count1, 3);
    assert_int_equal(count2, 4);

    expected_sig_name = amxp_signal_name(sig2);
    amxc_var_set_cstring_t(&var, expected_sig_name);
    amxp_signal_trigger(sig2, &var);
    assert_int_equal(count1, 3);
    assert_int_equal(count2, 5);

    expected_sig_name = amxp_signal_name(sig3);
    amxc_var_set_cstring_t(&var, expected_sig_name);
    amxp_signal_trigger(sig3, &var);
    assert_int_equal(count1, 4);
    assert_int_equal(count2, 6);

    assert_int_equal(amxp_sigmngr_delete(&local_sigmngr), 0);
    assert_ptr_equal(local_sigmngr, NULL);
    amxp_signal_delete(&sig3);
    amxc_var_clean(&var);
}

void test_sigmngr_disconnect_all_2(UNUSED void** state) {
    amxc_var_t var;
    amxp_signal_mngr_t* local_sigmngr = NULL;
    amxp_signal_t* sig1 = NULL;
    amxp_signal_t* sig2 = NULL;
    amxp_signal_t* sig3 = NULL;

    amxc_var_init(&var);

    assert_int_equal(amxp_sigmngr_new(&local_sigmngr), 0);
    assert_ptr_not_equal(local_sigmngr, NULL);
    assert_int_equal(amxp_signal_new(local_sigmngr, &sig1, "test:signal1"), 0);
    assert_int_equal(amxp_signal_new(local_sigmngr, &sig2, "test:signal2"), 0);
    assert_int_equal(amxp_signal_new(NULL, &sig3, "test:signal3"), 0);

    assert_int_equal(amxp_slot_connect(local_sigmngr, "test:signal1", NULL, test_slot1, NULL), 0);
    assert_int_equal(amxp_slot_connect(local_sigmngr, "test:signal2", NULL, test_slot1, NULL), 0);
    assert_int_equal(amxp_slot_connect(NULL, "test:signal3", NULL, test_slot1, NULL), 0);
    assert_int_equal(amxp_slot_connect(local_sigmngr, "test:signal1", NULL, test_slot2, NULL), 0);
    assert_int_equal(amxp_slot_connect(local_sigmngr, "test:signal2", NULL, test_slot2, NULL), 0);
    assert_int_equal(amxp_slot_connect(NULL, "test:signal3", NULL, test_slot2, NULL), 0);

    count1 = 0;
    count2 = 0;

    expected_sig_name = amxp_signal_name(sig1);
    amxc_var_set_cstring_t(&var, expected_sig_name);
    amxp_signal_trigger(sig1, &var);
    assert_int_equal(count1, 1);
    assert_int_equal(count2, 1);

    expected_sig_name = amxp_signal_name(sig2);
    amxc_var_set_cstring_t(&var, expected_sig_name);
    amxp_signal_trigger(sig2, &var);
    assert_int_equal(count1, 2);
    assert_int_equal(count2, 2);

    expected_sig_name = amxp_signal_name(sig3);
    amxc_var_set_cstring_t(&var, expected_sig_name);
    amxp_signal_trigger(sig3, &var);
    assert_int_equal(count1, 3);
    assert_int_equal(count2, 3);

    amxp_slot_disconnect_all(test_slot1);

    expected_sig_name = amxp_signal_name(sig1);
    amxc_var_set_cstring_t(&var, expected_sig_name);
    amxp_signal_trigger(sig1, &var);
    assert_int_equal(count1, 3);
    assert_int_equal(count2, 4);

    expected_sig_name = amxp_signal_name(sig2);
    amxc_var_set_cstring_t(&var, expected_sig_name);
    amxp_signal_trigger(sig2, &var);
    assert_int_equal(count1, 3);
    assert_int_equal(count2, 5);

    expected_sig_name = amxp_signal_name(sig3);
    amxc_var_set_cstring_t(&var, expected_sig_name);
    amxp_signal_trigger(sig3, &var);
    assert_int_equal(count1, 3);
    assert_int_equal(count2, 6);

    assert_int_equal(amxp_sigmngr_delete(&local_sigmngr), 0);
    assert_ptr_equal(local_sigmngr, NULL);
    amxp_signal_delete(&sig3);
    amxc_var_clean(&var);

    amxp_slot_disconnect_all(NULL);
}

void test_sigmngr_add_remove_signal(UNUSED void** state) {
    amxp_signal_mngr_t* local_sigmngr = NULL;
    amxp_signal_t* sig = NULL;

    assert_int_equal(amxp_sigmngr_new(&local_sigmngr), 0);

    assert_int_equal(amxp_sigmngr_add_signal(NULL, "test:signal1"), 0);
    assert_int_not_equal(amxp_sigmngr_add_signal(local_sigmngr, NULL), 0);
    assert_int_not_equal(amxp_sigmngr_add_signal(local_sigmngr, ""), 0);

    assert_int_equal(amxp_sigmngr_add_signal(local_sigmngr, "test:signal1"), 0);
    assert_int_equal(amxp_sigmngr_add_signal(local_sigmngr, "test:signal2"), 0);
    assert_int_equal(amxp_sigmngr_add_signal(local_sigmngr, "test:signal3"), 0);

    sig = amxp_sigmngr_find_signal(NULL, "test:signal1");
    assert_int_equal(amxp_sigmngr_remove_signal(NULL, "test:signal1"), 0);
    amxp_signal_delete(&sig);

    assert_int_not_equal(amxp_sigmngr_remove_signal(local_sigmngr, NULL), 0);
    assert_int_not_equal(amxp_sigmngr_remove_signal(local_sigmngr, ""), 0);

    assert_int_not_equal(amxp_sigmngr_remove_signal(local_sigmngr, "test:signal4"), 0);

    sig = amxp_sigmngr_find_signal(local_sigmngr, "test:signal1");
    assert_int_equal(amxp_sigmngr_remove_signal(local_sigmngr, "test:signal1"), 0);
    amxp_signal_delete(&sig);

    sig = amxp_sigmngr_find_signal(local_sigmngr, "test:signal2");
    assert_int_equal(amxp_sigmngr_remove_signal(local_sigmngr, "test:signal2"), 0);
    amxp_signal_delete(&sig);

    sig = amxp_sigmngr_find_signal(local_sigmngr, "test:signal3");
    assert_int_equal(amxp_sigmngr_remove_signal(local_sigmngr, "test:signal3"), 0);
    amxp_signal_delete(&sig);

    assert_int_not_equal(amxp_sigmngr_remove_signal(local_sigmngr, "test:signal1"), 0);

    assert_int_equal(amxp_sigmngr_delete(&local_sigmngr), 0);
    assert_ptr_equal(local_sigmngr, NULL);
}

void test_sigmngr_crash_connect_not_existing_signal(UNUSED void** state) {
    amxp_signal_mngr_t* local_sigmngr = NULL;

    assert_int_equal(amxp_sigmngr_new(&local_sigmngr), 0);
    assert_int_equal(amxp_sigmngr_add_signal(local_sigmngr, "mysignal"), 0);
    assert_int_not_equal(amxp_slot_connect(local_sigmngr, "anothersignal", NULL, test_slot1, NULL), 0);
    printf("%p\n", local_sigmngr);
    assert_int_equal(amxp_sigmngr_delete(&local_sigmngr), 0);
}

void test_sigmngr_find_signal(UNUSED void** state) {
    amxp_signal_mngr_t* local_sigmngr = NULL;

    assert_int_equal(amxp_sigmngr_new(&local_sigmngr), 0);

    assert_int_equal(amxp_sigmngr_add_signal(local_sigmngr, "test:signal1"), 0);
    assert_int_equal(amxp_sigmngr_add_signal(local_sigmngr, "test:signal2"), 0);
    assert_int_equal(amxp_sigmngr_add_signal(local_sigmngr, "test:signal3"), 0);

    assert_ptr_not_equal(amxp_sigmngr_find_signal(local_sigmngr, "test:signal1"), NULL);
    assert_ptr_not_equal(amxp_sigmngr_find_signal(local_sigmngr, "test:signal3"), NULL);

    assert_ptr_equal(amxp_sigmngr_find_signal(local_sigmngr, ""), NULL);
    assert_ptr_equal(amxp_sigmngr_find_signal(local_sigmngr, NULL), NULL);

    assert_int_equal(amxp_sigmngr_delete(&local_sigmngr), 0);
}

void test_signal_has_slots(UNUSED void** state) {
    amxp_signal_mngr_t* local_sigmngr = NULL;
    amxp_signal_t* sig1 = NULL;

    assert_int_equal(amxp_sigmngr_new(&local_sigmngr), 0);

    assert_int_equal(amxp_signal_new(local_sigmngr, &sig1, "test:signal1"), 0);
    assert_int_equal(amxp_signal_disconnect_all(sig1), 0);

    assert_false(amxp_signal_has_slots(sig1));
    assert_false(amxp_signal_has_slots(NULL));

    assert_int_equal(amxp_slot_connect(local_sigmngr, "test:signal1", NULL, test_slot1, NULL), 0);
    assert_true(amxp_signal_has_slots(sig1));

    assert_int_equal(amxp_sigmngr_delete(&local_sigmngr), 0);
}

void test_slot_disconnect_priv(UNUSED void** state) {
    amxp_signal_mngr_t* local_sigmngr = NULL;
    amxp_signal_t* sig1 = NULL;
    const char* priv = "PRIV DATA";

    assert_int_equal(amxp_sigmngr_new(&local_sigmngr), 0);

    assert_int_equal(amxp_signal_new(local_sigmngr, &sig1, "test:signal1"), 0);

    assert_int_equal(amxp_slot_connect(local_sigmngr, "test:signal1", NULL, test_slot1, (void*) priv), 0);

    count1 = 0;
    expected_sig_name = NULL;
    amxp_signal_trigger(sig1, NULL);
    assert_int_equal(count1, 1);

    assert_int_equal(amxp_slot_disconnect_with_priv(local_sigmngr, NULL, (void*) priv), 0);

    count1 = 0;
    expected_sig_name = NULL;
    amxp_signal_trigger(sig1, NULL);
    assert_int_equal(count1, 0);

    assert_int_equal(amxp_slot_connect(local_sigmngr, "test:signal1", NULL, test_slot1, (void*) priv), 0);

    count1 = 0;
    expected_sig_name = NULL;
    amxp_signal_trigger(sig1, NULL);
    assert_int_equal(count1, 1);

    assert_int_equal(amxp_slot_disconnect_with_priv(local_sigmngr, test_slot1, NULL), 0);
    assert_int_equal(amxp_slot_disconnect_with_priv(local_sigmngr, test_slot2, (void*) priv), 0);

    count1 = 0;
    expected_sig_name = NULL;
    amxp_signal_trigger(sig1, NULL);
    assert_int_equal(count1, 1);

    assert_int_equal(amxp_slot_disconnect_with_priv(local_sigmngr, test_slot1, (void*) priv), 0);
    count1 = 0;
    expected_sig_name = NULL;
    amxp_signal_trigger(sig1, NULL);
    assert_int_equal(count1, 0);

    assert_int_equal(amxp_sigmngr_delete(&local_sigmngr), 0);
}

void test_does_not_crash_with_rogue_signal(UNUSED void** state) {
    amxp_signal_t* sig1 = calloc(1, sizeof(amxp_signal_t));

    amxp_signal_trigger(sig1, NULL);
    assert_int_not_equal(amxp_signal_emit(sig1, NULL), 0);

    free(sig1);
}

void test_sigmngr_disable(UNUSED void** state) {
    amxp_signal_mngr_t* local_sigmngr = NULL;
    amxp_signal_t* sig1 = NULL;

    assert_int_equal(amxp_sigmngr_new(&local_sigmngr), 0);
    assert_ptr_not_equal(local_sigmngr, NULL);
    assert_int_equal(amxp_signal_new(local_sigmngr, &sig1, "test:signal1"), 0);

    assert_int_equal(amxp_slot_connect(local_sigmngr, "test:signal1", NULL, test_slot1, NULL), 0);

    count1 = 0;
    expected_sig_name = NULL;
    assert_int_equal(amxp_sigmngr_enable(local_sigmngr, false), 0);
    amxp_signal_trigger(sig1, NULL);
    assert_int_not_equal(amxp_signal_emit(sig1, NULL), 0);
    assert_int_equal(count1, 0);

    assert_int_equal(amxp_sigmngr_enable(local_sigmngr, true), 0);
    assert_int_not_equal(amxp_signal_read(), 0);
    amxp_signal_trigger(sig1, NULL);
    assert_int_equal(count1, 1);

    assert_int_equal(amxp_sigmngr_delete(&local_sigmngr), 0);
    assert_ptr_equal(local_sigmngr, NULL);
}

void test_sigmngr_trigger_unknown_signal_should_not_segfault(UNUSED void** state) {
    amxp_sigmngr_trigger_signal(NULL, "NotExisiting", NULL);
}

void test_removing_signal_in_slot(UNUSED void** state) {
    amxp_signal_mngr_t* local_sigmngr = NULL;
    amxp_signal_t* sig1 = NULL;

    assert_int_equal(amxp_sigmngr_new(&local_sigmngr), 0);
    assert_ptr_not_equal(local_sigmngr, NULL);
    assert_int_equal(amxp_signal_new(local_sigmngr, &sig1, "test:signal1"), 0);

    assert_int_equal(amxp_slot_connect(local_sigmngr, "test:signal1", NULL, test_slot_remove_signal, local_sigmngr), 0);
    amxp_signal_trigger(sig1, NULL);

    sig1 = amxp_sigmngr_find_signal(local_sigmngr, "test:signal1");
    assert_null(sig1);

    assert_int_equal(amxp_sigmngr_delete(&local_sigmngr), 0);
}

void test_delete_sigmngr_in_slot(UNUSED void** state) {
    amxp_signal_t* sig1 = NULL;

    assert_int_equal(amxp_sigmngr_new(&my_sigmngr), 0);
    assert_ptr_not_equal(my_sigmngr, NULL);
    assert_int_equal(amxp_signal_new(my_sigmngr, &sig1, "test:signal1"), 0);

    assert_int_equal(amxp_slot_connect(my_sigmngr, "test:signal1", NULL, test_slot_delete_sigmngr, NULL), 0);
    assert_int_equal(amxp_slot_connect(my_sigmngr, "test:signal1", NULL, test_slot_check_deleted_sigmngr, NULL), 0);
    amxp_signal_trigger(sig1, NULL);

    sig1 = NULL;
    assert_null(my_sigmngr);

    assert_int_equal(amxp_sigmngr_new(&my_sigmngr), 0);
    assert_ptr_not_equal(my_sigmngr, NULL);
    assert_int_equal(amxp_signal_new(my_sigmngr, &sig1, "test:signal1"), 0);

    assert_int_equal(amxp_slot_connect(my_sigmngr, "test:signal1", NULL, test_slot_delete_sigmngr, NULL), 0);
    assert_int_equal(amxp_slot_connect(my_sigmngr, "test:signal1", NULL, test_slot_check_deleted_sigmngr, NULL), 0);
    amxp_sigmngr_trigger_signal(my_sigmngr, "test:signal1", NULL);
}

void test_deferred_call(UNUSED void** state) {
    amxc_var_t var_data;
    char* data = calloc(1, 10);
    strcpy(data, "abcdefg");

    amxc_var_init(&var_data);
    amxc_var_set(cstring_t, &var_data, "Hello");

    assert_int_equal(amxp_sigmngr_new(&my_sigmngr), 0);
    assert_ptr_not_equal(my_sigmngr, NULL);

    expect_memory(test_deferred_func, priv, data, 10);
    assert_int_equal(amxp_sigmngr_deferred_call(my_sigmngr, test_deferred_func, NULL, (void*) data), 0);
    handle_events();

    expect_memory(test_deferred_func, priv, data, 10);
    assert_int_equal(amxp_sigmngr_deferred_call(my_sigmngr, test_deferred_func, &var_data, (void*) data), 0);
    handle_events();

    free(data);
    amxc_var_clean(&var_data);
    assert_int_equal(amxp_sigmngr_delete(&my_sigmngr), 0);
}

void test_deferred_call_delete_sigmngr(UNUSED void** state) {
    char* data = calloc(1, 10);
    strcpy(data, "abcdefg");

    assert_int_equal(amxp_sigmngr_new(&my_sigmngr), 0);
    assert_ptr_not_equal(my_sigmngr, NULL);

    expect_memory(test_deferred_func_remove_sigmngr, priv, data, 10);
    assert_int_equal(amxp_sigmngr_deferred_call(my_sigmngr, test_deferred_func_remove_sigmngr, NULL, (void*) data), 0);
    handle_events();

    free(data);
    assert_null(my_sigmngr);
}

void test_can_disconnect_in_slot(UNUSED void** state) {
    amxp_signal_mngr_t* local_sigmngr = NULL;
    amxp_signal_t* sig1 = NULL;
    const char* priv = "PRIV DATA";

    assert_int_equal(amxp_sigmngr_new(&local_sigmngr), 0);

    assert_int_equal(amxp_signal_new(local_sigmngr, &sig1, "test:signal1"), 0);

    assert_int_equal(amxp_slot_connect(local_sigmngr, "test:signal1", NULL, test_slot1, NULL), 0);
    assert_int_equal(amxp_slot_connect(local_sigmngr, "test:signal1", NULL, test_slot_disconnect_all, (void*) priv), 0);
    assert_int_equal(amxp_slot_connect(local_sigmngr, "test:signal1", NULL, test_slot2, NULL), 0);

    count1 = 0;
    count2 = 0;
    expected_sig_name = NULL;
    amxp_signal_trigger(sig1, NULL);
    assert_int_equal(count1, 1);
    assert_int_equal(count2, 0);

    count1 = 0;
    count2 = 0;
    expected_sig_name = NULL;
    amxp_signal_trigger(sig1, NULL);
    assert_int_equal(count1, 0);
    assert_int_equal(count2, 0);

    assert_int_equal(amxp_sigmngr_delete(&local_sigmngr), 0);
}

void test_can_delete_signal_in_slot(UNUSED void** state) {
    amxp_signal_t* sig1 = NULL;
    amxp_signal_t* sig2 = NULL;

    assert_int_equal(amxp_signal_new(NULL, &sig1, "test:signal1"), 0);
    assert_int_equal(amxp_signal_new(NULL, &sig2, "test:signal2"), 0);

    assert_int_equal(amxp_slot_connect(NULL, "test:signal1", NULL, test_delete_signal_slot, NULL), 0);
    assert_int_equal(amxp_slot_connect(NULL, "test:signal2", NULL, test_delete_signal_slot, NULL), 0);

    amxp_signal_trigger(sig1, NULL);
    amxp_signal_trigger(sig2, NULL);
}

void test_can_delete_signal_in_multiple_slots(UNUSED void** state) {
    amxp_signal_t* sig1 = NULL;
    amxp_signal_t* sig2 = NULL;

    assert_int_equal(amxp_signal_new(NULL, &sig1, "test:signal1"), 0);
    assert_int_equal(amxp_signal_new(NULL, &sig2, "test:signal2"), 0);

    assert_int_equal(amxp_slot_connect(NULL, "test:signal1", NULL, test_delete_signal_slot, NULL), 0);
    assert_int_equal(amxp_slot_connect(NULL, "test:signal1", NULL, test_delete_signal_slot2, NULL), 0);
    assert_int_equal(amxp_slot_connect(NULL, "test:signal2", NULL, test_delete_signal_slot, NULL), 0);
    assert_int_equal(amxp_slot_connect_filtered(NULL, "^test:.*$", NULL, test_delete_signal_slot, NULL), 0);

    amxp_sigmngr_trigger_signal(NULL, "test:signal1", NULL);
    amxp_sigmngr_trigger_signal(NULL, "test:signal2", NULL);
}

void test_can_trigger_non_registered_signal(UNUSED void** state) {
    assert_int_equal(amxp_slot_connect_filtered(NULL, "^test:.*", NULL, test_slot1, NULL), 0);

    count1 = 0;
    count2 = 0;
    expected_sig_name = NULL;

    amxp_sigmngr_trigger_signal(NULL, "test:signal1", NULL);
    assert_int_equal(count1, 1);
    assert_int_equal(count2, 0);

    amxp_slot_disconnect_all(test_slot1);
}

void test_delete_sigmngr_in_regexp_slot(UNUSED void** state) {
    assert_int_equal(amxp_sigmngr_new(&my_sigmngr), 0);
    assert_ptr_not_equal(my_sigmngr, NULL);
    assert_int_equal(amxp_slot_connect_filtered(my_sigmngr, "^test:.*", NULL, test_slot_delete_sigmngr, NULL), 0);

    amxp_sigmngr_trigger_signal(my_sigmngr, "test:signal1", NULL);
    assert_null(my_sigmngr);
}

void test_delete_sigmngr_in_slot_and_trigger_slot(UNUSED void** state) {
    amxp_signal_t* sig1 = NULL;
    amxp_signal_t* sig2 = NULL;

    assert_int_equal(amxp_sigmngr_new(&my_sigmngr), 0);
    assert_ptr_not_equal(my_sigmngr, NULL);

    assert_int_equal(amxp_signal_new(my_sigmngr, &sig1, "test:signal1"), 0);
    assert_int_equal(amxp_signal_new(my_sigmngr, &sig2, "test:signal2"), 0);

    assert_int_equal(amxp_slot_connect(my_sigmngr, "test:signal1", NULL, test_delete_sigmngr_and_trigger_slot, NULL), 0);
    assert_int_equal(amxp_slot_connect(my_sigmngr, "test:signal2", NULL, test_slot2, NULL), 0);

    amxp_sigmngr_trigger_signal(my_sigmngr, "test:signal1", NULL);
    assert_null(my_sigmngr);
}
