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
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <fcntl.h>
#include <unistd.h>
#include <cmocka.h>

#include <amxc/amxc_macros.h>
#include <amxc/amxc_variant.h>
#include <amxc/amxc_lqueue.h>

#include <amxp/amxp_signal.h>
#include <amxp/amxp_slot.h>
#include <amxp_signal_priv.h>

#include "test_signal_slots_recursive.h"

static amxp_signal_t* sig1 = NULL;
static amxp_signal_t* sig2 = NULL;
static amxp_signal_mngr_t* sigmngr = NULL;

static void test_slot_delete_sigmngr(UNUSED const char* const sig_name,
                                     UNUSED const amxc_var_t* const data,
                                     UNUSED void* const priv) {
    if(sig1 != NULL) {
        amxp_sigmngr_delete(&sig1->mngr);
    }
}

static void test_slot_delete_signal(UNUSED const char* const sig_name,
                                    UNUSED const amxc_var_t* const data,
                                    UNUSED void* const priv) {
    amxp_signal_delete(&sig1);
}

static void test_slot1(UNUSED const char* const sig_name,
                       UNUSED const amxc_var_t* const data,
                       UNUSED void* const priv) {
    printf("Test slot 1\n");
    amxp_sigmngr_trigger_signal(NULL, "test:signal2", NULL);
}

static void test_slot_disconnect(UNUSED const char* const sig_name,
                                 UNUSED const amxc_var_t* const data,
                                 UNUSED void* const priv) {
    printf("Test slot disconnect\n");
    amxp_slot_disconnect_all(test_slot1);
}

static void test_slot2(UNUSED const char* const sig_name,
                       UNUSED const amxc_var_t* const data,
                       UNUSED void* const priv) {
    printf("Test slot 2\n");
}

void test_signal_recursive_delete_global_sigmngr(UNUSED void** state) {
    assert_int_equal(amxp_signal_new(NULL, &sig1, "test:signal1"), 0);
    assert_int_equal(amxp_signal_new(NULL, &sig2, "test:signal2"), 0);

    assert_int_equal(amxp_slot_connect(NULL, "test:signal1", NULL, test_slot1, NULL), 0);
    assert_int_equal(amxp_slot_connect(NULL, "test:signal2", NULL, test_slot_delete_sigmngr, NULL), 0);

    amxp_sigmngr_trigger_signal(NULL, "test:signal1", NULL);

    amxp_sigmngr_trigger_signal(NULL, "test:signal1", NULL);
    amxp_sigmngr_trigger_signal(NULL, "test:signal2", NULL);

    // sig1 and sig2 will be deleted due to clean-up of global sigmngr
    // caused by deleting the global sigmngr
    sig1 = NULL;
    sig2 = NULL;
}

void test_signal_recursive_delete_sigmngr(UNUSED void** state) {
    assert_int_equal(amxp_sigmngr_new(&sigmngr), 0);
    assert_int_equal(amxp_signal_new(sigmngr, &sig1, "test:signal1"), 0);
    assert_int_equal(amxp_signal_new(NULL, &sig2, "test:signal2"), 0);

    assert_int_equal(amxp_slot_connect(sigmngr, "test:signal1", NULL, test_slot1, NULL), 0);
    assert_int_equal(amxp_slot_connect(NULL, "test:signal2", NULL, test_slot_delete_sigmngr, NULL), 0);

    amxp_sigmngr_trigger_signal(sigmngr, "test:signal1", NULL);
    sigmngr = NULL; // deleted due to trigger of slot 2 which deletes sigmngr of sig1
    sig1 = NULL;    // deleted due to trigger of slot 2 which deletes sigmngr of sig1

    amxp_sigmngr_trigger_signal(NULL, "test:signal2", NULL);

    amxp_signal_delete(&sig2);
}

void test_signal_recursive_delete_signal(UNUSED void** state) {
    assert_int_equal(amxp_sigmngr_new(&sigmngr), 0);
    assert_int_equal(amxp_signal_new(sigmngr, &sig1, "test:signal1"), 0);
    assert_int_equal(amxp_signal_new(NULL, &sig2, "test:signal2"), 0);

    assert_int_equal(amxp_slot_connect(sigmngr, "test:signal1", NULL, test_slot1, NULL), 0);
    assert_int_equal(amxp_slot_connect(sigmngr, "test:signal1", NULL, test_slot2, NULL), 0);
    assert_int_equal(amxp_slot_connect(NULL, "test:signal2", NULL, test_slot_delete_signal, NULL), 0);

    amxp_sigmngr_trigger_signal(sigmngr, "test:signal1", NULL);

    amxp_signal_delete(&sig2);
    amxp_sigmngr_delete(&sigmngr);
}

void test_signal_slot_disconnect(UNUSED void** state) {
    assert_int_equal(amxp_sigmngr_new(&sigmngr), 0);
    assert_int_equal(amxp_signal_new(sigmngr, &sig1, "test:signal1"), 0);
    assert_int_equal(amxp_signal_new(NULL, &sig2, "test:signal2"), 0);

    assert_int_equal(amxp_slot_connect(sigmngr, "test:signal1", NULL, test_slot_disconnect, NULL), 0);
    assert_int_equal(amxp_slot_connect(sigmngr, "test:signal1", NULL, test_slot1, NULL), 0);
    assert_int_equal(amxp_slot_connect(NULL, "test:signal2", NULL, test_slot_delete_signal, NULL), 0);

    amxp_sigmngr_trigger_signal(sigmngr, "test:signal1", NULL);

    amxp_signal_delete(&sig2);
    amxp_sigmngr_delete(&sigmngr);
}