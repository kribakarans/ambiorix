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
#include <signal.h>
#include <cmocka.h>

#include <amxc/amxc_variant.h>
#include <amxc/amxc_lqueue.h>

#include <amxp/amxp_signal.h>
#include <amxp/amxp_syssig.h>
#include <amxp/amxp_slot.h>
#include <amxp_signal_priv.h>

#include "test_signal_slots_filtered.h"

#include <amxc/amxc_macros.h>
static int slot_trigger_count = 0;
static const char* expected_sig_name = NULL;

static void test_slot1(const char* const sig_name,
                       UNUSED const amxc_var_t* const data,
                       UNUSED void* const priv) {
    assert_string_equal(expected_sig_name, sig_name);
    slot_trigger_count++;
}

static void test_slot2(const char* const sig_name,
                       UNUSED const amxc_var_t* const data,
                       UNUSED void* const priv) {
    assert_string_equal(expected_sig_name, sig_name);
    slot_trigger_count++;
}

void test_slot_connect_regexp(UNUSED void** state) {
    amxp_signal_t* sig = NULL;

    assert_int_equal(amxp_sigmngr_add_signal(NULL, "test:regexp-slot-1"), 0);
    assert_int_equal(amxp_sigmngr_add_signal(NULL, "test:regexp-slot-2"), 0);
    assert_int_equal(amxp_sigmngr_add_signal(NULL, "test:regexp-slot-3"), 0);

    assert_int_equal(amxp_slot_connect_filtered(NULL, "test:.*", NULL, test_slot1, NULL), 0);
    assert_int_equal(amxp_slot_connect_filtered(NULL, "test:.*-2", NULL, test_slot2, NULL), 0);

    slot_trigger_count = 0;
    expected_sig_name = "test:regexp-slot-1";
    amxp_sigmngr_trigger_signal(NULL, expected_sig_name, NULL);
    assert_int_equal(slot_trigger_count, 1);

    slot_trigger_count = 0;
    expected_sig_name = "test:regexp-slot-2";
    amxp_sigmngr_trigger_signal(NULL, expected_sig_name, NULL);
    assert_int_equal(slot_trigger_count, 2);

    sig = amxp_sigmngr_find_signal(NULL, "test:regexp-slot-1");
    amxp_sigmngr_remove_signal(NULL, "test:regexp-slot-1");
    amxp_signal_delete(&sig);

    sig = amxp_sigmngr_find_signal(NULL, "test:regexp-slot-2");
    amxp_sigmngr_remove_signal(NULL, "test:regexp-slot-2");
    amxp_signal_delete(&sig);

    sig = amxp_sigmngr_find_signal(NULL, "test:regexp-slot-3");
    amxp_sigmngr_remove_signal(NULL, "test:regexp-slot-3");
    amxp_signal_delete(&sig);
}

void test_slot_connect_regexp_sigmngr(UNUSED void** state) {
    amxp_signal_mngr_t sigmngr;
    amxp_sigmngr_init(&sigmngr);

    assert_int_equal(amxp_sigmngr_add_signal(&sigmngr, "test:regexp-slot-1"), 0);
    assert_int_equal(amxp_sigmngr_add_signal(&sigmngr, "test:regexp-slot-2"), 0);
    assert_int_equal(amxp_sigmngr_add_signal(&sigmngr, "test:regexp-slot-3"), 0);

    assert_int_equal(amxp_slot_connect_filtered(&sigmngr, "test:.*", NULL, test_slot1, NULL), 0);
    assert_int_equal(amxp_slot_connect_filtered(&sigmngr, "test:.*-2", NULL, test_slot2, NULL), 0);

    slot_trigger_count = 0;
    expected_sig_name = "test:regexp-slot-1";
    amxp_sigmngr_trigger_signal(&sigmngr, expected_sig_name, NULL);
    assert_int_equal(slot_trigger_count, 1);

    slot_trigger_count = 0;
    expected_sig_name = "test:regexp-slot-2";
    amxp_sigmngr_trigger_signal(&sigmngr, expected_sig_name, NULL);
    assert_int_equal(slot_trigger_count, 2);

    amxp_sigmngr_clean(&sigmngr);
}

void test_slot_connect_regexp_invalid_args(UNUSED void** state) {
    assert_int_not_equal(amxp_slot_connect_filtered(NULL, "", NULL, test_slot1, NULL), 0);
    assert_int_not_equal(amxp_slot_connect_filtered(NULL, NULL, NULL, test_slot1, NULL), 0);
    assert_int_not_equal(amxp_slot_connect_filtered(NULL, "test", NULL, NULL, NULL), 0);

    assert_int_not_equal(amxp_slot_connect_filtered(NULL, "test([]]", NULL, test_slot1, NULL), 0);
}

void test_slot_connect_filtered_signals(UNUSED void** state) {
    amxp_signal_mngr_t sigmngr;
    amxc_var_t filter_data;
    amxc_var_t* field1 = NULL;
    amxp_sigmngr_init(&sigmngr);
    amxc_var_init(&filter_data);
    amxc_var_set_type(&filter_data, AMXC_VAR_ID_HTABLE);

    assert_int_equal(amxp_sigmngr_add_signal(&sigmngr, "test:filter-slot-1"), 0);

    assert_int_equal(amxp_slot_connect_filtered(&sigmngr, "test:filter-slot-1", "field1 matches \"test-.*-data\"", test_slot1, NULL), 0);

    field1 = amxc_var_add_key(cstring_t, &filter_data, "field1", "test-extra-test-here-data");
    slot_trigger_count = 0;
    expected_sig_name = "test:filter-slot-1";
    amxp_sigmngr_trigger_signal(&sigmngr, expected_sig_name, &filter_data);
    assert_int_equal(slot_trigger_count, 1);

    amxc_var_set(cstring_t, field1, "not-matching-data");
    slot_trigger_count = 0;
    expected_sig_name = "test:filter-slot-1";
    amxp_sigmngr_trigger_signal(&sigmngr, expected_sig_name, &filter_data);
    assert_int_equal(slot_trigger_count, 0);

    assert_int_equal(amxp_slot_disconnect(&sigmngr, "test:filter-slot-1", test_slot1), 0);

    assert_int_equal(amxp_slot_connect_filtered(&sigmngr, "test:filter-slot-1", "field1 matches \"test-.*-data\"", test_slot1, NULL), 0);

    amxc_var_set_type(&filter_data, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &filter_data, "field2", "test-extra-test-here-data");
    slot_trigger_count = 0;
    expected_sig_name = "test:filter-slot-1";
    amxp_sigmngr_trigger_signal(&sigmngr, expected_sig_name, &filter_data);
    assert_int_equal(slot_trigger_count, 0);

    assert_int_equal(amxp_slot_disconnect(&sigmngr, "*", test_slot1), 0);

    amxp_sigmngr_clean(&sigmngr);
    amxc_var_clean(&filter_data);
}

void test_slot_connect_filtered_signals_invalid_regexp(UNUSED void** state) {
    amxp_signal_mngr_t sigmngr;
    amxc_var_t filter_data;
    amxp_sigmngr_init(&sigmngr);
    amxc_var_init(&filter_data);
    amxc_var_set_type(&filter_data, AMXC_VAR_ID_HTABLE);

    assert_int_equal(amxp_sigmngr_add_signal(&sigmngr, "test:filter-slot-1"), 0);

    assert_int_not_equal(amxp_slot_connect_filtered(&sigmngr, "test-([-data", "field1 matches \".*\"", test_slot1, NULL), 0);

    amxc_var_add_key(cstring_t, &filter_data, "field1", "test-extra-test-here-data");
    slot_trigger_count = 0;
    expected_sig_name = "test:filter-slot-1";
    amxp_sigmngr_trigger_signal(&sigmngr, expected_sig_name, &filter_data);
    assert_int_equal(slot_trigger_count, 0);

    amxp_sigmngr_clean(&sigmngr);
    amxc_var_clean(&filter_data);
}

void test_slot_connect_filtered_signals_invalid_expression(UNUSED void** state) {
    amxp_signal_mngr_t sigmngr;
    amxc_var_t filter_data;

    amxp_sigmngr_init(&sigmngr);
    amxc_var_init(&filter_data);
    amxc_var_set_type(&filter_data, AMXC_VAR_ID_HTABLE);

    assert_int_not_equal(amxp_slot_connect_filtered(&sigmngr, "test:filter-slot-1", "A <> B && !\"Test\"", test_slot1, NULL), 0);

    amxc_var_add_key(cstring_t, &filter_data, "field1", "test-extra-test-here-data");
    slot_trigger_count = 0;
    expected_sig_name = "test:filter-slot-1";
    amxp_sigmngr_trigger_signal(&sigmngr, expected_sig_name, &filter_data);
    assert_int_equal(slot_trigger_count, 0);

    amxp_sigmngr_clean(&sigmngr);
    amxc_var_clean(&filter_data);
}

void test_trigger_not_registered_signal(UNUSED void** state) {
    amxp_signal_mngr_t sigmngr;
    amxp_sigmngr_init(&sigmngr);

    assert_int_equal(amxp_slot_connect_filtered(&sigmngr, "my_.*", NULL, test_slot1, NULL), 0);

    slot_trigger_count = 0;
    expected_sig_name = "my_hallo";
    amxp_sigmngr_trigger_signal(&sigmngr, expected_sig_name, NULL);
    assert_int_equal(slot_trigger_count, 1);

    amxp_sigmngr_clean(&sigmngr);
}