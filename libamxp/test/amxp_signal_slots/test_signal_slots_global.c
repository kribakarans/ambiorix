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

#include <amxc/amxc_variant.h>
#include <amxc/amxc_lqueue.h>

#include <amxp/amxp_signal.h>
#include <amxp/amxp_slot.h>
#include <amxp_signal_priv.h>

#include "test_signal_slots_global.h"

static const char* expected_sig_name = NULL;
static int count1 = 0;
static int count2 = 0;

#include <amxc/amxc_macros.h>
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

void test_signal_new(UNUSED void** state) {
    const amxc_htable_t* sigs = amxp_get_signals(NULL);
    amxp_signal_t* sig1 = NULL;
    amxp_signal_t* sig2 = NULL;
    amxp_signal_t* sig3 = NULL;
    assert_ptr_not_equal(sigs, NULL);
    size_t nr_sigs = amxc_htable_size(sigs);

    assert_int_not_equal(amxp_signal_new(NULL, NULL, NULL), 0);
    assert_int_not_equal(amxp_signal_new(NULL, &sig1, NULL), 0);
    assert_int_not_equal(amxp_signal_new(NULL, NULL, "test:dummy"), 0);
    assert_int_not_equal(amxp_signal_new(NULL, &sig1, ""), 0);
    assert_int_equal(amxc_htable_size(sigs), nr_sigs + 0);

    assert_int_equal(amxp_signal_new(NULL, &sig1, "test:signal1"), 0);
    assert_int_equal(amxc_htable_size(sigs), nr_sigs + 1);

    assert_int_not_equal(amxp_signal_new(NULL, &sig1, "test:signal2"), 0);
    assert_int_equal(amxc_htable_size(sigs), nr_sigs + 1);

    assert_int_not_equal(amxp_signal_new(NULL, &sig2, "test:signal1"), 0);
    assert_int_equal(amxc_htable_size(sigs), nr_sigs + 1);

    assert_int_equal(amxp_signal_new(NULL, &sig2, "test:signal2"), 0);
    assert_int_equal(amxc_htable_size(sigs), nr_sigs + 2);

    assert_int_equal(amxp_signal_new(NULL, &sig3, "test:signal3"), 0);
    assert_int_equal(amxc_htable_size(sigs), nr_sigs + 3);

    amxp_signal_delete(&sig1);
    amxp_signal_delete(&sig2);
    amxp_signal_delete(&sig3);

    assert_int_equal(amxc_htable_size(sigs), nr_sigs + 0);
}

void test_signal_delete(UNUSED void** state) {
    const amxc_htable_t* sigs = amxp_get_signals(NULL);
    amxp_signal_t* sig1 = NULL;
    amxp_signal_t* sig2 = NULL;
    amxp_signal_t* sig3 = NULL;
    assert_ptr_not_equal(sigs, NULL);
    size_t nr_sigs = amxc_htable_size(sigs);

    assert_int_equal(amxp_signal_new(NULL, &sig1, "test:signal1"), 0);
    assert_int_equal(amxp_signal_new(NULL, &sig2, "test:signal2"), 0);
    assert_int_equal(amxp_signal_new(NULL, &sig3, "test:signal3"), 0);
    assert_int_equal(amxc_htable_size(sigs), nr_sigs + 3);

    assert_int_not_equal(amxp_signal_delete(NULL), 0);
    assert_int_equal(amxc_htable_size(sigs), nr_sigs + 3);
    assert_int_equal(amxp_signal_delete(&sig1), 0);
    assert_int_equal(amxc_htable_size(sigs), nr_sigs + 2);
    assert_int_not_equal(amxp_signal_delete(&sig1), 0);
    assert_int_equal(amxc_htable_size(sigs), nr_sigs + 2);

    amxp_signal_delete(&sig2);
    assert_int_equal(amxc_htable_size(sigs), nr_sigs + 1);
    amxp_signal_delete(&sig3);
    assert_int_equal(amxc_htable_size(sigs), nr_sigs + 0);

}

void test_slot_connect(UNUSED void** state) {
    const amxc_htable_t* sigs = amxp_get_signals(NULL);
    amxp_signal_t* sig1 = NULL;
    amxp_signal_t* sig3 = NULL;
    assert_ptr_not_equal(sigs, NULL);

    assert_int_equal(amxp_signal_new(NULL, &sig1, "test:signal1"), 0);
    assert_int_equal(amxp_signal_new(NULL, &sig3, "test:signal3"), 0);

    assert_int_not_equal(amxp_slot_connect(NULL, "not_existing", NULL, test_slot1, NULL), 0);
    assert_int_not_equal(amxp_slot_connect(NULL, NULL, NULL, test_slot1, NULL), 0);
    assert_int_not_equal(amxp_slot_connect(NULL, "", NULL, test_slot1, NULL), 0);
    assert_int_not_equal(amxp_slot_connect(NULL, "test:signal1", NULL, NULL, NULL), 0);

    assert_int_equal(amxp_slot_connect(NULL, "test:signal1", NULL, test_slot1, NULL), 0);
    assert_int_equal(amxc_llist_size(&sig1->slots), 1);
    assert_int_equal(amxp_slot_connect(NULL, "test:signal1", NULL, test_slot1, NULL), 0);
    assert_int_equal(amxc_llist_size(&sig1->slots), 1);
    assert_int_equal(amxp_slot_connect(NULL, "test:signal1", NULL, test_slot2, NULL), 0);
    assert_int_equal(amxc_llist_size(&sig1->slots), 2);
    assert_int_equal(amxp_slot_connect(NULL, "test:signal1", NULL, test_slot2, NULL), 0);
    assert_int_equal(amxc_llist_size(&sig1->slots), 2);

    assert_int_equal(amxc_llist_size(&sig3->slots), 0);
    assert_int_equal(amxp_slot_connect(NULL, "test:signal3", NULL, test_slot1, NULL), 0);
    assert_int_equal(amxc_llist_size(&sig3->slots), 1);
    assert_int_equal(amxp_slot_connect(NULL, "test:signal3", NULL, test_slot2, NULL), 0);
    assert_int_equal(amxc_llist_size(&sig3->slots), 2);
    assert_int_equal(amxc_llist_size(&sig1->slots), 2);

    amxp_signal_delete(&sig1);
    amxp_signal_delete(&sig3);
}

void test_slot_connect_all(UNUSED void** state) {
    const amxc_htable_t* sigs = amxp_get_signals(NULL);
    amxp_signal_t* sig1 = NULL;
    amxp_signal_t* sig2 = NULL;
    amxp_signal_t* sig3 = NULL;
    assert_ptr_not_equal(sigs, NULL);

    assert_int_equal(amxp_signal_new(NULL, &sig1, "test:signal1"), 0);
    assert_int_equal(amxp_signal_new(NULL, &sig2, "test:signal2"), 0);

    assert_int_not_equal(amxp_slot_connect_all(NULL, NULL, NULL, NULL), 0);
    assert_int_equal(amxp_slot_connect_all(NULL, NULL, test_slot1, NULL), 0);
    assert_int_equal(amxc_llist_size(&sig1->slots), 1);
    assert_int_equal(amxc_llist_size(&sig2->slots), 1);

    assert_int_equal(amxp_signal_new(NULL, &sig3, "test:signal3"), 0);
    assert_int_equal(amxc_llist_size(&sig3->slots), 1);

    assert_int_equal(amxp_slot_connect_all(NULL, NULL, test_slot2, NULL), 0);
    assert_int_equal(amxc_llist_size(&sig1->slots), 2);
    assert_int_equal(amxc_llist_size(&sig2->slots), 2);
    assert_int_equal(amxc_llist_size(&sig3->slots), 2);
    amxp_signal_delete(&sig3);
    assert_int_equal(amxc_llist_size(&sig1->slots), 2);
    assert_int_equal(amxc_llist_size(&sig2->slots), 2);
    assert_int_equal(amxp_signal_new(NULL, &sig3, "test:signal3"), 0);
    assert_int_equal(amxc_llist_size(&sig3->slots), 2);

    amxp_slot_disconnect_all(test_slot1);
    amxp_slot_disconnect_all(test_slot2);

    amxp_signal_trigger(sig1, NULL);
    amxp_signal_trigger(sig2, NULL);
    amxp_signal_trigger(sig3, NULL);
    assert_int_equal(amxc_llist_size(&sig1->slots), 0);
    assert_int_equal(amxc_llist_size(&sig2->slots), 0);

    assert_int_equal(amxp_slot_connect(NULL, "*", NULL, test_slot1, NULL), 0);
    assert_int_equal(amxc_llist_size(&sig1->slots), 1);
    assert_int_equal(amxc_llist_size(&sig2->slots), 1);
    assert_int_equal(amxc_llist_size(&sig3->slots), 1);

    amxp_slot_disconnect_all(test_slot1);

    amxp_signal_delete(&sig1);
    amxp_signal_delete(&sig2);
    amxp_signal_delete(&sig3);
}

void test_signal_trigger(UNUSED void** state) {
    amxc_var_t var;
    const amxc_htable_t* sigs = amxp_get_signals(NULL);
    amxp_signal_t* sig1 = NULL;
    amxp_signal_t* sig2 = NULL;
    amxp_signal_t* sig3 = NULL;

    amxc_var_init(&var);

    assert_ptr_not_equal(sigs, NULL);

    assert_int_equal(amxp_signal_new(NULL, &sig1, "test:signal1"), 0);
    assert_int_equal(amxp_signal_new(NULL, &sig2, "test:signal2"), 0);
    assert_int_equal(amxp_signal_new(NULL, &sig3, "test:signal3"), 0);

    assert_int_equal(amxp_slot_connect(NULL, "test:signal1", NULL, test_slot1, NULL), 0);
    assert_int_equal(amxp_slot_connect(NULL, "test:signal1", NULL, test_slot2, NULL), 0);
    assert_int_equal(amxp_slot_connect(NULL, "test:signal2", NULL, test_slot1, NULL), 0);
    assert_int_equal(amxp_slot_connect(NULL, "test:signal3", NULL, test_slot2, NULL), 0);

    count1 = 0;
    count2 = 0;

    amxp_signal_trigger(NULL, NULL);
    assert_int_equal(count1, 0);
    assert_int_equal(count2, 0);

    expected_sig_name = NULL;
    amxp_signal_trigger(sig1, NULL);
    assert_int_equal(count1, 1);
    assert_int_equal(count2, 1);

    expected_sig_name = amxp_signal_name(sig1);
    amxc_var_set_cstring_t(&var, expected_sig_name);
    amxp_signal_trigger(sig1, &var);
    assert_int_equal(count1, 2);
    assert_int_equal(count2, 2);

    expected_sig_name = amxp_signal_name(sig2);
    amxc_var_set_cstring_t(&var, expected_sig_name);
    amxp_signal_trigger(sig2, &var);
    assert_int_equal(count1, 3);
    assert_int_equal(count2, 2);

    expected_sig_name = amxp_signal_name(sig3);
    amxc_var_set_cstring_t(&var, expected_sig_name);
    amxp_signal_trigger(sig3, &var);
    assert_int_equal(count1, 3);
    assert_int_equal(count2, 3);

    amxp_signal_delete(&sig1);
    amxp_signal_delete(&sig2);
    amxp_signal_delete(&sig3);

    amxp_signal_trigger(sig3, &var);
    assert_int_equal(count1, 3);
    assert_int_equal(count2, 3);

    amxc_var_clean(&var);
}

void test_signal_emit(UNUSED void** state) {
    amxc_var_t var;
    amxp_signal_t* sig1 = NULL;
    amxp_signal_t* sig2 = NULL;
    amxp_signal_t* sig3 = NULL;

    amxc_var_init(&var);

    assert_int_equal(amxp_signal_new(NULL, &sig1, "test:signal1"), 0);
    assert_int_equal(amxp_signal_new(NULL, &sig2, "test:signal2"), 0);
    assert_int_equal(amxp_signal_new(NULL, &sig3, "test:signal3"), 0);

    assert_int_equal(amxp_slot_connect(NULL, "test:signal1", NULL, test_slot1, NULL), 0);
    assert_int_equal(amxp_slot_connect(NULL, "test:signal1", NULL, test_slot2, NULL), 0);
    assert_int_equal(amxp_slot_connect(NULL, "test:signal2", NULL, test_slot1, NULL), 0);
    assert_int_equal(amxp_slot_connect(NULL, "test:signal3", NULL, test_slot2, NULL), 0);

    count1 = 0;
    count2 = 0;

    assert_int_not_equal(amxp_signal_fd(), -1);

    assert_int_not_equal(amxp_signal_emit(NULL, NULL), 0);
    assert_int_equal(count1, 0);
    assert_int_equal(count2, 0);

    expected_sig_name = NULL;
    assert_int_equal(amxp_signal_emit(sig1, NULL), 0);
    assert_int_equal(count1, 0);
    assert_int_equal(count2, 0);
    assert_int_equal(amxp_signal_read(), 0);
    assert_int_equal(count1, 1);
    assert_int_equal(count2, 1);

    expected_sig_name = amxp_signal_name(sig1);
    amxc_var_set_cstring_t(&var, expected_sig_name);
    assert_int_equal(amxp_signal_emit(sig1, &var), 0);
    assert_int_equal(count1, 1);
    assert_int_equal(count2, 1);
    assert_int_equal(amxp_signal_read(), 0);
    assert_int_equal(count1, 2);
    assert_int_equal(count2, 2);

    expected_sig_name = amxp_signal_name(sig2);
    amxc_var_set_cstring_t(&var, expected_sig_name);
    assert_int_equal(amxp_signal_emit(sig2, &var), 0);
    assert_int_equal(count1, 2);
    assert_int_equal(count2, 2);
    assert_int_equal(amxp_signal_read(), 0);
    assert_int_equal(count1, 3);
    assert_int_equal(count2, 2);

    expected_sig_name = amxp_signal_name(sig3);
    amxc_var_set_cstring_t(&var, expected_sig_name);
    assert_int_equal(amxp_signal_emit(sig3, &var), 0);
    assert_int_equal(count1, 3);
    assert_int_equal(count2, 2);
    assert_int_equal(amxp_signal_read(), 0);
    assert_int_equal(count1, 3);
    assert_int_equal(count2, 3);

    assert_int_equal(amxp_signal_emit(sig3, &var), 0);
    assert_int_equal(amxp_signal_emit(sig3, &var), 0);
    assert_int_equal(count1, 3);
    assert_int_equal(count2, 3);
    assert_int_equal(amxp_signal_read(), 0);
    assert_int_equal(amxp_signal_read(), 0);
    assert_int_equal(count1, 3);
    assert_int_equal(count2, 5);

    amxp_signal_delete(&sig1);
    amxp_signal_delete(&sig2);
    amxp_signal_delete(&sig3);

    assert_int_not_equal(amxp_signal_emit(sig3, &var), 0);
    assert_int_equal(count1, 3);
    assert_int_equal(count2, 5);

    amxc_var_clean(&var);
}

void test_slot_disconnect(UNUSED void** state) {
    amxc_var_t var;
    amxp_signal_t* sig1 = NULL;

    amxc_var_init(&var);

    assert_int_equal(amxp_signal_new(NULL, &sig1, "test:signal1"), 0);

    assert_int_equal(amxp_slot_connect(NULL, "test:signal1", NULL, test_slot1, NULL), 0);
    assert_int_equal(amxp_slot_connect(NULL, "test:signal1", NULL, test_slot2, NULL), 0);
    assert_true(amxp_signal_has_slots(sig1));

    expected_sig_name = NULL;
    count1 = 0;
    count2 = 0;

    expected_sig_name = amxp_signal_name(sig1);
    amxc_var_set_cstring_t(&var, expected_sig_name);
    amxp_signal_trigger(sig1, &var);
    assert_int_equal(count1, 1);
    assert_int_equal(count2, 1);

    assert_int_equal(amxp_slot_disconnect(NULL, "test:signal1", test_slot1), 0);
    assert_true(amxp_signal_has_slots(sig1));
    amxp_signal_trigger(sig1, &var);
    assert_int_equal(count1, 1);
    assert_int_equal(count2, 2);

    assert_int_not_equal(amxp_slot_disconnect(NULL, "test:signal1", test_slot1), 0);
    amxp_signal_trigger(sig1, &var);
    assert_int_equal(count1, 1);
    assert_int_equal(count2, 3);

    assert_int_equal(amxp_slot_disconnect(NULL, "test:signal1", test_slot2), 0);
    assert_false(amxp_signal_has_slots(sig1));
    amxp_signal_trigger(sig1, &var);
    assert_int_equal(count1, 1);
    assert_int_equal(count2, 3);

    assert_int_not_equal(amxp_slot_disconnect(NULL, "not_existing", test_slot2), 0);
    assert_int_not_equal(amxp_slot_disconnect(NULL, NULL, test_slot2), 0);
    assert_int_not_equal(amxp_slot_disconnect(NULL, "", test_slot2), 0);
    assert_int_not_equal(amxp_slot_disconnect(NULL, "test:signal1", NULL), 0);

    amxp_signal_delete(&sig1);

    amxc_var_clean(&var);
}

void test_signal_disconnect_all(UNUSED void** state) {
    amxc_var_t var;
    amxp_signal_t* sig1 = NULL;
    amxp_signal_t* sig2 = NULL;

    amxc_var_init(&var);

    assert_int_equal(amxp_signal_new(NULL, &sig1, "test:signal1"), 0);
    assert_int_equal(amxp_signal_new(NULL, &sig2, "test:signal2"), 0);

    assert_int_equal(amxp_slot_connect(NULL, "test:signal1", NULL, test_slot1, NULL), 0);
    assert_int_equal(amxp_slot_connect(NULL, "test:signal1", NULL, test_slot2, NULL), 0);
    assert_int_equal(amxp_slot_connect(NULL, "test:signal2", NULL, test_slot1, NULL), 0);

    expected_sig_name = NULL;
    count1 = 0;
    count2 = 0;

    expected_sig_name = amxp_signal_name(sig1);
    amxc_var_set_cstring_t(&var, expected_sig_name);
    amxp_signal_trigger(sig1, &var);
    assert_int_equal(count1, 1);
    assert_int_equal(count2, 1);

    assert_int_equal(amxp_signal_disconnect_all(sig1), 0);

    amxp_signal_trigger(sig1, &var);
    assert_int_equal(count1, 1);
    assert_int_equal(count2, 1);

    expected_sig_name = amxp_signal_name(sig2);
    amxc_var_set_cstring_t(&var, expected_sig_name);
    amxp_signal_trigger(sig2, &var);
    assert_int_equal(count1, 2);
    assert_int_equal(count2, 1);

    assert_int_equal(amxp_slot_connect(NULL, "test:signal1", NULL, test_slot1, NULL), 0);
    assert_int_equal(amxp_slot_connect(NULL, "test:signal1", NULL, test_slot2, NULL), 0);
    assert_int_equal(amxp_slot_connect(NULL, "test:signal2", NULL, test_slot1, NULL), 0);

    assert_int_not_equal(amxp_signal_disconnect_all(NULL), 0);

    amxp_signal_delete(&sig1);
    amxp_signal_delete(&sig2);

    amxc_var_clean(&var);
}

void test_slot_disconnect_all(UNUSED void** state) {
    amxc_var_t var;
    amxp_signal_t* sig1 = NULL;
    amxp_signal_t* sig2 = NULL;

    amxc_var_init(&var);

    assert_int_equal(amxp_signal_new(NULL, &sig1, "test:signal1"), 0);
    assert_int_equal(amxp_signal_new(NULL, &sig2, "test:signal2"), 0);

    assert_int_equal(amxp_slot_connect(NULL, "test:signal1", NULL, test_slot1, NULL), 0);
    assert_int_equal(amxp_slot_connect(NULL, "test:signal1", NULL, test_slot2, NULL), 0);
    assert_int_equal(amxp_slot_connect(NULL, "test:signal2", NULL, test_slot1, NULL), 0);

    expected_sig_name = NULL;
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
    assert_int_equal(count2, 1);

    amxp_slot_disconnect_all(test_slot1);

    expected_sig_name = amxp_signal_name(sig1);
    amxc_var_set_cstring_t(&var, expected_sig_name);
    amxp_signal_trigger(sig1, &var);
    assert_int_equal(count1, 2);
    assert_int_equal(count2, 2);

    expected_sig_name = amxp_signal_name(sig2);
    amxc_var_set_cstring_t(&var, expected_sig_name);
    amxp_signal_trigger(sig2, &var);
    assert_int_equal(count1, 2);
    assert_int_equal(count2, 2);

    amxp_signal_delete(&sig1);
    amxp_signal_delete(&sig2);

    amxc_var_clean(&var);
}

void test_slot_disconnect_all2(UNUSED void** state) {
    amxc_var_t var;
    amxp_signal_t* sig1 = NULL;
    amxp_signal_t* sig2 = NULL;

    amxc_var_init(&var);

    assert_int_equal(amxp_signal_new(NULL, &sig1, "test:signal1"), 0);
    assert_int_equal(amxp_signal_new(NULL, &sig2, "test:signal2"), 0);

    assert_int_equal(amxp_slot_connect(NULL, "test:signal1", NULL, test_slot1, NULL), 0);
    assert_int_equal(amxp_slot_connect(NULL, "test:signal1", NULL, test_slot2, NULL), 0);
    assert_int_equal(amxp_slot_connect(NULL, "test:signal2", NULL, test_slot1, NULL), 0);

    expected_sig_name = NULL;
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
    assert_int_equal(count2, 1);

    amxp_slot_disconnect(NULL, "*", test_slot1);

    expected_sig_name = amxp_signal_name(sig1);
    amxc_var_set_cstring_t(&var, expected_sig_name);
    amxp_signal_trigger(sig1, &var);
    assert_int_equal(count1, 2);
    assert_int_equal(count2, 2);

    expected_sig_name = amxp_signal_name(sig2);
    amxc_var_set_cstring_t(&var, expected_sig_name);
    amxp_signal_trigger(sig2, &var);
    assert_int_equal(count1, 2);
    assert_int_equal(count2, 2);

    amxp_signal_delete(&sig1);
    amxp_signal_delete(&sig2);

    amxc_var_clean(&var);
}

// make sure this is the last test
void test_signal_slot_verify_cleanup(UNUSED void** state) {
    amxp_signal_t* sig1 = NULL;
    amxp_signal_t* sig2 = NULL;
    assert_int_equal(amxp_signal_new(NULL, &sig1, "test:signal1"), 0);
    assert_int_equal(amxp_signal_new(NULL, &sig2, "test:signal2"), 0);
    assert_int_equal(amxp_slot_connect(NULL, "test:signal1", NULL, test_slot1, NULL), 0);
    assert_int_equal(amxp_slot_connect(NULL, "test:signal1", NULL, test_slot2, NULL), 0);
    assert_int_equal(amxp_slot_connect(NULL, "test:signal2", NULL, test_slot1, NULL), 0);

    assert_int_equal(amxp_signal_emit(sig1, NULL), 0);
    assert_int_equal(amxp_signal_emit(sig2, NULL), 0);
    assert_int_equal(amxp_signal_emit(sig1, NULL), 0);
}
