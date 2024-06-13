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

#include <amxc/amxc.h>
#include <amxp/amxp.h>
#include <amxt/amxt_history.h>

#include "test_history.h"

#include <amxc/amxc_macros.h>
#define LARGE_TEXT "12345678901234567890123456789012345678901234567890" \
    "12345678901234567890123456789012345678901234567890" \
    "12345678901234567890123456789012345678901234567890" \
    "12345678901234567890123456789012345678901234567890" \
    "12345678901234567890123456789012345678901234567890" \
    "12345678901234567890123456789012345678901234567890" \
    "12345678901234567890123456789012345678901234567890" \
    "12345678901234567890123456789012345678901234567890" \
    "12345678901234567890123456789012345678901234567890" \
    "12345678901234567890123456789012345678901234567890" \
    "12345678901234567890123456789012345678901234567890"

void test_history_init_clean(UNUSED void** state) {
    amxt_hist_t history;

    assert_int_not_equal(amxt_hist_init(NULL), 0);
    assert_int_equal(amxt_hist_init(&history), 0);
    assert_int_equal(history.current_pos, 0);
    assert_ptr_equal(amxc_var_get_index(&history.history, 0, AMXC_VAR_FLAG_DEFAULT), NULL);

    amxt_hist_clean(NULL);
    amxt_hist_clean(&history);
}

void test_history_add(UNUSED void** state) {
    amxt_hist_t history;
    amxc_var_t* var_txt = NULL;
    assert_int_not_equal(amxt_hist_add(NULL, "First item"), 0);
    assert_int_equal(amxt_hist_init(&history), 0);

    assert_int_equal(history.current_pos, 0);
    assert_ptr_equal(amxc_var_get_index(&history.history, 0, AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_int_equal(amxt_hist_add(&history, "First item"), 0);
    assert_ptr_not_equal(amxc_var_get_index(&history.history, 0, AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_int_equal(amxt_hist_add(&history, "Second item"), 0);
    assert_ptr_not_equal(amxc_var_get_index(&history.history, 1, AMXC_VAR_FLAG_DEFAULT), NULL);
    assert_int_equal(amxc_llist_size(&history.history.data.vl), 2);
    assert_int_equal(history.current_pos, 0);
    assert_int_not_equal(amxt_hist_add(&history, NULL), 0);

    var_txt = amxc_var_get_index(&history.history, 0, AMXC_VAR_FLAG_DEFAULT);
    assert_ptr_not_equal(var_txt, NULL);
    assert_string_equal(amxc_var_constcast(cstring_t, var_txt), "Second item");

    var_txt = amxc_var_get_index(&history.history, 1, AMXC_VAR_FLAG_DEFAULT);
    assert_ptr_not_equal(var_txt, NULL);
    assert_string_equal(amxc_var_constcast(cstring_t, var_txt), "First item");

    amxt_hist_clean(NULL);
    amxt_hist_clean(&history);
}

void test_history_set_pos(UNUSED void** state) {
    amxt_hist_t history;

    assert_int_equal(amxt_hist_init(&history), 0);

    assert_int_equal(history.current_pos, 0);
    assert_int_not_equal(amxt_hist_set_pos(&history, 0), 0);
    assert_int_not_equal(amxt_hist_set_pos(NULL, 0), 0);
    assert_int_equal(amxt_hist_get_pos(NULL), 0);
    assert_ptr_equal(amxt_hist_get_current(NULL), NULL);

    assert_int_equal(amxt_hist_add(&history, "First item"), 0);
    assert_int_equal(amxt_hist_add(&history, "Second item"), 0);
    assert_int_equal(amxt_hist_add(&history, "Third item"), 0);
    assert_int_equal(amxc_llist_size(&history.history.data.vl), 3);
    assert_int_equal(history.current_pos, 0);

    assert_int_not_equal(amxt_hist_set_pos(&history, 10), 0);

    assert_string_equal(amxt_hist_get_current(&history), "Third item");
    assert_int_equal(amxc_llist_size(&history.history.data.vl), 3);

    assert_int_equal(amxt_hist_set_pos(&history, 1), 0);
    assert_int_equal(amxt_hist_get_pos(&history), 1);
    assert_string_equal(amxt_hist_get_current(&history), "Second item");
    assert_int_equal(amxc_llist_size(&history.history.data.vl), 3);

    assert_int_equal(amxt_hist_set_pos(&history, 2), 0);
    assert_int_equal(amxt_hist_get_pos(&history), 2);
    assert_string_equal(amxt_hist_get_current(&history), "First item");
    assert_int_equal(amxc_llist_size(&history.history.data.vl), 3);

    amxt_hist_clean(&history);
}

void test_history_get_next(UNUSED void** state) {
    amxt_hist_t history;

    assert_int_equal(amxt_hist_init(&history), 0);
    assert_ptr_equal(amxt_hist_get_next(NULL), NULL);

    assert_int_equal(history.current_pos, 0);

    assert_int_equal(amxt_hist_add(&history, "First item"), 0);
    assert_int_equal(amxt_hist_add(&history, "Second item"), 0);
    assert_int_equal(amxt_hist_add(&history, "Third item"), 0);
    assert_int_equal(amxc_llist_size(&history.history.data.vl), 3);
    assert_int_equal(history.current_pos, 0);

    assert_string_equal(amxt_hist_get_current(&history), "Third item");
    assert_int_equal(amxt_hist_get_pos(&history), 0);
    assert_string_equal(amxt_hist_get_next(&history), "Second item");
    assert_int_equal(amxt_hist_get_pos(&history), 1);
    assert_string_equal(amxt_hist_get_next(&history), "First item");
    assert_int_equal(amxt_hist_get_pos(&history), 2);
    assert_int_equal(history.current_pos, 2);
    assert_ptr_equal(amxt_hist_get_next(&history), NULL);
    assert_int_equal(history.current_pos, 2);

    amxt_hist_clean(&history);
}

void test_history_get_prev(UNUSED void** state) {
    amxt_hist_t history;

    assert_int_equal(amxt_hist_init(&history), 0);
    assert_ptr_equal(amxt_hist_get_prev(NULL), NULL);

    assert_int_equal(history.current_pos, 0);

    assert_int_equal(amxt_hist_add(&history, "First item"), 0);
    assert_int_equal(amxt_hist_add(&history, "Second item"), 0);
    assert_int_equal(amxt_hist_add(&history, "Third item"), 0);
    assert_int_equal(amxc_llist_size(&history.history.data.vl), 3);
    assert_int_equal(amxt_hist_set_pos(&history, 2), 0);
    assert_int_equal(history.current_pos, 2);

    assert_string_equal(amxt_hist_get_current(&history), "First item");
    assert_string_equal(amxt_hist_get_prev(&history), "Second item");
    assert_string_equal(amxt_hist_get_prev(&history), "Third item");
    assert_int_equal(history.current_pos, 0);
    assert_ptr_equal(amxt_hist_get_prev(&history), NULL);
    assert_int_equal(history.current_pos, 0);

    amxt_hist_clean(&history);
}

void test_history_update(UNUSED void** state) {
    amxt_hist_t history;

    assert_int_equal(amxt_hist_init(&history), 0);
    assert_int_not_equal(amxt_hist_update(NULL, "text"), 0);

    assert_int_equal(amxt_hist_add(&history, "First item"), 0);
    assert_int_equal(amxt_hist_add(&history, "Second item"), 0);
    assert_int_equal(amxt_hist_add(&history, "Third item"), 0);

    assert_int_equal(amxt_hist_set_pos(&history, 2), 0);
    assert_string_equal(amxt_hist_get_current(&history), "First item");
    assert_int_equal(amxt_hist_update(&history, "2nd item"), 0);
    assert_string_equal(amxt_hist_get_current(&history), "2nd item");
    assert_int_not_equal(amxt_hist_update(&history, NULL), 0);

    amxt_hist_clean(&history);
}

void test_history_save_load(UNUSED void** state) {
    amxt_hist_t history;

    assert_int_equal(amxt_hist_init(&history), 0);
    assert_int_equal(amxt_hist_add(&history, "First item"), 0);
    assert_int_equal(amxt_hist_add(&history, "Second item"), 0);
    assert_int_equal(amxt_hist_add(&history, "Third item"), 0);
    assert_int_equal(amxc_llist_size(&history.history.data.vl), 3);

    assert_int_equal(amxt_hist_save(&history, "/tmp/amxt_hist.txt"), 0);
    assert_int_equal(amxc_llist_size(&history.history.data.vl), 3);
    assert_int_equal(amxt_hist_set_pos(&history, 2), 0);

    assert_int_equal(amxt_hist_load(&history, "/tmp/amxt_hist.txt"), 0);
    assert_int_equal(history.current_pos, 0);
    assert_int_equal(amxc_llist_size(&history.history.data.vl), 3);
    assert_string_equal(amxt_hist_get_current(&history), "Third item");
    assert_string_equal(amxt_hist_get_next(&history), "Second item");
    assert_string_equal(amxt_hist_get_next(&history), "First item");
    assert_ptr_equal(amxt_hist_get_next(&history), NULL);

    amxt_hist_clean(&history);
}

void test_history_save_fail(UNUSED void** state) {
    amxt_hist_t history;

    assert_int_not_equal(amxt_hist_save(NULL, NULL), 0);

    assert_int_equal(amxt_hist_init(&history), 0);
    assert_int_not_equal(amxt_hist_save(&history, NULL), 0);
    assert_int_not_equal(amxt_hist_save(&history, ""), 0);

    assert_int_equal(amxt_hist_add(&history, "First item"), 0);
    assert_int_equal(amxt_hist_add(&history, "Second item"), 0);
    assert_int_equal(amxt_hist_add(&history, "Third item"), 0);
    assert_int_equal(amxc_llist_size(&history.history.data.vl), 3);

    assert_int_not_equal(amxt_hist_save(&history, "/non/existing/dir/amxt_hist.txt"), 0);

    amxt_hist_clean(&history);
    assert_int_equal(amxt_hist_add(&history, LARGE_TEXT), 0);
    assert_int_equal(amxt_hist_save(&history, "/tmp/amxt_hist.txt"), 0);
    assert_int_equal(amxt_hist_load(&history, "/tmp/amxt_hist.txt"), 0);
    assert_int_equal(amxc_llist_size(&history.history.data.vl), 0);

    amxt_hist_clean(&history);
}

void test_history_load_fail(UNUSED void** state) {
    amxt_hist_t history;

    assert_int_not_equal(amxt_hist_load(NULL, NULL), 0);

    assert_int_equal(amxt_hist_init(&history), 0);
    assert_int_not_equal(amxt_hist_load(&history, NULL), 0);
    assert_int_not_equal(amxt_hist_load(&history, ""), 0);

    assert_int_not_equal(amxt_hist_load(&history, "/non/existing/dir/amxt_hist.txt"), 0);

    amxt_hist_clean(&history);
}