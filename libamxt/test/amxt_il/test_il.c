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
#include <amxt/amxt_il.h>

#include "test_il.h"

#include <amxc/amxc_macros.h>
void test_il_new_delete(UNUSED void** state) {
    amxt_il_t* il = NULL;

    assert_int_not_equal(amxt_il_new(NULL, 0), 0);
    assert_int_equal(amxt_il_new(&il, 0), 0);
    assert_int_equal(il->cursor_pos, 0);
    assert_int_equal(il->mode, amxc_string_insert);

    assert_ptr_not_equal(il, NULL);
    amxt_il_delete(NULL);
    amxt_il_delete(&il);
    assert_ptr_equal(il, NULL);
}

void test_il_init_clean_reset(UNUSED void** state) {
    amxt_il_t il;

    assert_int_not_equal(amxt_il_init(NULL, 0), 0);
    assert_int_equal(amxt_il_init(&il, 0), 0);
    assert_int_equal(il.cursor_pos, 0);
    assert_int_equal(il.mode, amxc_string_insert);

    amxt_il_clean(NULL);
    amxt_il_reset(NULL);
    amxt_il_reset(&il);
    amxt_il_clean(&il);
}

void test_il_insert_block(UNUSED void** state) {
    amxt_il_t il;

    assert_int_equal(amxt_il_init(&il, 0), 0);

    assert_int_not_equal(amxt_il_insert_block(NULL, "", 0), 0);
    assert_int_not_equal(amxt_il_insert_block(&il, NULL, 0), 0);

    assert_int_equal(amxt_il_insert_block(&il, "", 0), 0);
    assert_int_equal(il.cursor_pos, 0);
    assert_int_equal(amxt_il_text_length(&il, amxt_il_no_flags, 0), 0);
    assert_string_equal(amxt_il_text(&il, amxt_il_no_flags, 0), "");

    assert_int_equal(amxt_il_insert_block(&il, "1234567890", 10), 0);
    assert_int_equal(il.cursor_pos, 10);
    assert_int_equal(amxt_il_text_length(&il, amxt_il_no_flags, 0), 10);
    assert_string_equal(amxt_il_text(&il, amxt_il_no_flags, 0), "1234567890");

    assert_int_equal(amxt_il_move_cursor(&il, -2), 8);
    assert_int_equal(amxt_il_insert_block(&il, "ab", 2), 0);
    assert_int_equal(il.cursor_pos, 10);
    assert_int_equal(amxt_il_text_length(&il, amxt_il_no_flags, 0), 12);
    assert_string_equal(amxt_il_text(&il, amxt_il_no_flags, 0), "12345678ab90");

    amxt_il_reset(&il);
    assert_int_equal(il.cursor_pos, 0);
    assert_int_equal(amxt_il_text_length(&il, amxt_il_no_flags, 0), 0);
    assert_string_equal(amxt_il_text(&il, amxt_il_no_flags, 0), "");

    assert_int_equal(amxt_il_insert_block(&il, "1234567890", 10), 0);
    assert_int_equal(amxt_il_move_cursor(&il, -2), 8);
    assert_int_equal(amxt_il_set_mode(&il, amxc_string_overwrite), 0);
    assert_int_equal(amxt_il_insert_block(&il, "abc", 3), 0);
    assert_int_equal(il.cursor_pos, 11);
    assert_int_equal(amxt_il_text_length(&il, amxt_il_no_flags, 0), 11);
    assert_string_equal(amxt_il_text(&il, amxt_il_no_flags, 0), "12345678abc");

    amxt_il_clean(&il);
}

void test_il_remove_char(UNUSED void** state) {
    amxt_il_t il;

    assert_int_equal(amxt_il_init(&il, 0), 0);

    assert_int_not_equal(amxt_il_remove_char(NULL, amxt_il_keep_cursor_pos), 0);

    assert_int_equal(amxt_il_insert_block(&il, "1234567890", 10), 0);
    assert_int_equal(il.cursor_pos, 10);
    assert_int_equal(amxt_il_text_length(&il, amxt_il_no_flags, 0), 10);
    assert_string_equal(amxt_il_text(&il, amxt_il_no_flags, 0), "1234567890");

    assert_int_equal(amxt_il_move_cursor(&il, -2), 8);
    assert_int_equal(amxt_il_remove_char(&il, amxt_il_keep_cursor_pos), 0);
    assert_int_equal(il.cursor_pos, 8);
    assert_int_equal(amxt_il_text_length(&il, amxt_il_no_flags, 0), 9);
    assert_string_equal(amxt_il_text(&il, amxt_il_no_flags, 0), "123456780");

    assert_int_equal(amxt_il_remove_char(&il, amxt_il_no_flags), 0);
    assert_int_equal(il.cursor_pos, 7);
    assert_int_equal(amxt_il_text_length(&il, amxt_il_no_flags, 0), 8);
    assert_string_equal(amxt_il_text(&il, amxt_il_no_flags, 0), "12345670");

    assert_int_equal(amxt_il_move_cursor(&il, 10), 8);
    assert_int_equal(amxt_il_remove_char(&il, amxt_il_keep_cursor_pos), 0);
    assert_int_equal(il.cursor_pos, 8);
    assert_int_equal(amxt_il_text_length(&il, amxt_il_no_flags, 0), 8);
    assert_string_equal(amxt_il_text(&il, amxt_il_no_flags, 0), "12345670");

    assert_int_equal(amxt_il_move_cursor(&il, -10), 0);
    assert_int_equal(amxt_il_remove_char(&il, amxt_il_no_flags), 0);
    assert_int_equal(il.cursor_pos, 0);
    assert_int_equal(amxt_il_text_length(&il, amxt_il_no_flags, 0), 8);
    assert_string_equal(amxt_il_text(&il, amxt_il_no_flags, 0), "12345670");

    amxt_il_clean(&il);
}

void test_il_cursor_pos(UNUSED void** state) {
    amxt_il_t il;

    assert_int_equal(amxt_il_init(&il, 0), 0);

    assert_int_equal(amxt_il_set_cursor_pos(NULL, 100), 0);
    assert_int_equal(amxt_il_move_cursor(NULL, 100), 0);
    assert_int_equal(amxt_il_move_cursor(NULL, -100), 0);

    assert_int_equal(amxt_il_insert_block(&il, "1234567890", 10), 0);
    assert_int_equal(il.cursor_pos, 10);
    assert_int_equal(amxt_il_set_cursor_pos(&il, 0), 0);
    assert_int_equal(il.cursor_pos, 0);

    assert_int_equal(amxt_il_set_cursor_pos(&il, 50), 10);
    assert_int_equal(il.cursor_pos, 10);

    assert_int_equal(amxt_il_set_cursor_pos(&il, 5), 5);
    assert_int_equal(il.cursor_pos, 5);

    amxt_il_clean(&il);
}

void test_il_text(UNUSED void** state) {
    amxt_il_t il;

    assert_int_equal(amxt_il_init(&il, 0), 0);

    assert_ptr_equal(amxt_il_text(NULL, amxt_il_no_flags, 0), NULL);
    assert_ptr_equal(amxt_il_text(NULL, amxt_il_text_after_cursor, 0), NULL);
    assert_ptr_equal(amxt_il_text(NULL, amxt_il_no_flags, 100), NULL);
    assert_ptr_equal(amxt_il_text(NULL, amxt_il_text_after_cursor, 100), NULL);

    assert_int_equal(amxt_il_text_length(NULL, amxt_il_no_flags, 0), 0);
    assert_int_equal(amxt_il_text_length(NULL, amxt_il_text_after_cursor, 0), 0);
    assert_int_equal(amxt_il_text_length(NULL, amxt_il_no_flags, 100), 0);
    assert_int_equal(amxt_il_text_length(NULL, amxt_il_text_after_cursor, 100), 0);

    assert_int_equal(amxt_il_insert_block(&il, "1234567890", 10), 0);
    assert_string_equal(amxt_il_text(&il, amxt_il_no_flags, 0), "1234567890");
    assert_int_equal(amxt_il_text_length(&il, amxt_il_no_flags, 0), 10);
    assert_string_equal(amxt_il_text(&il, amxt_il_no_flags, 5), "67890");
    assert_int_equal(amxt_il_text_length(&il, amxt_il_no_flags, 5), 5);
    assert_string_equal(amxt_il_text(&il, amxt_il_no_flags, 50), "");
    assert_int_equal(amxt_il_text_length(&il, amxt_il_no_flags, 50), 0);
    assert_string_equal(amxt_il_text(&il, amxt_il_no_flags, -10), "1234567890");
    assert_int_equal(amxt_il_text_length(&il, amxt_il_no_flags, -10), 10);

    assert_int_equal(amxt_il_set_cursor_pos(&il, 5), 5);
    assert_string_equal(amxt_il_text(&il, amxt_il_no_flags, 0), "1234567890");
    assert_int_equal(amxt_il_text_length(&il, amxt_il_no_flags, 0), 10);
    assert_string_equal(amxt_il_text(&il, amxt_il_text_after_cursor, 0), "67890");
    assert_int_equal(amxt_il_text_length(&il, amxt_il_text_after_cursor, 0), 5);
    assert_string_equal(amxt_il_text(&il, amxt_il_no_flags, 2), "34567890");
    assert_int_equal(amxt_il_text_length(&il, amxt_il_no_flags, 2), 8);
    assert_string_equal(amxt_il_text(&il, amxt_il_text_after_cursor, 2), "890");
    assert_int_equal(amxt_il_text_length(&il, amxt_il_text_after_cursor, 2), 3);

    amxt_il_clean(&il);
}

void test_il_mode(UNUSED void** state) {
    amxt_il_t il;

    assert_int_equal(amxt_il_mode(NULL), 0);
    assert_int_not_equal(amxt_il_set_mode(NULL, amxc_string_overwrite), 0);

    assert_int_equal(amxt_il_init(&il, 0), 0);

    assert_int_equal(amxt_il_mode(&il), amxc_string_insert);
    assert_int_equal(amxt_il_set_mode(&il, amxc_string_overwrite), 0);
    assert_int_equal(amxt_il_mode(&il), amxc_string_overwrite);

    amxt_il_clean(&il);
}
