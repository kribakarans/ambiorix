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
#include <ctype.h>
#include <string.h>
#include <setjmp.h>
#include <cmocka.h>

#include <amxc/amxc_variant.h>
#include <amxc/amxc_string.h>
#include <amxc/amxc_utils.h>

#include "test_amxc_string.h"

#include <amxc/amxc_macros.h>
char data[] = "abcdefghij";

void test_amxc_string_new_delete_null(UNUSED void** state) {
    // passing NULL pointers should not lead to segfault
    assert_int_not_equal(amxc_string_new(NULL, 0), 0);
    amxc_string_delete(NULL);
}

void test_amxc_string_init_reset_clean_null(UNUSED void** state) {
    // passing NULL pointers should not lead to segfault
    assert_int_equal(amxc_string_init(NULL, 0), -1);
    amxc_string_clean(NULL);
    amxc_string_reset(NULL);
}

void test_amxc_string_new_delete(UNUSED void** state) {
    amxc_string_t* string = NULL;

    assert_int_equal(amxc_string_new(&string, 0), 0);
    assert_ptr_equal(string->buffer, NULL);
    assert_int_equal(string->length, 0);
    assert_int_equal(string->last_used, 0);
    amxc_string_delete(&string);
    assert_ptr_equal(string, NULL);

    assert_int_equal(amxc_string_new(&string, 10), 0);
    assert_ptr_not_equal(string->buffer, NULL);
    assert_int_equal(string->length, 10);
    assert_int_equal(string->last_used, 0);
    amxc_string_delete(&string);
    assert_ptr_equal(string, NULL);
}

void test_amxc_string_init_reset_clean(UNUSED void** state) {
    amxc_string_t string;

    assert_int_equal(amxc_string_init(&string, 0), 0);
    assert_ptr_equal(string.buffer, NULL);
    assert_int_equal(string.length, 0);
    assert_int_equal(string.last_used, 0);
    amxc_string_clean(&string);
    assert_int_equal(string.length, 0);
    assert_int_equal(string.last_used, 0);

    assert_int_equal(amxc_string_init(&string, 10), 0);
    assert_ptr_not_equal(string.buffer, NULL);
    assert_int_equal(string.length, 10);
    assert_int_equal(string.last_used, 0);
    amxc_string_reset(&string);
    assert_int_equal(string.length, 10);
    assert_int_equal(string.last_used, 0);
    amxc_string_clean(&string);
    assert_ptr_equal(string.buffer, NULL);
    assert_int_equal(string.length, 0);
    assert_int_equal(string.last_used, 0);
}

void test_amxc_string_grow_null(UNUSED void** state) {
    assert_int_equal(amxc_string_grow(NULL, 5), -1);
}

void test_amxc_string_grow(UNUSED void** state) {
    amxc_string_t string;

    assert_int_equal(amxc_string_init(&string, 5), 0);

    assert_int_equal(amxc_string_grow(&string, 0), 0);
    assert_ptr_not_equal(string.buffer, NULL);
    assert_int_equal(string.length, 5);
    assert_int_equal(string.last_used, 0);

    assert_int_equal(amxc_string_grow(&string, 5), 0);
    assert_ptr_not_equal(string.buffer, NULL);
    assert_int_equal(string.length, 10);
    assert_int_equal(string.last_used, 0);

    assert_int_equal(amxc_string_grow(&string, 7), 0);
    assert_ptr_not_equal(string.buffer, NULL);
    assert_int_equal(string.length, 17);
    assert_int_equal(string.last_used, 0);

    amxc_string_clean(&string);
}

void test_amxc_string_shrink_null(UNUSED void** state) {
    assert_int_equal(amxc_string_shrink(NULL, 5), -1);
}

void test_amxc_string_shrink(UNUSED void** state) {
    amxc_string_t string;

    assert_int_equal(amxc_string_init(&string, 15), 0);

    assert_int_equal(amxc_string_shrink(&string, 20), -1);

    assert_int_equal(amxc_string_shrink(&string, 0), 0);
    assert_ptr_not_equal(string.buffer, NULL);
    assert_int_equal(string.length, 15);
    assert_int_equal(string.last_used, 0);

    assert_int_equal(amxc_string_shrink(&string, 5), 0);
    assert_ptr_not_equal(string.buffer, NULL);
    assert_int_equal(string.length, 10);
    assert_int_equal(string.last_used, 0);

    assert_int_equal(amxc_string_shrink(&string, 3), 0);
    assert_ptr_not_equal(string.buffer, NULL);
    assert_int_equal(string.length, 7);
    assert_int_equal(string.last_used, 0);

    assert_int_equal(amxc_string_shrink(&string, 7), 0);
    assert_ptr_equal(string.buffer, NULL);
    assert_int_equal(string.length, 0);
    assert_int_equal(string.last_used, 0);

    amxc_string_clean(&string);
}

void test_amxc_string_append(UNUSED void** state) {
    amxc_string_t string;

    assert_int_equal(amxc_string_init(&string, 10), 0);

    assert_int_not_equal(amxc_string_append(NULL, "abcde", 5), 0);
    assert_int_not_equal(amxc_string_append(&string, NULL, 0), 0);
    assert_int_not_equal(amxc_string_append(&string, "abcde", 0), 0);

    assert_int_equal(amxc_string_append(&string, "abcde", 5), 0);
    assert_int_equal(string.length, 10);
    assert_int_equal(string.last_used, 5);
    assert_string_equal(string.buffer, "abcde");

    assert_int_equal(amxc_string_append(&string, "12345", 5), 0);
    assert_int_equal(string.length, 11);
    assert_int_equal(string.last_used, 10);
    assert_string_equal(string.buffer, "abcde12345");

    assert_int_equal(amxc_string_append(&string, "abcde", 5), 0);
    assert_int_equal(string.length, 16);
    assert_int_equal(string.last_used, 15);
    assert_string_equal(string.buffer, "abcde12345abcde");

    assert_int_equal(amxc_string_shrink(&string, 5), 0);
    assert_int_equal(string.length, 11);
    assert_int_equal(string.last_used, 10);

    amxc_string_clean(&string);
}

void test_amxc_string_prepend(UNUSED void** state) {
    amxc_string_t string;

    assert_int_equal(amxc_string_init(&string, 10), 0);

    assert_int_not_equal(amxc_string_prepend(NULL, "abcde", 5), 0);
    assert_int_not_equal(amxc_string_prepend(&string, NULL, 0), 0);
    assert_int_not_equal(amxc_string_prepend(&string, "abcde", 0), 0);

    assert_int_equal(amxc_string_prepend(&string, "abcde", 5), 0);
    assert_int_equal(string.length, 10);
    assert_int_equal(string.last_used, 5);
    assert_string_equal(string.buffer, "abcde");

    assert_int_equal(amxc_string_prepend(&string, "12345", 5), 0);
    assert_int_equal(string.length, 11);
    assert_int_equal(string.last_used, 10);
    assert_string_equal(string.buffer, "12345abcde");

    assert_int_equal(amxc_string_prepend(&string, "abcde", 5), 0);
    assert_int_equal(string.length, 16);
    assert_int_equal(string.last_used, 15);
    assert_string_equal(string.buffer, "abcde12345abcde");

    assert_int_equal(amxc_string_shrink(&string, 5), 0);
    assert_int_equal(string.length, 11);
    assert_int_equal(string.last_used, 10);

    amxc_string_clean(&string);
}

void test_amxc_string_buffer_length(UNUSED void** state) {
    amxc_string_t string;

    assert_int_equal(amxc_string_init(&string, 10), 0);

    assert_int_equal(amxc_string_buffer_length(NULL), 0);
    assert_int_equal(amxc_string_buffer_length(&string), 10);
    assert_int_equal(amxc_string_shrink(&string, 5), 0);
    assert_int_equal(amxc_string_buffer_length(&string), 5);
    assert_int_equal(amxc_string_grow(&string, 15), 0);
    assert_int_equal(amxc_string_buffer_length(&string), 20);

    amxc_string_clean(&string);
}

void test_amxc_string_text_length(UNUSED void** state) {
    amxc_string_t string;

    assert_int_equal(amxc_string_init(&string, 10), 0);

    assert_int_equal(amxc_string_text_length(NULL), 0);
    assert_int_equal(amxc_string_text_length(&string), 0);
    assert_int_equal(amxc_string_append(&string, "abcde", 5), 0);
    assert_int_equal(amxc_string_text_length(&string), 5);
    assert_int_equal(amxc_string_append(&string, "abcde", 5), 0);
    assert_int_equal(amxc_string_text_length(&string), 10);
    assert_int_equal(amxc_string_append(&string, "abcde", 5), 0);
    assert_int_equal(amxc_string_text_length(&string), 15);
    assert_int_equal(amxc_string_shrink(&string, 5), 0);
    assert_int_equal(amxc_string_text_length(&string), 10);
    assert_int_equal(amxc_string_grow(&string, 15), 0);
    assert_int_equal(amxc_string_text_length(&string), 10);

    amxc_string_clean(&string);
}

void test_amxc_string_set_at(UNUSED void** state) {
    amxc_string_t string;

    assert_int_equal(amxc_string_init(&string, 10), 0);
    assert_int_not_equal(amxc_string_set_at(NULL,
                                            0,
                                            "hello world",
                                            11,
                                            amxc_string_no_flags), 0);
    assert_int_not_equal(amxc_string_set_at(&string,
                                            5,
                                            "hello world",
                                            11,
                                            amxc_string_no_flags), 0);
    assert_int_not_equal(amxc_string_set_at(&string,
                                            0,
                                            "",
                                            0,
                                            amxc_string_no_flags), 0);
    assert_int_equal(amxc_string_set_at(&string,
                                        0,
                                        "hello world",
                                        11,
                                        amxc_string_no_flags), 0);
    assert_int_equal(string.length, 12);
    assert_int_equal(string.last_used, 11);
    assert_int_equal(amxc_string_set_at(&string,
                                        6,
                                        "Europe",
                                        6,
                                        amxc_string_overwrite), 0);
    assert_int_equal(string.length, 12);
    assert_int_equal(string.last_used, 12);
    assert_string_equal(string.buffer, "hello Europe");

    assert_int_equal(amxc_string_set_at(&string,
                                        12,
                                        "and the rest of the world",
                                        25,
                                        amxc_string_overwrite), 0);

    assert_int_equal(amxc_string_set_at(&string,
                                        6,
                                        "Asia",
                                        4,
                                        amxc_string_overwrite), 0);
    assert_int_equal(string.length, 37);
    assert_int_equal(string.last_used, 37);
    assert_string_equal(string.buffer, "hello Asiapeand the rest of the world");

    amxc_string_clean(&string);
}

void test_amxc_string_remove_at(UNUSED void** state) {
    amxc_string_t string;

    assert_int_equal(amxc_string_init(&string, 10), 0);
    assert_int_not_equal(amxc_string_remove_at(NULL,
                                               0,
                                               10), 0);
    assert_int_not_equal(amxc_string_remove_at(&string,
                                               0,
                                               0), 0);
    assert_int_not_equal(amxc_string_remove_at(&string,
                                               5,
                                               10), 0);
    assert_int_equal(amxc_string_set_at(&string,
                                        0,
                                        "hello world",
                                        11,
                                        amxc_string_no_flags), 0);

    assert_int_equal(amxc_string_remove_at(&string,
                                           5,
                                           AMXC_STRING_MAX), 0);
    assert_int_equal(string.length, 12);
    assert_int_equal(string.last_used, 5);
    assert_string_equal(string.buffer, "hello");

    assert_int_equal(amxc_string_remove_at(&string, 2, 2), 0);
    assert_int_equal(string.length, 12);
    assert_int_equal(string.last_used, 3);
    assert_string_equal(string.buffer, "heo");

    amxc_string_reset(&string);
    assert_int_equal(amxc_string_set_at(&string,
                                        0,
                                        "hello world",
                                        11,
                                        amxc_string_no_flags), 0);

    assert_int_equal(amxc_string_remove_at(&string, 5, 35), 0);
    assert_int_equal(string.length, 12);
    assert_int_equal(string.last_used, 5);
    assert_string_equal(string.buffer, "hello");

    amxc_string_clean(&string);
}

void test_amxc_string_get(UNUSED void** state) {
    amxc_string_t string;

    assert_int_equal(amxc_string_init(&string, 0), 0);
    assert_string_equal(amxc_string_get(&string, 0), "");
    amxc_string_clean(&string);

    assert_int_equal(amxc_string_init(&string, 10), 0);
    assert_ptr_equal(amxc_string_get(NULL, 0), NULL);
    assert_ptr_equal(amxc_string_get(&string, 5), NULL);
    assert_int_equal(amxc_string_set_at(&string,
                                        0,
                                        "hello world",
                                        11,
                                        amxc_string_no_flags), 0);
    assert_ptr_equal(amxc_string_get(&string, 12), NULL);

    assert_string_equal(amxc_string_get(&string, 0), "hello world");
    assert_string_equal(amxc_string_get(&string, 6), "world");

    amxc_string_clean(&string);
}

void test_amxc_string_dup(UNUSED void** state) {
    amxc_string_t string;
    char* dup_buffer = NULL;

    assert_int_equal(amxc_string_init(&string, 10), 0);
    assert_ptr_equal(amxc_string_dup(NULL, 0, 10), NULL);
    assert_ptr_equal(amxc_string_dup(&string, 5, 10), NULL);
    assert_int_equal(amxc_string_set_at(&string,
                                        0,
                                        "hello world",
                                        11,
                                        amxc_string_no_flags), 0);

    assert_ptr_equal(amxc_string_dup(&string, 15, 15), NULL);
    assert_ptr_equal(amxc_string_dup(&string, 15, 0), NULL);
    assert_ptr_equal(amxc_string_dup(&string, 0, 0), NULL);

    dup_buffer = amxc_string_dup(&string, 0, AMXC_STRING_MAX);
    assert_ptr_not_equal(dup_buffer, NULL);
    assert_string_equal(dup_buffer, "hello world");
    free(dup_buffer);

    dup_buffer = amxc_string_dup(&string, 0, 25);
    assert_ptr_not_equal(dup_buffer, NULL);
    assert_string_equal(dup_buffer, "hello world");
    free(dup_buffer);

    dup_buffer = amxc_string_dup(&string, 6, 25);
    assert_ptr_not_equal(dup_buffer, NULL);
    assert_string_equal(dup_buffer, "world");
    free(dup_buffer);

    dup_buffer = amxc_string_dup(&string, 2, 2);
    assert_ptr_not_equal(dup_buffer, NULL);
    assert_string_equal(dup_buffer, "ll");
    free(dup_buffer);

    amxc_string_clean(&string);
}

void test_amxc_string_trim(UNUSED void** state) {
    amxc_string_t string;

    amxc_string_triml(NULL, NULL);
    amxc_string_trimr(NULL, NULL);
    amxc_string_trim(NULL, NULL);

    assert_int_equal(amxc_string_init(&string, 10), 0);

    amxc_string_triml(&string, isdigit);
    amxc_string_trimr(&string, isspace);
    assert_int_equal(string.last_used, 0);

    assert_int_equal(amxc_string_set_at(&string,
                                        0,
                                        "  \t hello world\t  ",
                                        18,
                                        amxc_string_no_flags), 0);

    amxc_string_triml(&string, isdigit);
    assert_int_equal(string.last_used, 18);
    amxc_string_trimr(&string, isdigit);
    assert_int_equal(string.last_used, 18);

    assert_int_equal(string.last_used, 18);
    amxc_string_triml(&string, NULL);
    assert_int_equal(string.last_used, 14);
    assert_string_equal(string.buffer, "hello world\t  ");

    amxc_string_trimr(&string, NULL);
    assert_int_equal(string.last_used, 11);
    assert_string_equal(string.buffer, "hello world");

    amxc_string_trim(&string, NULL);
    assert_string_equal(string.buffer, "hello world");
    amxc_string_reset(&string);

    assert_int_equal(amxc_string_set_at(&string,
                                        0,
                                        "1234567890",
                                        10,
                                        amxc_string_no_flags), 0);
    amxc_string_triml(&string, isdigit);
    assert_int_equal(string.last_used, 0);
    amxc_string_reset(&string);

    assert_int_equal(amxc_string_set_at(&string,
                                        0,
                                        "1234567890",
                                        10,
                                        amxc_string_no_flags), 0);
    amxc_string_trimr(&string, isdigit);
    assert_int_equal(string.last_used, 0);
    amxc_string_reset(&string);

    assert_int_equal(amxc_string_set_at(&string,
                                        0,
                                        "  \t hello world\t  ",
                                        18,
                                        amxc_string_no_flags), 0);
    amxc_string_trim(&string, NULL);
    assert_string_equal(string.buffer, "hello world");

    assert_int_equal(amxc_string_setf(&string, "%s", "     "), 0);
    amxc_string_triml(&string, NULL);
    assert_string_equal(string.buffer, "");

    assert_int_equal(amxc_string_setf(&string, "%s", "     "), 0);
    amxc_string_trimr(&string, NULL);
    assert_string_equal(string.buffer, "");

    amxc_string_clean(&string);
}

void test_amxc_string_take_push_buffer(UNUSED void** state) {
    amxc_string_t string;
    char* buffer = NULL;

    assert_ptr_equal(amxc_string_take_buffer(NULL), NULL);
    assert_int_not_equal(amxc_string_push_buffer(NULL, NULL, 0), NULL);

    assert_int_equal(amxc_string_init(&string, 0), 0);
    assert_ptr_equal(amxc_string_take_buffer(&string), NULL);
    assert_int_equal(amxc_string_append(&string, "Hello World", 11), 0);

    buffer = amxc_string_take_buffer(&string);
    assert_ptr_not_equal(buffer, NULL);
    assert_string_equal(buffer, "Hello World");
    assert_int_equal(string.length, 0);
    assert_int_equal(string.last_used, 0);
    assert_ptr_equal(string.buffer, NULL);

    assert_int_equal(amxc_string_push_buffer(&string, NULL, 0), 0);
    assert_int_not_equal(amxc_string_push_buffer(&string, buffer, 0), 0);
    assert_int_not_equal(amxc_string_push_buffer(&string, buffer, 5), 0);
    assert_int_equal(amxc_string_push_buffer(&string, buffer, 12), 0);

    amxc_string_clean(&string);
}

void test_amxc_string_setf(UNUSED void** state) {
    amxc_string_t string;

    assert_int_equal(amxc_string_init(&string, 0), 0);
    assert_int_not_equal(amxc_string_setf(NULL, NULL), 0);
    assert_int_not_equal(amxc_string_setf(&string, NULL), 0);

    assert_int_equal(amxc_string_setf(&string, "Hello world"), 0);
    assert_int_equal(string.length, 12);
    assert_int_equal(string.last_used, 11);
    assert_string_equal(amxc_string_get(&string, 0), "Hello world");
    assert_int_equal(string.buffer[string.last_used], 0);

    assert_int_equal(amxc_string_setf(&string, "%s-%d", "acracadabra", 5), 0);
    assert_string_equal(amxc_string_get(&string, 0), "acracadabra-5");
    assert_int_equal(string.buffer[string.last_used], 0);


    assert_int_equal(amxc_string_setf(&string, "%d", 1), 0);

    amxc_string_clean(&string);
}

void test_amxc_string_appendf(UNUSED void** state) {
    amxc_string_t string;

    assert_int_equal(amxc_string_init(&string, 0), 0);
    assert_int_not_equal(amxc_string_appendf(NULL, NULL), 0);
    assert_int_not_equal(amxc_string_appendf(&string, NULL), 0);

    assert_int_equal(amxc_string_appendf(&string, "Hello world"), 0);
    assert_int_equal(string.length, 12);
    assert_int_equal(string.last_used, 11);
    assert_string_equal(string.buffer, "Hello world");

    assert_int_equal(amxc_string_appendf(&string, "%s-%d", "acracadabra", 5), 0);
    assert_string_equal(string.buffer, "Hello worldacracadabra-5");

    amxc_string_reset(&string);

    assert_int_equal(amxc_string_appendf(&string, "%d", 1), 0);

    amxc_string_clean(&string);
}

void test_amxc_string_prependf(UNUSED void** state) {
    amxc_string_t string;

    assert_int_equal(amxc_string_init(&string, 0), 0);
    assert_int_not_equal(amxc_string_prependf(NULL, NULL), 0);
    assert_int_not_equal(amxc_string_prependf(&string, NULL), 0);

    assert_int_equal(amxc_string_prependf(&string, "Hello world"), 0);
    assert_int_equal(string.length, 12);
    assert_int_equal(string.last_used, 11);
    assert_string_equal(string.buffer, "Hello world");

    assert_int_equal(amxc_string_prependf(&string, "%s-%d", "acracadabra", 5), 0);
    assert_string_equal(string.buffer, "acracadabra-5Hello world");

    amxc_string_reset(&string);

    assert_int_equal(amxc_string_prependf(&string, "%d", 1), 0);

    amxc_string_clean(&string);
}

void test_amxc_string_is_numeric(UNUSED void** state) {
    amxc_string_t string;

    assert_int_equal(amxc_string_init(&string, 0), 0);
    assert_false(amxc_string_is_numeric(&string));
    amxc_string_clean(&string);

    assert_int_equal(amxc_string_init(&string, 0), 0);
    assert_int_equal(amxc_string_set_at(&string,
                                        0,
                                        "hello world",
                                        11,
                                        amxc_string_no_flags), 0);
    assert_false(amxc_string_is_numeric(&string));
    amxc_string_clean(&string);

    assert_int_equal(amxc_string_init(&string, 0), 0);
    assert_int_equal(amxc_string_set_at(&string,
                                        0,
                                        "42world",
                                        7,
                                        amxc_string_no_flags), 0);
    assert_false(amxc_string_is_numeric(&string));
    amxc_string_clean(&string);

    assert_int_equal(amxc_string_init(&string, 0), 0);
    assert_int_equal(amxc_string_set_at(&string,
                                        0,
                                        "world42",
                                        7,
                                        amxc_string_no_flags), 0);
    assert_false(amxc_string_is_numeric(&string));
    amxc_string_clean(&string);

    assert_int_equal(amxc_string_init(&string, 0), 0);
    assert_int_equal(amxc_string_set_at(&string,
                                        0,
                                        "42 world",
                                        8,
                                        amxc_string_no_flags), 0);
    assert_false(amxc_string_is_numeric(&string));
    amxc_string_clean(&string);

    assert_int_equal(amxc_string_init(&string, 0), 0);
    assert_int_equal(amxc_string_set_at(&string,
                                        0,
                                        "42",
                                        2,
                                        amxc_string_no_flags), 0);
    assert_true(amxc_string_is_numeric(&string));
    amxc_string_clean(&string);

    assert_int_equal(amxc_string_init(&string, 0), 0);
    assert_int_equal(amxc_string_set_at(&string,
                                        0,
                                        "00",
                                        2,
                                        amxc_string_no_flags), 0);
    assert_true(amxc_string_is_numeric(&string));
    amxc_string_clean(&string);

    assert_int_equal(amxc_string_init(&string, 0), 0);
    assert_int_equal(amxc_string_set_at(&string,
                                        0,
                                        "2",
                                        1,
                                        amxc_string_no_flags), 0);
    assert_true(amxc_string_is_numeric(&string));
    amxc_string_clean(&string);
}

void test_amxc_string_resolve_env(UNUSED void** state) {
    amxc_string_t string;
    setenv("TestEnvVar", "MyValue", 1);
    setenv("RefVar", "$(TestEnvVar)", 1);

    assert_int_equal(amxc_string_init(&string, 0), 0);

    assert_int_equal(amxc_string_appendf(&string, "Resolves Env Var $(TestEnvVar)"), 0);
    assert_int_equal(amxc_string_resolve_env(&string), 1);
    assert_string_equal(string.buffer, "Resolves Env Var MyValue");
    amxc_string_reset(&string);

    assert_int_equal(amxc_string_appendf(&string, "$(TestEnvVar) $(TestEnvVar) $TestEnvVar TestEnvVar"), 0);
    assert_int_equal(amxc_string_resolve_env(&string), 2);
    assert_string_equal(string.buffer, "MyValue MyValue $TestEnvVar TestEnvVar");
    amxc_string_reset(&string);

    assert_int_equal(amxc_string_appendf(&string, "$(TestEnvVar) $(RefVar)"), 0);
    assert_int_equal(amxc_string_resolve_env(&string), 3);
    assert_string_equal(string.buffer, "MyValue MyValue");
    amxc_string_reset(&string);

    assert_int_equal(amxc_string_appendf(&string, "$(Dummy) $(RefVar)"), 0);
    assert_int_equal(amxc_string_resolve_env(&string), 3);
    assert_string_equal(string.buffer, " MyValue");
    amxc_string_reset(&string);

    assert_int_equal(amxc_string_appendf(&string, "$(Dummy) $(RefVar"), 0);
    assert_int_equal(amxc_string_resolve_env(&string), 1);
    assert_string_equal(string.buffer, " $(RefVar");
    amxc_string_reset(&string);

    assert_int_equal(amxc_string_appendf(&string, "$(Dummy - $(RefVar"), 0);
    assert_int_equal(amxc_string_resolve_env(&string), 0);
    assert_string_equal(string.buffer, "$(Dummy - $(RefVar");
    amxc_string_reset(&string);

    assert_int_equal(amxc_string_resolve_env(&string), 0);
    assert_int_equal(amxc_string_resolve_env(NULL), 0);

    amxc_string_clean(&string);
}

void test_amxc_string_resolve_var(UNUSED void** state) {
    amxc_string_t string;
    amxc_var_t data;

    amxc_var_init(&data);
    amxc_var_set_type(&data, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &data, "rw_data_path", "/tmp/");
    amxc_var_add_key(cstring_t, &data, "name", "a_name");
    amxc_var_add_key(cstring_t, &data, "ref", "${name}");

    assert_int_equal(amxc_string_init(&string, 0), 0);

    assert_int_equal(amxc_string_appendf(&string, "Resolves Var ${rw_data_path}"), 0);
    assert_int_equal(amxc_string_resolve_var(&string, &data), 1);
    assert_string_equal(string.buffer, "Resolves Var /tmp/");
    amxc_string_reset(&string);

    assert_int_equal(amxc_string_appendf(&string, "${name} ${rw_data_path} $rw_data_path rw_data_path"), 0);
    assert_int_equal(amxc_string_resolve_var(&string, &data), 2);
    assert_string_equal(string.buffer, "a_name /tmp/ $rw_data_path rw_data_path");
    amxc_string_reset(&string);

    assert_int_equal(amxc_string_appendf(&string, "${name} ${ref}"), 0);
    assert_int_equal(amxc_string_resolve_var(&string, &data), 3);
    assert_string_equal(string.buffer, "a_name a_name");
    amxc_string_reset(&string);

    assert_int_equal(amxc_string_appendf(&string, "${Dummy} ${ref}"), 0);
    assert_int_equal(amxc_string_resolve_var(&string, &data), 3);
    assert_string_equal(string.buffer, " a_name");
    amxc_string_reset(&string);

    assert_int_equal(amxc_string_resolve_var(&string, &data), 0);
    assert_int_equal(amxc_string_appendf(&string, "${Dummy} ${ref}"), 0);
    assert_int_equal(amxc_string_resolve_var(&string, NULL), 0);
    assert_int_equal(amxc_string_resolve_var(NULL, &data), 0);
    amxc_var_clean(&data);
    assert_int_equal(amxc_string_resolve_var(&string, &data), 0);

    amxc_var_clean(&data);
    amxc_string_clean(&string);
}

void test_amxc_string_resolve(UNUSED void** state) {
    amxc_string_t string;
    amxc_var_t data;

    setenv("TESTENV", "MyValue", 1);
    setenv("DATAREF", "${name}", 1);

    amxc_var_init(&data);
    amxc_var_set_type(&data, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &data, "rw_data_path", "/tmp/");
    amxc_var_add_key(cstring_t, &data, "name", "a_name");
    amxc_var_add_key(cstring_t, &data, "ref", "$(TESTENV)");

    assert_int_equal(amxc_string_init(&string, 0), 0);

    assert_int_equal(amxc_string_appendf(&string, "TESTENV = $(TESTENV) & name = ${name}"), 0);
    assert_int_equal(amxc_string_resolve(&string, &data), 2);
    assert_string_equal(string.buffer, "TESTENV = MyValue & name = a_name");
    amxc_string_reset(&string);

    assert_int_equal(amxc_string_appendf(&string, "name = $(DATAREF) & TESTENV = ${ref}"), 0);
    assert_int_equal(amxc_string_resolve(&string, &data), 4);
    assert_string_equal(string.buffer, "name = a_name & TESTENV = MyValue");
    amxc_string_reset(&string);

    assert_int_equal(amxc_string_appendf(&string, "${ref} ${rw_data_path} $(TESTENV) ${name}"), 0);
    assert_int_equal(amxc_string_resolve(&string, &data), 5);
    assert_string_equal(string.buffer, "MyValue /tmp/ MyValue a_name");
    amxc_string_reset(&string);

    assert_int_equal(amxc_string_appendf(&string, "$\\{ref\\} \\\" $\\(TESTENV\\) \\' \\\\"), 0);
    assert_int_equal(amxc_string_resolve(&string, &data), 7);
    assert_string_equal(string.buffer, "${ref} \" $(TESTENV) ' \\");
    amxc_string_reset(&string);

    assert_int_equal(amxc_string_appendf(&string, "\\${ref} \\$(TESTENV)"), 0);
    assert_int_equal(amxc_string_resolve(&string, &data), 2);
    assert_string_equal(string.buffer, "${ref} $(TESTENV)");
    amxc_string_reset(&string);

    assert_int_equal(amxc_string_appendf(&string, "${ref} \" $(TESTENV) ' \\"), 0);
    assert_int_equal(amxc_string_esc(&string), 7);
    assert_string_equal(string.buffer, "$\\{ref\\} \\\" $\\(TESTENV\\) \\' \\\\");
    amxc_string_reset(&string);

    assert_int_equal(amxc_string_appendf(&string, "\n\t\\n"), 0);
    assert_int_equal(amxc_string_esc(&string), 3);
    assert_string_equal(string.buffer, "\\n\\t\\\\n");
    assert_int_equal(amxc_string_append(&string, "\\", 1), 0);
    assert_int_equal(amxc_string_resolve_esc(&string), 3);
    assert_string_equal(string.buffer, "\n\t\\n\\");
    amxc_string_reset(&string);

    amxc_var_clean(&data);
    amxc_string_clean(&string);
}

void test_amxc_string_set_resolved(UNUSED void** state) {
    amxc_string_t string;
    amxc_var_t data;

    setenv("TESTENV", "MyValue", 1);
    setenv("DATAREF", "${name}", 1);

    amxc_var_init(&data);
    amxc_var_set_type(&data, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &data, "rw_data_path", "/tmp/");
    amxc_var_add_key(cstring_t, &data, "name", "a_name");
    amxc_var_add_key(cstring_t, &data, "ref", "$(TESTENV)");

    assert_int_equal(amxc_string_init(&string, 0), 0);

    assert_int_equal(amxc_string_set_resolved(&string, "TESTENV = $(TESTENV) & name = ${name}", &data), 2);
    assert_string_equal(string.buffer, "TESTENV = MyValue & name = a_name");

    assert_int_equal(amxc_string_set_resolved(&string, "This is text without variables", &data), 0);
    assert_true(amxc_string_is_empty(&string));

    assert_int_equal(amxc_string_set_resolved(&string, "This is text without $variables", &data), 0);
    assert_true(amxc_string_is_empty(&string));

    assert_int_equal(amxc_string_set_resolved(&string, NULL, &data), 0);
    assert_int_equal(amxc_string_set_resolved(&string, "", &data), 0);
    assert_int_equal(amxc_string_set_resolved(NULL, "TESTENV = $(TESTENV) & name = ${name}", &data), 0);

    amxc_var_clean(&data);
    amxc_string_clean(&string);
}

void test_amxc_string_new_resolved(UNUSED void** state) {
    amxc_string_t* string = NULL;
    amxc_var_t data;

    setenv("TESTENV", "MyValue", 1);
    setenv("DATAREF", "${name}", 1);

    amxc_var_init(&data);
    amxc_var_set_type(&data, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &data, "rw_data_path", "/tmp/");
    amxc_var_add_key(cstring_t, &data, "name", "a_name");
    amxc_var_add_key(cstring_t, &data, "ref", "$(TESTENV)");

    assert_int_equal(amxc_string_new_resolved(&string, "TESTENV = $(TESTENV) & name = ${name}", &data), 2);
    assert_ptr_not_equal(string, NULL);
    assert_string_equal(string->buffer, "TESTENV = MyValue & name = a_name");
    amxc_string_delete(&string);

    assert_int_equal(amxc_string_new_resolved(&string, "This is text without variables", &data), 0);
    assert_ptr_equal(string, NULL);

    assert_int_equal(amxc_string_new_resolved(&string, "This is text without $variables", &data), 0);
    assert_ptr_equal(string, NULL);

    assert_int_equal(amxc_string_new_resolved(&string, NULL, &data), 0);
    assert_ptr_equal(string, NULL);
    assert_int_equal(amxc_string_new_resolved(&string, "", &data), 0);
    assert_ptr_equal(string, NULL);
    assert_int_equal(amxc_string_new_resolved(NULL, "TESTENV = $(TESTENV) & name = ${name}", &data), -1);
    assert_ptr_equal(string, NULL);

    amxc_var_clean(&data);
}

void test_amxc_llist_add_string(UNUSED void** state) {
    amxc_llist_t list;
    amxc_llist_init(&list);

    assert_ptr_not_equal(amxc_llist_add_string(&list, "text1"), NULL);
    assert_ptr_not_equal(amxc_llist_add_string(&list, "text2"), NULL);
    assert_ptr_not_equal(amxc_llist_add_string(&list, "text3"), NULL);
    assert_ptr_equal(amxc_llist_add_string(&list, NULL), NULL);
    assert_ptr_equal(amxc_llist_add_string(&list, ""), NULL);
    assert_int_equal(amxc_llist_size(&list), 3);

    assert_ptr_equal(amxc_llist_add_string(NULL, "text4"), NULL);

    amxc_llist_clean(&list, amxc_string_list_it_free);
}

void test_amxc_string_search(UNUSED void** state) {
    amxc_string_t string;
    amxc_string_init(&string, 0);

    assert_int_equal(amxc_string_search(&string, "text", 0), -1);
    amxc_string_setf(&string, "This is some text");
    assert_int_equal(amxc_string_search(&string, "text", 0), 13);
    assert_int_equal(amxc_string_search(&string, "Too long needle, it can not be in the text", 0), -1);
    amxc_string_appendf(&string, ", adding more text");
    assert_int_equal(amxc_string_search(&string, "text", 0), 13);
    assert_int_equal(amxc_string_search(&string, "text", 17), 31);
    assert_int_equal(amxc_string_search(&string, "NOT IN THERE", 0), -1);

    assert_int_equal(amxc_string_search(NULL, "text", 0), -1);
    assert_int_equal(amxc_string_search(&string, "", 0), -1);
    assert_int_equal(amxc_string_search(&string, NULL, 0), -1);
    assert_int_equal(amxc_string_search(&string, "more", 1000), -1);

    amxc_string_clean(&string);
}

void test_amxc_string_replace(UNUSED void** state) {
    amxc_string_t string;
    amxc_string_init(&string, 0);

    assert_int_equal(amxc_string_replace(&string, "text", "dummy", 10), 0);
    amxc_string_setf(&string, "This is text and some more text and more text text");
    assert_int_equal(amxc_string_replace(&string, "text", "dummy", 1), 1);
    assert_int_equal(amxc_string_replace(&string, "text", "foo", 2), 2);
    assert_int_equal(amxc_string_replace(&string, "text", "dummy-foo extra text", UINT32_MAX), 1);
    assert_int_equal(amxc_string_replace(&string, "text", "foo", UINT32_MAX), 1);
    assert_int_equal(amxc_string_replace(&string, "text", "dummy", UINT32_MAX), 0);
    assert_string_equal(string.buffer, "This is dummy and some more foo and more foo dummy-foo extra foo");

    amxc_string_setf(&string, "This is text and some more text and more text text");
    assert_int_equal(amxc_string_replace(&string, "text", "text", UINT32_MAX), 4);
    assert_string_equal(string.buffer, "This is text and some more text and more text text");

    assert_int_equal(amxc_string_replace(NULL, "text", "dummy", 10), 0);
    assert_int_equal(amxc_string_replace(&string, "", "dummy", 10), 0);
    assert_int_equal(amxc_string_replace(&string, "text", "", 10), 4);
    assert_string_equal(string.buffer, "This is  and some more  and more  ");

    amxc_string_setf(&string, "abbaabbaabbaabbaabbaabba");
    assert_int_equal(amxc_string_replace(&string, "abba", "12", UINT32_MAX), 6);

    amxc_string_reset(&string);
    assert_int_equal(amxc_string_replace(&string, "", "", UINT32_MAX), 0);

    assert_int_equal(amxc_string_replace(&string, NULL, "more", 10), 0);
    assert_int_equal(amxc_string_replace(&string, "more", NULL, 10), 0);

    amxc_string_clean(&string);
}

void test_amxc_string_copy(UNUSED void** state) {
    amxc_string_t src;
    amxc_string_t dst;

    amxc_string_init(&src, 0);
    amxc_string_init(&dst, 0);

    amxc_string_setf(&src, "Hello world, I am so happy");
    assert_int_equal(amxc_string_copy(&dst, &src), 0);

    assert_int_equal(dst.length, src.length);
    assert_int_equal(dst.last_used, src.last_used);
    assert_string_equal(dst.buffer, src.buffer);

    amxc_string_clean(&src);
    assert_int_equal(amxc_string_copy(&dst, &src), 0);

    assert_int_not_equal(dst.length, src.length);
    assert_int_equal(dst.last_used, src.last_used);
    assert_string_equal(dst.buffer, "");

    amxc_string_clean(&src);
    amxc_string_clean(&dst);

    assert_int_not_equal(amxc_string_copy(&dst, NULL), 0);
    assert_int_not_equal(amxc_string_copy(NULL, &src), 0);
}

void test_amxc_string_reset(UNUSED void** state) {
    amxc_string_t string;
    amxc_string_init(&string, 0);
    amxc_string_setf(&string, "Hello world, I am so happy");

    amxc_string_reset(&string);
    assert_int_equal(string.last_used, 0);
    assert_string_equal(string.buffer, "");
    amxc_string_clean(&string);
}

void test_amxc_string_set(UNUSED void** state) {
    amxc_string_t string;
    amxc_string_init(&string, 0);

    assert_int_equal(amxc_string_set(&string, "Hello world, I am so happy"), 26);
    assert_string_equal(amxc_string_get(&string, 0), "Hello world, I am so happy");
    assert_int_equal(amxc_string_set(&string, NULL), 0);
    assert_string_equal(amxc_string_get(&string, 0), "");
    assert_int_equal(amxc_string_set(NULL, "Test"), 0);

    amxc_string_clean(&string);
}

void test_amxc_string_build_hex_binary(UNUSED void** state) {
    amxc_string_t string;
    amxc_ts_t time;
    char data[11] = { 0xA0, 0x1B, 0xC2, 0x3D, 0xE4, 0x00, 0xA5, 0x6B, 0xC7, 0x8D, 0xE9 };

    memset(&time, 0, sizeof(amxc_ts_t));
    amxc_ts_parse(&time, "2020-02-29T16:16:16.123456-01:15", strlen("2020-02-29T16:16:16.123456-01:15"));

    amxc_string_init(&string, 0);
    assert_int_equal(amxc_string_bytes_2_hex_binary(&string, data, 11, NULL), 0);
    assert_string_equal(amxc_string_get(&string, 0), "A01BC23DE400A56BC78DE9");
    assert_int_equal(amxc_string_text_length(&string), 11 * 2);

    assert_int_equal(amxc_string_bytes_2_hex_binary(&string, (char*) &time, sizeof(amxc_ts_t), NULL), 0);
    assert_string_equal(amxc_string_get(&string, 0), "E49F5A5E0000000000CA5B07B5FF0000");
    assert_int_equal(amxc_string_text_length(&string), sizeof(amxc_ts_t) * 2);

    amxc_string_clean(&string);
}

void test_amxc_string_build_byte_array(UNUSED void** state) {
    amxc_string_t string;
    amxc_ts_t* time = NULL;
    char time_str[40];
    char* data = NULL;
    uint32_t len = 0;
    char verify[11] = { 0xA0, 0x1B, 0xC2, 0x3D, 0xE4, 0x00, 0xA5, 0x6B, 0xC7, 0x8D, 0xE9 };

    amxc_string_init(&string, 0);

    amxc_string_setf(&string, "A01BC23DE400A56BC78DE9");
    assert_int_equal(amxc_string_hex_binary_2_bytes(&string, &data, &len, NULL), 0);
    assert_non_null(data);
    assert_int_equal(len, 11);
    for(int i = 0; i < 11; i++) {
        assert_int_equal(data[i], verify[i]);
    }
    free(data);

    amxc_string_setf(&string, "a01bc23de400a56bc78de9");
    assert_int_equal(amxc_string_hex_binary_2_bytes(&string, &data, &len, NULL), 0);
    assert_non_null(data);
    assert_int_equal(len, 11);
    for(int i = 0; i < 11; i++) {
        assert_int_equal(data[i], verify[i]);
    }
    free(data);

    amxc_string_setf(&string, "E49F5A5E0000000000CA5B07B5FF0000");
    assert_int_equal(amxc_string_hex_binary_2_bytes(&string, (char**) &time, &len, NULL), 0);
    assert_non_null(time);
    assert_int_equal(len, sizeof(amxc_ts_t));
    amxc_ts_format(time, time_str, 40);
    assert_string_equal(time_str, "2020-02-29T16:16:16.123456-01:15");
    free(time);

    amxc_string_setf(&string, "e49f5a5e0000000000ca5b07b5ff0000");
    assert_int_equal(amxc_string_hex_binary_2_bytes(&string, (char**) &time, &len, NULL), 0);
    assert_non_null(time);
    assert_int_equal(len, sizeof(amxc_ts_t));
    amxc_ts_format(time, time_str, 40);
    assert_string_equal(time_str, "2020-02-29T16:16:16.123456-01:15");
    free(time);

    amxc_string_clean(&string);
}

void test_amxc_string_build_hex_binary_using_separator(UNUSED void** state) {
    amxc_string_t string;
    char mac_addr[6] = { 0x02, 0x42, 0xac, 0x11, 0x00, 0x02 };

    amxc_string_init(&string, 0);
    assert_int_equal(amxc_string_bytes_2_hex_binary(&string, mac_addr, 6, ":"), 0);
    assert_string_equal(amxc_string_get(&string, 0), "02:42:AC:11:00:02");
    assert_int_equal(amxc_string_text_length(&string), 6 * 2 + 5);

    amxc_string_clean(&string);
}

void test_amxc_string_build_byte_array_with_separator(UNUSED void** state) {
    amxc_string_t string;
    char* data = NULL;
    uint32_t len = 0;
    char verify[6] = { 0x02, 0x42, 0xac, 0x11, 0x00, 0x02 };

    amxc_string_init(&string, 0);

    amxc_string_setf(&string, "02:42:ac:11:00:02");
    assert_int_equal(amxc_string_hex_binary_2_bytes(&string, &data, &len, ":"), 0);
    assert_non_null(data);
    assert_int_equal(len, 6);
    for(int i = 0; i < 6; i++) {
        assert_int_equal(data[i], verify[i]);
    }
    free(data);

    amxc_string_clean(&string);
}

void test_amxc_string_build_byte_array_with_invalid_string(UNUSED void** state) {
    amxc_string_t string;
    char* data = NULL;
    uint32_t len = 0;

    amxc_string_init(&string, 0);

    amxc_string_setf(&string, "A01BC23QQ400A56BC78DE9");
    assert_int_not_equal(amxc_string_hex_binary_2_bytes(&string, &data, &len, NULL), 0);
    assert_null(data);
    assert_int_equal(len, 0);

    amxc_string_setf(&string, "A01BC23400A56BC78DE9");
    assert_int_not_equal(amxc_string_hex_binary_2_bytes(NULL, &data, &len, NULL), 0);
    assert_null(data);
    assert_int_equal(len, 0);

    assert_int_not_equal(amxc_string_hex_binary_2_bytes(&string, NULL, &len, NULL), 0);
    assert_null(data);
    assert_int_equal(len, 0);

    assert_int_not_equal(amxc_string_hex_binary_2_bytes(&string, &data, NULL, NULL), 0);
    assert_null(data);
    assert_int_equal(len, 0);

    amxc_string_clean(&string);
}

void test_amxc_string_build_byte_array_from_incomplete_string(UNUSED void** state) {
    amxc_string_t string;
    char* data = NULL;
    uint32_t len = 0;

    amxc_string_init(&string, 0);

    amxc_string_setf(&string, "A");
    assert_int_equal(amxc_string_hex_binary_2_bytes(&string, &data, &len, NULL), 0);
    assert_non_null(data);
    assert_int_equal(len, 1);

    assert_int_equal(data[0], 10);

    free(data);
    amxc_string_clean(&string);
}

void test_amxc_string_toupper(UNUSED void** state) {
    amxc_string_t string;

    amxc_string_init(&string, 0);
    amxc_string_setf(&string, "This is some text with symbols ;=) and uppercase ABC");

    assert_int_equal(amxc_string_to_upper(&string), 0);
    assert_string_equal(amxc_string_get(&string, 0), "THIS IS SOME TEXT WITH SYMBOLS ;=) AND UPPERCASE ABC");

    assert_int_not_equal(amxc_string_to_upper(NULL), 0);

    amxc_string_clean(&string);
}

void test_amxc_string_tolower(UNUSED void** state) {
    amxc_string_t string;

    amxc_string_init(&string, 0);
    amxc_string_setf(&string, "THIS IS SOME TEXT WITH SYMBOLS ;=) AND LOWERCASE abc");

    assert_int_equal(amxc_string_to_lower(&string), 0);
    assert_string_equal(amxc_string_get(&string, 0), "this is some text with symbols ;=) and lowercase abc");

    assert_int_not_equal(amxc_string_to_lower(NULL), 0);

    amxc_string_clean(&string);
}

static bool s_accept_all_strings(UNUSED const char* string) {
    return true;
}

static bool s_reject_all_strings(UNUSED const char* string) {
    return false;
}

static bool s_reject_longer_than_5(const char* string) {
    return string != NULL && strlen(string) <= 5;
}

static void s_testhelper_vappendf_checked(const char* expected, amxc_string_is_safe_cb_t is_safe_cb, const char* fmt, ...) {
    va_list args;
    amxc_string_t str;
    int retval = -1;
    va_start(args, fmt);

    amxc_string_init(&str, 64);
    retval = amxc_string_vappendf_checked(&str, is_safe_cb, fmt, args);
    if(expected == NULL) {
        assert_int_not_equal(0, retval);
        assert_true(amxc_string_is_empty(&str));
    } else {
        assert_int_equal(0, retval);
        assert_string_equal(expected, amxc_string_get(&str, 0));
    }

    va_end(args);
    amxc_string_clean(&str);
}

void test_amxc_string_vappendf_checked(UNUSED void** state) {
    // Case: Normal case
    s_testhelper_vappendf_checked("abc 1 2 hi def", s_accept_all_strings, "abc %i %d %s def", 1, 2, "hi");

    // Case: special characters in format string
    s_testhelper_vappendf_checked("Hello\t\n\r!", s_accept_all_strings, "Hello\t\n\r%s", "!");

    // Case: "%%""
    s_testhelper_vappendf_checked("abc%def", s_accept_all_strings, "abc%%def");

    // Case: No leading text, no trailing text
    s_testhelper_vappendf_checked("hi123", s_accept_all_strings, "hi%i", 123);
    s_testhelper_vappendf_checked("123hi", s_accept_all_strings, "%ihi", 123);
    s_testhelper_vappendf_checked("123", s_accept_all_strings, "%i", 123);

    // Case: long format placeholders:
    s_testhelper_vappendf_checked("hi123", s_accept_all_strings, "hi%ld", 123);
    s_testhelper_vappendf_checked("hi123hello", s_accept_all_strings, "hi%ldhello", 123);

    // Case: fixed integer width macro compatibility (without crosscompiling unfortunately)
    s_testhelper_vappendf_checked(
        "int8_t: -128, "
        "int16_t: -32768, "
        "int32_t: -2147483648, "
        "int64_t: -9223372036854775808, "
        "uint8_t: 255, "
        "uint16_t: 65535, "
        "uint32_t: 4294967295, "
        "uint64_t: 18446744073709551615",
        s_accept_all_strings,
        "int8_t: %" PRId8
        ", int16_t: %" PRId16
        ", int32_t: %" PRId32
        ", int64_t: %" PRId64
        ", uint8_t: %" PRIu8
        ", uint16_t: %" PRIu16
        ", uint32_t: %" PRIu32
        ", uint64_t: %" PRIu64,
        INT8_MIN,
        INT16_MIN,
        INT32_MIN,
        INT64_MIN,
        UINT8_MAX,
        UINT16_MAX,
        UINT32_MAX,
        UINT64_MAX);

    // Case: one string not accepted:
    s_testhelper_vappendf_checked(NULL, s_reject_longer_than_5, "short: %i long: %s", 1234, "looong");
    s_testhelper_vappendf_checked(NULL, s_reject_longer_than_5, "long: %i short: %s", 123456, "short");

    // Case: char (because C has auto integer promotion for varargs)
    s_testhelper_vappendf_checked("hello", s_accept_all_strings, "%c%cllo", 104, 101);

    // Case: unsupported format string placeholders
    s_testhelper_vappendf_checked(NULL, s_accept_all_strings, "%20s", "hi");
    s_testhelper_vappendf_checked(NULL, s_accept_all_strings, "%.2f", 3.14159265);
    s_testhelper_vappendf_checked(NULL, s_accept_all_strings, "%03d", 4);
    s_testhelper_vappendf_checked(NULL, s_accept_all_strings, "%1$d", 5);
    s_testhelper_vappendf_checked(NULL, s_accept_all_strings, "%1$.*2$d", 2, 3);
}

void test_amxc_string_appendf_checked__normalcase(UNUSED void** state) {
    bool retval = -1;
    // GIVEN a string
    amxc_string_t str;
    amxc_string_init(&str, 64);
    amxc_string_set(&str, "the");

    // WHEN appending using a formatstring and a checker (which accepts):
    retval = amxc_string_appendf_checked(&str, s_accept_all_strings, "quick%ibrown%s", 123, "dog");

    // THEN the string is formatted
    assert_string_equal(amxc_string_get(&str, 0), "thequick123browndog");
    assert_int_equal(0, retval);

    amxc_string_clean(&str);
}

void test_amxc_string_appendf_checked__rejected(UNUSED void** state) {
    int retval = -1;
    // GIVEN a string
    amxc_string_t str;
    amxc_string_init(&str, 64);
    amxc_string_set(&str, "the");

    // WHEN appending using a formatstring and a checker (which rejects):
    retval = amxc_string_appendf_checked(&str, s_reject_all_strings, "quick%ibrown%s", 123, "dog");

    // THEN the formatting is rejected, and the string is cleared:
    assert_string_equal(amxc_string_get(&str, 0), "");
    assert_int_not_equal(0, retval);

    amxc_string_clean(&str);
}