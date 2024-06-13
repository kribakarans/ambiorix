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
#include <setjmp.h>
#include <string.h>
#include <cmocka.h>

#include <amxc/amxc_rbuffer.h>

#include "test_amxc_rbuffer.h"

#include <amxc/amxc_macros.h>
void amxc_rbuffer_new_delete_null_check(UNUSED void** state) {
    // passing NULL pointers should not lead to segfault
    assert_int_equal(amxc_rbuffer_new(NULL, 0), -1);
    amxc_rbuffer_delete(NULL);
}

void amxc_rbuffer_new_delete_check(UNUSED void** state) {
    amxc_rbuffer_t* rbuffer = NULL;

    assert_int_equal(amxc_rbuffer_new(&rbuffer, 30), 0);
    assert_ptr_not_equal(rbuffer, NULL);
    assert_ptr_not_equal(rbuffer->buffer_start, NULL);
    assert_ptr_equal(rbuffer->buffer_end, rbuffer->buffer_start + 30);
    assert_ptr_equal(rbuffer->read_pos, rbuffer->buffer_start);
    assert_ptr_equal(rbuffer->write_pos, rbuffer->buffer_start);

    amxc_rbuffer_delete(&rbuffer);
    assert_ptr_equal(rbuffer, NULL);

    assert_int_equal(amxc_rbuffer_new(&rbuffer, 0), 0);
    assert_ptr_not_equal(rbuffer, NULL);
    assert_ptr_equal(rbuffer->buffer_start, NULL);
    assert_ptr_equal(rbuffer->buffer_end, NULL);
    assert_ptr_equal(rbuffer->read_pos, NULL);
    assert_ptr_equal(rbuffer->write_pos, NULL);

    amxc_rbuffer_delete(&rbuffer);
    assert_ptr_equal(rbuffer, NULL);
}

void amxc_rbuffer_init_clean_null_check(UNUSED void** state) {
    // passing NULL pointers should not lead to segfault
    assert_int_equal(amxc_rbuffer_init(NULL, 0), -1);
    amxc_rbuffer_clean(NULL);
}

void amxc_rbuffer_init_clean_check(UNUSED void** state) {
    amxc_rbuffer_t rbuffer;

    assert_int_equal(amxc_rbuffer_init(&rbuffer, 30), 0);
    assert_ptr_not_equal(rbuffer.buffer_start, NULL);
    assert_ptr_equal(rbuffer.buffer_end, rbuffer.buffer_start + 30);
    assert_ptr_equal(rbuffer.read_pos, rbuffer.buffer_start);
    assert_ptr_equal(rbuffer.write_pos, rbuffer.buffer_start);

    amxc_rbuffer_clean(&rbuffer);
    assert_ptr_equal(rbuffer.buffer_start, NULL);
    assert_ptr_equal(rbuffer.buffer_end, NULL);
    assert_ptr_equal(rbuffer.read_pos, NULL);
    assert_ptr_equal(rbuffer.write_pos, NULL);
}

void amxc_rbuffer_grow_shrink_null_check(UNUSED void** state) {
    // passing NULL pointers should not lead to segfault
    assert_int_equal(amxc_rbuffer_grow(NULL, 0), -1);
    assert_int_equal(amxc_rbuffer_shrink(NULL, 0), -1);
}

void amxc_rbuffer_grow_check(UNUSED void** state) {
    amxc_rbuffer_t* rbuffer = NULL;

    assert_int_equal(amxc_rbuffer_new(&rbuffer, 30), 0);

    assert_int_equal(amxc_rbuffer_grow(rbuffer, 10), 0);
    assert_ptr_not_equal(rbuffer->buffer_start, NULL);
    assert_ptr_equal(rbuffer->buffer_end, rbuffer->buffer_start + 40);
    assert_ptr_equal(rbuffer->read_pos, rbuffer->buffer_start);
    assert_ptr_equal(rbuffer->write_pos, rbuffer->buffer_start);

    amxc_rbuffer_delete(&rbuffer);
}

void amxc_rbuffer_grow_read_before_write_check(UNUSED void** state) {
    amxc_rbuffer_t* rbuffer = NULL;

    assert_int_equal(amxc_rbuffer_new(&rbuffer, 30), 0);
    rbuffer->read_pos = rbuffer->buffer_start + 10;
    rbuffer->write_pos = rbuffer->buffer_start + 20;

    assert_int_equal(amxc_rbuffer_grow(rbuffer, 10), 0);
    assert_ptr_not_equal(rbuffer->buffer_start, NULL);
    assert_ptr_equal(rbuffer->buffer_end, rbuffer->buffer_start + 40);
    assert_ptr_equal(rbuffer->read_pos, rbuffer->buffer_start + 10);
    assert_ptr_equal(rbuffer->write_pos, rbuffer->buffer_start + 20);

    amxc_rbuffer_delete(&rbuffer);
}

void amxc_rbuffer_grow_write_before_read_check(UNUSED void** state) {
    amxc_rbuffer_t* rbuffer = NULL;

    assert_int_equal(amxc_rbuffer_new(&rbuffer, 30), 0);
    rbuffer->read_pos = rbuffer->buffer_start + 20;
    rbuffer->write_pos = rbuffer->buffer_start + 10;

    assert_int_equal(amxc_rbuffer_grow(rbuffer, 10), 0);
    assert_ptr_not_equal(rbuffer->buffer_start, NULL);
    assert_ptr_equal(rbuffer->buffer_end, rbuffer->buffer_start + 40);
    assert_ptr_equal(rbuffer->read_pos, rbuffer->buffer_start + 30);
    assert_ptr_equal(rbuffer->write_pos, rbuffer->buffer_start + 10);

    amxc_rbuffer_delete(&rbuffer);
}

void amxc_rbuffer_shrink_check(UNUSED void** state) {
    amxc_rbuffer_t* rbuffer = NULL;

    assert_int_equal(amxc_rbuffer_new(&rbuffer, 30), 0);

    assert_int_equal(amxc_rbuffer_shrink(rbuffer, 10), 0);
    assert_ptr_not_equal(rbuffer->buffer_start, NULL);
    assert_ptr_equal(rbuffer->buffer_end, rbuffer->buffer_start + 20);
    assert_ptr_equal(rbuffer->read_pos, rbuffer->buffer_start);
    assert_ptr_equal(rbuffer->write_pos, rbuffer->buffer_start);

    assert_int_equal(amxc_rbuffer_shrink(rbuffer, 30), -1);

    amxc_rbuffer_delete(&rbuffer);
}

void amxc_rbuffer_shrink_read_before_write_check(UNUSED void** state) {
    amxc_rbuffer_t* rbuffer = NULL;

    assert_int_equal(amxc_rbuffer_new(&rbuffer, 30), 0);
    rbuffer->read_pos = rbuffer->buffer_start + 5;
    rbuffer->write_pos = rbuffer->buffer_start + 15;

    assert_int_equal(amxc_rbuffer_shrink(rbuffer, 10), 0);
    assert_ptr_not_equal(rbuffer->buffer_start, NULL);
    assert_ptr_equal(rbuffer->buffer_end, rbuffer->buffer_start + 20);
    assert_ptr_equal(rbuffer->read_pos, rbuffer->buffer_start);
    assert_ptr_equal(rbuffer->write_pos, rbuffer->buffer_start + 10);

    amxc_rbuffer_delete(&rbuffer);
}

void amxc_rbuffer_shrink_read_before_write_data_loss_check(UNUSED void** state) {
    amxc_rbuffer_t* rbuffer = NULL;

    assert_int_equal(amxc_rbuffer_new(&rbuffer, 30), 0);
    rbuffer->read_pos = rbuffer->buffer_start + 5;
    rbuffer->write_pos = rbuffer->buffer_start + 25;

    assert_int_equal(amxc_rbuffer_shrink(rbuffer, 15), 0);
    assert_ptr_not_equal(rbuffer->buffer_start, NULL);
    assert_ptr_equal(rbuffer->buffer_end, rbuffer->buffer_start + 15);
    assert_ptr_equal(rbuffer->read_pos, rbuffer->buffer_start);
    assert_ptr_equal(rbuffer->write_pos, rbuffer->buffer_start + 15);

    amxc_rbuffer_delete(&rbuffer);
}

void amxc_rbuffer_shrink_write_before_read_check(UNUSED void** state) {
    amxc_rbuffer_t* rbuffer = NULL;

    assert_int_equal(amxc_rbuffer_new(&rbuffer, 30), 0);
    rbuffer->read_pos = rbuffer->buffer_start + 25;
    rbuffer->write_pos = rbuffer->buffer_start + 5;

    assert_int_equal(amxc_rbuffer_shrink(rbuffer, 10), 0);
    assert_ptr_not_equal(rbuffer->buffer_start, NULL);
    assert_ptr_equal(rbuffer->buffer_end, rbuffer->buffer_start + 20);
    assert_ptr_equal(rbuffer->read_pos, rbuffer->buffer_start + 15);
    assert_ptr_equal(rbuffer->write_pos, rbuffer->buffer_start + 5);

    amxc_rbuffer_delete(&rbuffer);
}

void amxc_rbuffer_shrink_write_before_read_data_loss_check(UNUSED void** state) {
    amxc_rbuffer_t* rbuffer = NULL;

    assert_int_equal(amxc_rbuffer_new(&rbuffer, 30), 0);
    rbuffer->read_pos = rbuffer->buffer_start + 15;
    rbuffer->write_pos = rbuffer->buffer_start + 5;

    assert_int_equal(amxc_rbuffer_shrink(rbuffer, 15), 0);
    assert_ptr_not_equal(rbuffer->buffer_start, NULL);
    assert_ptr_equal(rbuffer->buffer_end, rbuffer->buffer_start + 15);
    assert_ptr_equal(rbuffer->read_pos, rbuffer->buffer_start);
    assert_ptr_equal(rbuffer->write_pos, rbuffer->buffer_start + 15);

    amxc_rbuffer_delete(&rbuffer);

    assert_int_equal(amxc_rbuffer_new(&rbuffer, 30), 0);
    rbuffer->read_pos = rbuffer->buffer_start + 14;
    rbuffer->write_pos = rbuffer->buffer_start + 5;

    assert_int_equal(amxc_rbuffer_shrink(rbuffer, 10), 0);
    assert_ptr_not_equal(rbuffer->buffer_start, NULL);
    assert_ptr_equal(rbuffer->buffer_end, rbuffer->buffer_start + 20);
    assert_ptr_equal(rbuffer->read_pos, rbuffer->buffer_start + 4);
    assert_ptr_equal(rbuffer->write_pos, rbuffer->buffer_start + 3);

    amxc_rbuffer_delete(&rbuffer);
}

void amxc_rbuffer_shrink_full(UNUSED void** state) {
    amxc_rbuffer_t* rbuffer = NULL;

    assert_int_equal(amxc_rbuffer_new(&rbuffer, 30), 0);
    rbuffer->read_pos = rbuffer->buffer_start + 15;
    rbuffer->write_pos = rbuffer->buffer_start + 5;

    assert_int_equal(amxc_rbuffer_shrink(rbuffer, 30), 0);
    assert_ptr_equal(rbuffer->buffer_start, NULL);
    assert_ptr_equal(rbuffer->buffer_end, NULL);
    assert_ptr_equal(rbuffer->read_pos, NULL);
    assert_ptr_equal(rbuffer->write_pos, NULL);

    amxc_rbuffer_delete(&rbuffer);
}

void amxc_rbuffer_size_null_check(UNUSED void** state) {
    // passing NULL pointers should not lead to segfault
    assert_int_equal(amxc_rbuffer_size(NULL), 0);
}

void amxc_rbuffer_size_check(UNUSED void** state) {
    amxc_rbuffer_t* rbuffer = NULL;

    assert_int_equal(amxc_rbuffer_new(&rbuffer, 30), 0);
    assert_int_equal(amxc_rbuffer_size(rbuffer), 0);

    rbuffer->read_pos = rbuffer->buffer_start + 10;
    rbuffer->write_pos = rbuffer->buffer_start + 25;
    assert_int_equal(amxc_rbuffer_size(rbuffer), 15);

    rbuffer->read_pos = rbuffer->buffer_start + 20;
    rbuffer->write_pos = rbuffer->buffer_start + 5;
    assert_int_equal(amxc_rbuffer_size(rbuffer), 15);

    amxc_rbuffer_delete(&rbuffer);
}

void amxc_rbuffer_capacity_null_check(UNUSED void** state) {
    // passing NULL pointers should not lead to segfault
    assert_int_equal(amxc_rbuffer_capacity(NULL), 0);
}

void amxc_rbuffer_capacity_check(UNUSED void** state) {
    amxc_rbuffer_t* rbuffer = NULL;

    assert_int_equal(amxc_rbuffer_new(&rbuffer, 30), 0);
    assert_int_equal(amxc_rbuffer_capacity(rbuffer), 30);

    amxc_rbuffer_grow(rbuffer, 10);
    assert_int_equal(amxc_rbuffer_capacity(rbuffer), 40);

    amxc_rbuffer_shrink(rbuffer, 20);
    assert_int_equal(amxc_rbuffer_capacity(rbuffer), 20);

    amxc_rbuffer_delete(&rbuffer);
}

void amxc_rbuffer_is_empty_null_check(UNUSED void** state) {
    // passing NULL pointers should not lead to segfault
    assert_int_equal(amxc_rbuffer_is_empty(NULL), true);
}

void amxc_rbuffer_is_empty_check(UNUSED void** state) {
    amxc_rbuffer_t* rbuffer = NULL;

    assert_int_equal(amxc_rbuffer_new(&rbuffer, 30), 0);
    assert_int_equal(amxc_rbuffer_is_empty(rbuffer), true);

    rbuffer->read_pos = rbuffer->buffer_start + 10;
    rbuffer->write_pos = rbuffer->buffer_start + 10;
    assert_int_equal(amxc_rbuffer_is_empty(rbuffer), true);

    rbuffer->write_pos = rbuffer->buffer_start + 15;
    assert_int_equal(amxc_rbuffer_is_empty(rbuffer), false);

    rbuffer->read_pos = rbuffer->buffer_start + 10;
    rbuffer->write_pos = rbuffer->buffer_start + 5;
    assert_int_equal(amxc_rbuffer_is_empty(rbuffer), false);

    amxc_rbuffer_delete(&rbuffer);
}

void amxc_rbuffer_write_null_check(UNUSED void** state) {
    // passing NULL pointers should not lead to segfault
    assert_int_equal(amxc_rbuffer_write(NULL, NULL, 0), -1);
}

void amxc_rbuffer_write_buffer_empty_check(UNUSED void** state) {
    amxc_rbuffer_t* rbuffer = NULL;
    const char* data = "0123456789";

    assert_int_equal(amxc_rbuffer_new(&rbuffer, 30), 0);

    assert_int_equal(amxc_rbuffer_write(rbuffer, data, 5), 5);
    assert_ptr_equal(rbuffer->read_pos, rbuffer->buffer_start);
    assert_ptr_equal(rbuffer->write_pos, rbuffer->buffer_start + 5);
    assert_int_equal(strncmp(rbuffer->buffer_start, data, 5), 0);

    assert_int_equal(amxc_rbuffer_write(rbuffer, data, 7), 7);
    assert_ptr_equal(rbuffer->read_pos, rbuffer->buffer_start);
    assert_ptr_equal(rbuffer->write_pos, rbuffer->buffer_start + 12);
    assert_int_equal(strncmp(rbuffer->buffer_start, data, 5), 0);
    assert_int_equal(strncmp(rbuffer->buffer_start + 5, data, 7), 0);

    amxc_rbuffer_delete(&rbuffer);
}

void amxc_rbuffer_write_buffer_wrap_buffer_check(UNUSED void** state) {
    amxc_rbuffer_t* rbuffer = NULL;
    const char* data = "0123456789";

    assert_int_equal(amxc_rbuffer_new(&rbuffer, 30), 0);
    rbuffer->read_pos = rbuffer->buffer_start + 25;
    rbuffer->write_pos = rbuffer->buffer_start + 25;

    assert_int_equal(amxc_rbuffer_write(rbuffer, data, 10), 10);
    assert_ptr_equal(rbuffer->read_pos, rbuffer->buffer_start + 25);
    assert_ptr_equal(rbuffer->write_pos, rbuffer->buffer_start + 5);
    assert_int_equal(strncmp(rbuffer->buffer_start + 25, data, 5), 0);
    assert_int_equal(strncmp(rbuffer->buffer_start, data + 5, 5), 0);

    amxc_rbuffer_delete(&rbuffer);
}

void amxc_rbuffer_write_buffer_need_to_grow_check(UNUSED void** state) {
    amxc_rbuffer_t* rbuffer = NULL;
    const char* data = "0123456789";

    assert_int_equal(amxc_rbuffer_new(&rbuffer, 30), 0);
    rbuffer->read_pos = rbuffer->buffer_start + 1;
    rbuffer->write_pos = rbuffer->buffer_start + 0;

    assert_int_equal(amxc_rbuffer_write(rbuffer, data, 10), 10);
    assert_int_equal(amxc_rbuffer_capacity(rbuffer), 50);
    assert_ptr_equal(rbuffer->read_pos, rbuffer->buffer_start + 21);
    assert_ptr_equal(rbuffer->write_pos, rbuffer->buffer_start + 10);
    assert_int_equal(strncmp(rbuffer->buffer_start, data, 10), 0);

    amxc_rbuffer_delete(&rbuffer);
}

void amxc_rbuffer_read_null_check(UNUSED void** state) {
    // passing NULL pointers should not lead to segfault
    assert_int_equal(amxc_rbuffer_read(NULL, NULL, 10), -1);

    amxc_rbuffer_t* rbuffer = NULL;
    assert_int_equal(amxc_rbuffer_new(&rbuffer, 30), 0);
    assert_int_equal(amxc_rbuffer_read(rbuffer, NULL, 10), -1);
    amxc_rbuffer_delete(&rbuffer);
}

void amxc_rbuffer_read_buffer_empty_check(UNUSED void** state) {
    amxc_rbuffer_t* rbuffer = NULL;
    char buffer[10] = "";

    assert_int_equal(amxc_rbuffer_new(&rbuffer, 30), 0);

    assert_int_equal(amxc_rbuffer_read(rbuffer, buffer, 5), 0);
    assert_ptr_equal(rbuffer->read_pos, rbuffer->buffer_start);
    assert_ptr_equal(rbuffer->write_pos, rbuffer->buffer_start);

    amxc_rbuffer_delete(&rbuffer);
}

void amxc_rbuffer_read_zero_bytes_check(UNUSED void** state) {
    amxc_rbuffer_t* rbuffer = NULL;
    const char* data = "0123456789";
    char buffer[10] = "";

    assert_int_equal(amxc_rbuffer_new(&rbuffer, 30), 0);

    assert_int_equal(amxc_rbuffer_write(rbuffer, data, 10), 10);

    assert_int_equal(amxc_rbuffer_read(rbuffer, buffer, 0), 0);
    assert_ptr_equal(rbuffer->read_pos, rbuffer->buffer_start);
    assert_ptr_equal(rbuffer->write_pos, rbuffer->buffer_start + 10);

    amxc_rbuffer_delete(&rbuffer);
}

void amxc_rbuffer_read_check(UNUSED void** state) {
    amxc_rbuffer_t* rbuffer = NULL;
    const char* data = "0123456789";
    char buffer[10] = "";

    assert_int_equal(amxc_rbuffer_new(&rbuffer, 30), 0);

    assert_int_equal(amxc_rbuffer_write(rbuffer, data, 10), 10);

    assert_int_equal(amxc_rbuffer_read(rbuffer, buffer, 5), 5);
    assert_ptr_equal(rbuffer->read_pos, rbuffer->buffer_start + 5);
    assert_ptr_equal(rbuffer->write_pos, rbuffer->buffer_start + 10);
    assert_int_equal(strncmp(buffer, data, 5), 0);

    assert_int_equal(amxc_rbuffer_read(rbuffer, buffer, 5), 5);
    assert_ptr_equal(rbuffer->read_pos, rbuffer->buffer_start + 10);
    assert_ptr_equal(rbuffer->write_pos, rbuffer->buffer_start + 10);
    assert_int_equal(strncmp(buffer, data + 5, 5), 0);

    assert_int_equal(amxc_rbuffer_read(rbuffer, buffer, 5), 0);
    assert_ptr_equal(rbuffer->read_pos, rbuffer->buffer_start + 10);
    assert_ptr_equal(rbuffer->write_pos, rbuffer->buffer_start + 10);

    amxc_rbuffer_delete(&rbuffer);
}

void amxc_rbuffer_read_short_check(UNUSED void** state) {
    amxc_rbuffer_t* rbuffer = NULL;
    const char* data = "0123456789";
    char buffer[30] = "";

    assert_int_equal(amxc_rbuffer_new(&rbuffer, 30), 0);

    assert_int_equal(amxc_rbuffer_write(rbuffer, data, 10), 10);
    assert_int_equal(amxc_rbuffer_write(rbuffer, data, 10), 10);

    assert_int_equal(amxc_rbuffer_read(rbuffer, buffer, 30), 20);
    assert_ptr_equal(rbuffer->read_pos, rbuffer->buffer_start + 20);
    assert_ptr_equal(rbuffer->write_pos, rbuffer->buffer_start + 20);
    assert_int_equal(strncmp(buffer, data, 10), 0);
    assert_int_equal(strncmp(buffer + 10, data, 10), 0);

    rbuffer->read_pos = rbuffer->buffer_start + 15;
    rbuffer->write_pos = rbuffer->buffer_start + 15;
    assert_int_equal(amxc_rbuffer_write(rbuffer, data, 10), 10);
    assert_int_equal(amxc_rbuffer_write(rbuffer, data, 10), 10);

    assert_int_equal(amxc_rbuffer_read(rbuffer, buffer, 10), 10);
    assert_ptr_equal(rbuffer->read_pos, rbuffer->buffer_start + 25);
    assert_ptr_equal(rbuffer->write_pos, rbuffer->buffer_start + 5);
    assert_int_equal(strncmp(buffer, data, 10), 0);

    amxc_rbuffer_delete(&rbuffer);
}

void amxc_rbuffer_read_wrap_check(UNUSED void** state) {
    amxc_rbuffer_t* rbuffer = NULL;
    const char* data = "0123456789";
    char buffer[10] = "";

    assert_int_equal(amxc_rbuffer_new(&rbuffer, 30), 0);
    rbuffer->read_pos = rbuffer->buffer_start + 25;
    rbuffer->write_pos = rbuffer->buffer_start + 25;

    assert_int_equal(amxc_rbuffer_write(rbuffer, data, 10), 10);
    assert_ptr_equal(rbuffer->read_pos, rbuffer->buffer_start + 25);
    assert_ptr_equal(rbuffer->write_pos, rbuffer->buffer_start + 5);

    assert_int_equal(amxc_rbuffer_read(rbuffer, buffer, 10), 10);
    assert_ptr_equal(rbuffer->read_pos, rbuffer->buffer_start + 5);
    assert_ptr_equal(rbuffer->write_pos, rbuffer->buffer_start + 5);
    assert_int_equal(strncmp(buffer, data, 10), 0);

    amxc_rbuffer_delete(&rbuffer);
}
