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

#include <stdio.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <amxc/amxc_array.h>

#include "test_amxc_array.h"

#include <amxc/amxc_macros.h>
static int counter = 0;

static amxc_array_t* array1 = NULL;
char data[] = "abcdefghij";

static void amxc_reset_test_array() {
    amxc_array_clean(array1, NULL);
    amxc_array_init(array1, 10);
    amxc_array_set_data_at(array1, 3, &data[3]);
    amxc_array_set_data_at(array1, 6, &data[6]);
    amxc_array_set_data_at(array1, 9, &data[9]);
}

static void amxc_check_array_it_delete(amxc_array_it_t* it) {
    counter++;
    assert_ptr_not_equal(it->data, NULL);
}

int test_amxc_array_setup(UNUSED void** state) {
    assert_int_equal(amxc_array_new(&array1, 10), 0);
    assert_ptr_not_equal(array1, NULL);
    assert_ptr_not_equal(array1->buffer, NULL);

    amxc_array_set_data_at(array1, 3, &data[3]);
    assert_int_equal(array1->first_used, 3);
    assert_int_equal(array1->last_used, 3);

    amxc_array_set_data_at(array1, 6, &data[6]);
    assert_int_equal(array1->first_used, 3);
    assert_int_equal(array1->last_used, 6);

    amxc_array_set_data_at(array1, 9, &data[9]);
    assert_int_equal(array1->first_used, 3);
    assert_int_equal(array1->last_used, 9);

    return 0;
}

int test_amxc_array_teardown(UNUSED void** state) {
    amxc_array_delete(&array1, NULL);

    return 0;
}


void test_amxc_array_new_delete_null(UNUSED void** state) {
    amxc_array_t* array = NULL;

    // passing NULL pointers should not lead to segfault
    assert_int_not_equal(amxc_array_new(NULL, 0), 0);
    assert_ptr_equal(array, NULL);
    amxc_array_delete(NULL, NULL);
}

void test_amxc_array_init_clean_null(UNUSED void** state) {
    // passing NULL pointers should not lead to segfault
    assert_int_equal(amxc_array_init(NULL, 0), -1);
    amxc_array_clean(NULL, NULL);
}

void test_amxc_array_init_clean(UNUSED void** state) {
    amxc_array_t array;

    // initialize array with 0 items
    assert_int_equal(amxc_array_init(&array, 0), 0);
    assert_ptr_equal(array.buffer, NULL);
    assert_int_equal(array.items, 0);
    amxc_array_clean(&array, NULL);
    assert_int_equal(array.items, 0);

    // initialize array with 10 items
    assert_int_equal(amxc_array_init(&array, 10), 0);
    assert_ptr_not_equal(array.buffer, NULL);
    assert_int_equal(array.items, 10);
    amxc_array_clean(&array, NULL);
    assert_int_equal(array.items, 0);
}

void test_amxc_array_clean_cb(UNUSED void** state) {
    amxc_array_t array;

    // initialize array with 10 items
    assert_int_equal(amxc_array_init(&array, 10), 0);
    assert_ptr_not_equal(array.buffer, NULL);
    assert_int_equal(array.items, 10);
    counter = 0;
    amxc_array_clean(&array, NULL);
    assert_int_equal(counter, 0);
    assert_int_equal(array.items, 0);

    // initialize array with 10 items
    assert_int_equal(amxc_array_init(&array, 10), 0);
    assert_ptr_not_equal(array.buffer, amxc_check_array_it_delete);
    assert_int_equal(array.items, 10);
    const char data[10] = "1234567890";
    for(unsigned int index = 0; index < 10; index++) {
        assert_ptr_equal(amxc_array_set_data_at(&array, index, (void*) &data[index]), &array.buffer[index]);
    }
    counter = 0;
    amxc_array_clean(&array, amxc_check_array_it_delete);
    assert_int_equal(array.items, 0);
    assert_int_equal(counter, 10);
}

void test_amxc_array_get_at_null(UNUSED void** state) {
    amxc_array_t* array = NULL;
    amxc_array_it_t* it = NULL;

    it = amxc_array_get_at(NULL, 5);
    assert_ptr_equal(it, NULL);

    assert_int_equal(amxc_array_new(&array, 0), 0);
    it = amxc_array_get_at(array, 0);
    assert_ptr_equal(it, NULL);

    amxc_array_delete(&array, NULL);
    assert_ptr_equal(array, NULL);
}

void test_amxc_array_get_at(UNUSED void** state) {
    amxc_array_it_t* it = NULL;
    for(int i = 0; i < 10; i++) {
        it = amxc_array_get_at(array1, i);
        assert_ptr_equal(it, &array1->buffer[i]);
        assert_ptr_equal(it->array, array1);
        if((i == 0) || ((i % 3) != 0)) {
            assert_ptr_equal(it->data, NULL);
        } else {
            assert_ptr_equal(it->data, &data[i]);
        }
    }
}

void test_amxc_array_get_first_null(UNUSED void** state) {
    amxc_array_it_t* it = NULL;
    it = amxc_array_get_first(NULL);
    assert_ptr_equal(it, NULL);
}

void test_amxc_array_get_first(UNUSED void** state) {
    amxc_array_it_t* it = NULL;
    it = amxc_array_get_first(array1);
    assert_ptr_equal(it, &array1->buffer[3]);
    assert_ptr_equal(it->array, array1);
    assert_ptr_equal(it->data, &data[3]);
}

void test_amxc_array_get_first_empty(UNUSED void** state) {
    amxc_array_t* array = NULL;
    assert_int_not_equal(amxc_array_new(&array, 10), -1);
    assert_ptr_not_equal(array, NULL);
    assert_ptr_not_equal(array->buffer, NULL);

    amxc_array_it_t* it = NULL;
    it = amxc_array_get_first(array);
    assert_ptr_equal(it, NULL);

    amxc_array_delete(&array, NULL);
}

void test_amxc_array_get_first_free_null(UNUSED void** state) {
    amxc_array_it_t* it = NULL;
    it = amxc_array_get_first_free(NULL);
    assert_ptr_equal(it, NULL);
}

void test_amxc_array_get_first_free(UNUSED void** state) {
    amxc_array_it_t* it = NULL;
    it = amxc_array_get_first_free(array1);
    assert_ptr_equal(it, &array1->buffer[0]);
    assert_ptr_equal(it->array, array1);
    assert_ptr_equal(it->data, NULL);
}

void test_amxc_array_get_last_null(UNUSED void** state) {
    amxc_array_it_t* it = NULL;
    it = amxc_array_get_last(NULL);
    assert_ptr_equal(it, NULL);
}

void test_amxc_array_get_last(UNUSED void** state) {
    amxc_array_it_t* it = NULL;
    it = amxc_array_get_last(array1);
    assert_ptr_equal(it, &array1->buffer[9]);
    assert_ptr_equal(it->array, array1);
    assert_ptr_equal(it->data, &data[9]);
}

void test_amxc_array_get_last_empty(UNUSED void** state) {
    amxc_array_t* array = NULL;
    assert_int_not_equal(amxc_array_new(&array, 10), -1);
    assert_ptr_not_equal(array, NULL);
    assert_ptr_not_equal(array->buffer, NULL);

    amxc_array_it_t* it = NULL;
    it = amxc_array_get_last(array);
    assert_ptr_equal(it, NULL);

    amxc_array_delete(&array, NULL);
}

void test_amxc_array_get_last_free_null(UNUSED void** state) {
    amxc_array_it_t* it = NULL;
    it = amxc_array_get_last_free(NULL);
    assert_ptr_equal(it, NULL);
}

void test_amxc_array_get_last_free(UNUSED void** state) {
    amxc_array_it_t* it = NULL;
    it = amxc_array_get_last_free(array1);
    assert_ptr_not_equal(it, NULL);
    assert_ptr_equal(it, &array1->buffer[8]);
    assert_ptr_equal(it->array, array1);
    assert_ptr_equal(it->data, NULL);
}

void test_amxc_array_get_first_free_full(UNUSED void** state) {
    for(int i = 0; i < 10; i++) {
        amxc_array_set_data_at(array1, i, &data[i]);
    }

    amxc_array_it_t* it = amxc_array_get_first_free(array1);
    assert_ptr_equal(it, NULL);
}

void test_amxc_array_get_last_free_full(UNUSED void** state) {
    for(int i = 0; i < 10; i++) {
        amxc_array_set_data_at(array1, i, &data[i]);
    }

    amxc_array_it_t* it = amxc_array_get_last_free(array1);
    assert_ptr_equal(it, NULL);
}

void test_amxc_array_it_get_next_null(UNUSED void** state) {
    amxc_array_it_t* it = NULL;
    it = amxc_array_it_get_next(NULL);
    assert_ptr_equal(it, NULL);
}

void test_amxc_array_it_get_next(UNUSED void** state) {
    amxc_array_it_t* it = NULL;
    it = amxc_array_get_first(array1);

    it = amxc_array_it_get_next(it);
    assert_ptr_equal(it, &array1->buffer[6]);
    assert_ptr_equal(it->array, array1);
    assert_ptr_equal(it->data, &data[6]);

    it = amxc_array_it_get_next(it);
    assert_ptr_equal(it, &array1->buffer[9]);
    assert_ptr_equal(it->array, array1);
    assert_ptr_equal(it->data, &data[9]);

    it = amxc_array_it_get_next(it);
    assert_ptr_equal(it, NULL);
}

void test_amxc_array_it_get_next_free_null(UNUSED void** state) {
    amxc_array_it_t* it = NULL;
    it = amxc_array_it_get_next_free(NULL);
    assert_ptr_equal(it, NULL);
}

void test_amxc_array_it_get_next_free(UNUSED void** state) {
    amxc_array_it_t* it = NULL;
    it = amxc_array_get_first(array1);

    it = amxc_array_it_get_next_free(it);
    assert_ptr_equal(it, &array1->buffer[4]);
    assert_ptr_equal(it->array, array1);
    assert_ptr_equal(it->data, NULL);

    it = amxc_array_it_get_next_free(it);
    assert_ptr_equal(it, &array1->buffer[5]);
    assert_ptr_equal(it->array, array1);
    assert_ptr_equal(it->data, NULL);

    it = amxc_array_it_get_next_free(it);
    assert_ptr_equal(it, &array1->buffer[7]);
    assert_ptr_equal(it->array, array1);
    assert_ptr_equal(it->data, NULL);

    it = amxc_array_it_get_next_free(it);
    assert_ptr_equal(it, &array1->buffer[8]);
    assert_ptr_equal(it->array, array1);
    assert_ptr_equal(it->data, NULL);

    it = amxc_array_it_get_next_free(it);
    assert_ptr_equal(it, NULL);
}

void test_amxc_array_it_get_previous_null(UNUSED void** state) {
    amxc_array_it_t* it = NULL;
    it = amxc_array_it_get_previous(NULL);
    assert_ptr_equal(it, NULL);
}

void test_amxc_array_it_get_previous(UNUSED void** state) {
    amxc_array_it_t* it = NULL;
    amxc_array_it_t* rit = amxc_array_set_data_at(array1, 1, &data[1]);

    it = amxc_array_get_last(array1);

    it = amxc_array_it_get_previous(it);
    assert_ptr_equal(it, &array1->buffer[6]);
    assert_ptr_equal(it->array, array1);
    assert_ptr_equal(it->data, &data[6]);

    it = amxc_array_it_get_previous(it);
    assert_ptr_equal(it, &array1->buffer[3]);
    assert_ptr_equal(it->array, array1);
    assert_ptr_equal(it->data, &data[3]);

    it = amxc_array_it_get_previous(it);
    assert_ptr_equal(it, &array1->buffer[1]);
    assert_ptr_equal(it->array, array1);
    assert_ptr_equal(it->data, &data[1]);

    it = amxc_array_it_get_previous(it);
    assert_ptr_equal(it, NULL);

    amxc_array_it_take_data(rit);
}

void test_amxc_array_it_get_previous_free_null(UNUSED void** state) {
    amxc_array_it_t* it = NULL;
    it = amxc_array_it_get_previous_free(NULL);
    assert_ptr_equal(it, NULL);
}

void test_amxc_array_it_get_previous_free(UNUSED void** state) {
    amxc_array_it_t* it = NULL;
    it = amxc_array_get_last(array1);

    it = amxc_array_it_get_previous_free(it);
    assert_ptr_equal(it, &array1->buffer[8]);
    assert_ptr_equal(it->array, array1);
    assert_ptr_equal(it->data, NULL);

    it = amxc_array_it_get_previous_free(it);
    assert_ptr_equal(it, &array1->buffer[7]);
    assert_ptr_equal(it->array, array1);
    assert_ptr_equal(it->data, NULL);

    it = amxc_array_it_get_previous_free(it);
    assert_ptr_equal(it, &array1->buffer[5]);
    assert_ptr_equal(it->array, array1);
    assert_ptr_equal(it->data, NULL);

    it = amxc_array_it_get_previous_free(it);
    assert_ptr_equal(it, &array1->buffer[4]);
    assert_ptr_equal(it->array, array1);
    assert_ptr_equal(it->data, NULL);

    it = amxc_array_it_get_previous_free(it);
    assert_ptr_equal(it, &array1->buffer[2]);
    assert_ptr_equal(it->array, array1);
    assert_ptr_equal(it->data, NULL);

    it = amxc_array_it_get_previous_free(it);
    assert_ptr_equal(it, &array1->buffer[1]);
    assert_ptr_equal(it->array, array1);
    assert_ptr_equal(it->data, NULL);

    it = amxc_array_it_get_previous_free(it);
    assert_ptr_equal(it, &array1->buffer[0]);
    assert_ptr_equal(it->array, array1);
    assert_ptr_equal(it->data, NULL);

    it = amxc_array_it_get_previous_free(it);
    assert_ptr_equal(it, NULL);
}

void test_amxc_array_it_get_data_null(UNUSED void** state) {
    assert_ptr_equal(amxc_array_it_get_data(NULL), NULL);
}

void test_amxc_array_it_get_data(UNUSED void** state) {
    amxc_array_it_t* it = NULL;
    it = amxc_array_get_at(array1, 0);
    assert_ptr_equal(amxc_array_it_get_data(it), NULL);

    it = amxc_array_get_at(array1, 1);
    assert_ptr_equal(amxc_array_it_get_data(it), NULL);

    it = amxc_array_get_at(array1, 2);
    assert_ptr_equal(amxc_array_it_get_data(it), NULL);

    it = amxc_array_get_at(array1, 3);
    assert_ptr_equal(amxc_array_it_get_data(it), &data[3]);
}

void test_amxc_array_is_empty_null(UNUSED void** state) {
    assert_int_equal(amxc_array_is_empty(NULL), true);
}

void test_amxc_array_is_empty(UNUSED void** state) {
    assert_int_equal(amxc_array_is_empty(array1), false);
    amxc_array_clean(array1, NULL);
    assert_int_equal(amxc_array_is_empty(array1), true);
}

void test_amxc_array_size_null(UNUSED void** state) {
    assert_int_equal(amxc_array_size(NULL), 0);
}

void test_amxc_array_size(UNUSED void** state) {
    assert_int_equal(amxc_array_size(array1), 3);
}

void test_amxc_array_capacity_null(UNUSED void** state) {
    assert_int_equal(amxc_array_capacity(NULL), 0);
}

void test_amxc_array_capacity(UNUSED void** state) {
    assert_int_equal(amxc_array_capacity(array1), 10);
}

void test_amxc_array_grow_null(UNUSED void** state) {
    assert_int_equal(amxc_array_grow(NULL, 0), -1);
}

void test_amxc_array_grow(UNUSED void** state) {
    assert_int_equal(amxc_array_grow(array1, 10), 0);
    assert_int_equal(amxc_array_capacity(array1), 20);
    assert_int_equal(array1->first_used, 3);
    assert_int_equal(array1->last_used, 9);

    assert_int_equal(amxc_array_grow(array1, 0), 0);
    assert_int_equal(amxc_array_capacity(array1), 20);
    assert_int_equal(array1->first_used, 3);
    assert_int_equal(array1->last_used, 9);

    assert_int_equal(amxc_array_shrink(array1, 10, NULL), 0);
}

void test_amxc_array_shrink_null(UNUSED void** state) {
    assert_int_equal(amxc_array_shrink(NULL, 0, NULL), -1);
}

void test_amxc_array_shrink(UNUSED void** state) {
    assert_int_equal(amxc_array_shrink(array1, 15, NULL), -1);

    assert_int_equal(amxc_array_shrink(array1, 5, NULL), 0);
    assert_int_equal(amxc_array_capacity(array1), 5);
    assert_int_equal(array1->first_used, 3);
    assert_int_equal(array1->last_used, 3);

    assert_int_equal(amxc_array_shrink(array1, 3, NULL), 0);
    assert_int_equal(amxc_array_capacity(array1), 2);
    assert_int_equal(array1->first_used, 0);
    assert_int_equal(array1->last_used, 0);

    assert_int_equal(amxc_array_shrink(array1, 2, NULL), 0);
    assert_int_equal(amxc_array_capacity(array1), 0);
    assert_int_equal(array1->first_used, 0);
    assert_int_equal(array1->last_used, 0);

    assert_int_equal(amxc_array_grow(array1, 10), 0);
    amxc_array_set_data_at(array1, 3, &data[3]);
    assert_int_equal(array1->first_used, 3);
    assert_int_equal(array1->last_used, 3);

    amxc_array_set_data_at(array1, 6, &data[6]);
    assert_int_equal(array1->first_used, 3);
    assert_int_equal(array1->last_used, 6);

    amxc_array_set_data_at(array1, 9, &data[9]);
    assert_int_equal(array1->first_used, 3);
    assert_int_equal(array1->last_used, 9);
}

void test_amxc_array_shift_null(UNUSED void** state) {
    assert_int_equal(amxc_array_shift_left(NULL, 0, NULL), -1);
    assert_int_equal(amxc_array_shift_right(NULL, 0, NULL), -1);
}

void test_amxc_array_shift_left(UNUSED void** state) {
    assert_int_equal(amxc_array_shift_left(array1, 15, NULL), -1);
    assert_int_equal(amxc_array_shift_left(array1, 0, NULL), 0);

    assert_int_equal(amxc_array_shift_left(array1, 1, NULL), 0);
    assert_int_equal(amxc_array_capacity(array1), 10);
    assert_int_equal(amxc_array_size(array1), 3);
    assert_int_equal(array1->first_used, 2);
    assert_int_equal(array1->last_used, 8);
    assert_ptr_equal(array1->buffer[2].data, &data[3]);
    assert_ptr_equal(array1->buffer[3].data, NULL);
    assert_ptr_equal(array1->buffer[5].data, &data[6]);
    assert_ptr_equal(array1->buffer[6].data, NULL);
    assert_ptr_equal(array1->buffer[8].data, &data[9]);
    assert_ptr_equal(array1->buffer[9].data, NULL);

    assert_int_equal(amxc_array_shift_left(array1, 3, NULL), 0);
    assert_int_equal(amxc_array_capacity(array1), 10);
    assert_int_equal(amxc_array_size(array1), 2);
    assert_ptr_equal(array1->buffer[2].data, &data[6]);
    assert_ptr_equal(array1->buffer[5].data, &data[9]);
    assert_ptr_equal(array1->buffer[8].data, NULL);
    assert_int_equal(array1->first_used, 2);
    assert_int_equal(array1->last_used, 5);

    assert_int_equal(amxc_array_shift_left(array1, 6, NULL), 0);
    assert_int_equal(amxc_array_capacity(array1), 10);
    assert_int_equal(amxc_array_size(array1), 0);
    assert_int_equal(array1->first_used, 0);
    assert_int_equal(array1->last_used, 0);
}

void test_amxc_array_shift_left_all(UNUSED void** state) {
    assert_int_equal(amxc_array_shift_left(array1, 10, NULL), 0);
    assert_int_equal(amxc_array_capacity(array1), 10);
    assert_int_equal(amxc_array_size(array1), 0);
    assert_int_equal(array1->first_used, 0);
    assert_int_equal(array1->last_used, 0);
    assert_ptr_equal(array1->buffer[3].data, NULL);
    assert_ptr_equal(array1->buffer[6].data, NULL);
    assert_ptr_equal(array1->buffer[9].data, NULL);

    amxc_reset_test_array();
}

void test_amxc_array_shift_right(UNUSED void** state) {
    assert_int_equal(amxc_array_shift_right(array1, 15, NULL), -1);
    assert_int_equal(amxc_array_shift_right(array1, 0, NULL), 0);

    assert_int_equal(amxc_array_shift_right(array1, 1, NULL), 0);
    assert_int_equal(amxc_array_capacity(array1), 10);
    assert_int_equal(amxc_array_size(array1), 2);
    assert_int_equal(array1->first_used, 4);
    assert_int_equal(array1->last_used, 7);
    assert_ptr_equal(array1->buffer[4].data, &data[3]);
    assert_ptr_equal(array1->buffer[3].data, NULL);
    assert_ptr_equal(array1->buffer[7].data, &data[6]);
    assert_ptr_equal(array1->buffer[6].data, NULL);
    assert_ptr_equal(array1->buffer[9].data, NULL);

    assert_int_equal(amxc_array_shift_right(array1, 3, NULL), 0);
    assert_int_equal(amxc_array_capacity(array1), 10);
    assert_int_equal(amxc_array_size(array1), 1);
    assert_ptr_equal(array1->buffer[7].data, &data[3]);
    assert_ptr_equal(array1->buffer[4].data, NULL);
    assert_int_equal(array1->first_used, 7);
    assert_int_equal(array1->last_used, 7);

    assert_int_equal(amxc_array_shift_right(array1, 3, NULL), 0);
    assert_int_equal(amxc_array_capacity(array1), 10);
    assert_int_equal(amxc_array_size(array1), 0);
    assert_int_equal(array1->first_used, 0);
    assert_int_equal(array1->last_used, 0);

    amxc_reset_test_array();
}

void test_amxc_array_shift_right_all(UNUSED void** state) {
    assert_int_equal(amxc_array_shift_right(array1, 10, NULL), 0);
    assert_int_equal(amxc_array_capacity(array1), 10);
    assert_int_equal(amxc_array_size(array1), 0);
    assert_int_equal(array1->first_used, 0);
    assert_int_equal(array1->last_used, 0);
    assert_ptr_equal(array1->buffer[3].data, NULL);
    assert_ptr_equal(array1->buffer[6].data, NULL);
    assert_ptr_equal(array1->buffer[9].data, NULL);

    amxc_reset_test_array();
}


void test_amxc_array_set_at_null(UNUSED void** state) {
    assert_ptr_equal(amxc_array_set_data_at(NULL, 0, NULL), NULL);
}

void test_amxc_array_set_at(UNUSED void** state) {
    assert_ptr_equal(amxc_array_set_data_at(array1, 2, NULL), &array1->buffer[2]);
    assert_int_equal(array1->first_used, 3);
    assert_int_equal(array1->last_used, 9);
    assert_int_equal(amxc_array_is_empty(array1), false);
    assert_int_equal(amxc_array_size(array1), 3);

    assert_ptr_equal(amxc_array_set_data_at(array1, 9, NULL), &array1->buffer[9]);
    assert_int_equal(array1->first_used, 3);
    assert_int_equal(array1->last_used, 6);
    assert_int_equal(amxc_array_is_empty(array1), false);
    assert_int_equal(amxc_array_size(array1), 2);

    assert_ptr_equal(amxc_array_set_data_at(array1, 3, NULL), &array1->buffer[3]);
    assert_int_equal(array1->first_used, 6);
    assert_int_equal(array1->last_used, 6);
    assert_int_equal(amxc_array_is_empty(array1), false);
    assert_int_equal(amxc_array_size(array1), 1);

    assert_ptr_equal(amxc_array_set_data_at(array1, 6, NULL), &array1->buffer[6]);
    assert_int_equal(array1->first_used, 0);
    assert_int_equal(array1->last_used, 0);
    assert_int_equal(amxc_array_is_empty(array1), true);
    assert_int_equal(amxc_array_size(array1), 0);

    assert_ptr_equal(amxc_array_set_data_at(array1, 7, &data[7]), &array1->buffer[7]);
    assert_int_equal(array1->first_used, 7);
    assert_int_equal(array1->last_used, 7);
    assert_int_equal(amxc_array_is_empty(array1), false);
    assert_int_equal(amxc_array_size(array1), 1);

    assert_ptr_equal(amxc_array_set_data_at(array1, 2, &data[2]), &array1->buffer[2]);
    assert_int_equal(array1->first_used, 2);
    assert_int_equal(array1->last_used, 7);
    assert_int_equal(amxc_array_is_empty(array1), false);
    assert_int_equal(amxc_array_size(array1), 2);

    assert_ptr_equal(amxc_array_set_data_at(array1, 5, &data[5]), &array1->buffer[5]);
    assert_int_equal(array1->first_used, 2);
    assert_int_equal(array1->last_used, 7);
    assert_int_equal(amxc_array_is_empty(array1), false);
    assert_int_equal(amxc_array_size(array1), 3);

    assert_ptr_equal(amxc_array_set_data_at(array1, 10, NULL), NULL);
    assert_ptr_equal(amxc_array_set_data_at(array1, 11, NULL), NULL);

    amxc_reset_test_array();
}

void test_amxc_array_it_set_data_null(UNUSED void** state) {
    assert_int_equal(amxc_array_it_set_data(NULL, NULL), -1);
    amxc_array_it_t* it = amxc_array_get_at(array1, 2);
    assert_int_equal(amxc_array_it_set_data(it, NULL), -1);
    assert_int_equal(array1->first_used, 3);
    assert_int_equal(amxc_array_grow(array1, 10), 0);
    it = amxc_array_get_at(array1, 15);
    assert_int_equal(amxc_array_it_set_data(it, NULL), -1);
    assert_int_equal(array1->last_used, 9);
}

void test_amxc_array_it_set_data(UNUSED void** state) {
    amxc_array_it_t* it = NULL;

    amxc_array_clean(array1, NULL);
    amxc_array_init(array1, 9);

    it = amxc_array_get_at(array1, 0);
    assert_int_equal(amxc_array_it_set_data(it, &data[0]), 0);
    assert_int_equal(array1->first_used, 0);

    it = amxc_array_get_at(array1, 2);
    assert_int_equal(amxc_array_it_set_data(it, &data[2]), 0);
    assert_int_equal(array1->first_used, 0);
    assert_int_equal(array1->last_used, 2);

    assert_int_equal(amxc_array_grow(array1, 10), 0);
    it = amxc_array_get_at(array1, 15);
    assert_int_equal(amxc_array_it_set_data(it, &data[5]), 0);
    assert_int_equal(array1->last_used, 15);

    amxc_reset_test_array();
}

void test_amxc_array_append_data_null(UNUSED void** state) {
    assert_ptr_equal(amxc_array_append_data(NULL, NULL), NULL);
}

void test_amxc_array_append_data(UNUSED void** state) {
    amxc_array_it_t* it = amxc_array_append_data(array1, NULL);
    assert_ptr_equal(it, NULL);
    assert_int_equal(amxc_array_capacity(array1), 10);
    assert_int_equal(amxc_array_size(array1), 3);
    assert_int_equal(array1->last_used, 9);

    it = amxc_array_append_data(array1, &data[0]);
    assert_ptr_not_equal(it, NULL);
    assert_int_equal(amxc_array_capacity(array1), 13);
    assert_int_equal(amxc_array_size(array1), 4);
    assert_int_equal(array1->last_used, 10);

    it = amxc_array_append_data(array1, &data[1]);
    assert_ptr_not_equal(it, NULL);
    assert_int_equal(amxc_array_capacity(array1), 13);
    assert_int_equal(amxc_array_size(array1), 5);
    assert_int_equal(array1->last_used, 11);

    amxc_array_clean(array1, NULL);
    assert_int_equal(amxc_array_capacity(array1), 0);

    it = amxc_array_append_data(array1, &data[0]);
    assert_ptr_not_equal(it, NULL);
    assert_int_equal(amxc_array_capacity(array1), 3);
    assert_int_equal(amxc_array_size(array1), 1);
    assert_int_equal(array1->last_used, 0);
    assert_int_equal(array1->first_used, 0);

    it = amxc_array_append_data(array1, &data[1]);
    assert_ptr_not_equal(it, NULL);
    assert_int_equal(amxc_array_capacity(array1), 3);
    assert_int_equal(amxc_array_size(array1), 2);
    assert_int_equal(array1->last_used, 1);
    assert_int_equal(array1->first_used, 0);

    amxc_reset_test_array();
}

void test_amxc_array_prepend_data_null(UNUSED void** state) {
    assert_ptr_equal(amxc_array_prepend_data(NULL, NULL), NULL);
}

void test_amxc_array_prepend_data(UNUSED void** state) {
    amxc_array_it_t* it = amxc_array_prepend_data(array1, NULL);
    assert_ptr_equal(it, NULL);
    assert_int_equal(amxc_array_capacity(array1), 10);
    assert_int_equal(amxc_array_size(array1), 3);
    assert_int_equal(array1->first_used, 3);

    it = amxc_array_prepend_data(array1, &data[0]);
    assert_ptr_not_equal(it, NULL);
    assert_int_equal(amxc_array_capacity(array1), 10);
    assert_int_equal(amxc_array_size(array1), 4);
    assert_int_equal(array1->first_used, 2);

    it = amxc_array_prepend_data(array1, &data[1]);
    assert_ptr_not_equal(it, NULL);
    assert_int_equal(amxc_array_capacity(array1), 10);
    assert_int_equal(amxc_array_size(array1), 5);
    assert_int_equal(array1->first_used, 1);

    amxc_array_clean(array1, NULL);
    assert_int_equal(amxc_array_capacity(array1), 0);

    it = amxc_array_prepend_data(array1, &data[0]);
    assert_ptr_not_equal(it, NULL);
    assert_int_equal(amxc_array_capacity(array1), 3);
    assert_int_equal(amxc_array_size(array1), 1);
    assert_int_equal(array1->last_used, 0);
    assert_int_equal(array1->first_used, 0);

    it = amxc_array_prepend_data(array1, &data[1]);
    assert_ptr_not_equal(it, NULL);
    assert_int_equal(amxc_array_capacity(array1), 6);
    assert_int_equal(amxc_array_size(array1), 2);
    assert_int_equal(array1->last_used, 3);
    assert_int_equal(array1->first_used, 2);

    amxc_reset_test_array();
}

void test_amxc_array_take_first_data_null(UNUSED void** state) {
    assert_ptr_equal(amxc_array_take_first_data(NULL), NULL);
}

void test_amxc_array_take_first_data(UNUSED void** state) {
    char* d = amxc_array_take_first_data(array1);
    assert_ptr_equal(d, &data[3]);
    assert_int_equal(amxc_array_capacity(array1), 10);
    assert_int_equal(amxc_array_size(array1), 2);
    assert_int_equal(array1->first_used, 6);

    d = amxc_array_take_first_data(array1);
    assert_ptr_equal(d, &data[6]);
    assert_int_equal(amxc_array_capacity(array1), 10);
    assert_int_equal(amxc_array_size(array1), 1);
    assert_int_equal(array1->first_used, 9);

    d = amxc_array_take_first_data(array1);
    assert_ptr_equal(d, &data[9]);
    assert_int_equal(amxc_array_capacity(array1), 10);
    assert_int_equal(amxc_array_size(array1), 0);
    assert_int_equal(array1->first_used, 0);

    amxc_reset_test_array();
}

void test_amxc_array_take_last_data_null(UNUSED void** state) {
    assert_ptr_equal(amxc_array_take_last_data(NULL), NULL);
}

void test_amxc_array_take_last_data(UNUSED void** state) {
    char* d = amxc_array_take_last_data(array1);
    assert_ptr_equal(d, &data[9]);
    assert_int_equal(amxc_array_capacity(array1), 10);
    assert_int_equal(amxc_array_size(array1), 2);
    assert_int_equal(array1->last_used, 6);

    d = amxc_array_take_last_data(array1);
    assert_ptr_equal(d, &data[6]);
    assert_int_equal(amxc_array_capacity(array1), 10);
    assert_int_equal(amxc_array_size(array1), 1);
    assert_int_equal(array1->last_used, 3);

    d = amxc_array_take_last_data(array1);
    assert_ptr_equal(d, &data[3]);
    assert_int_equal(amxc_array_capacity(array1), 10);
    assert_int_equal(amxc_array_size(array1), 0);
    assert_int_equal(array1->first_used, 0);

    amxc_reset_test_array();
}

void test_amxc_array_it_take_data_null(UNUSED void** state) {
    assert_int_equal(amxc_array_it_index(NULL), 0);
}

void test_amxc_array_it_take_data(UNUSED void** state) {
    assert_ptr_equal(amxc_array_it_take_data(NULL), NULL);
    amxc_array_it_t* it = amxc_array_get_at(array1, 3);
    assert_ptr_equal(amxc_array_it_take_data(it), &data[3]);
    assert_int_equal(array1->first_used, 6);
    assert_int_equal(array1->last_used, 9);

    it = amxc_array_get_at(array1, 4);
    assert_ptr_equal(amxc_array_it_take_data(it), NULL);
    assert_int_equal(array1->first_used, 6);
    assert_int_equal(array1->last_used, 9);

    it = amxc_array_get_at(array1, 9);
    assert_ptr_equal(amxc_array_it_take_data(it), &data[9]);
    assert_int_equal(array1->first_used, 6);
    assert_int_equal(array1->last_used, 6);

    it = amxc_array_get_at(array1, 6);
    assert_ptr_equal(amxc_array_it_take_data(it), &data[6]);
    assert_int_equal(array1->first_used, 0);
    assert_int_equal(array1->last_used, 0);

    assert_int_equal(amxc_array_is_empty(array1), true);
}

void test_amxc_array_it_index_null(UNUSED void** state) {
    assert_int_equal(amxc_array_it_index(NULL), 0);
}

void test_amxc_array_it_index(UNUSED void** state) {
    for(unsigned int index = 0; index < amxc_array_capacity(array1); index++) {
        amxc_array_it_t* it = amxc_array_get_at(array1, index);
        assert_int_equal(amxc_array_it_index(it), index);
    }
}

static int test_cmp(amxc_array_it_t* it1, amxc_array_it_t* it2) {
    char* d1 = amxc_array_it_get_data(it1);
    char* d2 = amxc_array_it_get_data(it2);

    if(d1[0] < d2[0]) {
        return -1;
    } else if(d1[0] > d2[0]) {
        return 1;
    }

    return 0;
}

void test_amxc_array_sort(UNUSED void** state) {
    amxc_array_t array;
    const char data[16] = "KRATELEPUIMQCXOS";
    const char sorted[16] = "ACEEIKLMOPQRSTUX";

    const char data_sets[6][3] = {
        "ABC", "BCA", "CAB", "CBA", "BAC", "ACB"
    };

    // initialize array with 10 items
    assert_int_equal(amxc_array_init(&array, 20), 0);
    for(unsigned int index = 0; index < 16; index++) {
        assert_ptr_equal(amxc_array_set_data_at(&array, index, (void*) &data[index]), &array.buffer[index]);
    }

    assert_int_equal(amxc_array_sort(&array, test_cmp), 0);
    for(unsigned int index = 0; index < 16; index++) {
        char* d = amxc_array_it_get_data(amxc_array_get_at(&array, index));
        printf("%c\n", d[0]);
        assert_int_equal(d[0], sorted[index]);
    }
    amxc_array_clean(&array, NULL);

    assert_int_equal(amxc_array_init(&array, 40), 0);
    for(unsigned int index = 0; index < 32; index += 2) {
        assert_ptr_equal(amxc_array_set_data_at(&array, index, (void*) &data[index / 2]), &array.buffer[index]);
    }

    assert_int_equal(amxc_array_sort(&array, test_cmp), 0);
    for(unsigned int index = 0; index < 16; index++) {
        char* d = amxc_array_it_get_data(amxc_array_get_at(&array, index));
        printf("%c\n", d[0]);
        assert_int_equal(d[0], sorted[index]);
    }
    assert_int_equal(amxc_array_size(&array), 16);
    amxc_array_clean(&array, NULL);

    for(int sets = 0; sets < 6; sets++) {
        printf("\n %d - ", sets);
        assert_int_equal(amxc_array_init(&array, 20), 0);
        for(unsigned int index = 0; index < 3; index++) {
            assert_ptr_equal(amxc_array_set_data_at(&array, index, (void*) &data_sets[sets][index]), &array.buffer[index]);
        }

        assert_int_equal(amxc_array_sort(&array, test_cmp), 0);
        for(unsigned int index = 0; index < 3; index++) {
            char* d = amxc_array_it_get_data(amxc_array_get_at(&array, index));
            printf("%c", d[0]);
        }
        amxc_array_clean(&array, NULL);
    }
    printf("\n");

    assert_int_not_equal(amxc_array_sort(NULL, test_cmp), 0);
    assert_int_equal(amxc_array_init(&array, 20), 0);
    assert_int_not_equal(amxc_array_sort(&array, NULL), 0);
    assert_int_equal(amxc_array_sort(&array, test_cmp), 0);
    amxc_array_clean(&array, NULL);
    assert_int_equal(amxc_array_init(&array, 0), 0);
    assert_int_equal(amxc_array_sort(&array, test_cmp), 0);
    amxc_array_clean(&array, NULL);
}
