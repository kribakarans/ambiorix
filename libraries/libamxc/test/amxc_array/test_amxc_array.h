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

#ifndef __TEST_AMXC_ARRAY_H__
#define __TEST_AMXC_ARRAY_H__

int test_amxc_array_setup(void** state);
int test_amxc_array_teardown(void** state);

void test_amxc_array_new_delete_null(void** state);
void test_amxc_array_init_clean_null(void** state);
void test_amxc_array_init_clean(void** state);
void test_amxc_array_clean_cb(void** state);
void test_amxc_array_get_at_null(void** state);
void test_amxc_array_get_at(void** state);
void test_amxc_array_get_first_null(void** state);
void test_amxc_array_get_first(void** state);
void test_amxc_array_get_first_empty(void** state);
void test_amxc_array_get_first_free_null(void** state);
void test_amxc_array_get_first_free(void** state);
void test_amxc_array_get_first_free_full(void** state);
void test_amxc_array_get_last_null(void** state);
void test_amxc_array_get_last(void** state);
void test_amxc_array_get_last_empty(void** state);
void test_amxc_array_get_last_free_null(void** state);
void test_amxc_array_get_last_free(void** state);
void test_amxc_array_get_last_free_full(void** state);
void test_amxc_array_it_get_next_null(void** state);
void test_amxc_array_it_get_next(void** state);
void test_amxc_array_it_get_next_free_null(void** state);
void test_amxc_array_it_get_next_free(void** state);
void test_amxc_array_it_get_previous_null(void** state);
void test_amxc_array_it_get_previous(void** state);
void test_amxc_array_it_get_previous_free_null(void** state);
void test_amxc_array_it_get_previous_free(void** state);
void test_amxc_array_it_get_data_null(void** state);
void test_amxc_array_it_get_data(void** state);
void test_amxc_array_is_empty_null(void** state);
void test_amxc_array_is_empty(void** state);
void test_amxc_array_size_null(void** state);
void test_amxc_array_size(void** state);
void test_amxc_array_capacity_null(void** state);
void test_amxc_array_capacity(void** state);
void test_amxc_array_grow_null(void** state);
void test_amxc_array_grow(void** state);
void test_amxc_array_shrink_null(void** state);
void test_amxc_array_shrink(void** state);
void test_amxc_array_shift_null(void** state);
void test_amxc_array_shift_left(void** state);
void test_amxc_array_shift_left_all(void** state);
void test_amxc_array_shift_right(void** state);
void test_amxc_array_shift_right_all(void** state);
void test_amxc_array_set_at_null(void** state);
void test_amxc_array_set_at(void** state);
void test_amxc_array_it_set_data_null(void** state);
void test_amxc_array_it_set_data(void** state);
void test_amxc_array_append_data_null(void** state);
void test_amxc_array_append_data(void** state);
void test_amxc_array_prepend_data_null(void** state);
void test_amxc_array_prepend_data(void** state);
void test_amxc_array_take_first_data_null(void** state);
void test_amxc_array_take_first_data(void** state);
void test_amxc_array_take_last_data_null(void** state);
void test_amxc_array_take_last_data(void** state);
void test_amxc_array_it_take_data_null(void** state);
void test_amxc_array_it_take_data(void** state);
void test_amxc_array_it_index_null(void** state);
void test_amxc_array_it_index(void** state);
void test_amxc_array_sort(void** state);

#endif // __TEST_AMXC_ARRAY_H__