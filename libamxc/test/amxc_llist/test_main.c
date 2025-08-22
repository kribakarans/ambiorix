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
#include <setjmp.h>
#include <stdarg.h>
#include <cmocka.h>

#include "test_amxc_llist.h"

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(amxc_llist_new_delete_null_check),
        cmocka_unit_test(amxc_llist_new_delete_check),
        cmocka_unit_test(amxc_llist_init_clean_null_check),
        cmocka_unit_test(amxc_llist_init_clean_check),
        cmocka_unit_test(amxc_llist_delete_func_check),
        cmocka_unit_test(amxc_llist_clean_func_check),
        cmocka_unit_test(amxc_llist_delete_cb_check),
        cmocka_unit_test(amxc_llist_clean_cb_check),
        cmocka_unit_test(amxc_llist_append_null_check),
        cmocka_unit_test(amxc_llist_append_check),
        cmocka_unit_test(amxc_llist_prepend_null_check),
        cmocka_unit_test(amxc_llist_prepend_check),
        cmocka_unit_test(amxc_llist_append_move_same_list_check),
        cmocka_unit_test(amxc_llist_prepend_move_same_list_check),
        cmocka_unit_test(amxc_llist_is_empty_null_check),
        cmocka_unit_test(amxc_llist_is_empty_check),
        cmocka_unit_test(amxc_llist_size_null_check),
        cmocka_unit_test(amxc_llist_size_check),
        cmocka_unit_test(amxc_llist_get_at_check),
        cmocka_unit_test(amxc_llist_set_at_check),
        cmocka_unit_test(amxc_llist_get_first_check),
        cmocka_unit_test(amxc_llist_get_last_check),

        cmocka_unit_test(amxc_llist_it_init_null_check),
        cmocka_unit_test(amxc_llist_it_init_check),
        cmocka_unit_test(amxc_llist_it_clean_null_check),
        cmocka_unit_test(amxc_llist_it_clean_check),
        cmocka_unit_test(amxc_llist_it_clean_cb_check),
        cmocka_unit_test(amxc_llist_it_take_null_check),
        cmocka_unit_test(amxc_llist_it_take_check),
        cmocka_unit_test(amxc_llist_it_take_double_check),
        cmocka_unit_test(amxc_llist_it_insert_before_null_check),
        cmocka_unit_test(amxc_llist_it_insert_before_check),
        cmocka_unit_test(amxc_llist_it_insert_before_head_check),
        cmocka_unit_test(amxc_llist_it_insert_before_invalid_it_check),
        cmocka_unit_test(amxc_llist_it_insert_after_null_check),
        cmocka_unit_test(amxc_llist_it_insert_after_check),
        cmocka_unit_test(amxc_llist_it_insert_after_tail_check),
        cmocka_unit_test(amxc_llist_it_insert_after_invalid_it_check),
        cmocka_unit_test(amxc_llist_it_index_of_check),
        cmocka_unit_test(amxc_llist_it_next_prev_check),
        cmocka_unit_test(amxc_llist_it_is_in_list_check),
        cmocka_unit_test(amxc_llist_take_at_check),
        cmocka_unit_test(amxc_llist_swap_in_same_llist_check),
        cmocka_unit_test(amxc_llist_swap_in_different_llist_check),
        cmocka_unit_test(test_amxc_llist_sort),
        cmocka_unit_test(test_amxc_llist_move),
    };
    return cmocka_run_group_tests_name("amxc-linked-list", tests, NULL, NULL);
}
