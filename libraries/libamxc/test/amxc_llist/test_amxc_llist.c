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
#include <stdlib.h>
#include <setjmp.h>
#include <cmocka.h>

#include <amxc/amxc_llist.h>

#include "test_amxc_llist.h"

#include <amxc/amxc_macros.h>
void amxc_llist_new_delete_null_check(UNUSED void** state) {
    // passing NULL pointers should not lead to segfault
    assert_int_equal(amxc_llist_new(NULL), -1);
    amxc_llist_delete(NULL, NULL);
}

void amxc_llist_new_delete_check(UNUSED void** state) {
    amxc_llist_t* llist = NULL;
    assert_int_not_equal(amxc_llist_new(&llist), -1);
    assert_ptr_not_equal(llist, NULL);
    assert_ptr_equal(llist->head, NULL);
    assert_ptr_equal(llist->tail, NULL);
    amxc_llist_delete(&llist, NULL);
    assert_ptr_equal(llist, NULL);
}

void amxc_llist_init_clean_null_check(UNUSED void** state) {
    // passing NULL pointers should not lead to segfault
    assert_int_equal(amxc_llist_init(NULL), -1);
    amxc_llist_clean(NULL, NULL);
}

void amxc_llist_init_clean_check(UNUSED void** state) {
    amxc_llist_t llist;

    assert_int_equal(amxc_llist_init(&llist), 0);
    assert_ptr_equal(llist.head, NULL);
    assert_ptr_equal(llist.tail, NULL);
    amxc_llist_clean(&llist, NULL);
}

static amxc_llist_it_t s_it_func_check;

static void check_it_delete_func(amxc_llist_it_t* it) {
    assert_ptr_equal(it, &s_it_func_check);
}

void amxc_llist_delete_func_check(UNUSED void** state) {
    amxc_llist_t* llist = NULL;

    // create list
    assert_int_not_equal(amxc_llist_new(&llist), -1);
    assert_int_equal(amxc_llist_it_init(&s_it_func_check), 0);
    assert_int_equal(amxc_llist_append(llist, &s_it_func_check), 0);

    amxc_llist_delete(&llist, check_it_delete_func);
}

void amxc_llist_clean_func_check(UNUSED void** state) {
    amxc_llist_t* llist = NULL;

    // create list
    assert_int_not_equal(amxc_llist_new(&llist), -1);
    assert_int_equal(amxc_llist_it_init(&s_it_func_check), 0);
    assert_int_equal(amxc_llist_append(llist, &s_it_func_check), 0);

    amxc_llist_clean(llist, check_it_delete_func);

    amxc_llist_delete(&llist, check_it_delete_func);
}

void amxc_llist_delete_cb_check(UNUSED void** state) {
    amxc_llist_t* llist = NULL;

    // create list
    assert_int_not_equal(amxc_llist_new(&llist), -1);
    assert_int_equal(amxc_llist_it_init(&s_it_func_check), 0);
    assert_int_equal(amxc_llist_append(llist, &s_it_func_check), 0);
    amxc_llist_delete(&llist, NULL);
    assert_ptr_equal(s_it_func_check.next, NULL);
    assert_ptr_equal(s_it_func_check.prev, NULL);
    assert_ptr_equal(s_it_func_check.llist, NULL);
}

void amxc_llist_clean_cb_check(UNUSED void** state) {
    amxc_llist_t* llist = NULL;

    // create list
    assert_int_not_equal(amxc_llist_new(&llist), -1);
    assert_int_equal(amxc_llist_it_init(&s_it_func_check), 0);
    assert_int_equal(amxc_llist_append(llist, &s_it_func_check), 0);
    amxc_llist_clean(llist, NULL);
    assert_ptr_equal(s_it_func_check.next, NULL);
    assert_ptr_equal(s_it_func_check.prev, NULL);
    assert_ptr_equal(s_it_func_check.llist, NULL);
    amxc_llist_delete(&llist, NULL);
}

void amxc_llist_append_null_check(UNUSED void** state) {
    amxc_llist_t* llist = NULL;
    amxc_llist_it_t it1;

    assert_int_equal(amxc_llist_new(&llist), 0);
    assert_int_equal(amxc_llist_it_init(&it1), 0);

    // passing NULL pointers should not lead to segfault
    assert_int_not_equal(amxc_llist_append(NULL, NULL), 0);
    assert_int_not_equal(amxc_llist_append(llist, NULL), 0);
    assert_int_not_equal(amxc_llist_append(NULL, &it1), 0);

    amxc_llist_delete(&llist, NULL);
}

void amxc_llist_append_check(UNUSED void** state) {
    amxc_llist_t* llist = NULL;
    amxc_llist_it_t it1;
    amxc_llist_it_t it2;

    assert_int_equal(amxc_llist_new(&llist), 0);
    assert_int_equal(amxc_llist_it_init(&it1), 0);
    assert_int_equal(amxc_llist_it_init(&it2), 0);

    // append iterator 1
    assert_int_equal(amxc_llist_append(llist, &it1), 0);
    assert_ptr_equal(llist->head, &it1);
    assert_ptr_equal(llist->tail, &it1);
    assert_ptr_equal(it1.next, NULL);
    assert_ptr_equal(it1.prev, NULL);
    assert_ptr_equal(it1.llist, llist);

    // append iterator 2
    assert_int_equal(amxc_llist_append(llist, &it2), 0);
    assert_ptr_equal(llist->head, &it1);
    assert_ptr_equal(llist->tail, &it2);
    assert_ptr_equal(it1.next, &it2);
    assert_ptr_equal(it2.prev, &it1);
    assert_ptr_equal(it1.prev, NULL);
    assert_ptr_equal(it2.next, NULL);
    assert_ptr_equal(it2.llist, llist);

    amxc_llist_delete(&llist, NULL);
}

void amxc_llist_prepend_null_check(UNUSED void** state) {
    amxc_llist_t* llist = NULL;
    amxc_llist_it_t it1;

    assert_int_equal(amxc_llist_new(&llist), 0);
    assert_int_equal(amxc_llist_it_init(&it1), 0);

    // passing NULL pointers should not lead to segfault
    assert_int_not_equal(amxc_llist_prepend(NULL, NULL), 0);
    assert_int_not_equal(amxc_llist_prepend(llist, NULL), 0);
    assert_int_not_equal(amxc_llist_prepend(NULL, &it1), 0);

    amxc_llist_delete(&llist, NULL);
}

void amxc_llist_prepend_check(UNUSED void** state) {
    amxc_llist_t* llist = NULL;
    amxc_llist_it_t it1;
    amxc_llist_it_t it2;

    assert_int_equal(amxc_llist_new(&llist), 0);
    assert_int_equal(amxc_llist_it_init(&it1), 0);
    assert_int_equal(amxc_llist_it_init(&it2), 0);

    // prepend iterator 1
    assert_int_equal(amxc_llist_prepend(llist, &it1), 0);
    assert_ptr_equal(llist->head, &it1);
    assert_ptr_equal(llist->tail, &it1);
    assert_ptr_equal(it1.next, NULL);
    assert_ptr_equal(it1.prev, NULL);
    assert_ptr_equal(it1.llist, llist);

    // append iterator 2
    assert_int_equal(amxc_llist_prepend(llist, &it2), 0);
    assert_ptr_equal(llist->head, &it2);
    assert_ptr_equal(llist->tail, &it1);
    assert_ptr_equal(it2.next, &it1);
    assert_ptr_equal(it1.prev, &it2);
    assert_ptr_equal(it2.prev, NULL);
    assert_ptr_equal(it1.next, NULL);
    assert_ptr_equal(it2.llist, llist);

    amxc_llist_delete(&llist, NULL);
}

static amxc_llist_t* llist = NULL;
static amxc_llist_t* llist1 = NULL;
static amxc_llist_t* llist2 = NULL;
static amxc_llist_it_t it1;
static amxc_llist_it_t it2;
static amxc_llist_it_t it3;
static amxc_llist_it_t it4;

static void amxc_llist_setup(void) {
    assert_int_equal(amxc_llist_new(&llist1), 0);
    assert_int_equal(amxc_llist_new(&llist2), 0);
    assert_int_equal(amxc_llist_it_init(&it1), 0);
    assert_int_equal(amxc_llist_it_init(&it2), 0);
    assert_int_equal(amxc_llist_it_init(&it3), 0);
    assert_int_equal(amxc_llist_it_init(&it4), 0);
    assert_int_equal(amxc_llist_append(llist1, &it1), 0);
    assert_int_equal(amxc_llist_append(llist1, &it2), 0);
    assert_int_equal(amxc_llist_append(llist1, &it3), 0);
}

static void amxc_llist_teardown(void) {
    amxc_llist_delete(&llist1, NULL);
    amxc_llist_delete(&llist2, NULL);
}

void amxc_llist_append_move_same_list_check(UNUSED void** state) {
    amxc_llist_setup();
    // move iterator 1 from head to tail in llist1
    assert_int_equal(amxc_llist_append(llist1, &it1), 0);
    assert_ptr_equal(llist1->head, &it2);
    assert_ptr_equal(llist1->tail, &it1);
    assert_ptr_equal(it1.next, NULL);
    assert_ptr_equal(it1.prev, &it3);
    assert_ptr_equal(it2.next, &it3);
    assert_ptr_equal(it2.prev, NULL);
    assert_ptr_equal(it3.next, &it1);
    assert_ptr_equal(it3.prev, &it2);
    assert_ptr_equal(it1.llist, llist1);

    // move iterator 3 to tail in llist1
    assert_int_equal(amxc_llist_append(llist1, &it3), 0);
    assert_ptr_equal(llist1->head, &it2);
    assert_ptr_equal(llist1->tail, &it3);
    assert_ptr_equal(it1.prev, &it2);
    assert_ptr_equal(it1.next, &it3);
    assert_ptr_equal(it2.next, &it1);
    assert_ptr_equal(it2.prev, NULL);
    assert_ptr_equal(it3.next, NULL);
    assert_ptr_equal(it3.prev, &it1);
    assert_ptr_equal(it3.llist, llist1);
    amxc_llist_teardown();
}

void amxc_llist_prepend_move_same_list_check(UNUSED void** state) {
    amxc_llist_setup();
    // move iterator 3 from tail to head in llist1
    assert_int_equal(amxc_llist_prepend(llist1, &it3), 0);
    assert_ptr_equal(llist1->head, &it3);
    assert_ptr_equal(llist1->tail, &it2);
    assert_ptr_equal(it1.next, &it2);
    assert_ptr_equal(it1.prev, &it3);
    assert_ptr_equal(it2.next, NULL);
    assert_ptr_equal(it2.prev, &it1);
    assert_ptr_equal(it3.next, &it1);
    assert_ptr_equal(it3.prev, NULL);
    assert_ptr_equal(it3.llist, llist1);

    // move iterator 2 to tail in llist1
    assert_int_equal(amxc_llist_prepend(llist1, &it2), 0);
    assert_ptr_equal(llist1->head, &it2);
    assert_ptr_equal(llist1->tail, &it1);
    assert_ptr_equal(it1.prev, &it3);
    assert_ptr_equal(it1.next, NULL);
    assert_ptr_equal(it2.next, &it3);
    assert_ptr_equal(it2.prev, NULL);
    assert_ptr_equal(it3.next, &it1);
    assert_ptr_equal(it3.prev, &it2);
    assert_ptr_equal(it2.llist, llist1);
    amxc_llist_teardown();
}

void amxc_llist_is_empty_null_check(UNUSED void** state) {
    // passing NULL pointers should not lead to segfault
    assert_int_equal(amxc_llist_is_empty(NULL), true);
}

void amxc_llist_is_empty_check(UNUSED void** state) {
    amxc_llist_t* llist = NULL;
    amxc_llist_it_t it1;

    assert_int_equal(amxc_llist_new(&llist), 0);
    assert_int_equal(amxc_llist_it_init(&it1), 0);

    assert_int_equal(amxc_llist_is_empty(llist), true);
    assert_int_equal(amxc_llist_append(llist, &it1), 0);
    assert_int_equal(amxc_llist_is_empty(llist), false);

    amxc_llist_delete(&llist, NULL);
}

void amxc_llist_size_null_check(UNUSED void** state) {
    // passing NULL pointers should not lead to segfault
    assert_int_equal(amxc_llist_size(NULL), 0);
}

void amxc_llist_size_check(UNUSED void** state) {
    amxc_llist_t* llist = NULL;
    amxc_llist_it_t it1;
    amxc_llist_it_t it2;

    assert_int_equal(amxc_llist_new(&llist), 0);
    assert_int_equal(amxc_llist_it_init(&it1), 0);
    assert_int_equal(amxc_llist_it_init(&it2), 0);

    assert_int_equal(amxc_llist_size(llist), 0);
    assert_int_equal(amxc_llist_append(llist, &it1), 0);
    assert_int_equal(amxc_llist_size(llist), 1);
    assert_int_equal(amxc_llist_append(llist, &it2), 0);
    assert_int_equal(amxc_llist_size(llist), 2);

    amxc_llist_clean(llist, NULL);
    assert_int_equal(amxc_llist_size(llist), 0);

    amxc_llist_delete(&llist, NULL);
}

void amxc_llist_get_at_check(UNUSED void** state) {
    amxc_llist_setup();
    assert_ptr_equal(amxc_llist_get_at(NULL, 10), NULL);
    assert_ptr_equal(amxc_llist_get_at(llist1, 0), &it1);
    assert_ptr_equal(amxc_llist_get_at(llist1, 1), &it2);
    assert_ptr_equal(amxc_llist_get_at(llist1, 2), &it3);
    assert_ptr_equal(amxc_llist_get_at(llist1, 3), NULL);
    amxc_llist_teardown();
}

void amxc_llist_set_at_check(UNUSED void** state) {
    amxc_llist_setup();
    amxc_llist_it_t it;
    assert_int_equal(amxc_llist_set_at(NULL, 10, &it1), -1);

    assert_int_equal(amxc_llist_it_init(&it), 0);

    assert_int_equal(amxc_llist_set_at(llist1, 0, &it), 0);
    assert_ptr_equal(it.next, &it1);
    assert_ptr_equal(it.prev, NULL);
    amxc_llist_it_take(&it);

    assert_int_equal(amxc_llist_set_at(llist1, 1, &it), 0);
    assert_ptr_equal(it.next, &it2);
    assert_ptr_equal(it.prev, &it1);
    amxc_llist_it_take(&it);

    assert_int_equal(amxc_llist_set_at(llist1, 2, &it), 0);
    assert_ptr_equal(it.next, &it3);
    assert_ptr_equal(it.prev, &it2);
    amxc_llist_it_take(&it);

    assert_int_equal(amxc_llist_set_at(llist1, 3, &it), 0);
    assert_ptr_equal(it.next, NULL);
    assert_ptr_equal(it.prev, &it3);
    amxc_llist_it_take(&it);

    assert_int_equal(amxc_llist_set_at(llist1, 10, &it), -1);
    assert_ptr_equal(it.next, NULL);
    assert_ptr_equal(it.prev, NULL);
    amxc_llist_it_take(&it);
    amxc_llist_teardown();
}

void amxc_llist_get_first_check(UNUSED void** state) {
    assert_ptr_equal(amxc_llist_get_first(NULL), NULL);
}

void amxc_llist_get_last_check(UNUSED void** state) {
    assert_ptr_equal(amxc_llist_get_last(NULL), NULL);
}

void amxc_llist_it_init_null_check(UNUSED void** state) {
    // passing NULL pointers should not lead to segfault
    assert_int_equal(amxc_llist_it_init(NULL), -1);
}

void amxc_llist_it_init_check(UNUSED void** state) {
    amxc_llist_it_t it;

    assert_int_equal(amxc_llist_it_init(&it), 0);
    assert_ptr_equal(it.next, NULL);
    assert_ptr_equal(it.prev, NULL);
    assert_ptr_equal(it.llist, NULL);
}

void amxc_llist_it_clean_null_check(UNUSED void** state) {
    amxc_llist_it_t it;

    assert_int_equal(amxc_llist_it_init(&it), 0);

    // passing NULL pointers should not lead to segfault
    amxc_llist_it_clean(NULL, check_it_delete_func);
    amxc_llist_it_clean(&it, NULL);
}

void amxc_llist_it_clean_check(UNUSED void** state) {
    amxc_llist_it_t it;

    assert_int_equal(amxc_llist_it_init(&it), 0);
    amxc_llist_it_clean(&it, NULL);
}

void amxc_llist_it_clean_cb_check(UNUSED void** state) {
    assert_int_equal(amxc_llist_it_init(&s_it_func_check), 0);
    amxc_llist_it_clean(&s_it_func_check, check_it_delete_func);
}

static void amxc_llist_it_setup(void) {
    assert_int_equal(amxc_llist_new(&llist), 0);
    assert_int_equal(amxc_llist_it_init(&it1), 0);
    assert_int_equal(amxc_llist_it_init(&it2), 0);
    assert_int_equal(amxc_llist_it_init(&it3), 0);
    assert_int_equal(amxc_llist_append(llist, &it1), 0);
    assert_int_equal(amxc_llist_append(llist, &it2), 0);
    assert_int_equal(amxc_llist_append(llist, &it3), 0);

    assert_int_equal(amxc_llist_it_init(&s_it_func_check), 0);
}

static void amxc_llist_it_teardown(void) {
    amxc_llist_delete(&llist, NULL);
}

void amxc_llist_it_take_null_check(UNUSED void** state) {
    amxc_llist_it_take(NULL);
}

void amxc_llist_it_take_check(UNUSED void** state) {
    amxc_llist_it_setup();
    amxc_llist_it_take(&it2);
    assert_ptr_equal(llist->head, &it1);
    assert_ptr_equal(llist->tail, &it3);
    assert_ptr_equal(it1.next, &it3);
    assert_ptr_equal(it1.prev, NULL);
    assert_ptr_equal(it2.next, NULL);
    assert_ptr_equal(it2.prev, NULL);
    assert_ptr_equal(it3.next, NULL);
    assert_ptr_equal(it3.prev, &it1);
    assert_ptr_equal(it2.llist, NULL);
    amxc_llist_it_teardown();
}

void amxc_llist_it_take_double_check(UNUSED void** state) {
    amxc_llist_it_setup();
    amxc_llist_it_take(&it2);
    // remove the iterator again should not lead to segfault
    amxc_llist_it_take(&it2);
    amxc_llist_it_teardown();
}

void amxc_llist_it_insert_before_null_check(UNUSED void** state) {
    amxc_llist_it_setup();
    assert_int_equal(amxc_llist_it_insert_before(NULL, NULL), -1);
    assert_int_equal(amxc_llist_it_insert_before(&it1, NULL), -1);
    assert_ptr_equal(it1.next, &it2);
    assert_ptr_equal(it1.prev, NULL);
    assert_ptr_equal(it1.llist, llist);
    assert_int_equal(amxc_llist_it_insert_before(NULL, &it1), -1);
    assert_ptr_equal(it1.next, &it2);
    assert_ptr_equal(it1.prev, NULL);
    assert_ptr_equal(it1.llist, llist);
    amxc_llist_it_teardown();
}

void amxc_llist_it_insert_before_check(UNUSED void** state) {
    amxc_llist_it_setup();
    assert_int_equal(amxc_llist_it_insert_before(&it2, &s_it_func_check), 0);
    assert_ptr_equal(it1.next, &s_it_func_check);
    assert_ptr_equal(it1.prev, NULL);
    assert_ptr_equal(it2.next, &it3);
    assert_ptr_equal(it2.prev, &s_it_func_check);
    assert_ptr_equal(s_it_func_check.next, &it2);
    assert_ptr_equal(s_it_func_check.prev, &it1);
    assert_ptr_equal(s_it_func_check.llist, llist);
    amxc_llist_it_teardown();
}

void amxc_llist_it_insert_before_head_check(UNUSED void** state) {
    amxc_llist_it_setup();
    assert_int_equal(amxc_llist_it_insert_before(&it1, &s_it_func_check), 0);
    assert_ptr_equal(it1.next, &it2);
    assert_ptr_equal(it1.prev, &s_it_func_check);
    assert_ptr_equal(s_it_func_check.next, &it1);
    assert_ptr_equal(s_it_func_check.prev, NULL);
    assert_ptr_equal(s_it_func_check.llist, llist);
    amxc_llist_it_teardown();
}

void amxc_llist_it_insert_before_invalid_it_check(UNUSED void** state) {
    amxc_llist_it_setup();
    amxc_llist_it_take(&it2);

    assert_int_equal(amxc_llist_it_insert_before(&it2, &s_it_func_check), -1);
    assert_ptr_equal(it2.next, NULL);
    assert_ptr_equal(it2.prev, NULL);
    assert_ptr_equal(s_it_func_check.next, NULL);
    assert_ptr_equal(s_it_func_check.prev, NULL);
    assert_ptr_equal(s_it_func_check.llist, NULL);
    amxc_llist_it_teardown();
}

void amxc_llist_it_insert_after_null_check(UNUSED void** state) {
    amxc_llist_it_setup();
    assert_int_equal(amxc_llist_it_insert_after(NULL, NULL), -1);
    assert_int_equal(amxc_llist_it_insert_after(&it1, NULL), -1);
    assert_ptr_equal(it1.next, &it2);
    assert_ptr_equal(it1.prev, NULL);
    assert_ptr_equal(it1.llist, llist);
    assert_int_equal(amxc_llist_it_insert_after(NULL, &it1), -1);
    assert_ptr_equal(it1.next, &it2);
    assert_ptr_equal(it1.prev, NULL);
    assert_ptr_equal(it1.llist, llist);
    amxc_llist_it_teardown();
}

void amxc_llist_it_insert_after_check(UNUSED void** state) {
    amxc_llist_it_setup();
    assert_int_equal(amxc_llist_it_insert_after(&it2, &s_it_func_check), 0);
    assert_ptr_equal(it3.next, NULL);
    assert_ptr_equal(it3.prev, &s_it_func_check);
    assert_ptr_equal(it2.next, &s_it_func_check);
    assert_ptr_equal(it2.prev, &it1);
    assert_ptr_equal(s_it_func_check.next, &it3);
    assert_ptr_equal(s_it_func_check.prev, &it2);
    assert_ptr_equal(s_it_func_check.llist, llist);
    amxc_llist_it_teardown();
}

void amxc_llist_it_insert_after_tail_check(UNUSED void** state) {
    amxc_llist_it_setup();
    assert_int_equal(amxc_llist_it_insert_after(&it3, &s_it_func_check), 0);
    assert_ptr_equal(it3.next, &s_it_func_check);
    assert_ptr_equal(it3.prev, &it2);
    assert_ptr_equal(s_it_func_check.next, NULL);
    assert_ptr_equal(s_it_func_check.prev, &it3);
    assert_ptr_equal(s_it_func_check.llist, llist);
    amxc_llist_it_teardown();
}

void amxc_llist_it_insert_after_invalid_it_check(UNUSED void** state) {
    amxc_llist_it_setup();
    amxc_llist_it_take(&it2);

    assert_int_equal(amxc_llist_it_insert_after(&it2, &s_it_func_check), -1);
    assert_ptr_equal(it2.next, NULL);
    assert_ptr_equal(it2.prev, NULL);
    assert_ptr_equal(s_it_func_check.next, NULL);
    assert_ptr_equal(s_it_func_check.prev, NULL);
    assert_ptr_equal(s_it_func_check.llist, NULL);
    amxc_llist_it_teardown();
}

void amxc_llist_it_index_of_check(UNUSED void** state) {
    amxc_llist_it_setup();
    amxc_llist_it_t it;

    assert_int_equal(amxc_llist_it_init(&it), 0);
    assert_int_equal(amxc_llist_it_index_of(NULL), AMXC_LLIST_RANGE);
    assert_int_equal(amxc_llist_it_index_of(&it1), 0);
    assert_int_equal(amxc_llist_it_index_of(&it2), 1);
    assert_int_equal(amxc_llist_it_index_of(&it3), 2);
    assert_int_equal(amxc_llist_it_index_of(&it), AMXC_LLIST_RANGE);
    amxc_llist_it_teardown();
}

void amxc_llist_it_next_prev_check(UNUSED void** state) {
    amxc_llist_it_setup();

    assert_ptr_equal(amxc_llist_it_get_next(NULL), NULL);
    assert_ptr_equal(amxc_llist_it_get_previous(NULL), NULL);

    assert_ptr_equal(amxc_llist_it_get_next(&it1), &it2);
    assert_ptr_equal(amxc_llist_it_get_previous(&it2), &it1);
    assert_ptr_equal(amxc_llist_it_get_previous(&it1), NULL);
    assert_ptr_equal(amxc_llist_it_get_next(&it3), NULL);

    amxc_llist_it_teardown();
}

void amxc_llist_it_is_in_list_check(UNUSED void** state) {
    amxc_llist_it_setup();
    amxc_llist_it_t it;

    assert_int_equal(amxc_llist_it_init(&it), 0);

    assert_false(amxc_llist_it_is_in_list(NULL));
    assert_false(amxc_llist_it_is_in_list(&it));
    assert_true(amxc_llist_it_is_in_list(&it1));
    assert_true(amxc_llist_it_is_in_list(&it2));
    assert_true(amxc_llist_it_is_in_list(&it3));

    amxc_llist_it_teardown();
}

void amxc_llist_take_at_check(UNUSED void** state) {
    amxc_llist_it_setup();

    assert_ptr_equal(amxc_llist_take_at(NULL, 0), NULL);
    assert_ptr_equal(amxc_llist_take_at(NULL, 1), NULL);

    assert_ptr_equal(amxc_llist_take_at(llist, 2), &it3);
    assert_ptr_equal(amxc_llist_take_at(llist, 0), &it1);
    assert_ptr_equal(amxc_llist_take_at(llist, 0), &it2);

    amxc_llist_it_teardown();
}

void amxc_llist_swap_in_same_llist_check(UNUSED void** state) {
    amxc_llist_setup();

    assert_ptr_equal(amxc_llist_get_first(llist1), &it1);
    assert_int_equal(amxc_llist_it_swap(&it1, &it2), 0);
    assert_ptr_equal(amxc_llist_get_first(llist1), &it2);
    assert_ptr_equal(amxc_llist_it_get_next(&it1), &it3);
    assert_ptr_equal(amxc_llist_it_get_previous(&it1), &it2);
    assert_ptr_equal(amxc_llist_it_get_previous(&it2), NULL);
    assert_ptr_equal(amxc_llist_it_get_next(&it2), &it1);

    assert_int_equal(amxc_llist_it_swap(&it3, &it2), 0);
    assert_ptr_equal(amxc_llist_get_first(llist1), &it3);
    assert_ptr_equal(amxc_llist_it_get_next(&it1), &it2);
    assert_ptr_equal(amxc_llist_it_get_previous(&it1), &it3);
    assert_ptr_equal(amxc_llist_it_get_previous(&it3), NULL);
    assert_ptr_equal(amxc_llist_it_get_next(&it3), &it1);
    assert_ptr_equal(amxc_llist_get_last(llist1), &it2);

    assert_int_equal(amxc_llist_it_swap(&it1, &it3), 0);
    assert_int_equal(amxc_llist_it_swap(&it2, &it3), 0);
    assert_ptr_equal(amxc_llist_get_first(llist1), &it1);
    assert_ptr_equal(amxc_llist_it_get_next(&it1), &it2);
    assert_ptr_equal(amxc_llist_it_get_next(&it2), &it3);
    assert_ptr_equal(amxc_llist_it_get_next(&it3), NULL);
    assert_ptr_equal(amxc_llist_get_last(llist1), &it3);
    assert_ptr_equal(amxc_llist_it_get_previous(&it3), &it2);
    assert_ptr_equal(amxc_llist_it_get_previous(&it2), &it1);
    assert_ptr_equal(amxc_llist_it_get_previous(&it1), NULL);

    assert_int_equal(amxc_llist_it_swap(&it1, &it1), 0);
    assert_int_not_equal(amxc_llist_it_swap(&it1, NULL), 0);
    assert_int_not_equal(amxc_llist_it_swap(NULL, &it1), 0);

    amxc_llist_teardown();
}

void amxc_llist_swap_in_different_llist_check(UNUSED void** state) {
    amxc_llist_setup();

    assert_int_equal(amxc_llist_append(llist2, &it4), 0);
    assert_int_equal(amxc_llist_it_swap(&it4, &it1), 0);
    assert_ptr_equal(it4.llist, llist1);
    assert_ptr_equal(it1.llist, llist2);

    assert_ptr_equal(amxc_llist_it_get_next(&it1), NULL);
    assert_ptr_equal(amxc_llist_it_get_previous(&it1), NULL);

    assert_ptr_equal(amxc_llist_it_get_next(&it4), &it2);
    assert_ptr_equal(amxc_llist_it_get_previous(&it4), NULL);

    amxc_llist_it_take(&it3);
    assert_ptr_equal(it3.llist, NULL);
    assert_int_equal(amxc_llist_it_swap(&it4, &it3), 0);

    amxc_llist_teardown();
}

typedef struct {
    amxc_llist_it_t it;
    char data;
} test_data_t;

static int test_cmp(amxc_llist_it_t* it1, amxc_llist_it_t* it2) {
    test_data_t* d1 = amxc_llist_it_get_data(it1, test_data_t, it);
    test_data_t* d2 = amxc_llist_it_get_data(it2, test_data_t, it);

    if(d1->data < d2->data) {
        return -1;
    } else if(d1->data > d2->data) {
        return 1;
    }

    return 0;
}

static void test_del_data(amxc_llist_it_t* it) {
    test_data_t* d = amxc_llist_it_get_data(it, test_data_t, it);
    free(d);
}

void test_amxc_llist_sort(UNUSED void** state) {
    amxc_llist_t llist;
    const char data[16] = "KRATELEPUIMQCXOS";
    const char sorted[16] = "ACEEIKLMOPQRSTUX";

    amxc_llist_init(&llist);
    for(int i = 0; i < 16; i++) {
        test_data_t* item = calloc(1, sizeof(test_data_t));
        item->data = data[i];
        amxc_llist_append(&llist, &item->it);
    }

    assert_int_equal(amxc_llist_sort(&llist, test_cmp), 0);
    const amxc_llist_it_t* it = amxc_llist_get_first(&llist);
    for(unsigned int index = 0; index < 16; index++) {
        test_data_t* d = amxc_llist_it_get_data(it, test_data_t, it);
        printf("%c\n", d->data);
        assert_int_equal(d->data, sorted[index]);
        it = amxc_llist_it_get_next(it);
    }
    amxc_llist_clean(&llist, test_del_data);

    amxc_llist_init(&llist);
    assert_int_equal(amxc_llist_sort(&llist, test_cmp), 0);
    amxc_llist_clean(&llist, test_del_data);

    assert_int_not_equal(amxc_llist_sort(&llist, NULL), 0);
    assert_int_not_equal(amxc_llist_sort(NULL, test_cmp), 0);
}


void test_amxc_llist_move(UNUSED void** state) {
    amxc_llist_t src;
    amxc_llist_t dst;
    const char data[16] = "KRATELEPUIMQCXOS";

    amxc_llist_init(&src);
    amxc_llist_init(&dst);
    for(int i = 0; i < 16; i++) {
        test_data_t* item = calloc(1, sizeof(test_data_t));
        item->data = data[i];
        amxc_llist_append(&src, &item->it);
    }
    assert_int_equal(amxc_llist_size(&src), 16);
    assert_int_equal(amxc_llist_size(&dst), 0);

    assert_int_equal(amxc_llist_move(&dst, &src), 0);
    assert_int_equal(amxc_llist_size(&src), 0);
    assert_int_equal(amxc_llist_size(&dst), 16);

    for(int i = 0; i < 16; i++) {
        test_data_t* item = calloc(1, sizeof(test_data_t));
        item->data = data[i];
        amxc_llist_append(&src, &item->it);
    }

    assert_int_equal(amxc_llist_size(&src), 16);
    assert_int_equal(amxc_llist_size(&dst), 16);

    assert_int_equal(amxc_llist_move(&dst, &src), 0);
    assert_int_equal(amxc_llist_size(&src), 0);
    assert_int_equal(amxc_llist_size(&dst), 32);

    assert_int_not_equal(amxc_llist_move(&dst, NULL), 0);
    assert_int_not_equal(amxc_llist_move(NULL, &src), 0);

    amxc_llist_clean(&dst, test_del_data);
    amxc_llist_clean(&src, test_del_data);
}