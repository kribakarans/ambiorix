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
#include <sys/signalfd.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <fcntl.h>
#include <cmocka.h>

#include <amxc/amxc_macros.h>
#include <amxc/amxc.h>
#include <amxp/amxp_expression.h>

#include "../../include_priv/amxp_expr_priv.h"
#include "test_expression_node.h"

void test_node_tree_and(UNUSED void** state) {
    amxp_expr_node_t* node = NULL;
    amxp_expr_node_t* left = NULL;
    amxp_expr_node_t* right = NULL;
    amxc_var_t* b1 = NULL;
    amxc_var_t* b2 = NULL;
    amxp_expr_t expression;

    assert_int_equal(amxp_expr_init(&expression, ""), 0);

    amxp_expr_node_new(&node, amxp_expr_and);
    amxp_expr_node_new(&left, amxp_expr_value);
    amxp_expr_node_new(&right, amxp_expr_value);
    amxp_expr_node_set_left(node, left);
    amxp_expr_node_set_right(node, right);

    amxc_var_new(&b1);
    amxc_var_new(&b2);

    amxc_var_set(bool, b1, true);
    amxc_var_set(bool, b2, true);

    amxp_expr_node_set_value(left, b1);
    amxp_expr_node_set_value(right, b2);

    assert_true(amxp_expr_node_eval(&expression, node));

    amxc_var_set(bool, b1, false);

    assert_false(amxp_expr_node_eval(&expression, node));

    amxc_var_set(bool, b1, true);
    amxc_var_set(bool, b2, false);

    assert_false(amxp_expr_node_eval(&expression, node));

    amxp_expr_node_delete(&node);
    amxp_expr_clean(&expression);
}

void test_node_tree_or(UNUSED void** state) {
    amxp_expr_node_t* node = NULL;
    amxp_expr_node_t* left = NULL;
    amxp_expr_node_t* right = NULL;
    amxc_var_t* b1 = NULL;
    amxc_var_t* b2 = NULL;
    amxp_expr_t expression;

    assert_int_equal(amxp_expr_init(&expression, ""), 0);

    amxp_expr_node_new(&node, amxp_expr_or);
    amxp_expr_node_new(&left, amxp_expr_value);
    amxp_expr_node_new(&right, amxp_expr_value);
    amxp_expr_node_set_left(node, left);
    amxp_expr_node_set_right(node, right);

    amxc_var_new(&b1);
    amxc_var_new(&b2);

    amxc_var_set(bool, b1, true);
    amxc_var_set(bool, b2, true);

    amxp_expr_node_set_value(left, b1);
    amxp_expr_node_set_value(right, b2);

    assert_true(amxp_expr_node_eval(&expression, node));

    amxc_var_set(bool, b1, false);

    assert_true(amxp_expr_node_eval(&expression, node));

    amxc_var_set(bool, b1, true);
    amxc_var_set(bool, b2, false);

    assert_true(amxp_expr_node_eval(&expression, node));

    amxc_var_set(bool, b1, false);

    assert_false(amxp_expr_node_eval(&expression, node));

    amxp_expr_node_delete(&node);
    amxp_expr_clean(&expression);
}

void test_node_tree_not(UNUSED void** state) {
    amxp_expr_node_t* node = NULL;
    amxp_expr_node_t* left = NULL;
    amxc_var_t* b1 = NULL;
    amxp_expr_t expression;

    assert_int_equal(amxp_expr_init(&expression, ""), 0);

    amxp_expr_node_new(&node, amxp_expr_not);
    amxp_expr_node_new(&left, amxp_expr_value);
    amxp_expr_node_set_left(node, left);

    amxc_var_new(&b1);

    amxc_var_set(bool, b1, true);

    amxp_expr_node_set_value(left, b1);

    assert_false(amxp_expr_node_eval(&expression, node));

    amxc_var_set(bool, b1, false);

    assert_true(amxp_expr_node_eval(&expression, node));

    amxp_expr_node_delete(&node);
    amxp_expr_clean(&expression);
}

void test_node_tree_compop(UNUSED void** state) {
    amxp_expr_node_t* node = NULL;
    amxp_expr_node_t* left = NULL;
    amxp_expr_node_t* right = NULL;
    amxc_var_t* b1 = NULL;
    amxc_var_t* b2 = NULL;
    amxp_expr_t expression;

    assert_int_equal(amxp_expr_init(&expression, ""), 0);

    amxp_expr_node_new(&node, amxp_expr_compare_oper);
    amxp_expr_node_new(&left, amxp_expr_value);
    amxp_expr_node_new(&right, amxp_expr_value);
    amxp_expr_node_set_left(node, left);
    amxp_expr_node_set_right(node, right);

    amxc_var_new(&b1);
    amxc_var_new(&b2);

    amxc_var_set(int32_t, b1, 1);
    amxc_var_set(int32_t, b2, 10);

    amxp_expr_node_set_value(left, b1);
    amxp_expr_node_set_value(right, b2);
    amxp_expr_node_set_compop(node, amxp_expr_comp_equal);

    assert_false(amxp_expr_node_eval(&expression, node));

    amxp_expr_node_set_compop(node, amxp_expr_comp_not_equal);

    assert_true(amxp_expr_node_eval(&expression, node));

    amxp_expr_node_set_compop(node, amxp_expr_comp_lesser);

    assert_true(amxp_expr_node_eval(&expression, node));

    amxp_expr_node_set_compop(node, amxp_expr_comp_bigger);

    assert_false(amxp_expr_node_eval(&expression, node));

    amxp_expr_node_delete(&node);
    amxp_expr_clean(&expression);
}

void test_node_tree_field(UNUSED void** state) {
    amxp_expr_node_t* node = NULL;
    amxp_expr_node_t* left = NULL;
    amxp_expr_node_t* right = NULL;
    amxc_var_t* b1 = NULL;
    amxc_var_t* b2 = NULL;
    amxc_var_t* t = NULL;
    amxp_expr_t expression;

    amxc_var_new(&b1);
    amxc_var_new(&b2);

    assert_int_equal(amxp_expr_init(&expression, ""), 0);
    expression.priv = b1;
    expression.get_field = amxp_expr_get_field_var;

    amxp_expr_node_new(&node, amxp_expr_compare_oper);
    amxp_expr_node_new(&left, amxp_expr_field);
    amxp_expr_node_new(&right, amxp_expr_value);
    amxp_expr_node_set_left(node, left);
    amxp_expr_node_set_right(node, right);

    amxc_var_set_type(b1, AMXC_VAR_ID_HTABLE);
    t = amxc_var_add_key(amxc_htable_t, b1, "test", NULL);
    amxc_var_add_key(int32_t, t, "value", 1);
    amxc_var_set(int32_t, b2, 10);

    amxp_expr_node_set_field(left, strdup("test.value"));
    amxp_expr_node_set_value(right, b2);
    amxp_expr_node_set_compop(node, amxp_expr_comp_equal);

    assert_false(amxp_expr_node_eval(&expression, node));

    amxp_expr_node_set_compop(node, amxp_expr_comp_not_equal);

    assert_true(amxp_expr_node_eval(&expression, node));

    amxp_expr_node_set_compop(node, amxp_expr_comp_lesser);

    assert_true(amxp_expr_node_eval(&expression, node));

    amxp_expr_node_set_compop(node, amxp_expr_comp_bigger);

    assert_false(amxp_expr_node_eval(&expression, node));

    amxp_expr_node_delete(&node);
    amxp_expr_clean(&expression);
    amxc_var_delete(&b1);
}


void test_node_tree_value_list(UNUSED void** state) {
    amxp_expr_node_t* node = NULL;
    amxp_expr_node_t* left = NULL;
    amxp_expr_node_t* right = NULL;
    amxp_expr_node_t* value = NULL;
    amxp_expr_t expression;

    amxc_var_t* b1 = NULL;
    amxc_var_t* b2 = NULL;

    assert_int_equal(amxp_expr_init(&expression, ""), 0);

    amxp_expr_node_new(&node, amxp_expr_compare_oper);
    amxp_expr_node_new(&left, amxp_expr_value);
    amxp_expr_node_new(&right, amxp_expr_value);
    amxp_expr_node_set_left(node, left);
    amxp_expr_node_set_right(node, right);

    amxc_var_new(&b1);
    amxc_var_set(int32_t, b1, 1);
    amxp_expr_node_set_value(left, b1);

    amxc_var_new(&b2);
    amxp_expr_node_new(&value, amxp_expr_value);
    amxc_var_set(int32_t, b2, 1);
    amxp_expr_node_set_value(value, b2);
    amxp_expr_node_add_value(right, value);

    amxc_var_new(&b2);
    amxp_expr_node_new(&value, amxp_expr_value);
    amxc_var_set(int32_t, b2, 2);
    amxp_expr_node_set_value(value, b2);
    amxp_expr_node_add_value(right, value);

    amxc_var_new(&b2);
    amxp_expr_node_new(&value, amxp_expr_value);
    amxc_var_set(int32_t, b2, 3);
    amxp_expr_node_set_value(value, b2);
    amxp_expr_node_add_value(right, value);

    amxp_expr_node_set_compop(node, amxp_expr_comp_in);

    assert_true(amxp_expr_node_eval(&expression, node));

    amxc_var_set(int32_t, b1, 10);

    assert_false(amxp_expr_node_eval(&expression, node));

    amxc_var_set(int32_t, b1, 3);

    assert_true(amxp_expr_node_eval(&expression, node));

    amxp_expr_node_delete(&node);
    amxp_expr_clean(&expression);
}

void test_node_tree_bool_func(UNUSED void** state) {
    amxp_expr_node_t* node = NULL;
    amxp_expr_node_t* value = NULL;
    amxp_expr_t expression;
    amxc_var_t* data = NULL;
    amxc_var_t* list = NULL;

    amxc_var_new(&data);
    amxc_var_set_type(data, AMXC_VAR_ID_HTABLE);
    list = amxc_var_add_key(amxc_llist_t, data, "list", NULL);

    assert_int_equal(amxp_expr_init(&expression, ""), 0);
    expression.priv = data;
    expression.get_field = amxp_expr_get_field_var;

    amxp_expr_node_new(&node, amxp_expr_bool_func);
    amxp_expr_node_set_function(node, strdup("is_empty"));

    amxp_expr_node_new(&value, amxp_expr_field);
    amxp_expr_node_set_field(value, strdup("list"));
    amxp_expr_node_add_value(node, value);

    assert_true(amxp_expr_node_eval(&expression, node));

    amxc_var_add(cstring_t, list, "123");

    assert_false(amxp_expr_node_eval(&expression, node));

    amxp_expr_node_delete(&node);
    amxp_expr_clean(&expression);
    amxc_var_delete(&data);
}

void test_node_tree_value_func(UNUSED void** state) {
    amxp_expr_node_t* node = NULL;
    amxp_expr_node_t* left = NULL;
    amxp_expr_node_t* right = NULL;
    amxp_expr_node_t* value = NULL;
    amxp_expr_t expression;
    amxc_var_t* data = NULL;
    amxc_var_t* number = NULL;

    amxc_var_new(&data);
    amxc_var_set_type(data, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(int32_t, data, "key1", 10);

    assert_int_equal(amxp_expr_init(&expression, ""), 0);
    expression.priv = data;
    expression.get_field = amxp_expr_get_field_var;

    amxp_expr_node_new(&node, amxp_expr_compare_oper);
    amxp_expr_node_new(&left, amxp_expr_value);
    amxp_expr_node_new(&right, amxp_expr_value_func);
    amxp_expr_node_set_left(node, left);
    amxp_expr_node_set_right(node, right);

    amxp_expr_node_set_function(right, strdup("first_existing"));

    amxc_var_new(&number);
    amxc_var_set(int32_t, number, 10);
    amxp_expr_node_set_value(left, number);

    amxp_expr_node_new(&value, amxp_expr_field);
    amxp_expr_node_set_field(value, strdup("key1"));
    amxp_expr_node_add_value(right, value);
    amxp_expr_node_new(&value, amxp_expr_field);
    amxp_expr_node_set_field(value, strdup("key2"));
    amxp_expr_node_add_value(right, value);

    amxp_expr_node_set_compop(node, amxp_expr_comp_equal);

    assert_true(amxp_expr_node_eval(&expression, node));

    amxp_expr_node_delete(&node);
    amxp_expr_clean(&expression);
    amxc_var_delete(&data);
}