/****************************************************************************
**
** SPDX-License-Identifier: BSD-2-Clause-Patent
**
** SPDX-FileCopyrightText: Copyright (c) 2024 SoftAtHome
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

#include "test_amxc_var_add_value.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <math.h>

#include <amxc/amxc_variant.h>
#include <amxc_variant_priv.h>
#include <amxc/amxc_macros.h>
#include <amxc/amxc_variant.h>
#include "../common/newvar.h"
#include "../common/longtext.h"

/**
 * Adds `add_this` to `add_to_this` and checks if result is `expected_result`.
 */
static void s_assert_add_equals(amxc_var_t* add_to_this, amxc_var_t* add_this, amxc_var_t* expected_result) {
    int compare_status = -2;
    int compare_result = -2;
    assert_non_null(add_to_this);
    assert_non_null(add_this);
    assert_non_null(expected_result);
    assert_int_equal(amxc_var_add_value(add_to_this, add_this), 0);
    compare_status = amxc_var_compare(add_to_this, expected_result, &compare_result);
    // tip: if a test fails, simply put a breakpoint on "cm_print_error" to see where it fails.
    assert_int_equal(0, compare_status);
    assert_int_equal(0, compare_result);

    amxc_var_delete(&add_to_this);
    amxc_var_delete(&add_this);
    amxc_var_delete(&expected_result);
}

static void s_assert_add_unsupported(amxc_var_t* add_to_this, amxc_var_t* add_this) {
    // Note: we cannot use s_assert_add_equals here, because the null variant is not equal to itself
    //       according to amxc_var_compare.
    assert_non_null(add_to_this);
    assert_non_null(add_this);
    assert_int_not_equal(amxc_var_add_value(add_to_this, add_this), 0);
    assert_int_equal(0, amxc_var_type_of(add_to_this));

    amxc_var_delete(&add_to_this);
    amxc_var_delete(&add_this);
}

void test_amxc_var_add_value_string(UNUSED void** state) {
    s_assert_add_equals(newvar_cstring_t("hello"), newvar_cstring_t(" world"), newvar_cstring_t("hello world"));
    s_assert_add_equals(newvar_cstring_t(""), newvar_cstring_t("hi"), newvar_cstring_t("hi"));
    s_assert_add_equals(newvar_cstring_t("Hi"), newvar_cstring_t(""), newvar_cstring_t("Hi"));
    s_assert_add_equals(newvar_cstring_t(""), newvar_cstring_t(""), newvar_cstring_t(""));
    s_assert_add_equals(newvar_cstring_t("\\"), newvar_cstring_t("\""), newvar_cstring_t("\\\""));
    s_assert_add_equals(newvar_cstring_t("${somevar}"), newvar_cstring_t("bla"), newvar_cstring_t("${somevar}bla"));
    s_assert_add_equals(newvar_cstring_t("♥"), newvar_cstring_t("☃"), newvar_cstring_t("♥☃"));
    s_assert_add_equals(newvar_cstring_t("sometimes\n"), newvar_cstring_t("it rains!"), newvar_cstring_t("sometimes\nit rains!"));
    s_assert_add_equals(newvar_cstring_t(LONGTEXT1), newvar_cstring_t(LONGTEXT2), newvar_cstring_t(LONGTEXT1 LONGTEXT2));
}

void test_amxc_var_add_value_unsupported_types(UNUSED void** state) {
    // Null:
    s_assert_add_unsupported(newvar_null(), newvar_null());
    s_assert_add_unsupported(newvar_null(), newvar_cstring_t("hello"));
    s_assert_add_unsupported(newvar_null(), newvar_bool(false));
    s_assert_add_unsupported(newvar_null(), newvar_bool(false));
    s_assert_add_unsupported(newvar_null(), newvar_list((amxc_var_t*[2]) {newvar_cstring_t("hello")}));

    // Bool:
    s_assert_add_unsupported(newvar_bool(false), newvar_bool(false));

    // Fd:
    s_assert_add_unsupported(newvar_fd_t(0), newvar_fd_t(0));

    // csv:
    s_assert_add_unsupported(newvar_csv_string_t(" ab,[',c "), newvar_cstring_t(" d,'],f"));

    // ssv:
    s_assert_add_unsupported(newvar_ssv_string_t(" a b "), newvar_cstring_t(" c d "));
}

void test_amxc_var_add_value_i8(UNUSED void** state) {
    s_assert_add_equals(newvar_int8_t(1), newvar_int8_t(2), newvar_int8_t(3));

    s_assert_add_equals(newvar_int8_t(INT8_MIN), newvar_int8_t(0), newvar_int8_t(INT8_MIN));
    s_assert_add_equals(newvar_int8_t(INT8_MAX), newvar_int8_t(0), newvar_int8_t(INT8_MAX));
    s_assert_add_equals(newvar_int8_t(INT8_MIN), newvar_int8_t(1), newvar_int8_t(-127));
    s_assert_add_equals(newvar_int8_t(INT8_MAX), newvar_int8_t(-1), newvar_int8_t(126));
    s_assert_add_equals(newvar_int8_t(INT8_MIN), newvar_int8_t(INT8_MAX), newvar_int8_t(-1));

    s_assert_add_equals(newvar_int8_t(INT8_MIN + 1), newvar_int8_t(-1), newvar_int8_t(INT8_MIN));
    s_assert_add_equals(newvar_int8_t(-1), newvar_int8_t(INT8_MIN + 1), newvar_int8_t(INT8_MIN));
    s_assert_add_equals(newvar_int8_t(INT8_MAX - 1), newvar_int8_t(1), newvar_int8_t(INT8_MAX));
    s_assert_add_equals(newvar_int8_t(1), newvar_int8_t(INT8_MAX - 1), newvar_int8_t(INT8_MAX));

    s_assert_add_unsupported(newvar_int8_t(INT8_MIN), newvar_int8_t(-1));
    s_assert_add_unsupported(newvar_int8_t(-1), newvar_int8_t(INT8_MIN));
    s_assert_add_unsupported(newvar_int8_t(INT8_MAX), newvar_int8_t(1));
    s_assert_add_unsupported(newvar_int8_t(1), newvar_int8_t(INT8_MAX));
    s_assert_add_unsupported(newvar_int8_t(INT8_MIN + 10), newvar_int8_t(INT8_MIN + 10));
    s_assert_add_unsupported(newvar_int8_t(INT8_MAX - 10), newvar_int8_t(INT8_MAX - 10));
}

void test_amxc_var_add_value_i16(UNUSED void** state) {
    s_assert_add_equals(newvar_int16_t(1), newvar_int16_t(2), newvar_int16_t(3));

    s_assert_add_equals(newvar_int16_t(INT16_MIN), newvar_int16_t(0), newvar_int16_t(INT16_MIN));
    s_assert_add_equals(newvar_int16_t(INT16_MAX), newvar_int16_t(0), newvar_int16_t(INT16_MAX));
    s_assert_add_equals(newvar_int16_t(INT16_MIN), newvar_int16_t(1), newvar_int16_t(-32767));
    s_assert_add_equals(newvar_int16_t(INT16_MAX), newvar_int16_t(-1), newvar_int16_t(32766));
    s_assert_add_equals(newvar_int16_t(INT16_MIN), newvar_int16_t(INT16_MAX), newvar_int16_t(-1));
    s_assert_add_equals(newvar_int16_t(INT8_MIN), newvar_int16_t(INT8_MIN), newvar_int16_t(2 * INT8_MIN));
    s_assert_add_equals(newvar_int16_t(INT8_MAX), newvar_int16_t(INT8_MAX), newvar_int16_t(2 * INT8_MAX));

    s_assert_add_equals(newvar_int16_t(INT16_MIN + 1), newvar_int16_t(-1), newvar_int16_t(INT16_MIN));
    s_assert_add_equals(newvar_int16_t(-1), newvar_int16_t(INT16_MIN + 1), newvar_int16_t(INT16_MIN));
    s_assert_add_equals(newvar_int16_t(INT16_MAX - 1), newvar_int16_t(1), newvar_int16_t(INT16_MAX));
    s_assert_add_equals(newvar_int16_t(1), newvar_int16_t(INT16_MAX - 1), newvar_int16_t(INT16_MAX));

    s_assert_add_unsupported(newvar_int16_t(INT16_MIN), newvar_int16_t(-1));
    s_assert_add_unsupported(newvar_int16_t(-1), newvar_int16_t(INT16_MIN));
    s_assert_add_unsupported(newvar_int16_t(INT16_MAX), newvar_int16_t(1));
    s_assert_add_unsupported(newvar_int16_t(1), newvar_int16_t(INT16_MAX));

    s_assert_add_unsupported(newvar_int16_t(INT16_MIN + 10), newvar_int16_t(INT16_MIN + 10));
    s_assert_add_unsupported(newvar_int16_t(INT16_MAX - 10), newvar_int16_t(INT16_MAX - 10));
}

void test_amxc_var_add_value_i32(UNUSED void** state) {
    s_assert_add_equals(newvar_int32_t(1), newvar_int32_t(2), newvar_int32_t(3));

    s_assert_add_equals(newvar_int32_t(INT32_MIN), newvar_int32_t(0), newvar_int32_t(INT32_MIN));
    s_assert_add_equals(newvar_int32_t(INT32_MAX), newvar_int32_t(0), newvar_int32_t(INT32_MAX));
    s_assert_add_equals(newvar_int32_t(INT32_MIN), newvar_int32_t(1), newvar_int32_t(-2147483647));
    s_assert_add_equals(newvar_int32_t(INT32_MAX), newvar_int32_t(-1), newvar_int32_t(2147483646));
    s_assert_add_equals(newvar_int32_t(INT32_MIN), newvar_int32_t(INT32_MAX), newvar_int32_t(-1));

    s_assert_add_equals(newvar_int32_t(INT32_MIN + 1), newvar_int32_t(-1), newvar_int32_t(INT32_MIN));
    s_assert_add_equals(newvar_int32_t(-1), newvar_int32_t(INT32_MIN + 1), newvar_int32_t(INT32_MIN));
    s_assert_add_equals(newvar_int32_t(INT32_MAX - 1), newvar_int32_t(1), newvar_int32_t(INT32_MAX));
    s_assert_add_equals(newvar_int32_t(1), newvar_int32_t(INT32_MAX - 1), newvar_int32_t(INT32_MAX));

    s_assert_add_equals(newvar_int32_t(INT8_MIN), newvar_int32_t(INT8_MIN), newvar_int32_t(2 * INT8_MIN));
    s_assert_add_equals(newvar_int32_t(INT8_MAX), newvar_int32_t(INT8_MAX), newvar_int32_t(2 * INT8_MAX));
    s_assert_add_equals(newvar_int32_t(INT16_MIN), newvar_int32_t(INT16_MIN), newvar_int32_t(2 * INT16_MIN));
    s_assert_add_equals(newvar_int32_t(INT16_MAX), newvar_int32_t(INT16_MAX), newvar_int32_t(2 * INT16_MAX));

    s_assert_add_unsupported(newvar_int32_t(INT32_MIN), newvar_int32_t(-1));
    s_assert_add_unsupported(newvar_int32_t(-1), newvar_int32_t(INT32_MIN));
    s_assert_add_unsupported(newvar_int32_t(INT32_MAX), newvar_int32_t(1));
    s_assert_add_unsupported(newvar_int32_t(1), newvar_int32_t(INT32_MAX));
    s_assert_add_unsupported(newvar_int32_t(INT32_MIN + 10), newvar_int32_t(INT32_MIN + 10));
    s_assert_add_unsupported(newvar_int32_t(INT32_MAX - 10), newvar_int32_t(INT32_MAX - 10));
}

void test_amxc_var_add_value_i64(UNUSED void** state) {
    s_assert_add_equals(newvar_int64_t(1), newvar_int64_t(2), newvar_int64_t(3));

    s_assert_add_equals(newvar_int64_t(INT64_MIN), newvar_int64_t(0), newvar_int64_t(INT64_MIN));
    s_assert_add_equals(newvar_int64_t(INT64_MAX), newvar_int64_t(0), newvar_int64_t(INT64_MAX));
    s_assert_add_equals(newvar_int64_t(INT64_MIN), newvar_int64_t(1), newvar_int64_t(-9223372036854775807LL));
    s_assert_add_equals(newvar_int64_t(INT64_MAX), newvar_int64_t(-1), newvar_int64_t(9223372036854775806L));
    s_assert_add_equals(newvar_int64_t(INT64_MIN), newvar_int64_t(INT64_MAX), newvar_int64_t(-1));

    s_assert_add_equals(newvar_int64_t(INT64_MIN + 1), newvar_int64_t(-1), newvar_int64_t(INT64_MIN));
    s_assert_add_equals(newvar_int64_t(-1), newvar_int64_t(INT64_MIN + 1), newvar_int64_t(INT64_MIN));
    s_assert_add_equals(newvar_int64_t(INT64_MAX - 1), newvar_int64_t(1), newvar_int64_t(INT64_MAX));
    s_assert_add_equals(newvar_int64_t(1), newvar_int64_t(INT64_MAX - 1), newvar_int64_t(INT64_MAX));

    s_assert_add_equals(newvar_int64_t(INT8_MIN), newvar_int64_t(INT8_MIN), newvar_int64_t(2 * INT8_MIN));
    s_assert_add_equals(newvar_int64_t(INT8_MAX), newvar_int64_t(INT8_MAX), newvar_int64_t(2 * INT8_MAX));
    s_assert_add_equals(newvar_int64_t(INT16_MIN), newvar_int64_t(INT16_MIN), newvar_int64_t(2 * INT16_MIN));
    s_assert_add_equals(newvar_int64_t(INT16_MAX), newvar_int64_t(INT16_MAX), newvar_int64_t(2 * INT16_MAX));
    s_assert_add_equals(newvar_int64_t(INT32_MIN), newvar_int64_t(INT32_MIN), newvar_int64_t(-4294967296LL));
    s_assert_add_equals(newvar_int64_t(INT32_MAX), newvar_int64_t(INT32_MAX), newvar_int64_t(4294967294LL));

    s_assert_add_unsupported(newvar_int64_t(INT64_MIN), newvar_int64_t(-1));
    s_assert_add_unsupported(newvar_int64_t(-1), newvar_int64_t(INT64_MIN));
    s_assert_add_unsupported(newvar_int64_t(INT64_MAX), newvar_int64_t(1));
    s_assert_add_unsupported(newvar_int64_t(1), newvar_int64_t(INT64_MAX));
    s_assert_add_unsupported(newvar_int64_t(INT64_MIN + 10), newvar_int64_t(INT64_MIN + 10));
    s_assert_add_unsupported(newvar_int64_t(INT64_MAX - 10), newvar_int64_t(INT64_MAX - 10));
}

void test_amxc_var_add_value_u8(UNUSED void** state) {
    s_assert_add_equals(newvar_int8_t(1), newvar_uint8_t(2), newvar_uint8_t(3));
    s_assert_add_equals(newvar_uint8_t(0), newvar_uint8_t(0), newvar_uint8_t(0));
    s_assert_add_equals(newvar_uint8_t(UINT8_MAX), newvar_uint8_t(0), newvar_uint8_t(UINT8_MAX));

    s_assert_add_equals(newvar_uint8_t(UINT8_MAX - 1), newvar_uint8_t(1), newvar_uint8_t(UINT8_MAX));
    s_assert_add_equals(newvar_uint8_t(1), newvar_uint8_t(UINT8_MAX - 1), newvar_uint8_t(UINT8_MAX));
    s_assert_add_equals(newvar_uint8_t(0), newvar_uint8_t(UINT8_MAX), newvar_uint8_t(UINT8_MAX));

    s_assert_add_unsupported(newvar_uint8_t(UINT8_MAX), newvar_uint8_t(1));
    s_assert_add_unsupported(newvar_uint8_t(1), newvar_uint8_t(UINT8_MAX));
    s_assert_add_unsupported(newvar_uint8_t(UINT8_MAX - 10), newvar_uint8_t(UINT8_MAX - 10));
}

void test_amxc_var_add_value_u16(UNUSED void** state) {
    s_assert_add_equals(newvar_int16_t(1), newvar_uint16_t(2), newvar_uint16_t(3));
    s_assert_add_equals(newvar_uint16_t(0), newvar_uint16_t(0), newvar_uint16_t(0));
    s_assert_add_equals(newvar_uint16_t(UINT16_MAX), newvar_uint16_t(0), newvar_uint16_t(UINT16_MAX));

    s_assert_add_equals(newvar_uint16_t(UINT16_MAX - 1), newvar_uint16_t(1), newvar_uint16_t(UINT16_MAX));
    s_assert_add_equals(newvar_uint16_t(1), newvar_uint16_t(UINT16_MAX - 1), newvar_uint16_t(UINT16_MAX));
    s_assert_add_equals(newvar_uint16_t(0), newvar_uint16_t(UINT16_MAX), newvar_uint16_t(UINT16_MAX));
    s_assert_add_equals(newvar_uint16_t(UINT8_MAX), newvar_uint16_t(UINT8_MAX), newvar_uint16_t(2 * UINT8_MAX));

    s_assert_add_unsupported(newvar_uint16_t(UINT16_MAX), newvar_uint16_t(1));
    s_assert_add_unsupported(newvar_uint16_t(1), newvar_uint16_t(UINT16_MAX));
    s_assert_add_unsupported(newvar_uint16_t(UINT16_MAX - 10), newvar_uint16_t(UINT16_MAX - 10));
}

void test_amxc_var_add_value_u32(UNUSED void** state) {
    s_assert_add_equals(newvar_int32_t(1), newvar_uint32_t(2), newvar_uint32_t(3));
    s_assert_add_equals(newvar_uint32_t(0), newvar_uint32_t(0), newvar_uint32_t(0));
    s_assert_add_equals(newvar_uint32_t(UINT32_MAX), newvar_uint32_t(0), newvar_uint32_t(UINT32_MAX));

    s_assert_add_equals(newvar_uint32_t(UINT32_MAX - 1), newvar_uint32_t(1), newvar_uint32_t(UINT32_MAX));
    s_assert_add_equals(newvar_uint32_t(1), newvar_uint32_t(UINT32_MAX - 1), newvar_uint32_t(UINT32_MAX));
    s_assert_add_equals(newvar_uint32_t(0), newvar_uint32_t(UINT32_MAX), newvar_uint32_t(UINT32_MAX));
    s_assert_add_equals(newvar_uint32_t(UINT8_MAX), newvar_uint32_t(UINT8_MAX), newvar_uint32_t(2 * UINT8_MAX));
    s_assert_add_equals(newvar_uint32_t(UINT16_MAX), newvar_uint32_t(UINT16_MAX), newvar_uint32_t(2 * UINT16_MAX));

    s_assert_add_unsupported(newvar_uint32_t(UINT32_MAX), newvar_uint32_t(1));
    s_assert_add_unsupported(newvar_uint32_t(1), newvar_uint32_t(UINT32_MAX));
    s_assert_add_unsupported(newvar_uint32_t(UINT32_MAX - 10), newvar_uint32_t(UINT32_MAX - 10));
}

void test_amxc_var_add_value_u64(UNUSED void** state) {
    s_assert_add_equals(newvar_int64_t(1), newvar_uint64_t(2), newvar_uint64_t(3));
    s_assert_add_equals(newvar_uint64_t(0), newvar_uint64_t(0), newvar_uint64_t(0));
    s_assert_add_equals(newvar_uint64_t(UINT64_MAX), newvar_uint64_t(0), newvar_uint64_t(UINT64_MAX));

    s_assert_add_equals(newvar_uint64_t(UINT64_MAX - 1), newvar_uint64_t(1), newvar_uint64_t(UINT64_MAX));
    s_assert_add_equals(newvar_uint64_t(1), newvar_uint64_t(UINT64_MAX - 1), newvar_uint64_t(UINT64_MAX));
    s_assert_add_equals(newvar_uint64_t(0), newvar_uint64_t(UINT64_MAX), newvar_uint64_t(UINT64_MAX));
    s_assert_add_equals(newvar_uint64_t(UINT8_MAX), newvar_uint64_t(UINT8_MAX), newvar_uint64_t(2 * UINT8_MAX));
    s_assert_add_equals(newvar_uint64_t(UINT16_MAX), newvar_uint64_t(UINT16_MAX), newvar_uint64_t(2 * UINT16_MAX));
    s_assert_add_equals(newvar_uint64_t(UINT32_MAX), newvar_uint64_t(UINT32_MAX), newvar_uint64_t(2LL * UINT32_MAX));

    s_assert_add_unsupported(newvar_uint64_t(UINT64_MAX), newvar_uint64_t(1));
    s_assert_add_unsupported(newvar_uint64_t(1), newvar_uint64_t(UINT64_MAX));
    s_assert_add_unsupported(newvar_uint64_t(UINT64_MAX - 10), newvar_uint64_t(UINT64_MAX - 10));
}

void test_amxc_var_add_value_f64(UNUSED void** state) {
    s_assert_add_equals(newvar_double(1), newvar_double(2), newvar_double(3));
    s_assert_add_equals(newvar_double(1), newvar_double(-1), newvar_double(0));
    s_assert_add_equals(newvar_double(3.14159265), newvar_double(3.14159265), newvar_double(6.28318530));
    s_assert_add_equals(newvar_double(INFINITY), newvar_double(1), newvar_double(INFINITY));
}

void test_amxc_var_add_value_list(UNUSED void** state) {
    s_assert_add_equals(newvar_list_empty(), newvar_list_empty(), newvar_list_empty());
    s_assert_add_equals(
        newvar_list((amxc_var_t*[]) {newvar_int16_t(1), newvar_int16_t(2), NULL}),
        newvar_list((amxc_var_t*[]) {newvar_int16_t(3), newvar_int16_t(4), NULL}),
        newvar_list((amxc_var_t*[]) {newvar_int16_t(1), newvar_int16_t(2), newvar_int16_t(3), newvar_int16_t(4), NULL}));
    s_assert_add_equals(
        newvar_list((amxc_var_t*[]) {newvar_int16_t(123), newvar_int8_t(45), NULL}),
        newvar_list((amxc_var_t*[]) {newvar_bool(true), NULL}),
        newvar_list((amxc_var_t*[]) {newvar_int16_t(123), newvar_int8_t(45), newvar_bool(true), NULL }));
    s_assert_add_equals(
        newvar_list((amxc_var_t*[]) {newvar_cstring_t("hello"), NULL}),
        newvar_list_empty(),
        newvar_list((amxc_var_t*[]) {newvar_cstring_t("hello"), NULL}));
    s_assert_add_equals(
        newvar_list_empty(),
        newvar_list((amxc_var_t*[]) {newvar_cstring_t("hello"), NULL}),
        newvar_list((amxc_var_t*[]) {newvar_cstring_t("hello"), NULL}));
    s_assert_add_equals(
        newvar_list((amxc_var_t*[]) {newvar_list_empty(), NULL}),
        newvar_list((amxc_var_t*[]) {newvar_list_empty(), NULL}),
        newvar_list((amxc_var_t*[]) {newvar_list_empty(), newvar_list_empty(), NULL}));
}

void test_amxc_var_add_value_htable(UNUSED void** state) {
    s_assert_add_equals(newvar_htable_empty(), newvar_htable_empty(), newvar_htable_empty());

    s_assert_add_equals(
        newvar_htable((newvar_kv_t*[]) {
        &(newvar_kv_t) { "key1", newvar_cstring_t("value1")},
        NULL
    }),
        newvar_htable((newvar_kv_t*[]) {
        &(newvar_kv_t) { "key2", newvar_cstring_t("value2")},
        NULL
    }),
        newvar_htable((newvar_kv_t*[]) {
        &(newvar_kv_t) { "key1", newvar_cstring_t("value1")},
        &(newvar_kv_t) { "key2", newvar_cstring_t("value2")},
        NULL
    }));
}

void test_amxc_var_add_value_htable_overwrite(UNUSED void** state) {
    // GIVEN two variants containing a htable that have the same key
    amxc_var_t* var1 = newvar_htable((newvar_kv_t*[]) {
        &(newvar_kv_t) { "samekey", newvar_cstring_t("value1")},
        NULL
    });
    amxc_var_t* var2 = newvar_htable((newvar_kv_t*[]) {
        &(newvar_kv_t) { "samekey", newvar_cstring_t("value2")},
        NULL
    });

    // WHEN adding those (var1 += var2)
    // THEN the resulting htable doe not map twice the key to a value (while an amxc_htable_t allows this,
    //      an amxc_var_t containing a htable does not)
    //      and instead maps to the new value.
    s_assert_add_equals(var1, var2,
                        newvar_htable((newvar_kv_t*[]) {
        &(newvar_kv_t) { "samekey", newvar_cstring_t("value2")},
        NULL
    }));
}

void test_amxc_var_add_value_conversion_needed(UNUSED void** state) {
    s_assert_add_equals(newvar_int32_t(1), newvar_int16_t(2), newvar_int16_t(3));
    s_assert_add_equals(newvar_uint16_t(1), newvar_int16_t(2), newvar_int16_t(3));
    s_assert_add_unsupported(newvar_int16_t(1), newvar_uint16_t(INT16_MAX + 1));
    s_assert_add_equals(newvar_cstring_t("hello"), newvar_int32_t(123), newvar_cstring_t("hello123"));
}
