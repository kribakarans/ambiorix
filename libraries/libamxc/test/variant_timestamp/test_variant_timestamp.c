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
#include <setjmp.h>
#include <cmocka.h>
#include <unistd.h>

#include <amxc/amxc_variant.h>
#include <amxc_variant_priv.h>

#include "test_variant_timestamp.h"

#include <amxc/amxc_macros.h>
void test_variant_ts_copy(UNUSED void** state) {
    amxc_var_t var;
    amxc_var_t copy_var;
    amxc_ts_t now;

    amxc_ts_now(&now);

    assert_int_equal(amxc_var_init(&var), 0);
    assert_int_equal(amxc_var_init(&copy_var), 0);
    assert_int_equal(var.type_id, AMXC_VAR_ID_NULL);
    assert_int_equal(amxc_var_set_type(&var, AMXC_VAR_ID_TIMESTAMP), 0);
    assert_int_equal(var.type_id, AMXC_VAR_ID_TIMESTAMP);
    assert_int_equal(amxc_var_set(amxc_ts_t, &var, &now), 0);

    assert_int_equal(copy_var.type_id, AMXC_VAR_ID_NULL);
    assert_int_equal(amxc_var_copy(&copy_var, &var), 0);
    assert_int_equal(copy_var.type_id, AMXC_VAR_ID_TIMESTAMP);
    assert_int_equal(copy_var.data.ts.sec, now.sec);

    amxc_var_clean(&var);
    amxc_var_clean(&copy_var);
}

void test_variant_ts_convert_to_string(UNUSED void** state) {
    amxc_var_t var;
    amxc_var_t copy_var;

    assert_int_equal(amxc_var_init(&var), 0);
    assert_int_equal(amxc_var_init(&copy_var), 0);
    assert_int_equal(amxc_var_set_type(&var, AMXC_VAR_ID_TIMESTAMP), 0);
    amxc_var_dump(&var, STDOUT_FILENO);

    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_CSTRING), 0);
    assert_string_equal(copy_var.data.s, "0001-01-01T00:00:00Z");
    amxc_var_dump(&copy_var, STDOUT_FILENO);
    amxc_var_clean(&var);
    amxc_var_clean(&copy_var);
}

void test_variant_ts_convert_to_int64(UNUSED void** state) {
    amxc_var_t var;
    amxc_var_t copy_var;
    amxc_ts_t now;

    amxc_ts_now(&now);

    assert_int_equal(amxc_var_init(&var), 0);
    assert_int_equal(amxc_var_init(&copy_var), 0);
    assert_int_equal(amxc_var_set(amxc_ts_t, &var, &now), 0);
    assert_int_equal(var.type_id, AMXC_VAR_ID_TIMESTAMP);

    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_INT64), 0);
    assert_int_equal(copy_var.data.i64, now.sec);

    amxc_var_clean(&var);
    amxc_var_clean(&copy_var);
}

void test_variant_ts_convert_to_other_int(UNUSED void** state) {
    amxc_var_t var;
    amxc_var_t copy_var;
    amxc_ts_t now;

    amxc_ts_now(&now);

    assert_int_equal(amxc_var_init(&var), 0);
    assert_int_equal(amxc_var_init(&copy_var), 0);
    assert_int_equal(amxc_var_set(amxc_ts_t, &var, &now), 0);
    assert_int_equal(var.type_id, AMXC_VAR_ID_TIMESTAMP);

    assert_int_not_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_INT8), 0);
    assert_int_not_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_INT16), 0);
    assert_int_not_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_INT32), 0);
    assert_int_not_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_UINT8), 0);
    assert_int_not_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_UINT16), 0);
    assert_int_not_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_UINT32), 0);
    assert_int_not_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_UINT64), 0);

    amxc_var_clean(&var);
    amxc_var_clean(&copy_var);
}

void test_variant_ts_convert_to_double(UNUSED void** state) {
    amxc_var_t var;
    amxc_var_t copy_var;
    amxc_ts_t now;

    amxc_ts_now(&now);

    assert_int_equal(amxc_var_init(&var), 0);
    assert_int_equal(amxc_var_init(&copy_var), 0);
    assert_int_equal(amxc_var_set(amxc_ts_t, &var, &now), 0);
    assert_int_equal(var.type_id, AMXC_VAR_ID_TIMESTAMP);

    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_DOUBLE), 0);
    assert_true(copy_var.data.d == var.data.ts.sec);

    amxc_var_clean(&var);
    amxc_var_clean(&copy_var);
}

void test_variant_ts_convert_to_any(UNUSED void** state) {
    amxc_var_t var;
    amxc_var_t copy_var;
    amxc_ts_t now;

    amxc_ts_now(&now);

    assert_int_equal(amxc_var_init(&var), 0);
    assert_int_equal(amxc_var_init(&copy_var), 0);
    assert_int_equal(amxc_var_set(amxc_ts_t, &var, &now), 0);
    assert_int_equal(var.type_id, AMXC_VAR_ID_TIMESTAMP);

    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_ANY), 0);
    assert_int_equal(copy_var.type_id, AMXC_VAR_ID_TIMESTAMP);

    amxc_var_clean(&var);
    amxc_var_clean(&copy_var);
}


void test_variant_ts_compare(UNUSED void** state) {
    amxc_var_t var1;
    amxc_var_t var2;
    amxc_var_t var3;
    int result = 0;

    assert_int_equal(amxc_var_init(&var1), 0);
    assert_int_equal(amxc_var_init(&var2), 0);
    assert_int_equal(amxc_var_init(&var3), 0);

    assert_int_equal(amxc_var_set(cstring_t, &var1, "2020-06-19T09:08:16Z"), 0);
    assert_int_equal(amxc_var_set(cstring_t, &var2, "2020-06-19T09:08:17Z"), 0);
    assert_int_equal(amxc_var_convert(&var3, &var1, AMXC_VAR_ID_TIMESTAMP), 0);

    assert_int_equal(amxc_var_compare(&var1, &var3, &result), 0);
    assert_true(result == 0);
    assert_int_equal(amxc_var_compare(&var2, &var3, &result), 0);
    assert_true(result > 0);
    assert_int_equal(amxc_var_compare(&var3, &var2, &result), 0);
    assert_true(result < 0);

    amxc_var_clean(&var1);
    amxc_var_clean(&var2);
    amxc_var_clean(&var3);
}

void test_variant_ts_get(UNUSED void** state) {
    amxc_var_t var1;
    amxc_var_t var2;
    amxc_ts_t* ts = NULL;
    const amxc_ts_t* cts = NULL;

    assert_int_equal(amxc_var_init(&var1), 0);
    assert_int_equal(amxc_var_init(&var2), 0);

    assert_int_equal(amxc_var_set(cstring_t, &var1, "2020-06-19T09:08:16Z"), 0);
    ts = amxc_var_dyncast(amxc_ts_t, &var1);
    assert_ptr_not_equal(ts, NULL);
    assert_int_equal(amxc_var_set(amxc_ts_t, &var2, ts), 0);
    cts = amxc_var_constcast(amxc_ts_t, &var2);
    assert_ptr_not_equal(cts, NULL);
    cts = amxc_var_constcast(amxc_ts_t, &var1);
    assert_ptr_equal(cts, NULL);

    assert_int_not_equal(amxc_var_set(amxc_ts_t, NULL, ts), 0);
    assert_int_not_equal(amxc_var_set(amxc_ts_t, &var2, NULL), 0);

    assert_ptr_equal(amxc_var_dyncast(amxc_ts_t, NULL), NULL);
    assert_ptr_equal(amxc_var_constcast(amxc_ts_t, NULL), NULL);
    free(ts);

    assert_int_equal(amxc_var_set(cstring_t, &var1, "THIS is NOT a TIMESTAMP"), 0);
    ts = amxc_var_dyncast(amxc_ts_t, &var1);
    assert_ptr_equal(ts, NULL);

    amxc_var_clean(&var1);
    amxc_var_clean(&var2);
    free(ts);
}

void test_variant_ts_add_to_composite_types(UNUSED void** state) {
    amxc_var_t var1;
    amxc_var_t var2;
    amxc_ts_t now;

    amxc_ts_now(&now);

    assert_int_equal(amxc_var_init(&var1), 0);
    assert_int_equal(amxc_var_init(&var2), 0);

    amxc_var_set_type(&var1, AMXC_VAR_ID_LIST);
    assert_ptr_not_equal(amxc_var_add(amxc_ts_t, &var1, &now), NULL);
    assert_ptr_not_equal(amxc_var_add(amxc_ts_t, &var1, NULL), NULL);

    amxc_var_set_type(&var2, AMXC_VAR_ID_HTABLE);
    assert_ptr_not_equal(amxc_var_add_key(amxc_ts_t, &var2, "current_time", &now), NULL);
    assert_ptr_not_equal(amxc_var_add_key(amxc_ts_t, &var2, "uknown_time", NULL), NULL);

    assert_ptr_equal(amxc_var_add(amxc_ts_t, NULL, &now), NULL);
    assert_ptr_equal(amxc_var_add_key(amxc_ts_t, NULL, "current_time", &now), NULL);

    amxc_var_clean(&var1);
    amxc_var_clean(&var2);
}