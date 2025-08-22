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

#include <amxc/amxc_variant.h>
#include <amxc_variant_priv.h>

#include "test_variant_uint16.h"

#include <amxc/amxc_macros.h>
void test_variant_uint16_copy(UNUSED void** state) {
    amxc_var_t var;
    amxc_var_t copy_var;

    assert_int_equal(amxc_var_init(&var), 0);
    assert_int_equal(amxc_var_init(&copy_var), 0);
    assert_int_equal(var.type_id, AMXC_VAR_ID_NULL);
    assert_int_equal(amxc_var_set_type(&var, AMXC_VAR_ID_UINT16), 0);
    assert_int_equal(var.type_id, AMXC_VAR_ID_UINT16);
    var.data.ui16 = 65535;

    assert_int_equal(amxc_var_copy(&copy_var, &var), 0);
    var.data.ui16 = 65535;
}

void test_variant_uint16_convert_to(UNUSED void** state) {
    amxc_var_t var;
    amxc_var_t copy_var;


    assert_int_equal(amxc_var_init(&var), 0);
    assert_int_equal(amxc_var_init(&copy_var), 0);
    assert_int_equal(var.type_id, AMXC_VAR_ID_NULL);
    assert_int_equal(amxc_var_set_type(&var, AMXC_VAR_ID_UINT16), 0);
    assert_int_equal(var.type_id, AMXC_VAR_ID_UINT16);

    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_NULL), 0);
    assert_int_equal(copy_var.type_id, AMXC_VAR_ID_NULL);
    assert_ptr_equal(copy_var.data.data, NULL);
    var.data.ui16 = 0xF000;
    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(copy_var.type_id, AMXC_VAR_ID_CSTRING);
    assert_string_equal(copy_var.data.s, "61440");

    var.data.ui16 = 0xF000;
    assert_int_not_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_INT8), 0);
    var.data.ui16 = 0x1001;
    assert_int_not_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_INT8), 0);
    var.data.ui16 = 127;
    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_INT8), 0);
    assert_int_equal(copy_var.type_id, AMXC_VAR_ID_INT8);
    assert_int_equal(copy_var.data.i8, 127);

    var.data.ui16 = 0xF000;
    assert_int_not_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_INT16), 0);
    var.data.ui16 = 0x1001;
    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_INT16), 0);
    var.data.ui16 = 1024;
    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_INT16), 0);
    assert_int_equal(copy_var.type_id, AMXC_VAR_ID_INT16);
    assert_int_equal(copy_var.data.i16, 1024);

    var.data.ui16 = 32766;
    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_INT32), 0);
    assert_int_equal(copy_var.type_id, AMXC_VAR_ID_INT32);
    assert_int_equal(copy_var.data.i32, 32766);

    var.data.ui16 = 0xF00;
    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_INT32), 0);
    var.data.ui16 = 32766;
    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_INT32), 0);
    assert_int_equal(copy_var.type_id, AMXC_VAR_ID_INT32);
    assert_int_equal(copy_var.data.i32, 32766);

    var.data.ui16 = UINT16_MAX;
    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_INT64), 0);
    assert_int_equal(copy_var.type_id, AMXC_VAR_ID_INT64);
    assert_int_equal(copy_var.data.i64, UINT16_MAX);

    var.data.ui16 = 256;
    assert_int_not_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_UINT8), 0);
    var.data.ui16 = 255;
    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_UINT8), 0);
    assert_int_equal(copy_var.type_id, AMXC_VAR_ID_UINT8);
    assert_int_equal(copy_var.data.ui8, 255);

    var.data.ui16 = 65535;
    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_UINT16), 0);
    assert_int_equal(copy_var.type_id, AMXC_VAR_ID_UINT16);
    assert_int_equal(copy_var.data.ui16, 65535);

    var.data.ui16 = 65535;
    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_UINT32), 0);
    assert_int_equal(copy_var.type_id, AMXC_VAR_ID_UINT32);
    assert_int_equal(copy_var.data.ui32, 65535);

    var.data.ui16 = UINT16_MAX;
    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_UINT64), 0);
    assert_int_equal(copy_var.type_id, AMXC_VAR_ID_UINT64);
    assert_int_equal(copy_var.data.ui64, UINT16_MAX);

    var.data.ui16 = 1000;
    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_TIMESTAMP), 0);
    assert_int_equal(copy_var.type_id, AMXC_VAR_ID_TIMESTAMP);
    var.data.ui16 = -1000;
    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_TIMESTAMP), 0);
    assert_int_equal(copy_var.type_id, AMXC_VAR_ID_TIMESTAMP);

    var.data.ui16 = 0xF000;
    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_BOOL), 0);
    assert_int_equal(copy_var.type_id, AMXC_VAR_ID_BOOL);
    assert_true(copy_var.data.b);
    var.data.ui16 = 0x00;
    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_BOOL), 0);
    assert_int_equal(copy_var.type_id, AMXC_VAR_ID_BOOL);
    assert_false(copy_var.data.b);

    var.data.ui16 = UINT16_MAX;
    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_FLOAT), 0);
    assert_int_equal(copy_var.type_id, AMXC_VAR_ID_FLOAT);
    assert_true(copy_var.data.f == UINT16_MAX);

    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_DOUBLE), 0);
    assert_int_equal(copy_var.type_id, AMXC_VAR_ID_DOUBLE);
    assert_true(copy_var.data.d == UINT16_MAX);

    struct rlimit nofile = { 0, 0 };
    assert_int_equal(getrlimit(RLIMIT_NOFILE, &nofile), 0);

    var.data.ui16 = 0xE0;
    assert_int_not_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_FD), 0);
    var.data.ui16 = STDIN_FILENO;
    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_FD), 0);
    assert_int_equal(copy_var.type_id, AMXC_VAR_ID_FD);
    assert_int_equal(copy_var.data.fd, STDIN_FILENO);

    assert_int_not_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_CUSTOM_BASE), 0);

}

void test_variant_uint16_compare(UNUSED void** state) {
    amxc_var_t var1;
    amxc_var_t var2;
    int result = 0;

    assert_int_equal(amxc_var_init(&var1), 0);
    assert_int_equal(amxc_var_init(&var2), 0);
    assert_int_equal(amxc_var_set_type(&var1, AMXC_VAR_ID_UINT16), 0);
    assert_int_equal(var1.type_id, AMXC_VAR_ID_UINT16);
    var1.data.ui16 = 65535;
    assert_int_equal(amxc_var_set_type(&var2, AMXC_VAR_ID_UINT16), 0);
    assert_int_equal(var2.type_id, AMXC_VAR_ID_UINT16);
    var2.data.ui16 = 10;

    assert_int_equal(amxc_var_compare(&var1, &var2, &result), 0);
    assert_true(result > 0);

    assert_int_equal(amxc_var_compare(&var2, &var1, &result), 0);
    assert_true(result < 0);

    var2.data.ui16 = 65535;
    assert_int_equal(amxc_var_compare(&var2, &var1, &result), 0);
    assert_true(result == 0);

}

void test_variant_uint16_set_get(UNUSED void** state) {
    amxc_var_t var1;

    assert_int_equal(amxc_var_init(&var1), 0);
    assert_int_equal(amxc_var_set_uint16_t(&var1, 1024), 0);
    assert_int_equal(var1.type_id, AMXC_VAR_ID_UINT16);
    assert_true(var1.data.ui16 = 1024);

    assert_true(amxc_var_get_uint16_t(&var1) == 1024);
    assert_true(amxc_var_dyncast(uint16_t, &var1) == 1024);

    assert_int_not_equal(amxc_var_set_uint16_t(NULL, 512), 0);
    assert_true(amxc_var_get_uint16_t(NULL) == 0);

    assert_int_equal(amxc_var_constcast(uint16_t, &var1), 1024);
    assert_int_equal(amxc_var_constcast(int16_t, &var1), 0);
    assert_int_equal(amxc_var_constcast(uint16_t, NULL), 0);
}

void test_variant_uint16_add(UNUSED void** state) {
    amxc_var_t var;
    const amxc_llist_t* list = NULL;
    const amxc_htable_t* table = NULL;

    assert_int_equal(amxc_var_init(&var), 0);
    assert_int_equal(amxc_var_set_type(&var, AMXC_VAR_ID_LIST), 0);
    assert_ptr_not_equal(amxc_var_add(uint16_t, &var, 123), NULL);
    assert_ptr_not_equal(amxc_var_add(uint16_t, &var, 456), NULL);

    assert_ptr_equal(amxc_var_add(uint16_t, NULL, 123), NULL);
    assert_ptr_equal(amxc_var_add(uint16_t, NULL, 456), NULL);

    list = amxc_var_constcast(amxc_llist_t, &var);
    assert_int_equal(amxc_llist_size(list), 2);
    amxc_var_clean(&var);

    assert_int_equal(amxc_var_init(&var), 0);
    assert_int_equal(amxc_var_set_type(&var, AMXC_VAR_ID_HTABLE), 0);
    assert_ptr_not_equal(amxc_var_add_key(uint16_t, &var, "B1", 123), NULL);
    assert_ptr_not_equal(amxc_var_add_key(uint16_t, &var, "B2", 456), NULL);

    assert_ptr_equal(amxc_var_add_key(uint16_t, NULL, "B1", 123), NULL);
    assert_ptr_equal(amxc_var_add_key(uint16_t, NULL, "B2", 456), NULL);

    table = amxc_var_constcast(amxc_htable_t, &var);
    assert_int_equal(amxc_htable_size(table), 2);
    amxc_var_clean(&var);
}