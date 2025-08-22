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

#include <string.h>
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

#include "test_variant_double.h"

#include <amxc/amxc_macros.h>
void test_variant_double_copy(UNUSED void** state) {
    amxc_var_t var;
    amxc_var_t copy_var;

    assert_int_equal(amxc_var_init(&var), 0);
    assert_int_equal(amxc_var_init(&copy_var), 0);

    assert_int_equal(amxc_var_set(double, &var, 3.141595), 0);
    assert_int_equal(amxc_var_type_of(&var), AMXC_VAR_ID_DOUBLE);

    assert_int_equal(amxc_var_copy(&copy_var, &var), 0);
    assert_int_equal(amxc_var_type_of(&copy_var), AMXC_VAR_ID_DOUBLE);
    assert_true(amxc_var_constcast(double, &copy_var) == 3.141595);

    amxc_var_clean(&var);
    amxc_var_clean(&copy_var);
}

void test_variant_double_convert_to_bool(UNUSED void** state) {
    amxc_var_t var;
    amxc_var_t copy_var;

    assert_int_equal(amxc_var_init(&var), 0);
    assert_int_equal(amxc_var_init(&copy_var), 0);

    assert_int_equal(amxc_var_set(double, &var, 3.141595), 0);
    assert_int_equal(amxc_var_type_of(&var), AMXC_VAR_ID_DOUBLE);

    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_BOOL), 0);
    assert_int_equal(amxc_var_type_of(&copy_var), AMXC_VAR_ID_BOOL);
    assert_true(amxc_var_constcast(bool, &copy_var));

    assert_int_equal(amxc_var_set(double, &var, 0), 0);
    assert_int_equal(amxc_var_type_of(&var), AMXC_VAR_ID_DOUBLE);

    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_BOOL), 0);
    assert_int_equal(amxc_var_type_of(&copy_var), AMXC_VAR_ID_BOOL);
    assert_false(amxc_var_constcast(bool, &copy_var));

    amxc_var_clean(&var);
    amxc_var_clean(&copy_var);
}

void test_variant_double_convert_to_integer(UNUSED void** state) {
    amxc_var_t var;
    amxc_var_t copy_var;

    assert_int_equal(amxc_var_init(&var), 0);
    assert_int_equal(amxc_var_init(&copy_var), 0);

    assert_int_equal(amxc_var_set(double, &var, 3.141595), 0);
    assert_int_equal(amxc_var_type_of(&var), AMXC_VAR_ID_DOUBLE);

    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_INT64), 0);
    assert_int_equal(amxc_var_type_of(&copy_var), AMXC_VAR_ID_INT64);
    assert_int_equal(amxc_var_constcast(int64_t, &copy_var), 3);

    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_INT32), 0);
    assert_int_equal(amxc_var_type_of(&copy_var), AMXC_VAR_ID_INT32);

    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_INT16), 0);
    assert_int_equal(amxc_var_type_of(&copy_var), AMXC_VAR_ID_INT16);

    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_INT8), 0);
    assert_int_equal(amxc_var_type_of(&copy_var), AMXC_VAR_ID_INT8);

    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_UINT64), 0);
    assert_int_equal(amxc_var_type_of(&copy_var), AMXC_VAR_ID_UINT64);
    assert_int_equal(amxc_var_constcast(uint64_t, &copy_var), 3);

    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_UINT32), 0);
    assert_int_equal(amxc_var_type_of(&copy_var), AMXC_VAR_ID_UINT32);

    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_UINT16), 0);
    assert_int_equal(amxc_var_type_of(&copy_var), AMXC_VAR_ID_UINT16);

    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_UINT8), 0);
    assert_int_equal(amxc_var_type_of(&copy_var), AMXC_VAR_ID_UINT8);

    amxc_var_clean(&var);
    amxc_var_clean(&copy_var);
}

void test_variant_double_convert_to_htable(UNUSED void** state) {
    amxc_var_t var;
    amxc_var_t copy_var;

    assert_int_equal(amxc_var_init(&var), 0);
    assert_int_equal(amxc_var_init(&copy_var), 0);

    assert_int_equal(amxc_var_set(double, &var, 3.141595), 0);
    assert_int_equal(amxc_var_type_of(&var), AMXC_VAR_ID_DOUBLE);

    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_HTABLE), 0);
    assert_int_equal(amxc_var_type_of(&copy_var), AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_htable_size(&copy_var.data.vm), 1);
    assert_false(amxc_htable_is_empty(&copy_var.data.vm));

    amxc_var_clean(&var);
    amxc_var_clean(&copy_var);
}

void test_variant_double_convert_to_list(UNUSED void** state) {
    amxc_var_t var;
    amxc_var_t copy_var;

    assert_int_equal(amxc_var_init(&var), 0);
    assert_int_equal(amxc_var_init(&copy_var), 0);

    assert_int_equal(amxc_var_set(double, &var, 3.141595), 0);
    assert_int_equal(amxc_var_type_of(&var), AMXC_VAR_ID_DOUBLE);

    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_LIST), 0);
    assert_int_equal(amxc_llist_size(&copy_var.data.vl), 1);
    assert_false(amxc_llist_is_empty(&copy_var.data.vl));

    amxc_var_clean(&var);
    amxc_var_clean(&copy_var);
}

void test_variant_double_convert_to_string(UNUSED void** state) {
    amxc_var_t var;
    amxc_var_t copy_var;

    assert_int_equal(amxc_var_init(&var), 0);
    assert_int_equal(amxc_var_init(&copy_var), 0);

    assert_int_equal(amxc_var_set(double, &var, 3.141595), 0);
    assert_int_equal(amxc_var_type_of(&var), AMXC_VAR_ID_DOUBLE);

    assert_int_equal(amxc_var_convert(&copy_var, &var, AMXC_VAR_ID_CSTRING), 0);
    assert_ptr_not_equal(copy_var.data.s, NULL);
    assert_string_equal(copy_var.data.s, "3.141595");

    amxc_var_clean(&var);
    amxc_var_clean(&copy_var);
}

void test_variant_double_compare(UNUSED void** state) {
    amxc_var_t var1;
    amxc_var_t var2;
    int result = 0;

    assert_int_equal(amxc_var_init(&var1), 0);
    assert_int_equal(amxc_var_init(&var2), 0);

    assert_int_equal(amxc_var_set(double, &var1, 3.141595), 0);
    assert_int_equal(amxc_var_type_of(&var1), AMXC_VAR_ID_DOUBLE);
    assert_int_equal(amxc_var_set(double, &var2, 3.141596), 0);
    assert_int_equal(amxc_var_type_of(&var2), AMXC_VAR_ID_DOUBLE);

    assert_int_equal(amxc_var_compare(&var1, &var2, &result), 0);
    assert_true(result < 0);
    assert_int_equal(amxc_var_compare(&var2, &var1, &result), 0);
    assert_true(result > 0);

    assert_int_equal(amxc_var_copy(&var1, &var2), 0);
    assert_int_equal(amxc_var_compare(&var1, &var2, &result), 0);
    assert_true(result == 0);

    amxc_var_clean(&var1);
    amxc_var_clean(&var2);
}

void test_variant_double_set_get(UNUSED void** state) {
    amxc_var_t var;

    assert_int_equal(amxc_var_init(&var), 0);

    assert_int_equal(amxc_var_set(double, &var, 3.141595), 0);
    assert_int_equal(amxc_var_type_of(&var), AMXC_VAR_ID_DOUBLE);

    assert_true(amxc_var_get_double(&var) == 3.141595);
    assert_true(amxc_var_get_double(NULL) == 0);

    amxc_var_clean(&var);
}

void test_variant_double_add(UNUSED void** state) {
    amxc_var_t var;
    const amxc_llist_t* list = NULL;
    const amxc_htable_t* table = NULL;

    assert_int_equal(amxc_var_init(&var), 0);
    assert_int_equal(amxc_var_set_type(&var, AMXC_VAR_ID_LIST), 0);
    assert_ptr_not_equal(amxc_var_add(double, &var, 3.1415), NULL);
    assert_ptr_not_equal(amxc_var_add(double, &var, 0.3333), NULL);

    assert_ptr_equal(amxc_var_add(double, NULL, 3.1415), NULL);
    assert_ptr_equal(amxc_var_add(double, NULL, 0.3333), NULL);

    list = amxc_var_constcast(amxc_llist_t, &var);
    assert_int_equal(amxc_llist_size(list), 2);
    amxc_var_clean(&var);

    assert_int_equal(amxc_var_init(&var), 0);
    assert_int_equal(amxc_var_set_type(&var, AMXC_VAR_ID_HTABLE), 0);
    assert_ptr_not_equal(amxc_var_add_key(double, &var, "B1", 3.1415), NULL);
    assert_ptr_not_equal(amxc_var_add_key(double, &var, "B2", 0.3333), NULL);

    assert_ptr_equal(amxc_var_add_key(double, NULL, "B1", 3.1415), NULL);
    assert_ptr_equal(amxc_var_add_key(double, NULL, "B2", 0.3333), NULL);

    table = amxc_var_constcast(amxc_htable_t, &var);
    assert_int_equal(amxc_htable_size(table), 2);
    amxc_var_clean(&var);
}