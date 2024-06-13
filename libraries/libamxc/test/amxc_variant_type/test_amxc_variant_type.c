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

#include <amxc/amxc_variant_type.h>
#include <amxc_variant_priv.h>

#include "test_amxc_variant_type.h"

#include <amxc/amxc_macros.h>
static amxc_var_type_t dummy1 =
{
    .copy = NULL,
    .convert_from = NULL,
    .convert_to = NULL,
    .compare = NULL,
    .del = NULL,
    .name = "dummy1_t"
};

static amxc_var_type_t dummy2 =
{
    .copy = NULL,
    .convert_from = NULL,
    .convert_to = NULL,
    .compare = NULL,
    .del = NULL,
    .name = "dummy2_t"
};

static amxc_var_type_t dummy3 =
{
    .copy = NULL,
    .convert_from = NULL,
    .convert_to = NULL,
    .compare = NULL,
    .del = NULL,
    .name = "dummy3_t"
};

static amxc_var_type_t dummy4 =
{
    .copy = NULL,
    .convert_from = NULL,
    .convert_to = NULL,
    .compare = NULL,
    .del = NULL,
    .name = "dummy4_t"
};

void test_amxc_var_add_type(UNUSED void** state) {
    amxc_array_t* types = amxc_variant_get_types_array();

    assert_int_equal(amxc_var_add_type(&dummy1, 0), 0);
    assert_ptr_equal(amxc_array_get_at(types, 0)->data, &dummy1);
    assert_int_equal(dummy1.type_id, 0);
    assert_int_equal(amxc_var_add_type(&dummy1, 1), 0);
    assert_ptr_equal(amxc_array_get_at(types, 0)->data, &dummy1);
    assert_int_equal(amxc_var_add_type(&dummy1, 0), 0);
    assert_ptr_equal(amxc_array_get_at(types, 0)->data, &dummy1);

    assert_int_equal(amxc_var_add_type(&dummy2, -1), AMXC_VAR_ID_CUSTOM_BASE);
    assert_int_equal(dummy2.type_id, AMXC_VAR_ID_CUSTOM_BASE);
    assert_ptr_equal(amxc_array_get_at(types, AMXC_VAR_ID_CUSTOM_BASE)->data, &dummy2);
    assert_int_equal(amxc_var_add_type(&dummy2, 1), AMXC_VAR_ID_CUSTOM_BASE);
    assert_ptr_equal(amxc_array_get_at(types, AMXC_VAR_ID_CUSTOM_BASE)->data, &dummy2);
    assert_int_equal(amxc_var_add_type(&dummy2, AMXC_VAR_ID_CUSTOM_BASE), AMXC_VAR_ID_CUSTOM_BASE);
    assert_ptr_equal(amxc_array_get_at(types, AMXC_VAR_ID_CUSTOM_BASE)->data, &dummy2);

    assert_int_equal(amxc_var_add_type(&dummy3, AMXC_VAR_ID_MAX), AMXC_VAR_ID_CUSTOM_BASE + 1);
    assert_int_equal(amxc_var_remove_type(&dummy2), 0);
    assert_int_equal(amxc_var_add_type(&dummy4, AMXC_VAR_ID_MAX), AMXC_VAR_ID_CUSTOM_BASE);
    assert_int_equal(amxc_var_add_type(&dummy2, AMXC_VAR_ID_MAX), AMXC_VAR_ID_CUSTOM_BASE + 2);

    assert_int_equal(amxc_var_remove_type(&dummy1), 0);
    assert_int_equal(amxc_var_remove_type(&dummy2), 0);
    assert_int_equal(amxc_var_remove_type(&dummy3), 0);
    assert_int_equal(amxc_var_remove_type(&dummy4), 0);
}

void test_amxc_var_remove_type(UNUSED void** state) {
    amxc_array_t* types = amxc_variant_get_types_array();
    assert_int_equal(amxc_var_add_type(&dummy1, 0), 0);
    assert_int_equal(amxc_var_add_type(&dummy2, -1), AMXC_VAR_ID_CUSTOM_BASE);

    assert_int_equal(amxc_var_remove_type(&dummy1), 0);
    assert_ptr_equal(amxc_array_get_at(types, 0)->data, NULL);
    assert_int_equal(dummy1.type_id, AMXC_VAR_ID_MAX);
    assert_int_equal(amxc_var_remove_type(&dummy1), -1);

    assert_int_equal(amxc_var_add_type(&dummy2, 0), AMXC_VAR_ID_CUSTOM_BASE);
    assert_ptr_equal(amxc_array_get_at(types, 0)->data, NULL);
    assert_int_equal(amxc_var_remove_type(&dummy2), 0);
    assert_int_equal(dummy2.type_id, AMXC_VAR_ID_MAX);
    assert_ptr_equal(amxc_array_get_data_at(types, AMXC_VAR_ID_CUSTOM_BASE), NULL);
    assert_int_equal(amxc_array_size(types), 0);
    assert_int_equal(amxc_var_remove_type(&dummy2), -1);
    assert_int_equal(amxc_var_add_type(&dummy1, -1), AMXC_VAR_ID_CUSTOM_BASE);
    assert_ptr_equal(amxc_array_get_at(types, AMXC_VAR_ID_CUSTOM_BASE)->data, &dummy1);
    assert_int_equal(amxc_var_remove_type(&dummy1), 0);
}

void test_amxc_var_get_type(UNUSED void** state) {
    assert_int_equal(amxc_var_add_type(&dummy1, 0), 0);
    assert_int_equal(amxc_var_add_type(&dummy2, -1), AMXC_VAR_ID_CUSTOM_BASE);

    assert_ptr_equal(amxc_var_get_type(0), &dummy1);
    assert_ptr_equal(amxc_var_get_type(AMXC_VAR_ID_CUSTOM_BASE), &dummy2);
    assert_ptr_equal(amxc_var_get_type(999), NULL);

    assert_int_equal(amxc_var_remove_type(&dummy1), 0);
    assert_int_equal(amxc_var_remove_type(&dummy2), 0);
}

void test_amxc_var_register_type(UNUSED void** state) {
    amxc_array_t* types = amxc_variant_get_types_array();

    assert_int_equal(amxc_var_register_type(NULL), AMXC_VAR_ID_MAX);

    assert_int_equal(amxc_var_register_type(&dummy1), AMXC_VAR_ID_CUSTOM_BASE);
    assert_int_equal(dummy1.type_id, AMXC_VAR_ID_CUSTOM_BASE);
    assert_ptr_equal(amxc_array_get_at(types, AMXC_VAR_ID_CUSTOM_BASE)->data, &dummy1);

    assert_int_equal(amxc_var_register_type(&dummy2), AMXC_VAR_ID_CUSTOM_BASE + 1);
    assert_int_equal(dummy2.type_id, AMXC_VAR_ID_CUSTOM_BASE + 1);
    assert_ptr_equal(amxc_array_get_at(types, AMXC_VAR_ID_CUSTOM_BASE + 1)->data, &dummy2);

    assert_int_equal(amxc_var_remove_type(&dummy1), 0);
    assert_int_equal(amxc_var_remove_type(&dummy2), 0);
}

void test_amxc_var_unregister_type(UNUSED void** state) {
    amxc_array_t* types = amxc_variant_get_types_array();

    assert_int_equal(amxc_var_add_type(&dummy1, 0), 0);
    assert_int_equal(amxc_var_add_type(&dummy2, AMXC_VAR_ID_MAX), AMXC_VAR_ID_CUSTOM_BASE);

    assert_int_equal(amxc_var_unregister_type(NULL), -1);

    assert_int_equal(amxc_var_unregister_type(&dummy1), -1);
    assert_ptr_equal(amxc_array_get_at(types, 0)->data, &dummy1);

    assert_int_equal(amxc_var_unregister_type(&dummy2), 0);
    assert_ptr_equal(amxc_array_get_at(types, AMXC_VAR_ID_CUSTOM_BASE)->data, NULL);
    assert_int_equal(amxc_var_unregister_type(&dummy2), -1);

    assert_int_equal(amxc_var_remove_type(&dummy1), 0);
}

void test_amxc_var_get_type_name_from_id(UNUSED void** state) {
    assert_int_equal(amxc_var_add_type(&dummy1, 0), 0);
    assert_int_equal(amxc_var_add_type(&dummy2, -1), AMXC_VAR_ID_CUSTOM_BASE);

    assert_ptr_equal(amxc_var_get_type_name_from_id(AMXC_VAR_ID_MAX), NULL);
    assert_ptr_equal(amxc_var_get_type_name_from_id(9999), NULL);

    assert_string_equal(amxc_var_get_type_name_from_id(0), "dummy1_t");
    assert_string_equal(amxc_var_get_type_name_from_id(AMXC_VAR_ID_CUSTOM_BASE), "dummy2_t");

    assert_int_equal(amxc_var_remove_type(&dummy1), 0);
    assert_int_equal(amxc_var_remove_type(&dummy2), 0);
}

void test_amxc_var_get_type_id_from_name(UNUSED void** state) {
    assert_int_equal(amxc_var_add_type(&dummy1, 0), 0);
    assert_int_equal(amxc_var_add_type(&dummy2, -1), AMXC_VAR_ID_CUSTOM_BASE);

    assert_ptr_equal(amxc_var_get_type_id_from_name(NULL), AMXC_VAR_ID_MAX);
    assert_ptr_equal(amxc_var_get_type_id_from_name("NotValid_t"), AMXC_VAR_ID_MAX);
    assert_ptr_equal(amxc_var_get_type_id_from_name(""), AMXC_VAR_ID_MAX);

    assert_int_equal(amxc_var_get_type_id_from_name("dummy1_t"), 0);
    assert_int_equal(amxc_var_get_type_id_from_name("dummy2_t"), AMXC_VAR_ID_CUSTOM_BASE);

    assert_int_equal(amxc_var_remove_type(&dummy1), 0);
    assert_int_equal(amxc_var_remove_type(&dummy2), 0);
}