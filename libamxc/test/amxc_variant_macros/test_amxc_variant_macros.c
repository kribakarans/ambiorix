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
#include <string.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <amxc/amxc_variant.h>
#include <amxc_variant_priv.h>

#include "test_amxc_variant_macros.h"

#include <amxc/amxc_macros.h>

void test_amxc_var_get_macros(UNUSED void** state) {
    amxc_var_t var;
    amxc_var_t* part;
    amxc_var_init(&var);

    amxc_var_set_type(&var, AMXC_VAR_ID_HTABLE);
    part = amxc_var_add_key(amxc_llist_t, &var, "list", NULL);
    amxc_var_add(uint32_t, part, 100);
    amxc_var_add(bool, part, true);
    amxc_var_add(cstring_t, part, "yes");

    part = amxc_var_add_key(amxc_htable_t, &var, "table", NULL);
    amxc_var_add_key(uint32_t, part, "test1", 100);
    amxc_var_add_key(bool, part, "test2", true);
    amxc_var_add_key(cstring_t, part, "test3", "yes");

    assert_true(GETP_BOOL(&var, "list.0"));
    assert_int_equal(GETP_UINT32(&var, "list.0"), 100);
    assert_int_equal(GETP_INT32(&var, "list.0"), 100);
    assert_true(GETP_BOOL(&var, "list.1"));
    assert_true(GETP_BOOL(&var, "list.2"));
    assert_string_equal(GETP_CHAR(&var, "list.2"), "yes");

    part = GETP_ARG(&var, "list.0");
    assert_int_equal(GETP_UINT32(part, NULL), 100);
    assert_int_equal(GETP_INT32(part, NULL), 100);
    assert_int_equal(GET_UINT32(part, NULL), 100);
    assert_int_equal(GET_INT32(part, NULL), 100);

    part = GETP_ARG(&var, "list.2");
    assert_true(GETP_BOOL(part, NULL));
    assert_true(GET_BOOL(part, NULL));
    assert_string_equal(GET_CHAR(part, NULL), "yes");
    assert_string_equal(GETP_CHAR(part, NULL), "yes");

    part = GETP_ARG(&var, "table.test1");
    assert_int_equal(GETP_UINT32(part, NULL), 100);
    assert_int_equal(GETP_INT32(part, NULL), 100);
    assert_int_equal(GET_UINT32(part, NULL), 100);
    assert_int_equal(GET_INT32(part, NULL), 100);

    part = GETP_ARG(&var, "table.test3");
    assert_true(GETP_BOOL(part, NULL));
    assert_true(GET_BOOL(part, NULL));
    assert_string_equal(GET_CHAR(part, NULL), "yes");
    assert_string_equal(GETP_CHAR(part, NULL), "yes");

    amxc_var_clean(&var);
}

void test_amxc_var_for_each_htable(UNUSED void** state) {
    amxc_var_t var;
    uint32_t count = 0;
    amxc_var_init(&var);

    amxc_var_set_type(&var, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(uint32_t, &var, "key1", 100);
    amxc_var_add_key(uint32_t, &var, "key2", 200);
    amxc_var_add_key(bool, &var, "key3", true);
    amxc_var_add_key(cstring_t, &var, "key4", "text");

    amxc_var_for_each(data, &var) {
        const char* key = amxc_var_key(data);
        assert_non_null(key);
        printf("%s = ", key);
        fflush(stdout);
        amxc_var_dump(data, 1);
        assert_ptr_equal(amxc_var_get_parent(data), &var);
        count++;
    }
    assert_int_equal(count, 4);

    printf("\n");

    count = 0;
    amxc_var_for_each_reverse(data, &var) {
        const char* key = amxc_var_key(data);
        assert_non_null(key);
        printf("%s = ", key);
        fflush(stdout);
        amxc_var_dump(data, 1);
        assert_ptr_equal(amxc_var_get_parent(data), &var);
        count++;
    }
    assert_int_equal(count, 4);

    amxc_var_clean(&var);
}

void test_amxc_var_for_each_list(UNUSED void** state) {
    amxc_var_t var;
    uint32_t count = 0;
    amxc_var_init(&var);

    amxc_var_set_type(&var, AMXC_VAR_ID_LIST);
    amxc_var_add(uint32_t, &var, 100);
    amxc_var_add(uint32_t, &var, 200);
    amxc_var_add(bool, &var, true);
    amxc_var_add(cstring_t, &var, "text");

    amxc_var_for_each(data, &var) {
        const char* key = amxc_var_key(data);
        assert_null(key);
        fflush(stdout);
        amxc_var_dump(data, 1);
        assert_ptr_equal(amxc_var_get_parent(data), &var);
        count++;
    }
    assert_int_equal(count, 4);

    printf("\n");

    count = 0;
    amxc_var_for_each_reverse(data, &var) {
        const char* key = amxc_var_key(data);
        assert_null(key);
        fflush(stdout);
        amxc_var_dump(data, 1);
        assert_ptr_equal(amxc_var_get_parent(data), &var);
        count++;
    }
    assert_int_equal(count, 4);

    amxc_var_clean(&var);
}

void test_amxc_var_for_each_non_composite(UNUSED void** state) {
    amxc_var_t var;
    uint32_t count = 0;
    amxc_var_init(&var);

    amxc_var_set_type(&var, AMXC_VAR_ID_CSTRING);

    amxc_var_for_each(data, &var) {
        fflush(stdout);
        amxc_var_dump(data, 1);
        assert_ptr_equal(amxc_var_get_parent(data), &var);
        count++;
    }
    assert_int_equal(count, 0);

    amxc_var_for_each_reverse(data, &var) {
        const char* key = amxc_var_key(data);
        assert_non_null(key);
        printf("%s = ", key);
        fflush(stdout);
        amxc_var_dump(data, 1);
        assert_ptr_equal(amxc_var_get_parent(data), &var);
        count++;
    }
    assert_int_equal(count, 0);

    assert_null(amxc_var_get_parent(&var));

    amxc_var_clean(&var);
}
