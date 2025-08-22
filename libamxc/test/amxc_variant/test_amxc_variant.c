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

#include "test_amxc_variant.h"

#include <amxc/amxc_macros.h>
int amxc_var_init_success(amxc_var_t* const var);
int amxc_var_init_fail(amxc_var_t* const var);
void amxc_var_del(amxc_var_t* const var);
int amxc_var_copy_success(amxc_var_t* const dst, const amxc_var_t* const src);
int amxc_var_copy_fail(amxc_var_t* const dest, const amxc_var_t* const src);
int amxc_var_move_fail(amxc_var_t* const dest, amxc_var_t* const src);
int amxc_var_convert_success(amxc_var_t* const dest, const amxc_var_t* const src);
int amxc_var_convert_fail(amxc_var_t* const dest, const amxc_var_t* const src);
int amxc_var_compare_success(const amxc_var_t* const var1,
                             const amxc_var_t* const var2,
                             int* const result);
int amxc_var_compare_fail(const amxc_var_t* const var1,
                          const amxc_var_t* const var2,
                          int* const result);
int dummy4_convert_to(amxc_var_t* const dest,
                      const amxc_var_t* const src);

void free_variant_htable(const char* key, amxc_htable_it_t* it);
void free_variant_llist(amxc_llist_it_t* it);

int amxc_var_init_success(UNUSED amxc_var_t* const var) {
    return 0;
}

int amxc_var_init_fail(UNUSED amxc_var_t* const var) {
    return -1;
}

void amxc_var_del(UNUSED amxc_var_t* const var) {
    return;
}

int amxc_var_copy_success(amxc_var_t* const dest, const amxc_var_t* const src) {
    dest->type_id = src->type_id;
    dest->data.ui32 = src->data.ui32;
    return 0;
}

int amxc_var_copy_fail(UNUSED amxc_var_t* const dest,
                       UNUSED const amxc_var_t* const src) {
    return -1;
}

int amxc_var_move_fail(UNUSED amxc_var_t* const dest,
                       UNUSED amxc_var_t* const src) {
    return -1;
}

int amxc_var_convert_success(amxc_var_t* const dest,
                             const amxc_var_t* const src) {

    if(dest->type_id != src->type_id) {
        dest->data.ui32 = src->data.ui32 >> 1;
    } else {
        dest->data.ui32 = src->data.ui32;
    }
    return 0;
}

int amxc_var_convert_fail(UNUSED amxc_var_t* const dest,
                          UNUSED const amxc_var_t* const src) {
    return -1;
}

int amxc_var_compare_success(const amxc_var_t* const var1,
                             const amxc_var_t* const var2,
                             int* const result) {
    if(var1->data.ui32 < var2->data.ui32) {
        *result = -1;
    } else if(var1->data.ui32 > var2->data.ui32) {
        *result = 1;
    } else {
        *result = 0;
    }
    return 0;
}

int amxc_var_compare_fail(UNUSED const amxc_var_t* const var1,
                          UNUSED const amxc_var_t* const var2,
                          UNUSED int* const result) {
    return -1;
}

int dummy4_convert_to(amxc_var_t* const dest,
                      const amxc_var_t* const src) {
    int retval = -1;
    amxc_var_convert_fn_t convfn[AMXC_VAR_ID_CUSTOM_BASE] = {
        amxc_var_default_convert_to_null,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        amxc_var_default_convert_to_list,
        amxc_var_default_convert_to_htable,
        NULL,
    };

    if(dest->type_id >= AMXC_VAR_ID_CUSTOM_BASE) {
        goto exit;
    }

    if(convfn[dest->type_id] != NULL) {
        retval = convfn[dest->type_id](dest, src);
    }

exit:
    return retval;
}

static amxc_var_t test_var;

static amxc_var_t* amxc_var_test_get_key(UNUSED const amxc_var_t* const src,
                                         const char* const key,
                                         int flags) {
    if(strcmp(key, "valid") != 0) {
        return NULL;
    }

    if((flags & AMXC_VAR_FLAG_COPY) == AMXC_VAR_FLAG_COPY) {
        amxc_var_t* copy_var = NULL;
        amxc_var_new(&copy_var);
        amxc_var_copy(copy_var, &test_var);
        return copy_var;
    }

    return &test_var;
}

static int amxc_var_test_set_key(UNUSED amxc_var_t* const dest,
                                 UNUSED amxc_var_t* const src,
                                 UNUSED const char* const key,
                                 UNUSED int flags) {
    if(strcmp(key, "valid") != 0) {
        return -1;
    }

    return 0;
}

static amxc_var_t* amxc_var_test_get_index(UNUSED const amxc_var_t* const src,
                                           const int64_t index,
                                           int flags) {

    if((index > 5) && (index != UINT32_MAX)) {
        return NULL;
    }

    if((flags & AMXC_VAR_FLAG_COPY) == AMXC_VAR_FLAG_COPY) {
        amxc_var_t* copy_var = NULL;
        amxc_var_new(&copy_var);
        amxc_var_copy(copy_var, &test_var);
        return copy_var;
    }

    return &test_var;
}

static int amxc_var_test_set_index(UNUSED amxc_var_t* const dest,
                                   UNUSED amxc_var_t* const src,
                                   UNUSED const int64_t index,
                                   UNUSED int flags) {
    if((index > 5) && (index != UINT32_MAX)) {
        return -1;
    }

    return 0;
}


static amxc_var_type_t dummy1 =
{
    .init = amxc_var_init_success,
    .del = amxc_var_del,
    .copy = amxc_var_default_copy,
    .move = amxc_var_default_move,
    .convert_from = amxc_var_convert_success,
    .convert_to = amxc_var_convert_success,
    .compare = amxc_var_compare_success,
    .get_key = amxc_var_test_get_key,
    .set_key = amxc_var_test_set_key,
    .get_index = amxc_var_test_get_index,
    .set_index = amxc_var_test_set_index,
    .name = "dummy1_t"
};

static amxc_var_type_t dummy2 =
{
    .init = NULL,
    .del = NULL,
    .copy = amxc_var_copy_fail,
    .move = amxc_var_move_fail,
    .convert_from = amxc_var_convert_fail,
    .convert_to = amxc_var_convert_fail,
    .compare = amxc_var_compare_fail,
    .name = "dummy2_t"
};

static amxc_var_type_t dummy3 =
{
    .init = NULL,
    .del = NULL,
    .copy = NULL,
    .move = NULL,
    .convert_from = NULL,
    .convert_to = NULL,
    .compare = NULL,
    .get_key = amxc_var_test_get_key,
    .set_key = amxc_var_test_set_key,
    .get_index = amxc_var_test_get_index,
    .set_index = amxc_var_test_set_index,
    .name = "dummy3_t"
};

void test_amxc_var_new_delete(UNUSED void** state) {
    amxc_var_t* var = NULL;
    assert_int_equal(amxc_var_add_type(&dummy1, 0), 0);
    assert_int_equal(amxc_var_add_type(&dummy2, -1), AMXC_VAR_ID_CUSTOM_BASE);

    assert_int_equal(amxc_var_new(NULL), -1);

    assert_int_equal(amxc_var_new(&var), 0);
    assert_ptr_not_equal(var, NULL);
    assert_int_equal(var->type_id, AMXC_VAR_ID_NULL);
    assert_ptr_equal(var->data.data, NULL);
    assert_ptr_equal(var->lit.llist, NULL);
    assert_ptr_equal(var->hit.ait, NULL);

    amxc_var_delete(NULL);
    amxc_var_delete(&var);

    assert_int_equal(amxc_var_remove_type(&dummy1), 0);
    assert_int_equal(amxc_var_remove_type(&dummy2), 0);
}

void test_amxc_var_init_clean(UNUSED void** state) {
    amxc_var_t var;
    assert_int_equal(amxc_var_add_type(&dummy1, 0), 0);
    assert_int_equal(amxc_var_add_type(&dummy2, -1), AMXC_VAR_ID_CUSTOM_BASE);

    assert_int_equal(amxc_var_init(NULL), -1);

    assert_int_equal(amxc_var_init(&var), 0);
    assert_int_equal(var.type_id, AMXC_VAR_ID_NULL);
    assert_ptr_equal(var.data.data, NULL);
    assert_ptr_equal(var.lit.llist, NULL);
    assert_ptr_equal(var.hit.ait, NULL);

    amxc_var_clean(NULL);
    amxc_var_clean(&var);

    assert_int_equal(amxc_var_remove_type(&dummy1), 0);
    amxc_var_clean(&var);

    assert_int_equal(amxc_var_remove_type(&dummy2), 0);
}

void test_amxc_var_set_type(UNUSED void** state) {
    amxc_var_t var;
    assert_int_equal(amxc_var_add_type(&dummy1, 0), 0);
    assert_int_equal(amxc_var_add_type(&dummy2, -1), AMXC_VAR_ID_CUSTOM_BASE);

    assert_int_equal(amxc_var_init(&var), 0);

    assert_int_equal(amxc_var_set_type(NULL, 0), -1);
    assert_int_not_equal(amxc_var_set_type(&var, AMXC_VAR_ID_CUSTOM_BASE + 1), 0);
    assert_int_equal(amxc_var_set_type(&var, AMXC_VAR_ID_CUSTOM_BASE), 0);
    assert_int_equal(var.type_id, AMXC_VAR_ID_CUSTOM_BASE);
    assert_int_equal(var.data.data, NULL);

    assert_int_equal(amxc_var_set_type(&var, AMXC_VAR_ID_CUSTOM_BASE), 0);
    assert_int_equal(var.type_id, AMXC_VAR_ID_CUSTOM_BASE);
    assert_int_equal(var.data.data, NULL);

    assert_int_not_equal(amxc_var_set_type(&var, AMXC_VAR_ID_CUSTOM_BASE + 1), 0);
    assert_int_equal(var.type_id, AMXC_VAR_ID_CUSTOM_BASE);
    assert_int_equal(var.data.data, NULL);

    assert_int_equal(amxc_var_set_type(&var, 0), 0);
    assert_int_equal(var.type_id, 0);
    assert_int_equal(var.data.data, NULL);

    dummy2.init = amxc_var_init_fail;
    assert_int_not_equal(amxc_var_set_type(&var, AMXC_VAR_ID_CUSTOM_BASE), 0);
    dummy2.init = NULL;

    assert_int_equal(amxc_var_remove_type(&dummy1), 0);
    assert_int_equal(amxc_var_remove_type(&dummy2), 0);
}

void test_amxc_var_copy(UNUSED void** state) {
    amxc_var_t var1;
    amxc_var_t var2;
    assert_int_equal(amxc_var_add_type(&dummy1, 0), 0);
    assert_int_equal(amxc_var_add_type(&dummy2, -1), AMXC_VAR_ID_CUSTOM_BASE);
    assert_int_equal(amxc_var_add_type(&dummy3, -1), AMXC_VAR_ID_CUSTOM_BASE + 1);

    assert_int_equal(amxc_var_init(&var1), 0);
    var1.data.ui32 = 100;
    assert_int_equal(amxc_var_init(&var2), 0);
    assert_int_equal(amxc_var_set_type(&var2, AMXC_VAR_ID_CUSTOM_BASE), 0);
    assert_int_equal(var2.type_id, AMXC_VAR_ID_CUSTOM_BASE);
    assert_int_equal(var2.data.ui32, 0);

    assert_int_not_equal(amxc_var_copy(NULL, NULL), 0);
    assert_int_not_equal(amxc_var_copy(&var1, NULL), 0);
    assert_true(amxc_var_is_null(&var1));

    assert_int_equal(amxc_var_copy(&var2, &var1), 0);
    assert_int_equal(var2.type_id, 0);
    assert_int_equal(var2.data.ui32, 100);

    assert_int_equal(amxc_var_set_type(&var1, AMXC_VAR_ID_CUSTOM_BASE + 1), 0);
    assert_int_not_equal(amxc_var_copy(&var2, &var1), 0);
    assert_true(amxc_var_is_null(&var2));

    assert_int_equal(amxc_var_set_type(&var1, 0), 0);
    var1.data.ui32 = 100;
    assert_int_equal(amxc_var_remove_type(&dummy1), 0);
    assert_int_equal(amxc_var_set_type(&var2, AMXC_VAR_ID_CUSTOM_BASE), 0);
    assert_int_equal(amxc_var_copy(&var2, &var1), -1);
    assert_true(amxc_var_is_null(&var2));
    assert_int_equal(amxc_var_add_type(&dummy1, 0), 0);

    assert_int_equal(amxc_var_remove_type(&dummy1), 0);
    assert_int_equal(amxc_var_remove_type(&dummy2), 0);
    assert_int_equal(amxc_var_remove_type(&dummy3), 0);
}

void test_amxc_var_convert(UNUSED void** state) {
    amxc_var_t var1;
    amxc_var_t var2;
    assert_int_equal(amxc_var_add_type(&dummy1, 0), 0);
    assert_int_equal(amxc_var_add_type(&dummy2, -1), AMXC_VAR_ID_CUSTOM_BASE);
    assert_int_equal(amxc_var_add_type(&dummy3, -1), AMXC_VAR_ID_CUSTOM_BASE + 1);

    assert_int_equal(amxc_var_init(&var1), 0);
    var1.data.ui32 = 100;
    assert_int_equal(amxc_var_init(&var2), 0);
    assert_int_not_equal(amxc_var_convert(NULL, NULL, 0), 0);
    assert_int_not_equal(amxc_var_convert(&var1, NULL, 0), 0);
    assert_int_not_equal(amxc_var_convert(&var1, &var2, AMXC_VAR_ID_CUSTOM_BASE + 2), 0);

    assert_int_equal(amxc_var_set_type(&var1, AMXC_VAR_ID_CUSTOM_BASE + 1), 0);
    var1.data.ui32 = 100;
    assert_int_equal(amxc_var_set_type(&var2, AMXC_VAR_ID_CUSTOM_BASE), 0);
    var2.data.ui32 = 999;

    assert_int_equal(amxc_var_convert(&var2, &var1, 0), 0);
    assert_int_equal(var2.type_id, 0);
    assert_ptr_equal(var2.data.ui32, 50);
    var2.data.ui32 = 999;

    assert_int_not_equal(amxc_var_convert(&var2, &var1, AMXC_VAR_ID_CUSTOM_BASE), 0);
    assert_int_equal(var2.type_id, 0);
    assert_ptr_equal(var2.data.data, NULL);

    assert_int_not_equal(amxc_var_convert(&var2, &var1, AMXC_VAR_ID_CUSTOM_BASE + 1), 0);
    assert_int_equal(var2.type_id, 0);
    assert_ptr_equal(var2.data.data, NULL);

    assert_int_equal(amxc_var_set_type(&var1, 0), 0);
    var1.data.ui32 = 100;
    assert_int_equal(amxc_var_remove_type(&dummy1), 0);
    assert_int_not_equal(amxc_var_convert(&var2, &var1, AMXC_VAR_ID_CUSTOM_BASE + 1), 0);
    assert_int_equal(var2.type_id, 0);
    assert_ptr_equal(var2.data.data, NULL);
    assert_int_equal(amxc_var_add_type(&dummy1, 0), 0);

    assert_int_equal(amxc_var_set_type(&var1, 0), 0);
    var1.data.ui32 = 100;
    var2.data.ui32 = 500;
    assert_int_equal(amxc_var_convert(&var1, &var2, AMXC_VAR_ID_CUSTOM_BASE + 1), 0);
    assert_int_equal(var1.type_id, AMXC_VAR_ID_CUSTOM_BASE + 1);
    assert_int_equal(var1.data.ui32, 250);

    assert_int_equal(amxc_var_set_type(&var1, 0), 0);
    assert_int_equal(amxc_var_set_type(&var2, 0), 0);
    assert_int_equal(amxc_var_convert(&var1, &var2, 0), 0);

    assert_int_equal(amxc_var_remove_type(&dummy1), 0);
    assert_int_equal(amxc_var_remove_type(&dummy2), 0);
    assert_int_equal(amxc_var_remove_type(&dummy3), 0);
}

void test_amxc_var_compare(UNUSED void** state) {
    amxc_var_t var1;
    amxc_var_t var2;
    amxc_var_t var3;
    int result = 0;
    assert_int_equal(amxc_var_add_type(&dummy1, 0), 0);
    assert_int_equal(amxc_var_add_type(&dummy2, -1), AMXC_VAR_ID_CUSTOM_BASE);
    assert_int_equal(amxc_var_add_type(&dummy3, -1), AMXC_VAR_ID_CUSTOM_BASE + 1);

    assert_int_equal(amxc_var_init(&var1), 0);
    assert_int_equal(amxc_var_init(&var2), 0);
    assert_int_equal(amxc_var_init(&var3), 0);
    assert_int_not_equal(amxc_var_compare(NULL, NULL, NULL), 0);
    assert_int_equal(amxc_var_compare(NULL, NULL, &result), 0);
    assert_int_equal(result, 0);
    assert_int_equal(amxc_var_compare(&var1, NULL, &result), 0);
    assert_int_equal(result, 1);
    assert_int_equal(amxc_var_compare(NULL, &var1, &result), 0);
    assert_int_equal(result, -1);
    assert_int_equal(amxc_var_compare(&var1, &var2, &result), 0);
    assert_int_equal(result, 0);

    var1.data.ui32 = 100;
    var2.data.ui32 = 100;
    assert_int_equal(amxc_var_compare(&var1, &var2, &result), 0);
    assert_int_equal(result, 0);
    var2.data.ui32 = 50;
    assert_int_equal(amxc_var_compare(&var1, &var2, &result), 0);
    assert_int_equal(result, 1);
    var2.data.ui32 = 200;
    assert_int_equal(amxc_var_compare(&var1, &var2, &result), 0);
    assert_int_equal(result, -1);

    assert_int_equal(amxc_var_set_type(&var1, 0), 0);
    assert_int_equal(amxc_var_set_type(&var2, AMXC_VAR_ID_CUSTOM_BASE), 0);
    assert_int_equal(amxc_var_set_type(&var3, AMXC_VAR_ID_CUSTOM_BASE + 1), 0);

    var1.data.ui32 = 100;
    var2.data.ui32 = 100;
    assert_int_equal(amxc_var_compare(&var1, &var2, &result), 0);
    assert_int_equal(result, 1); // conversion var2 to var1
    var1.data.ui32 = 100;
    var2.data.ui32 = 100;
    var3.data.ui32 = 100;
    // should fail because compare of var2 always fails
    assert_int_not_equal(amxc_var_compare(&var2, &var1, &result), 0);
    assert_int_equal(amxc_var_compare(&var3, &var1, &result), 0);
    assert_int_equal(result, -1); // conversion var3 to var1
    assert_int_equal(amxc_var_compare(&var1, &var1, &result), 0);
    assert_int_equal(result, 0);
    assert_int_not_equal(amxc_var_compare(&var2, &var2, &result), 0);

    assert_int_equal(amxc_var_remove_type(&dummy1), 0);
    assert_int_not_equal(amxc_var_compare(&var1, &var2, &result), 0);
    assert_int_not_equal(amxc_var_compare(&var2, &var1, &result), 0);

    assert_int_equal(amxc_var_remove_type(&dummy2), 0);
    assert_int_equal(amxc_var_remove_type(&dummy3), 0);
}

void free_variant_htable(UNUSED const char* key, amxc_htable_it_t* it) {
    amxc_var_t* var = amxc_htable_it_get_data(it, amxc_var_t, hit);
    amxc_var_delete(&var);
}

void free_variant_llist(amxc_llist_it_t* it) {
    amxc_var_t* var = amxc_llist_it_get_data(it, amxc_var_t, lit);
    amxc_var_delete(&var);
}

void test_amxc_var_type_of(UNUSED void** state) {
    amxc_var_t var1;

    assert_int_equal(amxc_var_add_type(&dummy1, AMXC_VAR_ID_NULL), AMXC_VAR_ID_NULL);
    assert_int_equal(amxc_var_init(&var1), 0);
    assert_int_equal(amxc_var_set_type(&var1, 0), 0);
    assert_int_equal(amxc_var_type_of(&var1), AMXC_VAR_ID_NULL);
    assert_true(amxc_var_type_of(NULL) == AMXC_VAR_ID_INVALID);
    assert_ptr_equal(amxc_var_type_name_of(NULL), NULL);
    assert_string_equal(amxc_var_type_name_of(&var1), "dummy1_t");

    assert_int_equal(amxc_var_remove_type(&dummy1), 0);
}

void test_amxc_var_get_set_key(UNUSED void** state) {
    amxc_var_t var1;
    amxc_var_t* subvar = NULL;

    assert_int_equal(amxc_var_add_type(&dummy3, AMXC_VAR_ID_NULL), AMXC_VAR_ID_NULL);
    assert_int_equal(amxc_var_init(&var1), 0);
    assert_int_equal(amxc_var_init(&test_var), 0);
    assert_int_equal(amxc_var_set_type(&var1, 0), 0);

    subvar = amxc_var_get_key(&var1, "valid", AMXC_VAR_FLAG_DEFAULT);
    assert_ptr_equal(subvar, &test_var);
    subvar = amxc_var_get_key(&var1, "valid", AMXC_VAR_FLAG_COPY);
    assert_ptr_not_equal(subvar, NULL);
    assert_ptr_not_equal(subvar, &test_var);
    amxc_var_delete(&subvar);

    subvar = amxc_var_get_key(&var1, "not_valid", AMXC_VAR_FLAG_DEFAULT);
    assert_ptr_equal(subvar, NULL);

    amxc_var_remove_type(&dummy3);
}

void test_amxc_var_add_new_key(UNUSED void** state) {
    amxc_var_t var1;
    amxc_var_t var2;
    amxc_var_t* subvar = NULL;

    assert_int_equal(amxc_var_add_type(&dummy3, AMXC_VAR_ID_UINT16), AMXC_VAR_ID_UINT16);
    assert_int_equal(amxc_var_add_type(&dummy2, AMXC_VAR_ID_UINT32), AMXC_VAR_ID_UINT32);
    assert_int_equal(amxc_var_init(&var1), 0);
    assert_int_equal(amxc_var_init(&test_var), 0);
    assert_int_equal(amxc_var_set_type(&var1, AMXC_VAR_ID_UINT16), 0);

    subvar = amxc_var_add_new_key(&var1, "valid");
    assert_ptr_not_equal(subvar, NULL);
    assert_ptr_not_equal(subvar, &test_var);
    amxc_var_delete(&subvar);

    assert_ptr_equal(amxc_var_add_new_key(NULL, "valid"), NULL);
    assert_ptr_equal(amxc_var_add_new_key(&var1, NULL), NULL);
    assert_ptr_equal(amxc_var_add_new_key(&var1, ""), NULL);

    assert_int_equal(amxc_var_init(&var2), 0);
    assert_int_equal(amxc_var_set_type(&var2, AMXC_VAR_ID_UINT32), 0);
    assert_ptr_equal(amxc_var_add_new_key(&var2, "valid"), NULL);

    amxc_var_remove_type(&dummy2);
    amxc_var_remove_type(&dummy3);
}

void test_amxc_var_add_new(UNUSED void** state) {
    amxc_var_t var1;
    amxc_var_t var2;
    amxc_var_t* subvar = NULL;

    assert_int_equal(amxc_var_add_type(&dummy3, -1), AMXC_VAR_ID_CUSTOM_BASE);
    assert_int_equal(amxc_var_add_type(&dummy2, -1), AMXC_VAR_ID_CUSTOM_BASE + 1);
    assert_int_equal(amxc_var_init(&var1), 0);
    assert_int_equal(amxc_var_init(&test_var), 0);
    assert_int_equal(amxc_var_set_type(&var1, AMXC_VAR_ID_CUSTOM_BASE), 0);

    subvar = amxc_var_add_new(&var1);
    assert_ptr_not_equal(subvar, NULL);
    assert_ptr_not_equal(subvar, &test_var);
    amxc_var_delete(&subvar);

    assert_ptr_equal(amxc_var_add_new(NULL), NULL);

    assert_int_equal(amxc_var_init(&var2), 0);
    assert_int_equal(amxc_var_set_type(&var2, AMXC_VAR_ID_CUSTOM_BASE + 1), 0);
    assert_ptr_equal(amxc_var_add_new(&var2), NULL);

    amxc_var_remove_type(&dummy2);
    amxc_var_remove_type(&dummy3);
}

void test_amxc_var_get_path(UNUSED void** state) {
    amxc_var_t var1;
    amxc_var_t* subvar = NULL;

    assert_int_equal(amxc_var_add_type(&dummy3, -1), AMXC_VAR_ID_CUSTOM_BASE);
    assert_int_equal(amxc_var_add_type(&dummy1, -1), AMXC_VAR_ID_CUSTOM_BASE + 1);
    assert_int_equal(amxc_var_init(&var1), 0);
    assert_int_equal(amxc_var_init(&test_var), 0);
    assert_int_equal(amxc_var_set_type(&test_var, AMXC_VAR_ID_CUSTOM_BASE + 1), 0);
    assert_int_equal(amxc_var_set_type(&var1, AMXC_VAR_ID_CUSTOM_BASE), 0);

    subvar = amxc_var_get_path(&var1, "valid.1.valid.2.valid.3", AMXC_VAR_FLAG_DEFAULT);
    assert_ptr_not_equal(subvar, NULL);
    assert_ptr_equal(subvar, &test_var);

    subvar = amxc_var_get_pathf(&var1, AMXC_VAR_FLAG_DEFAULT, "valid.%d.valid.2.valid.3", 1);
    assert_ptr_not_equal(subvar, NULL);
    assert_ptr_equal(subvar, &test_var);

    subvar = amxc_var_get_pathf(&var1, AMXC_VAR_FLAG_DEFAULT, "%s.%d.valid.%d.valid.3", "valid", 1, 2);
    assert_ptr_not_equal(subvar, NULL);
    assert_ptr_equal(subvar, &test_var);

    subvar = amxc_var_get_path(&var1, "valid.1.valid.99.valid.3", AMXC_VAR_FLAG_DEFAULT);
    assert_ptr_equal(subvar, NULL);
    subvar = amxc_var_get_path(&var1, "valid.1.valid.99.valid.3", AMXC_VAR_FLAG_COPY);
    assert_ptr_equal(subvar, NULL);

    subvar = amxc_var_get_path(&var1, "valid.1.valid.2.notexisting.3", AMXC_VAR_FLAG_DEFAULT);
    assert_ptr_equal(subvar, NULL);
    subvar = amxc_var_get_path(&var1, "valid.1.valid.2.notexisting.3", AMXC_VAR_FLAG_COPY);
    assert_ptr_equal(subvar, NULL);

    subvar = amxc_var_get_path(&var1, "valid.1.valid.2.valid.3", AMXC_VAR_FLAG_COPY);
    assert_ptr_not_equal(subvar, NULL);
    assert_ptr_not_equal(subvar, &test_var);
    amxc_var_delete(&subvar);

    subvar = amxc_var_get_path(NULL, "valid.1.valid.2.valid.3", AMXC_VAR_FLAG_COPY);
    assert_ptr_equal(subvar, NULL);
    subvar = amxc_var_get_path(&var1, NULL, AMXC_VAR_FLAG_COPY);
    assert_ptr_equal(subvar, NULL);
    subvar = amxc_var_get_path(&var1, "", AMXC_VAR_FLAG_COPY);
    assert_ptr_equal(subvar, NULL);
    subvar = amxc_var_get_path(&test_var, "", AMXC_VAR_FLAG_DEFAULT);
    assert_ptr_not_equal(subvar, NULL);

    subvar = amxc_var_get_pathf(NULL, AMXC_VAR_FLAG_COPY, "valid.1.valid.2.valid.3");
    assert_ptr_equal(subvar, NULL);
    subvar = amxc_var_get_pathf(NULL, AMXC_VAR_FLAG_COPY, NULL);
    assert_ptr_equal(subvar, NULL);

    amxc_var_remove_type(&dummy3);
    amxc_var_remove_type(&dummy1);
}

void test_amxc_var_set_path(UNUSED void** state) {
    amxc_var_t var1;
    amxc_var_t var2;

    assert_int_equal(amxc_var_add_type(&dummy3, -1), AMXC_VAR_ID_CUSTOM_BASE);
    assert_int_equal(amxc_var_add_type(&dummy1, -1), AMXC_VAR_ID_CUSTOM_BASE + 1);
    assert_int_equal(amxc_var_init(&var1), 0);
    assert_int_equal(amxc_var_set_type(&var1, AMXC_VAR_ID_CUSTOM_BASE), 0);
    assert_int_equal(amxc_var_init(&var2), 0);
    assert_int_equal(amxc_var_set_type(&var2, AMXC_VAR_ID_CUSTOM_BASE + 1), 0);

    assert_int_equal(amxc_var_set_path(&var1, "valid.1.valid.2.valid.3", &var2, AMXC_VAR_FLAG_DEFAULT | AMXC_VAR_FLAG_AUTO_ADD), 0);

    amxc_var_remove_type(&dummy3);
    amxc_var_remove_type(&dummy1);
}

void test_amxc_var_push_take_amxc_string(UNUSED void** state) {
    amxc_var_t var1;
    amxc_string_t source;
    amxc_string_t* string = NULL;

    assert_int_equal(amxc_string_init(&source, 0), 0);
    assert_int_equal(amxc_string_append(&source, "This is a test string", 21), 0);
    assert_int_equal(amxc_var_init(&var1), 0);
    assert_int_equal(amxc_var_push_amxc_string_t(&var1, &source), 0);
    assert_int_equal(amxc_var_type_of(&var1), AMXC_VAR_ID_CSTRING);
    assert_int_equal(source.length, 0);
    assert_int_equal(source.last_used, 0);
    assert_ptr_equal(source.buffer, NULL);

    string = amxc_var_take_amxc_string_t(&var1);
    assert_int_equal(amxc_var_type_of(&var1), AMXC_VAR_ID_NULL);
    assert_ptr_not_equal(string, NULL);
    assert_int_not_equal(string->length, 0);
    assert_int_not_equal(string->last_used, 0);
    assert_ptr_not_equal(string->buffer, NULL);
    amxc_string_delete(&string);

    amxc_var_clean(&var1);
    assert_ptr_equal(var1.data.s, NULL);
    string = amxc_var_take_amxc_string_t(&var1);
    assert_ptr_equal(string, NULL);

    amxc_string_clean(&source);
}

void test_amxc_var_move(UNUSED void** state) {
    amxc_var_t src;
    amxc_var_t dst;

    assert_int_equal(amxc_var_add_type(&dummy1, -1), AMXC_VAR_ID_CUSTOM_BASE);
    assert_int_equal(amxc_var_add_type(&dummy2, -1), AMXC_VAR_ID_CUSTOM_BASE + 1);
    assert_int_equal(amxc_var_add_type(&dummy3, -1), AMXC_VAR_ID_CUSTOM_BASE + 2);
    amxc_var_init(&src);
    amxc_var_init(&dst);

    assert_int_equal(amxc_var_set_type(&src, AMXC_VAR_ID_CUSTOM_BASE), 0);
    assert_int_equal(amxc_var_move(&dst, &src), 0);
    assert_int_equal(amxc_var_type_of(&dst), AMXC_VAR_ID_CUSTOM_BASE);
    assert_true(amxc_var_is_null(&src));

    assert_int_equal(amxc_var_set_type(&dst, AMXC_VAR_ID_CUSTOM_BASE), 0);
    assert_int_equal(amxc_var_set_type(&src, AMXC_VAR_ID_CUSTOM_BASE + 1), 0);
    assert_int_not_equal(amxc_var_move(&dst, &src), 0);
    assert_int_equal(amxc_var_type_of(&src), AMXC_VAR_ID_CUSTOM_BASE + 1);
    assert_true(amxc_var_is_null(&dst));

    assert_int_equal(amxc_var_set_type(&dst, AMXC_VAR_ID_CUSTOM_BASE), 0);
    assert_int_equal(amxc_var_set_type(&src, AMXC_VAR_ID_CUSTOM_BASE + 2), 0);
    assert_int_not_equal(amxc_var_move(&dst, &src), 0);
    assert_int_equal(amxc_var_type_of(&src), AMXC_VAR_ID_CUSTOM_BASE + 2);
    assert_true(amxc_var_is_null(&dst));

    amxc_var_clean(&src);
    amxc_var_clean(&dst);

    assert_int_not_equal(amxc_var_move(&dst, NULL), 0);
    assert_int_not_equal(amxc_var_move(NULL, &src), 0);

    amxc_var_remove_type(&dummy1);
    amxc_var_remove_type(&dummy2);
    amxc_var_remove_type(&dummy3);
}

void test_amxc_var_take_it(UNUSED void** state) {
    amxc_var_take_it(NULL);
}