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

#include "newvar.h"
#include <stdlib.h>

#include <stdarg.h> // needed for cmocka
#include <setjmp.h> // needed for cmocka
#include <unistd.h> // needed for cmocka
#include <cmocka.h>

#include <amxc/amxc_variant_type.h>
#include <amxc/amxc_variant.h>
#include <amxc/amxc_htable.h>
#include <amxc_variant_priv.h>


static amxc_var_t* s_new_var() {
    amxc_var_t* var = NULL;
    assert_int_equal(0, amxc_var_new(&var));
    assert_non_null(var);
    return var;
}

amxc_var_t* newvar_null() {
    return s_new_var();
}

amxc_var_t* newvar_bool(bool value) {
    amxc_var_t* var = s_new_var();
    amxc_var_set(bool, var, value);
    return var;
}

amxc_var_t* newvar_uint8_t(uint8_t value) {
    amxc_var_t* var = s_new_var();
    amxc_var_set(uint8_t, var, value);
    return var;
}

amxc_var_t* newvar_uint16_t(uint16_t value) {
    amxc_var_t* var = s_new_var();
    amxc_var_set(uint16_t, var, value);
    return var;
}

amxc_var_t* newvar_uint32_t(uint32_t value) {
    amxc_var_t* var = s_new_var();
    amxc_var_set(uint32_t, var, value);
    return var;
}

amxc_var_t* newvar_uint64_t(uint64_t value) {
    amxc_var_t* var = s_new_var();
    amxc_var_set(uint64_t, var, value);
    return var;
}

amxc_var_t* newvar_int8_t(int8_t value) {
    amxc_var_t* var = s_new_var();
    amxc_var_set(int8_t, var, value);
    return var;
}

amxc_var_t* newvar_int16_t(int16_t value) {
    amxc_var_t* var = s_new_var();
    amxc_var_set(int16_t, var, value);
    return var;
}

amxc_var_t* newvar_int32_t(int32_t value) {
    amxc_var_t* var = s_new_var();
    amxc_var_set(int32_t, var, value);
    return var;
}

amxc_var_t* newvar_int64_t(int64_t value) {
    amxc_var_t* var = s_new_var();
    amxc_var_set(int64_t, var, value);
    return var;
}

amxc_var_t* newvar_cstring_t(const char* value) {
    assert_non_null(value);
    amxc_var_t* var = s_new_var();
    amxc_var_set(cstring_t, var, value);
    return var;
}

amxc_var_t* newvar_csv_string_t(const char* value) {
    assert_non_null(value);
    amxc_var_t* var = s_new_var();
    amxc_var_set(csv_string_t, var, value);
    return var;
}

amxc_var_t* newvar_ssv_string_t(const char* value) {
    assert_non_null(value);
    amxc_var_t* var = s_new_var();
    amxc_var_set(ssv_string_t, var, value);
    return var;
}

amxc_var_t* newvar_double(double value) {
    amxc_var_t* var = s_new_var();
    amxc_var_set(double, var, value);
    return var;
}

amxc_var_t* newvar_list(amxc_var_t* value[]) {
    size_t i = 0;
    amxc_var_t* var = s_new_var();
    assert_non_null(value);
    amxc_var_set_type(var, AMXC_VAR_ID_LIST);
    while(value[i] != NULL) {
        amxc_var_set_index(var, -1, value[i], AMXC_VAR_FLAG_DEFAULT);
        i++;
    }
    return var;
}

amxc_var_t* newvar_list_empty(void) {
    return newvar_list((amxc_var_t*[]) {NULL});
}

amxc_var_t* newvar_htable(newvar_kv_t* keyvalue_pairs[]) {
    size_t i = 0;
    amxc_var_t* var = s_new_var();
    assert_non_null(keyvalue_pairs);
    amxc_var_set_type(var, AMXC_VAR_ID_HTABLE);
    while(keyvalue_pairs[i] != NULL) {
        amxc_var_t* value_in_htable = amxc_var_add_new_key(var, keyvalue_pairs[i]->key);
        assert_int_equal(0, amxc_var_move(value_in_htable, keyvalue_pairs[i]->value));
        free(keyvalue_pairs[i]->value);
        keyvalue_pairs[i]->value = NULL;
        i++;
    }
    return var;
}

amxc_var_t* newvar_htable_empty(void) {
    return newvar_htable((newvar_kv_t*[]) {NULL});
}


amxc_var_t* newvar_fd_t(int value) {
    amxc_var_t* var = s_new_var();
    amxc_var_set(fd_t, var, value);
    assert_int_equal(AMXC_VAR_ID_FD, amxc_var_type_of(var));
    return var;
}