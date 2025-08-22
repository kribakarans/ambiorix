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

#ifndef __AMXC_TEST_COMMON_NEWVAR_H__
#define __AMXC_TEST_COMMON_NEWVAR_H__

#include <amxc/amxc.h>
#include <amxc/amxc_variant.h>
#include <stdint.h>

/**
 * @file Utility functions for easier syntax for creating variants.
 *
 * While more convenient, they are less efficient because they more often use the heap in
 * situations where the stack can technically be used as well.
 *
 * This is useful for tests of libamxc, but in higher-level libraries, you might want
 * to use libamxj instead.
 *
 * Example:
 * ```
 * amxc_var_t* mylist = newvar_list((amxc_var_t*[]) {
 *     newvar_list((amxc_var_t*[]) {
 *         newvar_cstring_t("hello"),
 *         NULL
 *     }),
 *     newvar_int32_t(123),
 *     NULL
 * });
 * ```
 *
 * This corresponds to the following manual version:
 * ```
 * amxc_var_t mylist;
 * amxc_var_init(&mylist);
 * amxc_var_set_type(&mylist, AMXC_VAR_ID_LIST);
 * amxc_var_t* sublist = amxc_var_add_new(&mylist);
 * amxc_var_add(cstring_t, sublist, "hello");
 * amxc_var_add(int32_t, &mylist, 123);
 * ```
 */


typedef struct {
    const char* key;
    amxc_var_t* value;
} newvar_kv_t;

amxc_var_t* newvar_null();
amxc_var_t* newvar_bool(bool value);
amxc_var_t* newvar_uint8_t(uint8_t value);
amxc_var_t* newvar_uint16_t(uint16_t value);
amxc_var_t* newvar_uint32_t(uint32_t value);
amxc_var_t* newvar_uint64_t(uint64_t value);
amxc_var_t* newvar_int8_t(int8_t value);
amxc_var_t* newvar_int16_t(int16_t value);
amxc_var_t* newvar_int32_t(int32_t value);
amxc_var_t* newvar_int64_t(int64_t value);
amxc_var_t* newvar_cstring_t(const char* value);
amxc_var_t* newvar_csv_string_t(const char* value);
amxc_var_t* newvar_ssv_string_t(const char* value);
amxc_var_t* newvar_double(double value);
amxc_var_t* newvar_list(amxc_var_t* value[]);
amxc_var_t* newvar_list_empty(void);
amxc_var_t* newvar_htable(newvar_kv_t* keyvalue_pairs[]);
amxc_var_t* newvar_htable_empty(void);
amxc_var_t* newvar_fd_t(int value);

#endif // __AMXO_TEST_COMMON_NEWVAR_H__