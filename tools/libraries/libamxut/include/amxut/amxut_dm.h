/****************************************************************************
**
** SPDX-License-Identifier: BSD-2-Clause-Patent
**
** SPDX-FileCopyrightText: Copyright (c) 2023 SoftAtHome
**
** Redistribution and use in source and binary forms, with or
** without modification, are permitted provided that the following
** conditions are met:
**
** 1. Redistributions of source code must retain the above copyright
** notice, this list of conditions and the following disclaimer.
**
** 2. Redistributions in binary form must reproduce the above
** copyright notice, this list of conditions and the following
** disclaimer in the documentation and/or other materials provided
** with the distribution.
**
** Subject to the terms and conditions of this license, each
** copyright holder and contributor hereby grants to those receiving
** rights under this license a perpetual, worldwide, non-exclusive,
** no-charge, royalty-free, irrevocable (except for failure to
** satisfy the conditions of this license) patent license to make,
** have made, use, offer to sell, sell, import, and otherwise
** transfer this software, where such license applies only to those
** patent claims, already acquired or hereafter acquired, licensable
** by such copyright holder or contributor that are necessarily
** infringed by:
**
** (a) their Contribution(s) (the licensed copyrights of copyright
** holders and non-copyrightable additions of contributors, in
** source or binary form) alone; or
**
** (b) combination of their Contribution(s) with the work of
** authorship to which such Contribution(s) was added by such
** copyright holder or contributor, if, at the time the Contribution
** is added, such addition causes such combination to be necessarily
** infringed. The patent license shall not apply to any other
** combinations which include the Contribution.
**
** Except as expressly stated above, no rights or licenses from any
** copyright holder or contributor is granted under this license,
** whether expressly, by implication, estoppel or otherwise.
**
** DISCLAIMER
**
** THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
** CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
** INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
** MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
** DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR
** CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
** SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
** LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
** USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
** AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
** LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
** ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
** POSSIBILITY OF SUCH DAMAGE.
**
****************************************************************************/

#if !defined(__AMXUT_DM_H__)
#define __AMXUT_DM_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>
#include <amxc/amxc.h>

typedef struct {
    const char* file;
    int line;
} amxut_dm_origin_t;

#define AMXUT_DM_ORIGIN ((amxut_dm_origin_t) { .file = __FILE__, .line = __LINE__})

/*
 * ODL
 */
void _amxut_dm_load_odl(amxut_dm_origin_t origin, const char* format, ...);
#define amxut_dm_load_odl(file_name_fmt, ...) _amxut_dm_load_odl(AMXUT_DM_ORIGIN, file_name_fmt, ## __VA_ARGS__)

/*
 * Parameter Asserts
 */

#define _amxut_dm_param_equals(type, path, param, expected) _amxut_dm_param_equals_ ## type(path, param, expected, AMXUT_DM_ORIGIN)

void _amxut_dm_param_equals_bool(const char* path, const char* parameter, const bool expected, amxut_dm_origin_t origin);
#define amxut_dm_param_equals_bool(path, param, expected) _amxut_dm_param_equals(bool, path, param, expected)

void _amxut_dm_param_equals_int8_t(const char* path, const char* parameter, const int8_t expected, amxut_dm_origin_t origin);
void _amxut_dm_param_equals_int16_t(const char* path, const char* parameter, const int16_t expected, amxut_dm_origin_t origin);
void _amxut_dm_param_equals_int32_t(const char* path, const char* parameter, const int32_t expected, amxut_dm_origin_t origin);
void _amxut_dm_param_equals_int64_t(const char* path, const char* parameter, const int64_t expected, amxut_dm_origin_t origin);
#define amxut_dm_param_equals_int8_t(path, param, expected) _amxut_dm_param_equals(int8_t, path, param, expected)
#define amxut_dm_param_equals_int16_t(path, param, expected) _amxut_dm_param_equals(int16_t, path, param, expected)
#define amxut_dm_param_equals_int32_t(path, param, expected) _amxut_dm_param_equals(int32_t, path, param, expected)
#define amxut_dm_param_equals_int64_t(path, param, expected) _amxut_dm_param_equals(int64_t, path, param, expected)

void _amxut_dm_param_equals_uint8_t(const char* path, const char* parameter, const uint8_t expected, amxut_dm_origin_t origin);
void _amxut_dm_param_equals_uint16_t(const char* path, const char* parameter, const uint16_t expected, amxut_dm_origin_t origin);
void _amxut_dm_param_equals_uint32_t(const char* path, const char* parameter, const uint32_t expected, amxut_dm_origin_t origin);
void _amxut_dm_param_equals_uint64_t(const char* path, const char* parameter, const uint64_t expected, amxut_dm_origin_t origin);
#define amxut_dm_param_equals_uint8_t(path, param, expected) _amxut_dm_param_equals(uint8_t, path, param, expected)
#define amxut_dm_param_equals_uint16_t(path, param, expected) _amxut_dm_param_equals(uint16_t, path, param, expected)
#define amxut_dm_param_equals_uint32_t(path, param, expected) _amxut_dm_param_equals(uint32_t, path, param, expected)
#define amxut_dm_param_equals_uint64_t(path, param, expected) _amxut_dm_param_equals(uint64_t, path, param, expected)

void _amxut_dm_param_equals_cstring_t(const char* path, const char* parameter, const cstring_t expected, amxut_dm_origin_t origin);
void _amxut_dm_param_equals_csv_string_t(const char* path, const char* parameter, const csv_string_t expected, amxut_dm_origin_t origin);
void _amxut_dm_param_equals_ssv_string_t(const char* path, const char* parameter, const ssv_string_t expected, amxut_dm_origin_t origin);
#define amxut_dm_param_equals_cstring_t(path, param, expected) _amxut_dm_param_equals(cstring_t, path, param, expected)
#define amxut_dm_param_equals_csv_string_t(path, param, expected) _amxut_dm_param_equals(csv_string_t, path, param, expected)
#define amxut_dm_param_equals_ssv_string_t(path, param, expected) _amxut_dm_param_equals(ssv_string_t, path, param, expected)

#define amxut_dm_param_equals(type, path, param, expected) amxut_dm_param_equals_ ## type(path, param, expected)


/*
 * Parameter Setters
 */

#define _amxut_dm_param_set(type, path, param, value) _amxut_dm_param_set_ ## type(path, param, value, AMXUT_DM_ORIGIN)

void _amxut_dm_param_set_bool(const char* path, const char* parameter, const bool value, amxut_dm_origin_t origin);
#define amxut_dm_param_set_bool(path, param, value) _amxut_dm_param_set(bool, path, param, value)

void _amxut_dm_param_set_int8_t(const char* path, const char* parameter, const int8_t value, amxut_dm_origin_t origin);
void _amxut_dm_param_set_int16_t(const char* path, const char* parameter, const int16_t value, amxut_dm_origin_t origin);
void _amxut_dm_param_set_int32_t(const char* path, const char* parameter, const int32_t value, amxut_dm_origin_t origin);
void _amxut_dm_param_set_int64_t(const char* path, const char* parameter, const int64_t value, amxut_dm_origin_t origin);
#define amxut_dm_param_set_int8_t(path, param, value) _amxut_dm_param_set(int8_t, path, param, value)
#define amxut_dm_param_set_int16_t(path, param, value) _amxut_dm_param_set(int16_t, path, param, value)
#define amxut_dm_param_set_int32_t(path, param, value) _amxut_dm_param_set(int32_t, path, param, value)
#define amxut_dm_param_set_int64_t(path, param, value) _amxut_dm_param_set(int64_t, path, param, value)

void _amxut_dm_param_set_uint8_t(const char* path, const char* parameter, const uint8_t value, amxut_dm_origin_t origin);
void _amxut_dm_param_set_uint16_t(const char* path, const char* parameter, const uint16_t value, amxut_dm_origin_t origin);
void _amxut_dm_param_set_uint32_t(const char* path, const char* parameter, const uint32_t value, amxut_dm_origin_t origin);
void _amxut_dm_param_set_uint64_t(const char* path, const char* parameter, const uint64_t value, amxut_dm_origin_t origin);
#define amxut_dm_param_set_uint8_t(path, param, value) _amxut_dm_param_set(uint8_t, path, param, value)
#define amxut_dm_param_set_uint16_t(path, param, value) _amxut_dm_param_set(uint16_t, path, param, value)
#define amxut_dm_param_set_uint32_t(path, param, value) _amxut_dm_param_set(uint32_t, path, param, value)
#define amxut_dm_param_set_uint64_t(path, param, value) _amxut_dm_param_set(uint64_t, path, param, value)

void _amxut_dm_param_set_cstring_t(const char* path, const char* parameter, const cstring_t value, amxut_dm_origin_t origin);
void _amxut_dm_param_set_csv_string_t(const char* path, const char* parameter, const csv_string_t value, amxut_dm_origin_t origin);
void _amxut_dm_param_set_ssv_string_t(const char* path, const char* parameter, const ssv_string_t value, amxut_dm_origin_t origin);
#define amxut_dm_param_set_cstring_t(path, param, value) _amxut_dm_param_set(cstring_t, path, param, value)
#define amxut_dm_param_set_csv_string_t(path, param, value) _amxut_dm_param_set(csv_string_t, path, param, value)
#define amxut_dm_param_set_ssv_string_t(path, param, value) _amxut_dm_param_set(ssv_string_t, path, param, value)

#define amxut_dm_param_set(type, path, param, value) amxut_dm_param_set_ ## type(path, param, value)


/*
 * RPC
 */

int _amxut_dm_invoke(const char* obj_path, const char* func_name, amxc_var_t* args, amxc_var_t* ret, amxut_dm_origin_t origin);
#define amxut_dm_invoke(obj_path, func_name, args, ret) assert_int_equal(_amxut_dm_invoke(obj_path, func_name, args, ret, AMXUT_DM_ORIGIN), 0);


/*
 * Deprecated
 */

void amxut_dm_assert_int8(const char* path, const char* parameter, int8_t expected_value);
void amxut_dm_assert_uint8(const char* path, const char* parameter, uint8_t expected_value);
void amxut_dm_assert_int16(const char* path, const char* parameter, int16_t expected_value);
void amxut_dm_assert_uint16(const char* path, const char* parameter, uint16_t expected_value);
void amxut_dm_assert_int32(const char* path, const char* parameter, int32_t expected_value);
void amxut_dm_assert_uint32(const char* path, const char* parameter, uint32_t expected_value);

void amxut_dm_assert_str(const char* path, const char* parameter, const char* expected_value);

#ifdef __cplusplus
}
#endif

#endif

