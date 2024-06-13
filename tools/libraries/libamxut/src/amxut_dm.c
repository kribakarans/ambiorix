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

#include "amxut/amxut_dm.h"

#include <unistd.h> // needed for cmocka
#include <setjmp.h> // needed for cmocka
#include <stdarg.h> // needed for cmocka
#include <cmocka.h>

#include "amxut/amxut_bus.h"

#include <amxc/amxc_macros.h>
#include <amxd/amxd_dm.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_object_parameter.h>
#include <amxd/amxd_transaction.h>

#define origin_to_cmocka(origin) origin.file, origin.line
#define fail_from_origin(origin) _fail(origin_to_cmocka(origin))
#define fail_msg_from_origin(origin, msg, ...) do { print_error("ERROR: " msg "\n", ## __VA_ARGS__); fail_from_origin(origin); } while (0)

/**
 * The cmocka version we are using doesn't have unsigned infrastructure yet
 * The newer versions do have this.
 * So once we use a newer version this will be overriden (weak) and can be removed.
 */
void _assert_uint_equal(const uintmax_t a,
                        const uintmax_t b,
                        const char* const file,
                        const int line);

__attribute__((weak)) void _assert_uint_equal(const uintmax_t a,
                                              const uintmax_t b,
                                              const char* const file,
                                              const int line) {
    if(a == b) {
        return;
    }

    print_error("%ju (%#jx) != %ju (%#jx)\n",
                a,
                a,
                b,
                b);
    _fail(file, line);
}


/*
 * ODL
 */

void _amxut_dm_load_odl(amxut_dm_origin_t origin, const char* format, ...) {
    va_list args;
    amxc_string_t odl_file_name;
    amxd_object_t* root_obj = amxd_dm_get_root(amxut_bus_dm());

    if(format == NULL) {
        fail_msg_from_origin(origin, "No odl file format given");
    }

    va_start(args, format);
    amxc_string_init(&odl_file_name, 0);
    amxc_string_vsetf(&odl_file_name, format, args);

    if(0 != amxo_parser_parse_file(amxut_bus_parser(), amxc_string_get(&odl_file_name, 0), root_obj)) {
        fail_msg_from_origin(origin, "PARSER MESSAGE = %s", amxc_string_get(&amxut_bus_parser()->msg, 0));
    }

    va_end(args);
    amxc_string_clean(&odl_file_name);
}

/*
 * Parameter Asserts
 */

static amxd_object_t* amxut_dm_get_object(const char* obj_path, amxut_dm_origin_t origin) {
    amxd_object_t* obj = amxd_dm_findf(amxut_bus_dm(), "%s", obj_path);
    if(obj == NULL) {
        fail_msg_from_origin(origin, "Failed to get object: %s", obj_path);
    }
    return obj;
}

static amxc_var_t* amxut_dm_get_object_param_value(const char* obj_path, const char* parameter, uint32_t expected_type, amxut_dm_origin_t origin) {
    amxd_object_t* obj = amxut_dm_get_object(obj_path, origin);

    amxc_var_t* var;
    amxc_var_new(&var);
    amxd_status_t status = amxd_object_get_param(obj, parameter, var);
    if(status != amxd_status_ok) {
        amxc_var_delete(&var);
        fail_msg_from_origin(origin, "Failed to get parameter %s of object: %s", parameter, obj_path);
    }

    uint32_t actual_type = amxc_var_type_of(var);
    if(expected_type != actual_type) {
        amxc_var_delete(&var);
        fail_msg_from_origin(origin, "Parameter type mismatch %s(%d) != %s(%d) '%s' '%s'",
                             amxc_var_get_type_name_from_id(expected_type), expected_type,
                             amxc_var_get_type_name_from_id(actual_type), actual_type,
                             obj_path, parameter);
    }

    return var;
}

void _amxut_dm_param_equals_int8_t(const char* path, const char* parameter, const int8_t expected, amxut_dm_origin_t origin) {
    amxc_var_t* var = amxut_dm_get_object_param_value(path, parameter, AMXC_VAR_ID_INT8, origin);
    _assert_int_equal(expected, amxc_var_constcast(int8_t, var), origin_to_cmocka(origin));
    amxc_var_delete(&var);
}
void _amxut_dm_param_equals_int16_t(const char* path, const char* parameter, const int16_t expected, amxut_dm_origin_t origin) {
    amxc_var_t* var = amxut_dm_get_object_param_value(path, parameter, AMXC_VAR_ID_INT16, origin);
    _assert_int_equal(expected, amxc_var_constcast(int16_t, var), origin_to_cmocka(origin));
    amxc_var_delete(&var);

}
void _amxut_dm_param_equals_int32_t(const char* path, const char* parameter, const int32_t expected, amxut_dm_origin_t origin) {
    amxc_var_t* var = amxut_dm_get_object_param_value(path, parameter, AMXC_VAR_ID_INT32, origin);
    _assert_int_equal(expected, amxc_var_constcast(int32_t, var), origin_to_cmocka(origin));
    amxc_var_delete(&var);

}
void _amxut_dm_param_equals_int64_t(const char* path, const char* parameter, const int64_t expected, amxut_dm_origin_t origin) {
    amxc_var_t* var = amxut_dm_get_object_param_value(path, parameter, AMXC_VAR_ID_INT64, origin);
    _assert_int_equal(expected, amxc_var_constcast(int64_t, var), origin_to_cmocka(origin));
    amxc_var_delete(&var);
}

void _amxut_dm_param_equals_uint8_t(const char* path, const char* parameter, const uint8_t expected, amxut_dm_origin_t origin) {
    amxc_var_t* var = amxut_dm_get_object_param_value(path, parameter, AMXC_VAR_ID_UINT8, origin);
    _assert_uint_equal(expected, amxc_var_constcast(uint8_t, var), origin_to_cmocka(origin));
    amxc_var_delete(&var);
}
void _amxut_dm_param_equals_uint16_t(const char* path, const char* parameter, const uint16_t expected, amxut_dm_origin_t origin) {
    amxc_var_t* var = amxut_dm_get_object_param_value(path, parameter, AMXC_VAR_ID_UINT16, origin);
    _assert_uint_equal(expected, amxc_var_constcast(uint16_t, var), origin_to_cmocka(origin));
    amxc_var_delete(&var);
}
void _amxut_dm_param_equals_uint32_t(const char* path, const char* parameter, const uint32_t expected, amxut_dm_origin_t origin) {
    amxc_var_t* var = amxut_dm_get_object_param_value(path, parameter, AMXC_VAR_ID_UINT32, origin);
    _assert_uint_equal(expected, amxc_var_constcast(uint32_t, var), origin_to_cmocka(origin));
    amxc_var_delete(&var);
}
void _amxut_dm_param_equals_uint64_t(const char* path, const char* parameter, const uint64_t expected, amxut_dm_origin_t origin) {
    amxc_var_t* var = amxut_dm_get_object_param_value(path, parameter, AMXC_VAR_ID_UINT64, origin);
    _assert_uint_equal(expected, amxc_var_constcast(uint64_t, var), origin_to_cmocka(origin));
    amxc_var_delete(&var);
}

void _amxut_dm_param_equals_cstring_t(const char* path, const char* parameter, const cstring_t expected, amxut_dm_origin_t origin) {
    amxc_var_t* var = amxut_dm_get_object_param_value(path, parameter, AMXC_VAR_ID_CSTRING, origin);
    _assert_string_equal(expected, amxc_var_constcast(cstring_t, var), origin_to_cmocka(origin));
    amxc_var_delete(&var);
}
void _amxut_dm_param_equals_csv_string_t(const char* path, const char* parameter, const csv_string_t expected, amxut_dm_origin_t origin) {
    amxc_var_t* var = amxut_dm_get_object_param_value(path, parameter, AMXC_VAR_ID_CSV_STRING, origin);
    _assert_string_equal(expected, amxc_var_constcast(csv_string_t, var), origin_to_cmocka(origin));
    amxc_var_delete(&var);
}
void _amxut_dm_param_equals_ssv_string_t(const char* path, const char* parameter, const ssv_string_t expected, amxut_dm_origin_t origin) {
    amxc_var_t* var = amxut_dm_get_object_param_value(path, parameter, AMXC_VAR_ID_SSV_STRING, origin);
    _assert_string_equal(expected, amxc_var_constcast(ssv_string_t, var), origin_to_cmocka(origin));
    amxc_var_delete(&var);
}

void _amxut_dm_param_equals_bool(const char* path, const char* parameter, const bool expected, amxut_dm_origin_t origin) {
    amxc_var_t* var = amxut_dm_get_object_param_value(path, parameter, AMXC_VAR_ID_BOOL, origin);
    _assert_int_equal(expected, amxc_var_constcast(bool, var), origin_to_cmocka(origin));
    amxc_var_delete(&var);
}


/*
 * Parameter Setters
 */

static void amxut_dm_trans_set_object_param(const char* obj_path, const char* parameter_name, amxc_var_t* var, amxut_dm_origin_t origin) {
    amxd_trans_t trans;
    amxd_trans_init(&trans);
    _assert_int_equal(amxd_trans_set_attr(&trans, amxd_tattr_change_ro, true), amxd_status_ok, origin_to_cmocka(origin));
    _assert_int_equal(amxd_trans_select_pathf(&trans, "%s", obj_path), amxd_status_ok, origin_to_cmocka(origin));
    _assert_int_equal(amxd_trans_set_param(&trans, parameter_name, var), amxd_status_ok, origin_to_cmocka(origin));
    _assert_int_equal(amxd_trans_apply(&trans, amxut_bus_dm()), amxd_status_ok, origin_to_cmocka(origin));
    amxd_trans_clean(&trans);
}

static void amxut_dm_set_object_param_value(const char* obj_path, const char* parameter_name, amxc_var_t* var, amxut_dm_origin_t origin) {
    amxd_object_t* obj = amxut_dm_get_object(obj_path, origin);
    if(obj == NULL) {
        fail_msg_from_origin(origin, "Failed to get object: '%s'", obj_path);
    }

    amxd_param_t* param = amxd_object_get_param_def(obj, parameter_name);
    if(param == NULL) {
        fail_msg_from_origin(origin, "Failed to get object parameter: '%s' '%s'", obj_path, parameter_name);
    }

    uint32_t expected_type = amxc_var_type_of(var);
    uint32_t actual_type = amxd_param_get_type(param);
    if(expected_type != actual_type) {
        fail_msg_from_origin(origin, "Parameter type mismatch %s(%d) != %s(%d) '%s' '%s'",
                             amxc_var_get_type_name_from_id(expected_type), expected_type,
                             amxc_var_get_type_name_from_id(actual_type), actual_type,
                             obj_path, parameter_name);
    }

    amxut_dm_trans_set_object_param(obj_path, parameter_name, var, origin);
}

void _amxut_dm_param_set_int8_t(const char* path, const char* parameter, const int8_t value, amxut_dm_origin_t origin) {
    amxc_var_t var;
    amxc_var_init(&var);
    amxc_var_set(int8_t, &var, value);
    amxut_dm_set_object_param_value(path, parameter, &var, origin);
    amxc_var_clean(&var);
}
void _amxut_dm_param_set_int16_t(const char* path, const char* parameter, const int16_t value, amxut_dm_origin_t origin) {
    amxc_var_t var;
    amxc_var_init(&var);
    amxc_var_set(int16_t, &var, value);
    amxut_dm_set_object_param_value(path, parameter, &var, origin);
    amxc_var_clean(&var);
}
void _amxut_dm_param_set_int32_t(const char* path, const char* parameter, const int32_t value, amxut_dm_origin_t origin) {
    amxc_var_t var;
    amxc_var_init(&var);
    amxc_var_set(int32_t, &var, value);
    amxut_dm_set_object_param_value(path, parameter, &var, origin);
    amxc_var_clean(&var);
}
void _amxut_dm_param_set_int64_t(const char* path, const char* parameter, const int64_t value, amxut_dm_origin_t origin) {
    amxc_var_t var;
    amxc_var_init(&var);
    amxc_var_set(int64_t, &var, value);
    amxut_dm_set_object_param_value(path, parameter, &var, origin);
    amxc_var_clean(&var);
}

void _amxut_dm_param_set_uint8_t(const char* path, const char* parameter, const uint8_t value, amxut_dm_origin_t origin) {
    amxc_var_t var;
    amxc_var_init(&var);
    amxc_var_set(uint8_t, &var, value);
    amxut_dm_set_object_param_value(path, parameter, &var, origin);
    amxc_var_clean(&var);
}
void _amxut_dm_param_set_uint16_t(const char* path, const char* parameter, const uint16_t value, amxut_dm_origin_t origin) {
    amxc_var_t var;
    amxc_var_init(&var);
    amxc_var_set(uint16_t, &var, value);
    amxut_dm_set_object_param_value(path, parameter, &var, origin);
    amxc_var_clean(&var);
}
void _amxut_dm_param_set_uint32_t(const char* path, const char* parameter, const uint32_t value, amxut_dm_origin_t origin) {
    amxc_var_t var;
    amxc_var_init(&var);
    amxc_var_set(uint32_t, &var, value);
    amxut_dm_set_object_param_value(path, parameter, &var, origin);
    amxc_var_clean(&var);
}
void _amxut_dm_param_set_uint64_t(const char* path, const char* parameter, const uint64_t value, amxut_dm_origin_t origin) {
    amxc_var_t var;
    amxc_var_init(&var);
    amxc_var_set(uint64_t, &var, value);
    amxut_dm_set_object_param_value(path, parameter, &var, origin);
    amxc_var_clean(&var);
}

void _amxut_dm_param_set_cstring_t(const char* path, const char* parameter, const cstring_t value, amxut_dm_origin_t origin) {
    amxc_var_t var;
    amxc_var_init(&var);
    amxc_var_set(cstring_t, &var, value);
    amxut_dm_set_object_param_value(path, parameter, &var, origin);
    amxc_var_clean(&var);
}
void _amxut_dm_param_set_csv_string_t(const char* path, const char* parameter, const csv_string_t value, amxut_dm_origin_t origin) {
    amxc_var_t var;
    amxc_var_init(&var);
    amxc_var_set(csv_string_t, &var, value);
    amxut_dm_set_object_param_value(path, parameter, &var, origin);
    amxc_var_clean(&var);
}
void _amxut_dm_param_set_ssv_string_t(const char* path, const char* parameter, const ssv_string_t value, amxut_dm_origin_t origin) {
    amxc_var_t var;
    amxc_var_init(&var);
    amxc_var_set(ssv_string_t, &var, value);
    amxut_dm_set_object_param_value(path, parameter, &var, origin);
    amxc_var_clean(&var);
}

void _amxut_dm_param_set_bool(const char* path, const char* parameter, const bool value, amxut_dm_origin_t origin) {
    amxc_var_t var;
    amxc_var_init(&var);
    amxc_var_set(bool, &var, value);
    amxut_dm_set_object_param_value(path, parameter, &var, origin);
    amxc_var_clean(&var);
}


/*
 * RPC
 */

int _amxut_dm_invoke(const char* obj_path, const char* func_name, amxc_var_t* args, amxc_var_t* ret, amxut_dm_origin_t origin) {
    amxd_object_t* obj = amxut_dm_get_object(obj_path, origin);
    return amxd_object_invoke_function(obj, func_name, args, ret);
}


/*
 * Deprecated
 */

static amxc_var_t* s_get_param(const char* path, const char* param_name, uint32_t expected_type) {
    amxc_var_t params_with_path;
    amxc_var_t* params = NULL;
    amxc_var_t* value = NULL;
    amxc_var_t* value_copy = NULL;
    int rv = 0;
    amxc_var_init(&params_with_path);

    assert_non_null(path);
    assert_non_null(param_name);

    rv = amxb_get(amxut_bus_ctx(), path, 0, &params_with_path, 1);
    if(rv != 0) {
        fail_msg("Cannot find '%s'", path);
    }
    params = amxc_var_get_first(amxc_var_get_first(&params_with_path));
    value = GET_ARG(params, param_name);
    if(value == NULL) {
        fail_msg("Cannot find parameter '%s' in '%s'", param_name, path);
    }

    if(expected_type != amxc_var_type_of(value)) {
        fail_msg("Unexpected type for '%s' '%s' : got %d but expected %d", path, param_name,
                 amxc_var_type_of(value), expected_type);
    }

    amxc_var_new(&value_copy);
    amxc_var_copy(value_copy, value);
    amxc_var_clean(&params_with_path);

    return value_copy;
}

void amxut_dm_assert_int8(const char* path, const char* parameter, int8_t expected_value) {
    amxc_var_t* var = s_get_param(path, parameter, AMXC_VAR_ID_INT8);
    assert_int_equal(expected_value, amxc_var_constcast(int8_t, var));
    amxc_var_delete(&var);
}

void amxut_dm_assert_uint8(const char* path, const char* parameter, uint8_t expected_value) {
    amxc_var_t* var = s_get_param(path, parameter, AMXC_VAR_ID_UINT8);
    assert_int_equal(expected_value, amxc_var_constcast(uint8_t, var));
    amxc_var_delete(&var);
}

void amxut_dm_assert_int16(const char* path, const char* parameter, int16_t expected_value) {
    amxc_var_t* var = s_get_param(path, parameter, AMXC_VAR_ID_INT16);
    assert_int_equal(expected_value, amxc_var_constcast(int16_t, var));
    amxc_var_delete(&var);
}

void amxut_dm_assert_uint16(const char* path, const char* parameter, uint16_t expected_value) {
    amxc_var_t* var = s_get_param(path, parameter, AMXC_VAR_ID_UINT16);
    assert_int_equal(expected_value, amxc_var_constcast(uint16_t, var));
    amxc_var_delete(&var);
}

void amxut_dm_assert_int32(const char* path, const char* parameter, int32_t expected_value) {
    amxc_var_t* var = s_get_param(path, parameter, AMXC_VAR_ID_INT32);
    assert_int_equal(expected_value, amxc_var_constcast(int32_t, var));
    amxc_var_delete(&var);
}

void amxut_dm_assert_uint32(const char* path, const char* parameter, uint32_t expected_value) {
    amxc_var_t* var = s_get_param(path, parameter, AMXC_VAR_ID_UINT32);
    assert_int_equal(expected_value, amxc_var_constcast(uint32_t, var));
    amxc_var_delete(&var);
}

void amxut_dm_assert_str(const char* path, const char* parameter, const char* expected_value) {
    amxc_var_t* var = s_get_param(path, parameter, AMXC_VAR_ID_CSTRING);
    assert_string_equal(expected_value, amxc_var_constcast(cstring_t, var));
    amxc_var_delete(&var);
}
