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
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <cmocka.h>

#include <amxc/amxc.h>
#include <amxp/amxp_signal.h>
#include <amxp/amxp_slot.h>

#include <amxd/amxd_common.h>
#include <amxd/amxd_dm.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_parameter.h>
#include <amxd/amxd_function.h>
#include <amxd/amxd_action.h>

#include "test_amxd_parameter_validation.h"

#include <amxc/amxc_macros.h>
static amxd_dm_t dm;

static amxd_object_t* test_build_dm(void) {
    amxd_object_t* object = NULL;
    amxd_object_t* sub_object = NULL;
    amxd_param_t* param = NULL;

    assert_int_equal(amxd_dm_init(&dm), 0);

    assert_int_equal(amxd_object_new(&object, amxd_object_singleton, "TestObject"), 0);
    assert_int_equal(amxd_dm_add_root_object(&dm, object), 0);
    assert_int_equal(amxd_param_new(&param, "Text", AMXC_VAR_ID_CSTRING), 0);
    assert_int_equal(amxd_object_add_param(object, param), 0);
    assert_int_equal(amxd_param_new(&param, "Number", AMXC_VAR_ID_INT32), 0);
    assert_int_equal(amxd_object_add_param(object, param), 0);
    assert_int_equal(amxd_param_new(&param, "Reference", AMXC_VAR_ID_CSV_STRING), 0);
    assert_int_equal(amxd_object_add_param(object, param), 0);
    assert_int_equal(amxd_param_new(&param, "CsvText", AMXC_VAR_ID_CSV_STRING), 0);
    assert_int_equal(amxd_object_add_param(object, param), 0);
    assert_int_equal(amxd_object_new(&sub_object, amxd_object_singleton, "SubObject"), 0);
    assert_int_equal(amxd_object_add_object(object, sub_object), 0);
    assert_int_equal(amxd_param_new(&param, "Number", AMXC_VAR_ID_INT32), 0);
    assert_int_equal(amxd_object_add_param(sub_object, param), 0);

    return object;
}

void test_amxd_param_validate_min(UNUSED void** state) {
    amxd_object_t* object = NULL;
    amxd_param_t* param = NULL;
    amxc_var_t* data;
    amxc_var_t value;

    amxc_var_new(&data);
    amxc_var_set(uint32_t, data, 10);

    amxc_var_init(&value);

    object = test_build_dm();
    param = amxd_object_get_param_def(object, "Text");
    amxc_var_set(cstring_t, &value, "abcdefghij");
    amxd_param_set_value(param, &value);
    assert_int_equal(amxd_param_describe(param, &value), 0);
    assert_null(GETP_ARG(&value, "validate"));
    assert_int_equal(amxd_param_add_action_cb(param, action_param_validate, amxd_action_param_check_minimum, data), 0);
    assert_int_equal(amxd_param_describe(param, &value), 0);
    amxc_var_dump(&value, STDOUT_FILENO);
    assert_non_null(GETP_ARG(&value, "validate.check_minimum_length"));

    amxc_var_set(cstring_t, &value, "");
    assert_int_not_equal(amxd_param_set_value(param, &value), 0);

    assert_int_not_equal(amxd_param_validate(param, &value), 0);
    amxc_var_set(cstring_t, &value, "abcde");
    assert_int_not_equal(amxd_param_validate(param, &value), 0);
    amxc_var_set(cstring_t, &value, "abcdefghij");
    assert_int_equal(amxd_param_validate(param, &value), 0);
    amxc_var_set(cstring_t, &value, "abcdefghij12345");
    assert_int_equal(amxd_param_validate(param, &value), 0);
    amxc_var_set_type(&value, AMXC_VAR_ID_CSTRING);
    assert_int_not_equal(amxd_param_validate(param, &value), 0);

    assert_int_equal(amxd_param_remove_action_cb(param, action_param_validate, amxd_action_param_check_minimum), 0);
    amxc_var_set(cstring_t, &value, "abcde");
    assert_int_equal(amxd_param_validate(param, &value), 0);
    assert_int_equal(amxd_param_add_action_cb(param, action_param_validate, amxd_action_param_check_minimum, NULL), 0);
    assert_int_not_equal(amxd_param_validate(param, &value), 0);
    amxc_var_set(cstring_t, &value, "abcdefghij");
    assert_int_not_equal(amxd_param_validate(param, &value), 0);
    assert_int_equal(amxd_param_remove_action_cb(param, action_param_validate, amxd_action_param_check_minimum), 0);

    param = amxd_object_get_param_def(object, "Number");
    amxc_var_set(uint32_t, &value, 10);
    amxd_param_set_value(param, &value);

    param = amxd_object_get_param_def(object, "Text");
    amxc_var_set(cstring_t, &value, "abcdefghij");
    amxd_param_set_value(param, &value);
    amxc_var_set(cstring_t, data, "TestObject.Number");
    assert_int_equal(amxd_param_add_action_cb(param, action_param_validate, amxd_action_param_check_minimum, data), 0);

    amxc_var_set(cstring_t, &value, "");
    assert_int_not_equal(amxd_param_set_value(param, &value), 0);

    assert_int_not_equal(amxd_param_validate(param, &value), 0);
    amxc_var_set(cstring_t, &value, "abcde");
    assert_int_not_equal(amxd_param_validate(param, &value), 0);
    amxc_var_set(cstring_t, &value, "abcdefghij");
    assert_int_equal(amxd_param_validate(param, &value), 0);
    amxc_var_set(cstring_t, &value, "abcdefghij12345");
    assert_int_equal(amxd_param_validate(param, &value), 0);

    assert_int_equal(amxd_param_remove_action_cb(param, action_param_validate, amxd_action_param_check_minimum), 0);

    param = amxd_object_get_param_def(object, "Number");
    assert_int_equal(amxd_param_add_action_cb(param, action_param_validate, amxd_action_param_check_minimum, data), 0);

    amxc_var_set(uint64_t, &value, 5);
    assert_int_not_equal(amxd_param_validate(param, &value), 0);
    amxc_var_set(uint64_t, &value, 10);
    assert_int_equal(amxd_param_validate(param, &value), 0);
    amxc_var_set(uint64_t, &value, 15);
    assert_int_equal(amxd_param_validate(param, &value), 0);

    assert_int_equal(amxd_param_remove_action_cb(param, action_param_validate, amxd_action_param_check_minimum), 0);
    amxc_var_set(int32_t, &value, 5);
    assert_int_equal(amxd_param_validate(param, &value), 0);

    param = amxd_object_get_param_def(object, "Reference");
    assert_int_equal(amxd_param_add_action_cb(param, action_param_validate, amxd_action_param_check_minimum, data), 0);
    amxc_var_set(cstring_t, &value, "foo,bar");
    assert_int_not_equal(amxd_param_validate(param, &value), 0);
    amxc_var_set(cstring_t, &value, "foo,bar,foo,bar");
    assert_int_equal(amxd_param_validate(param, &value), 0);

    amxc_var_delete(&data);
    amxc_var_clean(&value);
    amxd_dm_clean(&dm);
}

void test_amxd_param_validate_max(UNUSED void** state) {
    amxd_object_t* object = NULL;
    amxd_object_t* sub_object = NULL;
    amxd_param_t* param = NULL;
    amxc_var_t* data;
    amxc_var_t value;

    amxc_var_init(&value);
    amxc_var_new(&data);
    amxc_var_set(uint32_t, data, 10);

    object = test_build_dm();
    param = amxd_object_get_param_def(object, "Text");
    assert_int_equal(amxd_param_add_action_cb(param, action_param_validate, amxd_action_param_check_maximum, data), 0);
    assert_int_equal(amxd_param_describe(param, &value), 0);
    assert_non_null(GETP_ARG(&value, "validate.check_maximum_length"));

    assert_int_not_equal(amxd_param_validate(param, &value), 0);
    amxc_var_set(cstring_t, &value, "abcde");
    assert_int_equal(amxd_param_validate(param, &value), 0);
    amxc_var_set(cstring_t, &value, "abcdefghij");
    assert_int_equal(amxd_param_validate(param, &value), 0);
    amxc_var_set(cstring_t, &value, "abcdefghij12345");
    assert_int_not_equal(amxd_param_validate(param, &value), 0);

    amxc_var_set_type(&value, AMXC_VAR_ID_CSTRING);
    assert_int_equal(amxd_param_validate(param, &value), 0);

    assert_int_equal(amxd_param_remove_action_cb(param, action_param_validate, amxd_action_param_check_maximum), 0);
    amxc_var_set(cstring_t, &value, "abcdefghij12345");
    assert_int_equal(amxd_param_validate(param, &value), 0);
    assert_int_equal(amxd_param_add_action_cb(param, action_param_validate, amxd_action_param_check_maximum, NULL), 0);
    assert_int_not_equal(amxd_param_validate(param, &value), 0);
    amxc_var_set(cstring_t, &value, "abcde");
    assert_int_not_equal(amxd_param_validate(param, &value), 0);

    assert_int_equal(amxd_param_remove_action_cb(param, action_param_validate, amxd_action_param_check_maximum), 0);

    sub_object = amxd_object_get_child(object, "SubObject");
    param = amxd_object_get_param_def(sub_object, "Number");
    amxc_var_set(uint32_t, &value, 10);
    amxd_param_set_value(param, &value);

    param = amxd_object_get_param_def(object, "Text");
    amxc_var_set(cstring_t, &value, "abcdefghij");
    amxd_param_set_value(param, &value);
    amxc_var_set(cstring_t, data, ".SubObject.Number");
    assert_int_equal(amxd_param_add_action_cb(param, action_param_validate, amxd_action_param_check_maximum, data), 0);

    amxc_var_set(cstring_t, &value, "abcde");
    assert_int_equal(amxd_param_validate(param, &value), 0);
    amxc_var_set(cstring_t, &value, "abcdefghij");
    assert_int_equal(amxd_param_validate(param, &value), 0);
    amxc_var_set(cstring_t, &value, "abcdefghij12345");
    assert_int_not_equal(amxd_param_validate(param, &value), 0);
    assert_int_equal(amxd_param_remove_action_cb(param, action_param_validate, amxd_action_param_check_maximum), 0);

    param = amxd_object_get_param_def(object, "Number");
    assert_int_equal(amxd_param_add_action_cb(param, action_param_validate, amxd_action_param_check_maximum, data), 0);

    amxc_var_set(uint64_t, &value, 5);
    assert_int_equal(amxd_param_validate(param, &value), 0);
    amxc_var_set(uint64_t, &value, 10);
    assert_int_equal(amxd_param_validate(param, &value), 0);
    amxc_var_set(uint64_t, &value, 15);
    assert_int_not_equal(amxd_param_validate(param, &value), 0);

    assert_int_equal(amxd_param_remove_action_cb(param, action_param_validate, amxd_action_param_check_maximum), 0);
    assert_int_equal(amxd_param_validate(param, &value), 0);

    param = amxd_object_get_param_def(object, "Reference");
    assert_int_equal(amxd_param_add_action_cb(param, action_param_validate, amxd_action_param_check_maximum, data), 0);
    amxc_var_set(cstring_t, &value, "foo,bar");
    assert_int_equal(amxd_param_validate(param, &value), 0);
    amxc_var_set(cstring_t, &value, "foo,bar,foo,bar");
    assert_int_not_equal(amxd_param_validate(param, &value), 0);

    amxc_var_delete(&data);
    amxc_var_clean(&value);
    amxd_dm_clean(&dm);
}

void test_amxd_param_validate_range_table(UNUSED void** state) {
    amxd_object_t* object = NULL;
    amxd_param_t* param = NULL;
    amxc_var_t* data;
    amxc_var_t value;

    amxc_var_init(&value);
    amxc_var_new(&data);
    amxc_var_set_type(data, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(uint32_t, data, "min", 10);
    amxc_var_add_key(uint32_t, data, "max", 20);

    object = test_build_dm();
    param = amxd_object_get_param_def(object, "Text");
    assert_int_equal(amxd_param_add_action_cb(param, action_param_validate, amxd_action_param_check_range, data), 0);
    assert_int_equal(amxd_param_describe(param, &value), 0);
    assert_non_null(GETP_ARG(&value, "validate.check_range"));

    assert_int_not_equal(amxd_param_validate(param, &value), 0);
    amxc_var_set(cstring_t, &value, "abcde");
    assert_int_not_equal(amxd_param_validate(param, &value), 0);
    amxc_var_set(cstring_t, &value, "abcdefghij");
    assert_int_equal(amxd_param_validate(param, &value), 0);
    amxc_var_set(cstring_t, &value, "abcdefghij12345");
    assert_int_equal(amxd_param_validate(param, &value), 0);
    amxc_var_set(cstring_t, &value, "abcdefghij1234567890");
    assert_int_equal(amxd_param_validate(param, &value), 0);
    amxc_var_set(cstring_t, &value, "abcdefghijklmnopqrstuvwxyz");
    assert_int_not_equal(amxd_param_validate(param, &value), 0);

    amxc_var_set_type(&value, AMXC_VAR_ID_CSTRING);
    assert_int_not_equal(amxd_param_validate(param, &value), 0);

    assert_int_equal(amxd_param_remove_action_cb(param, action_param_validate, amxd_action_param_check_range), 0);
    amxc_var_set(cstring_t, &value, "abcde");
    assert_int_equal(amxd_param_validate(param, &value), 0);
    assert_int_equal(amxd_param_add_action_cb(param, action_param_validate, amxd_action_param_check_range, NULL), 0);
    assert_int_not_equal(amxd_param_validate(param, &value), 0);
    amxc_var_set(cstring_t, &value, "abcdefghijkl");
    assert_int_not_equal(amxd_param_validate(param, &value), 0);

    param = amxd_object_get_param_def(object, "Number");
    assert_int_equal(amxd_param_add_action_cb(param, action_param_validate, amxd_action_param_check_range, data), 0);

    amxc_var_set(uint64_t, &value, 5);
    assert_int_not_equal(amxd_param_validate(param, &value), 0);
    amxc_var_set(uint64_t, &value, 10);
    assert_int_equal(amxd_param_validate(param, &value), 0);
    amxc_var_set(uint64_t, &value, 15);
    assert_int_equal(amxd_param_validate(param, &value), 0);
    amxc_var_set(uint64_t, &value, 20);
    assert_int_equal(amxd_param_validate(param, &value), 0);
    amxc_var_set(uint64_t, &value, 26);
    assert_int_not_equal(amxd_param_validate(param, &value), 0);

    assert_int_equal(amxd_param_remove_action_cb(param, action_param_validate, amxd_action_param_check_range), 0);
    assert_int_equal(amxd_param_validate(param, &value), 0);

    amxc_var_clean(data);
    assert_int_equal(amxd_param_add_action_cb(param, action_param_validate, amxd_action_param_check_range, data), 0);
    amxc_var_set(uint64_t, &value, 10);
    assert_int_not_equal(amxd_param_validate(param, &value), 0);

    amxc_var_delete(&data);
    amxc_var_clean(&value);
    amxd_dm_clean(&dm);
}

void test_amxd_param_validate_range_list(UNUSED void** state) {
    amxd_object_t* object = NULL;
    amxd_param_t* param = NULL;
    amxc_var_t* data;
    amxc_var_t value;

    amxc_var_new(&data);
    amxc_var_set_type(data, AMXC_VAR_ID_LIST);
    amxc_var_add(uint32_t, data, 10);
    amxc_var_add(uint32_t, data, 20);

    object = test_build_dm();
    param = amxd_object_get_param_def(object, "Text");
    assert_int_equal(amxd_param_add_action_cb(param, action_param_validate, amxd_action_param_check_range, data), 0);

    amxc_var_init(&value);
    assert_int_not_equal(amxd_param_validate(param, &value), 0);
    amxc_var_set(cstring_t, &value, "abcde");
    assert_int_not_equal(amxd_param_validate(param, &value), 0);
    amxc_var_set(cstring_t, &value, "abcdefghij");
    assert_int_equal(amxd_param_validate(param, &value), 0);
    amxc_var_set(cstring_t, &value, "abcdefghij12345");
    assert_int_equal(amxd_param_validate(param, &value), 0);
    amxc_var_set(cstring_t, &value, "abcdefghij1234567890");
    assert_int_equal(amxd_param_validate(param, &value), 0);
    amxc_var_set(cstring_t, &value, "abcdefghijklmnopqrstuvwxyz");
    assert_int_not_equal(amxd_param_validate(param, &value), 0);

    amxc_var_set_type(&value, AMXC_VAR_ID_CSTRING);
    assert_int_not_equal(amxd_param_validate(param, &value), 0);

    assert_int_equal(amxd_param_remove_action_cb(param, action_param_validate, amxd_action_param_check_range), 0);
    amxc_var_set(cstring_t, &value, "abcde");
    assert_int_equal(amxd_param_validate(param, &value), 0);
    assert_int_equal(amxd_param_add_action_cb(param, action_param_validate, amxd_action_param_check_range, NULL), 0);
    assert_int_not_equal(amxd_param_validate(param, &value), 0);
    amxc_var_set(cstring_t, &value, "abcdefghijkl");
    assert_int_not_equal(amxd_param_validate(param, &value), 0);

    param = amxd_object_get_param_def(object, "Number");
    assert_int_equal(amxd_param_add_action_cb(param, action_param_validate, amxd_action_param_check_range, data), 0);

    amxc_var_set(uint64_t, &value, 5);
    assert_int_not_equal(amxd_param_validate(param, &value), 0);
    amxc_var_set(uint64_t, &value, 10);
    assert_int_equal(amxd_param_validate(param, &value), 0);
    amxc_var_set(uint64_t, &value, 15);
    assert_int_equal(amxd_param_validate(param, &value), 0);
    amxc_var_set(uint64_t, &value, 20);
    assert_int_equal(amxd_param_validate(param, &value), 0);
    amxc_var_set(uint64_t, &value, 26);
    assert_int_not_equal(amxd_param_validate(param, &value), 0);

    assert_int_equal(amxd_param_remove_action_cb(param, action_param_validate, amxd_action_param_check_range), 0);
    assert_int_equal(amxd_param_validate(param, &value), 0);

    amxc_var_clean(data);
    assert_int_equal(amxd_param_add_action_cb(param, action_param_validate, amxd_action_param_check_range, data), 0);
    amxc_var_set(uint64_t, &value, 10);
    assert_int_not_equal(amxd_param_validate(param, &value), 0);

    amxc_var_delete(&data);
    amxc_var_clean(&value);
    amxd_dm_clean(&dm);
}

void test_amxd_param_validate_range_invalid(UNUSED void** state) {
    amxd_object_t* object = NULL;
    amxd_param_t* param = NULL;
    amxc_var_t* data;
    amxc_var_t value;

    amxc_var_new(&data);
    amxc_var_set_type(data, AMXC_VAR_ID_LIST);
    amxc_var_add(uint32_t, data, 20);
    amxc_var_add(uint32_t, data, 10);

    object = test_build_dm();
    param = amxd_object_get_param_def(object, "Text");
    assert_int_equal(amxd_param_add_action_cb(param, action_param_validate, amxd_action_param_check_range, data), 0);

    amxc_var_init(&value);
    assert_int_not_equal(amxd_param_validate(param, &value), 0);
    amxc_var_set(cstring_t, &value, "abcde");
    assert_int_not_equal(amxd_param_validate(param, &value), 0);
    amxc_var_set(cstring_t, &value, "abcdefghijkl");
    assert_int_not_equal(amxd_param_validate(param, &value), 0);
    amxc_var_set(cstring_t, &value, "abcdefghijklmnopqrstuv");
    assert_int_not_equal(amxd_param_validate(param, &value), 0);

    param = amxd_object_get_param_def(object, "Number");
    assert_int_equal(amxd_param_add_action_cb(param, action_param_validate, amxd_action_param_check_range, data), 0);

    amxc_var_set(uint64_t, &value, 5);
    assert_int_not_equal(amxd_param_validate(param, &value), 0);
    amxc_var_set(uint64_t, &value, 15);
    assert_int_not_equal(amxd_param_validate(param, &value), 0);
    amxc_var_set(uint64_t, &value, 25);
    assert_int_not_equal(amxd_param_validate(param, &value), 0);

    amxc_var_delete(&data);
    amxc_var_clean(&value);
    amxd_dm_clean(&dm);
}

void test_amxd_param_validate_enum(UNUSED void** state) {
    amxd_object_t* object = NULL;
    amxd_param_t* param = NULL;
    amxc_var_t* data;
    amxc_var_t value;

    object = test_build_dm();

    amxc_var_init(&value);
    amxc_var_new(&data);
    amxc_var_set_type(data, AMXC_VAR_ID_LIST);
    amxc_var_add(int32_t, data, 10);
    amxc_var_add(uint64_t, data, 20);
    amxc_var_add(int64_t, data, -10);
    amxc_var_add(int64_t, data, -20);

    param = amxd_object_get_param_def(object, "Number");
    assert_int_equal(amxd_param_add_action_cb(param, action_param_validate, amxd_action_param_check_enum, data), 0);
    assert_int_equal(amxd_param_describe(param, &value), 0);
    assert_non_null(GETP_ARG(&value, "validate.check_enum"));

    assert_int_not_equal(amxd_param_validate(param, &value), 0);
    amxc_var_set(uint64_t, &value, 5);
    assert_int_not_equal(amxd_param_validate(param, &value), 0);
    amxc_var_set(uint64_t, &value, 10);
    assert_int_equal(amxd_param_validate(param, &value), 0);
    amxc_var_set(int64_t, &value, -5);
    assert_int_not_equal(amxd_param_validate(param, &value), 0);
    amxc_var_set(int64_t, &value, -20);
    assert_int_equal(amxd_param_validate(param, &value), 0);
    amxc_var_set(int32_t, &value, -10);
    assert_int_equal(amxd_param_validate(param, &value), 0);
    amxc_var_set(uint32_t, &value, 0);
    assert_int_not_equal(amxd_param_validate(param, &value), 0);

    assert_int_equal(amxd_param_remove_action_cb(param, action_param_validate, amxd_action_param_check_enum), 0);
    assert_int_equal(amxd_param_validate(param, &value), 0);

    amxc_var_clean(data);
    assert_int_equal(amxd_param_add_action_cb(param, action_param_validate, amxd_action_param_check_enum, data), 0);
    amxc_var_set(uint64_t, &value, 10);
    assert_int_not_equal(amxd_param_validate(param, &value), 0);

    amxc_var_delete(&data);
    amxc_var_clean(&value);
    amxd_dm_clean(&dm);
}

void test_amxd_param_csv_validate_enum(UNUSED void** state) {
    amxd_object_t* object = NULL;
    amxd_param_t* param = NULL;
    amxc_var_t* data;
    amxc_var_t value;

    object = test_build_dm();

    amxc_var_new(&data);
    amxc_var_set_type(data, AMXC_VAR_ID_LIST);
    amxc_var_add(int32_t, data, 10);
    amxc_var_add(uint64_t, data, 20);
    amxc_var_add(int64_t, data, -10);
    amxc_var_add(int64_t, data, -20);

    param = amxd_object_get_param_def(object, "CsvText");
    assert_int_equal(amxd_param_add_action_cb(param, action_param_validate, amxd_action_param_check_enum, data), 0);

    amxc_var_init(&value);
    assert_int_not_equal(amxd_param_validate(param, &value), 0);
    amxc_var_set(uint64_t, &value, 5);
    assert_int_not_equal(amxd_param_validate(param, &value), 0);
    amxc_var_set(uint64_t, &value, 10);
    assert_int_equal(amxd_param_validate(param, &value), 0);
    amxc_var_set(cstring_t, &value, "-5, 10");
    assert_int_not_equal(amxd_param_validate(param, &value), 0);
    amxc_var_set(cstring_t, &value, "-20, 20");
    assert_int_equal(amxd_param_validate(param, &value), 0);
    amxc_var_set(int32_t, &value, -10);
    assert_int_equal(amxd_param_validate(param, &value), 0);
    amxc_var_set(uint32_t, &value, 0);
    assert_int_not_equal(amxd_param_validate(param, &value), 0);

    assert_int_equal(amxd_param_remove_action_cb(param, action_param_validate, amxd_action_param_check_enum), 0);
    assert_int_equal(amxd_param_validate(param, &value), 0);

    amxc_var_clean(data);
    assert_int_equal(amxd_param_add_action_cb(param, action_param_validate, amxd_action_param_check_enum, data), 0);
    amxc_var_set(uint64_t, &value, 10);
    assert_int_not_equal(amxd_param_validate(param, &value), 0);

    amxc_var_delete(&data);
    amxc_var_clean(&value);
    amxd_dm_clean(&dm);
}

void test_amxd_param_validate_reference(UNUSED void** state) {
    amxd_object_t* object = NULL;
    amxd_param_t* param = NULL;
    amxc_var_t* data;
    amxc_var_t value;
    uint8_t i;
    const char* data_list[2] = {"TestObject.Reference", ".Reference"};

    for(i = 0; i < 2; i++) {
        object = test_build_dm();

        amxc_var_init(&value);
        amxc_var_new(&data);
        amxc_var_set(cstring_t, data, data_list[i]);

        param = amxd_object_get_param_def(object, "Text");
        assert_int_equal(amxd_param_add_action_cb(param, action_param_validate, amxd_action_param_check_is_in, data), 0);
        assert_int_equal(amxd_param_describe(param, &value), 0);
        assert_non_null(GETP_ARG(&value, "validate.check_is_in"));

        amxc_var_clean(&value); // reset value to NULL variant
        assert_int_not_equal(amxd_param_validate(param, &value), 0);
        amxc_var_set(cstring_t, &value, "universe");
        assert_int_equal(amxd_param_validate(param, &value), 0);

        amxd_object_set_value(csv_string_t, object, "Reference", "hello,world,and,universe");
        assert_int_equal(amxd_param_validate(param, &value), 0);

        amxc_var_set(cstring_t, &value, "silly text");
        assert_int_not_equal(amxd_param_validate(param, &value), 0);
        amxc_var_set(cstring_t, &value, "hello");
        assert_int_equal(amxd_param_validate(param, &value), 0);
        amxc_var_set(cstring_t, &value, "Brussels");
        assert_int_not_equal(amxd_param_validate(param, &value), 0);
        amxc_var_set(cstring_t, &value, "and");
        assert_int_equal(amxd_param_validate(param, &value), 0);
        amxc_var_set(cstring_t, &value, "world");
        assert_int_equal(amxd_param_validate(param, &value), 0);
        amxc_var_set(cstring_t, &value, "France");
        assert_int_not_equal(amxd_param_validate(param, &value), 0);

        assert_int_equal(amxd_param_remove_action_cb(param, action_param_validate, amxd_action_param_check_is_in), 0);
        assert_int_equal(amxd_param_validate(param, &value), 0);

        amxc_var_clean(data);
        assert_int_equal(amxd_param_add_action_cb(param, action_param_validate, amxd_action_param_check_is_in, data), 0);
        amxc_var_set(cstring_t, &value, "Europe");
        assert_int_not_equal(amxd_param_validate(param, &value), 0);

        amxc_var_delete(&data);
        amxc_var_clean(&value);
        amxd_dm_clean(&dm);
    }
}

void test_amxd_param_csv_validate_reference(UNUSED void** state) {
    amxd_object_t* object = NULL;
    amxd_param_t* param = NULL;
    amxc_var_t* data;
    amxc_var_t value;

    uint8_t i;
    const char* data_list[2] = {"TestObject.Reference", ".Reference"};

    for(i = 0; i < 2; i++) {
        object = test_build_dm();

        amxc_var_new(&data);
        amxc_var_set(cstring_t, data, data_list[i]);

        param = amxd_object_get_param_def(object, "CsvText");
        assert_int_equal(amxd_param_add_action_cb(param, action_param_validate, amxd_action_param_check_is_in, data), 0);

        amxc_var_init(&value);
        assert_int_not_equal(amxd_param_validate(param, &value), 0);
        amxc_var_set(cstring_t, &value, "universe,world");
        assert_int_equal(amxd_param_validate(param, &value), 0);

        amxd_object_set_value(csv_string_t, object, "Reference", "hello,world,and,universe");
        assert_int_equal(amxd_param_validate(param, &value), 0);

        amxc_var_set(cstring_t, &value, "univers,silly text");
        assert_int_not_equal(amxd_param_validate(param, &value), 0);
        amxc_var_set(cstring_t, &value, "world,hello");
        assert_int_equal(amxd_param_validate(param, &value), 0);
        amxc_var_set(cstring_t, &value, "Brussels,Paris");
        assert_int_not_equal(amxd_param_validate(param, &value), 0);
        amxc_var_set(cstring_t, &value, "world,and,universe");
        assert_int_equal(amxd_param_validate(param, &value), 0);
        amxc_var_set(cstring_t, &value, "world");
        assert_int_equal(amxd_param_validate(param, &value), 0);
        amxc_var_set(cstring_t, &value, "France");
        assert_int_not_equal(amxd_param_validate(param, &value), 0);

        assert_int_equal(amxd_param_remove_action_cb(param, action_param_validate, amxd_action_param_check_is_in), 0);
        assert_int_equal(amxd_param_validate(param, &value), 0);

        amxc_var_clean(data);
        assert_int_equal(amxd_param_add_action_cb(param, action_param_validate, amxd_action_param_check_is_in, data), 0);
        amxc_var_set(cstring_t, &value, "Europe");
        assert_int_not_equal(amxd_param_validate(param, &value), 0);

        amxc_var_delete(&data);
        amxc_var_clean(&value);
        amxd_dm_clean(&dm);
    }
}

void test_amxd_param_validate_invalid_reference(UNUSED void** state) {
    amxd_object_t* object = NULL;
    amxd_param_t* param = NULL;
    amxc_var_t* data;
    amxc_var_t value;

    uint8_t i;
    const char* data_list[2] = {"TestObject.InvalidReference", "InvalidReference"};

    for(i = 0; i < 2; i++) {
        object = test_build_dm();

        amxc_var_new(&data);
        amxc_var_set(cstring_t, data, data_list[i]);

        param = amxd_object_get_param_def(object, "Text");
        assert_int_equal(amxd_param_add_action_cb(param, action_param_validate, amxd_action_param_check_is_in, data), 0);

        amxc_var_init(&value);
        assert_int_not_equal(amxd_param_validate(param, &value), 0);
        amxc_var_set(cstring_t, &value, "universe");
        assert_int_not_equal(amxd_param_validate(param, &value), 0);
        amxc_var_set(cstring_t, &value, "silly text");
        assert_int_not_equal(amxd_param_validate(param, &value), 0);
        amxc_var_set(cstring_t, &value, "hello");
        assert_int_not_equal(amxd_param_validate(param, &value), 0);
        amxc_var_set(cstring_t, &value, "Brussels");
        assert_int_not_equal(amxd_param_validate(param, &value), 0);
        amxc_var_set(cstring_t, &value, "and");
        assert_int_not_equal(amxd_param_validate(param, &value), 0);
        amxc_var_set(cstring_t, &value, "world");
        assert_int_not_equal(amxd_param_validate(param, &value), 0);
        amxc_var_set(cstring_t, &value, "France");
        assert_int_not_equal(amxd_param_validate(param, &value), 0);

        assert_int_equal(amxd_param_remove_action_cb(param, action_param_validate, amxd_action_param_check_is_in), 0);
        amxc_var_set(cstring_t, data, "TestObject.InvalidReference.");
        assert_int_equal(amxd_param_add_action_cb(param, action_param_validate, amxd_action_param_check_is_in, data), 0);
        amxc_var_set(cstring_t, &value, "Brussels");
        assert_int_not_equal(amxd_param_validate(param, &value), 0);

        amxc_var_delete(&data);
        amxc_var_clean(&value);
        amxd_dm_clean(&dm);
    }
}

void test_amxd_param_validate_wrong_action(UNUSED void** state) {
    amxd_object_t* object = NULL;
    amxd_param_t* param = NULL;
    amxc_var_t* data;
    amxc_var_t value;

    object = test_build_dm();

    amxc_var_new(&data);
    amxc_var_set_type(data, AMXC_VAR_ID_LIST);
    amxc_var_add(int32_t, data, 10);
    amxc_var_add(uint64_t, data, 20);
    amxc_var_add(int64_t, data, -10);
    amxc_var_add(int64_t, data, -20);

    param = amxd_object_get_param_def(object, "Number");
    assert_int_equal(amxd_param_add_action_cb(param, action_param_write, amxd_action_param_check_enum, data), 0);

    amxc_var_init(&value);
    amxc_var_set(uint64_t, &value, 5);
    assert_int_equal(amxd_param_validate(param, &value), 0);
    assert_int_equal(amxd_param_set_value(param, &value), 0);

    amxc_var_delete(&data);
    amxc_var_clean(&value);
    amxd_dm_clean(&dm);
}
