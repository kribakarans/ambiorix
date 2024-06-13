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

#include "test_amxut_dm.h"

#include <stdlib.h> // Needed for cmocka
#include <setjmp.h> // Needed for cmocka
#include <stdarg.h> // Needed for cmocka
#include <cmocka.h>

#include "amxut/amxut_dm.h"
#include "amxut/amxut_bus.h"
#include "amxut/amxut_macros.h"

#include <amxc/amxc.h>
#include <amxc/amxc_macros.h>
#include <amxo/amxo.h>

amxd_status_t _TestMethod(UNUSED amxd_object_t* object, UNUSED amxd_function_t* func, UNUSED amxc_var_t* args, UNUSED amxc_var_t* ret) {
    return mock();
}

void test_amxut_dm_load_odl(UNUSED void** state) {
    // GIVEN a datamodel
    // (done by setup of `amxut_bus_setup`)

    // WHEN loading an .odl file
    amxut_dm_load_odl("../common/test.odl");

    // THEN the object parameters have the value written in the .odl file
    amxut_dm_assert_str("Test.", "StringParameter", "Default initial string value");
    amxut_dm_assert_uint8("Test.", "Uint8parameter", 255);
    amxut_dm_assert_int8("Test.", "Int8parameter", -128);
    amxut_dm_assert_uint16("Test.", "Uint16parameter", 65535);
    amxut_dm_assert_int16("Test.", "Int16parameter", -32768);
    amxut_dm_assert_uint32("Test.", "Uint32parameter", 4294967295);
    amxut_dm_assert_int32("Test.", "Int32parameter", -2147483648);
}

void test_amxut_dm_can_load_odl_based_on_formatted_path(UNUSED void** state) {
    // GIVEN a datamodel
    // (done by setup of `amxut_bus_setup`)

    // WHEN loading an .odl file
    amxut_dm_load_odl("../common/%s.odl", "test");

    // THEN the object parameters have the value written in the .odl file
    amxut_dm_param_equals(cstring_t, "Test.", "StringParameter", "Default initial string value");
}

void test_amxut_dm_loaded_odl_values_can_be_asserted(UNUSED void** state) {
    // GIVEN a datamodel
    // (done by setup of `amxut_bus_setup`)

    // WHEN loading an .odl file
    amxut_dm_load_odl("../common/test.odl");

    // THEN the object parameters have the value written in the .odl file
    amxut_dm_param_equals(cstring_t, "Test.", "StringParameter", "Default initial string value");
    amxut_dm_param_equals(csv_string_t, "Test.", "CsvStringParameter", "Banana,Apple");
    amxut_dm_param_equals(ssv_string_t, "Test.", "SsvStringParameter", "Grape Prune");

    amxut_dm_param_equals(uint8_t, "Test.", "Uint8parameter", 255);
    amxut_dm_param_equals(int8_t, "Test.", "Int8parameter", -128);
    amxut_dm_param_equals(uint16_t, "Test.", "Uint16parameter", 65535);
    amxut_dm_param_equals(int16_t, "Test.", "Int16parameter", -32768);
    amxut_dm_param_equals(uint32_t, "Test.", "Uint32parameter", 4294967295);
    amxut_dm_param_equals(int32_t, "Test.", "Int32parameter", -2147483648);
    // amxut_dm_param_equals(uint64_t, "Test.", "Uint64parameterMax", UINT64_MAX); // <- This is broken! MAX == INT64_MAX
    amxut_dm_param_equals(uint64_t, "Test.", "Uint64parameter", 123456789101112);
    amxut_dm_param_equals(int64_t, "Test.", "Int64parameter", INT64_MIN);

    amxut_dm_param_equals(bool, "Test.", "BoolParameter", true);
}

void test_amxut_dm_assert_parameters_in_subobject(UNUSED void** state) {
    // GIVEN a datamodel
    // (done by setup of `amxut_bus_setup`)

    // WHEN adding objects that contain subobjects with parameters
    amxut_dm_load_odl("../common/test.odl");

    // THEN the subobject parameters can be asserted to have their value
    amxut_dm_param_equals(cstring_t, "MyStreet.MyHouse.MyDoor.", "Color", "blue");
}

void test_amxut_dm_parameters_can_be_set(UNUSED void** state) {
    // GIVEN a datamodel
    // (done by setup of `amxut_bus_setup`)

    // WHEN loading an .odl file
    amxut_dm_load_odl("../common/test.odl");

    // THEN the object parameters can be set to a new value
    amxut_dm_param_set(cstring_t, "Test.", "StringParameter", "New string value");
    amxut_dm_param_equals(cstring_t, "Test.", "StringParameter", "New string value");

    amxut_dm_param_set(csv_string_t, "Test.", "CsvStringParameter", "Peach,Pear");
    amxut_dm_param_equals(csv_string_t, "Test.", "CsvStringParameter", "Peach,Pear");

    amxut_dm_param_set(ssv_string_t, "Test.", "SsvStringParameter", "Lemon Orange");
    amxut_dm_param_equals(ssv_string_t, "Test.", "SsvStringParameter", "Lemon Orange");

    amxut_dm_param_set(uint8_t, "Test.", "Uint8parameter", 42);
    amxut_dm_param_equals(uint8_t, "Test.", "Uint8parameter", 42);

    amxut_dm_param_set(int8_t, "Test.", "Int8parameter", -84);
    amxut_dm_param_equals(int8_t, "Test.", "Int8parameter", -84);

    amxut_dm_param_set(uint16_t, "Test.", "Uint16parameter", 126);
    amxut_dm_param_equals(uint16_t, "Test.", "Uint16parameter", 126);

    amxut_dm_param_set(int16_t, "Test.", "Int16parameter", -168);
    amxut_dm_param_equals(int16_t, "Test.", "Int16parameter", -168);

    amxut_dm_param_set(uint32_t, "Test.", "Uint32parameter", 210);
    amxut_dm_param_equals(uint32_t, "Test.", "Uint32parameter", 210);

    amxut_dm_param_set(int32_t, "Test.", "Int32parameter", -252);
    amxut_dm_param_equals(int32_t, "Test.", "Int32parameter", -252);

    amxut_dm_param_set(uint64_t, "Test.", "Uint64parameter", 294);
    amxut_dm_param_equals(uint64_t, "Test.", "Uint64parameter", 294);

    amxut_dm_param_set(int64_t, "Test.", "Int64parameter", -336);
    amxut_dm_param_equals(int64_t, "Test.", "Int64parameter", -336);

    amxut_dm_param_set(bool, "Test.", "BoolParameter", false);
    amxut_dm_param_equals(bool, "Test.", "BoolParameter", false);
}

void _test_amxut_dm_event(UNUSED const char* const event_name,
                          UNUSED const amxc_var_t* const event_data,
                          UNUSED void* const priv) {
    check_expected(event_name);
}

void test_amxut_dm_parameters_set_will_trigger_events(UNUSED void** state) {
    // GIVEN a datamodel
    // (done by setup of `amxut_bus_setup`)

    // AND GIVEN a loaded .odl file with all functions resolved
    amxut_resolve_function("test_amxut_dm_event", _test_amxut_dm_event);
    amxut_dm_load_odl("../common/watched.odl");

    // EXPECT an event callback
    expect_string(_test_amxut_dm_event, event_name, "dm:object-changed");

    // WHEN the object event is triggered
    amxut_dm_param_set(bool, "Something.", "Param", false);

    amxut_bus_handle_events();
}

void test_amxut_dm_rpc_can_be_invoked(UNUSED void** state) {
    // GIVEN a datamodel
    // (done by setup of `amxut_bus_setup`)

    // AND GIVEN initialized rpc call data
    amxc_var_t args;
    amxc_var_t ret;
    amxc_var_init(&args);
    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_init(&ret);

    // WHEN loading an .odl file with an rpc method
    amxut_resolve_function("TestMethod", _TestMethod);
    amxut_dm_load_odl("../common/test.odl");
    amxut_dm_load_odl("../common/rpc.odl");

    // THEN the rpc method can be invoked
    will_return(_TestMethod, amxd_status_ok);
    amxut_dm_invoke("Test.", "TestMethod", &args, &ret);

    amxc_var_clean(&ret);
    amxc_var_clean(&args);
}

