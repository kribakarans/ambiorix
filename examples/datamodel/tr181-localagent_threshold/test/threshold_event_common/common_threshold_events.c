/****************************************************************************
**
** Copyright (c) 2020 SoftAtHome
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
#include <stdlib.h>
#include <stdio.h>
#include <setjmp.h>
#include <stdarg.h>
#include <cmocka.h>

#include "common_threshold_events.h"

extern amxd_dm_t dm;
extern amxb_bus_ctx_t* bus_ctx;

static const char* expected_threshold_instance = "LocalAgent.Threshold.1.";

#define SKIP_OR_RUN if(bus_ctx == NULL) { skip(); }

void test_threshold_triggered(const char* const sig_name,
                              const amxc_var_t* const data,
                              void* const priv) {
    int* event_count = (int*) priv;
    assert_string_equal(CHAR(GET_KEY(data, "path")), expected_threshold_instance);
    assert_string_equal(sig_name, "Triggered");

    printf("==================================\n");
    fflush(stdout);
    amxc_var_dump(data, STDOUT_FILENO);
    printf("==================================\n");
    fflush(stdout);
    (*event_count)++;
}

void test_can_create_threshold_instance(UNUSED void** state) {
    SKIP_OR_RUN
    amxd_object_t* threshold = amxd_dm_findf(&dm, "LocalAgent.Threshold.");
    amxc_var_t args;
    amxc_var_t ret;
    amxc_var_t* params = NULL;

    assert_non_null(threshold);

    amxc_var_init(&args);
    amxc_var_init(&ret);
    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    params = amxc_var_add_key(amxc_htable_t, &args, "parameters", NULL);
    amxc_var_add_key(bool, params, "Enable", true);
    amxc_var_add_key(cstring_t, params, "ReferencePath", "Ethernet.Interface.[Enable == true].Stats.");
    amxc_var_add_key(cstring_t, params, "ThresholdParam", "BytesReceived");
    amxc_var_add_key(cstring_t, params, "ThresholdValue", "200");
    assert_int_equal(amxd_object_invoke_function(threshold, "_add", &args, &ret), amxd_status_ok);
    amxc_var_dump(&ret, STDOUT_FILENO);
    assert_false(amxc_var_is_null(&ret));

    handle_events();

    amxc_var_clean(&args);
    amxc_var_clean(&ret);
}

void test_can_get_rise_trigger_event(UNUSED void** state) {
    SKIP_OR_RUN
    amxc_var_t args;
    amxc_var_t ret;
    int counter = 0;

    amxc_var_init(&args);
    amxc_var_init(&ret);

    amxp_slot_connect(&dm.sigmngr, "Triggered", NULL, test_threshold_triggered, &counter);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(uint32_t, &args, "BytesReceived", 190);
    assert_int_equal(amxb_set(bus_ctx, "Ethernet.Interface.1.Stats", &args, &ret, 5), 0);

    handle_events();

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(uint32_t, &args, "BytesReceived", 210);
    assert_int_equal(amxb_set(bus_ctx, "Ethernet.Interface.1.Stats", &args, &ret, 5), 0);

    handle_events();

    assert_int_equal(counter, 1);

    amxp_slot_disconnect(&dm.sigmngr, "Triggered", test_threshold_triggered);

    amxc_var_clean(&args);
    amxc_var_clean(&ret);
}

void test_no_trigger_event_on_disabled_ethernet_interface(UNUSED void** state) {
    SKIP_OR_RUN
    amxc_var_t args;
    amxc_var_t ret;
    int counter = 0;

    amxc_var_init(&args);
    amxc_var_init(&ret);

    amxp_slot_connect(&dm.sigmngr, "Triggered", NULL, test_threshold_triggered, &counter);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(uint32_t, &args, "BytesReceived", 190);
    assert_int_equal(amxb_set(bus_ctx, "Ethernet.Interface.2.Stats", &args, &ret, 5), 0);

    handle_events();

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(uint32_t, &args, "BytesReceived", 210);
    assert_int_equal(amxb_set(bus_ctx, "Ethernet.Interface.2.Stats", &args, &ret, 5), 0);

    handle_events();

    assert_int_equal(counter, 0);

    amxp_slot_disconnect(&dm.sigmngr, "Triggered", test_threshold_triggered);

    amxc_var_clean(&args);
    amxc_var_clean(&ret);
}

void test_can_change_threshold_operator_to_fall(UNUSED void** state) {
    SKIP_OR_RUN
    amxd_object_t* threshold = amxd_dm_findf(&dm, "LocalAgent.Threshold.1");
    amxc_var_t args;
    amxc_var_t ret;
    amxc_var_t* params = NULL;

    assert_non_null(threshold);

    amxc_var_init(&args);
    amxc_var_init(&ret);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    params = amxc_var_add_key(amxc_htable_t, &args, "parameters", NULL);
    amxc_var_add_key(cstring_t, params, "ThresholdOperator", "Fall");
    assert_int_equal(amxd_object_invoke_function(threshold, "_set", &args, &ret), amxd_status_ok);

    handle_events();

    amxc_var_clean(&args);
    amxc_var_clean(&ret);
}

void test_can_get_fall_trigger_event(UNUSED void** state) {
    SKIP_OR_RUN
    amxc_var_t args;
    amxc_var_t ret;
    int counter = 0;

    amxc_var_init(&args);
    amxc_var_init(&ret);

    amxp_slot_connect(&dm.sigmngr, "Triggered", NULL, test_threshold_triggered, &counter);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(uint32_t, &args, "BytesReceived", 205);
    assert_int_equal(amxb_set(bus_ctx, "Ethernet.Interface.1.Stats", &args, &ret, 5), 0);

    handle_events();

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(uint32_t, &args, "BytesReceived", 190);
    assert_int_equal(amxb_set(bus_ctx, "Ethernet.Interface.1.Stats", &args, &ret, 5), 0);

    handle_events();

    assert_int_equal(counter, 1);

    amxp_slot_disconnect(&dm.sigmngr, "Triggered", test_threshold_triggered);

    amxc_var_clean(&args);
    amxc_var_clean(&ret);
}

void test_can_change_mode_to_single(UNUSED void** state) {
    SKIP_OR_RUN
    amxd_object_t* threshold = amxd_dm_findf(&dm, "LocalAgent.Threshold.1");
    amxc_var_t args;
    amxc_var_t ret;
    amxc_var_t* params = NULL;

    assert_non_null(threshold);

    amxc_var_init(&args);
    amxc_var_init(&ret);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    params = amxc_var_add_key(amxc_htable_t, &args, "parameters", NULL);
    amxc_var_add_key(cstring_t, params, "OperatingMode", "Single");
    assert_int_equal(amxd_object_invoke_function(threshold, "_set", &args, &ret), amxd_status_ok);

    handle_events();

    amxc_var_clean(&args);
    amxc_var_clean(&ret);
}

void test_can_change_threshold_operator_to_eq(UNUSED void** state) {
    SKIP_OR_RUN
    amxd_object_t* threshold = amxd_dm_findf(&dm, "LocalAgent.Threshold.1");
    amxc_var_t args;
    amxc_var_t ret;
    amxc_var_t* params = NULL;

    assert_non_null(threshold);

    amxc_var_init(&args);
    amxc_var_init(&ret);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    params = amxc_var_add_key(amxc_htable_t, &args, "parameters", NULL);
    amxc_var_add_key(cstring_t, params, "ThresholdOperator", "Eq");
    assert_int_equal(amxd_object_invoke_function(threshold, "_set", &args, &ret), amxd_status_ok);

    handle_events();

    amxc_var_clean(&args);
    amxc_var_clean(&ret);
}

void test_can_get_eq_trigger_event(UNUSED void** state) {
    SKIP_OR_RUN
    amxc_var_t args;
    amxc_var_t ret;
    int counter = 0;

    amxc_var_init(&args);
    amxc_var_init(&ret);

    amxp_slot_connect(&dm.sigmngr, "Triggered", NULL, test_threshold_triggered, &counter);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(uint32_t, &args, "BytesReceived", 195);
    assert_int_equal(amxb_set(bus_ctx, "Ethernet.Interface.1.Stats", &args, &ret, 5), 0);

    handle_events();

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(uint32_t, &args, "BytesReceived", 200);
    assert_int_equal(amxb_set(bus_ctx, "Ethernet.Interface.1.Stats", &args, &ret, 5), 0);

    handle_events();

    assert_int_equal(counter, 1);

    amxp_slot_disconnect(&dm.sigmngr, "Triggered", test_threshold_triggered);

    amxc_var_clean(&args);
    amxc_var_clean(&ret);
}

void test_threshold_is_disabled(UNUSED void** state) {
    SKIP_OR_RUN
    amxd_object_t* threshold = amxd_dm_findf(&dm, "%s", expected_threshold_instance);
    amxc_var_t ret;

    assert_non_null(threshold);

    amxc_var_init(&ret);

    assert_int_equal(amxd_object_get_param(threshold, "Enable", &ret), amxd_status_ok);
    assert_int_equal(amxc_var_type_of(&ret), AMXC_VAR_ID_BOOL);
    assert_false(amxc_var_constcast(bool, &ret));

    handle_events();

    amxc_var_clean(&ret);
}

void test_threshold_is_not_triggered_when_disabled(UNUSED void** state) {
    SKIP_OR_RUN
    amxc_var_t args;
    amxc_var_t ret;
    int counter = 0;

    amxc_var_init(&args);
    amxc_var_init(&ret);

    amxp_slot_connect(&dm.sigmngr, "Triggered", NULL, test_threshold_triggered, &counter);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(uint32_t, &args, "BytesReceived", 195);
    assert_int_equal(amxb_set(bus_ctx, "Ethernet.Interface.1.Stats", &args, &ret, 5), 0);

    handle_events();

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(uint32_t, &args, "BytesReceived", 200);
    assert_int_equal(amxb_set(bus_ctx, "Ethernet.Interface.1.Stats", &args, &ret, 5), 0);

    handle_events();

    assert_int_equal(counter, 0);

    amxp_slot_disconnect(&dm.sigmngr, "Triggered", test_threshold_triggered);

    amxc_var_clean(&args);
    amxc_var_clean(&ret);
}

void test_can_change_threshold_operator_to_noteq(UNUSED void** state) {
    SKIP_OR_RUN
    amxd_object_t* threshold = amxd_dm_findf(&dm, "LocalAgent.Threshold.1");
    amxc_var_t args;
    amxc_var_t ret;
    amxc_var_t* params = NULL;

    assert_non_null(threshold);

    amxc_var_init(&args);
    amxc_var_init(&ret);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    params = amxc_var_add_key(amxc_htable_t, &args, "parameters", NULL);
    amxc_var_add_key(cstring_t, params, "ThresholdOperator", "NotEq");
    assert_int_equal(amxd_object_invoke_function(threshold, "_set", &args, &ret), amxd_status_ok);

    handle_events();

    amxc_var_clean(&args);
    amxc_var_clean(&ret);
}

void test_can_change_mode_to_normal(UNUSED void** state) {
    SKIP_OR_RUN
    amxd_object_t* threshold = amxd_dm_findf(&dm, "LocalAgent.Threshold.1");
    amxc_var_t args;
    amxc_var_t ret;
    amxc_var_t* params = NULL;

    assert_non_null(threshold);

    amxc_var_init(&args);
    amxc_var_init(&ret);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    params = amxc_var_add_key(amxc_htable_t, &args, "parameters", NULL);
    amxc_var_add_key(cstring_t, params, "OperatingMode", "Normal");
    assert_int_equal(amxd_object_invoke_function(threshold, "_set", &args, &ret), amxd_status_ok);

    handle_events();

    amxc_var_clean(&args);
    amxc_var_clean(&ret);
}

void test_can_enable_threshold(UNUSED void** state) {
    SKIP_OR_RUN
    amxd_object_t* threshold = amxd_dm_findf(&dm, expected_threshold_instance);
    amxc_var_t args;
    amxc_var_t ret;
    amxc_var_t* params = NULL;

    assert_non_null(threshold);

    amxc_var_init(&args);
    amxc_var_init(&ret);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    params = amxc_var_add_key(amxc_htable_t, &args, "parameters", NULL);
    amxc_var_add_key(bool, params, "Enable", true);
    assert_int_equal(amxd_object_invoke_function(threshold, "_set", &args, &ret), amxd_status_ok);

    handle_events();

    amxc_var_clean(&args);
    amxc_var_clean(&ret);
}

void test_can_get_noteq_trigger_event(UNUSED void** state) {
    SKIP_OR_RUN
    amxc_var_t args;
    amxc_var_t ret;
    int counter = 0;

    amxc_var_init(&args);
    amxc_var_init(&ret);

    amxp_slot_connect(&dm.sigmngr, "Triggered", NULL, test_threshold_triggered, &counter);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(uint32_t, &args, "BytesReceived", 195);
    assert_int_equal(amxb_set(bus_ctx, "Ethernet.Interface.1.Stats", &args, &ret, 5), 0);

    handle_events();

    assert_int_equal(counter, 1);

    amxp_slot_disconnect(&dm.sigmngr, "Triggered", test_threshold_triggered);

    amxc_var_clean(&args);
    amxc_var_clean(&ret);
}

void test_can_delete_threshold_instance(UNUSED void** state) {
    SKIP_OR_RUN
    amxd_object_t* threshold = amxd_dm_findf(&dm, "LocalAgent.Threshold.");
    amxc_var_t args;
    amxc_var_t ret;

    assert_non_null(threshold);

    amxc_var_init(&args);
    amxc_var_init(&ret);
    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(uint32_t, &args, "index", 1);
    assert_int_equal(amxd_object_invoke_function(threshold, "_del", &args, &ret), amxd_status_ok);
    amxc_var_dump(&ret, STDOUT_FILENO);

    handle_events();

    amxc_var_clean(&args);
    amxc_var_clean(&ret);
}

void test_can_create_another_threshold_instance(UNUSED void** state) {
    SKIP_OR_RUN
    amxd_object_t* threshold = amxd_dm_findf(&dm, "LocalAgent.Threshold.");
    amxc_var_t args;
    amxc_var_t ret;
    amxc_var_t* params = NULL;

    assert_non_null(threshold);

    amxc_var_init(&args);
    amxc_var_init(&ret);
    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    params = amxc_var_add_key(amxc_htable_t, &args, "parameters", NULL);
    amxc_var_add_key(cstring_t, params, "ReferencePath", "Ethernet.Interface.[Enable == true].");
    amxc_var_add_key(cstring_t, params, "ThresholdParam", "DuplexMode");
    amxc_var_add_key(cstring_t, params, "ThresholdValue", "Full");
    assert_int_equal(amxd_object_invoke_function(threshold, "_add", &args, &ret), amxd_status_ok);
    amxc_var_dump(&ret, STDOUT_FILENO);
    assert_false(amxc_var_is_null(&ret));

    handle_events();

    expected_threshold_instance = "LocalAgent.Threshold.2.";
    amxc_var_clean(&args);
    amxc_var_clean(&ret);
}

void test_can_get_string_based_rise_trigger_event(UNUSED void** state) {
    SKIP_OR_RUN
    amxc_var_t args;
    amxc_var_t ret;
    int counter = 0;

    amxc_var_init(&args);
    amxc_var_init(&ret);

    amxp_slot_connect(&dm.sigmngr, "Triggered", NULL, test_threshold_triggered, &counter);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &args, "DuplexMode", "Auto");
    assert_int_equal(amxb_set(bus_ctx, "Ethernet.Interface.1.", &args, &ret, 5), 0);

    handle_events();

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &args, "DuplexMode", "Half");
    assert_int_equal(amxb_set(bus_ctx, "Ethernet.Interface.1.", &args, &ret, 5), 0);

    handle_events();

    assert_int_equal(counter, 1);

    amxp_slot_disconnect(&dm.sigmngr, "Triggered", test_threshold_triggered);

    amxc_var_clean(&args);
    amxc_var_clean(&ret);
}

void test_can_get_string_based_fall_trigger_event(UNUSED void** state) {
    SKIP_OR_RUN
    amxd_object_t* threshold = amxd_dm_findf(&dm, "LocalAgent.Threshold.2.");
    amxc_var_t args;
    amxc_var_t ret;
    amxc_var_t* params = NULL;
    int counter = 0;

    amxc_var_init(&args);
    amxc_var_init(&ret);

    assert_non_null(threshold);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    params = amxc_var_add_key(amxc_htable_t, &args, "parameters", NULL);
    amxc_var_add_key(cstring_t, params, "ThresholdOperator", "Fall");
    assert_int_equal(amxd_object_invoke_function(threshold, "_set", &args, &ret), amxd_status_ok);

    handle_events();

    amxp_slot_connect(&dm.sigmngr, "Triggered", NULL, test_threshold_triggered, &counter);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &args, "DuplexMode", "Auto");
    assert_int_equal(amxb_set(bus_ctx, "Ethernet.Interface.1.", &args, &ret, 5), 0);

    handle_events();

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &args, "DuplexMode", "Half");
    assert_int_equal(amxb_set(bus_ctx, "Ethernet.Interface.1.", &args, &ret, 5), 0);

    handle_events();

    assert_int_equal(counter, 1);

    amxp_slot_disconnect(&dm.sigmngr, "Triggered", test_threshold_triggered);

    amxc_var_clean(&args);
    amxc_var_clean(&ret);
}

void test_can_not_change_threshold_operator_to_cross(UNUSED void** state) {
    SKIP_OR_RUN
    amxd_object_t* threshold = amxd_dm_findf(&dm, "LocalAgent.Threshold.2");
    amxc_var_t args;
    amxc_var_t ret;
    amxc_var_t* params = NULL;

    assert_non_null(threshold);

    amxc_var_init(&args);
    amxc_var_init(&ret);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    params = amxc_var_add_key(amxc_htable_t, &args, "parameters", NULL);
    amxc_var_add_key(cstring_t, params, "ThresholdOperator", "Cross");
    assert_int_not_equal(amxd_object_invoke_function(threshold, "_set", &args, &ret), amxd_status_ok);

    handle_events();

    amxc_var_clean(&args);
    amxc_var_clean(&ret);
}

void test_change_supported_threshold_operators(UNUSED void** state) {
    SKIP_OR_RUN
    amxd_object_t* threshold = amxd_dm_findf(&dm, "LocalAgent.");

    assert_non_null(threshold);

    assert_int_equal(amxd_object_set_value(csv_string_t, threshold, "SupportedThresholdOperator", "Rise,Fall,Cross,Eq,NotEq,Custom"), amxd_status_ok);
}

void test_can_change_threshold_operator_to_cross(UNUSED void** state) {
    SKIP_OR_RUN
    amxd_object_t* threshold = amxd_dm_findf(&dm, "LocalAgent.Threshold.2");
    amxc_var_t args;
    amxc_var_t ret;
    amxc_var_t* params = NULL;

    assert_non_null(threshold);

    amxc_var_init(&args);
    amxc_var_init(&ret);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    params = amxc_var_add_key(amxc_htable_t, &args, "parameters", NULL);
    amxc_var_add_key(cstring_t, params, "ThresholdOperator", "Cross");
    assert_int_equal(amxd_object_invoke_function(threshold, "_set", &args, &ret), amxd_status_ok);

    handle_events();

    amxc_var_clean(&args);
    amxc_var_clean(&ret);
}

void test_can_change_threshold_operator_to_custom(UNUSED void** state) {
    SKIP_OR_RUN
    amxd_object_t* threshold = amxd_dm_findf(&dm, "LocalAgent.Threshold.2");
    amxc_var_t args;
    amxc_var_t ret;
    amxc_var_t* params = NULL;

    assert_non_null(threshold);

    amxc_var_init(&args);
    amxc_var_init(&ret);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    params = amxc_var_add_key(amxc_htable_t, &args, "parameters", NULL);
    amxc_var_add_key(bool, params, "Enable", true);
    amxc_var_add_key(cstring_t, params, "ThresholdOperator", "Custom");
    assert_int_equal(amxd_object_invoke_function(threshold, "_set", &args, &ret), amxd_status_ok);

    handle_events();

    amxc_var_clean(&args);
    amxc_var_clean(&ret);
}