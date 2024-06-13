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
#include <setjmp.h>
#include <stdarg.h>
#include <cmocka.h>

#include <amxc/amxc.h>
#include <amxp/amxp.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_dm.h>
#include <amxo/amxo.h>

#include "amxa/amxa_permissions.h"
#include "amxa/amxa_validator.h"
#include "amxa/amxa_merger.h"
#include "amxa_merger_priv.h"
#include "amxa/amxa_get.h"

#include "test_amxa_get.h"

#include "dummy_backend.h"
#include "test_amxa_common.h"

#define UNUSED __attribute__((unused))

static const char* acl_file = "set_rules_merged.json";

static amxc_var_t* test_invoke_get(void) {
    amxd_dm_t* dm = test_amxa_get_dm();
    amxc_var_t* ret = NULL;
    amxc_var_t* get_resp = NULL;
    amxd_object_t* dhcpv4 = NULL;
    amxc_var_t args;

    amxc_var_init(&args);
    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);

    amxc_var_new(&get_resp);
    amxc_var_set_type(get_resp, AMXC_VAR_ID_LIST);
    ret = amxc_var_add(amxc_htable_t, get_resp, NULL);

    dhcpv4 = amxd_dm_findf(dm, "DHCPv4.");
    assert_non_null(dhcpv4);
    amxc_var_add_key(int32_t, &args, "depth", INT32_MAX);
    assert_int_equal(amxd_object_invoke_function(dhcpv4, "_get", &args, ret), 0);

    amxc_var_clean(&args);
    return get_resp;
}

int test_amxa_get_setup(UNUSED void** state) {
    amxc_var_t* data = NULL;

    test_amxa_setup(NULL);

    data = data_from_json("set_rules.json");
    assert_int_equal(amxa_merge_rules(data, acl_file), 0);
    amxc_var_delete(&data);
    return 0;
}

int test_amxa_get_teardown(UNUSED void** state) {
    return test_amxa_teardown(NULL);
}

void test_amxa_filter_get_resp_invalid(UNUSED void** state) {
    amxc_var_t get_resp;
    amxc_llist_t filters;

    amxc_var_init(&get_resp);
    assert_int_equal(amxa_filter_get_resp(NULL, &filters), -1);
    assert_int_equal(amxa_filter_get_resp(&get_resp, NULL), -1);
    assert_int_equal(amxa_filter_get_resp(&get_resp, &filters), -1);

    amxc_var_clean(&get_resp);
}

void test_amxa_filter_get_resp_full(UNUSED void** state) {
    amxc_llist_t filters;
    amxc_string_t new_filter;
    amxc_var_t* get_resp = NULL;
    amxc_var_t* first = NULL;

    amxc_llist_init(&filters);

    get_resp = test_invoke_get();
    assert_int_equal(amxa_filter_get_resp(get_resp, &filters), 0);

    amxc_string_init(&new_filter, 0);
    amxc_string_setf(&new_filter, "DHCPv4.");
    amxc_llist_append(&filters, &new_filter.it);

    assert_int_equal(amxa_filter_get_resp(get_resp, &filters), 0);
    first = GETI_ARG(get_resp, 0);
    assert_non_null(first);
    assert_null(GET_ARG(first, "DHCPv4."));
    assert_null(GET_ARG(first, "DHCPv4.Client.1."));
    assert_null(GET_ARG(first, "DHCPv4.Client.2."));
    assert_null(GET_ARG(first, "DHCPv4.Client.3."));
    assert_null(GET_ARG(first, "DHCPv4.Relay."));
    assert_null(GET_ARG(first, "DHCPv4.Server."));
    assert_null(GET_ARG(first, "DHCPv4.Server.Pool.1."));
    assert_null(GET_ARG(first, "DHCPv4.Server.Pool.1.Client.1."));
    assert_null(GET_ARG(first, "DHCPv4.Server.Pool.1.Client.1.IPv4Address.1."));
    assert_null(GET_ARG(first, "DHCPv4.Server.Pool.1.Client.1.IPv4Address.2."));

    amxc_var_delete(&get_resp);
    amxc_string_clean(&new_filter);
    amxc_llist_clean(&filters, NULL);
}

void test_amxa_filter_get_resp_instances(UNUSED void** state) {
    amxc_llist_t filters;
    amxc_string_t* new_filter = NULL;
    amxc_var_t* get_resp = NULL;
    amxc_var_t* first = NULL;

    amxc_llist_init(&filters);
    amxc_string_new(&new_filter, 0);
    amxc_string_setf(new_filter, "DHCPv4.Client.1");
    amxc_llist_append(&filters, &new_filter->it);
    amxc_string_new(&new_filter, 0);
    amxc_string_setf(new_filter, "DHCPv4.Client.2");
    amxc_llist_append(&filters, &new_filter->it);
    amxc_string_new(&new_filter, 0);
    amxc_string_setf(new_filter, "DHCPv4.Server.Pool.1.Client.1.IPv4Address.2");
    amxc_llist_append(&filters, &new_filter->it);

    get_resp = test_invoke_get();
    assert_int_equal(amxa_filter_get_resp(get_resp, &filters), 0);
    amxc_var_dump(get_resp, STDOUT_FILENO);
    first = GETI_ARG(get_resp, 0);
    assert_non_null(first);
    assert_non_null(GET_ARG(first, "DHCPv4."));
    assert_null(GET_ARG(first, "DHCPv4.Client.1."));
    assert_null(GET_ARG(first, "DHCPv4.Client.2."));
    assert_non_null(GET_ARG(first, "DHCPv4.Client.3."));
    assert_non_null(GET_ARG(first, "DHCPv4.Relay."));
    assert_non_null(GET_ARG(first, "DHCPv4.Server."));
    assert_non_null(GET_ARG(first, "DHCPv4.Server.Pool.1."));
    assert_non_null(GET_ARG(first, "DHCPv4.Server.Pool.1.Client.1."));
    assert_non_null(GET_ARG(first, "DHCPv4.Server.Pool.1.Client.1.IPv4Address.1."));
    assert_null(GET_ARG(first, "DHCPv4.Server.Pool.1.Client.1.IPv4Address.2."));

    amxc_var_delete(&get_resp);
    amxc_llist_clean(&filters, amxc_string_list_it_free);
}

void test_amxa_filter_get_resp_params(UNUSED void** state) {
    amxc_llist_t filters;
    amxc_string_t* new_filter = NULL;
    amxc_var_t* get_resp = NULL;
    amxc_var_t* first = NULL;

    amxc_llist_init(&filters);
    amxc_string_new(&new_filter, 0);
    amxc_string_setf(new_filter, "DHCPv4.Client.1.Enable");
    amxc_llist_append(&filters, &new_filter->it);
    amxc_string_new(&new_filter, 0);
    amxc_string_setf(new_filter, "DHCPv4.Client.1.IPAddress");
    amxc_llist_append(&filters, &new_filter->it);
    amxc_string_new(&new_filter, 0);
    amxc_string_setf(new_filter, "DHCPv4.Server.Pool.1.Client.1.IPv4Address.2.IPAddress");
    amxc_llist_append(&filters, &new_filter->it);

    get_resp = test_invoke_get();
    assert_int_equal(amxa_filter_get_resp(get_resp, &filters), 0);
    first = GETI_ARG(get_resp, 0);
    amxc_var_dump(first, STDOUT_FILENO);
    assert_non_null(first);
    assert_non_null(GET_ARG(first, "DHCPv4."));
    assert_non_null(GET_ARG(first, "DHCPv4.Client.1."));
    assert_non_null(GET_ARG(first, "DHCPv4.Client.2."));
    assert_non_null(GET_ARG(first, "DHCPv4.Client.3."));
    assert_non_null(GET_ARG(first, "DHCPv4.Relay."));
    assert_non_null(GET_ARG(first, "DHCPv4.Server."));
    assert_non_null(GET_ARG(first, "DHCPv4.Server.Pool.1."));
    assert_non_null(GET_ARG(first, "DHCPv4.Server.Pool.1.Client.1."));
    assert_non_null(GET_ARG(first, "DHCPv4.Server.Pool.1.Client.1.IPv4Address.1."));
    assert_non_null(GET_ARG(first, "DHCPv4.Server.Pool.1.Client.1.IPv4Address.2."));

    assert_null(GETP_ARG(first, "'DHCPv4.Client.1.'.Enable"));
    assert_non_null(GETP_ARG(first, "'DHCPv4.Client.2.'.Enable"));
    assert_null(GETP_ARG(first, "'DHCPv4.Client.1.'.IPAddress"));
    assert_non_null(GETP_ARG(first, "'DHCPv4.Client.2.'.IPAddress"));
    assert_null(GETP_ARG(first, "'DHCPv4.Server.Pool.1.Client.1.IPv4Address.2.'.IPAddress"));
    assert_non_null(GETP_ARG(first, "'DHCPv4.Server.Pool.1.Client.1.IPv4Address.1.'.IPAddress"));

    amxc_var_delete(&get_resp);
    amxc_llist_clean(&filters, amxc_string_list_it_free);
}

// Test that if all parameters are filtered from a get response, the object is also removed from the
// response
void test_amxa_filter_get_resp_params_all(UNUSED void** state) {
    amxd_dm_t* dm = test_amxa_get_dm();
    amxc_var_t* ret = NULL;
    amxc_var_t* get_resp = NULL;
    amxd_object_t* target_object = NULL;
    amxc_var_t args;
    amxc_llist_t filters;
    amxc_string_t* new_filter = NULL;

    amxc_llist_init(&filters);
    amxc_string_new(&new_filter, 0);
    amxc_string_setf(new_filter, "DHCPv4.Server.Pool.1.Client.1.IPv4Address.2.IPAddress");
    amxc_llist_append(&filters, &new_filter->it);
    amxc_string_new(&new_filter, 0);
    amxc_string_setf(new_filter, "DHCPv4.Server.Pool.1.Client.1.IPv4Address.2.LeaseTimeRemaining");
    amxc_llist_append(&filters, &new_filter->it);

    amxc_var_init(&args);
    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);

    amxc_var_new(&get_resp);
    amxc_var_set_type(get_resp, AMXC_VAR_ID_LIST);
    ret = amxc_var_add(amxc_htable_t, get_resp, NULL);

    target_object = amxd_dm_findf(dm, "DHCPv4.Server.Pool.1.Client.1.IPv4Address.2.");
    assert_non_null(target_object);
    amxc_var_add_key(int32_t, &args, "depth", INT32_MAX);
    assert_int_equal(amxd_object_invoke_function(target_object, "_get", &args, ret), 0);
    amxc_var_dump(ret, 1);

    assert_int_equal(amxa_filter_get_resp(get_resp, &filters), 0);
    amxc_var_dump(get_resp, 1);

    amxc_var_clean(&args);
    amxc_var_delete(&get_resp);
    amxc_llist_clean(&filters, amxc_string_list_it_free);
}

void test_amxa_get_is_allowed(UNUSED void** state) {
    amxc_llist_t filters;
    amxc_string_t* new_filter = NULL;
    const char* requested_path = "DHCPv4.";

    amxc_llist_init(&filters);

    // Empty filter list
    assert_true(amxa_is_get_allowed(&filters, requested_path));

    amxc_string_new(&new_filter, 0);
    amxc_string_setf(new_filter, "DHCPv4.Client.1.Enable");
    amxc_llist_append(&filters, &new_filter->it);

    // Only need to filter child objects/params
    assert_true(amxa_is_get_allowed(&filters, requested_path));

    amxc_llist_clean(&filters, amxc_string_list_it_free);
}

void test_amxa_get_is_not_allowed(UNUSED void** state) {
    amxc_llist_t filters;
    amxc_string_t* new_filter = NULL;
    const char* requested_path = "DHCPv4.";

    amxc_llist_init(&filters);

    assert_false(amxa_is_get_allowed(NULL, requested_path));
    assert_false(amxa_is_get_allowed(&filters, NULL));
    assert_false(amxa_is_get_allowed(&filters, ""));

    amxc_string_new(&new_filter, 0);
    amxc_string_setf(new_filter, "DHCPv4");
    amxc_llist_append(&filters, &new_filter->it);

    assert_false(amxa_is_get_allowed(&filters, requested_path));

    requested_path = "DHCPv4.Client.";
    assert_false(amxa_is_get_allowed(&filters, requested_path));

    amxc_llist_clean(&filters, amxc_string_list_it_free);
}

void test_amxa_get(UNUSED void** state) {
    amxb_bus_ctx_t* bus_ctx = test_amxa_get_bus_ctx();
    amxc_var_t result;
    amxc_var_init(&result);
    amxb_get(bus_ctx, "DHCPv4.", -1, &result, 5);
    // Check that the SentOption object is reachable with amxb_get
    assert_int_not_equal(GETP_ARG(&result, "0.'DHCPv4.Client.4.SentOption.1.'.Alias"), 0);
    amxa_get(bus_ctx, "DHCPv4.", "set_rules_merged.json", -1, &result, 5);
    // Checks that the SentOption object is unreachable with amxa_get
    assert_int_equal(GETP_ARG(&result, "0.'DHCPv4.Client.4.SentOption.1.'.Alias"), 0);
    assert_int_equal(GETP_UINT32(&result, "0.'DHCPv4.'.ClientNumberOfEntries"), 5);
    assert_string_equal(GETP_CHAR(&result, "0.'DHCPv4.Client.4.'.Alias"), "test-client-1");
    amxa_get(bus_ctx, "DHCPv4.Client.[Alias == 'test-client-1'].", "set_rules_merged.json", -1, &result, 5);
    //Check that client 1 can be found
    assert_string_equal(GETP_CHAR(&result, "0.'DHCPv4.Client.4.'.Alias"), "test-client-1");
    // Check that client2 is missing
    assert_int_equal(GETP_ARG(&result, "0.'DHCPv4.Client.5.'.Alias"), 0);
    // Check that wildcard only reply the allowed object
    amxa_get(bus_ctx, "DHCPv4.Server.Pool.*.Client.*.IPv4Address.*.", "set_rules_merged.json", -1, &result, 5);
    assert_int_equal(amxc_llist_size(amxc_var_constcast(amxc_llist_t, &result)), 1);
    assert_string_equal(GETP_CHAR(&result, "0.'DHCPv4.Server.Pool.1.Client.1.IPv4Address.1.'.IPAddress"), "123.456.789.0");
    amxc_var_clean(&result);
}

void test_amxa_is_get_param_allowed(UNUSED void** state) {
    amxc_llist_t filters;
    amxc_string_t new_filter;
    const char* object = "DHCPv4.Client.1.";
    const char* param_allowed = "Enable";
    const char* param_forbidden = "Password";

    amxc_llist_init(&filters);
    amxc_string_init(&new_filter, 0);
    amxc_string_setf(&new_filter, "%s%s", object, param_forbidden);
    amxc_llist_append(&filters, &new_filter.it);

    assert_false(amxa_is_get_param_allowed(NULL, NULL, NULL));
    assert_false(amxa_is_get_param_allowed("", NULL, NULL));
    assert_false(amxa_is_get_param_allowed(object, NULL, NULL));
    assert_false(amxa_is_get_param_allowed(object, "", NULL));
    assert_false(amxa_is_get_param_allowed(object, param_forbidden, NULL));
    assert_false(amxa_is_get_param_allowed(object, param_forbidden, &filters));
    assert_true(amxa_is_get_param_allowed(object, param_allowed, &filters));

    amxc_string_clean(&new_filter);
    amxc_llist_clean(&filters, NULL);
}

void test_dont_filter_resp_without_params(UNUSED void** state) {
    amxd_dm_t* dm = test_amxa_get_dm();
    amxc_var_t* acls = amxa_parse_files("./phonebook_rules.json");
    const char* requested_path = "Phonebook.";
    amxc_llist_t filters;
    amxc_var_t get_resp;
    amxc_var_t args;
    amxc_var_t* ret = NULL;
    amxd_object_t* phonebook = NULL;

    amxc_llist_init(&filters);
    amxc_var_init(&get_resp);
    amxc_var_set_type(&get_resp, AMXC_VAR_ID_LIST);
    amxc_var_init(&args);
    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);

    // First assume get is not allowed on object path
    // If get is not allowed, it must not be invoked, so we won't end up with a
    // return variant without parameters
    amxa_get_filters(acls, AMXA_PERMIT_GET, &filters, requested_path);
    assert_false(amxa_is_get_allowed(&filters, requested_path));

    // Now assume get is allowed and depth is set to 0
    amxc_llist_clean(&filters, amxc_string_list_it_free);
    amxc_llist_init(&filters); // filters are empty

    phonebook = amxd_dm_findf(dm, "Phonebook.");
    assert_non_null(phonebook);
    amxc_var_add_key(int32_t, &args, "depth", 0);
    ret = amxc_var_add(amxc_htable_t, &get_resp, NULL);
    assert_int_equal(amxd_object_invoke_function(phonebook, "_get", &args, ret), 0);
    amxc_var_dump(ret, STDOUT_FILENO);

    assert_int_equal(amxa_filter_get_resp(&get_resp, &filters), 0);
    amxc_var_dump(ret, STDOUT_FILENO);
    assert_non_null(GETP_ARG(ret, "'Phonebook.'"));

    amxc_var_clean(&args);
    amxc_var_clean(&get_resp);
    amxc_var_delete(&acls);
    amxc_llist_clean(&filters, NULL);
}
