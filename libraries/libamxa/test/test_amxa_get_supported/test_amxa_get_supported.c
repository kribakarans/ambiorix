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
#include <amxc/amxc_macros.h>
#include <amxp/amxp.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_dm.h>
#include <amxo/amxo.h>

#include "amxa/amxa_validator.h"
#include "amxa/amxa_merger.h"

#include "test_amxa_get_supported.h"

static amxo_parser_t parser;
static const char* odl_root = "../reference-dm/dhcpv4_root.odl";
static amxd_dm_t dm;

static void handle_events(void) {
    printf("Handling events ");
    while(amxp_signal_read() == 0) {
        printf(".");
    }
    printf("\n");
}

static amxc_var_t* test_invoke_get_supported(bool functions,
                                             bool parameters,
                                             bool events,
                                             bool first_level) {
    amxc_var_t* ret = NULL;
    amxc_var_t* response = NULL;
    amxd_object_t* dhcpv4 = NULL;
    amxc_var_t args;

    amxc_var_init(&args);
    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);

    amxc_var_new(&response);
    amxc_var_set_type(response, AMXC_VAR_ID_LIST);
    ret = amxc_var_add(amxc_htable_t, response, NULL);

    dhcpv4 = amxd_dm_findf(&dm, "DHCPv4.");
    assert_non_null(dhcpv4);

    amxc_var_add_key(bool, &args, "functions", functions);
    amxc_var_add_key(bool, &args, "parameters", parameters);
    amxc_var_add_key(bool, &args, "events", events);
    amxc_var_add_key(bool, &args, "first_level_only", first_level);
    amxc_var_add_key(bool, &args, "access", AMXB_PUBLIC);
    assert_int_equal(amxd_object_invoke_function(dhcpv4, "_get_supported", &args, ret), 0);

    amxc_var_clean(&args);
    return response;
}

int test_dm_setup(UNUSED void** state) {
    amxd_object_t* root_obj = NULL;

    amxd_dm_init(&dm);

    assert_int_equal(amxo_parser_init(&parser), 0);

    root_obj = amxd_dm_get_root(&dm);
    assert_non_null(root_obj);

    assert_int_equal(amxo_parser_parse_file(&parser, odl_root, root_obj), 0);

    handle_events();

    return 0;
}

int test_dm_teardown(UNUSED void** state) {
    amxo_parser_clean(&parser);
    amxd_dm_clean(&dm);
    return 0;
}

void test_amxa_filter_get_supported_resp(UNUSED void** state) {
    amxc_var_t* response = NULL;
    amxc_var_t* first = NULL;
    bool functions = true;
    bool parameters = true;
    bool events = true;
    bool first_level = false;
    const char* requested_path = "DHCPv4.";
    amxc_var_t* acl_rules = amxa_parse_files("../examples/10_merged.json");

    assert_non_null(acl_rules);

    response = test_invoke_get_supported(functions, parameters, events, first_level);
    assert_int_equal(amxa_filter_get_supported_resp(requested_path, response, acl_rules), 0);
    amxc_var_dump(response, STDOUT_FILENO);

    first = GETI_ARG(response, 0);
    assert_non_null(first);
    assert_non_null(GETP_ARG(first, "'DHCPv4.'"));
    assert_non_null(GETP_ARG(first, "'DHCPv4.'.supported_commands"));
    assert_non_null(GETP_ARG(first, "'DHCPv4.'.supported_params"));
    assert_non_null(GETP_ARG(first, "'DHCPv4.'.is_multi_instance"));

    assert_non_null(GETP_ARG(first, "'DHCPv4.Client.{i}.'"));
    assert_non_null(GETP_ARG(first, "'DHCPv4.Client.{i}.DummyOne.'"));
    assert_non_null(GETP_ARG(first, "'DHCPv4.Client.{i}.DummyOne.DummyTwo.'"));
    assert_non_null(GETP_ARG(first, "'DHCPv4.Client.{i}.DummyOne.DummyTwo.DummyInst.{i}.'"));
    assert_null(GETP_ARG(first, "'DHCPv4.Client.{i}.'.supported_commands"));
    assert_null(GETP_ARG(first, "'DHCPv4.Client.{i}.DummyOne.'.supported_commands"));
    assert_null(GETP_ARG(first, "'DHCPv4.Client.{i}.DummyOne.DummyTwo.'.supported_commands"));
    assert_null(GETP_ARG(first, "'DHCPv4.Client.{i}.DummyOne.DummyTwo.DummyInst.{i}.'.supported_commands"));
    assert_null(GETP_ARG(first, "'DHCPv4.Client.{i}.'.supported_events"));
    assert_null(GETP_ARG(first, "'DHCPv4.Client.{i}.DummyOne.'.supported_events"));
    assert_null(GETP_ARG(first, "'DHCPv4.Client.{i}.DummyOne.DummyTwo.'.supported_events"));
    assert_null(GETP_ARG(first, "'DHCPv4.Client.{i}.DummyOne.DummyTwo.DummyInst.{i}.'.supported_events"));

    assert_non_null(GETP_ARG(first, "'DHCPv4.Server.'"));
    assert_non_null(GETP_ARG(first, "'DHCPv4.Server.Pool.{i}.'"));
    assert_non_null(GETP_ARG(first, "'DHCPv4.Server.Pool.{i}.Client.{i}.'"));
    assert_non_null(GETP_ARG(first, "'DHCPv4.Server.Pool.{i}.Client.{i}.IPv4Address.{i}.'"));
    assert_non_null(GETP_ARG(first, "'DHCPv4.Server.Pool.{i}.Client.{i}.Option.{i}.'"));
    assert_non_null(GETP_ARG(first, "'DHCPv4.Server.Pool.{i}.Option.{i}.'"));
    assert_non_null(GETP_ARG(first, "'DHCPv4.Server.Pool.{i}.StaticAddress.{i}.'"));
    assert_null(GETP_ARG(first, "'DHCPv4.Server.'.supported_params"));
    assert_null(GETP_ARG(first, "'DHCPv4.Server.Pool.{i}.'.supported_params"));
    assert_null(GETP_ARG(first, "'DHCPv4.Server.Pool.{i}.Client.{i}.'.supported_params"));
    assert_null(GETP_ARG(first, "'DHCPv4.Server.Pool.{i}.Client.{i}.IPv4Address.{i}.'.supported_params"));
    assert_null(GETP_ARG(first, "'DHCPv4.Server.Pool.{i}.Client.{i}.Option.{i}.'.supported_params"));
    assert_null(GETP_ARG(first, "'DHCPv4.Server.Pool.{i}.Option.{i}.'.supported_params"));
    assert_null(GETP_ARG(first, "'DHCPv4.Server.Pool.{i}.StaticAddress.{i}.'.supported_params"));

    assert_non_null(GETP_ARG(first, "'DHCPv4.Relay.'"));
    assert_non_null(GETP_ARG(first, "'DHCPv4.Relay.Forwarding.{i}.'"));
    assert_null(GETP_ARG(first, "'DHCPv4.Relay.'.access"));
    assert_null(GETP_ARG(first, "'DHCPv4.Relay.Forwarding.{i}.'.access"));
    assert_null(GETP_ARG(first, "'DHCPv4.Relay.'.is_multi_instance"));
    assert_null(GETP_ARG(first, "'DHCPv4.Relay.Forwarding.{i}.'.is_multi_instance"));

    amxc_var_delete(&acl_rules);
    amxc_var_delete(&response);
}

void test_amxa_filter_get_supported_resp_invalid(UNUSED void** state) {
    const char* requested_path = "DHCPv4.";
    amxc_var_t* response = NULL;
    amxc_var_t* acl_rules = amxa_parse_files("../examples/10_merged.json");
    bool functions = true;
    bool parameters = true;
    bool events = true;
    bool first_level = false;

    response = test_invoke_get_supported(functions, parameters, events, first_level);

    assert_int_equal(amxa_filter_get_supported_resp(NULL, response, acl_rules), -1);
    assert_int_equal(amxa_filter_get_supported_resp("", response, acl_rules), -1);
    assert_int_equal(amxa_filter_get_supported_resp(requested_path, NULL, acl_rules), -1);
    assert_int_equal(amxa_filter_get_supported_resp(requested_path, response, NULL), -1);

    amxc_var_delete(&acl_rules);
    amxc_var_delete(&response);
}
