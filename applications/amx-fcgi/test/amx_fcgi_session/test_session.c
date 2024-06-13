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
#include <sys/signalfd.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>

#include <stdlib.h>
#include <stdio.h>
#include <setjmp.h>
#include <stdarg.h>
#include <cmocka.h>
#include <string.h>

#include "amx_fcgi.h"

#include <amxb/amxb_register.h>

#include "../mocks/fcgx_mock.h"
#include "../mocks/dummy_be.h"
#include "../mocks/test_common.h"

#include "test_session.h"

static amxo_parser_t parser;
static amxd_dm_t dm;
static amxb_bus_ctx_t* bus_ctx = NULL;

int test_amx_fcgi_setup(UNUSED void** state) {
    amxd_object_t* root_obj = NULL;
    const char* socket = NULL;

    block_sigalrm();

    amxo_parser_init(&parser);
    amxd_dm_init(&dm);

    root_obj = amxd_dm_get_root(&dm);
    amxo_parser_parse_file(&parser, "../mocks/test.odl", root_obj);

    assert_int_equal(test_register_dummy_be(), 0);
    assert_int_equal(amxb_connect(&bus_ctx, "dummy:/tmp/dummy.sock"), 0);
    amxb_register(bus_ctx, &dm);
    amxb_set_access(bus_ctx, amxd_dm_access_public);

    handle_events();

    assert_int_equal(test_load_dummy_remote("../test_data/odl/greeter_definition.odl"), 0);
    assert_int_equal(test_load_dummy_remote("../test_data/odl/userinterface.odl"), 0);
    assert_int_equal(test_load_dummy_remote("../test_data/odl/users.odl"), 0);

    socket = GETP_CHAR(&parser.config, "fcgi-socket");
    expect_string(__wrap_FCGX_OpenSocket, path, socket);
    expect_value(__wrap_FCGX_OpenSocket, backlog, 10);
    will_return(__wrap_FCGX_OpenSocket, 6);
    will_return(__wrap_FCGX_Init, 0);

    assert_int_equal(_amx_fcgi_main(AMXO_START, &dm, &parser), 0);

    return 0;
}

int test_amx_fcgi_setup_httpaccess(UNUSED void** state) {
    amxd_object_t* root_obj = NULL;
    const char* socket = NULL;
    amxc_var_t* ctrl = NULL;

    block_sigalrm();

    amxo_parser_init(&parser);
    amxd_dm_init(&dm);

    root_obj = amxd_dm_get_root(&dm);
    amxo_parser_parse_file(&parser, "../mocks/test.odl", root_obj);

    ctrl = GET_ARG(&parser.config, "session-ctrl");
    amxc_var_delete(&ctrl);

    assert_int_equal(test_register_dummy_be(), 0);
    assert_int_equal(amxb_connect(&bus_ctx, "dummy:/tmp/dummy.sock"), 0);
    amxb_register(bus_ctx, &dm);
    amxb_set_access(bus_ctx, amxd_dm_access_public);

    handle_events();

    assert_int_equal(test_load_dummy_remote("../test_data/odl/greeter_definition.odl"), 0);
    assert_int_equal(test_load_dummy_remote("../test_data/odl/userinterface.odl"), 0);
    assert_int_equal(test_load_dummy_remote("../test_data/odl/users.odl"), 0);

    socket = GETP_CHAR(&parser.config, "fcgi-socket");
    expect_string(__wrap_FCGX_OpenSocket, path, socket);
    expect_value(__wrap_FCGX_OpenSocket, backlog, 10);
    will_return(__wrap_FCGX_OpenSocket, 6);
    will_return(__wrap_FCGX_Init, 0);

    assert_int_equal(_amx_fcgi_main(AMXO_START, &dm, &parser), 0);

    return 0;
}

int test_amx_fcgi_teardown(UNUSED void** state) {
    assert_int_equal(_amx_fcgi_main(AMXO_STOP, &dm, &parser), 0);

    amxo_parser_clean(&parser);
    amxd_dm_clean(&dm);

    test_unregister_dummy_be();
    test_clean_response();

    bus_ctx = NULL;

    return 0;
}

void test_get_session_id_from_req(UNUSED void** state) {
    amx_fcgi_request_t req = {0};
    amxc_var_set_type(&req.roles, AMXC_VAR_ID_LIST);

    will_return(__wrap_FCGX_GetParam, "bearer J86mD3vA8hjFblCBaJUyggmcFXCbGr9RAeptigBVSRZXi7cDPOoZRsARgnkR1UwH");
    assert_string_equal(amx_fcgi_get_session_id(&req), "J86mD3vA8hjFblCBaJUyggmcFXCbGr9RAeptigBVSRZXi7cDPOoZRsARgnkR1UwH");
    will_return(__wrap_FCGX_GetParam, "bearer ");
    assert_null(amx_fcgi_get_session_id(&req));
    will_return(__wrap_FCGX_GetParam, "bearer J86mD3vA8hjFblCBaJUyggmcFXCbGr9RAeptigBVSRZXi7cDPOoZRsARgnkR1U");
    assert_null(amx_fcgi_get_session_id(&req));
}

void test_http_login(UNUSED void** state) {
    amx_fcgi_request_t req = {0};
    amxc_var_t data;
    amxc_var_set_type(&req.roles, AMXC_VAR_ID_LIST);

    amxc_var_init(&data);

    // Wrong credentials
    amxc_var_set(jstring_t, &data, "{\"username\":\"admin\",\"password\":\"nimda\"}");
    assert_int_equal(amxc_var_cast(&data, AMXC_VAR_ID_ANY), 0);
    will_return(__wrap_FCGX_GetParam, "UserInterface.HTTPAccess.1."); // HTTPACCESS_HEADER
    assert_int_equal(amx_fcgi_http_login(&req, &data, false), 400);

    // Successful login
    amxc_var_set(jstring_t, &data, "{\"username\":\"admin\",\"password\":\"admin\"}");
    assert_int_equal(amxc_var_cast(&data, AMXC_VAR_ID_ANY), 0);
    will_return(__wrap_FCGX_GetParam, "UserInterface.HTTPAccess.1."); // HTTPACCESS_HEADER
    will_return(__wrap_FCGX_GetParam, "UserInterface.HTTPAccess.1."); // HTTPACCESS_HEADER
    will_return(__wrap_FCGX_GetParam, "HTTPS");                       // REQUEST_SCHEME_HTTP_HEADER
    will_return(__wrap_FCGX_GetParam, "192.168.1.10");                // REMOTE_ADDR_HTTP_HEADER
    will_return(__wrap_FCGX_GetParam, "23456");                       // REMOTE_PORT_HTTP_HEADER
    assert_int_equal(amx_fcgi_http_login(&req, &data, false), 200);

    // Successful login
    amxc_var_set(jstring_t, &data, "{\"username\":\"admin\",\"password\":\"admin\"}");
    assert_int_equal(amxc_var_cast(&data, AMXC_VAR_ID_ANY), 0);
    will_return(__wrap_FCGX_GetParam, "UserInterface.HTTPAccess.1."); // HTTPACCESS_HEADER
    will_return(__wrap_FCGX_GetParam, "UserInterface.HTTPAccess.1."); // HTTPACCESS_HEADER
    will_return(__wrap_FCGX_GetParam, "HTTP");                        // REQUEST_SCHEME_HTTP_HEADER
    will_return(__wrap_FCGX_GetParam, "192.168.1.10");                // REMOTE_ADDR_HTTP_HEADER
    will_return(__wrap_FCGX_GetParam, "23456");                       // REMOTE_PORT_HTTP_HEADER
    assert_int_equal(amx_fcgi_http_login(&req, &data, false), 200);

    amxc_var_clean(&data);
}

void test_is_request_authorized(UNUSED void** state) {
    amx_fcgi_request_t req = {0};
    amxc_var_set_type(&req.roles, AMXC_VAR_ID_LIST);

    assert_non_null(bus_ctx);
    will_return(__wrap_FCGX_GetParam, "bearer J86mD3vA8hjFblCBaJUyggmcFXCbGr9RAeptigBVSRZXi7cDPOoZRsARgnkR1UwH");  // AUTHORIZATION_HTTP_HEADER
    will_return(__wrap_FCGX_GetParam, "192.168.1.10");                                                             // REMOTE_ADDR_HTTP_HEADER
    will_return(__wrap_FCGX_GetParam, "UserInterface.HTTPAccess.1.");                                              // HTTPACCESS_HEADER
    assert_int_equal(amx_fcgi_is_request_authorized(&req), 0);
    assert_int_equal(req.authorized, 1);
    assert_string_equal(GETI_CHAR(&req.roles, 0), "admin");
    amxc_var_set_type(&req.roles, AMXC_VAR_ID_LIST);

    will_return(__wrap_FCGX_GetParam, "bearer J86mD3vA8hjFblCBaJUyggmcFXCbGr9RAeptigBVSRZXi7cDPOoZRsARgnkR1UwH");  // AUTHORIZATION_HTTP_HEADER
    will_return(__wrap_FCGX_GetParam, "192.168.1.11");                                                             // REMOTE_ADDR_HTTP_HEADER
    will_return(__wrap_FCGX_GetParam, "UserInterface.HTTPAccess.1.");                                              // HTTPACCESS_HEADER
    assert_int_not_equal(amx_fcgi_is_request_authorized(&req), 0);
    assert_int_equal(req.authorized, 0);
    assert_null(GETI_ARG(&req.roles, 0));
}

void test_http_logout(UNUSED void** state) {
    amx_fcgi_request_t req = {0};
    amxc_var_set_type(&req.roles, AMXC_VAR_ID_LIST);

    // Unauthorized logout
    will_return(__wrap_FCGX_GetParam, "UserInterface.HTTPAccess.1.");                                             // HTTPACCESS_HEADER
    req.authorized = false;
    assert_int_equal(amx_fcgi_http_logout(&req, NULL, false), 400);

    // Successful logout
    will_return(__wrap_FCGX_GetParam, "UserInterface.HTTPAccess.1.");                                             // HTTPACCESS_HEADER
    will_return(__wrap_FCGX_GetParam, "bearer J86mD3vA8hjFblCBaJUyggmcFXCbGr9RAeptigBVSRZXi7cDPOoZRsARgnkR1UwH"); // AUTHORIZATION_HTTP_HEADER
    will_return(__wrap_FCGX_GetParam, "192.168.1.10");                                                            // REMOTE_ADDR_HTTP_HEADER
    req.authorized = true;
    assert_int_equal(amx_fcgi_http_logout(&req, NULL, false), 200);
}