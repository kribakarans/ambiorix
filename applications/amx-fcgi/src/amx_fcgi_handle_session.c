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

#include <string.h>
#include <amxc/amxc.h>

#include "amx_fcgi.h"

static int amx_fcgi_check_credentials(const char* username, const char* password, const char* httpaccess, amxc_var_t* data) {
    int ret = 400;
    amxc_var_t args;
    amxc_var_t result;
    const char* session_ctrl = GET_CHAR(amx_fcgi_get_conf_opt("session-ctrl"), NULL);

    amxc_var_init(&args);
    amxc_var_init(&result);

    when_failed(amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE), exit);
    when_null(amxc_var_add_key(cstring_t, &args, "username", username), exit);
    when_null(amxc_var_add_key(cstring_t, &args, "password", password), exit);
    when_null(amxc_var_add_key(cstring_t, &args, "httpaccess", httpaccess), exit);
    when_failed(amxm_execute_function(session_ctrl, "fcgi-session", "check_credentials", &args, &result), exit);

    ret = GET_INT32(&result, NULL);
    if(ret == 0) {
        amxc_var_add_key(uint32_t, data, "login_attempts", GET_UINT32(&args, "LoginAttempts"));
    }

exit:
    amxc_var_clean(&args);
    amxc_var_clean(&result);
    return ret;
}

static const char* amx_fcgi_get_req_scheme(amx_fcgi_request_t* fcgi_req) {
    const char* scheme = FCGX_GetParam(REQUEST_SCHEME_HTTP_HEADER, fcgi_req->request.envp);
    const char* upper_scheme = NULL;

    when_str_empty(scheme, exit);
    if(strcasecmp(scheme, "http") == 0) {
        upper_scheme = "HTTP";
    } else if(strcasecmp(scheme, "https") == 0) {
        upper_scheme = "HTTPS";
    }
exit:
    return upper_scheme;
}

static int amx_fcgi_create_session_response(amxc_var_t* data, amxc_var_t* result) {
    int status = 500;
    amxc_var_t* login_attempts = amxc_var_take_key(data, "login_attempts");

    when_str_empty(GET_CHAR(result, "session_id"), exit);
    amxc_var_set_type(data, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, data, "sessionID", GET_CHAR(result, "session_id"));
    amxc_var_add_key(uint32_t, data, "absoluteTimeout", SESSION_ABSOLUTE_TIMER);
    amxc_var_add_key(uint32_t, data, "idleTimeout", SESSION_IDLE_TIMER);
    if(amxc_var_type_of(login_attempts) == AMXC_VAR_ID_UINT32) {
        amxc_var_add_key(uint32_t, data, "loginAttempts", amxc_var_constcast(uint32_t, login_attempts));
    }

    status = 200;
exit:
    amxc_var_delete(&login_attempts);
    return status;
}

static int amx_fcgi_create_session(amx_fcgi_request_t* fcgi_req, amxc_var_t* data) {
    int status = 0;
    const char* httpaccess = FCGX_GetParam(HTTPACCESS_HEADER, fcgi_req->request.envp);
    const char* scheme = amx_fcgi_get_req_scheme(fcgi_req);
    const char* session_ctrl = GET_CHAR(amx_fcgi_get_conf_opt("session-ctrl"), NULL);
    amxc_var_t args;
    amxc_var_t result;

    amxc_var_init(&args);
    amxc_var_init(&result);

    when_failed(amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE), exit);
    when_str_empty_status(scheme, exit, status = 500);
    when_null_status(amxc_var_add_key(cstring_t, &args, "username", GET_CHAR(data, "username")), exit, status = 500);
    when_null_status(amxc_var_add_key(cstring_t, &args, "ip", FCGX_GetParam(REMOTE_ADDR_HTTP_HEADER, fcgi_req->request.envp)), exit, status = 500);
    when_null_status(amxc_var_add_key(cstring_t, &args, "port", FCGX_GetParam(REMOTE_PORT_HTTP_HEADER, fcgi_req->request.envp)), exit, status = 500);
    when_null_status(amxc_var_add_key(cstring_t, &args, "protocol", scheme), exit, status = 500);
    when_null_status(amxc_var_add_key(uint32_t, &args, "absolute_timeout", SESSION_ABSOLUTE_TIMER), exit, status = 500);
    when_null_status(amxc_var_add_key(uint32_t, &args, "idle_timeout", SESSION_IDLE_TIMER), exit, status = 500);
    when_null_status(amxc_var_add_key(cstring_t, &args, "httpaccess", httpaccess), exit, status = 500);

    when_failed_status(amxm_execute_function(session_ctrl, "fcgi-session", "create_session", &args, &result), exit, status = 500);

    status = amx_fcgi_create_session_response(data, &result);

exit:
    amxc_var_clean(&args);
    amxc_var_clean(&result);
    return status;
}

static int amx_fcgi_delete_session(amx_fcgi_request_t* fcgi_req, const char* session_id, const char* httpaccess) {
    int status = 200;
    amxc_var_t args;
    amxc_var_t result;
    const char* session_ctrl = GET_CHAR(amx_fcgi_get_conf_opt("session-ctrl"), NULL);

    amxc_var_init(&args);
    amxc_var_init(&result);

    when_failed(amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE), exit);
    when_null_status(amxc_var_add_key(cstring_t, &args, "httpaccess", httpaccess), exit, status = 500);
    when_null_status(amxc_var_add_key(cstring_t, &args, "session_id", session_id), exit, status = 500);
    when_null_status(amxc_var_add_key(cstring_t, &args, "ip", FCGX_GetParam(REMOTE_ADDR_HTTP_HEADER, fcgi_req->request.envp)), exit, status = 500);

    when_failed_status(amxm_execute_function(session_ctrl, "fcgi-session", "delete_session", &args, &result), exit, status = 500);

exit:
    amxc_var_clean(&args);
    amxc_var_clean(&result);

    return status;
}

int amx_fcgi_http_login(amx_fcgi_request_t* fcgi_req, amxc_var_t* data, UNUSED bool acl_verify) {
    int status = 0;
    const char* httpaccess = FCGX_GetParam(HTTPACCESS_HEADER, fcgi_req->request.envp);
    const char* username = NULL;
    const char* password = NULL;

    when_str_empty_status(httpaccess, exit, status = 400);
    when_true_status(fcgi_req->authorized == true, exit, status = 400); // User already logged in
    username = GET_CHAR(data, "username");
    password = GET_CHAR(data, "password");
    when_str_empty_status(username, exit, status = 400);
    when_str_empty_status(password, exit, status = 400);
    status = amx_fcgi_check_credentials(username, password, httpaccess, data);
    when_failed(status, exit);
    status = amx_fcgi_create_session(fcgi_req, data);
exit:
    return status;
}

int amx_fcgi_http_logout(UNUSED amx_fcgi_request_t* fcgi_req, UNUSED amxc_var_t* data, UNUSED bool acl_verify) {
    int status = 0;
    const char* session_id;
    const char* httpaccess = FCGX_GetParam(HTTPACCESS_HEADER, fcgi_req->request.envp);

    when_true_status(fcgi_req->authorized == false, exit, status = 400); // User isn't logged in
    session_id = amx_fcgi_get_session_id(fcgi_req);
    when_str_empty_status(session_id, exit, status = 400);
    when_str_empty_status(httpaccess, exit, status = 400);
    status = amx_fcgi_delete_session(fcgi_req, session_id, httpaccess);

exit:
    return status;
}
