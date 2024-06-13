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

#include <syslog.h>
#include <string.h>
#include <amxc/amxc_macros.h>
#include "amx_fcgi.h"

static int amx_fcgi_validate_session(const char* session_id, const char* ip_addr, const char* httpaccess) {
    int ret = -1;
    amxc_var_t args;
    amxc_var_t result;
    const char* session_ctrl = GET_CHAR(amx_fcgi_get_conf_opt("session-ctrl"), NULL);

    when_failed(amxc_var_init(&args), exit);
    when_failed(amxc_var_init(&result), exit);
    when_failed(amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE), exit);
    when_null(amxc_var_add_key(cstring_t, &args, "id", session_id), exit);
    when_null(amxc_var_add_key(cstring_t, &args, "ip", ip_addr), exit);
    when_null(amxc_var_add_key(cstring_t, &args, "httpaccess", httpaccess), exit);
    when_failed(amxm_execute_function(session_ctrl, "fcgi-session", "is_valid_session", &args, &result), exit);

    ret = (GET_BOOL(&result, 0)) ? 0 : -1;
exit:
    amxc_var_clean(&args);
    amxc_var_clean(&result);
    return ret;
}

static int amx_fcgi_get_acl_role(amx_fcgi_request_t* fcgi_req, const char* session_id, const char* httpaccess) {
    int ret = -1;
    amxc_var_t args;
    const char* session_ctrl = GET_CHAR(amx_fcgi_get_conf_opt("session-ctrl"), NULL);

    when_failed(amxc_var_init(&args), exit);
    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &args, "session_id", session_id);
    amxc_var_add_key(cstring_t, &args, "httpaccess", httpaccess);

    when_failed(amxm_execute_function(session_ctrl, "fcgi-session", "get_acl_role", &args, &fcgi_req->roles), exit);

    when_null(GETI_ARG(&fcgi_req->roles, 0), exit);

    ret = 0;
exit:
    amxc_var_clean(&args);
    return ret;
}

const char* amx_fcgi_get_session_id(amx_fcgi_request_t* fcgi_req) {
    const char* bearer_token;
    const char* session_id = NULL;

    bearer_token = FCGX_GetParam(AUTHORIZATION_HTTP_HEADER, fcgi_req->request.envp);
    when_str_empty(bearer_token, exit);
    // To be correct the following line should use "strncmp".
    // For now strncasecmp as sometimes the "bearer" token in not with capital B
    // in the incomming request, which is a bug from the sending side.
    // For now accept the "Bearer " token regardless of the case (do a case
    // insensitive compare).
    when_false((strncasecmp(BEARER_TOKEN, bearer_token, BEARER_TOKEN_LENGTH) == 0), exit);
    bearer_token += BEARER_TOKEN_LENGTH;
    when_false(strlen(bearer_token) == TOKEN_LENGTH, exit);
    session_id = bearer_token;
exit:
    return session_id;
}

int amx_fcgi_is_request_authorized(amx_fcgi_request_t* fcgi_req) {
    int ret = -1;
    const char* session_id = amx_fcgi_get_session_id(fcgi_req);
    const char* ip_addr = FCGX_GetParam(REMOTE_ADDR_HTTP_HEADER, fcgi_req->request.envp);
    const char* httpaccess = FCGX_GetParam(HTTPACCESS_HEADER, fcgi_req->request.envp);

    when_str_empty(session_id, exit);
    when_str_empty(ip_addr, exit);
    when_str_empty(httpaccess, exit);

    ret = amx_fcgi_validate_session(session_id, ip_addr, httpaccess);
    when_true(ret != 0, exit);

    when_failed(amx_fcgi_get_acl_role(fcgi_req, session_id, httpaccess), exit);

exit:
    fcgi_req->authorized = ((ret == 0) ? true : false);
    return ret;
}