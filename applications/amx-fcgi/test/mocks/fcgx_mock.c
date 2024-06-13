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
#include <setjmp.h>
#include <stdarg.h>
#include <cmocka.h>
#include <string.h>
#include <stdio.h>

#include <amxc/amxc.h>

#include "fcgx_mock.h"
#include "amx_fcgi.h"

static amxc_string_t response;
static const char* acl_user;

int __wrap_FCGX_Init(void) {
    return mock();
}

void __wrap_FCGX_Free(UNUSED FCGX_Request* request, UNUSED int close) {
}

void __wrap_FCGX_ClearError(UNUSED FCGX_Stream* stream) {
}

int __wrap_FCGX_PutS(const char* str, UNUSED FCGX_Stream* stream) {
    amxc_string_appendf(&response, "%s", str);

    return 0;
}

int __wrap_FCGX_PutChar(UNUSED int c, UNUSED FCGX_Stream* stream) {
    return 0;
}

int __wrap_FCGX_FPrintF(UNUSED FCGX_Stream* stream, UNUSED const char* format, ...) {
    va_list args;

    va_start(args, format);
    amxc_string_vappendf(&response, format, args);
    va_end(args);

    return 0;
}

int __wrap_FCGX_FFlush(UNUSED FCGX_Stream* stream) {
    return 0;
}

int __wrap_FCGX_GetError(UNUSED FCGX_Stream* stream) {
    return mock();
}

void __wrap_FCGX_Finish_r(UNUSED FCGX_Request* request) {
}

int __wrap_FCGX_InitRequest(UNUSED FCGX_Request* request, UNUSED int sock, UNUSED int flags) {
    return mock();
}

int __wrap_FCGX_Accept_r(UNUSED FCGX_Request* request) {
    return mock();
}

char* __wrap_FCGX_GetParam(UNUSED const char* name, UNUSED FCGX_ParamArray envp) {
    return mock_ptr_type(char*);
}

int __wrap_FCGX_GetStr(char* str, int n, UNUSED FCGX_Stream* stream) {
    const char* content = mock_ptr_type(const char*);
    int length = mock();

    strncpy(str, content, n);
    str[n] = 0;
    return length;
}

int __wrap_FCGX_OpenSocket(UNUSED const char* path, UNUSED int backlog) {
    check_expected(path);
    check_expected(backlog);
    return mock();
}

void __wrap_OS_LibShutdown(void) {

}

int __wrap_amx_fcgi_is_request_authorized(amx_fcgi_request_t* fcgi_req, UNUSED amxb_bus_ctx_t* ctx) {
    int ret = mock();
    fcgi_req->authorized = (ret == 0) ? true : false;
    if(acl_user == NULL) {
        amxc_var_set_type(&fcgi_req->roles, AMXC_VAR_ID_LIST);
    } else {
        amxc_var_add(cstring_t, &fcgi_req->roles, acl_user);
    }
    return ret;
}

void test_clean_response(void) {
    amxc_string_clean(&response);
}

void test_reset_response(void) {
    amxc_string_reset(&response);
}

const char* test_get_response(void) {
    return amxc_string_get(&response, 0);
}

void set_acl_user(const char* user) {
    acl_user = user;
}