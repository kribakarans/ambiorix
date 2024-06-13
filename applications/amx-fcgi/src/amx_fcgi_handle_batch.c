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
#include <string.h>

#include "amx_fcgi.h"

static amx_fcgi_func_t exec_funcs[] = {
    NULL,                       // INVALID
    amx_fcgi_http_add,          // POST PATH (service elements)
    amx_fcgi_http_get,          // GET PATH (service elements)
    amx_fcgi_http_set,          // PATCH PATH (service elements)
    amx_fcgi_http_del,          // DELETE PATH (service elements)
    NULL,                       // POST CMD
    NULL,                       // OPEN EVENT STREAM
    NULL,                       // SUBSCRIBE
    NULL,                       // UNSUBSCRIBE
    NULL,                       // SEBATCH
    NULL,
    NULL,
};

static request_method_t amx_fcgi_batch_action_2_method(const char* action) {
    const char* names[] = {
        NULL,
        "Add",
        "Get",
        "Set",
        "Delete",
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
    };
    request_method_t method = METHOD_UNSUPORTED;

    when_null(action, exit);

    for(uint32_t i = 0; i <= (uint32_t) METHOD_LAST; i++) {
        if((names[i] != NULL) && (strcmp(action, names[i]) == 0)) {
            method = (request_method_t) i;
            break;
        }
    }

exit:
    return method;
}

int amx_fcgi_http_batch(amx_fcgi_request_t* fcgi_req,
                        amxc_var_t* data,
                        bool acl_verify) {
    int status = 200;

    amxc_var_for_each(sub_req, data) {
        int retval = 200;
        const char* action = GET_CHAR(sub_req, "action");
        const char* path = GET_CHAR(sub_req, "path");
        amxc_var_t* params = GET_ARG(sub_req, "parameters");
        amxc_var_t* req_path = GET_ARG(sub_req, "path");
        request_method_t method = amx_fcgi_batch_action_2_method(action);

        if(method == METHOD_UNSUPORTED) {
            status = 400;
            break;
        }

        fcgi_req->raw_path = path;
        amxd_path_init(&fcgi_req->path, path);

        if(params == NULL) {
            params = amxc_var_add_new_key(sub_req, "parameters");
        }

        retval = exec_funcs[method](fcgi_req, params, acl_verify);

        amxc_var_add_key(uint32_t, sub_req, "status", retval);
        amxc_var_set_key(sub_req, "requested_path", req_path, AMXC_VAR_FLAG_DEFAULT);
        if(!amxc_var_is_null(params)) {
            amxc_var_set_key(sub_req, "response", params, AMXC_VAR_FLAG_DEFAULT);
        } else {
            amxc_var_delete(&params);
        }

        amxd_path_clean(&fcgi_req->path);
        fcgi_req->raw_path = NULL;
    }

    return status;
}
