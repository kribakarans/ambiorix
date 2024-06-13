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

#include "amx_fcgi.h"

static int amx_fcgi_verify_set(amxb_bus_ctx_t* ctx,
                               amx_fcgi_request_t* fcgi_req,
                               const char* fixed,
                               amxc_var_t* params) {
    amxc_var_t* acls = NULL;
    amxc_var_t resolved;
    char* file = amx_fcgi_get_acl_file(fcgi_req);
    int retval = -1;
    bool allowed = false;
    amxc_string_t resolved_path;

    amxc_string_init(&resolved_path, 0);
    amxc_var_init(&resolved);

    when_str_empty(file, exit);

    acls = amxa_parse_files(file);
    retval = amxa_resolve_search_paths(ctx, acls, fixed);
    when_failed(retval, exit);

    if(amxd_path_is_search_path(&fcgi_req->path)) {
        amxb_resolve(ctx, &fcgi_req->path, &resolved);
        amxc_var_for_each(var, &resolved) {
            amxc_string_setf(&resolved_path, "%s", amxc_var_constcast(cstring_t, var));
            allowed = amx_fcgi_verify_params(ctx, acls, amxc_string_get(&resolved_path, 0),
                                             params);
            when_false_status(allowed, exit, retval = -1);
        }
    } else {
        allowed = amx_fcgi_verify_params(ctx, acls, fixed, params);
        when_false_status(allowed, exit, retval = -1);
    }

    retval = 0;
exit:
    free(file);
    amxc_var_delete(&acls);
    amxc_var_clean(&resolved);
    amxc_string_clean(&resolved_path);

    return retval;
}

bool amx_fcgi_verify_params(amxb_bus_ctx_t* ctx,
                            amxc_var_t* acls,
                            const char* obj_path,
                            amxc_var_t* params) {
    bool allowed = false;
    amxc_var_for_each(var, params) {
        const char* param = amxc_var_key(var);
        allowed = amxa_is_set_allowed(ctx, acls, obj_path, param);
        if(!allowed) {
            goto exit;
        }
    }

exit:
    return allowed;
}

int amx_fcgi_http_set(amx_fcgi_request_t* fcgi_req,
                      amxc_var_t* data,
                      bool acl_verify) {
    int retval = -1;
    char* p = amxd_path_get_fixed_part(&fcgi_req->path, false);
    amxb_bus_ctx_t* ctx = amxb_be_who_has(p);
    amxc_var_t* params = GET_ARG(data, "parameters") == NULL ? data : GET_ARG(data, "parameters");
    amxc_var_t rv;

    amxc_var_init(&rv);

    when_null_status(ctx, exit, retval = 404);
    amxb_set_access(ctx, AMXB_PUBLIC);

    if(acl_verify) {
        retval = amx_fcgi_verify_set(ctx, fcgi_req, p, params);
        when_true_status(retval != 0, exit, retval = 403);
    }
    retval = amxb_set(ctx, fcgi_req->raw_path, params, &rv, 5);
    when_true_status(retval != 0, exit, retval = 400);

    amxc_var_clean(data);
    retval = 204;

exit:
    amxc_var_clean(&rv);
    free(p);
    return retval;
}