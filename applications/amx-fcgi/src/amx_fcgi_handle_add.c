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

static void amx_fcgi_filter_out(amxc_var_t* full, amxc_var_t* filter) {
    amxc_var_for_each(var, full) {
        if(GET_ARG(filter, amxc_var_key(var)) != NULL) {
            amxc_var_delete(&var);
        }
    }
}

static int amx_fcgi_verify_add(amxb_bus_ctx_t* ctx,
                               amx_fcgi_request_t* fcgi_req,
                               amxc_var_t* params) {
    amxc_var_t* acls = NULL;
    amxc_var_t resolved;
    char* file = amx_fcgi_get_acl_file(fcgi_req);
    int retval = -1;
    bool allowed = false;
    const amxc_htable_t* params_table = amxc_var_constcast(amxc_htable_t, params);
    amxd_path_t path;
    char* fixed_part = NULL;

    amxc_var_init(&resolved);
    amxd_path_init(&path, fcgi_req->raw_path);

    when_str_empty(file, exit);

    fixed_part = amxd_path_get_fixed_part(&path, false);
    when_str_empty(fixed_part, exit);
    acls = amxa_parse_files(file);
    retval = amxa_resolve_search_paths(ctx, acls, fixed_part);
    when_failed(retval, exit);

    allowed = amxa_is_add_allowed(ctx, acls, fcgi_req->raw_path);
    when_false_status(allowed, exit, retval = -1);
    if((params_table != NULL) && !amxc_htable_is_empty(params_table)) {
        allowed = amx_fcgi_verify_params(ctx, acls, fcgi_req->raw_path, params);
        when_false_status(allowed, exit, retval = -1);
    }

    retval = 0;
exit:
    free(file);
    amxc_var_delete(&acls);
    amxc_var_clean(&resolved);
    free(fixed_part);
    amxd_path_clean(&path);

    return retval;
}

int amx_fcgi_http_add(amx_fcgi_request_t* fcgi_req,
                      amxc_var_t* data,
                      bool acl_verify) {
    int retval = -1;
    char* p = amxd_path_get_first(&fcgi_req->path, false);
    amxb_bus_ctx_t* ctx = amxb_be_who_has(p);
    amxc_var_t* params = GET_ARG(data, "parameters") == NULL ? data : GET_ARG(data, "parameters");
    amxc_var_t rv;
    amxc_var_t all;
    const char* path = NULL;

    amxc_var_t* keys = NULL;
    amxc_var_t* parameters = NULL;

    amxc_var_init(&rv);
    amxc_var_init(&all);

    when_null_status(ctx, exit, retval = 404);
    amxb_set_access(ctx, AMXB_PUBLIC);

    if(acl_verify) {
        retval = amx_fcgi_verify_add(ctx, fcgi_req, params);
        when_true_status(retval != 0, exit, retval = 403);
    }

    retval = amxb_add(ctx, fcgi_req->raw_path, 0,
                      NULL, params, &rv, 5);
    when_true_status(retval != 0, exit, retval = 400);

    amxc_var_set_type(data, AMXC_VAR_ID_HTABLE);
    path = GETP_CHAR(&rv, "0.path");
    amxb_get(ctx, path, 0, &all, 5);

    amx_fcgi_filter_out(GET_ARG(GETI_ARG(&all, 0), path), GETP_ARG(&rv, "0.parameters"));

    amxc_var_add_key(cstring_t, data, "path", path);
    keys = amxc_var_add_key(amxc_htable_t, data, "uniqueKeys", NULL);
    parameters = amxc_var_add_key(amxc_htable_t, data, "parameters", NULL);

    amxc_var_move(keys, GETP_ARG(&rv, "0.parameters"));
    amxc_var_move(parameters, GET_ARG(GETI_ARG(&all, 0), path));

    retval = 201;

exit:
    amxc_var_clean(&rv);
    amxc_var_clean(&all);
    free(p);
    return retval;
}