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

#include "amx_fcgi.h"

static void amx_fcgi_convert_to_se(amxc_var_t* dst, amxc_var_t* src) {
    amxc_var_set_type(dst, AMXC_VAR_ID_LIST);
    const amxc_htable_t* src_table = amxc_var_constcast(amxc_htable_t, src);
    amxc_array_t* keys = amxc_htable_get_sorted_keys(src_table);

    for(uint32_t i = 0; i < amxc_array_capacity(keys); i++) {
        const char* key
            = (const char*) amxc_array_it_get_data(amxc_array_get_at(keys, i));
        amxc_var_t* obj = GET_ARG(src, key);
        amxc_var_t* result_obj = amxc_var_add(amxc_htable_t, dst, NULL);
        amxc_var_add_key(cstring_t, result_obj, "path", amxc_var_key(obj));
        amxc_var_set_key(result_obj, "parameters", obj, AMXC_VAR_FLAG_DEFAULT);
    }

    amxc_array_delete(&keys, NULL);
}

int amx_fcgi_http_get(amx_fcgi_request_t* fcgi_req,
                      amxc_var_t* data,
                      bool acl_verify) {
    int retval = -1;
    char* p = amxd_path_get_fixed_part(&fcgi_req->path, false);
    amxb_bus_ctx_t* ctx = amxb_be_who_has(p);
    amxc_var_t rv;
    amxc_var_t* acls = NULL;
    amxc_llist_t filters;
    char* file = NULL;

    amxc_var_init(&rv);
    amxc_llist_init(&filters);

    when_null_status(ctx, exit, retval = 404);
    amxb_set_access(ctx, AMXB_PUBLIC);

    if(acl_verify) {
        file = amx_fcgi_get_acl_file(fcgi_req);
        retval = amxa_get(ctx, fcgi_req->raw_path, file, INT32_MAX, &rv, 5);
        free(file);
        when_false_status(retval == 0, exit, retval = (fcgi_req->authorized) ? 403 : 401);
    } else {
        when_true_status(fcgi_req->authorized == false, exit, retval = 401); // When no ACL verify 401 every non-authorized request
        retval = amxb_get(ctx, fcgi_req->raw_path, INT32_MAX, &rv, 5);
        when_false_status(retval == 0, exit, retval = 400);
    }

    amx_fcgi_convert_to_se(data, GETI_ARG(&rv, 0));

    retval = 200;

exit:
    amxc_var_clean(&rv);
    amxc_var_delete(&acls);
    amxc_llist_clean(&filters, amxc_string_list_it_free);
    free(p);

    return retval;
}
