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
#include <stdbool.h>

#include <amxc/amxc.h>
#include <amxc/amxc_macros.h>
#include <amxp/amxp.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_path.h>
#include <amxb/amxb.h>

#include "amxa/amxa_merger.h"
#include "amxa/amxa_resolver.h"
#include "amxa/amxa_validator.h"
#include "amxa/amxa_set.h"

// Always returns false if required is set to false. Returns true if 'required' is set to true and
// one of the required parameters cannot be updated with the given acls.
//
// Removes forbidden parameters from the request and adds them to the resolved_path variant.
static bool amxa_validate_params(amxb_bus_ctx_t* ctx,
                                 amxc_var_t* acls,
                                 const char* obj_path,
                                 amxc_var_t* params,
                                 amxc_var_t* resolved_path,
                                 bool required) {
    bool allowed = false;
    bool req_params_allowed = true;

    amxc_var_for_each(var, params) {
        const char* param = amxc_var_key(var);
        allowed = amxa_is_set_allowed(ctx, acls, obj_path, param);
        if(!allowed) {
            amxc_var_add(cstring_t, resolved_path, param);
            if(required) {
                req_params_allowed = false;
            }
            amxc_var_delete(&var);
        }
    }

    return req_params_allowed;
}

static bool amxa_set_validate_search_path(amxb_bus_ctx_t* bus_ctx,
                                          amxc_var_t* acls,
                                          amxd_path_t* search_path,
                                          amxc_var_t* params,
                                          amxc_var_t* oparams,
                                          amxc_var_t* forbidden) {
    amxc_var_t resolved;
    bool allowed = true;
    amxc_var_t* requested_path = NULL;

    amxc_var_init(&resolved);

    requested_path = amxc_var_add_key(amxc_htable_t, forbidden,
                                      amxd_path_get(search_path, AMXD_OBJECT_TERMINATE), NULL);

    amxb_resolve(bus_ctx, search_path, &resolved);
    amxc_var_for_each(var, &resolved) {
        const char* instance_path = amxc_var_constcast(cstring_t, var);
        amxc_var_t* resolved_path = amxc_var_add_key(amxc_llist_t, requested_path, instance_path, NULL);
        // When one required param fails, the set operation will fail, so we can exit
        allowed = amxa_validate_params(bus_ctx, acls, instance_path, params, resolved_path, true);
        when_false(allowed, exit);
        // Also consider optional params as required for search paths
        allowed = amxa_validate_params(bus_ctx, acls, instance_path, oparams, resolved_path, true);
        when_false(allowed, exit);
    }

exit:
    amxc_var_clean(&resolved);
    return allowed;
}

static void amxa_set_filter_request(amxc_var_t* request, amxc_var_t* params, amxc_var_t* oparams) {
    const amxc_htable_t* params_table = amxc_var_constcast(amxc_htable_t, params);
    const amxc_htable_t* oparams_table = amxc_var_constcast(amxc_htable_t, oparams);

    when_null(request, exit);

    if(amxc_htable_is_empty(params_table) && amxc_htable_is_empty(oparams_table)) {
        amxc_var_delete(&request);
        goto exit;
    }
    if((params != NULL) && amxc_htable_is_empty(params_table)) {
        amxc_var_delete(&params);
    }
    if((oparams != NULL) && amxc_htable_is_empty(oparams_table)) {
        amxc_var_delete(&oparams);
    }
exit:
    return;
}

static int amxa_set_validate_acls(amxb_bus_ctx_t* bus_ctx,
                                  uint32_t flags,
                                  const char* acl_file,
                                  amxc_var_t* req_paths,
                                  amxc_var_t* forbidden) {
    int retval = -1;
    char* fixed_part = NULL;
    amxd_path_t path;
    amxc_var_t* acls = NULL;
    bool allow_partial = ((flags & AMXB_FLAG_PARTIAL) != 0);
    bool req_params_allowed = true;

    amxd_path_init(&path, NULL);

    acls = amxa_parse_files(acl_file);
    when_null(acls, exit);

    amxc_var_for_each(request, req_paths) {
        const char* obj_path = GET_CHAR(request, "path");
        amxc_var_t* params = GET_ARG(request, "parameters");
        amxc_var_t* oparams = GET_ARG(request, "oparameters");

        amxd_path_setf(&path, true, "%s", obj_path);
        fixed_part = amxd_path_get_fixed_part(&path, false);
        amxa_resolve_search_paths(bus_ctx, acls, fixed_part);

        if(amxd_path_is_search_path(&path)) {
            req_params_allowed = amxa_set_validate_search_path(bus_ctx, acls, &path, params,
                                                               oparams, forbidden);
            if(!req_params_allowed) {
                amxc_var_delete(&request);
                when_true(!allow_partial, exit);
            }
        } else {
            amxc_var_t* requested_path = amxc_var_add_key(amxc_htable_t, forbidden, obj_path, NULL);
            amxc_var_t* resolved_path = amxc_var_add_key(amxc_llist_t, requested_path, obj_path, NULL);
            req_params_allowed = amxa_validate_params(bus_ctx, acls, obj_path, params,
                                                      resolved_path, true);
            amxa_validate_params(bus_ctx, acls, obj_path, oparams, resolved_path, true);
            if(!req_params_allowed) {
                amxc_var_delete(&request);
                when_true(!allow_partial, exit);
            } else {
                amxa_set_filter_request(request, params, oparams);
            }
        }
        free(fixed_part);
        fixed_part = NULL;
    }

    retval = 0;
exit:
    free(fixed_part);
    amxd_path_clean(&path);
    amxc_var_delete(&acls);
    return retval;
}

static void amxa_set_forbidden_to_result(const char* requested_path,
                                         const char* resolved_path,
                                         const amxc_llist_t* resolved_list,
                                         amxc_var_t* ret) {
    amxc_var_t* ret_requested = NULL;
    amxc_var_t* ret_result = NULL;
    amxc_var_t* ret_resolved = NULL;
    amxc_var_t* ret_param = NULL;
    amxc_string_t search;

    amxc_string_init(&search, 0);
    amxc_string_setf(&search, "[path == '%s']", requested_path);
    ret_requested = amxp_expr_find_var(ret, amxc_string_get(&search, 0));
    amxc_string_clean(&search);
    if(ret_requested == NULL) {
        amxc_var_t* status = NULL;
        amxc_var_new(&status);
        amxc_var_set(uint32_t, status, amxd_status_permission_denied);

        ret_requested = amxc_var_add(amxc_htable_t, ret, NULL);
        amxc_var_add_key(cstring_t, ret_requested, "path", requested_path);
        ret_result = amxc_var_add_key(amxc_htable_t, ret_requested, "result", NULL);
        ret_resolved = amxc_var_add_key(amxc_htable_t, ret_result, resolved_path, NULL);
        amxc_llist_for_each(it, resolved_list) {
            amxc_var_t* param = amxc_var_from_llist_it(it);
            const char* param_name = amxc_var_constcast(cstring_t, param);
            ret_param = amxc_var_add_key(amxc_htable_t, ret_resolved, param_name, NULL);
            amxc_var_add_key(uint32_t, ret_param, "error_code", amxd_status_permission_denied);
        }
        amxc_var_set_key(ret_requested, "status", status, AMXC_VAR_FLAG_UPDATE);
    }

    ret_result = GET_ARG(ret_requested, "result");
    ret_resolved = GET_ARG(ret_result, resolved_path);
    if(ret_resolved == NULL) {
        ret_resolved = amxc_var_add_key(amxc_htable_t, ret_result, resolved_path, NULL);
    }

    amxc_llist_for_each(it, resolved_list) {
        amxc_var_t* param = amxc_var_from_llist_it(it);
        const char* param_name = amxc_var_constcast(cstring_t, param);
        ret_param = amxc_var_add_key(amxc_htable_t, ret_resolved, param_name, NULL);
        amxc_var_add_key(uint32_t, ret_param, "error_code", amxd_status_permission_denied);
    }
}

static void amxa_set_combine(amxc_var_t* ret, amxc_var_t* forbidden) {
    amxc_var_for_each(requested, forbidden) {
        const char* requested_path = amxc_var_key(requested);
        amxc_var_for_each(resolved, requested) {
            const char* resolved_path = amxc_var_key(resolved);
            const amxc_llist_t* resolved_list = amxc_var_constcast(amxc_llist_t, resolved);
            if(!amxc_llist_is_empty(resolved_list)) {
                amxa_set_forbidden_to_result(requested_path, resolved_path, resolved_list, ret);
            }
        }
    }
}

int amxa_set_multiple(amxb_bus_ctx_t* const bus_ctx,
                      uint32_t flags,
                      const char* acl_file,
                      amxc_var_t* req_paths,
                      amxc_var_t* ret,
                      int timeout) {
    int retval = -1;
    amxc_var_t forbidden;

    amxc_var_init(&forbidden);
    amxc_var_set_type(&forbidden, AMXC_VAR_ID_HTABLE);

    when_null(bus_ctx, exit);
    when_str_empty(acl_file, exit);
    when_null(req_paths, exit);
    when_null(ret, exit);

    retval = amxa_set_validate_acls(bus_ctx, flags, acl_file, req_paths, &forbidden);
    if(retval != 0) {
        amxc_var_set_type(ret, AMXC_VAR_ID_LIST);
        amxa_set_combine(ret, &forbidden);
        goto exit;
    }

    retval = amxb_set_multiple(bus_ctx, flags, req_paths, ret, timeout);
    when_failed(retval, exit);

    amxa_set_combine(ret, &forbidden);

exit:
    amxc_var_clean(&forbidden);
    return retval;
}
