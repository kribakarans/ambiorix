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
#include <stdlib.h>
#include <stdio.h>

#include <amxc/amxc.h>
#include <amxc/amxc_macros.h>
#include <amxp/amxp.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_path.h>

#include "amxa/amxa_permissions.h"
#include "amxa/amxa_validator.h"
#include "amxa/amxa_merger.h"
#include "amxa/amxa_resolver.h"

#include "amxa_utils_priv.h"
#include "amxa/amxa_get.h"

static bool prepare_amxa_get(amxb_bus_ctx_t* bus_ctx,
                             amxc_var_t* acls,
                             amxc_llist_t* filters,
                             const char* requested_path) {
    int rv = -1;
    bool allowed = false;
    amxc_llist_t filtered_path;

    amxc_llist_init(&filtered_path);
    if(filters == NULL) {
        filters = &filtered_path;
    }
    rv = amxa_get_filters(acls, AMXA_PERMIT_GET, filters, requested_path);
    when_failed(rv, exit);

    allowed = amxa_is_search_path_allowed(bus_ctx, acls, requested_path);
    when_false(allowed, exit);

    allowed = amxa_is_get_allowed(filters, requested_path);
    when_false(allowed, exit);
exit:
    amxc_llist_clean(&filtered_path, amxc_string_list_it_free);
    return allowed;
}

static bool amxa_get_search_path(amxb_bus_ctx_t* bus_ctx,
                                 amxd_path_t* path,
                                 amxc_var_t* acls,
                                 amxc_llist_t* filters) {
    int rv = -1;
    bool has_one_path_allowed = false;
    amxc_var_t resolved_paths;

    amxc_var_init(&resolved_paths);
    rv = amxb_resolve(bus_ctx, path, &resolved_paths);
    when_failed(rv, exit);
    amxc_var_for_each(resolved_path, &resolved_paths) {
        if(prepare_amxa_get(bus_ctx, acls, NULL, amxc_var_constcast(cstring_t, resolved_path))) {
            has_one_path_allowed = true;
        } else {
            amxc_llist_add_string(filters, amxc_var_constcast(cstring_t, resolved_path));
        }
    }
exit:
    amxc_var_clean(&resolved_paths);
    return has_one_path_allowed;
}

int amxa_get(amxb_bus_ctx_t* bus_ctx,
             const char* object,
             const char* acl,
             int32_t depth,
             amxc_var_t* ret,
             int timeout) {
    return amxa_get_filtered(bus_ctx, object, NULL, acl,
                             depth, ret, timeout);
}

int amxa_get_filtered(amxb_bus_ctx_t* bus_ctx,
                      const char* object,
                      const char* filter,
                      const char* acl,
                      int32_t depth,
                      amxc_var_t* ret,
                      int timeout) {
    amxc_var_t* acls = NULL;
    char* fixed_part = NULL;
    amxc_llist_t filters;
    amxd_path_t path;
    int rv = -1;
    bool allowed = false;

    amxc_llist_init(&filters);
    amxd_path_init(&path, object);

    acls = amxa_parse_files(acl);
    when_null(acls, exit);

    fixed_part = amxd_path_get_fixed_part(&path, false);
    rv = amxa_resolve_search_paths(bus_ctx, acls, fixed_part);
    when_failed(rv, exit);

    if(!amxd_path_is_search_path(&path)) {
        allowed = prepare_amxa_get(bus_ctx, acls, &filters, amxd_path_get(&path, AMXD_OBJECT_TERMINATE));
    } else {
        allowed = amxa_get_search_path(bus_ctx, &path, acls, &filters);
    }
    when_false_status(allowed, exit, rv = -1);

    rv = amxb_get_filtered(bus_ctx, object, filter, depth, ret, timeout);
    when_failed_status(rv, exit, rv = -1);

    amxa_filter_get_resp(ret, &filters);

exit:
    amxc_llist_clean(&filters, amxc_string_list_it_free);
    amxc_var_delete(&acls);
    free(fixed_part);
    amxd_path_clean(&path);
    return rv;
}
