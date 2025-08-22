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
#include "amxa/amxa_get_instances.h"

/**
   If not supported -> return amxd_status_not_supported
   If not a template -> return amxd_status_not_a_template
   If template object not found in instantiated data model -> return amxd_status_not_instantiated
 */
static int amxa_get_instances_check_object(amxb_bus_ctx_t* bus_ctx, const char* object) {
    amxd_path_t path;
    char* supported_path = NULL;
    amxc_var_t ret;
    int retval = -1;

    amxd_path_init(&path, object);
    amxc_var_init(&ret);

    supported_path = amxd_path_build_supported_path(&path);
    retval = amxb_get_supported(bus_ctx, supported_path, AMXB_FLAG_FIRST_LVL, &ret, 5);
    when_failed_status(retval, exit, retval = amxd_status_not_supported);
    when_false_status(GETP_BOOL(&ret, "0.0.is_multi_instance"), exit,
                      retval = amxd_status_not_a_template);

    retval = amxb_get(bus_ctx, object, 0, &ret, 5);
    when_true_status(retval != 0, exit, retval = amxd_status_not_instantiated);

exit:
    free(supported_path);
    amxc_var_clean(&ret);
    amxd_path_clean(&path);
    return retval;
}

int amxa_get_instances(amxb_bus_ctx_t* bus_ctx,
                       const char* object,
                       const char* acl_file,
                       int32_t depth,
                       amxc_var_t* ret,
                       int timeout) {
    amxc_var_t* acls = NULL;
    char* fixed_part = NULL;
    amxc_llist_t filters;
    amxd_path_t path;
    int rv = amxd_status_not_supported;
    bool allowed = false;

    amxc_llist_init(&filters);
    amxd_path_init(&path, object);

    when_null(bus_ctx, exit);
    when_str_empty(object, exit);
    when_str_empty(acl_file, exit);
    when_null(ret, exit);

    rv = amxa_get_instances_check_object(bus_ctx, object);
    when_failed(rv, exit);

    acls = amxa_parse_files(acl_file);
    when_null_status(acls, exit, rv = amxd_status_permission_denied);

    fixed_part = amxd_path_get_fixed_part(&path, false);
    rv = amxa_resolve_search_paths(bus_ctx, acls, fixed_part);
    when_failed_status(rv, exit, rv = amxd_status_permission_denied);

    rv = amxa_get_filters(acls, AMXA_PERMIT_GET_INST, &filters, fixed_part);
    when_failed_status(rv, exit, rv = amxd_status_permission_denied);

    allowed = amxa_is_get_inst_allowed(&filters, fixed_part);
    when_false_status(allowed, exit, rv = amxd_status_permission_denied);

    rv = amxb_get_instances(bus_ctx, object, depth, ret, timeout);
    when_false_status(allowed, exit, rv = amxd_status_not_instantiated);

    amxa_filter_get_inst_resp(ret, &filters);

exit:
    amxc_llist_clean(&filters, amxc_string_list_it_free);
    amxc_var_delete(&acls);
    free(fixed_part);
    amxd_path_clean(&path);
    return rv;
}
