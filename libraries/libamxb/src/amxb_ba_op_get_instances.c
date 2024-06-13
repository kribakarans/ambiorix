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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>

#include <amxc/amxc.h>
#include <amxp/amxp.h>

#include <amxd/amxd_common.h>
#include <amxd/amxd_dm.h>
#include <amxd/amxd_path.h>
#include <amxd/amxd_object.h>

#include <amxb/amxb_be_intf.h>
#include <amxb/amxb.h>

#include "amxb_priv.h"

static int amxb_invoke_get_instances(amxb_bus_ctx_t* const bus_ctx,
                                     bool islocal,
                                     const char* object,
                                     const char* search_path,
                                     int32_t depth,
                                     amxc_var_t* ret,
                                     int timeout) {
    amxb_invoke_t* invoke_ctx = NULL;
    int retval = amxd_status_unknown_error;
    amxc_var_t* args = NULL;
    amxc_string_t full_path;
    amxd_object_t* root = amxd_dm_get_root(bus_ctx->dm);
    timeout = amxb_get_minimal_timeout(timeout);

    amxc_string_init(&full_path, 0);
    amxc_var_new(&args);
    amxc_var_set_type(args, AMXC_VAR_ID_HTABLE);

    if(search_path != NULL) {
        amxc_var_add_key(cstring_t, args, "rel_path", search_path);
    }
    amxc_var_add_key(int32_t, args, "depth", depth);
    amxc_var_add_key(uint32_t, args, "access", bus_ctx->access);

    retval = amxb_new_invoke(&invoke_ctx, bus_ctx, object, NULL, "_get_instances");
    when_failed(retval, exit);
    retval = amxb_invoke(invoke_ctx, args, ret, NULL, NULL, timeout);
    when_true(!islocal, exit);
    when_true(retval == 0, exit);

    amxc_string_setf(&full_path, "%s%s", object, search_path);
    if(amxd_object_is_supported(root, amxc_string_get(&full_path, 0))) {
        amxc_var_set_type(ret, AMXC_VAR_ID_LIST);
        amxc_var_add(amxc_htable_t, ret, NULL);
        retval = amxd_status_ok;
    }

exit:
    amxc_string_clean(&full_path);
    amxc_var_delete(&args);
    amxb_free_invoke(&invoke_ctx);
    return retval;
}

int amxb_get_instances(amxb_bus_ctx_t* const bus_ctx,
                       const char* search_path,
                       int32_t depth,
                       amxc_var_t* ret,
                       int timeout) {
    int retval = amxd_status_unknown_error;
    const amxb_be_funcs_t* fns = NULL;
    amxd_path_t path;
    bool islocal = false;
    char* object = NULL;
    const char* param = NULL;
    amxc_string_t temp;
    timeout = amxb_get_minimal_timeout(timeout);

    amxc_string_init(&temp, 0);
    amxd_path_init(&path, search_path);
    when_null(bus_ctx, exit);
    when_null(bus_ctx->bus_ctx, exit);

    object = amxd_path_get_fixed_part(&path, true);
    if((object == NULL) || (strcmp(object, ".") == 0)) {
        retval = amxd_status_object_not_found;
        goto exit;
    }
    search_path = amxd_path_get(&path, AMXD_OBJECT_TERMINATE);
    search_path = search_path == NULL ? "" : search_path;
    param = amxd_path_get_param(&path);
    islocal = amxb_is_local_object(bus_ctx, object);
    fns = bus_ctx->bus_fn;

    if(param != NULL) {
        amxc_string_setf(&temp, "%s%s", search_path, param);
        search_path = amxc_string_get(&temp, 0);
    }

    if(islocal || !amxb_is_valid_be_func(fns, get, fns->get_instances)) {
        retval = amxb_invoke_get_instances(bus_ctx, islocal, object, search_path,
                                           depth, ret, timeout);
    } else {
        retval = fns->get_instances(bus_ctx->bus_ctx, object, search_path,
                                    depth, bus_ctx->access, ret, timeout);
    }

exit:
    amxb_log(bus_ctx, "get_instances", search_path, retval);
    amxc_string_clean(&temp);
    free(object);
    amxd_path_clean(&path);
    return retval;
}
