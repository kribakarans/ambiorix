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

static int amxb_invoke_get_supported(amxb_bus_ctx_t* const bus_ctx,
                                     const char* object,
                                     const char* rel_path,
                                     uint32_t flags,
                                     amxc_var_t* values,
                                     int timeout) {
    amxb_invoke_t* invoke_ctx = NULL;
    amxc_var_t args;
    int retval = amxd_status_unknown_error;
    timeout = amxb_get_minimal_timeout(timeout);

    amxc_var_init(&args);
    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);

    if((rel_path != NULL) && (*rel_path != 0)) {
        amxc_var_add_key(cstring_t, &args, "rel_path", rel_path);
    }

    amxc_var_add_key(bool, &args,
                     "first_level_only", (flags & AMXB_FLAG_FIRST_LVL) != 0);
    amxc_var_add_key(bool, &args, "functions", (flags & AMXB_FLAG_FUNCTIONS) != 0);
    amxc_var_add_key(bool, &args, "parameters", (flags & AMXB_FLAG_PARAMETERS) != 0);
    amxc_var_add_key(bool, &args, "events", (flags & AMXB_FLAG_EVENTS) != 0);
    amxc_var_add_key(uint32_t, &args, "access", bus_ctx->access);

    retval = amxb_new_invoke(&invoke_ctx, bus_ctx, object, NULL, "_get_supported");
    when_failed(retval, exit);
    retval = amxb_invoke(invoke_ctx, &args, values, NULL, NULL, timeout);
    when_failed(retval, exit);

exit:
    amxc_var_clean(&args);
    amxb_free_invoke(&invoke_ctx);
    return retval;
}

int amxb_get_supported(amxb_bus_ctx_t* const bus_ctx,
                       const char* object,
                       uint32_t flags,
                       amxc_var_t* values,
                       int timeout) {
    int retval = amxd_status_unknown_error;
    const amxb_be_funcs_t* fns = NULL;
    bool lobject = false;
    amxd_path_t path;
    char* fixed = NULL;
    const char* rel_path = NULL;
    timeout = amxb_get_minimal_timeout(timeout);

    amxd_path_init(&path, NULL);
    when_null(bus_ctx, exit);
    when_null(bus_ctx->bus_ctx, exit);

    amxd_path_setf(&path, true, "%s", object);
    fixed = amxd_path_get_fixed_part(&path, true);
    rel_path = amxd_path_get(&path, AMXD_OBJECT_TERMINATE);

    lobject = amxb_is_local_object(bus_ctx, fixed);
    fns = bus_ctx->bus_fn;

    if(lobject || !amxb_is_valid_be_func(fns, get_supported, fns->get_supported)) {
        retval = amxb_invoke_get_supported(bus_ctx, fixed, rel_path, flags,
                                           values, timeout);
    } else {
        if(bus_ctx->access == amxd_dm_access_protected) {
            flags |= AMXB_FLAG_PROTECTED;
        }
        retval = fns->get_supported(bus_ctx->bus_ctx, fixed, rel_path, flags,
                                    values, timeout);
    }

exit:
    amxb_log(bus_ctx, "get_supported", object, retval);
    free(fixed);
    amxd_path_clean(&path);
    return retval;
}
