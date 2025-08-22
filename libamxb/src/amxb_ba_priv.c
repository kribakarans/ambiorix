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
#include <errno.h>
#include <fcntl.h>
#include <string.h>

#include <amxc/amxc.h>
#include <amxp/amxp.h>

#include <amxd/amxd_dm.h>
#include <amxd/amxd_object.h>

#include <amxb/amxb_be_intf.h>
#include <amxb/amxb.h>
#include <amxd/amxd_path.h>

#include "amxb_priv.h"

void amxb_dm_event_to_object_event(const char* const sig_name,
                                   const amxc_var_t* const data,
                                   void* const priv) {
    amxc_htable_it_t* sub_hit = (amxc_htable_it_t*) priv;
    const char* subscriber_object = amxc_htable_it_get_key(sub_hit);
    amxb_bus_ctx_t* ctx = amxc_container_of(sub_hit->ait->array, amxb_bus_ctx_t, subscriptions);

    amxc_var_add_key(cstring_t, (amxc_var_t*) data, "notification", sig_name);
    amxp_sigmngr_emit_signal(&ctx->sigmngr, subscriber_object, data);
}

amxd_object_t* amxb_fetch_local_object(amxb_bus_ctx_t* ctx,
                                       const char* obj_path) {
    amxd_dm_t* dm = ctx->dm;
    amxd_object_t* object = amxd_dm_findf(dm, "%s", obj_path);
    return object;
}

bool amxb_is_local_object(amxb_bus_ctx_t* ctx,
                          const char* obj_path) {
    amxd_dm_t* dm = ctx->dm;
    amxd_path_t path;
    amxd_object_t* object = NULL;

    amxd_path_init(&path, NULL);
    amxd_path_setf(&path, true, "%s", obj_path);
    when_null(dm, exit);

    while(object == NULL && !amxc_string_is_empty(&path.path)) {
        char* part = NULL;
        object = amxd_dm_findf(dm, "%s", amxd_path_get(&path, AMXD_OBJECT_TERMINATE));
        part = amxd_path_get_last(&path, true);
        free(part);
    }

exit:
    amxd_path_clean(&path);
    return object != NULL;
}

int amxb_follow_reference(amxb_bus_ctx_t* const bus_ctx,
                          amxd_path_t* reference,
                          int timeout) {
    int retval = amxd_status_unknown_error;
    amxc_var_t resolved;
    char* ref = amxd_path_get_reference_part(reference, true);
    uint32_t index = amxd_path_get_reference_index(reference);
    amxd_path_t ref_path;
    amxc_var_t* real_path = NULL;

    amxd_path_init(&ref_path, ref);
    amxc_var_init(&resolved);

    when_true(index == 0, exit);
    when_str_empty(amxd_path_get_param(&ref_path), exit);
    retval = amxb_get(bus_ctx, ref, 0, &resolved, timeout);
    when_failed(retval, exit);

    when_true(amxc_htable_size(amxc_var_constcast(amxc_htable_t, GETP_ARG(&resolved, "0"))) > 1, exit);

    real_path = amxc_var_get_pathf(&resolved, AMXC_VAR_FLAG_DEFAULT,
                                   "0.0.%s",
                                   amxd_path_get_param(&ref_path));

    amxc_var_cast(real_path, AMXC_VAR_ID_CSV_STRING);
    amxc_var_cast(real_path, AMXC_VAR_ID_LIST);

    if(index - 1 >= amxc_llist_size(amxc_var_constcast(amxc_llist_t, real_path))) {
        goto exit;
    }

    amxd_path_setf(&ref_path, true, "%s", GETI_CHAR(real_path, index - 1));
    amxd_path_prepend(reference, amxd_path_get(&ref_path, 0));

exit:
    amxd_path_clean(&ref_path);
    free(ref);
    amxc_var_clean(&resolved);
    return retval;
}

uint32_t amxb_be_get_capabilities(amxb_bus_ctx_t* bus_ctx) {
    uint32_t caps = AMXB_BE_DISCOVER_DESCRIBE | AMXB_BE_DISCOVER_LIST | AMXB_BE_DISCOVER_RESOLVE;
    const amxb_be_funcs_t* fns = NULL;

    when_null(bus_ctx, exit);
    fns = bus_ctx->bus_fn;

    if(amxb_is_valid_be_func(fns, capabilities, fns->capabilities)) {
        caps = fns->capabilities(bus_ctx->bus_ctx);
    }

exit:
    return caps;
}
