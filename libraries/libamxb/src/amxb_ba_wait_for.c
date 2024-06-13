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

#include <syslog.h>
#include <stdlib.h>
#include <unistd.h>

#include <amxc/amxc.h>
#include <amxp/amxp.h>

#include <amxd/amxd_common.h>
#include <amxd/amxd_dm.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_object_event.h>
#include <amxd/amxd_path.h>

#include <amxb/amxb_be_intf.h>
#include <amxb/amxb.h>

#include "amxb_priv.h"

static int32_t wait_for_objects = 0;

static void amxb_wait_object_available(const char* const sig_name,
                                       UNUSED const amxc_var_t* const data,
                                       UNUSED void* const priv) {
    amxp_signal_t* signal = NULL;
    syslog(LOG_USER | LOG_NOTICE, "object '%s' available", sig_name + 5);
    signal = amxp_sigmngr_find_signal(NULL, sig_name);
    amxp_signal_delete(&signal);

    wait_for_objects--;
    if(wait_for_objects <= 0) {
        wait_for_objects = 0;
        amxp_sigmngr_emit_signal(NULL, "wait:done", NULL);
    }
}

static int amxb_wait_for_impl(amxb_bus_ctx_t* bus_ctx,
                              UNUSED const amxc_var_t* args,
                              void* priv) {
    int retval = 0;
    const amxb_be_funcs_t* fns = NULL;
    const char* object = (const char*) priv;

    fns = bus_ctx->bus_fn;
    if(amxb_is_valid_be_func(fns, wait_for, fns->wait_for)) {
        retval = fns->wait_for(bus_ctx->bus_ctx, object);
    } else {
        retval = AMXB_ERROR_NOT_SUPPORTED_OP;
    }

    return retval;
}

int amxb_wait_for_object(const char* object) {
    int retval = -1;
    amxd_path_t path;
    char* object_path = NULL;
    amxb_bus_ctx_t* bus_ctx = NULL;
    amxc_string_t signal_name;
    amxp_signal_t* signal = NULL;

    amxd_path_init(&path, NULL);
    amxc_string_init(&signal_name, 0);

    when_str_empty(object, exit);

    amxd_path_setf(&path, true, "%s", object);
    object_path = amxd_path_get_fixed_part(&path, AMXD_OBJECT_TERMINATE);
    amxc_string_setf(&signal_name, "wait:%s", object_path);

    signal = amxp_sigmngr_find_signal(NULL, amxc_string_get(&signal_name, 0));
    if(signal == NULL) {
        retval = amxp_signal_new(NULL, &signal, amxc_string_get(&signal_name, 0));
        when_failed(retval, exit);
        amxp_slot_connect(NULL, amxc_string_get(&signal_name, 0), NULL,
                          amxb_wait_object_available, NULL);
        wait_for_objects++;
    }

    // When waiting for an object, make sure that the exact full path is matched
    // remove entry from the cache and check again with full path matching
    // full path is the fixed part (no wildcard or search parts)
    amxb_be_cache_remove_path(object_path);
    bus_ctx = amxb_be_who_has_ex(object_path, true);
    if(bus_ctx != NULL) {
        amxp_signal_emit(signal, NULL);
        retval = 0;
    } else {
        retval = amxb_be_for_all_connections(amxb_wait_for_impl, NULL, (void*) object_path);
    }

exit:
    free(object_path);
    amxc_string_clean(&signal_name);
    amxd_path_clean(&path);
    return retval;
}
