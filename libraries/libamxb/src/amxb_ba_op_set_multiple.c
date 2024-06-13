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

static void amxb_filter_params(amxc_var_t* current,
                               amxc_var_t* parameters,
                               amxc_var_t* oparameters) {
    const amxc_htable_t* htparams = amxc_var_constcast(amxc_htable_t, parameters);
    const amxc_htable_t* htoparams = amxc_var_constcast(amxc_htable_t, oparameters);

    amxc_var_for_each(object, current) {
        amxc_var_for_each(param, object) {
            const char* pname = amxc_var_key(param);
            if(amxc_htable_contains(htparams, pname) ||
               amxc_htable_contains(htoparams, pname)) {
                continue;
            }
            amxc_var_delete(&param);
        }
    }
}

static void amxb_add_rollback(amxc_var_t* current,
                              amxc_var_t* rollback) {

    amxc_var_for_each(object, current) {
        const char* path = amxc_var_key(object);
        amxc_var_t* data = amxc_var_get_pathf(rollback, AMXC_VAR_FLAG_DEFAULT, "'%s'", path);
        if(data != NULL) {
            amxc_var_delete(&object);
            continue;
        }
        amxc_var_take_it(object);
        amxc_var_set_key(rollback, path, object, AMXC_VAR_FLAG_DEFAULT);
    }
}

static void amxb_set_result(const char* req_path,
                            amxc_var_t* ret,
                            amxc_var_t* sub_ret,
                            int rv) {
    amxc_var_for_each(result, sub_ret) {
        amxc_var_t* rp = amxc_var_add(amxc_htable_t, ret, NULL);
        amxc_var_add_key(cstring_t, rp, "path", req_path);
        amxc_var_add_key(uint32_t, rp, "status", rv);
        if(!amxc_htable_is_empty(amxc_var_constcast(amxc_htable_t, result))) {
            amxc_var_take_it(result);
            amxc_var_set_key(rp, "result", result, AMXC_VAR_FLAG_DEFAULT);
        }
    }
}

static void amxb_set_rollback(amxb_bus_ctx_t* const bus_ctx,
                              amxc_var_t* rollback) {
    amxc_var_t ret;
    amxc_var_init(&ret);

    amxc_var_for_each(params, rollback) {
        const char* path = amxc_var_key(params);
        amxc_var_clean(&ret);
        amxb_set(bus_ctx, path, params, &ret, amxb_get_internal_timeout());
        amxc_var_delete(&params);
    }

    amxc_var_clean(&ret);
}

int amxb_set_multiple(amxb_bus_ctx_t* const bus_ctx,
                      uint32_t flags,
                      amxc_var_t* req_paths,
                      amxc_var_t* ret,
                      int timeout) {
    int retval = amxd_status_unknown_error;
    amxc_var_t sub_ret;
    amxc_var_t rollback;
    amxc_var_t current;
    int count = 0;
    bool allow_partial = ((flags & AMXB_FLAG_PARTIAL) != 0);
    timeout = amxb_get_minimal_timeout(timeout);

    amxc_var_init(&sub_ret);
    amxc_var_init(&rollback);
    amxc_var_init(&current);
    amxc_var_set_type(ret, AMXC_VAR_ID_LIST);
    amxc_var_set_type(&rollback, AMXC_VAR_ID_HTABLE);

    when_false(amxc_var_type_of(req_paths) == AMXC_VAR_ID_LIST, exit);

    count = amxc_llist_size(amxc_var_constcast(amxc_llist_t, req_paths));

    retval = amxd_status_ok;

    amxc_var_for_each(req_path, req_paths) {
        int rv = 0;
        const char* object = GET_CHAR(req_path, "path");
        amxc_var_t* params = GET_ARG(req_path, "parameters");
        amxc_var_t* oparams = GET_ARG(req_path, "oparameters");
        if(!allow_partial && (count > 1)) {
            amxc_var_clean(&current);
            amxb_get(bus_ctx, object, 0, &current, amxb_get_internal_timeout());
            amxb_filter_params(GETI_ARG(&current, 0), params, oparams);
        }
        rv = amxb_set_impl(bus_ctx, object, flags, params, oparams, &sub_ret, timeout);

        if((rv != 0) && !allow_partial) {
            // reset return variant, only keep failed set
            amxc_var_set_type(ret, AMXC_VAR_ID_LIST);
        }

        // add results
        amxb_set_result(object, ret, &sub_ret, rv);

        // what is next? continue or fail.
        if(rv != 0) {
            if(!allow_partial) {
                if(count > 1) {
                    amxb_set_rollback(bus_ctx, &rollback);
                }
                retval = rv;
                break;
            }
        } else {
            if(!allow_partial && (count > 1)) {
                amxb_add_rollback(GETI_ARG(&current, 0), &rollback);
            }
        }

        amxc_var_clean(&sub_ret);
    }

exit:
    amxc_var_clean(&current);
    amxc_var_clean(&rollback);
    amxc_var_clean(&sub_ret);
    return retval;
}
