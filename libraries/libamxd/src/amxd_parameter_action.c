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

#include <amxc/amxc.h>
#include <amxp/amxp_signal.h>

#include <amxd/amxd_types.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_parameter.h>

#include "amxd_priv.h"
#include "amxd_assert.h"

amxd_status_t amxd_param_add_action_cb(amxd_param_t* const param,
                                       const amxd_action_t reason,
                                       amxd_action_fn_t fn,
                                       void* priv) {
    amxd_status_t status = amxd_status_unknown_error;
    amxd_dm_cb_t* cb = NULL;
    when_null(param, exit);
    when_null(fn, exit);

    cb = amxd_get_action(&param->cb_fns, reason, fn);
    if((cb != NULL) && (cb->priv == priv)) {
        goto exit;
    }

    cb = (amxd_dm_cb_t*) calloc(1, sizeof(amxd_dm_cb_t));
    when_null(cb, exit);

    cb->fn = fn;
    cb->reason = reason;
    cb->priv = priv;
    cb->enable = true;

    amxc_llist_append(&param->cb_fns, &cb->it);
    status = amxd_status_ok;

exit:
    return status;
}

amxd_status_t amxd_param_remove_action_cb(amxd_param_t* const param,
                                          const amxd_action_t reason,
                                          amxd_action_fn_t fn) {
    amxd_status_t status = amxd_status_unknown_error;
    amxd_dm_cb_t* cb = NULL;
    when_null(param, exit);
    when_null(fn, exit);

    cb = amxd_get_action(&param->cb_fns, reason, fn);
    when_null(cb, exit);

    amxc_llist_it_take(&cb->it);
    free(cb);

    status = amxd_status_ok;

exit:
    return status;
}


void amxd_param_enable_action_cb(const amxd_param_t* const param,
                                 const amxd_action_t reason,
                                 amxd_action_fn_t fn,
                                 bool enable) {

    amxd_dm_cb_t* cb = NULL;
    when_null(param, exit);
    when_null(fn, exit);

    cb = amxd_get_action(&param->cb_fns, reason, fn);
    when_null(cb, exit);

    cb->enable = enable;

exit:
    return;
}

bool amxd_param_has_action_cb(amxd_param_t* const param,
                              const amxd_action_t reason,
                              amxd_action_fn_t fn) {
    bool has_cb = false;
    amxd_dm_cb_t* cb = NULL;
    when_null(param, exit);
    when_null(fn, exit);

    cb = amxd_get_action(&param->cb_fns, reason, fn);
    when_null(cb, exit);

    has_cb = true;

exit:
    return has_cb;
}

bool amxd_param_has_action(amxd_param_t* const param, const amxd_action_t reason) {
    bool has_cb = false;
    amxd_dm_cb_t* cb = NULL;
    amxd_object_t* super = NULL;
    amxd_param_t* current = NULL;
    when_null(param, exit);

    current = param;
    super = amxd_param_get_owner(current);
    while(current != NULL && super != NULL) {
        cb = amxd_get_action(&current->cb_fns, reason, NULL);
        if(cb != NULL) {
            has_cb = true;
            break;
        }

        if(amxd_object_get_type(super) == amxd_object_instance) {
            super = amxd_object_get_parent(super);
        } else {
            super = (super->derived_from.llist == NULL) ?
                NULL :
                amxc_container_of(super->derived_from.llist,
                                  amxd_object_t,
                                  derived_objects);
        }

        current = amxd_object_get_param_def(super, amxd_param_get_name(param));
    }

exit:
    return has_cb;
}

void* amxd_param_get_action_cb_data(amxd_param_t* const param,
                                    const amxd_action_t reason,
                                    amxd_action_fn_t fn) {
    amxd_dm_cb_t* cb = NULL;
    when_null(param, exit);
    when_null(fn, exit);

    cb = amxd_get_action(&param->cb_fns, reason, fn);

exit:
    if(cb != NULL) {
        return cb->priv;
    } else {
        return NULL;
    }
}

void amxd_param_set_action_cb_data(amxd_param_t* const param,
                                   const amxd_action_t reason,
                                   amxd_action_fn_t fn,
                                   void* data) {
    amxd_dm_cb_t* cb = NULL;
    when_null(param, exit);
    when_null(fn, exit);

    cb = amxd_get_action(&param->cb_fns, reason, fn);
    if(cb != NULL) {
        cb->priv = data;
    }

exit:
    return;
}