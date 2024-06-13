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
#include <string.h>
#include <ctype.h>

#include <amxc/amxc.h>

#include <amxp/amxp_signal.h>
#include <amxp/amxp_slot.h>

#include <amxd/amxd_common.h>
#include <amxd/amxd_types.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_function.h>

#include "amxd_priv.h"
#include "amxd_assert.h"
#include "amxd_dm_priv.h"

static amxc_llist_t deferred;
static uint64_t g_call_id;

static void amxd_delete_deferred(amxc_llist_it_t* it) {
    amxd_deferred_ctx_t* data = amxc_container_of(it, amxd_deferred_ctx_t, it);
    amxc_llist_it_take(it);
    amxc_llist_it_take(&data->dm_it);
    free(data);
}

static void amxd_cancel_deferred(amxd_deferred_ctx_t* call, amxc_var_t* sig_data) {
    if(call->cancel != NULL) {
        call->cancel(call->call_id, call->called_priv);
    }
    if(call->cb != NULL) {
        call->cb(sig_data, call->caller_priv);
    }
}

amxd_deferred_ctx_t* amxd_find_deferred(uint64_t call_id) {
    amxd_deferred_ctx_t* data = NULL;
    amxc_llist_for_each(it, &deferred) {
        data = amxc_container_of(it, amxd_deferred_ctx_t, it);
        if(data->call_id == call_id) {
            break;
        }
        data = NULL;
    }

    return data;
}

void amxd_dm_cancel_deferred(amxd_dm_t* dm) {
    amxc_var_t sig_data;

    amxc_var_init(&sig_data);
    amxc_var_set_type(&sig_data, AMXC_VAR_ID_HTABLE);
    amxc_var_add_new_key(&sig_data, "retval");
    amxc_var_add_key(uint32_t, &sig_data, "status", amxd_status_unknown_error);

    amxc_llist_for_each(it, &dm->deferred) {
        amxd_deferred_ctx_t* call = amxc_container_of(it, amxd_deferred_ctx_t, dm_it);
        amxd_cancel_deferred(call, &sig_data);
        amxd_delete_deferred(&call->it);
    }

    amxc_var_clean(&sig_data);
}

amxd_status_t amxd_function_defer(const amxd_function_t* const func,
                                  uint64_t* call_id,
                                  amxc_var_t* const ret,
                                  amxd_deferred_cancel_t cancel_fn,
                                  void* priv) {
    amxd_status_t status = amxd_status_unknown_error;
    amxd_deferred_ctx_t* call = NULL;

    when_null(func, exit);
    when_null(ret, exit);
    when_null(call_id, exit)

    call = (amxd_deferred_ctx_t*) calloc(1, sizeof(amxd_deferred_ctx_t));
    when_null(call, exit);

    call->call_id = g_call_id++;
    call->called_priv = priv;
    call->cancel = cancel_fn;
    amxc_llist_append(&deferred, &call->it);
    amxc_var_set(uint64_t, ret, call->call_id);
    *call_id = call->call_id;

    status = amxd_status_ok;

exit:
    return status;
}

void amxd_function_deferred_remove(uint64_t call_id) {
    amxd_deferred_ctx_t* call = amxd_find_deferred(call_id);
    amxc_var_t sig_data;

    amxc_var_init(&sig_data);
    when_null(call, exit);

    amxc_var_set_type(&sig_data, AMXC_VAR_ID_HTABLE);
    amxc_var_add_new_key(&sig_data, "retval");
    amxc_var_add_key(uint32_t, &sig_data, "status", amxd_status_unknown_error);

    amxd_cancel_deferred(call, &sig_data);
    amxd_delete_deferred(&call->it);

exit:
    amxc_var_clean(&sig_data);
    return;
}

void* amxd_function_deferred_get_priv(uint64_t call_id) {
    void* data = NULL;
    amxd_deferred_ctx_t* call = amxd_find_deferred(call_id);

    when_null(call, exit);
    data = call->called_priv;

exit:
    return data;
}

amxd_status_t amxd_function_set_deferred_cb(uint64_t call_id,
                                            amxp_deferred_fn_t cb,
                                            void* priv) {
    amxd_status_t rv = amxd_status_invalid_function;
    amxd_deferred_ctx_t* call = amxd_find_deferred(call_id);

    when_null(call, exit);

    call->cb = cb;
    call->caller_priv = priv;

    rv = amxd_status_ok;

exit:
    return rv;
}

static amxd_status_t amxd_function_deferred_done_impl(uint64_t call_id,
                                                      amxd_status_t status,
                                                      amxc_var_t* out_args,
                                                      amxc_var_t* ret,
                                                      bool now) {
    amxd_status_t rv = amxd_status_unknown_error;
    amxc_var_t sig_data;
    amxd_deferred_ctx_t* call = amxd_find_deferred(call_id);

    amxc_var_init(&sig_data);

    when_null(call, exit);
    when_null_status(call->cb, exit, rv = amxd_status_ok);

    amxc_var_set_type(&sig_data, AMXC_VAR_ID_HTABLE);
    if(ret != NULL) {
        amxc_var_set_key(&sig_data, "retval", ret, AMXC_VAR_FLAG_COPY);
    } else {
        amxc_var_add_new_key(&sig_data, "retval");
    }
    if(out_args != NULL) {
        amxc_var_set_key(&sig_data, "args", out_args, AMXC_VAR_FLAG_COPY);
    }
    amxc_var_add_key(uint32_t, &sig_data, "status", status);

    if(now) {
        call->cb(&sig_data, call->caller_priv);
    } else {
        amxp_sigmngr_deferred_call(NULL, call->cb, &sig_data, call->caller_priv);
    }

    rv = amxd_status_ok;

exit:
    if(call != NULL) {
        amxd_delete_deferred(&call->it);
    }
    amxc_var_clean(&sig_data);
    return rv;
}

amxd_status_t amxd_function_deferred_done(uint64_t call_id,
                                          amxd_status_t status,
                                          amxc_var_t* out_args,
                                          amxc_var_t* ret) {
    return amxd_function_deferred_done_impl(call_id, status, out_args, ret, false);
}

amxd_status_t amxd_function_deferred_call_done(uint64_t call_id,
                                               amxd_status_t status,
                                               amxc_var_t* out_args,
                                               amxc_var_t* ret) {
    return amxd_function_deferred_done_impl(call_id, status, out_args, ret, true);
}


static CONSTRUCTOR void amxd_function_deferred_init(void) {
    amxc_llist_init(&deferred);
}
