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

#include <ctype.h>

#include <amxc/amxc.h>
#include <amxp/amxp_signal.h>

#include <amxd/amxd_common.h>
#include <amxd/amxd_types.h>

#include "amxd_priv.h"
#include "amxd_assert.h"
#include "amxd_object_priv.h"

static const char* amxd_error_str[] = {
    "ok",
    "unknown error",
    "object not found",
    "function not found",
    "parameter not found",
    "function not implemented",
    "invalid function",
    "invalid function argument",
    "invalid name",
    "invalid attribute",
    "invalid value",
    "invalid action",
    "invalid type",
    "duplicate",
    "operation deferred",
    "is read only",
    "missing key value",
    "file not found",
    "invalid argument",
    "out of memory",
    "invalid recursion detected",
    "invalid path",
    "invalid expression",
    "permission denied",
    "not supported",
    "not in instantiated data model",
    "not a template object",
    "timeout",
    "last",
};

amxd_dm_cb_t* amxd_get_action(const amxc_llist_t* const cb_fns,
                              const amxd_action_t reason,
                              amxd_action_fn_t fn) {
    amxd_dm_cb_t* cb = NULL;
    amxc_llist_for_each(it, cb_fns) {
        cb = amxc_llist_it_get_data(it, amxd_dm_cb_t, it);
        if((cb->reason == reason) &&
           ((fn == NULL) || (cb->fn == fn))) {
            break;
        }
        cb = NULL;
    }

    return cb;
}

bool amxd_name_is_valid(const char* name) {
    bool retval = false;
    when_str_empty(name, exit);
    when_true(isalpha(name[0]) == 0 && name[0] != '_', exit);

    for(int i = 0; name[i] != 0; i++) {
        if(isalnum(name[i]) == 0) {
            if((name[i] != '_') && (name[i] != '-')) {
                goto exit;
            }
        }
    }

    retval = true;

exit:
    return retval;
}

const char* amxd_status_string(const amxd_status_t status) {
    if((status >= 0) && (status <= amxd_status_last)) {
        return amxd_error_str[status];
    }

    return amxd_error_str[1];
}

amxd_status_t amxd_action_describe_action(amxd_action_t reason,
                                          amxc_var_t* const retval,
                                          const char* description,
                                          void* priv) {
    amxd_status_t status = amxd_status_function_not_implemented;
    amxc_var_t* var_description = NULL;
    amxc_var_t* data = (amxc_var_t*) priv;

    when_true(reason != action_describe_action, exit);
    when_false(amxc_var_type_of(retval) == AMXC_VAR_ID_HTABLE, exit);

    var_description = amxc_var_add_new_key(retval, description);
    amxc_var_copy(var_description, data);
    status = amxd_status_ok;

exit:
    return status;
}
