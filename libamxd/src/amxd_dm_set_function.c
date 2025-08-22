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

#include "amxd_priv.h"

#include <amxd/amxd_dm.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_path.h>
#include <amxd/amxd_dm_functions.h>
#include <amxd/amxd_transaction.h>

#include "amxd_assert.h"
#include "amxd_object_priv.h"
#include "amxd_dm_priv.h"

static void amxd_add_set(amxd_object_t* object,
                         amxd_trans_t* transaction,
                         amxc_var_t* args) {
    amxd_trans_select_object(transaction, object);
    amxd_trans_add_action(transaction, action_object_write, args);
}

static void amxd_add_result(amxc_var_t* result,
                            amxc_var_t* retval,
                            amxd_status_t status) {
    amxc_var_for_each(r, result) {
        const char* path = amxc_var_key(r);
        amxc_var_t* updated_params = GET_ARG(retval, path);

        if(updated_params == NULL) {
            updated_params = amxc_var_add_key(amxc_htable_t, retval, path, NULL);
        }
        amxc_var_for_each(param, GET_ARG(r, "parameters")) {
            const char* param_name = amxc_var_key(param);
            amxc_var_take_it(param);
            if(status != amxd_status_ok) {
                if(!GET_BOOL(param, "required") ||
                   (amxc_var_type_of(param) != AMXC_VAR_ID_HTABLE)) {
                    amxc_var_delete(&param);
                    continue;
                }
            }
            amxc_var_set_key(updated_params, param_name, param, AMXC_VAR_FLAG_DEFAULT);
        }
        if(amxc_htable_is_empty(amxc_var_constcast(amxc_htable_t, updated_params))) {
            amxc_var_delete(&updated_params);
        }
    }
}

amxd_status_t amxd_object_func_set(amxd_object_t* object,
                                   UNUSED amxd_function_t* func,
                                   amxc_var_t* args,
                                   amxc_var_t* ret) {
    amxd_status_t retval = amxd_status_unknown_error;
    amxc_var_t* var_rel_path = GET_ARG(args, "rel_path");
    const char* rel_path = GET_CHAR(var_rel_path, NULL);
    amxc_llist_t paths;
    amxd_dm_t* dm = amxd_object_get_dm(object);
    amxd_trans_t transaction;

    amxd_def_funcs_remove_args(args);
    amxd_trans_init(&transaction);
    amxc_llist_init(&paths);
    amxc_var_set_type(ret, AMXC_VAR_ID_HTABLE);

    amxc_var_take_it(var_rel_path);
    if((rel_path != NULL) && (*rel_path != 0)) {
        retval = amxd_object_resolve_pathf(object, &paths, "%s", rel_path);
        when_failed(retval, exit);
        if(amxc_llist_is_empty(&paths)) {
            retval = amxd_status_object_not_found;
            goto exit;
        }
        amxc_llist_for_each(it, (&paths)) {
            amxc_string_t* path = amxc_string_from_llist_it(it);
            object = amxd_dm_findf(dm, "%s", amxc_string_get(path, 0));
            amxd_add_set(object, &transaction, args);
        }
    } else {
        amxd_add_set(object, &transaction, args);
    }

    retval = amxd_trans_apply(&transaction, amxd_object_get_dm(object));

    if((rel_path != NULL) && (*rel_path != 0)) {
        uint32_t index = 1;
        amxc_llist_for_each(it, (&paths)) {
            amxc_var_t* result = GETI_ARG(&transaction.retvals, index);
            amxd_add_result(result, ret, retval);
            index += 2;
        }
    } else {
        amxc_var_t* result = GETI_ARG(&transaction.retvals, 1);
        amxd_add_result(result, ret, retval);
    }

    if(amxc_htable_is_empty(amxc_var_constcast(amxc_htable_t, ret))) {
        amxc_var_set_type(ret, AMXC_VAR_ID_NULL);
    }

exit:
    amxc_var_delete(&var_rel_path);
    amxc_llist_clean(&paths, amxc_string_list_it_free);
    amxd_trans_clean(&transaction);
    return retval;
}
