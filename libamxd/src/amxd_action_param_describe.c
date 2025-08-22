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

#include <amxc/amxc.h>
#include <amxp/amxp_signal.h>

#include <amxd/amxd_types.h>
#include <amxd/amxd_common.h>
#include <amxd/amxd_dm.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_action.h>
#include <amxd/amxd_parameter.h>

#include "amxd_priv.h"
#include "amxd_assert.h"

static void amxd_param_describe_actions(amxd_object_t* object,
                                        amxd_param_t* param,
                                        amxc_var_t* actions,
                                        amxd_action_t action) {
    amxc_llist_t* cb_fns = &param->cb_fns;
    amxd_object_t* super = NULL;
    amxd_param_t* super_param = NULL;

    when_null(object, exit);
    when_null(param, exit);

    amxc_llist_for_each(it, cb_fns) {
        amxd_dm_cb_t* cb_fn = amxc_llist_it_get_data(it, amxd_dm_cb_t, it);
        if(cb_fn->reason != action) {
            continue;
        }
        cb_fn->fn(object, param, action_describe_action, NULL, actions, cb_fn->priv);
    }

    when_false(amxc_htable_is_empty(amxc_var_constcast(amxc_htable_t, actions)), exit);

    if(amxd_object_get_type(object) == amxd_object_instance) {
        super = amxd_object_get_parent(object);
    } else {
        super = (object->derived_from.llist == NULL) ?
            NULL :
            amxc_container_of(object->derived_from.llist,
                              amxd_object_t,
                              derived_objects);
    }
    if(super != NULL) {
        super_param = amxd_object_get_param_def(object, amxd_param_get_name(param));
        if(super_param != NULL) {
            amxd_param_describe_actions(super, super_param, actions, action);
        }
    }

exit:
    return;
}

void amxd_param_build_description(amxc_var_t* description,
                                  const char* name,
                                  uint32_t type_id,
                                  uint32_t attrs,
                                  amxc_var_t* flags) {
    static const char* attr_name[] = {
        "template", "instance", "private", "read-only", "persistent",
        "volatile", "counter", "key", "unique", "protected", "mutable"
    };
    amxc_var_t* subvar = NULL;
    amxc_var_set_type(description, AMXC_VAR_ID_HTABLE);

    amxc_var_add_key(cstring_t, description, "name", name);
    amxc_var_add_key(uint32_t, description, "type_id", type_id);
    amxc_var_add_key(cstring_t, description, "type_name", amxc_var_get_type_name_from_id(type_id));
    amxc_var_add_new_key(description, "value");
    subvar = amxc_var_add_key(amxc_htable_t, description, "attributes", NULL);
    for(int i = 0; i <= amxd_pattr_max; i++) {
        amxc_var_add_key(bool, subvar, attr_name[i], IS_BIT_SET(attrs, i));
    }
    subvar = amxc_var_add_key(amxc_llist_t, description, "flags", NULL);
    if(flags != NULL) {
        const amxc_htable_t* ht_flags = amxc_var_constcast(amxc_htable_t, flags);
        amxc_htable_iterate(it, ht_flags) {
            amxc_var_t* flag = amxc_var_from_htable_it(it);
            if(amxc_var_dyncast(bool, flag)) {
                amxc_var_add(cstring_t, subvar, amxc_htable_it_get_key(it));
            }
        }
    }
}

amxd_status_t amxd_action_param_describe(amxd_object_t* object,
                                         amxd_param_t* param,
                                         amxd_action_t reason,
                                         const amxc_var_t* const args,
                                         amxc_var_t* const retval,
                                         UNUSED void* priv) {
    amxd_status_t status = amxd_status_unknown_error;
    amxc_var_t* value = NULL;
    amxc_var_t* constraints = NULL;

    when_null(param, exit);
    when_null(retval, exit);

    when_true_status(reason != action_param_describe,
                     exit,
                     status = amxd_status_function_not_implemented);

    amxd_param_build_description(retval,
                                 amxd_param_get_name(param),
                                 amxd_param_get_type(param),
                                 amxd_param_get_attrs(param),
                                 param->flags);

    constraints = amxc_var_add_key(amxc_htable_t, retval, "validate", NULL);
    amxd_param_describe_actions(object, param, constraints, action_param_validate);
    if(amxc_htable_is_empty(amxc_var_constcast(amxc_htable_t, constraints))) {
        amxc_var_delete((&constraints));
    }

    if((GET_ARG(args, "no-param-value") == NULL) || !GET_BOOL(args, "no-param-value")) {
        value = amxc_var_get_key(retval, "value", AMXC_VAR_FLAG_DEFAULT);
        amxd_dm_invoke_action(object, param, action_param_read, args, value);
    }

    status = amxd_status_ok;

exit:
    return status;
}

amxd_status_t amxd_param_describe(amxd_param_t* const param,
                                  amxc_var_t* const value) {
    amxd_status_t retval = amxd_status_unknown_error;
    amxd_object_t* object = NULL;

    when_null(param, exit);
    when_null(value, exit);

    object = amxd_param_get_owner(param);
    retval = amxd_dm_invoke_action(object,
                                   param,
                                   action_param_describe,
                                   NULL,
                                   value);

exit:
    return retval;
}
