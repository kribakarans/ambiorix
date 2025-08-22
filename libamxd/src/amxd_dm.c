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
#include <string.h>

#include "amxd_priv.h"

#include <amxd/amxd_dm.h>
#include <amxd/amxd_action.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_path.h>

#include "amxd_dm_priv.h"
#include "amxd_object_priv.h"
#include "amxd_assert.h"

static amxd_action_fn_t default_actions[] = {
    NULL,                        // action_any
    amxd_action_param_read,      // action_param_read
    amxd_action_param_write,     // action_param_write
    amxd_action_param_validate,  // action_param_validate
    amxd_action_param_describe,  // action_param_describe
    amxd_action_param_destroy,   // action_param_destroy
    amxd_action_object_read,     // action_object_read
    amxd_action_object_write,    // action_object_write
    amxd_action_object_validate, // action_object_validate
    amxd_action_object_list,     // action_object_list
    amxd_action_object_describe, // action_object_describe
    NULL,                        // action_object_tree
    amxd_action_object_add_inst, // action_object_add_inst
    amxd_action_object_del_inst, // action_object_del_inst
    amxd_action_object_destroy,  // action_object_destroy
};

static void amxd_dm_free_mib_object_it(amxc_llist_it_t* it) {
    amxd_object_t* object = amxc_llist_it_get_data(it, amxd_object_t, it);
    amxd_object_free(&object);
}

static amxd_status_t amxd_dm_invoke_action_impl(amxc_llist_t* fns,
                                                amxd_object_t* object,
                                                amxd_param_t* param,
                                                amxd_action_t reason,
                                                const amxc_var_t* const args,
                                                amxc_var_t* const retval) {
    amxd_status_t status = amxd_status_function_not_implemented;
    amxc_var_clean(retval);
    amxc_llist_for_each(it, fns) {
        amxd_dm_cb_t* cb_fn = amxc_llist_it_get_data(it, amxd_dm_cb_t, it);
        if((cb_fn->reason != action_any) &&
           ((cb_fn->reason != reason) ||
            ( cb_fn->fn == NULL) ||
            ( !cb_fn->enable))) {
            continue;
        }
        status = cb_fn->fn(object, param, reason, args, retval, cb_fn->priv);
        if((reason == action_object_destroy) ||
           ( reason == action_param_destroy)) {
            if(((object != NULL) && amxd_object_has_action_cb(object, reason, cb_fn->fn)) ||
               (( param != NULL) && amxd_param_has_action_cb(param, reason, cb_fn->fn))) {
                amxc_llist_it_take(&cb_fn->it);
                free(it);
            }
            status = amxd_status_ok;
            continue;
        }
        if((status != amxd_status_ok) &&
           ( status != amxd_status_function_not_implemented)) {
            break;
        }
    }

    return status;
}

static amxd_status_t amxd_dm_invoke_action_base(amxd_object_t* const object,
                                                amxd_param_t* const param,
                                                amxd_action_t reason,
                                                const amxc_var_t* const args,
                                                amxc_var_t* const retval) {
    amxd_status_t status = amxd_status_function_not_implemented;
    amxd_object_t* super = object;
    amxc_llist_t* cb_fns = NULL;

    while(super != NULL) {
        if(amxd_object_get_type(super) == amxd_object_instance) {
            super = amxd_object_get_parent(super);
        } else {
            super = (super->derived_from.llist == NULL) ?
                NULL :
                amxc_container_of(super->derived_from.llist,
                                  amxd_object_t,
                                  derived_objects);
        }

        if(param != NULL) {
            amxd_param_t* base_param =
                amxd_object_get_param_def(super,
                                          amxd_param_get_name(param));
            cb_fns = (base_param == NULL) ? NULL : &base_param->cb_fns;
        } else {
            cb_fns = (super == NULL) ? NULL : &super->cb_fns;
        }

        if(cb_fns != NULL) {
            status = amxd_dm_invoke_action_impl(cb_fns,
                                                object,
                                                param,
                                                reason,
                                                args,
                                                retval);
            if(status == amxd_status_function_not_implemented) {
                continue;
            }
            break;
        }
    }

    return status;
}

static bool amxd_dm_can_invoke_action(int counter,
                                      amxd_action_t reason,
                                      amxd_object_t* current,
                                      amxd_object_t* object) {
    bool retval = false;
    if(counter == 0) {
        retval = true;
    } else if(counter < INT32_MAX) {
        switch(reason) {
        case action_object_read:
        case action_object_list:
        case action_object_validate:
        case action_object_describe:
        case action_param_read:
        case action_param_describe:
        case action_param_validate:
            retval = true;
            break;
        case action_object_destroy:
            retval = (amxd_object_get_parent(object) == NULL ||
                      amxd_object_is_child_of(object, current));
            if(retval) {
                retval = !amxd_object_is_child_of(current, object);
            }
            break;
        case action_object_del_inst:
            retval = amxd_object_is_child_of(object, current);
            break;
        default:
            break;
        }
    }
    return retval;
}

static amxd_status_t amxd_dm_invoke_default(amxd_object_t* const object,
                                            amxd_param_t* const param,
                                            amxd_action_t reason,
                                            const amxc_var_t* const args,
                                            amxc_var_t* const retval) {
    amxd_status_t status =
        amxd_dm_invoke_action_base(object, param, reason, args, retval);
    if((status == amxd_status_function_not_implemented) &&
       ( default_actions[reason] != NULL)) {
        status = default_actions[reason](object,
                                         param,
                                         reason,
                                         args,
                                         retval,
                                         NULL);
    }

    return status;
}

static amxd_status_t amxd_dm_check_add_inst_retval(amxc_var_t* retval) {
    amxd_status_t status = amxd_status_ok;
    amxc_var_t* tmp = NULL;

    tmp = amxc_var_get_path(retval, "index", AMXC_VAR_FLAG_DEFAULT);
    when_true_status(amxc_var_is_null(tmp),
                     exit,
                     status = amxd_status_invalid_name);

    tmp = amxc_var_get_path(retval, "name", AMXC_VAR_FLAG_DEFAULT);
    when_true_status(amxc_var_is_null(tmp),
                     exit,
                     status = amxd_status_invalid_name);

exit:
    return status;
}

static void amxd_dm_cleanup_add_inst(amxd_object_t* object,
                                     amxc_var_t* retval) {
    uint32_t index = 0;
    amxd_object_t* inst = NULL;
    amxc_var_t* var_index = NULL;
    when_true(amxc_var_is_null(retval), exit);

    var_index = amxc_var_get_path(retval, "index", AMXC_VAR_FLAG_DEFAULT);
    index = amxc_var_dyncast(uint32_t, var_index);
    when_true(index == 0, exit);

    inst = amxd_object_get_instance(object, NULL, index);
    amxd_object_free(&inst);

exit:
    return;
}

static void amxd_dm_invoke_action_start(UNUSED amxd_object_t* object,
                                        UNUSED amxd_param_t* param,
                                        amxd_action_t reason) {
    switch(reason) {
    case action_object_destroy:
        amxd_object_destroy_handlers(object);
        break;
    default:
        break;
    }
}

static amxd_status_t amxd_dm_invoke_action_end(amxd_object_t* object,
                                               amxd_param_t* param,
                                               amxd_status_t status,
                                               amxd_action_t reason,
                                               amxc_var_t* retval) {
    amxd_status_t new_status = status;
    switch(reason) {
    case action_object_destroy:
        amxd_object_free(&object);
        new_status = amxd_status_ok;
        break;
    case action_param_destroy:
        amxd_param_free(&param);
        new_status = amxd_status_ok;
        break;
    case action_object_add_inst:
        if(status == amxd_status_ok) {
            new_status = amxd_dm_check_add_inst_retval(retval);
        } else {
            amxd_dm_cleanup_add_inst(object, retval);
        }
        break;
    default:
        break;
    }

    return new_status;
}

amxd_status_t amxd_dm_new(amxd_dm_t** dm) {
    amxd_status_t retval = amxd_status_unknown_error;

    when_null(dm, exit);
    when_not_null((*dm), exit);

    *dm = (amxd_dm_t*) calloc(1, sizeof(amxd_dm_t));
    when_null((*dm), exit);

    retval = amxd_dm_init((*dm));

exit:
    return retval;
}

void amxd_dm_delete(amxd_dm_t** dm) {
    when_null(dm, exit);
    when_null((*dm), exit);

    amxd_dm_clean((*dm));

    free((*dm));
    *dm = NULL;

exit:
    return;
}

amxd_status_t amxd_dm_init(amxd_dm_t* dm) {
    amxd_status_t retval = amxd_status_unknown_error;

    when_null(dm, exit);

    amxd_init_base();

    when_failed(amxd_object_init(&dm->object, amxd_object_root, NULL, NULL, NULL), exit);
    when_failed(amxp_sigmngr_init(&dm->sigmngr), exit);
    when_failed(amxc_llist_init(&dm->mibs), exit);
    when_failed(amxc_llist_init(&dm->deferred), exit);

    when_failed(amxp_sigmngr_add_signal(&dm->sigmngr, "dm:root-added"), exit);
    when_failed(amxp_sigmngr_add_signal(&dm->sigmngr, "dm:root-removed"), exit);
    when_failed(amxp_sigmngr_add_signal(&dm->sigmngr, "dm:object-added"), exit);
    when_failed(amxp_sigmngr_add_signal(&dm->sigmngr, "dm:object-removed"), exit);
    when_failed(amxp_sigmngr_add_signal(&dm->sigmngr, "dm:instance-added"), exit);
    when_failed(amxp_sigmngr_add_signal(&dm->sigmngr, "dm:instance-removed"), exit);
    when_failed(amxp_sigmngr_add_signal(&dm->sigmngr, "dm:object-changed"), exit);
    when_failed(amxp_sigmngr_add_signal(&dm->sigmngr, "dm:periodic-inform"), exit);
    when_failed(amxp_sigmngr_add_signal(&dm->sigmngr, "dm:mib-added"), exit);
    when_failed(amxp_sigmngr_add_signal(&dm->sigmngr, "dm:mib-removed"), exit);
    when_failed(amxp_sigmngr_add_signal(&dm->sigmngr, "app:start"), exit);
    when_failed(amxp_sigmngr_add_signal(&dm->sigmngr, "app:stop"), exit);

    retval = amxd_status_ok;

exit:
    return retval;
}

void amxd_dm_clean(amxd_dm_t* dm) {
    when_null(dm, exit);

    amxd_dm_cancel_deferred(dm);
    amxd_dm_invoke_action_impl(&dm->object.cb_fns, &dm->object, NULL, action_object_destroy, NULL, NULL);
    amxd_object_clean(&dm->object);
    amxp_sigmngr_clean(&dm->sigmngr);
    amxc_llist_clean(&dm->mibs, amxd_dm_free_mib_object_it);

exit:
    return;
}

amxd_status_t amxd_dm_store_mib(amxd_dm_t* const dm,
                                amxd_object_t* const object) {
    amxd_status_t retval = amxd_status_unknown_error;
    const char* mib_name = NULL;
    when_null(dm, exit);
    when_null(object, exit);
    when_true(amxd_object_get_type(object) != amxd_object_mib, exit);
    mib_name = amxd_object_get_name(object, AMXD_OBJECT_NAMED);
    when_true_status(amxd_dm_get_mib(dm, mib_name) != NULL,
                     exit,
                     retval = amxd_status_duplicate);

    amxc_llist_append(&dm->mibs, &object->it);

    retval = amxd_status_ok;
exit:
    return retval;
}

amxd_object_t* amxd_dm_get_mib(amxd_dm_t* const dm,
                               const char* name) {
    amxd_object_t* mib = NULL;

    when_null(dm, exit);
    when_str_empty(name, exit);

    amxc_llist_for_each(it, (&dm->mibs)) {
        const char* mib_name = NULL;
        mib = amxc_llist_it_get_data(it, amxd_object_t, it);
        mib_name = amxd_object_get_name(mib, AMXD_OBJECT_NAMED);
        if((mib_name != NULL) && (strcmp(mib_name, name) == 0)) {
            break;
        }
        mib = NULL;
    }

exit:
    return mib;
}

amxd_status_t amxd_dm_add_root_object(amxd_dm_t* dm, amxd_object_t* object) {
    amxd_status_t retval = amxd_status_unknown_error;

    when_null(dm, exit);
    when_null(object, exit);

    retval = amxd_object_add_object(&dm->object, object);
    if(retval == 0) {
        amxd_dm_event("dm:root-added", object, NULL, false);
    }

exit:
    return retval;
}

amxd_status_t amxd_dm_remove_root_object(amxd_dm_t* dm, const char* name) {
    amxd_status_t retval = amxd_status_unknown_error;
    amxd_object_t* object = NULL;
    amxc_var_t data;

    amxc_var_init(&data);

    when_null(dm, exit);
    when_str_empty_status(name, exit, retval = amxd_status_invalid_name);

    object = amxd_object_get_child(&dm->object, name);
    when_null_status(object, exit, retval = amxd_status_object_not_found);

    amxd_dm_event("dm:root-removed", object, NULL, false);

    amxd_object_delete(&object);

    retval = amxd_status_ok;
exit:
    amxc_var_clean(&data);
    return retval;
}

amxd_object_t* amxd_dm_get_root(amxd_dm_t* const dm) {
    amxd_object_t* object = NULL;

    when_null(dm, exit);
    object = &dm->object;

exit:
    return object;
}

amxd_object_t* amxd_dm_get_object(amxd_dm_t* const dm, const char* name) {
    return amxd_object_get_child(&dm->object, name);
}

amxd_object_t* amxd_dm_findf(amxd_dm_t* const dm,
                             const char* abs_path,
                             ...) {
    amxd_object_t* object = NULL;
    amxd_object_t* root_obj = NULL;
    amxd_status_t status = amxd_status_ok;
    amxd_path_t path;
    va_list args;
    bool key_path = false;

    amxd_path_init(&path, NULL);

    when_null(dm, exit);
    root_obj = amxd_dm_get_root(dm);

    when_str_empty_status(abs_path, exit, object = root_obj);

    va_start(args, abs_path);
    status = amxd_path_vsetf(&path, true, abs_path, args);
    va_end(args);
    dm->status = status;
    when_failed(status, exit);

    object = amxd_object_find_internal(root_obj, &key_path, &path, &dm->status);

exit:
    amxd_path_clean(&path);
    return object;
}

amxd_status_t amxd_dm_resolve_pathf(amxd_dm_t* const dm,
                                    amxc_llist_t* paths,
                                    const char* abs_path,
                                    ...) {
    amxd_status_t status = amxd_status_unknown_error;
    amxd_object_t* root_obj = NULL;
    amxd_path_t path;
    va_list args;
    bool key_path = false;

    amxd_path_init(&path, NULL);

    when_null(dm, exit);
    root_obj = amxd_dm_get_root(dm);

    when_str_empty(abs_path, exit);

    va_start(args, abs_path);
    status = amxd_path_vsetf(&path, true, abs_path, args);
    va_end(args);
    when_failed(status, exit);

    status = amxd_object_resolve_internal(root_obj, &key_path, paths, &path);

exit:
    amxd_path_clean(&path);
    return status;
}

amxd_status_t amxd_dm_resolve_pathf_ext(amxd_dm_t* const dm,
                                        bool* key_path,
                                        amxc_llist_t* paths,
                                        const char* abs_path,
                                        ...) {
    amxd_status_t status = amxd_status_unknown_error;
    amxd_object_t* root_obj = NULL;
    amxd_path_t path;
    va_list args;

    amxd_path_init(&path, NULL);

    when_null(key_path, exit);
    when_null(dm, exit);
    root_obj = amxd_dm_get_root(dm);
    *key_path = false;

    when_str_empty(abs_path, exit);

    va_start(args, abs_path);
    status = amxd_path_vsetf(&path, true, abs_path, args);
    va_end(args);
    when_failed(status, exit);

    status = amxd_object_resolve_internal(root_obj, key_path, paths, &path);

exit:
    amxd_path_clean(&path);
    return status;
}

const char* amxd_dm_signal_get_path(amxd_dm_t* const dm,
                                    const amxc_var_t* const signal_data) {
    amxc_var_t* object_path = NULL;

    when_null(dm, exit);
    when_null(signal_data, exit);

    object_path = amxc_var_get_key(signal_data, "path", 0);

exit:
    return amxc_var_constcast(cstring_t, object_path);
}

amxd_object_t* amxd_dm_signal_get_object(amxd_dm_t* const dm,
                                         const amxc_var_t* const signal_data) {
    amxd_object_t* object = NULL;
    const char* path = NULL;

    when_null(dm, exit);
    when_null(signal_data, exit);

    path = amxd_dm_signal_get_path(dm, signal_data);
    when_null(path, exit);
    object = amxd_object_findf(amxd_dm_get_root(dm),
                               "%s",
                               path);

exit:
    return object;
}

amxd_status_t amxd_dm_invoke_action(amxd_object_t* object,
                                    amxd_param_t* param,
                                    amxd_action_t reason,
                                    const amxc_var_t* const args,
                                    amxc_var_t* const retval) {
    static int in_object_action = 0;
    static int in_param_action = 0;
    static amxd_object_t* current = NULL;

    amxd_object_t* temp = NULL;
    amxc_llist_t* cb_fns = NULL;
    int* counter = NULL;
    amxd_status_t status = amxd_status_function_not_implemented;
    when_true(object == NULL && param == NULL, exit);
    when_true_status(reason == action_any, exit, status = amxd_status_invalid_action);

    temp = current;
    if(param != NULL) {
        when_true_status(!amxd_dm_can_invoke_action(in_param_action, reason, current, object),
                         exit,
                         status = amxd_status_invalid_action);
        counter = &in_param_action;
        cb_fns = &param->cb_fns;
    } else {
        when_true_status(!amxd_dm_can_invoke_action(in_object_action + in_param_action,
                                                    reason, current, object),
                         exit,
                         status = amxd_status_invalid_action);
        counter = &in_object_action;
        cb_fns = &object->cb_fns;
    }

    (*counter)++;
    current = object;
    amxd_dm_invoke_action_start(object, param, reason);
    status = amxd_dm_invoke_action_impl(cb_fns, object, param, reason, args, retval);
    if(status == amxd_status_function_not_implemented) {
        status = amxd_dm_invoke_default(object, param, reason, args, retval);
    }
    (*counter)--;
    status = amxd_dm_invoke_action_end(object, param, status, reason, retval);

    current = temp;

exit:
    return status;
}
