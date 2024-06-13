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

#include "amxd_priv.h"

#include <amxd/amxd_common.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_action.h>
#include <amxd/amxd_function.h>

#include "amxd_dm_priv.h"
#include "amxd_object_priv.h"
#include "amxd_assert.h"

static int is_brace(int c) {
    return ((c == '(') || (c == ')'));
}

static bool amxd_object_can_invoke_function(const amxd_object_t* const object,
                                            const amxd_function_t* const func) {
    bool retval = false;

    if(amxd_object_get_type(object) == amxd_object_instance) {
        when_true(func->attr.instance == 0, exit);
    }
    if(amxd_object_get_type(object) == amxd_object_template) {
        when_true(func->attr.templ == 0, exit);
    }

    retval = true;

exit:
    return retval;
}

static void amxd_function_remove_in_args(amxd_function_t* func,
                                         amxc_var_t* args) {
    amxc_var_t* call_id = GET_ARG(args, "_call_id");
    amxc_var_delete(&call_id);
    amxc_llist_for_each(it, (&func->args)) {
        amxd_func_arg_t* arg = amxc_llist_it_get_data(it, amxd_func_arg_t, it);
        amxc_var_t* in_arg = amxc_var_get_key(args,
                                              arg->name,
                                              AMXC_VAR_FLAG_DEFAULT);
        if(arg->attr.out == 0) {
            amxc_var_delete(&in_arg);
        }
    }
}

static amxd_status_t amxd_object_invoke_check(amxd_object_t* const object,
                                              amxd_function_t** func,
                                              const char* func_name,
                                              amxc_var_t* const args) {
    amxd_status_t retval = amxd_status_unknown_error;

    when_null(object, exit);
    when_str_empty_status(func_name, exit, retval = amxd_status_invalid_name);
    when_null_status(args, exit, retval = amxd_status_invalid_function_argument);
    when_true_status(amxc_var_type_of(args) != AMXC_VAR_ID_HTABLE,
                     exit,
                     retval = amxd_status_invalid_function_argument);
    *func = amxd_object_get_function(object, func_name);
    when_null_status(*func, exit, retval = amxd_status_function_not_found);
    when_true_status(!amxd_function_are_args_valid(*func, args),
                     exit,
                     retval = amxd_status_invalid_function_argument);
    when_true_status(!amxd_object_can_invoke_function(object, *func),
                     exit,
                     retval = amxd_status_invalid_function);
    when_null_status((*func)->impl,
                     exit,
                     retval = amxd_status_function_not_implemented);

    retval = amxd_status_ok;

exit:
    return retval;
}

amxd_status_t amxd_object_add_function(amxd_object_t* const object,
                                       amxd_function_t* const func) {
    amxd_status_t retval = amxd_status_unknown_error;
    amxd_function_t* object_func = NULL;
    when_null(object, exit);
    when_null(func, exit);
    when_not_null(func->it.llist, exit);
    when_true(amxd_object_is_attr_set(object, amxd_oattr_locked), exit);

    amxc_llist_for_each(it, (&object->functions)) {
        const char* object_func_name = NULL;
        const char* func_name = NULL;
        object_func = amxc_llist_it_get_data(it, amxd_function_t, it);
        object_func_name = amxd_function_get_name(object_func);
        func_name = amxd_function_get_name(func);
        if(strcmp(func_name, object_func_name) == 0) {
            break;
        }
        object_func = NULL;
    }

    if(object_func == NULL) {
        // functions added to template object by default only work on
        // instances. This is a design descision.
        // For other behavior set the attributes before adding the function
        // to the object
        if(amxd_object_get_type(object) == amxd_object_template) {
            if((func->attr.instance == 0) &&
               ( func->attr.templ == 0)) {
                func->attr.instance = 1;
            }
        }
        amxc_llist_append(&object->functions, &func->it);
        retval = amxd_status_ok;
    } else {
        retval = amxd_status_duplicate;
    }

exit:
    return retval;
}

amxd_status_t amxd_object_change_function(amxd_object_t* const object,
                                          const char* name,
                                          amxd_object_fn_t impl) {
    amxd_status_t retval = amxd_status_unknown_error;
    amxd_function_t* func = NULL;
    amxd_object_t* owner = NULL;

    when_null(object, exit);
    when_str_empty(name, exit);

    func = amxd_object_get_function(object, name);
    when_null(func, exit);
    owner = amxd_function_get_owner(func);
    if(owner == object) {
        func->impl = impl;
        retval = amxd_status_ok;
    } else {
        amxd_function_t* new_func = NULL;
        retval = amxd_function_copy(&new_func, func);
        when_true(retval != amxd_status_ok, exit);
        new_func->impl = impl;
        when_failed(amxc_llist_append(&object->functions, &new_func->it), exit);
    }

exit:
    return retval;
}

amxd_function_t* amxd_object_get_function(const amxd_object_t* const object,
                                          const char* name) {
    amxd_function_t* func = NULL;
    amxc_string_t normalized;

    amxc_string_init(&normalized, 0);

    when_null(object, exit);
    when_str_empty(name, exit);

    amxc_string_setf(&normalized, "%s", name);
    amxc_string_trimr(&normalized, is_brace);

    func = amxd_object_get_self_func(object, amxc_string_get(&normalized, 0));

    when_not_null(func, exit);

    if(amxd_object_get_type(object) == amxd_object_instance) {
        func = amxd_object_get_function(amxd_object_get_parent(object), amxc_string_get(&normalized, 0));
    } else {
        if(amxc_llist_it_is_in_list(&object->derived_from)) {
            amxd_object_t* super = NULL;
            super = amxc_container_of(object->derived_from.llist,
                                      amxd_object_t,
                                      derived_objects);
            func = amxd_object_get_function(super, amxc_string_get(&normalized, 0));
        }
    }

exit:
    amxc_string_clean(&normalized);

    return func;
}

amxd_status_t amxd_object_invoke_function(amxd_object_t* const object,
                                          const char* func_name,
                                          amxc_var_t* const args,
                                          amxc_var_t* const ret) {
    amxd_status_t retval = amxd_status_unknown_error;
    amxd_function_t* func = NULL;

    when_null(ret, exit);
    retval = amxd_object_invoke_check(object, &func, func_name, args);
    when_failed(retval, exit);

    retval = func->impl(object, func, args, ret);
    amxd_function_remove_in_args(func, args);

    if(retval == amxd_status_deferred) {
        amxd_dm_t* dm = amxd_object_get_dm(object);
        uint64_t call_id = amxc_var_constcast(uint64_t, ret);
        amxd_deferred_ctx_t* call_ctx = amxd_find_deferred(call_id);
        if(call_ctx == NULL) {
            retval = amxd_status_unknown_error;
            amxc_var_clean(ret);
            goto exit;
        }

        amxc_llist_append(&dm->deferred, &call_ctx->dm_it);
    }

exit:
    return retval;
}

uint32_t amxd_object_get_function_count(amxd_object_t* const object,
                                        amxd_dm_access_t access) {
    uint32_t count = 0;
    amxc_var_t funcs;
    const amxc_llist_t* funcs_list = NULL;

    when_null(object, exit);

    amxc_var_init(&funcs);
    amxd_object_list_functions(object, &funcs, access);
    funcs_list = amxc_var_constcast(amxc_llist_t, &funcs);
    count = amxc_llist_size(funcs_list);
    amxc_var_clean(&funcs);

exit:
    return count;
}
