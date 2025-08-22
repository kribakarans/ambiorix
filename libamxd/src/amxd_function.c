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

static void amxd_function_free_arg_it(amxc_llist_it_t* it) {
    amxd_func_arg_t* arg = amxc_llist_it_get_data(it, amxd_func_arg_t, it);
    amxd_function_arg_clean(arg);
    free(arg);
}

static amxd_status_t amxd_function_init(amxd_function_t* const func,
                                        const char* name,
                                        uint32_t ret_type,
                                        amxd_object_fn_t impl) {
    amxd_status_t retval = amxd_status_unknown_error;

    amxc_llist_it_init(&func->it);

    func->attr.templ = 0;
    func->attr.instance = 0;
    func->attr.priv = 0;
    func->attr.prot = 0;

    if((ret_type == AMXC_VAR_ID_ANY) ||
       ( amxc_var_get_type(ret_type) != NULL)) {
        func->name = strdup(name);
        when_null(func->name, exit);

        amxc_llist_init(&func->args);
        func->ret_type = ret_type;
        func->impl = impl;

        retval = amxd_status_ok;
    }

exit:
    return retval;
}

static int amxd_function_clean(amxd_function_t* const func) {
    amxc_llist_it_take(&func->it);
    amxc_llist_clean(&func->args, amxd_function_free_arg_it);
    amxc_var_delete(&func->flags);

    free(func->name);
    func->name = NULL;
    func->impl = NULL;

    return 0;
}

static uint32_t amxd_function_get_attributes(const amxd_function_t* const func) {

    uint32_t attributes = 0;

    attributes |= func->attr.templ << amxd_fattr_template;
    attributes |= func->attr.instance << amxd_fattr_instance;
    attributes |= func->attr.priv << amxd_fattr_private;
    attributes |= func->attr.prot << amxd_fattr_protected;
    attributes |= func->attr.async << amxd_fattr_async;

    return attributes;
}

static void amxd_function_set_attributes(amxd_function_t* const func,
                                         const uint32_t attr) {
    func->attr.templ = IS_BIT_SET(attr, amxd_fattr_template);
    func->attr.instance = IS_BIT_SET(attr, amxd_fattr_instance);
    func->attr.priv = IS_BIT_SET(attr, amxd_fattr_private);
    func->attr.prot = IS_BIT_SET(attr, amxd_fattr_protected);
    func->attr.async = IS_BIT_SET(attr, amxd_fattr_async);
}

amxd_status_t amxd_function_new(amxd_function_t** func,
                                const char* name,
                                const uint32_t ret_type,
                                amxd_object_fn_t impl) {
    amxd_status_t retval = amxd_status_unknown_error;
    when_null(func, exit);
    when_true_status(!amxd_name_is_valid(name),
                     exit,
                     retval = amxd_status_invalid_name);

    *func = (amxd_function_t*) calloc(1, sizeof(amxd_function_t));
    when_null((*func), exit);

    retval = amxd_function_init(*func, name, ret_type, impl);

exit:
    if((retval != 0) && (func != NULL)) {
        free(*func);
        *func = NULL;
    }
    return retval;
}

void amxd_function_delete(amxd_function_t** func) {
    when_null(func, exit);
    when_null((*func), exit);

    amxd_function_clean((*func));
    free(*func);
    *func = NULL;

exit:
    return;
}

amxd_status_t amxd_function_copy(amxd_function_t** dest,
                                 const amxd_function_t* const source) {
    amxd_status_t retval = amxd_status_unknown_error;
    when_null(dest, exit);
    when_null(source, exit);

    *dest = (amxd_function_t*) calloc(1, sizeof(amxd_function_t));
    when_null((*dest), exit);

    when_failed(amxd_function_init(*dest, source->name,
                                   source->ret_type,
                                   source->impl), exit);
    (*dest)->attr = source->attr;

    amxc_llist_for_each(it, (&source->args)) {
        amxd_func_arg_t* arg = amxc_llist_it_get_data(it, amxd_func_arg_t, it);
        when_failed(amxd_function_new_arg((*dest),
                                          arg->name,
                                          arg->type,
                                          &arg->default_value), exit);
        if(amxd_function_arg_is_attr_set(source, arg->name, amxd_aattr_in)) {
            amxd_function_arg_set_attr((*dest), arg->name, amxd_aattr_in, true);
        }
        if(amxd_function_arg_is_attr_set(source, arg->name, amxd_aattr_out)) {
            amxd_function_arg_set_attr((*dest), arg->name, amxd_aattr_out, true);
        }
        if(amxd_function_arg_is_attr_set(source, arg->name, amxd_aattr_mandatory)) {
            amxd_function_arg_set_attr((*dest), arg->name, amxd_aattr_mandatory, true);
        }
        if(amxd_function_arg_is_attr_set(source, arg->name, amxd_aattr_strict)) {
            amxd_function_arg_set_attr((*dest), arg->name, amxd_aattr_strict, true);
        }
    }

    retval = amxd_status_ok;

exit:
    if((retval != amxd_status_ok) && (dest != NULL) && (*dest != NULL)) {
        amxd_function_clean(*dest);
        free(*dest);
        *dest = NULL;
    }
    return retval;
}

amxd_object_t* amxd_function_get_owner(const amxd_function_t* const func) {
    amxd_object_t* object = NULL;
    when_null(func, exit);
    when_null(func->it.llist, exit);

    object = amxc_container_of(func->it.llist, amxd_object_t, functions);

exit:
    return object;
}

amxd_function_t* amxd_function_get_base(const amxd_function_t* const func) {
    amxd_function_t* base = NULL;
    amxd_object_t* object = amxd_function_get_owner(func);

    when_null(object, exit);

    if(amxd_object_get_type(object) == amxd_object_instance) {
        base = amxd_object_get_function(amxd_object_get_parent(object),
                                        func->name);
    } else {
        if(amxc_llist_it_is_in_list(&object->derived_from)) {
            amxd_object_t* super = NULL;
            super = amxc_container_of(object->derived_from.llist,
                                      amxd_object_t,
                                      derived_objects);
            base = amxd_object_get_function(super, func->name);
        }
    }

exit:
    return base;
}

amxd_status_t amxd_function_call_base(const amxd_function_t* const func,
                                      amxd_object_t* const object,
                                      amxc_var_t* const args,
                                      amxc_var_t* const ret) {
    amxd_status_t status = amxd_status_unknown_error;
    amxd_function_t* base_func = amxd_function_get_base(func);

    when_null(object, exit);
    when_null(base_func, exit);
    if(base_func->impl == NULL) {
        status = amxd_status_function_not_implemented;
        goto exit;
    }
    status = base_func->impl(object, base_func, args, ret);

exit:
    return status;
}

const char* amxd_function_get_name(const amxd_function_t* const func) {
    return func == NULL ? NULL : func->name;
}

amxd_status_t amxd_function_set_attr(amxd_function_t* func,
                                     const amxd_fattr_id_t attr,
                                     const bool enable) {
    amxd_status_t retval = amxd_status_unknown_error;
    uint32_t flags = 0;
    when_null(func, exit);

    when_true_status(attr < 0 || attr > amxd_fattr_max,
                     exit,
                     retval = amxd_status_invalid_attr);

    flags = amxd_function_get_attributes(func);

    if(enable) {
        flags |= (1 << attr);
    } else {
        flags &= ~(1 << attr);
    }

    amxd_function_set_attributes(func, flags);

    retval = amxd_status_ok;

exit:
    return retval;
}

amxd_status_t amxd_function_set_attrs(amxd_function_t* func,
                                      const uint32_t bitmask,
                                      bool enable) {
    amxd_status_t retval = amxd_status_unknown_error;
    uint32_t flags = 0;
    uint32_t all = 0;

    for(int i = 0; i <= amxd_fattr_max; i++) {
        all |= SET_BIT(i);
    }

    when_null(func, exit);
    when_true_status(bitmask > all, exit, retval = amxd_status_invalid_attr);

    flags = amxd_function_get_attributes(func);

    if(enable) {
        flags |= bitmask;
    } else {
        flags &= ~bitmask;
    }

    amxd_function_set_attributes(func, flags);
    retval = amxd_status_ok;

exit:
    return retval;
}

uint32_t amxd_function_get_attrs(const amxd_function_t* const func) {
    uint32_t attributes = 0;
    when_null(func, exit);

    attributes |= func->attr.templ << amxd_fattr_template;
    attributes |= func->attr.instance << amxd_fattr_instance;
    attributes |= func->attr.priv << amxd_fattr_private;
    attributes |= func->attr.prot << amxd_fattr_protected;
    attributes |= func->attr.async << amxd_fattr_async;

exit:
    return attributes;
}

bool amxd_function_is_attr_set(const amxd_function_t* const func,
                               const amxd_fattr_id_t attr) {
    uint32_t flags = 0;
    bool retval = false;
    when_null(func, exit);
    when_true(attr < 0 || attr > amxd_fattr_max, exit);

    flags = amxd_function_get_attributes(func);
    retval = (flags & (1 << attr)) != 0 ? true : false;

exit:
    return retval;
}

void amxd_function_set_flag(amxd_function_t* func, const char* flag) {
    when_null(func, exit);
    when_null(flag, exit);
    when_true(*flag == 0, exit);

    amxd_common_set_flag(&func->flags, flag);

exit:
    return;
}

void amxd_function_unset_flag(amxd_function_t* func, const char* flag) {
    when_null(func, exit);
    when_null(flag, exit);
    when_true(*flag == 0, exit);

    amxd_common_unset_flag(&func->flags, flag);

exit:
    return;
}

bool amxd_function_has_flag(const amxd_function_t* const func, const char* flag) {
    bool retval = false;
    when_null(func, exit);
    when_null(flag, exit);
    when_true(*flag == 0, exit);

    retval = amxd_common_has_flag(func->flags, flag);

exit:
    return retval;
}

amxd_status_t amxd_function_set_impl(amxd_function_t* const func,
                                     amxd_object_fn_t impl) {
    amxd_status_t retval = amxd_status_unknown_error;
    when_null(func, exit);

    func->impl = impl;
    retval = amxd_status_ok;

exit:
    return retval;
}

amxd_status_t amxd_function_describe(amxd_function_t* const func,
                                     amxc_var_t* const value) {
    amxd_status_t status = amxd_status_unknown_error;
    amxc_var_t* table = NULL;
    uint32_t retvalt = 0;

    static const char* attr_name[] = {
        "template",
        "instance",
        "private",
        "protected",
        "asynchronous",
    };

    when_null(func, exit);
    when_null(value, exit);

    retvalt = amxd_function_get_type(func);
    amxc_var_set_type(value, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, value, "name", amxd_function_get_name(func));
    amxc_var_add_key(uint32_t, value, "type_id", retvalt);
    amxc_var_add_key(cstring_t,
                     value,
                     "type_name",
                     amxc_var_get_type_name_from_id(retvalt));
    table = amxc_var_add_key(amxc_htable_t, value, "attributes", NULL);
    for(int i = 0; i <= (int) amxd_fattr_max; i++) {
        amxc_var_add_key(bool,
                         table,
                         attr_name[i],
                         amxd_function_is_attr_set(func, (amxd_fattr_id_t) i));
    }

    table = amxc_var_add_key(amxc_llist_t, value, "arguments", NULL);
    amxc_llist_for_each(it, (&func->args)) {
        amxd_func_arg_t* farg = amxc_llist_it_get_data(it, amxd_func_arg_t, it);
        amxc_var_t* arg = amxc_var_add(amxc_htable_t, table, NULL);
        amxd_function_arg_describe(farg, arg);
    }

    table = amxc_var_add_key(amxc_llist_t, value, "flags", NULL);
    if(func->flags != NULL) {
        amxc_var_for_each(flag, func->flags) {
            if(amxc_var_dyncast(bool, flag)) {
                amxc_var_add(cstring_t, table, amxc_var_key(flag));
            }
        }
    }

    status = amxd_status_ok;

exit:
    return status;
}

amxd_func_arg_t* amxd_function_get_arg(const amxd_function_t* const func,
                                       const char* name) {
    amxd_func_arg_t* arg = NULL;
    when_null(func, exit);
    when_str_empty(name, exit);

    amxc_llist_for_each(it, (&func->args)) {
        arg = amxc_llist_it_get_data(it, amxd_func_arg_t, it);
        if(strcmp(arg->name, name) == 0) {
            break;
        }
        arg = NULL;
    }

exit:
    return arg;
}

bool amxd_function_are_args_valid(amxd_function_t* func,
                                  amxc_var_t* args) {
    bool valid = false;

    when_null(func, exit);
    when_null(args, exit);
    when_false(amxc_var_type_of(args) == AMXC_VAR_ID_HTABLE, exit);

    amxc_llist_for_each(it, (&func->args)) {
        amxd_func_arg_t* arg = amxc_llist_it_get_data(it, amxd_func_arg_t, it);
        amxc_var_t* in_arg = amxc_var_get_key(args,
                                              arg->name,
                                              AMXC_VAR_FLAG_DEFAULT);
        if(arg->attr.in == 0) {
            continue;
        }
        if(arg->attr.mandatory == 1) {
            when_null(in_arg, exit);
        }
        if((in_arg == NULL) &&
           ( amxc_var_type_of(&arg->default_value) != AMXC_VAR_ID_NULL)) {
            in_arg = amxc_var_add_new_key(args, arg->name);
            amxc_var_copy(in_arg, &arg->default_value);
        }
        if((arg->attr.strict == 1) &&
           ( in_arg != NULL)) {
            when_true(arg->type != amxc_var_type_of(in_arg), exit);
        }
    }

    valid = true;

exit:
    return valid;
}