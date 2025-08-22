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
#include <amxd/amxd_function.h>

#include "amxd_assert.h"

static amxd_status_t amxd_function_arg_init(amxd_func_arg_t* const arg,
                                            const char* name,
                                            uint32_t type,
                                            amxc_var_t* default_value) {
    amxd_status_t retval = amxd_status_unknown_error;

    amxc_llist_it_init(&arg->it);

    if((type == AMXC_VAR_ID_ANY) ||
       ( amxc_var_get_type(type) != NULL)) {
        arg->name = strdup(name);
        if(arg->name != NULL) {
            arg->attr.in = 0;
            arg->attr.out = 0;
            arg->attr.mandatory = 0;
            arg->attr.strict = 0;

            amxc_var_init(&arg->default_value);
            amxc_var_copy(&arg->default_value, default_value);
            arg->type = type;
            retval = amxd_status_ok;
        }
    }

    return retval;
}

static uint32_t amxd_function_arg_get_attributes(const amxd_func_arg_t* const arg) {
    uint32_t attributes = 0;

    attributes |= arg->attr.in << amxd_aattr_in;
    attributes |= arg->attr.out << amxd_aattr_out;
    attributes |= arg->attr.mandatory << amxd_aattr_mandatory;
    attributes |= arg->attr.strict << amxd_aattr_strict;

    return attributes;
}

static void amxd_function_arg_set_attributes(amxd_func_arg_t* const arg,
                                             const uint32_t attr) {
    arg->attr.in = IS_BIT_SET(attr, amxd_aattr_in);
    arg->attr.out = IS_BIT_SET(attr, amxd_aattr_out);
    arg->attr.mandatory = IS_BIT_SET(attr, amxd_aattr_mandatory);
    arg->attr.strict = IS_BIT_SET(attr, amxd_aattr_strict);
}

static bool amxd_function_arg_valid_name(amxd_function_t* func,
                                         const char* name) {
    bool retval = true;

    amxc_llist_for_each(it, (&func->args)) {
        amxd_func_arg_t* arg = amxc_llist_it_get_data(it, amxd_func_arg_t, it);
        if(strcmp(arg->name, name) == 0) {
            retval = false;
            break;
        }
    }

    return retval;
}

void PRIVATE amxd_function_arg_clean(amxd_func_arg_t* const arg) {
    amxc_llist_it_take(&arg->it);

    amxc_var_clean(&arg->default_value);
    free(arg->name);
    arg->name = NULL;
}

amxd_status_t amxd_function_new_arg(amxd_function_t* func,
                                    const char* name,
                                    const uint32_t type,
                                    amxc_var_t* default_value) {
    amxd_status_t retval = amxd_status_unknown_error;
    amxd_func_arg_t* arg = NULL;
    when_null(func, exit);

    when_str_empty_status(name, exit, retval = amxd_status_invalid_name);
    when_true_status(!amxd_function_arg_valid_name(func, name),
                     exit,
                     retval = amxd_status_invalid_name);

    arg = (amxd_func_arg_t*) calloc(1, sizeof(amxd_func_arg_t));
    when_null(arg, exit);

    retval = amxd_function_arg_init(arg, name, type, default_value);

    if(retval == amxd_status_ok) {
        amxc_llist_append(&func->args, &arg->it);
    }
exit:
    if(retval != amxd_status_ok) {
        free(arg);
    }
    return retval;
}

void amxd_function_del_arg(amxd_function_t* func, const char* name) {
    amxd_func_arg_t* arg = NULL;
    when_null(func, exit);
    when_str_empty(name, exit);

    arg = amxd_function_get_arg(func, name);
    when_null(arg, exit);

    amxd_function_arg_clean(arg);
    free(arg);

exit:
    return;
}

amxd_status_t amxd_function_arg_set_attr(amxd_function_t* const func,
                                         const char* name,
                                         const amxd_aattr_id_t attr,
                                         const bool enable) {
    amxd_status_t retval = amxd_status_unknown_error;
    uint32_t flags = 0;
    amxd_func_arg_t* arg = NULL;
    when_null(func, exit);

    when_true_status(attr < 0 || attr > amxd_aattr_max,
                     exit,
                     retval = amxd_status_invalid_attr);

    arg = amxd_function_get_arg(func, name);
    when_null(arg, exit);
    flags = amxd_function_arg_get_attributes(arg);

    // when type any is set, it can not be a strict typed argument
    if((attr == amxd_aattr_strict) &&
       ( arg->type == AMXC_VAR_ID_ANY)) {
        retval = amxd_status_invalid_attr;
        goto exit;
    }

    if(enable) {
        flags |= (1 << attr);
    } else {
        flags &= ~(1 << attr);
    }

    amxd_function_arg_set_attributes(arg, flags);
    retval = amxd_status_ok;

exit:
    return retval;
}

amxd_status_t amxd_function_arg_set_attrs(amxd_function_t* func,
                                          const char* name,
                                          const uint32_t bitmask,
                                          bool enable) {
    amxd_status_t retval = amxd_status_unknown_error;
    uint32_t flags = 0;
    amxd_func_arg_t* arg = NULL;
    uint32_t all = 0;

    for(int i = 0; i <= amxd_aattr_max; i++) {
        all |= SET_BIT(i);
    }

    when_null(func, exit);
    when_true_status(bitmask > all, exit, retval = amxd_status_invalid_attr);

    arg = amxd_function_get_arg(func, name);
    when_null(arg, exit);
    flags = amxd_function_arg_get_attributes(arg);

    // when type any is set, it can not be a strict typed argument
    if(((bitmask & SET_BIT(amxd_aattr_strict)) != 0) &&
       ( arg->type == AMXC_VAR_ID_ANY)) {
        retval = amxd_status_invalid_attr;
        goto exit;
    }

    if(enable) {
        flags |= bitmask;
    } else {
        flags &= ~bitmask;
    }

    amxd_function_arg_set_attributes(arg, flags);
    retval = amxd_status_ok;

exit:
    return retval;
}

bool amxd_function_arg_is_attr_set(const amxd_function_t* const func,
                                   const char* name,
                                   const amxd_aattr_id_t attr) {
    uint32_t flags = 0;
    amxd_func_arg_t* arg = NULL;
    bool retval = false;
    when_null(func, exit);
    when_true(attr < 0 || attr > amxd_aattr_max, exit);

    arg = amxd_function_get_arg(func, name);
    when_null(arg, exit);
    flags = amxd_function_arg_get_attributes(arg);
    retval = (flags & (1 << attr)) != 0 ? true : false;

exit:
    return retval;
}

amxd_status_t amxd_function_arg_describe(amxd_func_arg_t* const arg,
                                         amxc_var_t* const value) {
    amxd_status_t status = amxd_status_unknown_error;
    amxc_var_t* table = NULL;
    uint32_t attrs = 0;
    static const char* attr_name[] = {
        "in",
        "out",
        "mandatory",
        "strict"
    };

    when_null(arg, exit);
    when_null(value, exit);

    amxc_var_set_type(value, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, value, "name", arg->name);
    amxc_var_add_key(uint32_t, value, "type_id", arg->type);
    amxc_var_add_key(cstring_t,
                     value,
                     "type_name",
                     amxc_var_get_type_name_from_id(arg->type));
    if(!amxc_var_is_null(&arg->default_value)) {
        amxc_var_set_key(value, "default", &arg->default_value, AMXC_VAR_FLAG_COPY);
    }
    table = amxc_var_add_key(amxc_htable_t, value, "attributes", NULL);
    attrs = amxd_function_arg_get_attributes(arg);
    for(int i = 0; i <= amxd_aattr_max; i++) {
        bool is_set = (attrs & (1 << i)) != 0 ? true : false;
        amxc_var_add_key(bool,
                         table,
                         attr_name[i],
                         is_set);
    }

    status = amxd_status_ok;

exit:
    return status;
}