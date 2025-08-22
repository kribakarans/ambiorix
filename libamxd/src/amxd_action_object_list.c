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

#include "amxd_priv.h"

#include <amxd/amxd_dm.h>
#include <amxd/amxd_action.h>
#include <amxd/amxd_object.h>

#include "amxd_object_priv.h"
#include "amxd_dm_priv.h"
#include "amxd_assert.h"

static amxd_status_t amxd_action_list_params(amxd_object_t* const object,
                                             const amxc_var_t* args,
                                             amxc_var_t* const retval) {
    amxd_status_t status = amxd_status_unknown_error;
    amxd_dm_access_t access = (amxd_dm_access_t) GET_UINT32(args, "access");
    bool template_info = GET_BOOL(args, "template_info");

    amxc_llist_for_each(it, (&object->parameters)) {
        amxd_param_t* param = amxc_llist_it_get_data(it, amxd_param_t, it);
        const char* name = amxd_param_get_name(param);
        uint32_t param_attrs = amxd_param_get_attrs(param);
        if(!amxd_action_can_add_param(param_attrs, object->type, access, template_info)) {
            continue;
        }
        amxc_var_add(cstring_t, retval, name);
    }
    status = amxd_status_ok;

    return status;
}

static bool amxd_is_function_in_list(const amxc_llist_t* funcs,
                                     const char* name) {
    bool retval = false;
    amxc_llist_for_each(it, funcs) {
        amxc_var_t* stored = amxc_var_from_llist_it(it);
        if(strcmp(amxc_var_constcast(cstring_t, stored), name) == 0) {
            retval = true;
            break;
        }
    }

    return retval;
}

static void amxd_object_list_functions_impl(const amxd_object_t* object,
                                            amxd_dm_access_t access,
                                            bool template_info,
                                            amxc_var_t* const funcs,
                                            const amxd_object_type_t type) {
    const amxc_llist_t* lfuncs = amxc_var_constcast(amxc_llist_t, funcs);

    if(amxd_object_is_base(object) &&
       ( access == amxd_dm_access_public)) {
        goto exit;
    }

    amxc_llist_for_each(it, (&object->functions)) {
        amxd_function_t* func = amxc_llist_it_get_data(it, amxd_function_t, it);
        const char* func_name = amxd_function_get_name(func);
        uint32_t func_attrs = amxd_function_get_attrs(func);
        if(!amxd_is_function_in_list(lfuncs, func_name) &&
           amxd_action_can_add_function(func_attrs, type, access, template_info)) {
            amxc_var_add(cstring_t, funcs, func_name);
        }
    }

    if(amxd_object_get_type(object) == amxd_object_instance) {
        amxd_object_t* super = amxd_object_get_parent(object);
        amxd_object_list_functions_impl(super,
                                        access,
                                        template_info,
                                        funcs,
                                        type);
    } else {
        if(amxc_llist_it_is_in_list(&object->derived_from)) {
            amxd_object_t* super = amxc_container_of(object->derived_from.llist,
                                                     amxd_object_t,
                                                     derived_objects);
            amxd_object_list_functions_impl(super,
                                            access,
                                            template_info,
                                            funcs,
                                            type);
        }
    }

exit:
    return;
}

static amxd_status_t amxd_action_list_funcs(amxd_object_t* const object,
                                            const amxc_var_t* args,
                                            amxc_var_t* const retval) {
    amxd_status_t status = amxd_status_unknown_error;
    amxd_dm_access_t access = (amxd_dm_access_t) amxc_var_dyncast(uint32_t, GET_ARG(args, "access"));
    bool template_info = GET_BOOL(args, "template_info");

    amxd_object_list_functions_impl(object,
                                    access,
                                    template_info,
                                    retval,
                                    object->type);
    status = amxd_status_ok;

    return status;
}

static amxd_status_t amxd_action_list_objs(amxd_object_t* const object,
                                           UNUSED const amxc_var_t* args,
                                           amxc_var_t* const retval) {
    amxd_status_t status = amxd_status_unknown_error;
    amxd_dm_access_t access = (amxd_dm_access_t) amxc_var_dyncast(uint32_t, GET_ARG(args, "access"));
    bool template_info = GET_BOOL(args, "template_info");

    if((amxd_object_get_type(object) != amxd_object_template) || template_info) {
        amxc_llist_for_each(it, (&object->objects)) {
            amxd_object_t* child = amxc_llist_it_get_data(it, amxd_object_t, it);
            const char* name = amxd_object_get_name(child, AMXD_OBJECT_NAMED);
            uint32_t attrs = amxd_object_get_attrs(child);
            if(amxd_action_can_access_object(attrs, access)) {
                amxc_var_add(cstring_t, retval, name);
            }
        }
    }
    status = amxd_status_ok;

    return status;
}

static amxd_status_t amxd_action_list_insts(amxd_object_t* const object,
                                            UNUSED const amxc_var_t* args,
                                            amxc_var_t* const retval) {
    amxd_status_t status = amxd_status_unknown_error;
    amxc_llist_for_each(it, (&object->instances)) {
        amxd_object_t* inst = amxc_llist_it_get_data(it, amxd_object_t, it);
        amxc_var_t* item = amxc_var_add(amxc_htable_t, retval, NULL);
        const char* name = amxd_object_get_name(inst, AMXD_OBJECT_NAMED);
        uint32_t index = amxd_object_get_index(inst);
        amxc_var_add_key(cstring_t, item, "name", name);
        amxc_var_add_key(uint32_t, item, "index", index);
    }
    status = amxd_status_ok;

    return status;
}

static amxd_status_t amxd_action_list_events(amxd_object_t* const object,
                                             UNUSED const amxc_var_t* args,
                                             amxc_var_t* const retval) {
    amxd_status_t status = amxd_status_unknown_error;
    amxd_object_t* base = NULL;

    amxc_var_for_each(event, (&object->events)) {
        const char* ename = amxc_var_key(event);
        amxc_var_add(cstring_t, retval, ename);
    }

    if(amxd_object_get_type(object) == amxd_object_instance) {
        base = amxd_object_get_parent(object);
    } else {
        base = amxd_object_get_base(object);
    }
    while(base != NULL) {
        amxc_var_for_each(event, (&base->events)) {
            const char* ename = amxc_var_key(event);
            amxc_var_add(cstring_t, retval, ename);
        }
        base = amxd_object_get_base(base);
    }

    status = amxd_status_ok;

    return status;
}


static amxd_status_t amxd_object_list_item(amxd_object_t* const object,
                                           amxc_var_t* const value,
                                           uint32_t flags,
                                           amxd_dm_access_t access,
                                           const char* item) {
    amxd_status_t retval = amxd_status_unknown_error;
    amxc_var_t obj_data;

    amxc_var_init(&obj_data);

    when_null(value, exit);

    retval = amxd_object_list(object, &obj_data, flags, access);
    if(retval == amxd_status_ok) {
        amxd_fetch_item(&obj_data, item, value);
    }

exit:
    amxc_var_clean(&obj_data);
    return retval;
}


bool PRIVATE amxd_must_add(const amxc_var_t* const args,
                           const char* name,
                           amxd_object_t* object) {
    bool retval = false;
    amxc_var_t* arg = amxc_var_get_key(args, name, AMXC_VAR_FLAG_DEFAULT);

    if(amxc_var_is_null(arg) ||
       ( amxc_var_dyncast(bool, arg) == true)) {
        retval = true;
    }
    if((strcmp(name, "instances") == 0) &&
       ( amxd_object_get_type(object) != amxd_object_template)) {
        retval = false;
    }

    return retval;
}

amxd_status_t amxd_action_object_list(amxd_object_t* const object,
                                      UNUSED amxd_param_t* const p,
                                      amxd_action_t reason,
                                      const amxc_var_t* const args,
                                      amxc_var_t* const retval,
                                      UNUSED void* priv) {
    amxd_status_t status = amxd_status_invalid_function_argument;
    amxd_dm_access_t access = amxd_dm_access_public;
    static list_parts_t parts[5] = {
        { "parameters", amxd_action_list_params},
        { "functions", amxd_action_list_funcs},
        { "objects", amxd_action_list_objs},
        { "instances", amxd_action_list_insts},
        { "events", amxd_action_list_events},
    };

    when_null(object, exit);
    when_null(retval, exit);
    when_true_status(reason != action_object_list,
                     exit,
                     status = amxd_status_function_not_implemented);

    when_true_status(!amxc_var_is_null(args) &&
                     amxc_var_type_of(args) != AMXC_VAR_ID_HTABLE,
                     exit,
                     status = amxd_status_invalid_function_argument);

    access = (amxd_dm_access_t) amxc_var_dyncast(uint32_t, GET_ARG(args, "access"));
    when_true_status(!amxd_action_verify_access(object, access),
                     exit,
                     status = amxd_status_object_not_found);

    status = amxd_status_ok;
    amxc_var_set_type(retval, AMXC_VAR_ID_HTABLE);
    for(uint32_t i = 0; i < 5; i++) {
        if(amxd_must_add(args, parts[i].name, object)) {
            amxc_var_t* list =
                amxc_var_add_key(amxc_llist_t, retval, parts[i].name, NULL);
            status = parts[i].fn(object, args, list);
            when_failed(status, exit);
        }
    }

exit:
    return status;
}

amxd_status_t amxd_object_list(amxd_object_t* const object,
                               amxc_var_t* const list,
                               uint32_t flags,
                               amxd_dm_access_t access) {
    amxd_status_t retval = amxd_status_unknown_error;
    amxc_var_t args;

    amxc_var_init(&args);
    when_null(object, exit);
    when_null(list, exit);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(bool, &args, "parameters", flags & AMXD_OBJECT_PARAM);
    amxc_var_add_key(bool, &args, "functions", flags & AMXD_OBJECT_FUNC);
    amxc_var_add_key(bool, &args, "objects", flags & AMXD_OBJECT_CHILD);
    amxc_var_add_key(bool, &args, "instances", flags & AMXD_OBJECT_INSTANCE);
    amxc_var_add_key(bool, &args, "template_info", flags & AMXD_TEMPLATE_INFO);
    amxc_var_add_key(bool, &args, "events", flags & AMXD_OBJECT_EVENT);
    amxc_var_add_key(uint32_t, &args, "access", access);
    retval = amxd_dm_invoke_action(object,
                                   NULL,
                                   action_object_list,
                                   &args,
                                   list);

    amxc_var_clean(&args);

exit:
    return retval;
}

amxd_status_t amxd_object_list_params(amxd_object_t* const object,
                                      amxc_var_t* const list,
                                      amxd_dm_access_t access) {
    return amxd_object_list_item(object,
                                 list,
                                 AMXD_OBJECT_PARAM | AMXD_TEMPLATE_INFO,
                                 access,
                                 "parameters");
}

amxd_status_t amxd_object_list_functions(amxd_object_t* const object,
                                         amxc_var_t* const list,
                                         amxd_dm_access_t access) {
    return amxd_object_list_item(object,
                                 list,
                                 AMXD_OBJECT_FUNC | AMXD_TEMPLATE_INFO,
                                 access,
                                 "functions");
}
