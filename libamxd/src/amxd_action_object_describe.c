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

#include "amxd_priv.h"

#include <amxd/amxd_dm.h>
#include <amxd/amxd_action.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_object_event.h>

#include "amxd_object_priv.h"
#include "amxd_assert.h"

static amxd_status_t amxd_describe_object_impl(amxd_object_t* object,
                                               UNUSED const amxc_var_t* args,
                                               amxc_var_t* const retval) {
    amxd_status_t status = amxd_status_unknown_error;
    amxc_var_t* data = NULL;
    uint32_t obj_type = amxd_object_get_type(object);
    amxd_object_t* parent = amxd_object_get_parent(object);
    char* path = NULL;
    char* obj = NULL;
    static const char* attr_name[] = {
        "read-only", "persistent", "private", "locked", "protected"
    };
    static const char* type_name[] = {
        "root", "singleton", "template", "instance", "mib", "invalid",
    };

    if(amxd_object_get_type(object) == amxd_object_instance) {
        path = amxd_object_get_path(parent,
                                    AMXD_OBJECT_INDEXED | AMXD_OBJECT_TERMINATE);
        obj = amxd_object_get_path(parent,
                                   AMXD_OBJECT_NAMED | AMXD_OBJECT_TERMINATE);
    } else {
        path = amxd_object_get_path(object,
                                    AMXD_OBJECT_INDEXED | AMXD_OBJECT_TERMINATE);
        obj = amxd_object_get_path(object,
                                   AMXD_OBJECT_NAMED | AMXD_OBJECT_TERMINATE);
    }

    amxc_var_add_key(cstring_t,
                     retval,
                     "name",
                     amxd_object_get_name(object, AMXD_OBJECT_NAMED));
    amxc_var_add_key(uint32_t, retval, "type_id", obj_type);
    amxc_var_add_key(cstring_t, retval, "type_name", type_name[obj_type]);
    amxc_var_add_key(cstring_t, retval, "path", path == NULL ? "" : path);
    amxc_var_add_key(cstring_t, retval, "object", obj == NULL ? "" : obj);
    if(amxd_object_get_type(object) == amxd_object_instance) {
        amxc_var_add_key(uint32_t, retval, "index", amxd_object_get_index(object));
    }

    data = amxc_var_add_key(amxc_htable_t, retval, "attributes", NULL);
    for(int i = 0; i <= amxd_oattr_max; i++) {
        amxc_var_add_key(bool,
                         data,
                         attr_name[i],
                         amxd_object_is_attr_set(object, (amxd_oattr_id_t) i));
    }

    free(path);
    free(obj);
    status = amxd_status_ok;

    return status;
}

static amxd_status_t amxd_describe_params(amxd_object_t* object,
                                          const amxc_var_t* args,
                                          amxc_var_t* const retval) {
    amxd_status_t status = amxd_status_unknown_error;
    amxc_var_t* data = NULL;
    amxd_dm_access_t access = (amxd_dm_access_t) GET_UINT32(args, "access");
    amxd_object_type_t type = amxd_object_get_type(object);
    uint32_t attributes = GET_ARG(args, "attributes") == NULL ? 0xffffffff : GET_UINT32(args, "attributes");

    data = amxc_var_add_key(amxc_htable_t, retval, "parameters", NULL);
    amxc_llist_for_each(it, (&object->parameters)) {
        amxd_param_t* param = amxc_llist_it_get_data(it, amxd_param_t, it);
        const char* name = amxd_param_get_name(param);
        uint32_t param_attrs = amxd_param_get_attrs(param);
        amxc_var_t* desc = NULL;
        if(((attributes & param_attrs) == 0) && (attributes != 0xffffffff)) {
            continue;
        }
        if(!amxd_action_can_add_param(param_attrs, type, access, true)) {
            continue;
        }

        desc = amxc_var_add_key(amxc_htable_t, data, name, NULL);
        amxd_dm_invoke_action(object, param, action_param_describe, args, desc);
    }

    status = amxd_status_ok;

    return status;
}

static amxd_status_t amxd_describe_funcs(amxd_object_t* object,
                                         const amxc_var_t* args,
                                         amxc_var_t* const retval) {
    amxd_status_t status = amxd_status_unknown_error;
    amxc_var_t obj_list;
    amxc_var_t* var_funcs_list = NULL;
    const amxc_llist_t* ll_funcs = NULL;
    amxc_var_t* data = NULL;
    amxd_dm_access_t access = (amxd_dm_access_t) GET_UINT32(args, "access");
    bool template_info = GET_BOOL(args, "template_info");
    uint32_t flags = AMXD_OBJECT_FUNC;

    amxc_var_init(&obj_list);

    if(access == amxd_dm_access_public) {
        flags |= AMXD_OBJECT_NO_BASE;
    }

    if(template_info) {
        flags |= AMXD_TEMPLATE_INFO;
    }

    amxd_object_list(object, &obj_list, flags, access);
    var_funcs_list = GET_ARG(&obj_list, "functions");
    ll_funcs = amxc_var_constcast(amxc_llist_t, var_funcs_list);

    data = amxc_var_add_key(amxc_htable_t, retval, "functions", NULL);
    amxc_llist_for_each(it, ll_funcs) {
        const char* func_name = amxc_var_constcast(cstring_t,
                                                   amxc_var_from_llist_it(it));
        amxd_function_t* func = amxd_object_get_function(object, func_name);
        amxc_var_t* desc = amxc_var_add_key(amxc_htable_t, data, func_name, NULL);
        amxd_function_describe(func, desc);
    }

    status = amxd_status_ok;

    amxc_var_clean(&obj_list);
    return status;
}

static amxd_status_t amxd_describe_objects(amxd_object_t* object,
                                           const amxc_var_t* args,
                                           amxc_var_t* const retval) {
    amxd_status_t status = amxd_status_ok;
    amxc_var_t* data = NULL;
    amxd_dm_access_t access = (amxd_dm_access_t) GET_UINT32(args, "access");

    if(amxd_object_get_type(object) == amxd_object_template) {
        goto exit;
    }

    data = amxc_var_add_key(amxc_llist_t, retval, "objects", NULL);
    amxc_llist_for_each(it, (&object->objects)) {
        amxd_object_t* child = amxc_llist_it_get_data(it, amxd_object_t, it);
        if(!amxd_action_can_access_object(amxd_object_get_attrs(child), access)) {
            continue;
        }
        amxc_var_add(cstring_t, data, amxd_object_get_name(child, AMXD_OBJECT_NAMED));
    }

exit:
    return status;
}

static amxd_status_t amxd_describe_instances(amxd_object_t* object,
                                             UNUSED const amxc_var_t* args,
                                             amxc_var_t* const retval) {
    amxd_status_t status = amxd_status_ok;
    amxc_var_t* data = NULL;

    data = amxc_var_add_key(amxc_llist_t, retval, "instances", NULL);
    amxc_llist_for_each(it, (&object->instances)) {
        amxd_object_t* child = amxc_llist_it_get_data(it, amxd_object_t, it);
        amxc_var_add(cstring_t, data, amxd_object_get_name(child, AMXD_OBJECT_INDEXED));
    }

    return status;
}

static void amxd_add_event_params(amxc_var_t* event, amxc_var_t* params, const char* name) {
    amxc_string_t full_name;
    amxc_string_init(&full_name, 0);

    amxc_var_for_each(param, event) {
        const char* param_name = amxc_var_key(param);
        if((name != NULL) && (*name != 0)) {
            amxc_string_setf(&full_name, "%s.%s", name, param_name);
        } else {
            amxc_string_set(&full_name, param_name);
        }
        if(amxc_var_type_of(param) == AMXC_VAR_ID_HTABLE) {
            amxd_add_event_params(param, params, amxc_string_get(&full_name, 0));
        } else {
            amxc_var_add(cstring_t, params, amxc_string_get(&full_name, 0));
        }
    }

    amxc_string_clean(&full_name);
}

static void amxd_add_event_descriptions(amxd_object_t* object,
                                        amxc_var_t* events) {
    amxc_var_for_each(event, (&object->events)) {
        const char* ename = amxc_var_key(event);
        amxc_var_t* params = amxc_var_add_key(amxc_llist_t, events, ename, NULL);
        amxd_add_event_params(event, params, NULL);
    }
}

static amxd_status_t amxd_describe_events(amxd_object_t* object,
                                          UNUSED const amxc_var_t* args,
                                          amxc_var_t* const retval) {
    amxd_status_t status = amxd_status_unknown_error;
    amxc_var_t* data = NULL;

    data = amxc_var_add_key(amxc_htable_t, retval, "events", NULL);
    amxd_add_event_descriptions(object, data);

    if(amxd_object_get_type(object) == amxd_object_instance) {
        object = amxd_object_get_parent(object);
    } else {
        object = amxd_object_get_base(object);
    }
    while(object != NULL) {
        amxd_add_event_descriptions(object, data);
        object = amxd_object_get_base(object);
    }

    status = amxd_status_ok;

    return status;
}

static amxd_status_t amxd_object_describe_item(amxd_object_t* const object,
                                               amxc_var_t* const value,
                                               uint32_t flags,
                                               amxd_dm_access_t access,
                                               const char* item) {
    amxd_status_t retval = amxd_status_unknown_error;
    amxc_var_t obj_data;

    amxc_var_init(&obj_data);

    when_null(value, exit);

    retval = amxd_object_describe(object, &obj_data, flags, access);
    if(retval == amxd_status_ok) {
        amxd_fetch_item(&obj_data, item, value);
    }

exit:
    amxc_var_clean(&obj_data);
    return retval;
}

amxd_status_t amxd_action_object_describe(amxd_object_t* object,
                                          UNUSED amxd_param_t* param,
                                          amxd_action_t reason,
                                          const amxc_var_t* const args,
                                          amxc_var_t* const retval,
                                          UNUSED void* priv) {
    amxd_status_t status = amxd_status_unknown_error;
    amxd_dm_access_t access = amxd_dm_access_public;
    static list_parts_t parts[5] = {
        { "parameters", amxd_describe_params},
        { "functions", amxd_describe_funcs},
        { "objects", amxd_describe_objects},
        { "instances", amxd_describe_instances},
        { "events", amxd_describe_events},
    };
    when_null(object, exit);
    when_null(retval, exit);

    when_true_status(reason != action_object_describe,
                     exit,
                     status = amxd_status_function_not_implemented);

    access = (amxd_dm_access_t) amxc_var_dyncast(uint32_t, GET_ARG(args, "access"));

    when_true_status(!amxd_action_verify_access(object, access),
                     exit,
                     status = amxd_status_object_not_found);

    amxc_var_set_type(retval, AMXC_VAR_ID_HTABLE);
    amxd_describe_object_impl(object, args, retval);

    for(uint32_t i = 0; i < 5; i++) {
        if(amxd_must_add(args, parts[i].name, object)) {
            status = parts[i].fn(object, args, retval);
            when_failed(status, exit);
        }
    }

    status = amxd_status_ok;

exit:
    return status;
}

amxd_status_t amxd_object_describe(amxd_object_t* const object,
                                   amxc_var_t* const value,
                                   uint32_t flags,
                                   amxd_dm_access_t access) {
    amxd_status_t retval = amxd_status_unknown_error;
    amxc_var_t args;

    amxc_var_init(&args);

    when_null(object, exit);
    when_null(value, exit);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(bool, &args, "parameters", flags & (AMXD_OBJECT_PARAM | AMXD_OBJECT_KEY_PARAM));
    amxc_var_add_key(bool, &args, "functions", flags & AMXD_OBJECT_FUNC);
    amxc_var_add_key(bool, &args, "objects", flags & AMXD_OBJECT_CHILD);
    amxc_var_add_key(bool, &args, "instances", flags & AMXD_OBJECT_INSTANCE);
    amxc_var_add_key(bool, &args, "template_info", flags & AMXD_TEMPLATE_INFO);
    amxc_var_add_key(bool, &args, "events", flags & AMXD_OBJECT_EVENT);
    amxc_var_add_key(uint32_t, &args, "access", access);

    if(flags & (AMXD_OBJECT_KEY_PARAM)) {
        uint32_t attributes = flags & AMXD_OBJECT_KEY_PARAM ? SET_BIT(amxd_pattr_key) : 0;
        amxc_var_add_key(uint32_t, &args, "attributes", attributes);
    }

    retval = amxd_dm_invoke_action(object,
                                   NULL,
                                   action_object_describe,
                                   &args,
                                   value);

exit:
    amxc_var_clean(&args);
    return retval;
}

amxd_status_t amxd_object_describe_params(amxd_object_t* const object,
                                          amxc_var_t* const value,
                                          amxd_dm_access_t access) {
    return amxd_object_describe_item(object,
                                     value,
                                     AMXD_OBJECT_PARAM,
                                     access,
                                     "parameters");
}

amxd_status_t amxd_object_describe_key_params(amxd_object_t* const object,
                                              amxc_var_t* const value,
                                              amxd_dm_access_t access) {
    return amxd_object_describe_item(object,
                                     value,
                                     AMXD_OBJECT_KEY_PARAM,
                                     access,
                                     "parameters");
}

amxd_status_t amxd_object_describe_events(amxd_object_t* const object,
                                          amxc_var_t* const value,
                                          amxd_dm_access_t access) {
    return amxd_object_describe_item(object,
                                     value,
                                     AMXD_OBJECT_EVENT,
                                     access,
                                     "events");
}

amxd_status_t amxd_object_describe_functions(amxd_object_t* const object,
                                             amxc_var_t* const value,
                                             amxd_dm_access_t access) {
    return amxd_object_describe_item(object,
                                     value,
                                     AMXD_OBJECT_FUNC,
                                     access,
                                     "functions");
}