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
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <amxc/amxc.h>
#include <amxp/amxp.h>

#include <amxd/amxd_types.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_object_expression.h>
#include <amxd/amxd_dm.h>

#include "amxd_priv.h"
#include "amxd_dm_priv.h"
#include "amxd_object_priv.h"
#include "amxd_assert.h"

static void amxd_object_set_attributes(amxd_object_t* const object,
                                       const uint32_t attr) {
    object->attr.read_only = IS_BIT_SET(attr, amxd_oattr_read_only);
    object->attr.persistent = IS_BIT_SET(attr, amxd_oattr_persistent);
    object->attr.priv = IS_BIT_SET(attr, amxd_oattr_private);
    object->attr.prot = IS_BIT_SET(attr, amxd_oattr_protected);
    object->attr.locked = IS_BIT_SET(attr, amxd_oattr_locked);
}

static bool amxd_object_type_is_valid(const amxd_object_type_t type) {
    return (type == amxd_object_singleton ||
            type == amxd_object_template ||
            type == amxd_object_mib);
}

static bool amxd_is_valid_counter(amxd_object_t* const counter,
                                  amxd_object_t* const counted) {
    bool retval = false;

    when_null(counter, exit);
    when_null(counted, exit);

    when_true(amxd_object_get_type(counted) != amxd_object_template, exit);

    retval = true;

exit:
    return retval;
}

static amxd_param_t* amxd_create_counter_param(amxd_object_t* const container,
                                               amxd_object_t* const counted,
                                               const char* name) {
    amxd_param_t* param = NULL;
    amxc_var_t count;
    amxd_status_t status = amxd_status_ok;
    amxd_dm_t* dm = amxd_object_get_dm(container);

    amxc_var_init(&count);
    when_str_empty(name, exit);
    param = amxd_object_get_param_def(container, name);
    if(param != NULL) {
        if(!amxd_param_is_attr_set(param, amxd_pattr_counter)) {
            status = amxd_status_invalid_name;
            param = NULL;
        }
    } else {
        amxd_param_new(&param, name, AMXC_VAR_ID_UINT32);
        status = amxd_object_add_param(container, param);
        when_failed(status, exit);
        param->priv = amxd_object_get_rel_path(counted, container, AMXD_OBJECT_NAMED);
        amxd_param_add_action_cb(param,
                                 action_param_destroy,
                                 amxd_param_counter_destroy,
                                 dm);
    }

    when_null(param, exit);
    amxd_param_set_attr(param, amxd_pattr_read_only, true);
    amxd_param_set_attr(param, amxd_pattr_counter, true);

    amxc_var_set(uint32_t, &count, amxd_object_get_instance_count(counted));
    status = amxd_param_set_value(param, &count);
    when_failed(status, exit);

    status = amxd_status_ok;

exit:
    if(status != amxd_status_ok) {
        amxd_param_free(&param);
        param = NULL;
    }
    amxc_var_clean(&count);
    return param;
}

void amxd_object_free(amxd_object_t** object) {
    amxd_object_type_t object_type;
    amxd_param_t* counter = NULL;

    when_null(object, exit);
    when_null((*object), exit);

    object_type = amxd_object_get_type(*object);
    if((object_type == amxd_object_instance) || (object_type == amxd_object_template)) {
        counter = amxd_object_get_param_counter_by_counted_object(*object);
    }

    amxd_object_clean((*object));

    if(amxc_llist_is_empty(&(*object)->derived_objects)) {
        free((*object));
    }

    *object = NULL;

    when_null(counter, exit);

    if(object_type == amxd_object_instance) {
        amxd_param_counter_update(counter);
    } else if(object_type == amxd_object_template) {
        amxd_param_delete(&counter);
    }

exit:
    return;
}

amxd_status_t amxd_object_new(amxd_object_t** object,
                              const amxd_object_type_t type,
                              const char* name) {
    amxd_status_t retval = amxd_status_unknown_error;
    when_null(object, exit);
    when_true_status(!amxd_object_type_is_valid(type),
                     exit,
                     retval = amxd_status_invalid_type);
    when_true_status(!amxd_name_is_valid(name),
                     exit,
                     retval = amxd_status_invalid_name);

    *object = (amxd_object_t*) calloc(1, sizeof(amxd_object_t));
    when_null((*object), exit);

    retval = amxd_object_init(*object, type, name, NULL, NULL);
    when_failed(retval, exit);

exit:
    return retval;
}

amxd_status_t amxd_object_add_object(amxd_object_t* const parent,
                                     amxd_object_t* const child) {
    amxd_status_t retval = amxd_status_unknown_error;

    when_null(parent, exit);
    when_null(child, exit);
    when_true(parent == child, exit);

    when_true_status(child->it.llist == &parent->objects,
                     exit,
                     retval = amxd_status_ok);
    when_not_null(child->it.llist, exit);

    when_true_status(!amxd_object_type_is_valid(child->type),
                     exit,
                     retval = amxd_status_invalid_type);
    when_true_status(child->type == amxd_object_mib,
                     exit,
                     retval = amxd_status_invalid_type);
    when_not_null_status(amxd_object_get_child(parent, child->name),
                         exit,
                         retval = amxd_status_duplicate);

    when_failed(amxc_llist_append(&parent->objects, &child->it), exit);
    amxd_dm_event("dm:object-added", child, NULL, false);

    retval = amxd_status_ok;

exit:
    return retval;
}

const char* amxd_object_get_name(const amxd_object_t* const object,
                                 const uint32_t flags) {
    const char* name = NULL;

    when_null(object, exit);
    if(object->type == amxd_object_instance) {
        if((flags & AMXD_OBJECT_INDEXED) == AMXD_OBJECT_INDEXED) {
            name = object->index_name;
        } else {
            name = object->name;
        }
    } else {
        name = object->name;
        if((name == NULL) && (object->derived_from.llist != NULL)) {
            amxd_object_t* super = amxc_container_of(object->derived_from.llist,
                                                     amxd_object_t,
                                                     derived_objects);

            name = amxd_object_get_name(super, AMXD_OBJECT_NAMED);
        }
    }

exit:
    return name;
}

uint32_t amxd_object_get_index(const amxd_object_t* const object) {
    return object == NULL ? 0 : object->index;
}

amxd_status_t amxd_object_set_attr(amxd_object_t* const object,
                                   const amxd_oattr_id_t attr,
                                   const bool enable) {
    amxd_status_t retval = amxd_status_unknown_error;
    uint32_t flags = 0;
    when_null(object, exit);

    when_true_status(object->type == amxd_object_mib,
                     exit,
                     retval = amxd_status_invalid_type);

    when_true_status(attr < 0 || attr > amxd_oattr_max,
                     exit,
                     retval = amxd_status_invalid_attr);

    when_true(amxd_object_is_attr_set(object, amxd_oattr_locked), exit);

    flags = amxd_object_get_attrs(object);

    if(enable) {
        flags |= SET_BIT(attr);
    } else {
        flags &= ~SET_BIT(attr);
    }

    amxd_object_set_attributes(object, flags);
    retval = amxd_status_ok;

exit:
    return retval;
}

amxd_status_t amxd_object_set_attrs(amxd_object_t* const object,
                                    const uint32_t bitmask,
                                    bool enable) {
    amxd_status_t retval = amxd_status_unknown_error;
    uint32_t flags = 0;
    uint32_t all = 0;

    when_null(object, exit);
    when_true_status(object->type == amxd_object_mib,
                     exit,
                     retval = amxd_status_invalid_type);

    for(int i = 0; i <= amxd_oattr_max; i++) {
        all |= SET_BIT(i);
    }

    when_true_status(bitmask > all, exit, retval = amxd_status_invalid_attr);

    flags = amxd_object_get_attrs(object);

    if(enable) {
        flags |= bitmask;
    } else {
        flags &= ~bitmask;
    }

    amxd_object_set_attributes(object, flags);
    retval = amxd_status_ok;

exit:
    return retval;
}

uint32_t amxd_object_get_attrs(const amxd_object_t* const object) {
    uint32_t attributes = 0;
    when_null(object, exit);

    attributes |= object->attr.read_only << amxd_oattr_read_only;
    attributes |= object->attr.persistent << amxd_oattr_persistent;
    attributes |= object->attr.priv << amxd_oattr_private;
    attributes |= object->attr.prot << amxd_oattr_protected;
    attributes |= object->attr.locked << amxd_oattr_locked;

exit:
    return attributes;
}

bool amxd_object_is_attr_set(const amxd_object_t* const object,
                             const amxd_oattr_id_t attr) {
    uint32_t flags = 0;
    bool retval = false;
    when_null(object, exit);
    when_true(attr < 0 || attr > amxd_oattr_max, exit);

    flags = amxd_object_get_attrs(object);
    retval = (flags & (1 << attr)) != 0 ? true : false;

exit:
    return retval;
}

amxd_status_t amxd_object_set_counter(amxd_object_t* const object,
                                      const char* name) {
    amxd_status_t status = amxd_status_unknown_error;
    amxd_param_t* param = NULL;
    amxd_object_t* container = NULL;

    container = amxd_object_get_parent(object);
    when_true(!amxd_is_valid_counter(container, object), exit);
    param = amxd_create_counter_param(container, object, name);
    when_null(param, exit);

    if((amxd_object_get_type(container) == amxd_object_instance) ||
       (amxd_object_get_type(container) == amxd_object_singleton) ||
       (amxd_object_get_type(container) == amxd_object_template)) {
        status = amxd_status_ok;
    }

exit:
    if(status != amxd_status_ok) {
        if(param != NULL) {
            free(param->priv);
        }
        amxd_param_free(&param);
    }
    return status;
}

amxd_object_t* amxd_object_get_base(const amxd_object_t* const object) {
    amxd_object_t* base = NULL;

    when_null(object, exit);
    when_null(object->derived_from.llist, exit);
    base = amxc_container_of(object->derived_from.llist, amxd_object_t, derived_objects);

exit:
    return base;
}
