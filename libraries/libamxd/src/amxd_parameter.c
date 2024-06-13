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

#include <amxc/amxc.h>
#include <amxp/amxp_signal.h>
#include <amxp/amxp_slot.h>

#include <amxd/amxd_common.h>
#include <amxd/amxd_dm.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_object_event.h>

#include "amxd_priv.h"
#include "amxd_assert.h"
#include "amxd_dm_priv.h"

static void amxd_param_free_cb_it(amxc_llist_it_t* it) {
    amxd_dm_cb_t* cb = amxc_llist_it_get_data(it, amxd_dm_cb_t, it);
    free(cb);
}

static bool amxd_param_type_is_valid(const uint32_t type) {
    return (amxc_var_get_type(type) != NULL &&
            type < AMXC_VAR_ID_CUSTOM_BASE &&
            type != AMXC_VAR_ID_LIST &&
            type != AMXC_VAR_ID_HTABLE &&
            type != AMXC_VAR_ID_FD &&
            type != AMXC_VAR_ID_ANY);
}

static amxd_status_t amxd_param_init(amxd_param_t* const param,
                                     const char* name,
                                     uint32_t type) {
    amxd_status_t retval = amxd_status_unknown_error;

    amxc_llist_it_init(&param->it);
    amxc_llist_init(&param->cb_fns);

    param->attr.templ = 0;
    param->attr.instance = 0;
    param->attr.priv = 0;
    param->attr.read_only = 0;
    param->attr.persistent = 0;
    param->attr.variable = 0;
    param->attr.counter = 0;
    param->attr.key = 0;
    param->attr.unique = 0;
    param->attr.prot = 0;
    param->attr.changeable = 0;

    amxc_var_init(&param->value);
    param->name = strdup(name);
    when_null(param->name, exit);
    amxc_var_set_type(&param->value, type);
    retval = amxd_status_ok;

exit:
    return retval;
}

static int amxd_param_clean(amxd_param_t* const param) {
    amxc_llist_it_take(&param->it);
    amxc_llist_clean(&param->cb_fns, amxd_param_free_cb_it);
    amxc_var_delete(&param->flags);

    amxc_var_clean(&param->value);
    free(param->name);
    param->name = NULL;

    return 0;
}

static amxd_status_t amxd_param_check_key_attr(amxd_param_t* const param,
                                               const uint32_t attr) {
    amxd_status_t status = amxd_status_invalid_attr;
    amxd_object_t* owner = amxd_param_get_owner(param);

    if(param->attr.key == 1) {
        when_true(!IS_BIT_SET(attr, amxd_pattr_key), exit);
    }

    when_true_status(!IS_BIT_SET(attr, amxd_pattr_key),
                     exit,
                     status = amxd_status_ok);

    if(owner != NULL) {
        if(((amxd_object_get_type(owner) == amxd_object_template) &&
            !amxc_llist_is_empty(&owner->instances)) ||
           (amxd_object_get_type(owner) == amxd_object_instance) ||
           ( amxd_object_get_type(owner) == amxd_object_mib) ||
           ( amxd_object_get_type(owner) == amxd_object_singleton)) {
            goto exit;
        }
    }

    status = amxd_status_ok;

exit:
    return status;
}

static amxd_status_t amxd_param_check_templ_attr(amxd_param_t* const param,
                                                 const uint32_t attr) {
    amxd_status_t status = amxd_status_ok;
    amxd_object_t* owner = amxd_param_get_owner(param);

    when_null(owner, exit);
    if(amxd_object_get_type(owner) == amxd_object_instance) {
        if(IS_BIT_SET(attr, amxd_pattr_template)) {
            status = amxd_status_invalid_attr;
        }
    }

exit:
    return status;
}

static amxd_status_t amxd_param_set_attributes(amxd_param_t* const param,
                                               const uint32_t attr) {
    amxd_status_t status = amxd_status_ok;
    bool was_counter = param->attr.counter == 1 ? true : false;
    bool is_counter = false;

    status = amxd_param_check_templ_attr(param, attr);
    when_failed(status, exit);
    status = amxd_param_check_key_attr(param, attr);
    when_failed(status, exit);

    param->attr.templ = IS_BIT_SET(attr, amxd_pattr_template);
    param->attr.instance = IS_BIT_SET(attr, amxd_pattr_instance);
    param->attr.priv = IS_BIT_SET(attr, amxd_pattr_private);
    param->attr.prot = IS_BIT_SET(attr, amxd_pattr_protected);
    param->attr.read_only = IS_BIT_SET(attr, amxd_pattr_read_only);
    param->attr.persistent = IS_BIT_SET(attr, amxd_pattr_persistent);
    param->attr.variable = IS_BIT_SET(attr, amxd_pattr_variable);
    param->attr.counter = IS_BIT_SET(attr, amxd_pattr_counter);
    param->attr.key = IS_BIT_SET(attr, amxd_pattr_key);
    param->attr.unique = IS_BIT_SET(attr, amxd_pattr_unique);
    param->attr.changeable = IS_BIT_SET(attr, amxd_pattr_mutable);

    is_counter = param->attr.counter == 1 ? true : false;
    if(was_counter && !is_counter) {
        free(param->priv);
        param->priv = NULL;
    }

exit:
    return status;
}

amxd_status_t amxd_param_counter_update(amxd_param_t* counter) {
    amxd_status_t status = amxd_status_unknown_error;
    amxd_object_t* owner = NULL;
    amxd_object_t* counted = NULL;
    const char* template_path = NULL;
    amxc_var_t old_values;

    when_null(counter, exit);
    when_true(!amxd_param_is_attr_set(counter, amxd_pattr_counter), exit);

    owner = amxd_param_get_owner(counter);
    template_path = (const char*) counter->priv;
    counted = amxd_object_findf(owner, "%s", template_path);
    when_null(counted, exit);
    amxc_var_init(&old_values);
    amxc_var_set_type(&old_values, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(uint32_t,
                     &old_values,
                     amxd_param_get_name(counter),
                     GET_UINT32(&counter->value, NULL));
    amxc_var_set(uint32_t, &counter->value, amxd_object_get_instance_count(counted));
    amxd_object_send_changed(owner, &old_values, false);
    amxc_var_clean(&old_values);

    status = amxd_status_ok;

exit:
    return status;
}

amxd_status_t amxd_param_new(amxd_param_t** param,
                             const char* name,
                             const uint32_t type) {

    amxd_status_t retval = amxd_status_unknown_error;
    when_null(param, exit);
    when_true_status(!amxd_name_is_valid(name),
                     exit,
                     retval = amxd_status_invalid_name);

    when_true_status(!amxd_param_type_is_valid(type),
                     exit,
                     retval = amxd_status_invalid_type);

    *param = (amxd_param_t*) calloc(1, sizeof(amxd_param_t));
    when_null((*param), exit);

    retval = amxd_param_init(*param, name, type);

exit:
    if((retval != 0) && (param != NULL)) {
        free(*param);
        *param = NULL;
    }
    return retval;
}

void amxd_param_free(amxd_param_t** param) {
    when_null(param, exit);
    when_null((*param), exit);

    amxd_param_clean((*param));
    amxc_llist_it_take(&(*param)->it);

    free(*param);
    *param = NULL;

exit:
    return;
}

amxd_status_t amxd_param_copy(amxd_param_t** dest,
                              const amxd_param_t* const source) {
    amxd_status_t retval = amxd_status_unknown_error;
    when_null(dest, exit);
    when_null(source, exit);

    *dest = (amxd_param_t*) calloc(1, sizeof(amxd_param_t));
    when_null((*dest), exit);

    when_failed(amxd_param_init(*dest,
                                source->name,
                                amxc_var_type_of(&source->value)),
                exit);
    (*dest)->attr = source->attr;
    amxc_var_copy(&(*dest)->value, &source->value);
    if(source->flags != NULL) {
        amxc_var_new(&(*dest)->flags);
        amxc_var_copy((*dest)->flags, source->flags);
    }

    retval = amxd_status_ok;

exit:
    if((retval != amxd_status_ok) && (dest != NULL) && (*dest != NULL)) {
        amxd_param_clean(*dest);
        free(*dest);
        *dest = NULL;
    }
    return retval;
}

amxd_object_t* amxd_param_get_owner(const amxd_param_t* const param) {
    amxd_object_t* object = NULL;
    when_null(param, exit);
    when_null(param->it.llist, exit);

    object = amxc_container_of(param->it.llist, amxd_object_t, parameters);

exit:
    return object;
}

const char* amxd_param_get_name(const amxd_param_t* const param) {
    return param == NULL ? NULL : param->name;
}

amxd_status_t amxd_param_set_attr(amxd_param_t* param,
                                  const amxd_pattr_id_t attr,
                                  const bool enable) {
    amxd_status_t retval = amxd_status_unknown_error;
    uint32_t flags = 0;
    when_null(param, exit);
    when_true_status(attr < 0 || attr > amxd_pattr_max,
                     exit,
                     retval = amxd_status_invalid_attr);

    flags = amxd_param_get_attrs(param);

    if(enable) {
        flags |= (1 << attr);
    } else {
        flags &= ~(1 << attr);
    }

    retval = amxd_param_set_attributes(param, flags);

exit:
    return retval;
}

amxd_status_t amxd_param_set_attrs(amxd_param_t* param,
                                   const uint32_t bitmask,
                                   bool enable) {
    amxd_status_t retval = amxd_status_unknown_error;
    uint32_t flags = 0;
    uint32_t all = 0;
    for(int i = 0; i <= amxd_pattr_max; i++) {
        all |= SET_BIT(i);
    }

    when_null(param, exit);
    when_true_status(bitmask > all, exit, retval = amxd_status_invalid_attr);

    flags = amxd_param_get_attrs(param);

    if(enable) {
        flags |= bitmask;
    } else {
        flags &= ~bitmask;
    }

    retval = amxd_param_set_attributes(param, flags);

exit:
    return retval;
}

uint32_t amxd_param_get_attrs(const amxd_param_t* const param) {
    uint32_t attributes = 0;
    when_null(param, exit);

    attributes |= param->attr.templ << amxd_pattr_template;
    attributes |= param->attr.instance << amxd_pattr_instance;
    attributes |= param->attr.priv << amxd_pattr_private;
    attributes |= param->attr.prot << amxd_pattr_protected;
    attributes |= param->attr.read_only << amxd_pattr_read_only;
    attributes |= param->attr.persistent << amxd_pattr_persistent;
    attributes |= param->attr.variable << amxd_pattr_variable;
    attributes |= param->attr.counter << amxd_pattr_counter;
    attributes |= param->attr.key << amxd_pattr_key;
    attributes |= param->attr.unique << amxd_pattr_unique;
    attributes |= param->attr.changeable << amxd_pattr_mutable;

exit:
    return attributes;
}

bool amxd_param_is_attr_set(const amxd_param_t* const param,
                            const amxd_pattr_id_t attr) {
    uint32_t flags = 0;
    bool retval = false;
    when_null(param, exit);
    when_true(attr < 0 || attr > amxd_pattr_max, exit);

    flags = amxd_param_get_attrs(param);
    retval = (flags & (1 << attr)) != 0 ? true : false;

exit:
    return retval;
}

void amxd_param_set_flag(amxd_param_t* param, const char* flag) {
    when_null(param, exit);
    when_null(flag, exit);
    when_true(*flag == 0, exit);

    amxd_common_set_flag(&param->flags, flag);

exit:
    return;
}

void amxd_param_unset_flag(amxd_param_t* param, const char* flag) {
    when_null(param, exit);
    when_null(flag, exit);
    when_true(*flag == 0, exit);

    amxd_common_unset_flag(&param->flags, flag);

exit:
    return;
}

bool amxd_param_has_flag(const amxd_param_t* const param, const char* flag) {
    bool retval = false;
    when_null(param, exit);
    when_null(flag, exit);
    when_true(*flag == 0, exit);

    retval = amxd_common_has_flag(param->flags, flag);

exit:
    return retval;
}
