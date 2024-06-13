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
#include <amxp/amxp.h>

#include <amxd/amxd_types.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_object_expression.h>
#include <amxd/amxd_object_event.h>
#include <amxd/amxd_dm.h>
#include <amxd/amxd_dm_functions.h>

#include "amxd_priv.h"
#include "amxd_dm_priv.h"
#include "amxd_object_priv.h"
#include "amxd_assert.h"

static
void amxd_dm_llist_clean(amxc_llist_t* const llist,
                         amxc_llist_it_delete_t func) {
    amxc_llist_for_each(it, llist) {
        func(it);
    }
}

static
void amxd_object_free_object_it(amxc_llist_it_t* it) {
    amxd_object_t* object = amxc_llist_it_get_data(it, amxd_object_t, it);
    amxd_object_delete(&object);
}

static
void amxd_object_free_param_it(amxc_llist_it_t* it) {
    amxd_param_t* param = amxc_llist_it_get_data(it, amxd_param_t, it);
    amxd_object_t* owner = amxd_param_get_owner(param);
    amxd_dm_invoke_action(owner, param, action_param_destroy, NULL, NULL);
}

static
void amxd_object_free_cb_it(amxc_llist_it_t* it) {
    amxd_dm_cb_t* cb = amxc_llist_it_get_data(it, amxd_dm_cb_t, it);
    free(cb);
}

void amxd_object_free_func_it(amxc_llist_it_t* it) {
    amxd_function_t* func = amxc_llist_it_get_data(it, amxd_function_t, it);
    amxd_function_delete(&func);
}

const char* amxd_object_template_get_alias(amxc_var_t* templ_params,
                                           amxc_var_t* values) {
    amxc_var_t* alias_def = GET_FIELD(templ_params, "Alias");
    amxc_var_t* alias_val = GET_FIELD(values, "Alias");
    const char* alias_name = NULL;

    when_null(alias_def, exit);
    when_true(!amxc_var_constcast(bool,
                                  GET_FIELD(alias_def, "attributes.key")),
              exit);
    when_true(!amxc_var_constcast(bool,
                                  GET_FIELD(alias_def, "attributes.unique")),
              exit);

    alias_name = amxc_var_constcast(cstring_t, alias_val);

exit:
    return alias_name;
}

amxd_status_t amxd_object_init(amxd_object_t* const object,
                               const amxd_object_type_t type,
                               const char* name,
                               amxc_var_t* templ_params,
                               amxc_var_t* values) {
    amxd_status_t retval = amxd_status_unknown_error;

    amxd_object_init_base(object, type);

    if(amxd_object_get_type(object) == amxd_object_instance) {
        const char* alias = amxd_object_template_get_alias(templ_params, values);
        if((alias != NULL) && (alias[0] != 0)) {
            object->name = strdup(alias);
            when_null(object->name, exit);
        }
    }
    if(object->name == NULL) {
        if((name != NULL) && (name[0] != 0)) {
            object->name = strdup(name);
            when_null(object->name, exit);
        }
    }
    amxd_dm_set_derived_from(object);

    retval = amxd_status_ok;

exit:
    return retval;
}

void amxd_object_destroy_handlers(amxd_object_t* const object) {
    amxd_dm_llist_clean(&object->instances, amxd_object_free_object_it);
    amxd_dm_llist_clean(&object->objects, amxd_object_free_object_it);
}

void amxd_object_clean(amxd_object_t* const object) {
    amxd_object_destroy_handlers(object);
    amxd_dm_llist_clean(&object->parameters, amxd_object_free_param_it);
    amxc_llist_it_take(&object->it);

    amxc_llist_clean(&object->functions, amxd_object_free_func_it);
    amxc_llist_clean(&object->cb_fns, amxd_object_free_cb_it);
    amxc_array_clean(&object->mib_names, NULL);
    amxc_var_clean(&object->events);

    if(amxc_llist_it_is_in_list(&object->derived_from)) {
        amxd_object_t* super = NULL;
        super = amxc_container_of(object->derived_from.llist,
                                  amxd_object_t,
                                  derived_objects);
        amxc_llist_it_take(&object->derived_from);
        if(amxc_llist_is_empty(&super->derived_objects) &&
           ( super->it.llist == NULL)) {
            amxd_object_free(&super);
        }
    }

    free(object->index_name);
    object->index_name = NULL;
    free(object->name);
    object->name = NULL;
}

void amxd_fetch_item(amxc_var_t* const full_data,
                     const char* item,
                     amxc_var_t* const data) {
    amxc_var_t* item_data = amxc_var_get_path(full_data,
                                              item,
                                              AMXC_VAR_FLAG_DEFAULT);

    if(amxc_var_type_of(item_data) == AMXC_VAR_ID_LIST) {
        const amxc_llist_t* src_list = amxc_var_constcast(amxc_llist_t, item_data);
        amxc_var_set_type(data, AMXC_VAR_ID_LIST);
        amxc_llist_for_each(it, src_list) {
            amxc_llist_append(&data->data.vl, it);
        }

    } else if(amxc_var_type_of(item_data) == AMXC_VAR_ID_HTABLE) {
        const amxc_htable_t* src_table = amxc_var_constcast(amxc_htable_t, item_data);
        amxc_htable_it_t* it = NULL;
        amxc_var_set_type(data, AMXC_VAR_ID_HTABLE);
        it = amxc_htable_get_first(src_table);
        while(it) {
            const char* key = amxc_htable_it_get_key(it);
            amxc_htable_insert(&data->data.vm, key, it);
            it = amxc_htable_get_first(src_table);
        }
    }
}

amxd_function_t* amxd_object_get_self_func(const amxd_object_t* const object,
                                           const char* name) {
    amxd_function_t* func = NULL;

    amxc_llist_for_each(it, (&object->functions)) {
        const char* func_name = NULL;
        func = amxc_llist_it_get_data(it, amxd_function_t, it);
        func_name = amxd_function_get_name(func);
        if(strcmp(func_name, name) == 0) {
            break;
        }
        func = NULL;
    }

    return func;
}

amxd_status_t amxd_object_copy_params(amxd_object_t* const dst,
                                      const amxd_object_t* const src) {
    amxd_status_t retval = amxd_status_unknown_error;
    bool dst_is_inst = (amxd_object_get_type(dst) == amxd_object_instance);
    bool dst_is_templ = (amxd_object_get_type(dst) == amxd_object_template);
    bool src_is_mib = (amxd_object_get_type(src) == amxd_object_mib);
    amxc_llist_for_each(it, (&src->parameters)) {
        amxd_param_t* base = amxc_llist_it_get_data(it, amxd_param_t, it);
        amxd_param_t* derived = NULL;
        uint32_t attrs = amxd_param_get_attrs(base);
        if(!src_is_mib &&
           dst_is_inst &&
           !amxd_param_is_attr_set(base, amxd_pattr_instance)) {
            continue;
        }
        if(amxd_param_is_attr_set(base, amxd_pattr_counter) && !src_is_mib) {
            amxd_object_t* counted = amxd_object_get_child(dst, (char*) base->priv);
            retval = amxd_object_set_counter(counted, amxd_param_get_name(base));
            when_failed(retval, exit);
            derived = amxd_object_get_param_def(dst, amxd_param_get_name(base));
        } else {
            retval = amxd_param_copy(&derived, base);
            when_failed(retval, exit);
            if(src_is_mib) {
                amxc_llist_iterate(cb_it, (&base->cb_fns)) {
                    amxd_dm_cb_t* mib_cb = amxc_llist_it_get_data(cb_it, amxd_dm_cb_t, it);
                    if(mib_cb->reason == action_param_destroy) {
                        continue;
                    }
                    amxd_param_add_action_cb(derived,
                                             mib_cb->reason,
                                             mib_cb->fn,
                                             mib_cb->priv);
                }
                if(dst_is_inst || dst_is_templ) {
                    if(!IS_BIT_SET(attrs, amxd_pattr_instance) &&
                       !IS_BIT_SET(attrs, amxd_pattr_template)) {
                        amxd_param_set_attr(derived, amxd_pattr_instance, true);
                    }
                    if(dst_is_inst) {
                        if(!amxd_param_is_attr_set(derived, amxd_pattr_instance)) {
                            amxd_param_delete(&derived);
                            continue;
                        }
                    }
                }
            }
            amxc_llist_append(&dst->parameters, &derived->it);
        }
        amxd_param_set_attrs(derived, attrs, true);
    }

    retval = amxd_status_ok;
exit:
    return retval;
}

amxd_status_t amxd_object_copy_funcs(amxd_object_t* const dst,
                                     const amxd_object_t* const src) {
    amxd_status_t retval = amxd_status_unknown_error;
    bool dst_is_inst = (amxd_object_get_type(dst) == amxd_object_instance);
    bool dst_is_templ = (amxd_object_get_type(dst) == amxd_object_template);
    bool src_is_mib = (amxd_object_get_type(src) == amxd_object_mib);
    amxc_llist_for_each(it, (&src->functions)) {
        amxd_function_t* base = amxc_llist_it_get_data(it, amxd_function_t, it);
        amxd_function_t* derived = NULL;
        if(!src_is_mib &&
           dst_is_inst &&
           !amxd_function_is_attr_set(base, amxd_fattr_instance)) {
            continue;
        }
        retval = amxd_function_copy(&derived, base);
        when_failed(retval, exit);
        if(src_is_mib && (dst_is_inst || dst_is_templ)) {
            uint32_t attrs = amxd_function_get_attrs(base);
            if(!IS_BIT_SET(attrs, amxd_fattr_instance) &&
               !IS_BIT_SET(attrs, amxd_fattr_template)) {
                amxd_function_set_attr(derived, amxd_fattr_instance, true);
            }
            if(dst_is_inst) {
                if(!amxd_function_is_attr_set(derived, amxd_fattr_instance)) {
                    amxd_function_delete(&derived);
                    continue;
                }
            }
        }
        amxc_llist_append(&dst->functions, &derived->it);
    }

    retval = amxd_status_ok;
exit:
    return retval;
}

amxd_status_t amxd_object_copy_events(amxd_object_t* const dst,
                                      const amxd_object_t* const src) {
    amxc_var_for_each(data, &src->events) {
        amxc_var_t* new_data = NULL;
        const char* name = amxc_var_key(data);

        amxc_var_new(&new_data);
        amxc_var_copy(new_data, data);
        amxd_object_add_event_ext(dst, name, new_data);
    }

    return amxd_status_ok;
}

amxd_status_t amxd_object_copy_mib_names(amxd_object_t* const dst,
                                         const amxd_object_t* const src) {
    amxd_status_t retval = amxd_status_unknown_error;
    amxc_array_it_t* ait = amxc_array_get_first(&src->mib_names);
    while(ait != NULL) {
        const char* name = (const char*) amxc_array_it_get_data(ait);
        if(name != NULL) {
            amxc_array_append_data(&dst->mib_names, (void*) name);
        }
        ait = amxc_array_it_get_next(ait);
    }

    retval = amxd_status_ok;
    return retval;
}

amxd_status_t amxd_object_copy_children(amxd_object_t* const dst,
                                        const amxd_object_t* const src) {
    amxd_status_t retval = amxd_status_unknown_error;
    amxc_llist_for_each(it, (&src->objects)) {
        amxd_object_t* base = amxc_llist_it_get_data(it, amxd_object_t, it);
        amxd_object_t* derived = NULL;
        retval = amxd_object_derive(&derived, base, dst);
        when_failed(retval, exit);
        retval = amxd_object_copy_params(derived, base);
        when_failed(retval, exit);
        retval = amxd_object_copy_mib_names(derived, base);
        when_failed(retval, exit);
    }

    retval = amxd_status_ok;
exit:
    return retval;
}

amxd_status_t amxd_object_derive(amxd_object_t** object,
                                 amxd_object_t* const base,
                                 amxd_object_t* const parent) {
    amxd_status_t retval = amxd_status_unknown_error;
    when_null(object, exit);

    *object = (amxd_object_t*) calloc(1, sizeof(amxd_object_t));
    when_null((*object), exit);

    (*object)->attr = base->attr;
    (*object)->type = base->type;
    amxc_llist_append(&base->derived_objects, &(*object)->derived_from);
    amxc_llist_append(&parent->objects, &(*object)->it);

    retval = amxd_object_copy_children((*object), base);
    when_failed(retval, exit);

exit:
    if((retval != amxd_status_ok) &&
       (object != NULL) &&
       (*object != NULL)) {
        amxd_object_clean(*object);
        free(*object);
        *object = NULL;
    }
    return retval;
}
