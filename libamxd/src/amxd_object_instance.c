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
#include <amxd/amxd_action.h>
#include <amxd/amxd_dm.h>

#include "amxd_priv.h"
#include "amxd_dm_priv.h"
#include "amxd_object_priv.h"
#include "amxd_assert.h"

static bool amxd_template_has_instance(const amxd_object_t* const templ,
                                       const char* name) {
    bool retval = false;

    amxc_llist_for_each(it, (&templ->instances)) {
        const char* n = NULL;
        amxd_object_t* result = amxc_llist_it_get_data(it, amxd_object_t, it);
        n = amxd_object_get_name(result, AMXD_OBJECT_NAMED);
        if(strcmp(n, name) == 0) {
            retval = true;
            break;
        }
    }

    return retval;
}

static bool amxd_template_has_index(const amxd_object_t* const templ,
                                    uint32_t index) {
    bool retval = false;

    if(index != 0) {
        amxc_llist_for_each(it, (&templ->instances)) {
            amxd_object_t* result = amxc_llist_it_get_data(it, amxd_object_t, it);
            if(result->index == index) {
                retval = true;
                break;
            }
        }
    } else {
        // index 0 is a special case, it can not be used as an index id
        // it is considered always available.
        retval = true;
    }
    return retval;
}

static amxd_status_t amxd_object_check_instance_alias(amxd_object_t* const templ,
                                                      amxc_var_t* templ_params,
                                                      amxc_htable_t* values,
                                                      uint32_t index,
                                                      const char** name) {
    amxd_status_t status = amxd_status_ok;
    amxc_var_t* alias = amxc_var_get_key(templ_params, "Alias", AMXC_VAR_FLAG_DEFAULT);
    amxc_htable_it_t* halias = amxc_htable_get(values, "Alias");
    const char* obj_name = amxd_object_get_name(templ, AMXD_OBJECT_NAMED);
    uint32_t new_index = index == 0 ? (templ->last_index + 1) : index;
    amxc_var_t* alias_var = NULL;

    when_null(alias, exit);
    when_true(!amxc_var_constcast(bool, GET_FIELD(alias, "attributes.key")), exit);
    when_true(!amxc_var_constcast(bool, GET_FIELD(alias, "attributes.unique")), exit);

    if(halias == NULL) {
        amxc_var_new(&alias_var);
        if((*name != NULL) && ((*name)[0] != 0)) {
            amxc_var_set(cstring_t, alias_var, *name);
        } else {
            amxc_string_t alias_name;
            amxc_string_init(&alias_name, 0);
            amxc_string_appendf(&alias_name, "cpe-%s-%d", obj_name, new_index);
            amxc_var_push(amxc_string_t, alias_var, &alias_name);
            amxc_string_clean(&alias_name);
        }
        amxc_htable_insert(values, "Alias", &alias_var->hit);
    } else {
        alias_var = amxc_var_from_htable_it(halias);
        if((amxc_var_type_of(alias_var) != AMXC_VAR_ID_CSTRING) &&
           ( amxc_var_type_of(alias_var) != AMXC_VAR_ID_SSV_STRING) &&
           ( amxc_var_type_of(alias_var) != AMXC_VAR_ID_CSV_STRING)) {
            status = amxd_status_invalid_value;
            goto exit;
        }
    }

    *name = amxc_var_constcast(cstring_t, alias_var);
    if(isdigit((*name)[0]) != 0) {
        status = amxd_status_invalid_name;
    }
    *name = "";

exit:
    return status;
}

static amxd_status_t amxd_object_instance_validate_id(amxd_object_t* templ,
                                                      const char** name,
                                                      uint32_t index,
                                                      amxc_var_t* templ_params,
                                                      amxc_var_t* values) {
    amxd_status_t retval = amxd_status_ok;
    amxp_expr_t* expr = NULL;
    amxc_htable_t* hvalues = (amxc_htable_t*) amxc_var_constcast(amxc_htable_t, values);
    bool has_matches = false;

    if(index != 0) {
        when_true_status(amxd_template_has_index(templ, index),
                         exit,
                         retval = amxd_status_duplicate);
    }

    retval = amxd_object_check_instance_alias(templ, templ_params, hvalues, index, name);
    when_true(retval != amxd_status_ok, exit);

    retval = amxd_object_build_key_expr(templ_params, &expr, hvalues);
    when_failed(retval, exit);

    has_matches = amxd_object_has_matching_instances(templ, expr);
    when_true_status(has_matches, exit, retval = amxd_status_duplicate);


    if((*name != NULL) && ((*name)[0] != 0)) {
        when_true_status(!amxd_name_is_valid(*name),
                         exit,
                         retval = amxd_status_invalid_name);
        when_true_status(amxd_template_has_instance(templ, *name),
                         exit,
                         retval = amxd_status_duplicate);
    }

exit:
    amxp_expr_delete(&expr);
    return retval;
}

static amxd_status_t amxd_object_instance_set_index_name(amxd_object_t* object,
                                                         amxd_object_t* templ,
                                                         const char* name,
                                                         uint32_t index) {
    amxd_status_t retval = amxd_status_unknown_error;
    uint32_t index_try = 0;
    int size_needed = 0;

    if(index == 0) {
        while(amxd_template_has_index(templ, templ->last_index + 1)) {
            index_try++;
            templ->last_index++;

            if(index_try > 10) {
                goto exit;
            }
        }
        object->index = templ->last_index + 1;
    } else {
        object->index = index;
    }

    size_needed = snprintf(NULL, 0, "%" PRIu32, object->index);
    object->index_name = (char*) calloc(size_needed + 1, sizeof(char));
    when_null(object->index_name, exit);
    snprintf(object->index_name, size_needed + 1, "%" PRIu32, object->index);
    if(object->name == NULL) {
        if((name == NULL) || (name[0] == 0)) {
            object->name = strdup(object->index_name);
            when_null(object->name, exit);
        }
    }
    if(object->index > templ->last_index) {
        templ->last_index = object->index;
    }

    retval = amxd_status_ok;

exit:
    return retval;
}

static amxd_status_t amxd_object_instantiate(amxd_object_t** object,
                                             amxd_object_t* templ,
                                             const char* name,
                                             uint32_t index,
                                             amxc_var_t* templ_params,
                                             amxc_var_t* tmp_values) {
    amxd_status_t retval = amxd_status_unknown_error;
    uint32_t attrs = 0;
    amxd_param_t* counter = NULL;

    *object = (amxd_object_t*) calloc(1, sizeof(amxd_object_t));
    when_null((*object), exit);
    retval = amxd_object_init(*object, amxd_object_instance, name, templ_params, tmp_values);
    when_true(retval != amxd_status_ok, exit);
    retval = amxd_object_instance_set_index_name((*object), templ, name, index);
    when_true(retval != amxd_status_ok, exit);
    attrs = amxd_object_get_attrs(templ);
    amxd_object_set_attrs(*object, attrs, true);

    amxc_llist_append(&templ->instances, &(*object)->it);
    retval = amxd_object_copy_children((*object), templ);
    when_failed(retval, exit);
    retval = amxd_object_copy_params((*object), templ);
    when_failed(retval, exit);
    retval = amxd_object_copy_mib_names((*object), templ);

    counter = amxd_object_get_param_counter_by_counted_object(*object);
    when_null(counter, exit);
    amxd_param_counter_update(counter);

exit:
    if(*object != NULL) {
        if(retval != amxd_status_ok) {
            amxd_object_clean(*object);
            free(*object);
            *object = NULL;
        }
    }
    return retval;
}

static amxd_status_t amxd_cleanup_max_instance(amxd_object_t* const object,
                                               UNUSED amxd_param_t* const param,
                                               amxd_action_t reason,
                                               UNUSED const amxc_var_t* const args,
                                               UNUSED amxc_var_t* const retval,
                                               void* priv) {
    amxd_status_t status = amxd_status_ok;
    amxc_var_t* data = (amxc_var_t*) priv;

    // action private data must not be removed when the action is used
    // on derivced objects.
    // only remove action data when the action is owned by the object or
    // parameter on which the action is called.
    if(amxd_object_has_action_cb(object, reason, amxd_cleanup_max_instance)) {
        amxc_var_delete(&data);
        amxd_object_set_action_cb_data(object, reason, amxd_cleanup_max_instance, NULL);
    }

    return status;
}

static void amxd_object_remove_max_instance_check(amxd_object_t* object,
                                                  amxc_var_t* max_var) {
    if(max_var != NULL) {
        amxc_var_delete(&max_var);
        amxd_object_remove_action_cb(object,
                                     action_object_add_inst,
                                     amxd_action_object_add_inst);
        amxd_object_remove_action_cb(object,
                                     action_object_destroy,
                                     amxd_cleanup_max_instance);
    }
}

static amxd_status_t amxd_object_add_max_instance_check(amxd_object_t* object,
                                                        uint32_t max) {
    amxc_var_t* max_var = NULL;
    amxd_status_t retval = amxd_status_unknown_error;

    amxc_var_new(&max_var);
    amxc_var_set(uint32_t, max_var, max);
    retval = amxd_object_add_action_cb(object,
                                       action_object_add_inst,
                                       amxd_action_object_add_inst,
                                       max_var);
    when_failed_status(retval, exit, amxc_var_delete(&max_var));
    retval = amxd_object_add_action_cb(object,
                                       action_object_destroy,
                                       amxd_cleanup_max_instance,
                                       max_var);
    if(retval != amxd_status_ok) {
        amxd_object_remove_action_cb(object,
                                     action_object_add_inst,
                                     amxd_action_object_add_inst);
        amxc_var_delete(&max_var);
        goto exit;
    }

    retval = amxd_status_ok;

exit:
    return retval;
}

amxd_status_t amxd_object_new_instance(amxd_object_t** object,
                                       amxd_object_t* templ,
                                       const char* name,
                                       uint32_t index,
                                       amxc_var_t* values) {
    amxd_status_t retval = amxd_status_unknown_error;
    amxc_var_t templ_params;
    amxc_var_t* tmp_values = NULL;
    amxc_var_t rv;

    amxc_var_init(&templ_params);
    amxc_var_init(&rv);
    when_null(object, exit);
    when_null(templ, exit);
    when_true_status(templ->type != amxd_object_template,
                     exit,
                     retval = amxd_status_invalid_type);
    when_true_status(values != NULL && amxc_var_type_of(values) != AMXC_VAR_ID_HTABLE,
                     exit,
                     retval = amxd_status_invalid_value);
    if(values == NULL) {
        amxc_var_new(&tmp_values);
        amxc_var_set_type(tmp_values, AMXC_VAR_ID_HTABLE);
    } else {
        tmp_values = values;
    }
    *object = NULL;
    retval = amxd_object_describe_key_params(templ, &templ_params, amxd_dm_access_private);
    when_failed(retval, exit);
    retval = amxd_object_instance_validate_id(templ, &name, index, &templ_params, tmp_values);
    when_failed(retval, exit);
    retval = amxd_object_instantiate(object, templ, name, index, &templ_params, tmp_values);
    when_failed(retval, exit);
    if(values == NULL) {
        retval = amxd_action_set_values((*object), amxd_dm_access_protected, true,
                                        tmp_values, &rv, true);
    }

exit:
    if(values == NULL) {
        amxc_var_delete(&tmp_values);
    }
    amxc_var_clean(&rv);
    amxc_var_clean(&templ_params);
    return retval;
}

amxd_status_t amxd_object_set_max_instances(amxd_object_t* object,
                                            uint32_t max) {
    amxd_status_t retval = amxd_status_unknown_error;
    amxc_var_t* max_var = NULL;
    uint32_t instances = 0;
    when_null(object, exit);
    when_true_status(object->type != amxd_object_template,
                     exit,
                     retval = amxd_status_invalid_type);

    instances = amxd_object_get_instance_count(object);
    when_true_status(max < instances, exit, retval = amxd_status_invalid_value);

    max_var =
        (amxc_var_t*) amxd_object_get_action_cb_data(object,
                                                     action_object_add_inst,
                                                     amxd_action_object_add_inst);
    if(max == UINT32_MAX) {
        amxd_object_remove_max_instance_check(object, max_var);
        retval = amxd_status_ok;
        goto exit;
    }

    if(max_var != NULL) {
        amxc_var_set(uint32_t, max_var, max);
    } else {
        retval = amxd_object_add_max_instance_check(object, max);
        when_failed(retval, exit);
    }

    retval = amxd_status_ok;

exit:
    return retval;
}