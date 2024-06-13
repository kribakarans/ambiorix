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
#include <amxp/amxp_timer.h>

#include <amxd/amxd_types.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_object_event.h>
#include <amxd/amxd_dm.h>
#include <amxd/amxd_dm_functions.h>

#include "amxd_priv.h"
#include "amxd_dm_priv.h"
#include "amxd_assert.h"

static amxd_status_t amxd_object_delete_timer(amxd_object_t* object,
                                              UNUSED amxd_param_t* const p,
                                              amxd_action_t reason,
                                              UNUSED const amxc_var_t* const args,
                                              amxc_var_t* const retval,
                                              void* priv) {
    amxd_status_t status = amxd_status_ok;
    amxp_timer_t* timer = (amxp_timer_t*) priv;

    when_null(object, exit);
    when_null(timer, exit);

    when_true_status(reason != action_object_destroy,
                     exit,
                     status = amxd_status_function_not_implemented);


    amxp_timer_delete(&timer);

    amxc_var_clean(retval);

exit:
    return status;
}

static void amxd_periodic_inform(UNUSED amxp_timer_t* timer, void* priv) {
    amxd_object_t* object = (amxd_object_t*) priv;
    amxc_var_t data;
    amxc_var_t* parameters = NULL;

    amxc_var_init(&data);
    when_null(object, exit);
    amxc_var_set_type(&data, AMXC_VAR_ID_HTABLE);

    parameters = amxc_var_add_key(amxc_htable_t, &data, "parameters", NULL);
    amxd_object_get_params(object, parameters, amxd_dm_access_protected);
    amxd_dm_event("dm:periodic-inform", object, &data, false);

exit:
    amxc_var_clean(&data);
    return;
}

static void amxd_object_instance_sig_data(amxd_object_t* object,
                                          amxc_var_t* data) {
    amxc_var_t* params = NULL;

    amxc_var_add_key(uint32_t, data, "index", object->index);
    amxc_var_add_key(cstring_t, data, "name", object->name);
    params = amxc_var_add_key(amxc_htable_t, data, "parameters", NULL);
    amxd_object_get_params_filtered(object, params, "attributes.volatile == false", amxd_dm_access_protected);
    params = amxc_var_add_key(amxc_htable_t, data, "keys", NULL);
    amxd_object_get_key_params(object, params, amxd_dm_access_protected);
}

static bool amxd_object_event_filter(amxd_object_t* const object,
                                     UNUSED int32_t depth,
                                     UNUSED void* priv) {
    bool retval = true;
    when_true(amxd_object_get_type(object) == amxd_object_root, exit);

    if(amxd_object_is_attr_set(object, amxd_oattr_private)) {
        retval = false;
        goto exit;
    }

exit:
    return retval;
}

static bool amxd_object_event_filter_add(amxd_object_t* const object,
                                         int32_t depth,
                                         void* priv) {
    bool retval = amxd_object_event_filter(object, depth, priv);
    when_false(retval, exit);

    if(amxd_object_get_type(object) == amxd_object_instance) {
        retval = false;
        goto exit;
    }

exit:
    return retval;
}

static void amxd_object_send_event_add(amxd_object_t* const object,
                                       UNUSED int32_t depth,
                                       void* priv) {
    bool* trigger = (bool*) priv;
    amxc_var_t data;

    amxc_var_init(&data);
    amxc_var_set_type(&data, AMXC_VAR_ID_HTABLE);

    if(amxd_object_get_type(object) == amxd_object_instance) {
        amxd_object_t* templ = amxd_object_get_parent(object);
        amxd_object_instance_sig_data(object, &data);
        amxd_dm_event("dm:instance-added", templ, &data, *trigger);
    } else {
        amxc_var_t* params = amxc_var_add_key(amxc_htable_t, &data, "parameters", NULL);
        amxd_object_get_params_filtered(object, params, "attributes.volatile == false", amxd_dm_access_protected);
        amxd_dm_event("dm:object-added", object, &data, *trigger);
    }

    amxc_var_clean(&data);
}

static void amxd_object_send_event_del(amxd_object_t* const object,
                                       UNUSED int32_t depth,
                                       void* priv) {
    bool* trigger = (bool*) priv;
    amxc_var_t data;

    amxc_var_init(&data);
    amxc_var_set_type(&data, AMXC_VAR_ID_HTABLE);

    if(amxd_object_get_type(object) == amxd_object_instance) {
        amxd_object_t* templ = amxd_object_get_parent(object);
        amxd_object_instance_sig_data(object, &data);
        amxd_dm_event("dm:instance-removed", templ, &data, *trigger);
    } else {
        amxc_var_t* params = amxc_var_add_key(amxc_htable_t, &data, "parameters", NULL);
        amxd_object_get_params_filtered(object, params, "attributes.volatile == false", amxd_dm_access_protected);
        amxd_dm_event("dm:object-removed", object, &data, *trigger);
    }

    amxc_var_clean(&data);
}

static void amxd_build_param_changed(const char* name,
                                     amxc_var_t* values,
                                     amxc_var_t* data,
                                     amxc_var_t* ovalue) {
    amxc_var_t* new_value = NULL;
    amxc_var_t* data_param = NULL;
    int result = 0;

    new_value = amxc_var_get_pathf(values,
                                   AMXC_VAR_FLAG_DEFAULT,
                                   "'%s'",
                                   name);

    data_param = amxc_var_add_new_key(data, name);
    amxc_var_set_type(data_param, AMXC_VAR_ID_HTABLE);
    amxc_var_set_key(data_param, "from", ovalue, AMXC_VAR_FLAG_COPY);
    amxc_var_set_key(data_param, "to", new_value, AMXC_VAR_FLAG_DEFAULT);
    // when no change in value, remove from event data
    amxc_var_compare(ovalue, new_value, &result);
    if(result == 0) {
        amxc_var_delete(&data_param);
    }
}

void amxd_object_send_signal(amxd_object_t* const object,
                             const char* name,
                             amxc_var_t* const data,
                             bool trigger) {

    when_null(object, exit);
    when_str_empty(name, exit);

    amxd_dm_event(name, object, data, trigger);
exit:
    return;
}

void amxd_object_send_add_inst(amxd_object_t* instance, bool trigger) {
    when_null(instance, exit);
    when_true(amxd_object_get_type(instance) != amxd_object_instance, exit);

    amxd_object_send_event_add(instance, INT32_MAX, &trigger);
    amxd_object_for_each(child, it, instance) {
        amxd_object_t* object = amxc_container_of(it, amxd_object_t, it);
        amxd_object_hierarchy_walk(object,
                                   amxd_direction_down,
                                   amxd_object_event_filter_add,
                                   amxd_object_send_event_add,
                                   INT32_MAX,
                                   &trigger);
    }

exit:
    return;
}

void amxd_object_send_del_object(amxd_object_t* object, bool trigger) {
    when_null(object, exit);

    amxd_object_hierarchy_walk(object,
                               amxd_direction_down_reverse,
                               amxd_object_event_filter,
                               amxd_object_send_event_del,
                               INT32_MAX,
                               &trigger);

exit:
    return;
}

void amxd_object_send_del_inst(amxd_object_t* instance, bool trigger) {
    amxd_object_send_del_object(instance, trigger);
}

void amxd_object_send_changed(amxd_object_t* object,
                              amxc_var_t* params,
                              bool trigger) {
    const amxc_htable_t* tparams = NULL;
    amxc_var_t data;
    amxc_var_t values;
    amxc_var_t* parameters = NULL;
    amxc_var_init(&data);
    amxc_var_init(&values);

    when_null(object, exit);
    when_null(params, exit);
    when_true(amxc_var_type_of(params) != AMXC_VAR_ID_HTABLE, exit);
    amxc_var_set_type(&values, AMXC_VAR_ID_HTABLE);

    amxc_var_for_each(ovalue, params) {
        amxd_param_t* param_def = amxd_object_get_param_def(object, amxc_var_key(ovalue));
        if(param_def == NULL) {
            amxc_var_set_type(&values, AMXC_VAR_ID_HTABLE);
            amxd_object_get_params_filtered(amxd_param_get_owner(param_def),
                                            &values,
                                            "attributes.volatile==false",
                                            amxd_dm_access_protected);
            break;
        }
        if(!amxd_param_is_attr_set(param_def, amxd_pattr_variable)) {
            amxc_var_set_key(&values, amxc_var_key(ovalue), &param_def->value, AMXC_VAR_FLAG_COPY);
        }
    }

    amxc_var_set_type(&data, AMXC_VAR_ID_HTABLE);
    parameters = amxc_var_add_key(amxc_htable_t, &data, "parameters", NULL);
    amxc_var_for_each(ovalue, params) {
        const char* name = amxc_var_key(ovalue);
        amxd_build_param_changed(name, &values, parameters, ovalue);
    }

    tparams = amxc_var_constcast(amxc_htable_t, parameters);

    if(!amxc_htable_is_empty(tparams)) {
        amxd_dm_event("dm:object-changed", object, &data, trigger);
    }

exit:
    amxc_var_clean(&values);
    amxc_var_clean(&data);
    return;
}

amxd_status_t amxd_object_new_pi(amxd_object_t* object,
                                 uint32_t sec) {
    amxd_status_t status = amxd_status_unknown_error;
    amxp_timer_t* timer = NULL;

    when_null(object, exit);
    when_true(sec == 0, exit);
    when_true(object->type == amxd_object_root, exit);
    when_true(amxd_object_has_action_cb(object,
                                        action_object_destroy,
                                        amxd_object_delete_timer), exit);

    amxp_timer_new(&timer, amxd_periodic_inform, object);
    when_null(timer, exit);

    amxp_timer_set_interval(timer, sec * 1000);
    amxp_timer_start(timer, sec * 1000);

    status = amxd_object_add_action_cb(object,
                                       action_object_destroy,
                                       amxd_object_delete_timer,
                                       timer);
exit:
    return status;
}

amxd_status_t amxd_object_delete_pi(amxd_object_t* object) {
    amxd_status_t status = amxd_status_unknown_error;
    amxp_timer_t* timer = NULL;

    when_null(object, exit);
    when_true(object->type == amxd_object_root, exit);

    timer = (amxp_timer_t*) amxd_object_get_action_cb_data(object,
                                                           action_object_destroy,
                                                           amxd_object_delete_timer);
    when_null(timer, exit);
    amxp_timer_delete(&timer);
    status = amxd_object_remove_action_cb(object,
                                          action_object_destroy,
                                          amxd_object_delete_timer);

exit:
    return status;

}

amxd_status_t amxd_object_add_event_ext(amxd_object_t* const object,
                                        const char* event_name,
                                        amxc_var_t* event_data) {
    amxd_status_t retval = amxd_status_unknown_error;
    amxd_dm_t* dm = amxd_object_get_dm(object);

    when_null(dm, exit);

    if(event_data != NULL) {
        when_failed(amxc_var_set_key(&object->events,
                                     event_name,
                                     event_data,
                                     AMXC_VAR_FLAG_DEFAULT | AMXC_VAR_FLAG_UPDATE), exit);
    } else {
        amxc_var_t* event = amxc_var_get_key(&object->events,
                                             event_name,
                                             AMXC_VAR_FLAG_DEFAULT);
        if(event == NULL) {
            when_null(amxc_var_add_new_key(&object->events,
                                           event_name), exit);
        } else {
            amxc_var_set_type(event, AMXC_VAR_ID_NULL);
        }
    }

    amxp_sigmngr_add_signal(&dm->sigmngr, event_name);
    retval = amxd_status_ok;

exit:
    if(retval != amxd_status_ok) {
        amxc_var_delete(&event_data);
    }
    return retval;
}

amxd_status_t amxd_object_add_event(amxd_object_t* const object,
                                    const char* event_name) {
    return amxd_object_add_event_ext(object, event_name, NULL);
}

void amxd_object_remove_event(amxd_object_t* const object,
                              const char* event_name) {
    amxc_var_t* event = amxc_var_get_key(&object->events,
                                         event_name,
                                         AMXC_VAR_FLAG_DEFAULT);
    amxc_var_delete(&event);
}

amxc_var_t* amxd_object_new_event_data(const amxd_object_t* object,
                                       const char* event_name) {
    amxc_var_t* data = NULL;

    when_null(object, exit);
    when_str_empty(event_name, exit);

    data = amxc_var_get_key(&object->events, event_name, AMXC_VAR_FLAG_COPY);
    when_not_null(data, exit);

    if(amxd_object_get_type(object) == amxd_object_instance) {
        object = amxd_object_get_parent(object);
    } else {
        object = amxd_object_get_base(object);
    }
    while(object != NULL) {
        data = amxc_var_get_key(&object->events, event_name, AMXC_VAR_FLAG_COPY);
        if(data != NULL) {
            break;
        }
        object = amxd_object_get_base(object);
    }

exit:
    return data;
}