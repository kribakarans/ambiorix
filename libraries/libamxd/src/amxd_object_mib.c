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

#include <amxd/amxd_types.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_dm.h>
#include <amxd/amxd_dm_functions.h>
#include <amxd/amxd_mib.h>
#include <amxd/amxd_object_event.h>

#include "amxd_priv.h"
#include "amxd_dm_priv.h"
#include "amxd_object_priv.h"
#include "amxd_assert.h"

static void amxd_object_remove_mib_params(amxd_object_t* const object,
                                          amxd_object_t* const mib) {
    amxc_llist_for_each(it, (&mib->parameters)) {
        amxd_param_t* mib_param = amxc_llist_it_get_data(it, amxd_param_t, it);
        const char* param_name = amxd_param_get_name(mib_param);
        amxd_param_t* obj_param = amxd_object_get_param_def(object, param_name);
        if(obj_param == NULL) {
            continue;
        }
        amxd_param_free(&obj_param);
    }
}

static void amxd_object_remove_mib_functions(amxd_object_t* const object,
                                             amxd_object_t* const mib) {
    amxc_llist_for_each(it, (&mib->functions)) {
        amxd_function_t* mib_func = amxc_llist_it_get_data(it, amxd_function_t, it);
        const char* func_name = amxd_function_get_name(mib_func);
        amxd_function_t* obj_func = amxd_object_get_function(object, func_name);
        if(obj_func == NULL) {
            continue;
        }
        amxd_function_delete(&obj_func);
    }
}

static void amxd_object_remove_mib_objects(amxd_object_t* const object,
                                           amxd_object_t* const mib) {
    amxc_llist_for_each(it, (&mib->objects)) {
        amxd_object_t* mib_obj = amxc_llist_it_get_data(it, amxd_object_t, it);
        const char* obj_name = amxd_object_get_name(mib_obj, AMXD_OBJECT_NAMED);
        amxd_object_t* obj_child = amxd_object_get_child(object, obj_name);
        if(obj_child == NULL) {
            continue;
        }
        amxd_object_free(&obj_child);
    }
}

static void amxd_object_remove_mib_events(amxd_object_t* const object,
                                          amxd_object_t* const mib) {
    amxc_var_for_each(data, (&mib->events)) {
        const char* name = amxc_var_key(data);
        amxc_var_t* event = amxc_var_get_key(&object->events, name, AMXC_VAR_FLAG_DEFAULT);
        amxc_var_delete(&event);
    }
}

static void amxd_object_clear_mib(amxd_object_t* const object,
                                  const char* mib_name) {
    amxc_array_it_t* ait = amxc_array_get_first(&object->mib_names);
    while(ait != NULL) {
        const char* name = (const char*) amxc_array_it_get_data(ait);
        if(name != NULL) {
            if(strcmp(name, mib_name) == 0) {
                amxc_array_it_take_data(ait);
                break;
            }
        }
        ait = amxc_array_it_get_next(ait);
    }
}

static bool amxd_object_can_add_mib(amxd_object_t* const object,
                                    amxd_object_t* const mib) {
    bool retval = false;
    amxc_llist_for_each(it, (&mib->objects)) {
        amxd_object_t* mib_obj = amxc_llist_it_get_data(it, amxd_object_t, it);
        const char* obj_name = amxd_object_get_name(mib_obj, AMXD_OBJECT_NAMED);
        amxd_object_t* obj_child = amxd_object_get_child(object, obj_name);
        when_true(obj_child != NULL, exit);
    }

    amxc_llist_for_each(it, (&mib->parameters)) {
        amxd_param_t* mib_param = amxc_llist_it_get_data(it, amxd_param_t, it);
        const char* param_name = amxd_param_get_name(mib_param);
        amxd_param_t* obj_param = amxd_object_get_param_def(object, param_name);
        when_true(obj_param != NULL, exit);
    }

    amxc_llist_for_each(it, (&mib->functions)) {
        amxd_function_t* mib_func = amxc_llist_it_get_data(it, amxd_function_t, it);
        const char* func_name = amxd_function_get_name(mib_func);
        amxd_function_t* obj_func = amxd_object_get_self_func(object, func_name);
        when_true(obj_func != NULL, exit);
    }

    retval = true;
exit:
    return retval;
}

static void amxd_object_send_add_objects(amxd_object_t* object,
                                         amxd_object_t* mib) {
    amxc_llist_for_each(it, (&mib->objects)) {
        amxd_object_t* base = amxc_llist_it_get_data(it, amxd_object_t, it);
        const char* name = amxd_object_get_name(base, AMXD_OBJECT_NAMED);
        amxd_object_t* child = amxd_object_get(object, name);
        amxd_dm_event("dm:object-added", child, NULL, false);
        amxd_object_send_add_objects(child, base);
    }
}

static void amxd_object_send_del_objects(amxd_object_t* object,
                                         amxd_object_t* mib) {
    amxc_llist_for_each(it, (&mib->objects)) {
        amxd_object_t* base = amxc_llist_it_get_data(it, amxd_object_t, it);
        const char* name = amxd_object_get_name(base, AMXD_OBJECT_NAMED);
        amxd_object_t* child = amxd_object_get(object, name);
        amxd_object_send_del_object(child, false);
    }
}

static void amxd_object_send_mib(amxd_object_t* object,
                                 const char* mib_name,
                                 bool added) {
    amxc_var_t data;

    amxc_var_init(&data);
    amxc_var_set_type(&data, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &data, "mib", mib_name);

    amxd_dm_event(added ? "dm:mib-added" : "dm:mib-removed", object, &data, false);

    amxc_var_clean(&data);
}

char* amxd_object_get_mibs(amxd_object_t* object) {
    char* mibs = NULL;
    amxc_array_it_t* ait = NULL;
    amxc_string_t str;

    amxc_string_init(&str, 0);
    when_null(object, exit);

    ait = amxc_array_get_first(&object->mib_names);
    while(ait != NULL) {
        const char* name = (const char*) amxc_array_it_get_data(ait);
        if(name != NULL) {
            amxc_string_appendf(&str, "%s ", name);
        }
        ait = amxc_array_it_get_next(ait);
    }

    amxc_string_trim(&str, NULL);
    mibs = amxc_string_take_buffer(&str);

exit:
    amxc_string_clean(&str);
    return mibs;
}

bool amxd_object_has_mib(amxd_object_t* object,
                         const char* mib_name) {
    bool retval = false;
    amxc_array_it_t* ait = NULL;

    when_null(object, exit);
    when_str_empty(mib_name, exit);

    ait = amxc_array_get_first(&object->mib_names);
    while(ait != NULL) {
        const char* name = (const char*) amxc_array_it_get_data(ait);
        if(name != NULL) {
            if(strcmp(name, mib_name) == 0) {
                retval = true;
                break;
            }
        }
        ait = amxc_array_it_get_next(ait);
    }

exit:
    return retval;
}

amxd_status_t amxd_object_add_mib(amxd_object_t* const object,
                                  const char* mib_name) {
    amxd_status_t status = amxd_status_unknown_error;
    amxd_dm_t* dm = amxd_object_get_dm(object);
    amxd_object_t* mib = amxd_dm_get_mib(dm, mib_name);
    amxc_array_it_t* ait = NULL;

    when_null(dm, exit);
    when_null_status(mib, exit, status = amxd_status_object_not_found);
    if(amxd_object_has_mib(object, mib_name) ||
       !amxd_object_can_add_mib(object, mib)) {
        status = amxd_status_duplicate;
        goto exit;
    }

    amxd_object_copy_children(object, mib);
    amxd_object_send_add_objects(object, mib);
    amxd_object_copy_params(object, mib);
    amxd_object_copy_funcs(object, mib);
    amxd_object_copy_events(object, mib);

    mib_name = amxd_object_get_name(mib, AMXD_OBJECT_NAMED);
    amxd_object_send_mib(object, mib_name, true);
    ait = amxc_array_get_first_free(&object->mib_names);
    if(ait == NULL) {
        amxc_array_append_data(&object->mib_names, (void*) mib_name);
    } else {
        amxc_array_it_set_data(ait, (void*) mib_name);
    }

    status = amxd_status_ok;

exit:
    return status;
}

amxd_status_t amxd_object_remove_mib(amxd_object_t* const object,
                                     const char* mib_name) {
    amxd_status_t status = amxd_status_unknown_error;
    amxd_dm_t* dm = amxd_object_get_dm(object);
    amxd_object_t* mib = amxd_dm_get_mib(dm, mib_name);

    when_null(dm, exit);
    when_null_status(mib, exit, status = amxd_status_object_not_found);
    when_false_status(amxd_object_has_mib(object, mib_name), exit, status = amxd_status_ok);

    mib_name = amxd_object_get_name(mib, AMXD_OBJECT_NAMED);
    amxd_object_send_mib(object, mib_name, false);
    amxd_object_remove_mib_params(object, mib);
    amxd_object_remove_mib_functions(object, mib);
    amxd_object_send_del_objects(object, mib);
    amxd_object_remove_mib_objects(object, mib);
    amxd_object_remove_mib_events(object, mib);
    amxd_object_clear_mib(object, mib_name);

    status = amxd_status_ok;
exit:
    return status;
}

void amxd_mib_delete(amxd_object_t** mib) {
    when_null(mib, exit);
    when_null(*mib, exit);

    when_true(amxd_object_get_type(*mib) != amxd_object_mib, exit);

    amxd_object_free(mib);

exit:
    return;
}
