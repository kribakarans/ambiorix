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
#include <stdlib.h>

#include "amxd_priv.h"

#include <amxd/amxd_dm.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_path.h>
#include <amxd/amxd_dm_functions.h>
#include <amxd/amxd_transaction.h>

#include "amxd_assert.h"
#include "amxd_object_priv.h"
#include "amxd_dm_priv.h"

typedef struct _del_data {
    amxc_var_t* retval;
    bool key_path;
} del_data_t;

static bool amxd_object_del_rv_filter(amxd_object_t* const object,
                                      UNUSED int32_t depth,
                                      UNUSED void* priv) {
    amxd_object_t* parent = amxd_object_get_parent(object);
    if(amxd_object_get_type(parent) == amxd_object_template) {
        return (amxd_object_get_type(object) == amxd_object_instance);
    }
    return true;
}

static void amxd_object_del_rv(amxd_object_t* const object,
                               UNUSED int32_t depth,
                               void* priv) {
    del_data_t* data = (del_data_t*) priv;
    amxc_var_t* retval = data->retval;
    uint32_t flags = data->key_path ? AMXD_OBJECT_NAMED : AMXD_OBJECT_INDEXED;
    char* path = amxd_object_get_path(object, flags | AMXD_OBJECT_TERMINATE);

    amxc_var_add(cstring_t, retval, path);
    free(path);
}

static bool amxd_del_is_path_valid(amxd_object_t* object,
                                   amxc_var_t* args) {
    bool is_valid = false;
    const char* rel_path = GET_CHAR(args, "rel_path");
    char* obj_path = amxd_object_get_path(object, AMXD_OBJECT_TERMINATE |
                                          AMXD_OBJECT_INDEXED);
    amxc_llist_t paths;
    amxd_status_t retval = amxd_status_unknown_error;
    amxd_dm_t* dm = amxd_object_get_dm(object);

    amxc_llist_init(&paths);

    is_valid = amxd_object_is_supported(object, rel_path);
    when_false(is_valid, exit);

    is_valid = false;
    retval = amxd_object_resolve_pathf(object, &paths, "%s", rel_path);
    when_failed(retval, exit);
    when_true(amxc_llist_is_empty(&paths), exit);

    is_valid = true;
    amxc_llist_for_each(it, (&paths)) {
        amxc_string_t* path = amxc_string_from_llist_it(it);
        object = amxd_dm_findf(dm, "%s", amxc_string_get(path, 0));
        if((amxd_object_get_type(object) != amxd_object_template) &&
           ( amxd_object_get_type(object) != amxd_object_instance)) {
            is_valid = false;
            break;
        }
    }

exit:
    free(obj_path);
    amxc_llist_clean(&paths, amxc_string_list_it_free);

    return is_valid;
}

static void amxd_add_del_instance(amxd_object_t* object,
                                  bool key_path,
                                  amxd_trans_t* transaction,
                                  amxc_var_t* args,
                                  amxc_var_t* retval) {
    amxc_var_t* var_index = GET_ARG(args, "index");
    uint32_t index = 0;
    const char* name = NULL;
    del_data_t data = {
        .retval = retval,
        .key_path = key_path
    };

    if(amxd_object_get_type(object) == amxd_object_instance) {
        if(var_index == NULL) {
            amxc_var_add_key(uint32_t, args, "index", amxd_object_get_index(object));
        } else {
            amxc_var_set(uint32_t, var_index, amxd_object_get_index(object));
        }
        object = amxd_object_get_parent(object);
    }

    index = GET_UINT32(args, "index");
    name = GET_CHAR(args, "name");

    amxd_trans_select_object(transaction, object);
    amxd_trans_add_action(transaction, action_object_del_inst, args);

    object = amxd_object_get_instance(object, name, index);
    amxd_object_hierarchy_walk(object,
                               amxd_direction_down,
                               amxd_object_del_rv_filter,
                               amxd_object_del_rv,
                               INT32_MAX,
                               &data);
}

amxd_status_t amxd_object_func_del(amxd_object_t* object,
                                   UNUSED amxd_function_t* func,
                                   amxc_var_t* args,
                                   amxc_var_t* ret) {

    amxd_status_t retval = amxd_status_unknown_error;
    amxc_var_t* var_rel_path = GET_ARG(args, "rel_path");
    const char* rel_path = GET_CHAR(var_rel_path, NULL);
    amxc_llist_t paths;
    amxd_trans_t transaction;
    amxd_dm_t* dm = amxd_object_get_dm(object);

    amxd_def_funcs_remove_args(args);
    amxd_trans_init(&transaction);
    amxc_llist_init(&paths);
    amxc_var_set_type(ret, AMXC_VAR_ID_LIST);

    if(!amxd_del_is_path_valid(object, args)) {
        retval = amxd_status_object_not_found;
        goto exit;
    }

    amxc_var_take_it(var_rel_path);
    if((rel_path != NULL) && (*rel_path != 0)) {
        retval = amxd_object_resolve_pathf(object, &paths, "%s", rel_path);
        when_failed(retval, exit);
        amxc_llist_for_each(it, (&paths)) {
            amxc_string_t* path = amxc_string_from_llist_it(it);
            object = amxd_dm_findf(dm, "%s", amxc_string_get(path, 0));
            amxd_add_del_instance(object, false, &transaction, args, ret);
        }
    } else {
        amxd_add_del_instance(object, false, &transaction, args, ret);
    }

    retval = amxd_trans_apply(&transaction, dm);

exit:
    if(retval != amxd_status_ok) {
        amxc_var_clean(ret);
    }
    amxc_var_delete(&var_rel_path);
    amxc_llist_clean(&paths, amxc_string_list_it_free);
    amxd_trans_clean(&transaction);
    return retval;
}
