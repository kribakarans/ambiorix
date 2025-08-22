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
#include <string.h>

#include "amxd_priv.h"

#include <amxd/amxd_dm.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_object_event.h>
#include <amxd/amxd_transaction.h>
#include <amxd/amxd_path.h>

#include "amxd_assert.h"

typedef struct _validate {
    char* path;
    amxd_action_t reason;
    amxc_var_t* event_data;
    amxc_llist_it_t it;
} validate_t;

static void amxd_trans_delete_action(amxd_trans_action_t** trans) {
    amxc_var_clean(&(*trans)->data);
    free(*trans);
    *trans = NULL;
}

static void amxd_trans_free_action_it(amxc_llist_it_t* it) {
    amxd_trans_action_t* trans = amxc_llist_it_get_data(it, amxd_trans_action_t, it);
    amxd_trans_delete_action(&trans);
}

static void amxd_trans_free_validate_it(amxc_llist_it_t* it) {
    validate_t* val = amxc_llist_it_get_data(it, validate_t, it);
    free(val->path);
    free(val);
}

static amxd_object_t* amxd_get_instance_from_args(amxd_object_t* templ,
                                                  amxc_var_t* args) {
    amxd_object_t* instance = NULL;
    amxc_var_t* var_index = amxc_var_get_key(args, "index", AMXC_VAR_FLAG_DEFAULT);
    amxc_var_t* var_name = amxc_var_get_key(args, "name", AMXC_VAR_FLAG_DEFAULT);

    uint32_t index = amxc_var_dyncast(uint32_t, var_index);
    char* name = amxc_var_dyncast(cstring_t, var_name);
    instance = amxd_object_get_instance(templ, name, index);
    free(name);

    return instance;
}

static amxd_trans_action_t* amxd_trans_new_action(amxd_trans_t* trans,
                                                  amxd_action_t reason) {
    amxd_trans_action_t* action = (amxd_trans_action_t*) calloc(1, sizeof(amxd_trans_action_t));
    when_null(action, exit);

    action->action = reason;
    amxc_var_init(&action->data);
    amxc_var_set_type(&action->data, AMXC_VAR_ID_HTABLE);
    amxc_llist_append(&trans->actions, &action->it);

exit:
    return action;
}

static amxd_trans_action_t* amxd_trans_find_write_action(amxd_trans_t* trans) {
    amxd_trans_action_t* action = NULL;
    amxc_llist_for_each_reverse(it, (&trans->actions)) {
        action = amxc_llist_it_get_data(it, amxd_trans_action_t, it);
        if((action->action == action_object_write) ||
           ( action->action == action_object_add_inst)) {
            break;
        }
        if(action->action == action_any) {
            action = NULL;
            break;
        }
    }

    return action;
}

static amxd_object_t* amxd_trans_select(amxd_dm_t* dm,
                                        amxd_object_t* object,
                                        amxc_var_t* data) {
    amxd_object_t* result = NULL;
    amxc_var_t* var_path = amxc_var_get_key(data, "path", AMXC_VAR_FLAG_DEFAULT);
    const char* path = amxc_var_constcast(cstring_t, var_path);

    if((path == NULL) || (*path == 0)) {
        goto exit;
    }

    if(path[0] == '.') {
        result = amxd_object_findf(object, "%s", path + 1);
    } else {
        result = amxd_dm_findf(dm, "%s", path);
    }

exit:
    return result;
}

static amxd_object_t* amxd_trans_select_instance(amxd_object_t* object,
                                                 amxd_trans_t* rollback,
                                                 amxc_var_t* data) {
    amxc_var_t* temp = NULL;
    uint32_t index = 0;
    const char* name = NULL;

    temp = amxc_var_get_key(data, "index", AMXC_VAR_FLAG_DEFAULT);
    index = amxc_var_dyncast(uint32_t, temp);
    temp = amxc_var_get_key(data, "name", AMXC_VAR_FLAG_DEFAULT);
    name = amxc_var_constcast(cstring_t, temp);

    if(rollback != NULL) {
        amxd_trans_del_inst(rollback, index, name);
        amxd_trans_select_object(rollback, object);
    }
    return amxd_object_get_instance(object, name, index);
}

static void amxd_trans_store_all_params(amxd_object_t* object,
                                        const char* param,
                                        amxc_var_t* revert_params) {
    amxc_var_t temp;
    amxd_path_t param_path;
    amxc_string_t p;
    const char* path = "";

    amxc_string_init(&p, 0);
    amxd_path_init(&param_path, param);
    amxc_var_init(&temp);

    path = amxd_path_get(&param_path, AMXD_OBJECT_TERMINATE);

    if(path != NULL) {
        if((strlen(path) <= 1) && (path[0] == '.')) {
            path = "";
        }
    } else {
        path = "";
    }
    object = amxd_object_findf(object, "%s", amxd_path_get(&param_path, AMXD_OBJECT_TERMINATE));
    amxc_var_set_type(&temp, AMXC_VAR_ID_HTABLE);
    amxd_object_get_params_filtered(object,
                                    &temp,
                                    "attributes.volatile==false",
                                    amxd_dm_access_private);
    amxc_var_for_each(t, &temp) {
        amxc_string_setf(&p,
                         "%s%s",
                         path,
                         amxc_var_key(t));
        if(GET_ARG(revert_params, amxc_string_get(&p, 0)) != NULL) {
            continue;
        }
        amxc_var_set_key(revert_params,
                         amxc_string_get(&p, 0),
                         t,
                         AMXC_VAR_FLAG_DEFAULT | AMXC_VAR_FLAG_UPDATE);
    }
    amxc_string_clean(&p);
    amxd_path_clean(&param_path);
    amxc_var_clean(&temp);
}

static void amxd_trans_revert_write(amxd_object_t* object,
                                    amxd_trans_t* rollback,
                                    amxc_var_t* data) {
    const char* param_fields[] = { "parameters", "oparameters", NULL };
    amxd_trans_action_t* action = amxd_trans_new_action(rollback, action_object_write);
    amxc_var_t* revert_params = NULL;
    amxc_var_t* params = NULL;
    int index = 0;
    amxc_var_add_key(bool, &action->data, "set_read_only", true);
    amxc_var_add_key(uint32_t, &action->data, "access", amxd_dm_access_private);
    revert_params = amxc_var_add_key(amxc_htable_t, &action->data, "parameters", NULL);
    while(param_fields[index] != NULL) {
        params = GET_ARG(data, param_fields[index]);
        amxc_var_for_each(param, params) {
            amxd_param_t* param_def = NULL;
            if(GET_ARG(revert_params, amxc_var_key(param)) != NULL) {
                continue;
            }
            param_def = amxd_object_get_param_def(object, amxc_var_key(param));
            if(param_def == NULL) {
                amxd_trans_store_all_params(object, amxc_var_key(param), revert_params);
                continue;
            }
            if(!amxd_param_is_attr_set(param_def, amxd_pattr_variable)) {
                amxc_var_set_key(revert_params, amxc_var_key(param), &param_def->value, AMXC_VAR_FLAG_COPY);
            }
        }
        index++;
    }
}

static void amxd_trans_add_garbage(amxd_trans_t* trans,
                                   amxc_var_t* data) {
    amxd_object_t* object = amxd_get_instance_from_args(trans->current, data);
    amxc_string_t* path = (amxc_string_t*) calloc(1, sizeof(amxc_string_t));
    char* object_path = amxd_object_get_path(object,
                                             AMXD_OBJECT_INDEXED |
                                             AMXD_OBJECT_TERMINATE);
    amxc_string_init(path, 0);
    amxc_string_push_buffer(path, object_path, strlen(object_path) + 1);
    amxc_llist_append(&trans->garbage, &path->it);
}

static void amxd_trans_add_validate(amxd_trans_t* trans,
                                    amxd_object_t* object,
                                    amxd_action_t reason,
                                    amxc_var_t* data) {
    validate_t* val_info = NULL;
    char* object_path = amxd_object_get_path(object,
                                             AMXD_OBJECT_INDEXED |
                                             AMXD_OBJECT_TERMINATE);
    size_t path_len = strlen(object_path);

    amxc_llist_for_each(it, (&trans->validate)) {
        size_t length = 0;
        val_info = amxc_llist_it_get_data(it, validate_t, it);
        length = strlen(val_info->path);
        if(length <= path_len) {
            if((length == path_len) &&
               ( strcmp(object_path, val_info->path) == 0) &&
               ( val_info->reason == action_object_write)) {
                break;
            }
        }
        val_info = NULL;
    }

    if(val_info != NULL) {
        amxc_var_t* event_params = GET_ARG(val_info->event_data, "parameters");
        amxc_var_for_each(var, GET_ARG(data, "parameters")) {
            amxc_var_set_key(event_params, amxc_var_key(var), var, AMXC_VAR_FLAG_DEFAULT);
        }
        free(object_path);
    } else {
        val_info = (validate_t*) calloc(1, sizeof(validate_t));
        when_null(val_info, exit);
        val_info->path = object_path;
        val_info->reason = reason;
        val_info->event_data = data;
        amxc_llist_append(&trans->validate, &val_info->it);
    }

exit:
    return;
}

static void amxd_trans_action_start(amxd_trans_t* trans,
                                    amxd_trans_action_t* action,
                                    amxd_trans_t* rollback) {
    if(action->action == action_object_write) {
        if(rollback != NULL) {
            amxc_llist_it_t* it = NULL;
            amxd_trans_action_t* raction = NULL;
            amxd_trans_revert_write(trans->current, rollback, &action->data);
            it = amxc_llist_get_last(&rollback->actions);
            raction = amxc_llist_it_get_data(it, amxd_trans_action_t, it);
            amxd_trans_add_validate(trans, trans->current, action->action, &raction->data);
        }
    }
}

static amxd_status_t amxd_trans_action_end(amxd_trans_t* trans,
                                           amxd_trans_action_t* action,
                                           amxd_trans_t* rollback,
                                           amxc_var_t* retval) {
    amxd_status_t status = amxd_status_ok;
    if(action->action == action_object_add_inst) {
        trans->current = amxd_trans_select_instance(trans->current,
                                                    rollback,
                                                    retval);
        when_null_status(trans->current,
                         exit,
                         status = amxd_status_object_not_found);
        if(rollback != NULL) {
            amxd_trans_add_validate(trans, trans->current, action->action, NULL);
        }
    } else if(action->action == action_object_del_inst) {
        amxd_object_t* inst = amxd_trans_select_instance(trans->current,
                                                         NULL,
                                                         &action->data);
        amxd_trans_add_garbage(trans, &action->data);
        amxd_trans_add_validate(trans, inst, action->action, NULL);
    }

exit:
    return status;
}

static amxd_status_t amxd_trans_invoke_action(amxd_trans_t* trans,
                                              amxd_dm_t* dm,
                                              amxd_trans_action_t* action,
                                              amxd_trans_t* rollback) {
    amxd_status_t status = amxd_status_unknown_error;
    amxc_var_t* retval = amxc_var_add_new(&trans->retvals);

    if(action->action == action_any) {
        if((trans->current != NULL) && (rollback != NULL)) {
            amxd_trans_select_object(rollback, trans->current);
        }
        trans->current = amxd_trans_select(dm, trans->current, &action->data);
        when_null_status(trans->current,
                         exit,
                         status = amxd_status_object_not_found);
        status = amxd_status_ok;
    } else if(action->action == action_object_add_mib) {
        when_null_status(trans->current, exit, status = amxd_status_object_not_found);
        if(!amxd_object_has_mib(trans->current, GET_CHAR(&action->data, "mib"))) {
            status = amxd_object_add_mib(trans->current, GET_CHAR(&action->data, "mib"));
        } else {
            status = amxd_status_ok;
        }
    } else {
        when_null_status(trans->current, exit, status = amxd_status_object_not_found);
        amxd_trans_action_start(trans, action, rollback);
        status = amxd_dm_invoke_action(trans->current,
                                       NULL,
                                       action->action,
                                       &action->data,
                                       retval);
        when_failed(status, exit);
        status = amxd_trans_action_end(trans, action, rollback, retval);
    }

exit:
    return status;
}

static void amxd_trans_collect_garbage(amxd_trans_t* trans,
                                       amxd_dm_t* dm) {
    amxc_llist_for_each_reverse(it, (&trans->garbage)) {
        amxc_string_t* path = amxc_string_from_llist_it(it);
        amxd_object_t* object = amxd_dm_findf(dm, "%s", amxc_string_get(path, 0));
        if(object != NULL) {
            amxd_dm_invoke_action(object, NULL, action_object_destroy, NULL, NULL);
        }
    }
    amxc_llist_clean(&trans->garbage, amxc_string_list_it_free);
}

static void amxd_trans_revert(amxd_trans_t* trans, amxd_dm_t* dm) {
    amxc_llist_for_each_reverse(it, (&trans->actions)) {
        amxd_trans_action_t* action =
            amxc_llist_it_get_data(it, amxd_trans_action_t, it);
        amxd_trans_invoke_action(trans, dm, action, NULL);
    }

    amxd_trans_collect_garbage(trans, dm);
}

static void amxd_trans_emit_changed(UNUSED amxd_object_t* object, amxc_var_t* params) {
    amxd_path_t path;
    amxc_var_t objects;

    amxc_var_init(&objects);
    amxc_var_set_type(&objects, AMXC_VAR_ID_HTABLE);

    amxd_path_init(&path, NULL);

    amxc_var_for_each(param, params) {
        amxc_var_t* obj_params = NULL;
        const char* rel_obj_path = NULL;

        amxd_path_setf(&path, false, "%s", amxc_var_key(param));
        rel_obj_path = amxd_path_get(&path, AMXD_OBJECT_TERMINATE);
        obj_params = GET_ARG(&objects, rel_obj_path);

        if(obj_params == NULL) {
            obj_params = amxc_var_add_key(amxc_htable_t, &objects, rel_obj_path, NULL);
        }

        amxc_var_set_key(obj_params, amxd_path_get_param(&path), param, AMXC_VAR_FLAG_DEFAULT);
    }

    amxc_var_for_each(object_params, &objects) {
        amxd_object_t* rel_obj = amxd_object_findf(object, "%s", amxc_var_key(object_params));
        amxd_object_emit_changed(rel_obj, object_params);
    }

    amxd_path_clean(&path);
    amxc_var_clean(&objects);
}

static amxd_status_t amxd_trans_validate_objects(amxd_trans_t* trans,
                                                 amxd_dm_t* dm) {
    amxd_status_t status = amxd_status_ok;

    amxc_llist_for_each(it, (&trans->validate)) {
        validate_t* val = amxc_llist_it_get_data(it, validate_t, it);
        amxd_object_t* object = amxd_dm_findf(dm, "%s", val->path);
        if(val->reason != action_object_del_inst) {
            status = amxd_object_validate(object,
                                          val->reason != action_object_write ?
                                          INT32_MAX : 0);
            if(status != amxd_status_ok) {
                goto exit;
            }
        }
    }

    amxc_llist_for_each(it, (&trans->validate)) {
        validate_t* val = amxc_llist_it_get_data(it, validate_t, it);
        amxd_object_t* object = amxd_dm_findf(dm, "%s", val->path);
        if(val->reason == action_object_add_inst) {
            amxd_object_emit_add_inst(object);
        } else if(val->reason == action_object_del_inst) {
            amxd_object_emit_del_inst(object);
        } else if(val->reason == action_object_write) {
            amxc_var_t* params = GET_ARG(val->event_data, "parameters");
            if(params != NULL) {
                amxd_trans_emit_changed(object, params);
            }
        }

    }

    amxd_trans_collect_garbage(trans, dm);

exit:
    return status;
}

static void amxd_trans_dump_action(amxd_trans_action_t* action, int fd) {
    switch(action->action) {
    case action_any:
        when_true(write(fd, "SELECT - \n", 10) == -1, exit);
        break;
    case action_object_write:
        when_true(write(fd, "SET - \n", 7) == -1, exit);
        break;
    case action_object_add_inst:
        when_true(write(fd, "ADD - \n", 7) == -1, exit);
        break;
    case action_object_del_inst:
        when_true(write(fd, "DEL - \n", 7) == -1, exit);
        break;
    default:
        break;
    }
    amxc_var_dump(&action->data, fd);
    when_true(write(fd, "\n", 1) == -1, exit);

exit:
    return;
}

amxd_status_t amxd_trans_init(amxd_trans_t* const trans) {
    amxd_status_t status = amxd_status_unknown_error;
    when_null(trans, exit);

    amxc_llist_init(&trans->actions);
    amxc_llist_init(&trans->garbage);
    amxc_llist_init(&trans->validate);
    amxc_var_init(&trans->retvals);
    amxc_var_set_type(&trans->retvals, AMXC_VAR_ID_LIST);

    trans->current = NULL;
    trans->status = amxd_status_ok;
    trans->fail_index = -1;
    trans->attr.read_only = 0;
    trans->access = amxd_dm_access_protected;

    status = amxd_status_ok;

exit:
    return status;
}

void amxd_trans_clean(amxd_trans_t* const trans) {
    when_null(trans, exit);

    amxc_llist_clean(&trans->actions, amxd_trans_free_action_it);
    amxc_llist_clean(&trans->garbage, amxc_string_list_it_free);
    amxc_llist_clean(&trans->validate, amxd_trans_free_validate_it);
    amxc_var_clean(&trans->retvals);

    trans->status = amxd_status_ok;
    trans->fail_index = -1;

exit:
    return;
}

amxd_status_t amxd_trans_new(amxd_trans_t** trans) {
    amxd_status_t status = amxd_status_unknown_error;
    when_null(trans, exit);

    *trans = (amxd_trans_t*) calloc(1, sizeof(amxd_trans_t));
    when_null((*trans), exit);

    status = amxd_trans_init(*trans);

exit:
    return status;
}

void amxd_trans_delete(amxd_trans_t** trans) {
    when_null(trans, exit);
    when_null((*trans), exit);

    amxd_trans_clean(*trans);

    free(*trans);
    *trans = NULL;

exit:
    return;
}

amxd_status_t amxd_trans_set_attr(amxd_trans_t* trans,
                                  amxd_tattr_id_t attr,
                                  bool enable) {
    amxd_status_t retval = amxd_status_unknown_error;
    when_null(trans, exit);

    switch(attr) {
    case amxd_tattr_change_ro:
        trans->attr.read_only = enable;
        break;
    case amxd_tattr_change_pub:
        trans->access = amxd_dm_access_public;
        break;
    case amxd_tattr_change_prot:
        trans->access = enable ? amxd_dm_access_protected : amxd_dm_access_public;
        break;
    case amxd_tattr_change_priv:
        trans->access = enable ? amxd_dm_access_private : amxd_dm_access_public;
        break;
    }

    retval = amxd_status_ok;

exit:
    return retval;
}

amxd_status_t amxd_trans_add_action(amxd_trans_t* const trans,
                                    const amxd_action_t reason,
                                    const amxc_var_t* data) {
    amxd_status_t status = amxd_status_unknown_error;
    amxd_trans_action_t* action = NULL;

    when_null(trans, exit);
    when_true_status(reason != action_any &&
                     reason != action_object_write &&
                     reason != action_object_add_inst &&
                     reason != action_object_del_inst,
                     exit,
                     status = amxd_status_invalid_action);

    action = amxd_trans_new_action(trans, reason);
    when_null(action, exit);
    amxc_var_copy(&action->data, data);
    status = amxd_status_ok;

exit:
    if(trans != NULL) {
        trans->status = status;
    }
    return status;
}

amxd_status_t amxd_trans_select_pathf(amxd_trans_t* const trans,
                                      const char* path,
                                      ...) {
    amxd_status_t status = amxd_status_unknown_error;
    amxc_string_t full_path;
    amxd_trans_action_t* action = NULL;
    int length = 0;
    va_list args;

    amxc_string_init(&full_path, 64);

    when_null(trans, exit);
    when_null(path, exit);

    va_start(args, path);
    amxc_string_vsetf(&full_path, path, args);
    va_end(args);

    amxc_string_trim(&full_path, NULL);
    when_str_empty(amxc_string_get(&full_path, 0), exit);
    length = amxc_string_text_length(&full_path);
    if(amxc_string_get(&full_path, 0)[length - 1] != '.') {
        amxc_string_append(&full_path, ".", 1);
    }

    action = amxd_trans_new_action(trans, action_any);
    when_null(action, exit);
    when_null(amxc_var_add_key(cstring_t,
                               &action->data,
                               "path",
                               amxc_string_get(&full_path, 0)),
              exit);

    status = amxd_status_ok;

exit:
    if(trans != NULL) {
        trans->status = status;
    }
    amxc_string_clean(&full_path);
    return status;
}

amxd_status_t amxd_trans_select_object(amxd_trans_t* const trans,
                                       const amxd_object_t* const object) {
    amxd_status_t status = amxd_status_unknown_error;
    char* full_path = NULL;
    amxd_trans_action_t* action = NULL;

    when_null(trans, exit);
    when_null(object, exit);

    full_path = amxd_object_get_path(object, AMXD_OBJECT_INDEXED | AMXD_OBJECT_TERMINATE);
    action = amxd_trans_new_action(trans, action_any);
    when_null(action, exit);
    when_null(amxc_var_add_key(cstring_t, &action->data, "path", full_path), exit);

    status = amxd_status_ok;

exit:
    if(trans != NULL) {
        trans->status = status;
    }
    free(full_path);
    return status;
}

amxd_status_t amxd_trans_set_param(amxd_trans_t* trans,
                                   const char* param_name,
                                   amxc_var_t* const value) {
    amxd_status_t status = amxd_status_unknown_error;
    amxd_trans_action_t* action = NULL;
    amxc_var_t* params = NULL;

    when_null(trans, exit);
    when_str_empty(param_name, exit);
    when_null(value, exit);

    action = amxd_trans_find_write_action(trans);
    if(action == NULL) {
        action = amxd_trans_new_action(trans, action_object_write);
        when_null(action, exit);
        when_null(amxc_var_add_key(bool, &action->data, "set_read_only",
                                   trans->attr.read_only == 1),
                  exit);
        when_null(amxc_var_add_key(uint32_t, &action->data, "access", trans->access),
                  exit);
    }

    params = amxc_var_get_key(&action->data, "parameters",
                              AMXC_VAR_FLAG_DEFAULT);
    if(params == NULL) {
        params = amxc_var_add_key(amxc_htable_t, (&action->data), "parameters",
                                  NULL);
        when_null(params, exit);
    }

    when_failed(amxc_var_set_key(params, param_name, value,
                                 AMXC_VAR_FLAG_UPDATE | AMXC_VAR_FLAG_COPY),
                exit);

    status = amxd_status_ok;

exit:
    if(trans != NULL) {
        trans->status = status;
    }
    return status;
}

amxd_status_t amxd_trans_add_inst(amxd_trans_t* const trans,
                                  const uint32_t index,
                                  const char* name) {
    amxd_status_t status = amxd_status_unknown_error;
    amxd_trans_action_t* action = NULL;

    when_null(trans, exit);

    action = amxd_trans_new_action(trans, action_object_add_inst);
    when_null(action, exit);

    when_null(amxc_var_add_key(bool,
                               &action->data,
                               "set_read_only",
                               trans->attr.read_only == 1),
              exit);
    when_null(amxc_var_add_key(uint32_t,
                               &action->data,
                               "access",
                               trans->access),
              exit);
    when_null(amxc_var_add_key(uint32_t, &action->data, "index", index),
              exit);
    when_null(amxc_var_add_key(cstring_t,
                               &action->data,
                               "name",
                               name == NULL ? "" : name),
              exit);

    status = amxd_status_ok;

exit:
    if(trans != NULL) {
        trans->status = status;
    }
    return status;
}

amxd_status_t amxd_trans_del_inst(amxd_trans_t* const trans,
                                  const uint32_t index,
                                  const char* name) {
    amxd_status_t status = amxd_status_unknown_error;
    amxd_trans_action_t* action = NULL;

    when_null(trans, exit);

    action = amxd_trans_new_action(trans, action_object_del_inst);
    when_null(action, exit);
    when_true((index == 0 && (name == NULL || *name == 0)), exit);

    when_null(amxc_var_add_key(bool,
                               &action->data,
                               "set_read_only",
                               trans->attr.read_only == 1),
              exit);
    when_null(amxc_var_add_key(uint32_t,
                               &action->data,
                               "access",
                               trans->access),
              exit);
    when_null(amxc_var_add_key(uint32_t, &action->data, "index", index),
              exit);
    when_null(amxc_var_add_key(cstring_t,
                               &action->data,
                               "name",
                               name == NULL ? "" : name),
              exit);

    status = amxd_status_ok;

exit:
    if(trans != NULL) {
        trans->status = status;
    }
    return status;
}

amxd_status_t amxd_trans_add_mib(amxd_trans_t* const trans,
                                 const char* mib_name) {
    amxd_status_t status = amxd_status_unknown_error;
    amxd_trans_action_t* action = NULL;

    when_null(trans, exit);

    action = amxd_trans_new_action(trans, action_object_add_mib);
    when_null(action, exit);
    when_str_empty(mib_name, exit);

    when_null(amxc_var_add_key(cstring_t,
                               &action->data,
                               "mib",
                               mib_name),
              exit);

    status = amxd_status_ok;

exit:
    if(trans != NULL) {
        trans->status = status;
    }
    return status;
}

amxd_status_t amxd_trans_apply(amxd_trans_t* const trans,
                               amxd_dm_t* const dm) {
    static bool trans_buzy = false;
    amxd_status_t status = amxd_status_unknown_error;
    amxd_trans_t rollback;

    amxd_trans_init(&rollback);
    when_true(trans_buzy, exit);
    when_null(trans, exit);
    when_null(dm, exit);
    when_failed_status(trans->status, exit, status = trans->status);
    trans_buzy = true;
    trans->fail_index = 0;
    amxc_var_clean(&trans->retvals);
    amxc_var_set_type(&trans->retvals, AMXC_VAR_ID_LIST);
    amxc_llist_for_each(it, (&trans->actions)) {
        amxd_trans_action_t* action =
            amxc_llist_it_get_data(it, amxd_trans_action_t, it);
        status = amxd_trans_invoke_action(trans, dm, action, &rollback);
        when_failed(status, exit);
        trans->fail_index++;
    }
    status = amxd_trans_validate_objects(trans, dm);

exit:
    if(trans != NULL) {
        trans->status = status;
        if(status != amxd_status_ok) {
            amxd_trans_select_object(&rollback, trans->current);
            amxd_trans_revert(&rollback, dm);
            amxc_llist_clean(&trans->garbage, amxc_string_list_it_free);
            trans->current = NULL;
        } else {
            amxc_llist_clean(&trans->actions, amxd_trans_free_action_it);
        }
        amxd_trans_clean(&rollback);
    }
    trans_buzy = false;
    return status;
}

void amxd_trans_dump(const amxd_trans_t* const trans,
                     const int fd,
                     const bool reverse) {
    if(reverse) {
        amxc_llist_for_each_reverse(it, (&trans->actions)) {
            amxd_trans_action_t* action =
                amxc_llist_it_get_data(it, amxd_trans_action_t, it);
            amxd_trans_dump_action(action, fd);
        }
    } else {
        amxc_llist_for_each(it, (&trans->actions)) {
            amxd_trans_action_t* action =
                amxc_llist_it_get_data(it, amxd_trans_action_t, it);
            amxd_trans_dump_action(action, fd);
        }
    }
}
