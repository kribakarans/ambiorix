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

#include <amxrt/amxrt.h>
#include <amxo/amxo_save.h>
#include <amxd/amxd_object.h>
#include <amxp/amxp_dir.h>

#include "amxrt_priv.h"

typedef struct _odl_storage {
    amxp_timer_t* save_timer;
    amxd_dm_t* dm;
    amxo_parser_t* parser;
    amxc_llist_t save_paths;
} odl_storage_t;

static odl_storage_t storage;

static int isdot(int c) {
    if(c == '.') {
        return 1;
    }

    return 0;
}

static amxc_var_t* amxrt_get_save_objects(amxo_parser_t* parser) {
    amxc_var_t* paths = GETP_ARG(&parser->config, AMXRT_COPT_OBJECTS);

    when_null(paths, exit);

    if(amxc_var_type_of(paths) == AMXC_VAR_ID_CSTRING) {
        amxc_var_cast(paths, AMXC_VAR_ID_CSV_STRING);
        amxc_var_cast(paths, AMXC_VAR_ID_LIST);
    } else if(amxc_var_type_of(paths) == AMXC_VAR_ID_CSV_STRING) {
        amxc_var_cast(paths, AMXC_VAR_ID_LIST);
    } else if(amxc_var_type_of(paths) != AMXC_VAR_ID_LIST) {
        amxrt_print_error("Export - Export objects specified in wrong format");
    }

exit:
    return paths;
}

static char* amxrt_get_directory(amxo_parser_t* parser) {
    amxc_string_t dir;
    const char* odl_dir = GETP_CHAR(&parser->config, AMXRT_COPT_DIRECTORY);
    char* resolved_dir = NULL;

    amxc_string_init(&dir, 0);
    if(odl_dir == NULL) {
        odl_dir = GETP_CHAR(&parser->config, AMXRT_COPT_STORAGE_DIR);
    }
    if(odl_dir != NULL) {
        amxc_string_setf(&dir, "%s", odl_dir);
        amxc_string_resolve(&dir, &parser->config);
        resolved_dir = amxc_string_take_buffer(&dir);
    }

    return resolved_dir;
}

static int amxrt_dm_load(amxd_dm_t* dm, amxo_parser_t* parser) {
    int status = 0;
    amxc_string_t include;
    bool is_empty_dir = false;

    amxd_object_t* root = amxd_dm_get_root(dm);
    char* odl_dir = amxrt_get_directory(parser);
    amxc_var_t* eventing = GET_ARG(&parser->config, AMXRT_COPT_EVENT);
    bool orig_eventing = GET_BOOL(eventing, NULL);
    bool dm_eventing_enabled = GETP_BOOL(&parser->config, AMXRT_COPT_EVENTS);

    amxc_string_init(&include, 0);

    if((odl_dir == NULL) || (*odl_dir == 0)) {
        amxrt_print_message("Load - No odl directory specified");
        goto exit;
    }

    amxc_var_set(bool, eventing, dm_eventing_enabled);
    amxp_sigmngr_enable(&dm->sigmngr, dm_eventing_enabled);

    amxc_string_setf(&include, "include \"%s\";", odl_dir);
    status = amxo_parser_parse_string(parser, amxc_string_get(&include, 0), root);
    if(status == 0) {
        is_empty_dir = amxp_dir_is_empty(odl_dir);
    }
    if((status != 0) || is_empty_dir) {
        const char* def = GETP_CHAR(&parser->config, AMXRT_COPT_DEFAULTS);
        amxrt_print_message("Load - Failed to load %s or directory is empty", odl_dir);
        when_true((def == NULL) || (*def == 0), exit);
        amxrt_print_message("Load - Try to load default from %s", def);
        amxc_string_setf(&include, "include \"%s\";", def);
        status = amxo_parser_parse_string(parser, amxc_string_get(&include, 0), root);
        if(status != 0) {
            amxrt_print_message("Load - Failed to load defaults from %s", def);
        }
    }

exit:
    amxp_sigmngr_enable(&dm->sigmngr, true);
    amxc_var_set(bool, eventing, orig_eventing);
    free(odl_dir);
    amxc_string_clean(&include);
    return status;
}

static int amxrt_dm_save_object(amxo_parser_t* parser,
                                amxd_object_t* object,
                                const char* dir,
                                const char* name) {
    int status = 0;
    amxc_string_t file;
    amxc_string_init(&file, 0);

    amxc_string_setf(&file, "%s/%s.odl", dir, name);
    status = amxo_parser_save_object(parser, amxc_string_get(&file, 0), object, false);
    when_failed_status(status, exit,
                       amxrt_print_error("Export - Failed to write %s file", amxc_string_get(&file, 0)));

exit:
    amxc_string_clean(&file);
    return status;
}

static int amxrt_dm_save(amxd_dm_t* dm, amxo_parser_t* parser) {
    int status = 0;
    amxc_var_t* paths = amxrt_get_save_objects(parser);
    char* odl_dir = amxrt_get_directory(parser);
    uint32_t index = 0;
    amxc_string_t file_name;

    amxc_string_init(&file_name, 0);

    when_true_status((odl_dir == NULL) || (*odl_dir == 0), exit,
                     amxrt_print_error("Export - No odl directory specified"));

    if(paths == NULL) {
        amxd_object_t* root = amxd_dm_get_root(dm);
        const char* name = GETP_CHAR(&parser->config, AMXRT_COPT_NAME);
        when_null_status(name, exit, status = -1);
        status = amxrt_dm_save_object(parser, root, odl_dir, name);
        goto exit;
    }

    when_true(amxc_var_type_of(paths) != AMXC_VAR_ID_LIST, exit);

    amxc_var_for_each(path, paths) {
        const char* op = amxc_var_constcast(cstring_t, path);
        amxd_object_t* obj = NULL;
        amxc_string_setf(&file_name, "%2.2d_%s", index, op);
        amxc_string_trimr(&file_name, isdot);
        obj = amxd_dm_findf(dm, "%s", op);
        if(obj == NULL) {
            amxrt_print_error("Export - Object %s not found", op);
            continue;
        }
        status = amxrt_dm_save_object(parser, obj, odl_dir, amxc_string_get(&file_name, 0));
        index++;
    }

exit:
    amxc_string_clean(&file_name);
    free(odl_dir);
    return status;
}

static bool amxrt_save_check_tree(amxd_object_t* object) {
    bool persistent = true;
    amxd_object_t* parent = amxd_object_get_parent(object);

    while(amxd_object_get_type(parent) != amxd_object_root &&
          persistent) {
        persistent &= amxd_object_is_attr_set(object, amxd_oattr_persistent);
        parent = amxd_object_get_parent(parent);
    }

    return persistent;
}

static bool amxrt_save_check_persistent_params(amxd_object_t* object,
                                               const amxc_var_t* data) {
    bool persistent = false;
    amxc_var_t* params = GET_ARG(data, "parameters");

    amxc_var_for_each(param, params) {
        const char* name = amxc_var_key(param);
        amxd_param_t* param_def = amxd_object_get_param_def(object, name);
        persistent |= amxd_param_is_attr_set(param_def, amxd_pattr_persistent);
        if(persistent) {
            break;
        }
    }

    return persistent;
}

static void amxrt_save_add_path(const char* path) {
    amxc_string_t* save_path = NULL;
    bool is_set = false;

    amxc_llist_iterate(it, (&storage.save_paths)) {
        amxc_string_t* set_path = amxc_string_from_llist_it(it);
        if(strcmp(path, amxc_string_get(set_path, 0)) == 0) {
            is_set = true;
            break;
        }
    }
    if(!is_set) {
        amxc_string_new(&save_path, 0);
        amxc_string_setf(save_path, "%s", path);
        amxc_llist_append(&storage.save_paths, &save_path->it);
    }
}

static bool amxrt_save_check_paths(amxo_parser_t* parser, amxd_object_t* object) {
    bool save_needed = false;
    char* obj_path = amxd_object_get_path(object, AMXD_OBJECT_INDEXED);

    amxc_var_t* paths = amxrt_get_save_objects(parser);
    when_null_status(paths, exit, save_needed = true);

    when_true(amxc_var_type_of(paths) != AMXC_VAR_ID_LIST, exit);

    amxc_var_for_each(path, paths) {
        const char* str_path = amxc_var_constcast(cstring_t, path);
        int len = strlen(str_path);
        if(strncmp(str_path, obj_path, len) == 0) {
            amxrt_save_add_path(str_path);
            save_needed = true;
            break;
        }
    }

exit:
    free(obj_path);
    return save_needed;
}

static void amxrt_timed_save(UNUSED amxp_timer_t* const timer,
                             UNUSED void* data) {
    if(amxc_llist_is_empty(&storage.save_paths)) {
        amxrt_dm_save(storage.dm, storage.parser);
    } else {
        amxd_object_t* object = NULL;
        char* dir = amxrt_get_directory(storage.parser);
        uint32_t index = 0;
        amxc_string_t file_name;
        amxc_string_init(&file_name, 0);

        amxc_llist_for_each(it, (&storage.save_paths)) {
            amxc_string_t* path = amxc_string_from_llist_it(it);
            amxc_string_setf(&file_name, "%2.2d_%s", index, amxc_string_get(path, 0));
            amxc_string_trimr(&file_name, isdot);

            object = amxd_dm_findf(storage.dm, "%s", amxc_string_get(path, 0));
            amxrt_dm_save_object(storage.parser, object, dir, amxc_string_get(&file_name, 0));
            amxc_string_delete(&path);
        }

        amxc_string_clean(&file_name);
        free(dir);
    }
}

static void amxrt_save_changed(const char* const sig_name,
                               const amxc_var_t* const data,
                               UNUSED void* const priv) {
    amxd_object_t* object = amxd_dm_signal_get_object(storage.dm, data);
    amxo_parser_t* parser = storage.parser;
    uint32_t save_delay = amxc_var_dyncast(uint32_t, GETP_ARG(&parser->config, AMXRT_COPT_DELAY));
    bool save_needed = false;

    if((strcmp(sig_name, "dm:instance-added") == 0) ||
       (strcmp(sig_name, "dm:instance-removed") == 0)) {
        uint32_t index = GET_UINT32(data, "index");
        amxd_object_t* instance = amxd_object_get_instance(object, NULL, index);
        object = instance != NULL? instance: object;
        if(amxd_object_is_attr_set(object, amxd_oattr_persistent)) {
            save_needed = amxrt_save_check_tree(object);
        }
    } else if(strcmp(sig_name, "dm:object-changed") == 0) {
        if(amxd_object_is_attr_set(object, amxd_oattr_persistent)) {
            save_needed = amxrt_save_check_tree(object);
            if(save_needed) {
                save_needed = amxrt_save_check_persistent_params(object, data);
            }
        }
    } else {
        if(amxd_object_is_attr_set(object, amxd_oattr_persistent)) {
            save_needed = amxrt_save_check_tree(object);
        }
    }

    if(save_needed) {
        save_needed = amxrt_save_check_paths(parser, object);

    }
    if(save_needed) {
        if(storage.save_timer == NULL) {
            amxp_timer_new(&storage.save_timer, amxrt_timed_save, NULL);
            save_delay = amxc_var_dyncast(uint32_t, GETP_ARG(&parser->config, AMXRT_COPT_INIT_DELAY));
            save_delay = save_delay == 0 ? 30000 : save_delay;
        }

        if((amxp_timer_remaining_time(storage.save_timer) < save_delay) ||
           (amxp_timer_get_state(storage.save_timer) != amxp_timer_running)) {
            amxp_timer_start(storage.save_timer, save_delay == 0 ? 500 : save_delay);
        }
    }
}

static void amxrt_save_subscribe(amxd_dm_t* dm) {
    amxp_slot_connect(&dm->sigmngr, "dm:object-changed", NULL, amxrt_save_changed, NULL);
    amxp_slot_connect(&dm->sigmngr, "dm:instance-added", NULL, amxrt_save_changed, NULL);
    amxp_slot_connect(&dm->sigmngr, "dm:instance-removed", NULL, amxrt_save_changed, NULL);
}

static bool amxrt_is_odl_storage_enabled(amxo_parser_t* parser) {
    bool retval = true;
    const char* storage_type = GETP_CHAR(&parser->config, AMXRT_COPT_STORAGE);

    when_true((storage_type == NULL) || (*storage_type == 0), exit);
    when_true(strcmp(storage_type, "odl") == 0, exit);
    retval = false;

exit:
    return retval;
}

static void amxrt_monitor_changes(UNUSED const char* const sig_name,
                                  UNUSED const amxc_var_t* const data,
                                  UNUSED void* const priv) {
    amxp_slot_disconnect_all(amxrt_monitor_changes);
    amxrt_save_subscribe(storage.dm);
}

static int amxrt_odl_save_load_init(amxd_dm_t* dm, amxo_parser_t* parser) {
    char* directory = amxrt_get_directory(parser);
    int retval = 0;

    storage.dm = dm;
    storage.parser = parser;
    amxc_llist_init(&storage.save_paths);

    if(amxp_dir_make(directory, 0777) != 0) {
        amxrt_print_error("Failed to create directory %s", directory);
    }

    if(GETP_BOOL(&parser->config, AMXRT_COPT_LOAD)) {
        retval = amxrt_dm_load(dm, parser);
        if(retval != 0) {
            // turn off saving and exit
            amxc_var_t* save_opt = GETP_ARG(&parser->config, AMXRT_COPT_SAVE);
            amxc_var_set(bool, save_opt, false);
            goto exit;
        }
    }

    if(GETP_BOOL(&parser->config, AMXRT_COPT_ON_CHANGED)) {
        amxp_slot_connect(&dm->sigmngr, "app:start", NULL, amxrt_monitor_changes, NULL);
    }

exit:
    free(directory);
    return retval;
}

static void amxrt_odl_save_load_cleanup(amxd_dm_t* dm, amxo_parser_t* parser) {
    amxp_timer_delete(&storage.save_timer);
    amxp_slot_disconnect_all(amxrt_save_changed);
    amxp_slot_disconnect_all(amxrt_monitor_changes);
    if(GETP_BOOL(&parser->config, AMXRT_COPT_SAVE)) {
        amxrt_dm_save(dm, parser);
    }
    amxc_llist_clean(&storage.save_paths, amxc_string_list_it_free);
    storage.dm = NULL;
    storage.parser = NULL;
}

int amxrt_dm_create_dir(amxo_parser_t* parser, uid_t uid, gid_t gid) {
    int rv = -1;
    char* directory = NULL;

    when_null(parser, exit);

    if(!amxrt_is_odl_storage_enabled(parser)) {
        goto exit;
    }

    directory = amxrt_get_directory(parser);
    rv = amxp_dir_owned_make(directory, 0777, uid, gid);
    if(rv != 0) {
        amxrt_print_error("Failed to create directory %s", directory);
    }
    free(directory);

exit:
    return rv;
}

int amxrt_dm_save_load_main(int reason, amxd_dm_t* dm, amxo_parser_t* parser) {
    int retval = 0;

    when_false(amxrt_is_odl_storage_enabled(parser), exit);

    switch(reason) {
    case 0: // START
        retval = amxrt_odl_save_load_init(dm, parser);
        break;
    case 1: // STOP
        amxrt_odl_save_load_cleanup(dm, parser);
        break;
    }

exit:
    return retval;
}
