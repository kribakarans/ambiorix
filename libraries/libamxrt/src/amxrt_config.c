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

#include <amxrt/amxrt.h>
#include <amxp/amxp_dir.h>

#include "amxrt_priv.h"

static void amxrt_config_read_env_vars(void) {
    amxrt_config_read_env_var("AMXB_BACKENDS",
                              AMXRT_COPT_BACKENDS,
                              AMXC_VAR_ID_LIST);

    amxrt_config_read_env_var("AMXRT_PREFIX_PATH",
                              AMXRT_COPT_PREFIX_PATH,
                              AMXC_VAR_ID_CSTRING);

    amxrt_config_read_env_var("AMXRT_PLUGIN_DIR",
                              AMXRT_COPT_PLUGIN_DIR,
                              AMXC_VAR_ID_CSTRING);

    amxrt_config_read_env_var("AMXRT_CFG_DIR",
                              AMXRT_COPT_CFG_DIR,
                              AMXC_VAR_ID_CSTRING);
}

static void amxrt_config_add_dir(amxc_var_t* var_dirs, const char* dir) {
    bool found = false;
    const amxc_llist_t* dirs = amxc_var_constcast(amxc_llist_t, var_dirs);

    amxc_llist_for_each(it, dirs) {
        amxc_var_t* var_dir = amxc_var_from_llist_it(it);
        const char* stored_dir = amxc_var_constcast(cstring_t, var_dir);
        if((stored_dir != NULL) && (strcmp(dir, stored_dir) == 0)) {
            found = true;
            break;
        }
    }

    if(!found) {
        amxc_var_add(cstring_t, var_dirs, dir);
    }
}

static void amxrt_config_set_default_dirs(amxo_parser_t* parser) {
    amxc_var_t* inc_dirs = amxo_parser_claim_config(parser, AMXRT_COPT_INCDIRS);
    amxc_var_t* lib_dirs = amxo_parser_claim_config(parser, AMXRT_COPT_LIBDIRS);
    amxc_var_t* mib_dirs = amxo_parser_claim_config(parser, AMXRT_COPT_MIBDIRS);

    amxrt_config_add_dir(inc_dirs, ".");
    amxrt_config_add_dir(inc_dirs, "${prefix}${cfg-dir}/${name}");
    amxrt_config_add_dir(inc_dirs, "${prefix}${cfg-dir}/modules");

    amxrt_config_add_dir(lib_dirs, "${prefix}${plugin-dir}/${name}");
    amxrt_config_add_dir(lib_dirs, "${prefix}${plugin-dir}/modules");
    amxrt_config_add_dir(lib_dirs, "${prefix}/usr/local/lib/amx/${name}");
    amxrt_config_add_dir(lib_dirs, "${prefix}/usr/local/lib/amx/modules");

    amxrt_config_add_dir(mib_dirs, "${prefix}${cfg-dir}/${name}/mibs");


}

static int amxrt_config_add_backend(const char* name, void* priv) {
    amxc_var_t* backends = (amxc_var_t*) priv;
    amxc_var_add(cstring_t, backends, name);

    return 0;
}

// Config options are scoped within the odl file, so when an include is done,
// it is possible the config options are back to the original value
static void amxrt_config_include_end(amxo_parser_t* parser,
                                     UNUSED const char* file) {
    amxrt_t* rt = amxrt_get();
    amxd_dm_t* dm = &rt->dm;
    amxp_sigmngr_enable(&dm->sigmngr, GET_BOOL(&parser->config, AMXRT_COPT_EVENT));
}

// When a config section is done, check if any settings must be applied
static void amxrt_config_section_end(amxo_parser_t* parser,
                                     int section_id) {
    amxrt_t* rt = amxrt_get();
    amxd_dm_t* dm = &rt->dm;
    if(section_id == 0) {
        amxp_sigmngr_enable(&dm->sigmngr, GET_BOOL(&parser->config, AMXRT_COPT_EVENT));
    }
}

static void amxrt_config_option_changed(amxo_parser_t* parser,
                                        UNUSED const char* option,
                                        UNUSED amxc_var_t* value) {
    amxrt_t* rt = amxrt_get();
    amxc_var_for_each(cmd, &rt->forced_options) {
        const char* path = amxc_var_key(cmd);
        amxc_var_set_path(&parser->config, path, cmd, AMXC_VAR_FLAG_UPDATE | AMXC_VAR_FLAG_COPY);
    }
}

static amxo_hooks_t amxrt_config_hooks = {
    .it = { .next = NULL, .prev = NULL, .llist = NULL },
    .comment = NULL,
    .start = NULL,
    .end = NULL,
    .start_include = NULL,
    .end_include = amxrt_config_include_end,
    .set_config = amxrt_config_option_changed,
    .start_section = NULL,
    .end_section = amxrt_config_section_end,
    .create_object = NULL,
    .add_instance = NULL,
    .select_object = NULL,
    .end_object = NULL,
    .add_param = NULL,
    .set_param = NULL,
    .end_param = NULL,
    .add_func = NULL,
    .add_func_arg = NULL,
    .end_func = NULL,
    .add_mib = NULL,
    .set_counter = NULL,
};

// PRIVATE FUNCTIONS
void amxrt_config_add_options(amxo_parser_t* parser) {
    amxc_var_t* config = &parser->config;

    amxc_var_add_key(amxc_llist_t, config, AMXRT_COPT_BACKENDS, NULL);
    amxc_var_add_key(amxc_llist_t, config, AMXRT_COPT_URIS, NULL);
    amxc_var_add_key(amxc_llist_t, config, AMXRT_COPT_DATA_URIS, NULL);
    amxc_var_add_key(bool, config, AMXRT_COPT_AUTO_DETECT, true);
    amxc_var_add_key(bool, config, AMXRT_COPT_AUTO_CONNECT, true);
    amxc_var_add_key(bool, config, AMXRT_COPT_DAEMON, false);
    amxc_var_add_key(uint32_t, config, AMXRT_COPT_PRIORITY, 0);
    amxc_var_add_key(bool, config, AMXRT_COPT_PID_FILE, true);
    amxc_var_add_key(cstring_t, config, AMXRT_COPT_PREFIX_PATH, "");
    amxc_var_add_key(cstring_t, config, AMXRT_COPT_PLUGIN_DIR, AMXRT_CVAL_PLUGIN_DIR);
    amxc_var_add_key(cstring_t, config, AMXRT_COPT_CFG_DIR, AMXRT_CVAL_CFG_DIR);
    amxc_var_add_key(amxc_llist_t, config, AMXRT_COPT_LIBDIRS, NULL);
    amxc_var_add_key(amxc_llist_t, config, AMXRT_COPT_INCDIRS, NULL);
    amxc_var_add_key(amxc_llist_t, config, AMXRT_COPT_MIBDIRS, NULL);
    amxc_var_add_key(amxc_llist_t, config, AMXRT_COPT_LISTEN, NULL);
    amxc_var_add_key(bool, config, AMXRT_COPT_EVENT, false);
    amxc_var_add_key(bool, config, AMXRT_COPT_DUMP_CONFIG, false);
    amxc_var_add_key(bool, config, AMXRT_COPT_DUMP_CAPS, false);
    amxc_var_add_key(cstring_t, config, AMXRT_COPT_BACKENDS_DIR, AMXRT_CVAL_BACKEND_DIR);
    amxc_var_add_key(cstring_t, config, AMXRT_COPT_STORAGE_TYPE, AMXRT_CVAL_STORAGE_TYPE);
    amxc_var_add_key(bool, config, AMXRT_COPT_LOG, false);
    amxc_var_add_key(cstring_t, config, AMXRT_COPT_RW_DATA_PATH, "${prefix}" RWDATAPATH);
    amxc_var_add_key(cstring_t, config, AMXRT_COPT_STORAGE_DIR, "${rw_data_path}/${name}/");
    amxc_var_add_key(amxc_llist_t, config, AMXRT_COPT_REQUIRES, NULL);
    amxc_var_add_key(cstring_t, config, AMXRT_COPT_EXT_DIR, "extensions/");

    // set hooks to monitor config option changes
    amxo_parser_set_hooks(parser, &amxrt_config_hooks);
}

// PUBLIC FUNCTIONS
int amxrt_config_init(int argc, char* argv[], int* index, amxrt_arg_fn_t fn) {
    int retval = 0;
    char* base_name = NULL;
    amxo_parser_t* parser = amxrt_get_parser();

    amxrt_config_read_env_vars();

    amxrt_config_set_default_dirs(parser);

    base_name = strdup(basename(argv[0]));
    when_null_status(base_name, exit, retval = -1);
    for(int i = strlen(base_name) - 1; i > 0; i--) {
        if(base_name[i] == '.') {
            base_name[i] = 0;
        }
    }
    amxc_var_add_key(cstring_t, &parser->config, AMXRT_COPT_NAME, base_name);

    *index = amxrt_cmd_line_parse(argc, argv, fn);
    if(*index < 0) {
        retval = *index;
        *index = argc;
    }

exit:
    free(base_name);
    return retval;
}

void amxrt_config_scan_backend_dirs(void) {
    amxo_parser_t* parser = amxrt_get_parser();

    if(amxc_var_constcast(bool, GET_ARG(&parser->config, AMXRT_COPT_AUTO_DETECT))) {
        amxc_var_t* backends = GET_ARG(&parser->config, AMXRT_COPT_BACKENDS);
        amxc_var_t* dirs = GET_ARG(&parser->config, AMXRT_COPT_BACKENDS_DIR);
        if(amxc_var_type_of(dirs) == AMXC_VAR_ID_LIST) {
            amxc_var_for_each(dir, dirs) {
                const char* path = GET_CHAR(dir, NULL);
                amxp_dir_scan(path, "d_name matches '.*\\.so'", false, amxrt_config_add_backend, backends);
            }
        } else {
            const char* path = GET_CHAR(&parser->config, AMXRT_COPT_BACKENDS_DIR);
            amxp_dir_scan(path, "d_name matches '.*\\.so'", false, amxrt_config_add_backend, backends);
        }
    }
}

void amxrt_config_read_env_var(const char* var_name,
                               const char* config_name,
                               int32_t var_type) {
    const char* env = getenv(var_name);
    amxc_var_t* config = amxrt_get_config();
    amxc_var_t* coption = GET_ARG(config, config_name);
    amxc_var_t var_env;

    amxc_var_init(&var_env);

    if(env == NULL) {
        goto exit;
    }

    amxc_var_set(cstring_t, &var_env, env);

    if(coption == NULL) {
        coption = amxc_var_add_new_key(config, config_name);
        amxc_var_set_type(coption, var_type);
    }

    switch(var_type) {
    case AMXC_VAR_ID_LIST: {
        amxc_string_t* str_env = amxc_var_take(amxc_string_t, &var_env);
        amxc_llist_t parts;
        amxc_llist_init(&parts);
        amxc_string_split_to_llist(str_env, &parts, ';');
        amxc_llist_for_each(it, (&parts)) {
            amxc_string_t* part = amxc_string_from_llist_it(it);
            amxc_var_add(cstring_t, coption, amxc_string_get(part, 0));
            amxc_string_delete(&part);
        }
        amxc_llist_clean(&parts, amxc_string_list_it_free);
        amxc_string_delete(&str_env);
    }
    break;
    default: {
        amxc_var_convert(coption, &var_env, var_type);
    }
    break;
    }

exit:
    amxc_var_clean(&var_env);
    return;
}
