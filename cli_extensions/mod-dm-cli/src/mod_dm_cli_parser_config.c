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

#include <string.h>

#include "dm_cli_priv.h"

#define COPT_PREFIX_PATH "prefix"
#define COPT_PLUGIN_DIR "plugin-dir"
#define COPT_CFG_DIR "cfg-dir"

#define COPT_INCDIRS "include-dirs"
#define COPT_LIBDIRS "import-dirs"
#define COPT_MIBDIRS "mib-dirs"

#define PLUGIN_DIR "/usr/lib/amx"
#define CFG_DIR "/etc/amx"

static void args_read_env_var(amxc_var_t* config,
                              const char* var_name,
                              const char* config_name,
                              int32_t var_type) {
    const char* env = getenv(var_name);
    amxc_var_t* coption = GET_ARG(config, config_name);
    amxc_var_t var_env;

    amxc_var_init(&var_env);

    if(env == NULL) {
        goto exit;
    }

    amxc_var_set(cstring_t, &var_env, env);
    amxc_var_convert(coption, &var_env, var_type);

exit:
    amxc_var_clean(&var_env);
    return;
}

static void parser_config_read_env_vars(amxc_var_t* config) {
    args_read_env_var(config,
                      "AMXRT_PREFIX_PATH",
                      COPT_PREFIX_PATH,
                      AMXC_VAR_ID_CSTRING);

    args_read_env_var(config,
                      "AMXRT_PLUGIN_DIR",
                      COPT_PLUGIN_DIR,
                      AMXC_VAR_ID_CSTRING);

    args_read_env_var(config,
                      "AMXRT_CFG_DIR",
                      COPT_CFG_DIR,
                      AMXC_VAR_ID_CSTRING);
}

static void parser_config_add_dir(amxc_var_t* var_dirs, const char* dir) {
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

static void parser_config_set_default_dirs(amxo_parser_t* parser) {
    amxc_var_t* inc_dirs = amxo_parser_claim_config(parser, COPT_INCDIRS);
    amxc_var_t* lib_dirs = amxo_parser_claim_config(parser, COPT_LIBDIRS);
    amxc_var_t* mib_dirs = amxo_parser_claim_config(parser, COPT_MIBDIRS);

    parser_config_add_dir(inc_dirs, ".");
    parser_config_add_dir(inc_dirs, "${prefix}${cfg-dir}/${name}");
    parser_config_add_dir(inc_dirs, "${prefix}${cfg-dir}/modules");

    parser_config_add_dir(lib_dirs, "${prefix}${plugin-dir}/${name}");
    parser_config_add_dir(lib_dirs, "${prefix}${plugin-dir}/modules");
    parser_config_add_dir(lib_dirs, "${prefix}/usr/local/lib/amx/${name}");
    parser_config_add_dir(lib_dirs, "${prefix}/usr/local/lib/amx/modules");

    parser_config_add_dir(mib_dirs, "${prefix}${cfg-dir}/${name}/mibs");
}

void mod_dm_cli_parser_config_init(amxo_parser_t* parser) {
    amxc_var_t* config = &parser->config;
    amxc_var_add_key(cstring_t, config, COPT_PREFIX_PATH, "");
    amxc_var_add_key(cstring_t, config, COPT_PLUGIN_DIR, PLUGIN_DIR);
    amxc_var_add_key(cstring_t, config, COPT_CFG_DIR, CFG_DIR);
    amxc_var_add_key(amxc_llist_t, config, COPT_LIBDIRS, NULL);
    amxc_var_add_key(amxc_llist_t, config, COPT_INCDIRS, NULL);
    amxc_var_add_key(amxc_llist_t, config, COPT_MIBDIRS, NULL);

    parser_config_read_env_vars(&parser->config);
    parser_config_set_default_dirs(parser);
}

