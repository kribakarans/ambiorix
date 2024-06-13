/****************************************************************************
**
** Copyright (c) 2020 SoftAtHome
**
** Redistribution and use in source and binary forms, with or
** without modification, are permitted provided that the following
** conditions are met:
**
** 1. Redistributions of source code must retain the above copyright
** notice, this list of conditions and the following disclaimer.
**
** 2. Redistributions in binary form must reproduce the above
** copyright notice, this list of conditions and the following
** disclaimer in the documentation and/or other materials provided
** with the distribution.
**
** Subject to the terms and conditions of this license, each
** copyright holder and contributor hereby grants to those receiving
** rights under this license a perpetual, worldwide, non-exclusive,
** no-charge, royalty-free, irrevocable (except for failure to
** satisfy the conditions of this license) patent license to make,
** have made, use, offer to sell, sell, import, and otherwise
** transfer this software, where such license applies only to those
** patent claims, already acquired or hereafter acquired, licensable
** by such copyright holder or contributor that are necessarily
** infringed by:
**
** (a) their Contribution(s) (the licensed copyrights of copyright
** holders and non-copyrightable additions of contributors, in
** source or binary form) alone; or
**
** (b) combination of their Contribution(s) with the work of
** authorship to which such Contribution(s) was added by such
** copyright holder or contributor, if, at the time the Contribution
** is added, such addition causes such combination to be necessarily
** infringed. The patent license shall not apply to any other
** combinations which include the Contribution.
**
** Except as expressly stated above, no rights or licenses from any
** copyright holder or contributor is granted under this license,
** whether expressly, by implication, estoppel or otherwise.
**
** DISCLAIMER
**
** THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
** CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
** INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
** MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
** DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR
** CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
** SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
** LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
** USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
** AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
** LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
** ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
** POSSIBILITY OF SUCH DAMAGE.
**
****************************************************************************/

#include <string.h>

#include "dm_ssh_server.h"

typedef struct _uci_mapper {
    const char* uci_name;
    const char* param_name;
} uci_mapper_t;

typedef enum {
    UCI_2_PARAM,
    PARAM_2_UCI
} uci_mapper_direction_t;

static const char* ssh_server_uci_translate(const char* name,
                                            uci_mapper_direction_t direction) {
    uci_mapper_t names[] = {
        { "enable", "Enable" },
        { "PasswordAuth", "AllowPasswordLogin" },
        { "Port", "Port" },
        { "RootPasswordAuth", "AllowRootPasswordLogin" },
        { "RootLogin", "AllowRootLogin" },
        { NULL, NULL }
    };
    const char* translation = NULL;

    for(int i = 0; names[i].uci_name != NULL; i++) {
        if(direction == UCI_2_PARAM) {
            if(strcmp(names[i].uci_name, name) == 0) {
                translation = names[i].param_name;
                break;
            }
        } else {
            if(strcmp(names[i].param_name, name) == 0) {
                translation = names[i].uci_name;
                break;
            }
        }
    }

    return translation;
}

static void ssh_server_uci_set_options(amxd_trans_t* trans, const amxc_htable_t* options) {
    amxc_htable_iterate(it, options) {
        const char* key = amxc_htable_it_get_key(it);
        amxc_var_t* option = amxc_var_from_htable_it(it);
        const char* param_name = ssh_server_uci_translate(key, UCI_2_PARAM);
        amxd_trans_set_param(trans, param_name, option);
    }
}

static int ssh_server_uci_add_section(UNUSED amxd_object_t* templ,
                                      amxd_object_t* instance,
                                      void* priv) {
    amxc_var_t* config = (amxc_var_t*) priv;

    amxc_var_t* section = amxc_var_add(amxc_htable_t, config, NULL);
    amxd_object_for_each(parameter, it, instance) {
        amxd_param_t* param = amxc_container_of(it, amxd_param_t, it);
        const char* param_name = amxd_param_get_name(param);
        const char* option = ssh_server_uci_translate(param_name, PARAM_2_UCI);
        amxc_var_set_key(section, option, &param->value, AMXC_VAR_FLAG_COPY);
    }
    return 0;
}

void ssh_server_uci_import(amxd_dm_t* dm, amxo_parser_t* parser) {
    amxc_string_t package;
    amxc_var_t* config = NULL;
    amxd_object_t* ssh_server = amxd_dm_findf(dm, "SSH.Server.");
    amxd_trans_t trans;

    amxc_string_init(&package, 0);
    amxd_trans_init(&trans);

    if(ssh_server == NULL) {
        goto exit;
    }

    amxc_string_setf(&package, "uci.packages.${rw_data_path}/dropbear.dropbear");
    amxc_string_resolve_var(&package, &parser->config);

    config = GETP_ARG(&parser->config, amxc_string_get(&package, 0));
    if((config == NULL) || (amxc_var_type_of(config) != AMXC_VAR_ID_LIST)) {
        goto exit;
    }

    amxd_trans_select_object(&trans, ssh_server);
    amxc_var_for_each(dropbear, config) {
        const amxc_htable_t* options = amxc_var_constcast(amxc_htable_t, dropbear);
        amxd_trans_add_inst(&trans, 0, NULL);
        ssh_server_uci_set_options(&trans, options);
        amxd_trans_select_object(&trans, ssh_server);
    }

    amxd_trans_apply(&trans, dm);

exit:
    amxd_trans_clean(&trans);
    amxc_string_clean(&package);
}

void ssh_server_uci_export(amxd_dm_t* dm, amxo_parser_t* parser) {
    amxc_string_t package;
    amxc_var_t* config = NULL;
    amxd_object_t* ssh_server = amxd_dm_findf(dm, "SSH.Server.");

    amxc_string_init(&package, 0);

    if(ssh_server == NULL) {
        goto exit;
    }

    amxc_string_setf(&package, "uci.packages.${rw_data_path}/dropbear.dropbear");
    amxc_string_resolve_var(&package, &parser->config);

    config = GETP_ARG(&parser->config, amxc_string_get(&package, 0));
    if(config == NULL) {
        goto exit;
    }

    amxc_var_set_type(config, AMXC_VAR_ID_LIST);
    amxd_object_for_all(ssh_server, ".*", ssh_server_uci_add_section, config);

exit:
    amxc_string_clean(&package);
}