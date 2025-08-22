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
#include <sys/stat.h>

#include <amxrt/amxrt.h>
#include <amxp/amxp_dir.h>
#include <amxp/amxp_connection.h>
#include <amxb/amxb_register.h>

#include "amxrt_priv.h"

static void amxrt_connection_read(UNUSED int fd, UNUSED void* priv) {
    amxb_bus_ctx_t* bus_ctx = (amxb_bus_ctx_t*) priv;
    int rv = 0;

    if(amxb_is_data_socket(bus_ctx)) {
        rv = amxb_read(bus_ctx);
    } else {
        amxb_bus_ctx_t* new_ctx = NULL;
        rv = amxb_accept(bus_ctx, &new_ctx);
        if(rv == 0) {
            fd = amxb_get_fd(new_ctx);
            amxp_connection_add(fd, amxrt_connection_read, NULL, AMXO_BUS, new_ctx);
        }
    }
    if(rv != 0) {
        amxc_llist_t* connections = amxp_connection_get_connections();
        amxp_connection_t* con = amxrt_el_get_connection(connections, fd);
        when_null(con, exit);
        amxrt_print_message("Failed to read from %s (%d), did the remote end hang up?",
                            con->uri == NULL ? "accepted" : con->uri, fd);
        amxrt_print_message("=> Removing %s (%d)",
                            con->uri == NULL ? "accepted" : con->uri, fd);
        amxp_connection_remove(fd);
        amxb_free(&bus_ctx);

        if(amxc_llist_is_empty(amxp_connection_get_connections()) &&
           amxc_llist_is_empty(amxp_connection_get_listeners())) {
            amxrt_print_error("No more connections available");
            amxrt_print_message("=> Stop application");
            amxrt_el_stop();
        }
    }

exit:
    return;
}

static int amxrt_connection_listen_bus_uri(const char* uri, amxb_bus_ctx_t** bus_ctx) {
    int retval = amxb_listen(bus_ctx, uri);
    if(retval != 0) {
        amxrt_print_error("(%d) Failed to listen on [%s]\n", retval, uri);
        retval = 3;
    }

    return retval;
}

static int amxrt_connection_connect_all_type(const amxc_llist_t* uris,
                                             uint32_t type) {
    int retval = 0;

    amxc_llist_for_each(it, uris) {
        amxb_bus_ctx_t* bus_ctx = NULL;
        int fd = -1;
        const char* uri = amxc_var_constcast(cstring_t,
                                             amxc_var_from_llist_it(it));

        retval = amxb_connect(&bus_ctx, uri);
        if(retval != 0) {
            amxrt_print_error("(%d) Failed to connect to [%s]\n", retval, uri);
        } else {
            fd = amxb_get_fd(bus_ctx);
            amxp_connection_add(fd, amxrt_connection_read, uri, type, bus_ctx);
        }
    }

    return retval;
}

static bool amxrt_list_contains(amxc_var_t* list, const char* value) {
    bool retval = false;
    amxc_var_for_each(v, list) {
        const char* stored = GET_CHAR(v, NULL);
        if(strcmp(stored, value) == 0) {
            retval = true;
            break;
        }
    }

    return retval;
}

static int amxrt_connection_add_usp_socket(const char* name, void* priv) {
    amxc_var_t* sockets = (amxc_var_t*) priv;
    amxc_string_t filename;
    amxc_string_init(&filename, 0);
    amxc_string_setf(&filename, "usp:%s", name);
    if(!amxrt_list_contains(sockets, amxc_string_get(&filename, 0))) {
        amxc_var_add(cstring_t, sockets, amxc_string_get(&filename, 0));
    }
    amxc_string_clean(&filename);

    return 0;
}

static void amxrt_connection_filter_uris(const amxc_llist_t* uris,
                                         const amxc_llist_t* exclude_uris) {
    int cresult = 0;
    amxc_var_t* euri_var = NULL;
    amxc_var_t* uri_var = NULL;

    amxc_llist_for_each(eit, exclude_uris) {
        euri_var = amxc_var_from_llist_it(eit);
        amxc_llist_for_each(it, uris) {
            uri_var = amxc_var_from_llist_it(it);
            if((amxc_var_compare(uri_var, euri_var, &cresult) == 0) && (cresult == 0)) {
                amxc_llist_it_take(it);
                variant_list_it_free(it);
            }
        }
    }
}

static void amxrt_add_known_uris(amxc_var_t* uris) {
    struct stat sb;

    // always check if not already added
    if(amxb_be_get_info("pcb") != NULL) {
        if(stat("/var/run/pcb_sys", &sb) == 0) {
            if(!amxrt_list_contains(uris, "pcb:/var/run/pcb_sys")) {
                amxc_var_add(cstring_t, uris, "pcb:/var/run/pcb_sys");
            }
        }
    }
    if(amxb_be_get_info("ubus") != NULL) {
        if((stat("/var/run/ubus.sock", &sb) == 0) || (stat("/var/run/ubus/ubus.sock", &sb) == 0)) {
            if(stat("/var/run/ubus.sock", &sb) == 0) {
                if(!amxrt_list_contains(uris, "ubus:/var/run/ubus.sock")) {
                    amxc_var_add(cstring_t, uris, "ubus:/var/run/ubus.sock");
                }
            } else {
                if(!amxrt_list_contains(uris, "ubus:/var/run/ubus/ubus.sock")) {
                    amxc_var_add(cstring_t, uris, "ubus:/var/run/ubus/ubus.sock");
                }
            }
        }
    }

    if(amxb_be_get_info("usp") != NULL) {
        amxp_dir_scan("/var/run/usp", "d_type == DT_SOCK", false, amxrt_connection_add_usp_socket, uris);
    }
}

static void amxrt_set_backend_setting(amxc_var_t* config,
                                      const char* backend,
                                      const char* setting,
                                      const char* value) {
    amxc_var_t* backend_settings = GET_ARG(config, backend);
    amxc_var_t* backend_config_opt = NULL;
    if(backend_settings == NULL) {
        backend_settings = amxc_var_add_key(amxc_htable_t, config, backend, NULL);
    }
    backend_config_opt = GET_ARG(backend_settings, setting);
    if(backend_config_opt == NULL) {
        amxc_var_add_key(cstring_t, backend_settings, setting, value);
    } else {
        amxc_var_set(cstring_t, backend_config_opt, value);
    }
}

static void amxrt_move_backend_uris(amxc_var_t* config, amxc_var_t* backend_settings) {
    amxc_var_t* uris = GET_ARG(config, AMXRT_COPT_URIS);
    amxc_var_t* data_uris = GET_ARG(config, AMXRT_COPT_DATA_URIS);
    amxc_var_t* be_uris = GET_ARG(backend_settings, AMXRT_COPT_URIS);
    amxc_var_t* be_data_uris = GET_ARG(backend_settings, AMXRT_COPT_DATA_URIS);

    amxc_var_for_each(uri, be_uris) {
        const char* u = GET_CHAR(uri, NULL);
        if(!amxrt_list_contains(data_uris, u) &&
           !amxrt_list_contains(uris, u)) {
            amxc_var_set_index(uris, 0, uri, AMXC_VAR_FLAG_DEFAULT);
        }
    }

    amxc_var_for_each(uri, be_data_uris) {
        const char* u = GET_CHAR(uri, NULL);
        if(!amxrt_list_contains(data_uris, u) &&
           !amxrt_list_contains(uris, u)) {
            amxc_var_set_index(data_uris, 0, uri, AMXC_VAR_FLAG_DEFAULT);
        }
    }

    amxc_var_delete(&be_uris);
    amxc_var_delete(&be_data_uris);
}

void amxrt_connection_detect_sockets(amxc_var_t* config) {
    amxc_var_t* uris = GET_ARG(config, AMXRT_COPT_URIS);
    bool auto_detect = GET_BOOL(config, AMXRT_COPT_AUTO_DETECT);
    amxc_array_t* backends = amxb_be_list();
    size_t size = amxc_array_size(backends);

    // when auto-detect is on use the socket uris that:
    // 1. are provided by the back-ends (these are the back-end default uris)
    // 2. are known to libamxrt
    // never add uris that are already defined in the config, make sure
    // no double entries are added.

    if(auto_detect) {
        // loop over all loaded backends and fetch uris and data-uris
        // check if they are not already added to top-level uris or data-uris
        // if not found in top level move them to top level otherwise delete them
        for(size_t i = 0; i < size; i++) {
            const char* be_name = (const char*) amxc_array_get_data_at(backends, i);
            amxc_var_t* backend_settings = GET_ARG(config, be_name);
            amxrt_move_backend_uris(config, backend_settings);
        }
        // last step - check known unix domain sockets - this for backwards compatibility
        amxrt_add_known_uris(uris);
    } else {
        for(size_t i = 0; i < size; i++) {
            const char* be_name = (const char*) amxc_array_get_data_at(backends, i);
            amxc_var_t* backend_settings = GET_ARG(config, be_name);
            amxc_var_t* be_uris = GET_ARG(backend_settings, AMXRT_COPT_URIS);
            amxc_var_t* be_data_uris = GET_ARG(backend_settings, AMXRT_COPT_DATA_URIS);
            amxc_var_delete(&be_uris);
            amxc_var_delete(&be_data_uris);
        }
    }

    amxc_array_delete(&backends, NULL);
}

int amxrt_connection_load_backends(amxc_var_t* config) {
    int retval = 0;
    const char* name = GET_CHAR(config, AMXRT_COPT_NAME);
    amxc_array_t* backend_names = NULL;
    size_t size = 0;
    amxc_var_t* backends = amxc_var_get_key(config, AMXRT_COPT_BACKENDS, AMXC_VAR_FLAG_COPY);

    if(amxc_var_type_of(backends) == AMXC_VAR_ID_LIST) {
        const amxc_llist_t* bel = amxc_var_constcast(amxc_llist_t, backends);
        if(amxc_llist_is_empty(bel)) {
            amxrt_print_error("No backends specified\n");
            retval = 2;
        }
    } else {
        char* str = amxc_var_dyncast(cstring_t, backends);
        if((str == NULL) || (str[0] == 0)) {
            amxrt_print_error("No backends specified\n");
            retval = 2;
        }
        free(str);
    }

    if(retval == 0) {
        retval = amxb_be_load_multiple(backends);
        if(retval != 0) {
            amxrt_print_error("Failed to load backends\n");
            retval = 2;
        }
    }

    /*
       Create backend config section if not existing
       For backwards compatibility set `register-name` if not existing
       Needed for pcb backend if loaded
     */
    backend_names = amxb_be_list();
    size = amxc_array_size(backend_names);
    for(size_t i = 0; i < size; i++) {
        const char* be_name = (const char*) amxc_array_get_data_at(backend_names, i);
        amxrt_set_backend_setting(config, be_name, "register-name", name);
    }
    amxc_array_delete(&backend_names, NULL);

    amxb_set_config(config);

    amxc_var_delete(&backends);
    return retval;
}

int amxrt_connection_connect_all(amxo_parser_t* parser) {
    int retval = 0;
    const amxc_llist_t* uris = amxc_var_constcast(amxc_llist_t, GET_ARG(&parser->config, AMXRT_COPT_URIS));
    const amxc_llist_t* data_uris = amxc_var_constcast(amxc_llist_t, GET_ARG(&parser->config, AMXRT_COPT_DATA_URIS));
    bool connect = amxc_var_constcast(bool, GET_ARG(&parser->config, AMXRT_COPT_AUTO_CONNECT));
    if(!connect) {
        goto leave;
    }

    amxrt_connection_filter_uris(uris, data_uris);
    retval = amxrt_connection_connect_all_type(uris, AMXP_CONNECTION_BUS);
    when_failed(retval, leave);
    amxrt_connection_connect_all_type(data_uris, AMXP_CONNECTION_CUSTOM);

leave:
    return retval;
}

int amxrt_connection_listen_all(amxo_parser_t* parser) {
    int retval = 0;
    const amxc_llist_t* listen = amxc_var_constcast(amxc_llist_t, GET_ARG(&parser->config, AMXRT_COPT_LISTEN));

    amxc_llist_for_each(it, listen) {
        amxb_bus_ctx_t* bus_ctx = NULL;
        int fd = -1;
        const char* uri = amxc_var_constcast(cstring_t,
                                             amxc_var_from_llist_it(it));

        retval = amxrt_connection_listen_bus_uri(uri, &bus_ctx);
        if(retval != 0) {
            amxrt_print_error("Failed to listen on %s", uri);
        } else {
            fd = amxb_get_fd(bus_ctx);
            amxp_connection_add(fd, amxrt_connection_read, uri, AMXP_CONNECTION_LISTEN, bus_ctx);
        }
    }

    return retval;
}

int amxrt_connection_register_dm(UNUSED amxo_parser_t* parser, amxd_dm_t* dm) {
    int retval = 0;
    amxc_llist_t* connections = amxp_connection_get_connections();
    amxc_llist_for_each(it, connections) {
        amxp_connection_t* con = amxc_llist_it_get_data(it, amxp_connection_t, it);
        amxb_bus_ctx_t* bus_ctx = (amxb_bus_ctx_t*) con->priv;
        if(con->type != AMXP_CONNECTION_BUS) {
            continue;
        }
        retval = amxb_register(bus_ctx, dm);
        if(retval != 0) {
            amxrt_print_error("Failed to register data model on %s", con->uri);
            goto leave;
        }
    }

    amxc_llist_for_each(it, amxp_connection_get_listeners()) {
        amxp_connection_t* con = amxc_llist_it_get_data(it, amxp_connection_t, it);
        amxb_bus_ctx_t* bus_ctx = (amxb_bus_ctx_t*) con->priv;
        retval = amxb_register(bus_ctx, dm);
        when_failed(retval, leave);
    }

leave:
    return retval;
}
