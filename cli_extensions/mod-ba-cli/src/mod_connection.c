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
#include <stdio.h>

#include "ba_cli_priv.h"

#include "mod_connection.h"

#define MOD "connection"
#define MOD_DESC "Manage connections"

static amxt_cmd_help_t help[] = {
    {
        .cmd = "help",
        .usage = "help [<CMD>]",
        .brief = "Print this help",
        .desc = "Prints some help about the commands in this module.\n"
            "For more information about the supported commands use 'help <CMD>'",
        .options = NULL
    },
    {
        .cmd = "open",
        .usage = "open <URI> [<interface>] ",
        .brief = "Connects to the specified uri.",
        .desc = "",
        .options = NULL
    },
    {
        .cmd = "listen",
        .usage = "listen <URI>  ",
        .brief = "Creates a listen socket.",
        .desc = "",
        .options = NULL
    },
    {
        .cmd = "close",
        .usage = "close <URI> ",
        .brief = "Closes a connection.",
        .desc = "",
        .options = NULL
    },
    {
        .cmd = "list",
        .usage = "list        ",
        .brief = "List all open connections.",
        .desc = "",
        .options = NULL
    },
    {
        .cmd = "select",
        .usage = "select <URI>",
        .brief = "Select a connection.",
        .desc = "",
        .options = NULL
    },
    {
        .cmd = "who_has",
        .usage = "who_has <OBJECT>",
        .brief = "Search connection that provides an object.",
        .desc = "",
        .options = NULL
    },
    {
        .cmd = "access",
        .usage = "access <URI> <protected|public>",
        .brief = "Sets access method for connection.",
        .desc = "",
        .options = NULL
    },
    {
        .cmd = "autoconnect",
        .usage = "autoconnect",
        .brief = "Autodetect sockets and connect to them.",
        .desc = "",
        .options = NULL
    },
    { NULL, NULL, NULL, NULL, NULL },
};

static void mod_connection_read(UNUSED int fd, void* priv) {
    amxb_bus_ctx_t* bus_ctx = (amxb_bus_ctx_t*) priv;
    int rv = 0;

    if(amxb_is_data_socket(bus_ctx)) {
        rv = amxb_read(bus_ctx);
    } else {
        amxb_bus_ctx_t* new_ctx = NULL;
        rv = amxb_accept(bus_ctx, &new_ctx);
        if(rv == 0) {
            fd = amxb_get_fd(new_ctx);
            amxp_connection_add(fd, mod_connection_read, NULL, AMXP_CONNECTION_BUS, new_ctx);
        }
    }
    if(rv != 0) {
        amxp_connection_remove(fd);
        amxb_free(&bus_ctx);
    }
}

static int mod_connection_cmd_help(UNUSED const char* function_name,
                                   amxc_var_t* args,
                                   UNUSED amxc_var_t* ret) {
    amxt_tty_t* tty = GET_TTY(args);
    amxc_var_t* var_cmd = GET_ARG(args, "cmd");
    char* cmd = amxt_cmd_pop_word(var_cmd);

    amxt_cmd_print_help(tty, help, cmd);

    free(cmd);
    return 0;
}

static int mod_connection_cmd_open(UNUSED const char* function_name,
                                   amxc_var_t* args,
                                   UNUSED amxc_var_t* ret) {
    amxt_tty_t* tty = GET_TTY(args);
    amxc_var_t* var_cmd = GET_ARG(args, "cmd");
    char* uri = amxt_cmd_pop_word(var_cmd);
    char* intf = amxt_cmd_pop_word(var_cmd);
    amxb_bus_ctx_t* bus_ctx = NULL;
    int rv = 0;
    amxc_var_t* connection = amxt_tty_claim_config(tty, "connection");
    const char* con_name = amxc_var_constcast(cstring_t, connection);

    if(!amxt_cmd_is_empty(var_cmd)) {
        amxt_cmd_error_excess(tty, var_cmd, help[1].cmd);
        rv = -1;
        goto exit;
    }

    bus_ctx = amxb_find_uri(uri);
    if(bus_ctx != NULL) {
        amxt_tty_errorf(tty, "Already connected to %s\n", uri);
        rv = -1;
        goto exit;
    }

    rv = amxb_connect_intf(&bus_ctx, uri, intf);
    if(rv != 0) {
        amxt_tty_errorf(tty, "Connection failed %s (%d)\n", uri, rv);
    } else {
        amxt_tty_messagef(tty, "%s connected\n", uri);
        amxb_set_access(bus_ctx, AMXB_PUBLIC);
        amxp_connection_add(amxb_get_fd(bus_ctx),
                            mod_connection_read, uri, AMXP_CONNECTION_BUS, bus_ctx);
        if(con_name == NULL) {
            amxc_var_set(cstring_t, connection, uri);
        }
    }

exit:
    free(intf);
    free(uri);
    return rv;
}

static int mod_connection_cmd_listen(UNUSED const char* function_name,
                                     amxc_var_t* args,
                                     UNUSED amxc_var_t* ret) {
    amxt_tty_t* tty = GET_TTY(args);
    amxc_var_t* var_cmd = GET_ARG(args, "cmd");
    char* uri = amxt_cmd_pop_word(var_cmd);
    amxb_bus_ctx_t* bus_ctx = NULL;
    int rv = 0;

    if(!amxt_cmd_is_empty(var_cmd)) {
        amxt_cmd_error_excess(tty, var_cmd, help[2].cmd);
        rv = -1;
        goto exit;
    }

    bus_ctx = amxb_find_uri(uri);
    if(bus_ctx != NULL) {
        amxt_tty_errorf(tty, "Already listening on %s\n", uri);
        rv = -1;
        goto exit;
    }

    rv = amxb_listen(&bus_ctx, uri);
    if(rv != 0) {
        amxt_tty_errorf(tty, "Listen failed %s (%d)\n", uri, rv);
    } else {
        amxt_tty_messagef(tty, "%s listening\n", uri);
        amxb_set_access(bus_ctx, AMXB_PUBLIC);
        amxp_connection_add(amxb_get_fd(bus_ctx),
                            mod_connection_read, uri, AMXP_CONNECTION_LISTEN, bus_ctx);
    }

exit:
    free(uri);
    return rv;
}

static int mod_connection_cmd_close(UNUSED const char* function_name,
                                    amxc_var_t* args,
                                    UNUSED amxc_var_t* ret) {
    amxt_tty_t* tty = GET_TTY(args);
    amxc_var_t* var_cmd = GET_ARG(args, "cmd");
    amxb_bus_ctx_t* bus_ctx = NULL;
    char* uri = amxt_cmd_pop_word(var_cmd);
    int rv = 0;

    if(!amxt_cmd_is_empty(var_cmd)) {
        amxt_cmd_error_excess(tty, var_cmd, help[3].cmd);
        rv = -1;
        goto exit;
    }

    bus_ctx = amxb_find_uri(uri);
    if(bus_ctx == NULL) {
        amxt_tty_errorf(tty, "No connnection found for %s\n", uri);
        rv = -1;
        goto exit;
    }
    amxp_connection_remove(amxb_get_fd(bus_ctx));
    rv = amxb_disconnect(bus_ctx);
    if(rv != 0) {
        amxt_tty_errorf(tty, "Disconnecting failed %s (%d)\n", uri, rv);
        amxp_connection_add(amxb_get_fd(bus_ctx),
                            mod_connection_read, uri, AMXP_CONNECTION_BUS, bus_ctx);
    } else {
        amxt_tty_messagef(tty, "%s disconnected\n", uri);
        amxb_free(&bus_ctx);
    }


exit:
    free(uri);
    return rv;
}

static int mod_connection_cmd_list(UNUSED const char* function_name,
                                   amxc_var_t* args,
                                   UNUSED amxc_var_t* ret) {
    amxt_tty_t* tty = GET_TTY(args);
    amxc_array_t* uris = amxb_list_uris();
    size_t count = amxc_array_size(uris);
    amxc_var_t* var_cmd = GET_ARG(args, "cmd");
    int rv = 0;

    if(!amxt_cmd_is_empty(var_cmd)) {
        amxt_cmd_error_excess(tty, var_cmd, help[4].cmd);
        rv = -1;
        goto exit;
    }

    if(count == 0) {
        amxt_tty_writef(tty, "No open connections available\n");
        rv = -1;
        goto exit;
    }

    amxt_tty_writef(tty, "\n");
    for(size_t i = 0; i < count; i++) {
        const char* uri = (const char*) amxc_array_get_data_at(uris, i);
        amxt_tty_writef(tty, "%s\n", uri);
    }

exit:
    amxc_array_delete(&uris, NULL);
    return rv;
}

static int mod_connection_cmd_select(UNUSED const char* function_name,
                                     amxc_var_t* args,
                                     UNUSED amxc_var_t* ret) {
    amxt_tty_t* tty = GET_TTY(args);
    amxc_var_t* var_cmd = GET_ARG(args, "cmd");
    amxb_bus_ctx_t* bus_ctx = NULL;
    char* uri = amxt_cmd_pop_word(var_cmd);
    amxc_var_t* connection = amxt_tty_claim_config(tty, "connection");
    int rv = 0;

    if(!amxt_cmd_is_empty(var_cmd)) {
        amxt_cmd_error_excess(tty, var_cmd, help[5].cmd);
        rv = -1;
        goto exit;
    }

    if(strcmp(uri, "*") != 0) {
        bus_ctx = amxb_find_uri(uri);
        if(bus_ctx == NULL) {
            amxt_tty_errorf(tty, "Connection %s not found\n", uri);
            rv = -1;
            goto exit;
        }
    }

    amxc_var_set(cstring_t, connection, uri);

exit:
    free(uri);
    return rv;
}

static int mod_connection_cmd_who_has(UNUSED const char* function_name,
                                      amxc_var_t* args,
                                      UNUSED amxc_var_t* ret) {
    amxt_tty_t* tty = GET_TTY(args);
    amxc_var_t* var_cmd = GET_ARG(args, "cmd");
    amxb_bus_ctx_t* bus_ctx = NULL;
    char* path = amxt_cmd_pop_word(var_cmd);
    int rv = 0;

    if(!amxt_cmd_is_empty(var_cmd)) {
        amxt_cmd_error_excess(tty, var_cmd, help[6].cmd);
        rv = -1;
        goto exit;
    }

    bus_ctx = amxb_be_who_has(path);
    if(bus_ctx == NULL) {
        amxt_tty_errorf(tty, "No connection found that provides [%s]\n", path);
    } else {
        const char* uri = amxc_htable_it_get_key(&bus_ctx->hit);
        amxt_tty_messagef(tty, "[%s] is provided by %s\n", path, uri);
    }

exit:
    free(path);
    return rv;
}

static int mod_connection_cmd_access(UNUSED const char* function_name,
                                     amxc_var_t* args,
                                     UNUSED amxc_var_t* ret) {
    amxt_tty_t* tty = GET_TTY(args);
    amxc_var_t* var_cmd = GET_ARG(args, "cmd");
    amxb_bus_ctx_t* bus_ctx = NULL;
    char* uri = amxt_cmd_pop_word(var_cmd);
    char* access = amxt_cmd_pop_word(var_cmd);
    uint32_t access_method = AMXB_PUBLIC;
    int rv = 0;

    if(!amxt_cmd_is_empty(var_cmd)) {
        amxt_cmd_error_excess(tty, var_cmd, help[7].cmd);
        rv = -1;
        goto exit;
    }

    bus_ctx = amxb_find_uri(uri);
    if(bus_ctx == NULL) {
        amxt_tty_errorf(tty, "Connection %s not found\n", uri);
        rv = -1;
        goto exit;
    }

    if((access == NULL) || (*access == 0)) {
        amxt_tty_errorf(tty, "Missing access method for %s\n", uri);
        rv = -1;
        goto exit;
    }

    if(strcmp(access, "public") == 0) {
        access_method = AMXB_PUBLIC;
    } else if(strcmp(access, "protected") == 0) {
        access_method = AMXB_PROTECTED;
    } else {
        amxt_tty_errorf(tty, "Invalid access method %s, expected 'public' or 'protected'\n", access);
        rv = -1;
        goto exit;
    }

    amxb_set_access(bus_ctx, access_method);

exit:
    free(uri);
    free(access);
    return rv;
}

static void mod_connection_connect(amxc_var_t* uris, amxt_tty_t* tty) {
    amxb_bus_ctx_t* bus_ctx = NULL;
    int rv = 0;

    amxc_var_for_each(uri, uris) {
        bus_ctx = amxb_find_uri(GET_CHAR(uri, NULL));
        if(bus_ctx != NULL) {
            continue;
        }
        rv = amxb_connect(&bus_ctx, GET_CHAR(uri, NULL));
        if(rv != 0) {
            amxt_tty_errorf(tty, "Connection failed %s (%d)\n", uri, rv);
            continue;
        }
        amxb_set_access(bus_ctx, AMXB_PUBLIC);
        amxp_connection_add(amxb_get_fd(bus_ctx),
                            mod_connection_read, GET_CHAR(uri, NULL), AMXP_CONNECTION_BUS, bus_ctx);

    }
}

static int mod_connection_cmd_auto_connect(UNUSED const char* function_name,
                                           amxc_var_t* args,
                                           UNUSED amxc_var_t* ret) {
    amxt_tty_t* tty = GET_TTY(args);
    amxc_var_t* var_cmd = GET_ARG(args, "cmd");
    amxc_array_t* names = amxb_be_list();
    size_t count = amxc_array_size(names);
    int rv = 0;

    if(!amxt_cmd_is_empty(var_cmd)) {
        amxt_cmd_error_excess(tty, var_cmd, help[8].cmd);
        rv = -1;
        goto exit;
    }

    amxb_set_config(&tty->config);
    for(size_t i = 0; i < count; i++) {
        const char* name = (const char*) amxc_array_get_data_at(names, i);
        amxc_var_t* be_config = amxc_var_get_key(&tty->config, name, AMXC_VAR_FLAG_DEFAULT);

        amxc_var_t* uris = amxc_var_get_key(be_config, "uris", AMXC_VAR_FLAG_DEFAULT);
        mod_connection_connect(uris, tty);
        amxc_var_delete(&uris);

        uris = amxc_var_get_key(be_config, "data-uris", AMXC_VAR_FLAG_DEFAULT);
        mod_connection_connect(uris, tty);
        amxc_var_delete(&uris);
    }

exit:
    amxc_array_delete(&names, NULL);
    return rv;
}

static int mod_connection_describe(UNUSED const char* function_name,
                                   UNUSED amxc_var_t* args,
                                   amxc_var_t* ret) {
    amxc_var_set(cstring_t, ret, MOD_DESC);
    return 0;
}

static int mod_connection_complete_cmd_help(UNUSED const char* function_name,
                                            amxc_var_t* args,
                                            amxc_var_t* ret) {
    amxt_tty_t* tty = ba_cli_get_tty();

    amxt_cmd_complete_help(args, help, ret);
    amxp_sigmngr_emit_signal(tty->sigmngr, "tty:docomplete", ret);
    amxc_var_delete(&ret);

    return 0;
}

static int mod_connection_complete_cmd_open(UNUSED const char* function_name,
                                            amxc_var_t* args,
                                            amxc_var_t* ret) {
    amxt_tty_t* tty = ba_cli_get_tty();
    int words = amxt_cmd_count_words(args);
    amxc_array_t* names = amxb_be_list();
    size_t count = amxc_array_size(names);
    char* arg = amxt_cmd_pop_word(args);
    size_t len_arg = arg == NULL ? 0 : strlen(arg);
    amxc_string_t completion;

    amxc_string_init(&completion, len_arg + 1);

    if(words <= 1) {
        for(size_t i = 0; i < count; i++) {
            const char* name = (const char*) amxc_array_get_data_at(names, i);
            size_t len_name = strlen(name) + 1;
            if(len_name >= len_arg) {
                if((len_arg == 0) || (strncmp(name, arg, len_arg) == 0)) {
                    amxc_string_setf(&completion, "%s:", name);
                    amxc_var_add(cstring_t, ret, amxc_string_get(&completion, 0));
                }
            } else {
                // TODO: when no or one slash - use file system
            }
        }
    }

    amxp_sigmngr_emit_signal(tty->sigmngr, "tty:docomplete", ret);
    amxc_var_delete(&ret);
    amxc_string_clean(&completion);
    amxc_array_delete(&names, NULL);
    free(arg);
    return 0;
}

static int mod_connection_complete_cmd_close(UNUSED const char* function_name,
                                             amxc_var_t* args,
                                             amxc_var_t* ret) {
    amxt_tty_t* tty = ba_cli_get_tty();
    int words = amxt_cmd_count_words(args);
    amxc_array_t* uris = amxb_list_uris();
    size_t count = amxc_array_size(uris);
    char* arg = amxt_cmd_pop_word(args);
    size_t len_arg = arg == NULL ? 0 : strlen(arg);

    if(words <= 1) {
        for(size_t i = 0; i < count; i++) {
            const char* uri = (const char*) amxc_array_get_data_at(uris, i);
            if((len_arg == 0) || (strncmp(uri, arg, len_arg) == 0)) {
                amxc_var_add(cstring_t, ret, uri);
            }
        }
    }

    amxp_sigmngr_emit_signal(tty->sigmngr, "tty:docomplete", ret);
    amxc_var_delete(&ret);
    amxc_array_delete(&uris, NULL);
    free(arg);
    return 0;
}

int PRIVATE mod_connection_start(amxm_shared_object_t* me) {
    amxm_module_t* mod = NULL;

    // connection commands
    amxm_module_register(&mod, me, MOD);
    amxm_module_add_function(mod, "help", mod_connection_cmd_help);
    amxm_module_add_function(mod, "open", mod_connection_cmd_open);
    amxm_module_add_function(mod, "listen", mod_connection_cmd_listen);
    amxm_module_add_function(mod, "close", mod_connection_cmd_close);
    amxm_module_add_function(mod, "list", mod_connection_cmd_list);
    amxm_module_add_function(mod, "select", mod_connection_cmd_select);
    amxm_module_add_function(mod, "who_has", mod_connection_cmd_who_has);
    amxm_module_add_function(mod, "access", mod_connection_cmd_access);
    amxm_module_add_function(mod, "autoconnect", mod_connection_cmd_auto_connect);

    // connection describe
    amxm_module_add_function(mod, "__describe", mod_connection_describe);

    // connection tab completion functions
    amxm_module_add_function(mod, "__complete_help", mod_connection_complete_cmd_help);
    amxm_module_add_function(mod, "__complete_open", mod_connection_complete_cmd_open);
    amxm_module_add_function(mod, "__complete_close", mod_connection_complete_cmd_close);
    amxm_module_add_function(mod, "__complete_select", mod_connection_complete_cmd_close);

    return 0;
}

int PRIVATE mod_connection_stop(UNUSED amxm_shared_object_t* me) {
    amxc_llist_for_each(it, amxp_connection_get_connections()) {
        amxp_connection_t* con = amxc_llist_it_get_data(it, amxp_connection_t, it);
        amxb_bus_ctx_t* bus_ctx = NULL;

        if((con->type != AMXP_CONNECTION_BUS) && (con->type != AMXP_CONNECTION_LISTEN)) {
            continue;
        }

        bus_ctx = (amxb_bus_ctx_t*) con->priv;
        amxp_connection_remove(amxb_get_fd(bus_ctx));
    }

    amxc_llist_for_each(it, amxp_connection_get_listeners()) {
        amxp_connection_t* con = amxc_llist_it_get_data(it, amxp_connection_t, it);
        amxb_bus_ctx_t* bus_ctx = NULL;

        if((con->type != AMXP_CONNECTION_BUS) && (con->type != AMXP_CONNECTION_LISTEN)) {
            continue;
        }

        bus_ctx = (amxb_bus_ctx_t*) con->priv;
        amxp_connection_remove(amxb_get_fd(bus_ctx));
    }

    return 0;
}