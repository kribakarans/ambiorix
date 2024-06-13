/****************************************************************************
**
** SPDX-License-Identifier: BSD-2-Clause-Patent
**
** SPDX-FileCopyrightText: Copyright (c) 2022 SoftAtHome
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

#include "dm_cli_priv.h"
#include "mod_dm_cli.h"

#define MOD "dm"
#define MOD_DESC "Data Model cli."

typedef enum _dm_cli_cmd {
    dm_cli_help,
    dm_cli_load,
    dm_cli_save,
    dm_cli_reset,
} dm_cli_cmd_t;

static const char* cmd_load_opts[] = {
    "e", "events",
    NULL
};

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
        .cmd = "load",
        .usage = "load [<OPTIONS>] <ODL FILE>",
        .brief = "Loads an odl file.",
        .desc = "Loads an odl file and registers the data model objects to"
            "all open bus connections. All import plugins and modules will be "
            "loaded as well. When loading is successfull the new data model"
            "objects can be used ans should be fully functional\n"
            "\n"
            "Available options\n"
            "\t-e  --events     Enable data model events during loading\n",
        .options = cmd_load_opts
    },
    {
        .cmd = "save",
        .usage = "save <ODL FILE> [<OBJECT PATH>]",
        .brief = "saves persistent data to an odl file.",
        .desc = "Saves persistent parameters to an odl file\n",
        .options = NULL
    },
    {
        .cmd = "reset",
        .usage = "reset",
        .brief = "Resets the data model.",
        .desc = "Resets the loaded data model by removing all objects. All"
            "loaaded plugins and modules are removed as well",
        .options = NULL
    },
    { NULL, NULL, NULL, NULL, NULL },
};

static void dm_cli_entry_point_free(amxc_llist_it_t* it) {
    amxo_entry_t* entry = amxc_llist_it_get_data(it, amxo_entry_t, it);
    free(entry);
}

static bool mod_dm_contains_entry_point(amxc_llist_t* eps, amxo_entry_point_t fn) {
    bool found = false;

    amxc_llist_for_each(it, eps) {
        amxo_entry_t* ep = amxc_container_of(it, amxo_entry_t, it);
        if(ep->entry_point == fn) {
            found = true;
            goto exit;
        }
    }

exit:
    return found;
}

static void mod_dm_clean_entry_points(amxo_parser_t* parser) {
    amxc_llist_t* entry_points = dm_cli_get_entry_points();

    amxc_llist_for_each(it, parser->entry_points) {
        amxo_entry_t* ep = amxc_container_of(it, amxo_entry_t, it);
        if(mod_dm_contains_entry_point(entry_points, ep->entry_point)) {
            amxc_llist_it_take(it);
            free(ep);
            continue;
        }
    }
}

static int mod_dm_call_entry_points(amxo_parser_t* parser,
                                    amxd_dm_t* dm) {
    int rv = 0;

    if(parser->post_includes != NULL) {
        rv = amxo_parser_invoke_entry_points(parser, dm, AMXO_START);
        if(rv != 0) {
            rv = amxo_parser_invoke_entry_points(parser, dm, AMXO_ODL_LOADED);
        }
    } else {
        rv = amxo_parser_invoke_entry_points(parser, dm, AMXO_START);
    }

    return rv;
}

static int mod_dm_collect_new_root_objects(amxc_llist_t* objects,
                                           amxo_parser_t* parser,
                                           const char* file) {
    int rv = 0;
    amxd_dm_t tmpdm;
    amxd_object_t* root = NULL;
    amxc_var_t* var_resolve = amxo_parser_claim_config(parser, "odl-resolve");

    amxd_dm_init(&tmpdm);
    root = amxd_dm_get_root(&tmpdm);

    amxc_var_set(bool, var_resolve, false);

    rv = amxo_parser_parse_file(parser, file, root);
    amxc_var_delete(&var_resolve);
    when_failed(rv, exit);

    amxd_object_for_each(child, it, root) {
        amxd_object_t* newobj = amxc_container_of(it, amxd_object_t, it);
        amxc_string_t* name = NULL;
        amxc_string_new(&name, 0);
        amxc_string_setf(name, "%s", amxd_object_get_name(newobj, 0));
        amxc_llist_append(objects, &name->it);
    }

exit:
    amxd_dm_clean(&tmpdm);
    return rv;
}

static void dm_cli_remove_objects(amxc_llist_t* objects,
                                  amxd_dm_t* dm) {
    amxc_llist_for_each(it, objects) {
        amxc_string_t* name = amxc_container_of(it, amxc_string_t, it);
        amxd_object_t* object = amxd_dm_findf(dm, "%s", amxc_string_get(name, 0));
        amxd_object_delete(&object);
        amxc_string_delete(&name);
    }
}

static int dm_cli_load_dm(amxt_tty_t* tty,
                          amxc_var_t* options,
                          amxo_parser_t* parser,
                          amxd_dm_t* dm,
                          const char* odl) {
    int rv = 0;
    amxc_llist_t new_objects;

    amxc_llist_init(&new_objects);

    rv = mod_dm_collect_new_root_objects(&new_objects, parser, odl);
    if(rv != 0) {
        amxt_tty_errorf(tty, "Failed to load %s (%d)\n", odl, rv);
        amxt_tty_errorf(tty, "%s\n", amxo_parser_get_message(parser));
        goto exit;
    }

    if(!GET_BOOL(options, "e") && !GET_BOOL(options, "events")) {
        amxp_sigmngr_enable(&dm->sigmngr, false);
    }

    rv = amxo_parser_parse_file(parser, odl, amxd_dm_get_root(dm));
    if(rv != 0) {
        amxt_tty_errorf(tty, "Failed to load %s (%d)\n", odl, rv);
        amxt_tty_errorf(tty, "%s\n", amxo_parser_get_message(parser));
        goto exit;
    }

    amxt_tty_messagef(tty, "%s loaded\n", odl);

    mod_dm_clean_entry_points(parser);
    rv = mod_dm_call_entry_points(parser, dm);
    if(rv != 0) {
        amxt_tty_errorf(tty, "Entry-points failed (%d)\n", rv);
        amxo_parser_invoke_entry_points(parser, dm, AMXO_STOP);
        amxc_llist_clean(parser->entry_points, dm_cli_entry_point_free);
        dm_cli_remove_objects(&new_objects, dm);
        goto exit;
    }
    dm_cli_move_entry_points(dm_cli_get_entry_points(), parser->entry_points);
    amxp_sigmngr_enable(&dm->sigmngr, true);

    amxc_llist_for_each(it, &new_objects) {
        amxc_string_t* name = amxc_container_of(it, amxc_string_t, it);
        amxd_object_t* object = amxd_dm_findf(dm, "%s", amxc_string_get(name, 0));
        amxd_object_emit_signal(object, "dm:root-added", NULL);
        amxc_string_delete(&name);
    }

exit:
    amxp_sigmngr_enable(&dm->sigmngr, true);
    amxc_llist_clean(&new_objects, amxc_string_list_it_free);
    return rv;
}

static void mod_dm_cli_trigger_events(amxd_object_t* const object,
                                      UNUSED int32_t depth,
                                      UNUSED void* priv) {
    switch(amxd_object_get_type(object)) {
    case amxd_object_singleton:
    case amxd_object_template: {
        amxd_object_t* parent = amxd_object_get_parent(object);
        if(amxd_object_get_type(parent) == amxd_object_root) {
            amxd_object_trigger_signal(object, "dm:root-removed", NULL);
        } else {
            amxd_object_trigger_signal(object, "dm:object-removed", NULL);
        }
    }
    break;
    case amxd_object_instance:
        amxd_object_trigger_del_inst(object);
        break;
    default:
        break;
    }
}

static int mod_dm_cli_cmd_help(UNUSED const char* function_name,
                               amxc_var_t* args,
                               UNUSED amxc_var_t* ret) {
    amxt_tty_t* tty = GET_TTY(args);
    amxc_var_t* var_cmd = GET_ARG(args, "cmd");
    char* cmd = amxt_cmd_pop_word(var_cmd);

    amxt_cmd_print_help(tty, help, cmd);

    free(cmd);
    return 0;
}

static int mod_dm_cli_cmd_load(UNUSED const char* function_name,
                               amxc_var_t* args,
                               UNUSED amxc_var_t* ret) {
    amxt_tty_t* tty = GET_TTY(args);
    amxc_var_t* options = NULL;
    amxc_var_t* var_cmd = GET_ARG(args, "cmd");
    char* odl = NULL;
    amxo_parser_t* parser = dm_cli_get_parser();
    amxd_dm_t* dm = dm_cli_get_dm();
    int rv = 0;

    amxc_var_new(&options);

    rv = amxt_cmd_parse_options(tty, var_cmd, options, help[dm_cli_load].options);
    when_failed(rv, exit);
    odl = amxt_cmd_pop_word(var_cmd);

    if(!amxt_cmd_is_empty(var_cmd)) {
        amxt_cmd_error_excess(tty, var_cmd, help[dm_cli_load].cmd);
        rv = -1;
        goto exit;
    }

    rv = dm_cli_load_dm(tty, options, parser, dm, odl);

exit:
    amxc_var_delete(&options);
    free(odl);
    return rv;
}

static int mod_dm_cli_cmd_save(UNUSED const char* function_name,
                               amxc_var_t* args,
                               UNUSED amxc_var_t* ret) {
    amxt_tty_t* tty = GET_TTY(args);
    amxc_var_t* var_cmd = GET_ARG(args, "cmd");
    char* odl = NULL;
    char* object_path = NULL;
    amxo_parser_t* parser = dm_cli_get_parser();
    amxd_dm_t* dm = dm_cli_get_dm();
    amxd_object_t* object = NULL;
    int rv = -1;

    odl = amxt_cmd_pop_word(var_cmd);
    if(odl == NULL) {
        amxt_tty_errorf(tty, "Missing odl file\n");
        goto exit;
    }

    object_path = amxt_cmd_pop_word(var_cmd);
    if((object_path == NULL) || (*object_path == 0)) {
        object = amxd_dm_get_root(dm);
    } else {
        object = amxd_dm_findf(dm, "%s", object_path);
        if(object == NULL) {
            amxt_tty_errorf(tty, "Object not found %s\n", object_path);
            goto exit;
        }
    }

    if(!amxt_cmd_is_empty(var_cmd)) {
        amxt_cmd_error_excess(tty, var_cmd, help[dm_cli_load].cmd);
        goto exit;
    }

    rv = amxo_parser_save_object(parser, odl, object, false);

exit:
    free(object_path);
    free(odl);
    return rv;
}

static int mod_dm_cli_cmd_reset(UNUSED const char* function_name,
                                amxc_var_t* args,
                                UNUSED amxc_var_t* ret) {
    int rv = 0;
    amxt_tty_t* tty = GET_TTY(args);
    amxo_parser_t* parser = dm_cli_get_parser();
    amxc_var_t* var_cmd = GET_ARG(args, "cmd");
    amxd_dm_t* dm = dm_cli_get_dm();
    amxd_object_t* root = amxd_dm_get_root(dm);

    if(!amxt_cmd_is_empty(var_cmd)) {
        amxt_cmd_error_excess(tty, var_cmd, help[dm_cli_load].cmd);
        rv = -1;
        goto exit;
    }

    dm_cli_move_entry_points(parser->entry_points, dm_cli_get_entry_points());
    amxo_parser_rinvoke_entry_points(parser, dm, AMXO_STOP);

    amxd_object_for_each(child, it, root) {
        amxd_object_t* object = amxc_container_of(it, amxd_object_t, it);
        amxd_object_hierarchy_walk(amxd_dm_get_root(dm),
                                   amxd_direction_down_reverse,
                                   NULL,
                                   mod_dm_cli_trigger_events,
                                   INT32_MAX,
                                   NULL);
        amxd_object_delete(&object);
    }

    amxd_dm_clean(dm);
    amxo_resolver_import_close_all();
    amxc_llist_clean(parser->entry_points, dm_cli_entry_point_free);
    amxc_llist_clean(dm_cli_get_entry_points(), dm_cli_entry_point_free);

    amxd_dm_init(dm);
    dm_cli_register_dm(dm);

exit:
    return rv;
}

static int mod_dm_cli_describe(UNUSED const char* function_name,
                               UNUSED amxc_var_t* args,
                               amxc_var_t* ret) {
    amxc_var_set(cstring_t, ret, MOD_DESC);
    return 0;
}

static int mod_dm_cli_complete_cmd_help(UNUSED const char* function_name,
                                        amxc_var_t* args,
                                        amxc_var_t* ret) {
    amxt_tty_t* tty = dm_cli_get_tty();

    amxt_cmd_complete_help(args, help, ret);
    amxp_sigmngr_emit_signal(tty->sigmngr, "tty:docomplete", ret);
    amxc_var_delete(&ret);

    return 0;
}

static int mod_dm_cli_complete_cmd_load(UNUSED const char* function_name,
                                        amxc_var_t* args,
                                        amxc_var_t* ret) {
    amxt_tty_t* tty = dm_cli_get_tty();
    if(amxt_cmd_complete_option(args, help[dm_cli_load].options, ret) == 0) {
        amxt_cmd_complete_path(function_name, args, ret);
    }
    amxp_sigmngr_emit_signal(tty->sigmngr, "tty:docomplete", ret);
    amxc_var_delete(&ret);
    return 0;
}

int PRIVATE mod_dm_cli_start(amxm_shared_object_t* me) {
    amxm_module_t* mod = NULL;

    amxm_module_register(&mod, me, MOD);

    // implementations
    amxm_module_add_function(mod, "help", mod_dm_cli_cmd_help);
    amxm_module_add_function(mod, "load", mod_dm_cli_cmd_load);
    amxm_module_add_function(mod, "save", mod_dm_cli_cmd_save);
    amxm_module_add_function(mod, "reset", mod_dm_cli_cmd_reset);

    // description
    amxm_module_add_function(mod, "__describe", mod_dm_cli_describe);

    // connection tab completion functions
    amxm_module_add_function(mod, "__complete_help", mod_dm_cli_complete_cmd_help);
    amxm_module_add_function(mod, "__complete_load", mod_dm_cli_complete_cmd_load);

    return 0;
}

int PRIVATE mod_dm_cli_stop(UNUSED amxm_shared_object_t* me) {
    return 0;
}
