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

#include "mod_pcb_cli.h"
#include "mod_pcb_cli_cmd.h"
#include "mod_pcb_cli_common.h"

#define MOD "cli"
#define MOD_DESC "Bus Agnostic cli."

typedef int (* mod_pcb_cli_cmd_t) (amxt_tty_t* tty,
                                   amxb_bus_ctx_t* bus_ctx,
                                   amxc_var_t* options,
                                   const char* path,
                                   amxc_var_t* cmd);

static const char* cmd_list_opts[] = {
    "r", "recursive",
    "n", "named",
    "p", "parameters",
    "f", "functions",
    NULL
};

static const char* cmd_dump_opts[] = {
    "r", "recursive",
    "n", "named",
    "p", "parameters",
    "f", "functions",
    "e", "events",
    NULL
};

static const char* cmd_gsdm_opts[] = {
    "l", "first_lvl_only",
    "p", "parameters",
    "f", "functions",
    "e", "events",
    NULL
};

static const char* cmd_gi_opts[] = {
    "l", "first_lvl_only",
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
        .cmd = "cd",
        .usage = "cd <PATH>",
        .brief = "Sets the default object path",
        .desc = "Sets the default object path.\n"
            "All other commands will work relativaly from this path.\n"
            "When starting the path with a dot '.', the path is an absolute path\n"
            "Use dot only to reset the default path to the root",
        .options = NULL
    },
    {
        .cmd = "list",
        .usage = "list [<OPTIONS>] [<PATH>] | ls <SEARCH PATH>",
        .brief = "List objects.",
        .desc = "List the object. Depending on the given options more information\n"
            "of the object is displayed\n"
            "When a search path is provided, the options are ignored and all "
            "matching object paths are displayed\n"
            "When no path is provided, the options are ignored and all root objects "
            "are displayed"
            "\n\n"
            "Available options:\n"
            "\t-r --recursive     List all objects recursive.\n"
            "\t-n --named         Use object names instead of indexes.\n"
            "\t-p --parameters    Include parameter names\n"
            "\t-f --functions     Include function names\n",
        .options = cmd_list_opts
    },
    {
        .cmd = "ls",
        .usage = "ls [<OPTIONS>] [<PATH>]",
        .brief = "List objects.",
        .desc = "List the object. Depending on the given options more information\n"
            "of the object is displayed\n"
            "When a search path is provided, the options are ignored and all "
            "matching object paths are displayed\n"
            "When no path is provided, the options are ignored and all root objects "
            "are displayed"
            "\n\n"
            "Available options:\n"
            "\t-r --recursive     List all objects recursive.\n"
            "\t-n --named         Use object names instead of indexes.\n"
            "\t-p --parameters    Include parameter names\n"
            "\t-f --functions     Include function names\n",
        .options = cmd_list_opts
    },
    {
        .cmd = "dump",
        .usage = "dump [<OPTIONS>] <PATH>",
        .brief = "Dump object details",
        .desc = "Dump object details. Depending on the given options more information\n"
            "of the object is displayed\n"
            "\n"
            "Available options:\n"
            "\t-r --recursive     Dump all objects recursivly.\n"
            "\t-n --named         Use object names instead of indexes.\n"
            "\t-p --parameters    Include parameters\n"
            "\t-f --functions     Include functions\n"
            "\t-e --events        Include events\n"
            "\n"
            "Attributes of objects, parameters and functions are printed in front"
            "of the item\n"
            "\t- P = persistent\n"
            "\t- R = read-only\n"
            "\t- M = mutable (in combination with key)\n"
            "\t- U = unique (in combination with key)\n"
            "\t- K = key\n"
            "\t- C = instance counter\n"
            "\t- V = volatile\n"
            "\t- A = asynchronous function\n"
            "Attributes of method arguments are printed in front of the argument\n"
            "\t- I = in argument\n"
            "\t- O = out argument\n"
            "\t- S = strict\n"
            "\t- M = madatory\n"
            "\n"
            "This command supports json output format. When recursive option is used\n"
            "a separate json is created for each object, separated with a new line.\n",
        .options = cmd_dump_opts
    },
    {
        .cmd = "resolve",
        .usage = "resolve <PATH>",
        .brief = "Expand a search path to all matching object paths",
        .desc = "Find all object paths that are matching a given search path\n"
            "This command supports json output format.\n",
        .options = NULL
    },
    {
        .cmd = "subscriptions",
        .usage = "subscriptions",
        .brief = "List all open event subscriptions",
        .desc = "List all open event subscriptions\n",
        .options = NULL
    },
    {
        .cmd = "requests",
        .usage = "requests",
        .brief = "List all pending RPC requests",
        .desc = "List all pending RPC requests\n",
        .options = NULL
    },
    {
        .cmd = "gsdm",
        .usage = "gsdm [<OPTIONS>] <PATH>",
        .brief = "Get supported data model",
        .desc = "Get supported data model\n"
            "\n"
            "Available options:\n"
            "\t-l --first_lvl_only First Level Only.\n"
            "\t-p --parameters     Include parameter names\n"
            "\t-f --functions      Include function names\n"
            "\t-e --events         Include event names\n"
            "\n"
            "The type of objects and the access of objects and parameters\n"
            " are printed in front of the item\n"
            "\t- M = Is a multi-instance object\n"
            "\t- A = A controller can add an instance\n"
            "\t- D = A controller can delete an instance\n"
            "\t- R = A controller can read the parameter value\n"
            "\t- W = A controller can write the parameter value\n"
            "\t- U = Unknown command type\n"
            "\t- S = Synchronous command\n"
            "\t- A = Asynchronous command\n"
            "\n"
            "This command supports json output format.\n",
        .options = cmd_gsdm_opts
    },
    {
        .cmd = "gi",
        .usage = "gi [<OPTIONS>] <PATH>",
        .brief = "Get instances",
        .desc = "Get instances\n"
            "\n"
            "Available options:\n"
            "\t-l --first_lvl_only First Level Only.\n"
            "\n"
            "This command supports json output format.\n",
        .options = cmd_gi_opts
    },
    {
        .cmd = "?",
        .usage = "<PATH>.[<PARAM>]? [<DEPTH>] [<PARAM-FILTER-EXPR>]|& [<EVENT-FILTER-EXPR>]|$]",
        .brief = "Get object parameters",
        .desc = "Get all object parameters.\n"
            "Gets all object parameters and prints the parameter paths"
            "including the values in a flat list.\n"
            "When a parameter filter expression is given, only parameters that matches are\n"
            "returned. Parameter filtering is done on the parameter meta-data.\n"
            "When '&' is added, a subscription is taken on the object tree\n"
            "and events will be printed in human readable form when received.\n"
            "When an event filter expression is given, only events that matches are\n"
            ""
            "Set variable 'raw-event' to true to print the events as is.\n"
            "When '$' is added, the subscription for that object tree is closed\n"
            "\n"
            "This command supports json output format.\n"
            "\n"
            "This commands has support for:\n"
            "  - Object paths.......: Device.IP.Interface.1.IPv4Address.1.\n"
            "  - Parameter paths....: Device.IP.Interface.1.IPv4Address.1.Enable\n"
            "  - Search paths.......: Device.IP.Interface.[Status=='Error'].\n"
            "  - Wildcard paths.....: Device.IP.Interface.*.IPv4Address.*.IPAddress\n"
            "  - Key addressing.....: Device.IP.Interface.[Alias=='lan'].\n"
            "  - Reference following: Device.IP.Interface.1.LowerLayers#1+.\n"
            "\n"
            "For more information about these different path types read \n"
            "section 2.5 Path Names of https://usp.technology/specification/index.html",
        .options = NULL
    },
    {
        .cmd = "=",
        .usage = "<PATH>.<PARAM>=<VALUE> | <PATH>.{<PARAM>=<VALUE>, ...}",
        .brief = "Changes the value of parameter(s)",
        .desc = "Changes the value of a single parameter or multiple parameters.\n"
            "Sets the value of a parameter\n"
            "The value must be valid for that parameter and the parameter "
            "must be writable\n",
        .options = NULL
    },
    {
        .cmd = "+",
        .usage = "<PATH>.+ [{<PARAM>=<VALUE>}, ...]",
        .brief = "Adds a new instance of a multi-instance object",
        .desc = "Adds a new instance of a multi-instance object.\n"
            "Parameters can be specified as a comma separated list of values\n"
            "\t{<PARAM>=<VALUE>, <PARAM>=<VALUE>}\n"
            "The target object must be a multi-instance object and the "
            "parameters must be writable\n"
            "\n"
            "This command supports json output format.\n",
        .options = NULL
    },
    {
        .cmd = "-",
        .usage = "<PATH>.-",
        .brief = "Deletes an instance of a multi-instance object",
        .desc = "Deletes an instance of a multi-instance object.\n"
            "The target object must be a multi-instance object or a search "
            "path to one or more multi-instance objects\n"
            "\n"
            "This command supports json output format.",
        .options = NULL
    },
    {
        .cmd = "()",
        .usage = "<PATH>.<METHOD>([<ARG1>=<VALUE>][,<ARG2>=<VALUE>]...)",
        .brief = "Calls a method on the specified object path",
        .desc = "Calls a method on the specified object path.\n"
            "Read the documentation of the method to see what the input arguments are "
            "and what the return value or output arguments can be.\n"
            "\n"
            "The order of the arguments is not important.\n"
            "\n"
            "This command supports json output format.",
        .options = NULL
    },
    { NULL, NULL, NULL, NULL, NULL },
};

static pcb_cli_cmd_flags_t baapi_cmds[] = {
    // help
    { .cmd_flags = 0, .value_flags = 0 },
    // cd
    { .cmd_flags = 0, .value_flags = 0 },
    // list
    { .cmd_flags = CMD_EMPTY_PATH | CMD_SEARCH_PATH, .value_flags = 0 },
    // ls
    { .cmd_flags = CMD_EMPTY_PATH | CMD_SEARCH_PATH, .value_flags = 0 },
    // dump
    { .cmd_flags = 0, .value_flags = 0 },
    // resolve
    { .cmd_flags = CMD_SEARCH_PATH, .value_flags = 0 },
    // subscriptions
    { .cmd_flags = 0, .value_flags = 0 },
    // requests
    { .cmd_flags = 0, .value_flags = 0 },
    // get supported data model
    { .cmd_flags = 0, .value_flags = 0 },
    // get instances
    { .cmd_flags = CMD_SEARCH_PATH, .value_flags = 0 },
};

pcb_cli_cmd_flags_t* mod_pcb_cli_get_cmd_flags(uint32_t index) {
    return &baapi_cmds[index];
}

amxt_cmd_help_t* mod_pcb_cli_get_help(uint32_t index) {
    return &help[index];
}

static int mod_pcb_cli_cmd(amxt_tty_t* tty, amxc_var_t* cmd) {
    int cmd_id = -1;
    char* p = NULL;

    amxt_cmd_triml(cmd, ' ');
    p = amxt_cmd_pop_part(cmd);
    if(p == NULL) {
        amxt_tty_errorf(tty, "Missing or invalid operator\n");
        goto exit;
    }
    switch(p[0]) {
    case '?':
        cmd_id = PCB_GET;
        break;
    case '=':
        cmd_id = PCB_SET_PRIMITIVE;
        break;
    case '{':
        amxt_cmd_prepend_part(cmd, "{");
        cmd_id = PCB_SET_TABLE;
        break;
    case '+':
        cmd_id = PCB_ADD;
        break;
    case '-':
        cmd_id = PCB_DEL;
        break;
    case '(':
        cmd_id = PCB_INVOKE;
        break;
    }

exit:
    free(p);
    return cmd_id;
}

static mod_pcb_cli_cmd_t pcb_cli_cmd[PCB_MAX] = {
    NULL,                      // help
    NULL,                      // cd
    NULL,                      // list
    NULL,                      // ls
    NULL,                      // dump
    NULL,                      // resolve
    NULL,                      // subscriptions
    NULL,                      // requests
    NULL,                      // get supported data model
    NULL,                      // get instances
    mod_pcb_cli_get,
    mod_pcb_cli_set_primitive, // primitive
    mod_pcb_cli_set_table,     // table
    mod_pcb_cli_add,
    mod_pcb_cli_del,
    mod_pcb_cli_call
};

static int mod_pcb_cli_execute(UNUSED const char* function_name,
                               amxc_var_t* args,
                               UNUSED amxc_var_t* ret) {
    amxt_tty_t* tty = GET_TTY(args);
    amxc_var_t* input = GET_ARG(args, "cmd");
    amxc_var_t cmd_opts;
    amxb_bus_ctx_t* bus_ctx = NULL;
    char* input_path = NULL;
    int cmd_id = -1;
    int rv = 0;

    amxc_var_init(&cmd_opts);

    input_path = mod_pcb_cli_build_path(input);
    cmd_id = mod_pcb_cli_cmd(tty, input);
    if(cmd_id == -1) {
        rv = -1;
        goto exit;
    }

    if((input_path == NULL) || (*input_path == 0)) {
        amxt_tty_errorf(tty, "No path specified\n");
        rv = -1;
        goto exit;
    }

    bus_ctx = mod_pcb_cli_get_bus_ctx(input_path);
    if(bus_ctx == NULL) {
        amxt_tty_errorf(tty, "%s not found.\n", input_path);
        rv = -1;
        goto exit;
    }

    rv = pcb_cli_cmd[cmd_id](tty, bus_ctx, &cmd_opts, input_path, input);

exit:
    free(input_path);
    amxc_var_clean(&cmd_opts);
    return rv;
}

static int mod_pcb_cli_cmd_cd(UNUSED const char* function_name,
                              amxc_var_t* args,
                              amxc_var_t* ret) {
    // cd .<PATH> start from root
    // cd . set root
    amxt_tty_t* tty = GET_TTY(args);
    char* input_path = NULL;
    amxb_bus_ctx_t* bus_ctx = NULL;
    int rv = -1;

    rv = mod_pcb_cli_cmd_parse(args, PCB_CD, &bus_ctx, &input_path, NULL, NULL);
    if((rv != 0) && ((input_path == NULL) || (*input_path == 0))) {
        amxc_var_t* path = amxt_tty_claim_config(tty, "path");
        amxc_var_set(cstring_t, path, "");
        rv = 0;
        goto exit;
    }

    rv = amxb_describe(bus_ctx, input_path, AMXB_FLAG_EXISTS, ret, 5);
    if(rv == 0) {
        amxc_var_t* path = amxt_tty_claim_config(tty, "path");
        amxc_var_set(cstring_t, path, input_path);
    } else {
        amxt_tty_errorf(tty, "%s not found\n", input_path);
    }

exit:
    amxc_var_clean(ret);
    free(input_path);
    return rv;
}

static int mod_pcb_cli_cmd_help(UNUSED const char* function_name,
                                amxc_var_t* args,
                                UNUSED amxc_var_t* ret) {
    amxt_tty_t* tty = GET_TTY(args);
    amxc_var_t* var_cmd = GET_ARG(args, "cmd");
    char* cmd = amxt_cmd_pop_word(var_cmd);

    amxt_cmd_print_help(tty, help, cmd);

    free(cmd);
    return 0;
}

static int mod_pcb_cli_complete(UNUSED const char* function_name,
                                amxc_var_t* args,
                                amxc_var_t* ret) {
    amxc_var_t* params = mod_pcb_cli_search(args, "{");
    amxc_var_t* fargs = mod_pcb_cli_search(args, "(");
    amxt_tty_t* tty = ba_cli_get_tty();

    if((params == NULL) && (fargs == NULL)) {
        mod_pcb_cli_cmd_complete(args,
                                 AMXB_FLAG_INSTANCES | AMXB_FLAG_OBJECTS |
                                 AMXB_FLAG_FUNCTIONS | AMXB_FLAG_PARAMETERS,
                                 NULL, ret);
    } else {
        if(params != NULL) {
            mod_pcb_cli_params_complete(args, ret);
        } else {
            mod_pcb_cli_args_complete(args, ret);
            amxp_sigmngr_emit_signal(tty->sigmngr, "tty:docomplete", ret);
            amxc_var_delete(&ret);
        }
    }

    return 0;
}

static int mod_pcb_cli_describe(UNUSED const char* function_name,
                                UNUSED amxc_var_t* args,
                                amxc_var_t* ret) {

    amxc_var_set(cstring_t, ret, MOD_DESC);
    return 0;
}

static int mod_pcb_cli_activate(UNUSED const char* function_name,
                                amxc_var_t* args,
                                UNUSED amxc_var_t* ret) {
    amxt_tty_t* tty = GET_TTY(args);
    amxt_tty_set_prompt(tty,
                        "\n${color.green}$(USER)${color.reset} - "
                        "${color.blue}${connection}${color.reset} - [${cli-name}] (${rv})\n"
                        "${path} > ${color.white}");
    return 0;
}

int PRIVATE mod_pcb_cli_start(amxm_shared_object_t* me) {
    amxm_module_t* mod = NULL;

    mod_pcb_cli_subscriptions_init();
    mod_pcb_cli_requests_init();

    amxm_module_register(&mod, me, MOD);

    // implementations
    amxm_module_add_function(mod, "__execute", mod_pcb_cli_execute);
    amxm_module_add_function(mod, "help", mod_pcb_cli_cmd_help);
    amxm_module_add_function(mod, "cd", mod_pcb_cli_cmd_cd);
    amxm_module_add_function(mod, "ls", mod_pcb_cli_cmd_list);
    amxm_module_add_function(mod, "list", mod_pcb_cli_cmd_list);
    amxm_module_add_function(mod, "dump", mod_pcb_cli_cmd_dump);
    amxm_module_add_function(mod, "resolve", mod_pcb_cli_cmd_resolve);
    amxm_module_add_function(mod, "subscriptions", mod_pcb_cli_cmd_subscriptions);
    amxm_module_add_function(mod, "requests", mod_pcb_cli_cmd_requests);
    amxm_module_add_function(mod, "gsdm", mod_pcb_cli_cmd_gsdm);
    amxm_module_add_function(mod, "gi", mod_pcb_cli_cmd_gi);

    // completion functions
    amxm_module_add_function(mod, "__complete", mod_pcb_cli_complete);
    amxm_module_add_function(mod, "__complete_cd", mod_pcb_cli_cmd_complete_common);
    amxm_module_add_function(mod, "__complete_ls", mod_pcb_cli_cmd_complete_common);
    amxm_module_add_function(mod, "__complete_list", mod_pcb_cli_cmd_complete_common);
    amxm_module_add_function(mod, "__complete_dump", mod_pcb_cli_cmd_complete_common);
    amxm_module_add_function(mod, "__complete_resolve", mod_pcb_cli_cmd_complete_common);
    amxm_module_add_function(mod, "__complete_gsdm", mod_pcb_cli_cmd_complete_common);
    amxm_module_add_function(mod, "__complete_gi", mod_pcb_cli_cmd_complete_common);

    // description
    amxm_module_add_function(mod, "__describe", mod_pcb_cli_describe);

    // called when module is selected as active
    amxm_module_add_function(mod, "__activate", mod_pcb_cli_activate);

    return 0;
}

int PRIVATE mod_pcb_cli_stop(UNUSED amxm_shared_object_t* me) {
    mod_pcb_cli_subscriptions_clean();
    mod_pcb_cli_requests_clean();
    return 0;
}
