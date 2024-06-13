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

#include <yajl/yajl_gen.h>
#include <amxrt/amxrt.h>
#include <amxj/amxj_variant.h>

#include "amxrt_priv.h"

static void amxrt_cmd_line_free_option(amxc_llist_it_t* it) {
    amxrt_arg_t* option = amxc_container_of(it, amxrt_arg_t, it);
    free(option);
}

static int amxrt_cmd_line_default(amxc_var_t* config,
                                  int arg_id,
                                  const char* value) {
    int rv = 0;
    switch(arg_id) {
    case 'I':
        amxc_var_add(cstring_t, GET_ARG(config, AMXRT_COPT_INCDIRS), value);
        break;

    case 'L':
        amxc_var_add(cstring_t, GET_ARG(config, AMXRT_COPT_LIBDIRS), value);
        break;

    case 'B':
        amxc_var_add(cstring_t, GET_ARG(config, AMXRT_COPT_BACKENDS), value);
        break;

    case 'u':
        amxc_var_add(cstring_t, GET_ARG(config, AMXRT_COPT_URIS), value);
        break;

    case 'A':
        amxc_var_set(bool, GET_ARG(config, AMXRT_COPT_AUTO_DETECT), false);
        break;

    case 'C':
        amxc_var_set(bool, GET_ARG(config, AMXRT_COPT_AUTO_CONNECT), false);
        break;

    case 'D':
        amxc_var_set(bool, GET_ARG(config, AMXRT_COPT_DAEMON), true);
        break;

    case 'E':
        amxc_var_set(bool, GET_ARG(config, AMXRT_COPT_EVENT), true);
        break;

    case 'd':
        if((value == NULL) || (strcmp(value, "config") == 0)) {
            amxc_var_set(bool, GET_ARG(config, AMXRT_COPT_DUMP_CONFIG), true);
        } else if(strcmp(value, "caps") == 0) {
            amxc_var_set(bool, GET_ARG(config, AMXRT_COPT_DUMP_CAPS), true);
        }
        break;

    case 'p':
        amxc_var_set(int32_t, GET_ARG(config, AMXRT_COPT_PRIORITY), atoi(value));
        break;

    case 'N':
        amxc_var_set(bool, GET_ARG(config, AMXRT_COPT_PID_FILE), false);
        break;

    case 'O':
        amxc_var_add_key(cstring_t, config, AMXRT_COPT_ODL, value);
        break;

    case 'l':
        amxc_var_set(bool, GET_ARG(config, AMXRT_COPT_LOG), true);
        break;

    case 'R':
        amxc_var_add(cstring_t, GET_ARG(config, AMXRT_COPT_REQUIRES), value);
        break;

    case 'o':
        amxrt_cmd_line_parse_assignment(value, false);
        break;

    case 'F':
        amxrt_cmd_line_parse_assignment(value, true);
        break;


    case 'h': {
        amxrt_print_usage();
        amxc_var_set(bool, GET_ARG(config, AMXRT_COPT_DUMP_CONFIG), false);
        amxc_var_set(bool, GET_ARG(config, AMXRT_COPT_DUMP_CAPS), false);
        rv = -1;
    }
    break;

    case 'H': {
        amxrt_print_help();
        amxc_var_set(bool, GET_ARG(config, AMXRT_COPT_DUMP_CONFIG), false);
        amxc_var_set(bool, GET_ARG(config, AMXRT_COPT_DUMP_CAPS), false);
        rv = -1;
    }
    break;

    default: {
        amxrt_print_error("Argument not recognized - %d", arg_id);
        amxrt_print_usage();
        amxc_var_set(bool, GET_ARG(config, AMXRT_COPT_DUMP_CONFIG), false);
        amxc_var_set(bool, GET_ARG(config, AMXRT_COPT_DUMP_CAPS), false);
        rv = -1;
    }
    break;

    }

    return rv;
}

// private - called from constructor
void amxrt_cmd_line_add_default_options(void) {
    amxrt_cmd_line_add_option(0, 'h', "help", no_argument, "Print usage help and exit", NULL);
    amxrt_cmd_line_add_option(0, 'H', "HELP", no_argument, "Print extended help and exit", NULL);
    amxrt_cmd_line_add_option(0, 'B', "backend", required_argument, "Loads the shared object as bus backend", "so file");
    amxrt_cmd_line_add_option(0, 'u', "uri", required_argument, "Adds an uri to the list of uris", "uri");
    amxrt_cmd_line_add_option(0, 'A', "no-auto-detect", no_argument, "Do not auto detect unix domain sockets and back-ends", NULL);
    amxrt_cmd_line_add_option(0, 'C', "no-connect", no_argument, "Do not auto connect the provided or detected uris", NULL);
    amxrt_cmd_line_add_option(0, 'I', "include-dir", required_argument, "Adds include directory for odl parser, multiple allowed", "dir");
    amxrt_cmd_line_add_option(0, 'L', "import-dir", required_argument, "Adds import directory for odl parser, multiple allowed", "dir");
    amxrt_cmd_line_add_option(0, 'o', "option", required_argument, "Adds a configuration option", "name=value");
    amxrt_cmd_line_add_option(0, 'F', "forced-option", required_argument, "Adds a configuration option, which can not be overwritten by odl files", "name=value");
    amxrt_cmd_line_add_option(0, 'O', "ODL", required_argument, "An ODL in string format, only one ODL string allowed", "odl-string");
    amxrt_cmd_line_add_option(0, 'D', "daemon", no_argument, "Daemonize the process", NULL);
    amxrt_cmd_line_add_option(0, 'p', "priority", required_argument, "Sets the process nice level", "nice level");
    amxrt_cmd_line_add_option(0, 'N', "no-pid-file", no_argument, "Disables the creation of a pid-file in /var/run", NULL);
    amxrt_cmd_line_add_option(0, 'E', "eventing", no_argument, "Enables eventing during loading of ODL files", NULL);
    amxrt_cmd_line_add_option(0, 'd', "dump", optional_argument, "Dumps configuration options or capabilities at start-up", "[caps|config]");
    amxrt_cmd_line_add_option(0, 'l', "log", no_argument, "Write to syslog instead of stdout and stderr", NULL);
    amxrt_cmd_line_add_option(0, 'R', "requires", required_argument, "Checks if datamodel objects are available or waits until they are available", "root object");
}

// remove all defined command line options
void amxrt_cmd_line_options_reset(void) {
    amxrt_t* rt = amxrt_get();
    amxc_llist_clean(&rt->cmd_line_args, amxrt_cmd_line_free_option);
}

// add a command line option definition
int amxrt_cmd_line_add_option(int id, char short_option, const char* long_option, int has_args, const char* doc, const char* arg_doc) {
    int rv = -1;
    amxrt_t* rt = amxrt_get();
    amxrt_arg_t* option = NULL;

    option = (amxrt_arg_t*) calloc(1, sizeof(amxrt_arg_t));
    when_null(option, exit);

    option->id = id == 0 ? (int) short_option : id;
    option->short_option = short_option;
    option->long_option = long_option;
    option->has_args = has_args;
    option->doc = doc;
    option->arg_doc = arg_doc;

    rv = amxc_llist_append(&rt->cmd_line_args, &option->it);

exit:
    if(rv != 0) {
        free(option);
    }
    return rv;
}

void amxrt_cmd_line_set_usage_doc(const char* usage) {
    amxrt_t* rt = amxrt_get();
    rt->usage_doc = usage == NULL ? "[OPTIONS] <odl files>" : usage;
}

// parse the command line arguments
int amxrt_cmd_line_parse(int argc, char* argv[], amxrt_arg_fn_t fn) {
    amxrt_t* rt = amxrt_get();
    amxc_var_t* config = amxrt_get_config();
    int nr_options = amxc_llist_size(&rt->cmd_line_args);
    struct option* long_options = (struct option*) calloc(nr_options + 1, sizeof(struct option));
    amxc_string_t format;
    int index = 0;
    int rv = 0;
    int c;

    if(long_options == NULL) {
        // handle error case where calloc failed
        return -1;
    }

    optind = 1;
    amxc_string_init(&format, 0);
    amxc_llist_for_each(it, &rt->cmd_line_args) {
        amxrt_arg_t* option = amxc_container_of(it, amxrt_arg_t, it);
        long_options[index].name = option->long_option;
        long_options[index].has_arg = option->has_args;
        long_options[index].val = option->id;
        if(option->has_args == no_argument) {
            amxc_string_appendf(&format, "%c", option->short_option);
        } else if(option->has_args == optional_argument) {
            amxc_string_appendf(&format, "%c::", option->short_option);
        } else {
            amxc_string_appendf(&format, "%c:", option->short_option);
        }
        index++;
    }

    index = 0;
    while(1) {
        c = getopt_long(argc, argv, amxc_string_get(&format, 0), long_options, &index);
        if(c == -1) {
            break;
        }
        rv = -2;
        if(fn != NULL) {
            // call provided function
            // if it returns 0 the option is handled
            // if it returns -1 stop option parsing and exit
            // if it returns -2 call default argument handler
            // all others are considered as an error
            rv = fn(config, c, optarg);
        }
        if(rv == -2) {
            rv = amxrt_cmd_line_default(config, c, optarg);
        }
        when_failed_status(rv, exit, rv = -1);
    }

exit:
    free(long_options);
    amxc_string_clean(&format);
    return rv == 0 ? optind : rv;
}

// parse a command line option where the value has this format "name=value"
void amxrt_cmd_line_parse_assignment(const char* option, bool force) {
    amxrt_t* rt = amxrt_get();
    amxc_var_t* config = NULL;
    amxc_string_t str_option;
    amxc_llist_t options;
    amxc_string_t* name = NULL;
    amxc_string_t* value = NULL;
    amxc_var_t var_option;

    amxc_var_init(&var_option);
    amxc_llist_init(&options);
    amxc_string_init(&str_option, 0);

    amxc_string_set(&str_option, option);
    amxc_string_split_to_llist(&str_option, &options, '=');
    when_true(amxc_llist_is_empty(&options), leave);
    when_true(amxc_llist_size(&options) != 2, leave);

    name = amxc_string_from_llist_it(amxc_llist_get_first(&options));
    value = amxc_string_from_llist_it(amxc_llist_get_last(&options));

    amxc_string_trim(name, NULL);
    amxc_string_trim(value, NULL);

    if(amxc_var_set(jstring_t, &var_option, amxc_string_get(value, 0)) != 0) {
        amxc_var_set(cstring_t, &var_option, amxc_string_get(value, 0));
    } else {
        amxc_var_cast(&var_option, AMXC_VAR_ID_ANY);
    }

    config = force ? &rt->forced_options : &rt->parser.config;
    amxc_var_set_path(config, amxc_string_get(name, 0), &var_option,
                      AMXC_VAR_FLAG_AUTO_ADD | AMXC_VAR_FLAG_COPY);

leave:
    amxc_string_clean(&str_option);
    amxc_llist_clean(&options, amxc_string_list_it_free);
    amxc_var_clean(&var_option);
    return;
}
