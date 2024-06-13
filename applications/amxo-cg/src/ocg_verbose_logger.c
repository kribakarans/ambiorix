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
#include <stdio.h>
#include <string.h>
#include <getopt.h>

#include "utils.h"
#include "colors.h"

static int identation = 0;
static const char* arg_sep = "";

static void print_identation(void) {
    if(identation < 0) {
        identation = 0;
    }
    for(int i = 0; i < identation; i++) {
        printf("|   ");
    }
}

static void log_start(amxo_parser_t* parser) {
    const char* file = amxo_parser_get_file(parser);
    printf("%sStart%s - %s\n", c(WHITE), c(RESET), file);
    identation++;
}

static void log_end(amxo_parser_t* parser) {
    const char* file = amxo_parser_get_file(parser);
    identation--;
    printf("%sEnd%s - %s\n", c(WHITE), c(RESET), file);
}

static void log_start_include(amxo_parser_t* parser, const char* incfile) {
    const char* file = amxo_parser_get_file(parser);
    uint32_t line = amxo_parser_get_line(parser);
    print_identation();
    printf("%sOpen include file%s %s%s%s - %s@%d\n",
           c(WHITE), c(RESET),
           c(GREEN), incfile, c(RESET),
           file, line);
    identation++;
}

static void log_end_include(amxo_parser_t* parser, const char* incfile) {
    const char* file = amxo_parser_get_file(parser);
    uint32_t line = amxo_parser_get_line(parser);
    identation--;
    print_identation();
    printf("%sClose include file%s %s%s%s - %s@%d\n",
           c(WHITE), c(RESET),
           c(GREEN), incfile, c(RESET),
           file, line);
}

static void log_start_section(amxo_parser_t* parser,
                              int section_id) {
    const char* file = amxo_parser_get_file(parser);
    uint32_t line = amxo_parser_get_line(parser);
    const char* section_name = "";
    switch(section_id) {
    case 0: section_name = "config";
        break;
    case 1: section_name = "define";
        break;
    case 2: section_name = "populate";
        break;
    }
    print_identation();
    printf("%sOpen section%s %s%s%s - %s@%d\n",
           c(WHITE), c(RESET),
           c(GREEN), section_name, c(RESET),
           file, line);
    identation++;
}

static void log_end_section(amxo_parser_t* parser,
                            int section_id) {
    const char* file = amxo_parser_get_file(parser);
    uint32_t line = amxo_parser_get_line(parser);
    const char* section_name = "";
    switch(section_id) {
    case 0: section_name = "config";
        break;
    case 1: section_name = "define";
        break;
    case 2: section_name = "populate";
        break;
    }
    identation--;
    print_identation();
    printf("%sClose section%s %s%s%s - %s@%d\n",
           c(WHITE), c(RESET),
           c(GREEN), section_name, c(RESET),
           file, line);
}

static void log_set_config(amxo_parser_t* parser,
                           const char* option,
                           UNUSED amxc_var_t* value) {
    const char* file = amxo_parser_get_file(parser);
    uint32_t line = amxo_parser_get_line(parser);
    print_identation();
    printf("%sSet config option%s %s%s%s - %s@%d\n",
           c(WHITE), c(RESET),
           c(GREEN), option, c(RESET),
           file, line);
}

static void log_create_object(amxo_parser_t* parser,
                              UNUSED amxd_object_t* parent,
                              const char* name,
                              UNUSED int64_t attr_bitmask,
                              amxd_object_type_t type) {
    const char* file = amxo_parser_get_file(parser);
    uint32_t line = amxo_parser_get_line(parser);
    const char* type_name = "";
    switch(type) {
    case amxd_object_root:
        type_name = "root";
        break;
    case amxd_object_singleton:
        type_name = "singleton";
        break;
    case amxd_object_template:
        type_name = "template";
        break;
    case amxd_object_instance:
        type_name = "instance";
        break;
    case amxd_object_mib:
        type_name = "mib";
        break;
    default:
        type_name = "invalid";
        break;
    }
    print_identation();
    printf("%sCreate object%s %s%s%s %s%s%s - %s@%d\n",
           c(WHITE), c(RESET),
           c(BLUE), type_name, c(RESET),
           c(GREEN), name, c(RESET),
           file, line);
    identation++;
}

static void log_add_instance(amxo_parser_t* parser,
                             UNUSED amxd_object_t* parent,
                             uint32_t index,
                             const char* name) {
    const char* file = amxo_parser_get_file(parser);
    uint32_t line = amxo_parser_get_line(parser);
    print_identation();
    printf("%sAdd instance%s (%s%d%s, \"%s%s%s\") - %s@%d\n",
           c(WHITE), c(RESET),
           c(GREEN), index, c(RESET),
           c(GREEN), name, c(RESET),
           file, line);
    identation++;
}

static void log_select_object(amxo_parser_t* parser,
                              amxd_object_t* parent,
                              const char* path) {
    const char* file = amxo_parser_get_file(parser);
    uint32_t line = amxo_parser_get_line(parser);
    char* parent_path = amxd_object_get_path(parent, AMXD_OBJECT_NAMED);
    print_identation();
    printf("%sSelect from%s %s%s%s %s%s%s - %s@%d\n",
           c(WHITE), c(RESET),
           c(BLUE), parent_path == NULL ? "(root)" : parent_path, c(RESET),
           c(GREEN), path, c(RESET),
           file, line);
    identation++;
    free(parent_path);
}

static void log_end_object(amxo_parser_t* parser,
                           amxd_object_t* object) {
    const char* file = amxo_parser_get_file(parser);
    uint32_t line = amxo_parser_get_line(parser);
    identation--;
    print_identation();
    if(amxd_object_get_type(object) == amxd_object_instance) {
        printf("%sDone object%s (%s%d%s, \"%s%s%s\") - %s@%d\n",
               c(WHITE), c(RESET),
               c(GREEN), amxd_object_get_index(object), c(RESET),
               c(GREEN), amxd_object_get_name(object, AMXD_OBJECT_NAMED), c(RESET),
               file, line);
    } else {
        printf("%sDone object%s %s%s%s - %s@%d\n",
               c(WHITE), c(RESET),
               c(GREEN), amxd_object_get_name(object, AMXD_OBJECT_NAMED), c(RESET),
               file, line);
    }
}

static void log_add_param(amxo_parser_t* parser,
                          UNUSED amxd_object_t* object,
                          const char* name,
                          UNUSED int64_t attr_bitmask,
                          uint32_t type) {
    const char* file = amxo_parser_get_file(parser);
    uint32_t line = amxo_parser_get_line(parser);
    print_identation();
    printf("%sAdd parameter%s %s%s%s %s%s%s - %s@%d\n",
           c(WHITE), c(RESET),
           c(BLUE), amxc_var_get_type_name_from_id(type), c(RESET),
           c(GREEN), name, c(RESET),
           file, line);
}

static void log_set_param(amxo_parser_t* parser,
                          UNUSED amxd_object_t* object,
                          amxd_param_t* param,
                          amxc_var_t* value) {
    const char* file = amxo_parser_get_file(parser);
    uint32_t line = amxo_parser_get_line(parser);
    char* value_str = amxc_var_dyncast(cstring_t, value);
    print_identation();
    printf("%sSet parameter%s %s%s%s = %s - %s@%d\n",
           c(WHITE), c(RESET),
           c(GREEN), amxd_param_get_name(param), c(RESET),
           value_str,
           file, line);

    free(value_str);
}

static void log_add_func(UNUSED amxo_parser_t* parser,
                         UNUSED amxd_object_t* object,
                         const char* name,
                         UNUSED int64_t attr_bitmask,
                         uint32_t type) {
    print_identation();
    printf("%sAdd function%s %s%s%s %s%s%s(",
           c(WHITE), c(RESET),
           c(BLUE), amxc_var_get_type_name_from_id(type), c(RESET),
           c(GREEN), name, c(RESET));
}

static void log_end_func(amxo_parser_t* parser,
                         UNUSED amxd_object_t* object,
                         UNUSED amxd_function_t* function) {
    const char* file = amxo_parser_get_file(parser);
    uint32_t line = amxo_parser_get_line(parser);
    printf(" ) - %s@%d\n", file, line);
    arg_sep = "";
}

static void log_add_func_arg(UNUSED amxo_parser_t* parser,
                             UNUSED amxd_object_t* object,
                             UNUSED amxd_function_t* func,
                             const char* name,
                             UNUSED int64_t attr_bitmask,
                             uint32_t type,
                             UNUSED amxc_var_t* def_value) {
    printf("%s %s%s%s %s%s%s",
           arg_sep,
           c(BLUE), amxc_var_get_type_name_from_id(type), c(RESET),
           c(GREEN), name, c(RESET));
    arg_sep = ",";
}

static const char* log_get_action_name(amxd_action_t action_id) {
    const char* name = "invalid";
    const char* names[] = {
        "any",
        "parameter read",         // read parameter value
        "parameter write",        // set parameter value
        "parameter validate",     // validate new value
        "parameter describe",     // get parameter definition
        "parameter destroy",      // remove and clean up parameter
        "object read",            // get all parameter values of an object
        "object write",           // set parameter values of an object
        "object validate",        // validate the full object
        "object list",            // fetch list(s)
        "object describe",        // describe object, list all parameters, functions or children
        "tree",                   // list full tree, starting from an object (currently not used)
        "add instance",           // add an instance
        "delete instance",        // verify instance can be deleted
        "object destroy",         // remove and clean up an object (any)
        "add mib",                // extend the object with a known mib
        "describe_action",        // describe the action itself
    };

    if((action_id >= 0) && (action_id < (int32_t) (sizeof(names) / sizeof(char*)))) {
        name = names[action_id];
    }

    return name;
}

static void log_set_action_cb(UNUSED amxo_parser_t* parser,
                              UNUSED amxd_object_t* object,
                              UNUSED amxd_param_t* param,
                              amxd_action_t action_id,
                              const char* action_name,
                              const amxc_var_t* data) {
    const char* file = amxo_parser_get_file(parser);
    uint32_t line = amxo_parser_get_line(parser);
    const char* action_id_name = log_get_action_name(action_id);
    amxc_var_t json_data;

    amxc_var_init(&json_data);
    amxc_var_convert(&json_data, data, AMXC_VAR_ID_JSON);

    print_identation();
    printf("%sAdd Action Method%s %s%s%s %s%s%s",
           c(WHITE), c(RESET),
           c(BLUE), action_id_name, c(RESET),
           c(GREEN), action_name, c(RESET));
    if(!amxc_var_is_null(data)) {
        printf(" %s%s%s", c(GREEN), amxc_var_constcast(jstring_t, &json_data), c(RESET));
    }

    printf(" - %s@%d\n", file, line);

    amxc_var_clean(&json_data);
}

static amxo_hooks_t logger_hooks = {
    .it = { .next = NULL, .prev = NULL, .llist = NULL },
    .comment = NULL,
    .start = log_start,
    .end = log_end,
    .start_include = log_start_include,
    .end_include = log_end_include,
    .set_config = log_set_config,
    .start_section = log_start_section,
    .end_section = log_end_section,
    .create_object = log_create_object,
    .add_instance = log_add_instance,
    .select_object = log_select_object,
    .end_object = log_end_object,
    .add_param = log_add_param,
    .set_param = log_set_param,
    .end_param = NULL,
    .add_func = log_add_func,
    .add_func_arg = log_add_func_arg,
    .end_func = log_end_func,
    .add_mib = NULL,
    .set_counter = NULL,
    .set_action_cb = log_set_action_cb,
};

void ocg_verbose_logging(amxo_parser_t* parser, bool enable) {
    if(enable) {
        amxo_parser_set_hooks(parser, &logger_hooks);
    } else {
        amxo_parser_unset_hooks(parser, &logger_hooks);
    }
}