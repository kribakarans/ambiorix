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

#include "mod_pcb_cli_cmd.h"
#include "mod_pcb_cli_common.h"

static void mod_pcb_cli_write_access(amxc_var_t* attrs) {
    amxt_tty_t* tty = ba_cli_get_tty();
    amxt_tty_writef(tty, "${color.reset}");
    if(GET_BOOL(attrs, "protected")) {
        amxt_tty_writef(tty, "<protected>");
    } else {
        amxt_tty_writef(tty, "<public>   ");
    }
    // private members are never returned with amxb functions
}

static void mod_pcb_cli_write_obj_type(uint32_t obj_type) {
    amxt_tty_t* tty = ba_cli_get_tty();
    amxt_tty_writef(tty, "${color.blue}");
    if(obj_type == amxd_object_singleton) {
        amxt_tty_writef(tty, "   singleton ");
    } else if(obj_type == amxd_object_template) {
        amxt_tty_writef(tty, "  multi-inst ");
    } else {
        amxt_tty_writef(tty, "    instance ");
    }
    amxt_tty_writef(tty, "${color.reset}");
}

static void mod_pcb_cli_write_type(uint32_t type) {
    amxt_tty_t* tty = ba_cli_get_tty();
    const char* name = mod_pcb_cli_human_type_name(type);
    amxt_tty_writef(tty, "${color.blue}");
    amxt_tty_writef(tty, "%12.12s ", name);
    amxt_tty_writef(tty, "${color.reset}");
}

static void mod_pcb_cli_write_attrs(amxc_var_t* attrs) {
    amxt_tty_t* tty = ba_cli_get_tty();
    amxt_tty_writef(tty, "${color.blue}");
    if(GET_BOOL(attrs, "persistent")) {
        amxt_tty_writef(tty, "P");
    } else {
        amxt_tty_writef(tty, "${color.reset}.${color.blue}");
    }
    if(GET_BOOL(attrs, "read-only")) {
        amxt_tty_writef(tty, "R");
    } else {
        amxt_tty_writef(tty, "${color.reset}.${color.blue}");
    }
    if(GET_BOOL(attrs, "mutable")) {
        amxt_tty_writef(tty, "M");
    } else {
        amxt_tty_writef(tty, "${color.reset}.${color.blue}");
    }
    if(GET_BOOL(attrs, "unique")) {
        amxt_tty_writef(tty, "U");
    } else {
        amxt_tty_writef(tty, "${color.reset}.${color.blue}");
    }
    if(GET_BOOL(attrs, "key")) {
        amxt_tty_writef(tty, "K");
    } else {
        amxt_tty_writef(tty, "${color.reset}.${color.blue}");
    }
    if(GET_BOOL(attrs, "counter")) {
        amxt_tty_writef(tty, "C");
    } else {
        amxt_tty_writef(tty, "${color.reset}.${color.blue}");
    }
    if(GET_BOOL(attrs, "volatile")) {
        amxt_tty_writef(tty, "V");
    } else {
        amxt_tty_writef(tty, "${color.reset}.${color.blue}");
    }
    if(GET_BOOL(attrs, "asynchronous")) {
        amxt_tty_writef(tty, "A");
    } else {
        amxt_tty_writef(tty, "${color.reset}.${color.blue}");
    }
    amxt_tty_writef(tty, " ${color.reset}");
}

static void mod_pcb_cli_write_arg_attrs(amxc_var_t* attrs) {
    amxt_tty_t* tty = ba_cli_get_tty();
    amxt_tty_writef(tty, "${color.blue}");
    if(GET_BOOL(attrs, "in")) {
        amxt_tty_writef(tty, "I");
    } else {
        amxt_tty_writef(tty, "${color.reset}.${color.blue}");
    }
    if(GET_BOOL(attrs, "out")) {
        amxt_tty_writef(tty, "O");
    } else {
        amxt_tty_writef(tty, "${color.reset}.${color.blue}");
    }
    if(GET_BOOL(attrs, "strict")) {
        amxt_tty_writef(tty, "S");
    } else {
        amxt_tty_writef(tty, "${color.reset}.${color.blue}");
    }
    if(GET_BOOL(attrs, "mandatory")) {
        amxt_tty_writef(tty, "M");
    } else {
        amxt_tty_writef(tty, "${color.reset}.${color.blue}");
    }
    amxt_tty_writef(tty, "${color.reset} ");
}

static void mod_pcb_cli_base_path(amxc_var_t* object,
                                  uint32_t obj_type,
                                  const amxc_var_t* options,
                                  amxc_string_t* base_path,
                                  amxc_var_t** subobjs) {
    const char* obj_path = NULL;
    const char* obj_name = NULL;
    uint32_t obj_index = 0;
    bool named = GET_BOOL(options, "n") || GET_BOOL(options, "named");

    obj_path = named ? GET_CHAR(object, "object") : GET_CHAR(object, "path");
    obj_index = amxc_var_dyncast(uint32_t, GET_ARG(object, "index"));
    obj_name = GET_CHAR(object, "name");

    if(obj_type == amxd_object_instance) {
        if(named) {
            amxc_string_setf(base_path, "%s%s.", obj_path, obj_name);
        } else {
            amxc_string_setf(base_path, "%s%d.", obj_path, obj_index);
        }
        *subobjs = GET_ARG(object, "objects");
    } else if(obj_type == amxd_object_template) {
        amxc_string_setf(base_path, "%s", obj_path);
        *subobjs = GET_ARG(object, "instances");
    } else {
        amxc_string_setf(base_path, "%s", obj_path);
        *subobjs = GET_ARG(object, "objects");
    }
}

static void mod_pcb_cli_write_parameters(amxc_var_t* params,
                                         amxc_string_t* base_path) {
    amxt_tty_t* tty = ba_cli_get_tty();

    const amxc_htable_t* table = amxc_var_constcast(amxc_htable_t, params);
    amxc_htable_for_each(hit, table) {
        amxc_var_t* param = amxc_var_from_htable_it(hit);
        amxc_var_t* attrs = GET_ARG(param, "attributes");
        const char* name = GET_CHAR(param, "name");
        amxc_var_t* value = GET_ARG(param, "value");
        amxc_var_t* validate = GET_ARG(param, "validate");
        char* str_value = amxc_var_dyncast(cstring_t, value);
        uint32_t type = amxc_var_dyncast(uint32_t, GET_ARG(param, "type_id"));

        mod_pcb_cli_write_attrs(attrs);
        mod_pcb_cli_write_access(attrs);
        mod_pcb_cli_write_type(type);

        amxt_tty_writef(tty, "${color.green}%s${color.reset}", amxc_string_get(base_path, 0));
        amxt_tty_writef(tty, "%s=%s\n", name, str_value);
        amxc_var_for_each(constraint, validate) {
            const char* data = NULL;
            amxc_var_cast(constraint, AMXC_VAR_ID_JSON);
            data = amxc_var_constcast(jstring_t, constraint);
            amxt_tty_writef(tty, "                                     ");
            if((data == NULL) || (*data == 0)) {
                amxt_tty_writef(tty, "${color.blue}%s${colort.reset}\n",
                                amxc_var_key(constraint));
            } else {
                amxt_tty_writef(tty, "${color.blue}%s %s${colort.reset}\n",
                                amxc_var_key(constraint),
                                data);
            }
        }
        free(str_value);
    }
}

static void mod_pcb_cli_write_events(amxc_var_t* events,
                                     amxc_string_t* base_path) {
    amxt_tty_t* tty = ba_cli_get_tty();

    amxc_var_for_each(event, events) {
        const char* sep = "";

        amxt_tty_writef(tty, ".......            ");
        amxt_tty_writef(tty, "${color.blue}");
        amxt_tty_writef(tty, "%12.12s ", "event");
        amxt_tty_writef(tty, "${color.reset}");

        amxt_tty_writef(tty, "${color.green}%s${color.reset}", amxc_string_get(base_path, 0));
        amxt_tty_writef(tty, "%s [", amxc_var_key(event));
        amxc_var_for_each(param, event) {
            amxt_tty_writef(tty, "%s%s", sep, GET_CHAR(param, NULL));
            sep = ",";
        }
        amxt_tty_writef(tty, "]\n");
    }
}

static void mod_pcb_cli_write_arguments(amxc_var_t* args) {
    const amxc_llist_t* list = amxc_var_constcast(amxc_llist_t, args);
    amxt_tty_t* tty = ba_cli_get_tty();
    const char* sep = "";

    amxc_llist_for_each(lit, list) {
        amxc_var_t* arg = amxc_var_from_llist_it(lit);
        const char* name = GET_CHAR(arg, "name");
        uint32_t type_id = amxc_var_dyncast(uint32_t, GET_ARG(arg, "type_id"));
        amxc_var_t* attrs = GET_ARG(arg, "attributes");
        const char* type_name = mod_pcb_cli_human_type_name(type_id);
        amxt_tty_writef(tty, "%s", sep);
        mod_pcb_cli_write_arg_attrs(attrs);
        amxt_tty_writef(tty, "${color.blue}%s${color.reset} %s", type_name, name);
        sep = ", ";
    }
}

static void mod_pcb_cli_write_functions(amxc_var_t* funcs, amxc_string_t* base_path) {
    amxt_tty_t* tty = ba_cli_get_tty();

    const amxc_htable_t* table = amxc_var_constcast(amxc_htable_t, funcs);
    amxc_htable_for_each(hit, table) {
        amxc_var_t* func = amxc_var_from_htable_it(hit);
        amxc_var_t* attrs = GET_ARG(func, "attributes");
        const char* name = GET_CHAR(func, "name");
        amxc_var_t* args = GET_ARG(func, "arguments");
        uint32_t type = amxc_var_dyncast(uint32_t, GET_ARG(func, "type_id"));
        mod_pcb_cli_write_attrs(attrs);
        mod_pcb_cli_write_access(attrs);
        mod_pcb_cli_write_type(type);
        amxt_tty_writef(tty, "${color.green}%s${color.reset}", amxc_string_get(base_path, 0));
        amxt_tty_writef(tty, "%s(", name);
        mod_pcb_cli_write_arguments(args);
        amxt_tty_writef(tty, ")\n");
    }
}

static void mod_pcb_cli_write_object(amxc_var_t* object,
                                     uint32_t obj_type,
                                     amxc_string_t* base_path) {
    amxc_var_t* parameters = GET_ARG(object, "parameters");
    amxc_var_t* functions = GET_ARG(object, "functions");
    amxc_var_t* events = GET_ARG(object, "events");
    amxc_var_t* attrs = GET_ARG(object, "attributes");
    amxt_tty_t* tty = ba_cli_get_tty();

    mod_pcb_cli_write_attrs(attrs);
    mod_pcb_cli_write_access(attrs);
    mod_pcb_cli_write_obj_type(obj_type);

    amxt_tty_writef(tty, "${color.green}%s${color.reset}\n", amxc_string_get(base_path, 0));
    if(obj_type == amxd_object_template) {
        goto exit;
    }

    if(parameters != NULL) {
        mod_pcb_cli_write_parameters(parameters, base_path);
    }

    if(events != NULL) {
        mod_pcb_cli_write_events(events, base_path);
    }

    if(functions != NULL) {
        mod_pcb_cli_write_functions(functions, base_path);
    }

exit:
    return;
}

static int mod_pcb_cli_cmd_dump_impl(amxb_bus_ctx_t* bus_ctx,
                                     const char* input_path,
                                     amxc_var_t* options,
                                     uint32_t flags) {
    int rv = 0;
    uint32_t obj_type = 0;
    amxc_var_t data;
    amxc_string_t base_path;
    amxc_var_t* object = NULL;
    amxc_var_t* tmp = NULL;
    amxc_var_t subobjs;

    bool recursive = GET_BOOL(options, "r") || GET_BOOL(options, "recursive");
    amxt_tty_t* tty = ba_cli_get_tty();

    amxc_var_init(&data);
    amxc_var_init(&subobjs);
    amxc_string_init(&base_path, 64);

    rv = amxb_describe(bus_ctx, input_path, flags, &data, 5);
    if(rv != amxd_status_ok) {
        amxt_tty_errorf(tty, "dump %s failed (%d - %s)\n",
                        input_path, rv, amxd_status_string((amxd_status_t) rv));
        goto exit;
    }

    object = GETI_ARG(&data, 0);
    obj_type = amxc_var_dyncast(uint32_t, GET_ARG(object, "type_id"));

    mod_pcb_cli_base_path(object, obj_type, options, &base_path, &tmp);
    amxc_var_copy(&subobjs, tmp);

    if(!mod_pcb_cli_output_json(tty, &data)) {
        mod_pcb_cli_write_object(object, obj_type, &base_path);
    }

    when_false(recursive, exit);

    amxc_var_for_each(subobj, &subobjs) {
        const char* node = amxc_var_constcast(cstring_t, subobj);
        size_t pos = amxc_string_text_length(&base_path);
        amxc_string_appendf(&base_path, "%s.", node);
        mod_pcb_cli_cmd_dump_impl(bus_ctx, amxc_string_get(&base_path, 0), options, recursive ? flags : 0);
        amxc_string_remove_at(&base_path, pos, SIZE_MAX);
    }

exit:
    amxc_string_clean(&base_path);
    amxc_var_clean(&data);
    amxc_var_clean(&subobjs);
    return rv;
}

int mod_pcb_cli_cmd_dump(UNUSED const char* function_name,
                         amxc_var_t* args,
                         UNUSED amxc_var_t* ret) {
    amxc_var_t options;
    char* input_path = NULL;
    amxb_bus_ctx_t* bus_ctx = NULL;
    int rv = 0;
    int flags = AMXB_FLAG_OBJECTS | AMXB_FLAG_INSTANCES;

    amxc_var_init(&options);

    rv = mod_pcb_cli_cmd_parse(args, PCB_DUMP, NULL, &input_path, &options, NULL);
    when_failed(rv, exit);

    if(GET_BOOL(&options, "p") || GET_BOOL(&options, "parameters")) {
        flags |= AMXB_FLAG_PARAMETERS;
    }

    if(GET_BOOL(&options, "f") || GET_BOOL(&options, "functions")) {
        flags |= AMXB_FLAG_FUNCTIONS;
    }

    if(GET_BOOL(&options, "e") || GET_BOOL(&options, "events")) {
        flags |= AMXB_FLAG_EVENTS;
    }

    bus_ctx = mod_pcb_cli_get_bus_ctx(input_path);
    when_null(bus_ctx, exit);

    rv = mod_pcb_cli_cmd_dump_impl(bus_ctx, input_path, &options, flags);

exit:
    amxc_var_clean(&options);
    free(input_path);
    return rv;
}
