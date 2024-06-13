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

typedef struct _list_complete_t {
    amxc_var_t* ret;
    amxc_string_t* path;
    char* cur_path;
    char* part;
    uint32_t offset;
    amxc_var_t* used_values;
} list_complete_t;

static bool mod_pcb_cli_list_contains(amxc_var_t* ret, const char* path) {
    amxc_var_for_each(r, ret) {
        const char* p = amxc_var_constcast(cstring_t, r);
        if(strcmp(p, path) == 0) {
            return true;
        }
    }
    return false;
}

static void mod_pcb_cli_path_fill(const amxc_var_t* data,
                                  const char* part,
                                  uint32_t path_len,
                                  uint32_t offset,
                                  amxc_var_t* ret) {
    amxc_string_t helper;
    uint32_t len = part == NULL ? 0 : strlen(part);
    amxc_string_init(&helper, 32);

    amxc_var_for_each(name, data) {
        const char* node_name = amxc_var_constcast(cstring_t, name);
        if((len == 0) || (strncmp(node_name + path_len, part, len) == 0)) {
            if(offset == 1) {
                amxc_string_setf(&helper, ".%s", node_name);
                if(!mod_pcb_cli_list_contains(ret, amxc_string_get(&helper, 0))) {
                    amxc_var_add(cstring_t, ret, amxc_string_get(&helper, 0));
                }
            } else {
                if(!mod_pcb_cli_list_contains(ret, node_name + path_len)) {
                    amxc_var_add(cstring_t, ret, node_name + path_len);
                }
            }
        }
    }

    amxc_string_clean(&helper);
}

static void mod_pcb_cli_list_complete_cb(UNUSED const amxb_bus_ctx_t* bus_ctx,
                                         const amxc_var_t* const data,
                                         void* priv) {
    list_complete_t* lcomp = (list_complete_t*) priv;
    uint32_t cur_path_len = lcomp->cur_path != NULL ? strlen(lcomp->cur_path) : 0;
    const char* part = NULL;
    size_t pos = amxc_string_text_length(lcomp->path);

    if(data != NULL) {
        if(lcomp->part != NULL) {
            amxc_string_appendf(lcomp->path, "%s", lcomp->part);
        }
        part = amxc_string_get(lcomp->path, lcomp->offset + cur_path_len);
        mod_pcb_cli_path_fill(data, part, cur_path_len, lcomp->offset, lcomp->ret);
        amxc_string_remove_at(lcomp->path, pos, -1);
    }
}

static void mod_pcb_cli_list_complete_cb_done(const amxb_bus_ctx_t* bus_ctx,
                                              const amxc_var_t* const data,
                                              void* priv) {
    list_complete_t* lcomp = (list_complete_t*) priv;
    amxt_tty_t* tty = ba_cli_get_tty();

    if(data != NULL) {
        mod_pcb_cli_list_complete_cb(bus_ctx, data, priv);
    } else {
        amxp_sigmngr_emit_signal(tty->sigmngr, "tty:docomplete", lcomp->ret);
        amxc_var_delete(&lcomp->ret);
        amxc_string_delete(&lcomp->path);
        free(lcomp->cur_path);
        free(lcomp->part);
        free(lcomp);
    }
}

static int mod_pcb_cli_complete_all(amxb_bus_ctx_t* bus_ctx,
                                    UNUSED const amxc_var_t* args,
                                    void* priv) {
    amxb_list(bus_ctx,
              "",
              AMXB_FLAG_OBJECTS | AMXB_FLAG_INSTANCES |
              AMXB_FLAG_FIRST_LVL | AMXB_FLAG_EXISTS,
              mod_pcb_cli_list_complete_cb,
              priv);

    return 0;
}

static void mod_pcb_cli_complete_path(amxc_string_t* path,
                                      const char* part,
                                      uint32_t flags,
                                      amxc_var_t* ret) {
    amxb_bus_ctx_t* bus_ctx = NULL;
    amxt_tty_t* tty = ba_cli_get_tty();
    const char* str_path = amxc_string_get(path, 0);
    char* tmp = NULL;
    amxc_var_t* cur_path = amxt_tty_get_config(tty, "path");
    list_complete_t* lcomp = (list_complete_t*) calloc(1, sizeof(list_complete_t));

    lcomp->ret = ret;
    amxc_string_new(&lcomp->path, amxc_string_text_length(path) + 1);
    amxc_string_append(lcomp->path, amxc_string_get(path, 0), amxc_string_text_length(path));
    if(amxc_var_constcast(cstring_t, cur_path) != NULL) {
        lcomp->cur_path = strdup(amxc_var_constcast(cstring_t, cur_path));
    }
    lcomp->part = part == NULL ? NULL : strdup(part);
    lcomp->offset = 0;
    lcomp->used_values = NULL;

    if(!amxc_string_is_empty(lcomp->path)) {
        if(str_path[0] == '.') {
            lcomp->offset = 1;
            free(lcomp->cur_path);
            lcomp->cur_path = NULL;
        } else {
            if(lcomp->cur_path != NULL) {
                amxc_string_prependf(lcomp->path, "%s", lcomp->cur_path);
            }
        }
    } else {
        if(lcomp->cur_path != NULL) {
            amxc_string_prependf(lcomp->path, "%s", lcomp->cur_path);
        }
    }

    tmp = strdup(amxc_string_get(lcomp->path, lcomp->offset));
    bus_ctx = mod_pcb_cli_get_bus_ctx(str_path);
    flags |= AMXB_FLAG_FIRST_LVL;
    if(bus_ctx != NULL) {
        amxb_list(bus_ctx, tmp, flags, mod_pcb_cli_list_complete_cb, lcomp);
        flags |= AMXB_FLAG_NAMED;
        amxb_list(bus_ctx, tmp, flags, mod_pcb_cli_list_complete_cb_done, lcomp);
    } else {
        amxb_be_for_all_connections(mod_pcb_cli_complete_all, NULL, lcomp);
        amxp_sigmngr_emit_signal(tty->sigmngr, "tty:docomplete", lcomp->ret);
        amxc_var_delete(&lcomp->ret);
        amxc_string_delete(&lcomp->path);
        free(lcomp->cur_path);
        free(lcomp->part);
        free(lcomp);
    }
    free(tmp);
}

void mod_pcb_cli_cmd_complete(amxc_var_t* args,
                              uint32_t flags,
                              const char* options[],
                              amxc_var_t* ret) {
    amxc_string_t path;
    amxc_string_t last;
    amxt_tty_t* tty = ba_cli_get_tty();
    int rv = amxt_cmd_complete_option(args, options, ret);

    amxc_string_init(&path, 64);
    amxc_string_init(&last, 64);

    if((rv == 0) || (rv > 2)) {
        char* part = amxt_cmd_take_last_part(args);
        while(part != NULL && part[0] != '.') {
            amxc_string_prependf(&last, "%s", part);
            free(part);
            part = amxt_cmd_take_last_part(args);
        }

        if(part != NULL) {
            free(part);
            part = amxt_cmd_take_all(args);
            amxc_string_setf(&path, "%s.", part);
            free(part);
        }
        part = amxc_string_take_buffer(&last);
        mod_pcb_cli_complete_path(&path, part, flags, ret);
        free(part);
    } else {
        amxp_sigmngr_emit_signal(tty->sigmngr, "tty:docomplete", ret);
        amxc_var_delete(&ret);
    }

    amxc_string_clean(&last);
    amxc_string_clean(&path);
}

static bool mod_pcb_cli_params_complete_helper(amxt_tty_t* tty,
                                               amxc_var_t* args,
                                               char** path,
                                               amxc_string_t* name) {
    amxc_var_t cmd_opts;
    bool stop = false;
    bool value = false;
    char* part = NULL;

    amxc_var_init(&cmd_opts);

    amxt_cmd_parse_options(tty, args, &cmd_opts, NULL);
    *path = mod_pcb_cli_build_path(args);
    if(*path == NULL) {
        goto exit;
    }

    part = amxt_cmd_take_last_part(args);
    while(part != NULL) {
        switch(part[0]) {
        case '=':
            amxc_string_reset(name);
            stop = true;
            value = true;
            break;
        case ',':
            stop = true;
            break;
        case 0:
            break;
        case '{':
        case '(':
            stop = true;
            break;
        default:
            amxc_string_prependf(name, "%s", part);
            break;
        }
        free(part);
        if(stop) {
            break;
        }
        part = amxt_cmd_take_last_part(args);
    }

exit:
    amxc_var_clean(&cmd_opts);
    return !value;
}

static void mod_pcb_cli_list_complete_param_cb(UNUSED const amxb_bus_ctx_t* bus_ctx,
                                               const amxc_var_t* const data,
                                               void* priv) {
    list_complete_t* lcomp = (list_complete_t*) priv;
    amxt_tty_t* tty = ba_cli_get_tty();
    uint32_t path_len = 0;
    uint32_t len = 0;
    const char* i = NULL;

    if(data != NULL) {
        path_len = strlen(lcomp->cur_path);
        len = strlen(lcomp->part);
        i = lcomp->part;
        amxc_var_for_each(vp, data) {
            amxc_string_t* p = amxc_var_take(amxc_string_t, vp);
            if(GET_ARG(lcomp->used_values, amxc_string_get(p, path_len)) != NULL) {
                amxc_string_delete(&p);
                continue;
            }
            amxc_string_append(p, " = ", 3);
            if(strncmp(i, amxc_string_get(p, 0), len) == 0) {
                amxc_var_add(cstring_t, lcomp->ret, amxc_string_get(p, path_len));
            }
            amxc_string_delete(&p);
        }
    } else {
        amxp_sigmngr_emit_signal(tty->sigmngr, "tty:docomplete", lcomp->ret);
        amxc_var_delete(&lcomp->ret);
        amxc_var_delete(&lcomp->used_values);
        free(lcomp->cur_path);
        free(lcomp->part);
        free(lcomp);
    }
}

void mod_pcb_cli_params_complete(amxc_var_t* args,
                                 amxc_var_t* ret) {
    amxt_tty_t* tty = ba_cli_get_tty();
    amxc_string_t name;
    char* path = NULL;
    char* oper = NULL;
    amxb_bus_ctx_t* bus_ctx = NULL;
    list_complete_t* lcomp = (list_complete_t*) calloc(1, sizeof(list_complete_t));
    lcomp->ret = ret;

    amxc_string_init(&name, 32);

    if(!mod_pcb_cli_params_complete_helper(tty, args, &path, &name)) {
        free(path);
        free(lcomp);
        goto exit;
    }

    amxc_var_new(&lcomp->used_values);
    oper = amxt_cmd_pop_part(args);
    if(oper != NULL) {
        free(oper);
    }

    amxt_cmd_get_values(args, AMXT_VP_TABLE, lcomp->used_values);
    amxc_string_prependf(&name, "%s", path);

    bus_ctx = mod_pcb_cli_get_bus_ctx(path);
    lcomp->cur_path = path;
    lcomp->part = amxc_string_take_buffer(&name);
    amxb_list(bus_ctx, path, AMXB_FLAG_PARAMETERS | AMXB_FLAG_TEMPLATE_INFO | AMXB_FLAG_FIRST_LVL,
              mod_pcb_cli_list_complete_param_cb, lcomp);

exit:
    amxc_string_clean(&name);
}

void mod_pcb_cli_args_complete(amxc_var_t* args,
                               amxc_var_t* ret) {
    amxt_tty_t* tty = ba_cli_get_tty();
    amxc_var_t data;
    amxc_var_t used_args;
    amxc_string_t name;
    char* path = NULL;
    amxb_bus_ctx_t* bus_ctx = NULL;
    amxd_path_t function_path;
    amxc_var_t* func_args = NULL;
    amxc_string_t a;
    uint32_t len = 0;
    const char* i = NULL;

    amxc_var_init(&used_args);
    amxc_var_init(&data);
    amxc_string_init(&name, 32);
    amxc_string_init(&a, 32);
    amxd_path_init(&function_path, NULL);

    if(!mod_pcb_cli_params_complete_helper(tty, args, &path, &name)) {
        free(path);
        path = NULL;
        goto exit;
    }

    amxd_path_setf(&function_path, false, "%s", path);
    amxt_cmd_get_values(args, AMXT_VP_TABLE, &used_args);
    bus_ctx = mod_pcb_cli_get_bus_ctx(path);
    amxb_describe(bus_ctx, amxd_path_get(&function_path, AMXD_OBJECT_TERMINATE),
                  AMXB_FLAG_FUNCTIONS, &data, 5);
    func_args = amxc_var_get_path(&data, "0.functions", AMXC_VAR_FLAG_DEFAULT);
    func_args = GET_ARG(func_args, amxd_path_get_param(&function_path));
    func_args = GET_ARG(func_args, "arguments");
    len = amxc_string_text_length(&name);
    i = amxc_string_get(&name, 0);
    if(func_args != NULL) {
        amxc_var_for_each(func_arg, func_args) {
            bool is_in_arg = GETP_BOOL(func_arg, "attributes.in");
            const char* arg_name = GETP_CHAR(func_arg, "name");
            if((GET_ARG(&used_args, arg_name) != NULL) || !is_in_arg) {
                continue;
            }
            amxc_string_setf(&a, "%s = ", arg_name);
            if(strncmp(i, amxc_string_get(&a, 0), len) == 0) {
                amxc_var_add(cstring_t, ret, amxc_string_get(&a, 0));
            }
        }
    }
exit:
    free(path);
    amxc_string_clean(&a);
    amxd_path_clean(&function_path);
    amxc_var_clean(&data);
    amxc_var_clean(&used_args);
    amxc_string_clean(&name);
}
