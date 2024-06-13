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

#include <string.h>
#include <stdio.h>

#include "ba_cli_priv.h"

#include "mod_pcb_cli.h"
#include "mod_pcb_cli_cmd.h"
#include "mod_pcb_cli_common.h"

static amxc_llist_t requests;

static void mod_pcb_cli_free_request(amxc_llist_it_t* it) {
    amxb_request_t* req = amxc_container_of(it, amxb_request_t, it);
    free(req->priv);
    amxb_close_request(&req);
}

static void mod_pcb_cli_call_connection_closed(UNUSED const char* const sig_name,
                                               const amxc_var_t* const data,
                                               UNUSED void* const priv) {
    amxt_tty_t* tty = ba_cli_get_tty();
    if(amxc_var_type_of(data) != AMXC_VAR_ID_FD) {
        goto leave;
    }

    amxt_tty_hide_prompt(tty);
    amxc_llist_for_each(it, &requests) {
        amxb_request_t* request = amxc_container_of(it, amxb_request_t, it);
        amxb_bus_ctx_t* ctx = amxb_request_get_ctx(request);

        if(ctx == NULL) {
            char* info = (char*) request->priv;
            amxc_llist_it_take(it);
            amxb_close_request(&request);
            amxt_tty_errorf(tty, "Pending call %s closed - disconnected\n", info);
            free(info);
        }
    }
    amxt_tty_show_prompt(tty);

leave:
    return;
}

static void mod_pcb_cli_call_done(UNUSED const amxb_bus_ctx_t* bus_ctx,
                                  amxb_request_t* req,
                                  int status,
                                  void* priv) {
    amxt_tty_t* tty = ba_cli_get_tty();
    amxc_var_t* rv = amxt_tty_get_config(tty, "rv");
    char* info = (char*) priv;
    amxt_tty_hide_prompt(tty);

    amxc_var_set(uint32_t, rv, status);

    if(status != 0) {
        amxt_tty_errorf(tty, "call %s failed with status %d - %s\n",
                        info, status, amxd_status_string((amxd_status_t) status));
        goto exit;
    }

    amxt_tty_messagef(tty, "%s returned\n", info);
    if(!mod_pcb_cli_output_json(tty, req->result)) {
        amxc_var_dump(req->result, STDOUT_FILENO);
    }

exit:
    amxt_tty_show_prompt(tty);
    amxc_llist_it_take(&req->it);
    free(priv);
    amxb_close_request(&req);
}

static int mod_pcb_cli_call_verify(amxb_bus_ctx_t* ctx,
                                   const char* obj_path,
                                   const char* method) {
    amxd_path_t path;
    amxc_var_t* acls = NULL;
    amxc_var_t resolved;
    char* fixed = NULL;
    char* file = mod_pcb_cli_get_acl_file();
    int retval = -1;
    bool allowed = false;
    amxc_string_t resolved_path;

    amxc_string_init(&resolved_path, 0);
    amxc_var_init(&resolved);
    amxd_path_init(&path, obj_path);

    if(!mod_pcb_cli_acl_enabled()) {
        retval = 0;
        goto exit;
    }

    when_str_empty(file, exit);

    fixed = amxd_path_get_fixed_part(&path, false);
    acls = amxa_parse_files(file);
    amxa_resolve_search_paths(ctx, acls, fixed);

    if(amxd_path_is_search_path(&path)) {
        amxb_resolve(ctx, &path, &resolved);
        amxc_var_for_each(var, &resolved) {
            amxc_string_setf(&resolved_path, "%s", amxc_var_constcast(cstring_t, var));
            allowed = amxa_is_operate_allowed(ctx, acls, amxc_string_get(&resolved_path, 0), method);
            when_false(allowed, exit);
        }
    } else {
        allowed = amxa_is_operate_allowed(ctx, acls, obj_path, method);
        when_false(allowed, exit);
    }

    retval = 0;
exit:
    free(fixed);
    free(file);
    amxd_path_clean(&path);
    amxc_var_delete(&acls);
    amxc_var_clean(&resolved);
    amxc_string_clean(&resolved_path);

    return retval;
}

int mod_pcb_cli_call(amxt_tty_t* tty,
                     amxb_bus_ctx_t* bus_ctx,
                     UNUSED amxc_var_t* options,
                     const char* path,
                     amxc_var_t* cmd) {
    amxc_var_t values;
    amxb_request_t* req = NULL;
    amxd_path_t p;
    char* info = NULL;
    const char* method = NULL;
    amxc_string_t func_info;
    int rv = 0;
    amxc_var_t paths;

    amxc_string_init(&func_info, 0);
    amxc_var_init(&values);
    amxd_path_init(&p, path);
    amxc_var_init(&paths);

    amxc_var_set_type(&values, AMXC_VAR_ID_HTABLE);
    rv = amxt_cmd_get_values(cmd, AMXT_VP_TABLE | AMXT_VP_COMPOSITE, &values);
    if(rv != 0) {
        amxt_tty_errorf(tty, "Syntax error\n");
        goto exit;
    }

    method = amxd_path_get_param(&p);

    if(amxd_path_get_type(&p) == amxd_path_search) {
        rv = amxb_resolve(bus_ctx, &p, &paths);
        if((rv != 0) || amxc_llist_is_empty(amxc_var_constcast(amxc_llist_t, &paths))) {
            amxt_tty_errorf(tty, "No objects found %s\n", path);
            goto exit;
        }
    } else {
        amxc_var_set_type(&paths, AMXC_VAR_ID_LIST);
        amxc_var_add(cstring_t, &paths, amxd_path_get(&p, AMXD_OBJECT_TERMINATE));
    }

    amxc_var_for_each(object, &paths) {
        const char* object_path = GET_CHAR(object, NULL);
        amxc_string_setf(&func_info, "%s%s()", object_path, method);
        rv = mod_pcb_cli_call_verify(bus_ctx, object_path, method);
        if(rv != 0) {
            amxt_tty_errorf(tty, "permission denied %s\n", path);
            continue;
        }
        if(tty->interactive) {
            info = amxc_string_take_buffer(&func_info);
            req = amxb_async_call(bus_ctx, object_path,
                                  method, &values, mod_pcb_cli_call_done, info);
            if(req == NULL) {
                amxt_tty_errorf(tty, "call %s failed\n", info);
                rv = -1;
                free(info);
                goto exit;
            }

            amxc_llist_append(&requests, &req->it);
            rv = 0;
        } else {
            amxc_var_t result;
            amxc_var_init(&result);
            rv = amxb_call(bus_ctx, object_path, method, &values, &result, 30);
            if(rv != 0) {
                amxt_tty_errorf(tty, "call %s failed with status %d - %s\n",
                                info, rv, amxd_status_string((amxd_status_t) rv));
            }
            amxt_tty_messagef(tty, "%s returned\n", amxc_string_get(&func_info, 0), rv);
            if(!mod_pcb_cli_output_json(tty, &result)) {
                amxc_var_dump(&result, STDOUT_FILENO);
            }
            amxc_var_clean(&result);
        }
    }

exit:
    amxc_var_clean(&paths);
    amxc_string_clean(&func_info);
    amxd_path_clean(&p);
    amxc_var_clean(&values);

    return rv;
}

int mod_pcb_cli_cmd_requests(UNUSED const char* function_name,
                             amxc_var_t* args,
                             UNUSED amxc_var_t* ret) {
    amxt_tty_t* tty = GET_TTY(args);

    if(amxc_llist_is_empty(&requests)) {
        amxt_tty_writef(tty, "${color.green}No pending requests${color.reset}\n");
    }

    amxc_llist_iterate(it, &requests) {
        amxb_request_t* req = amxc_container_of(it, amxb_request_t, it);
        amxt_tty_writef(tty, "${color.blue}%s${color.reset}\n", (char*) req->priv);
    }

    return 0;
}

void mod_pcb_cli_requests_init(void) {
    amxc_llist_init(&requests);

    amxp_slot_connect(NULL, "connection-deleted", NULL, mod_pcb_cli_call_connection_closed, NULL);
}

void mod_pcb_cli_requests_clean(void) {
    amxc_llist_clean(&requests, mod_pcb_cli_free_request);
    amxp_slot_disconnect(NULL, "connection-deleted", mod_pcb_cli_call_connection_closed);
}
