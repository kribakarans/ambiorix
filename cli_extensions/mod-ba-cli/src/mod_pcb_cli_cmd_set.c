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

#include "ba_cli_priv.h"
#include "mod_pcb_cli_cmd.h"
#include "mod_pcb_cli_common.h"

static int mod_pcb_cli_set_verify(amxb_bus_ctx_t* ctx,
                                  const char* obj_path,
                                  amxc_var_t* params) {
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
            allowed = mod_pcb_cli_verify_params(ctx, acls, amxc_string_get(&resolved_path, 0),
                                                params);
            when_false(allowed, exit);
        }
    } else {
        allowed = mod_pcb_cli_verify_params(ctx, acls, obj_path, params);
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

static int mod_pcb_cli_set(amxt_tty_t* tty,
                           amxb_bus_ctx_t* bus_ctx,
                           const char* path,
                           amxc_var_t* values) {
    amxc_var_t data;
    int rv = 0;

    amxc_var_init(&data);

    if(amxc_var_type_of(values) != AMXC_VAR_ID_HTABLE) {
        amxd_path_t p;
        amxc_var_t v;
        amxc_var_init(&v);
        amxc_var_set_type(&v, AMXC_VAR_ID_HTABLE);
        amxd_path_init(&p, path);
        amxc_var_set_key(&v, amxd_path_get_param(&p), values, AMXC_VAR_FLAG_COPY);
        rv = mod_pcb_cli_set_verify(bus_ctx, amxd_path_get(&p, AMXD_OBJECT_TERMINATE), &v);
        if(rv != 0) {
            amxt_tty_errorf(tty, "permission denied %s\n", path);
        } else {
            rv = amxb_set(bus_ctx, amxd_path_get(&p, AMXD_OBJECT_TERMINATE),
                          &v, &data, 5);
        }
        amxc_var_clean(&v);
        amxd_path_clean(&p);
    } else {
        rv = mod_pcb_cli_set_verify(bus_ctx, path, values);
        if(rv != 0) {
            amxt_tty_errorf(tty, "permission denied %s\n", path);
            goto exit;
        }
        rv = amxb_set(bus_ctx, path, values, &data, 5);
    }

    mod_pcb_cli_output_flat(tty, &data, false);

exit:
    amxc_var_clean(&data);
    return rv;
}

int mod_pcb_cli_set_primitive(amxt_tty_t* tty,
                              amxb_bus_ctx_t* bus_ctx,
                              UNUSED amxc_var_t* options,
                              const char* path,
                              amxc_var_t* cmd) {
    amxc_var_t values;
    int rv = 0;

    amxc_var_init(&values);

    rv = amxt_cmd_get_values(cmd, AMXT_VP_PRIMITIVE, &values);
    if(rv != 0) {
        amxt_tty_errorf(tty, "Syntax error\n");
        goto exit;
    }

    rv = mod_pcb_cli_set(tty, bus_ctx, path, &values);

exit:
    amxc_var_clean(&values);

    return rv;
}

int mod_pcb_cli_set_table(amxt_tty_t* tty,
                          amxb_bus_ctx_t* bus_ctx,
                          UNUSED amxc_var_t* options,
                          const char* path,
                          amxc_var_t* cmd) {
    amxc_var_t values;
    int rv = 0;

    amxc_var_init(&values);

    rv = amxt_cmd_get_values(cmd, AMXT_VP_TABLE, &values);
    if(rv != 0) {
        amxt_tty_errorf(tty, "Syntax error\n");
        goto exit;
    }

    rv = mod_pcb_cli_set(tty, bus_ctx, path, &values);

exit:
    amxc_var_clean(&values);

    return rv;
}
