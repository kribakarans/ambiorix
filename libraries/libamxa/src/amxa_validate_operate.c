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
#include <stdlib.h>

#include <amxc/amxc.h>
#include <amxc/amxc_macros.h>
#include <amxp/amxp.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_path.h>

#include "amxa/amxa_permissions.h"
#include "amxa/amxa_merger.h"
#include "amxa/amxa_resolver.h"
#include "amxa/amxa_validator.h"

#include "amxa_utils_priv.h"

static bool amxa_has_supported_command(amxc_var_t* supported_commands, const char* command) {
    bool retval = false;
    amxc_string_t command_str;

    amxc_string_init(&command_str, 0);
    amxc_string_setf(&command_str, "%s", command);
    amxc_string_trimr(&command_str, amxa_utils_is_brace);

    amxc_var_for_each(entry, supported_commands) {
        const char* command_name = GET_CHAR(entry, "command_name");
        amxc_string_t command_name_str;

        if((command_name == NULL) || (*command_name == 0)) {
            continue;
        }

        amxc_string_init(&command_name_str, 0);
        amxc_string_setf(&command_name_str, "%s", command_name);
        amxc_string_trimr(&command_name_str, amxa_utils_is_brace);
        if(strcmp(amxc_string_get(&command_name_str, 0), amxc_string_get(&command_str, 0)) == 0) {
            retval = true;
            amxc_string_clean(&command_name_str);
            break;
        }
        amxc_string_clean(&command_name_str);
    }

    amxc_string_clean(&command_str);
    return retval;
}

static bool amxa_command_is_supported(amxb_bus_ctx_t* ctx,
                                      const char* object,
                                      const char* command) {
    bool retval = false;
    amxc_var_t ret;
    amxd_path_t path;
    char* supported_path = NULL;

    amxc_var_init(&ret);
    amxd_path_init(&path, object);

    when_null(ctx, exit);
    when_str_empty(object, exit);
    when_str_empty(command, exit);

    supported_path = amxd_path_build_supported_path(&path);

    amxb_get_supported(ctx, supported_path, AMXB_FLAG_FUNCTIONS | AMXB_FLAG_FIRST_LVL, &ret, 5);
    amxc_var_for_each(element, GETI_ARG(&ret, 0)) {
        amxc_var_t* supported_commands = GET_ARG(element, "supported_commands");
        if(supported_commands == NULL) {
            continue;
        }
        if(amxa_has_supported_command(supported_commands, command)) {
            retval = true;
            break;
        }
    }

exit:
    free(supported_path);
    amxd_path_clean(&path);
    amxc_var_clean(&ret);
    return retval;
}

static bool amxa_object_is_instantiated(amxb_bus_ctx_t* ctx, const char* object) {
    bool retval = false;
    amxc_var_t ret;

    amxc_var_init(&ret);

    when_null(ctx, exit);
    when_str_empty(object, exit);

    amxb_get(ctx, object, 0, &ret, 5);
    when_null(GETP_ARG(&ret, "0.0"), exit);

    retval = true;
exit:
    amxc_var_clean(&ret);
    return retval;
}

static void amxa_operate_add_result(amxc_var_t* retval, const char* obj_path, uint32_t err_code) {
    amxc_var_t* result = amxc_var_add(amxc_htable_t, retval, NULL);
    amxc_var_add_key(cstring_t, result, "object_path", obj_path);
    amxc_var_add_key(uint32_t, result, "status", err_code);
}

static void amxa_validate_operate_impl(amxb_bus_ctx_t* ctx,
                                       amxd_path_t* cmd_path,
                                       amxc_var_t* resolved,
                                       const char* function,
                                       const char* acl_file,
                                       amxc_var_t* retval) {
    int ret = -1;
    char* fixed_part = NULL;
    amxc_var_t* acls = NULL;
    const char* obj_path = amxd_path_get(cmd_path, AMXD_OBJECT_TERMINATE);

    acls = amxa_parse_files(acl_file);
    when_null_do(acls, exit, amxa_operate_add_result(retval, obj_path, amxd_status_permission_denied));
    fixed_part = amxd_path_get_fixed_part(cmd_path, false);

    ret = amxa_resolve_search_paths(ctx, acls, fixed_part);
    when_failed_do(ret, exit, amxa_operate_add_result(retval, obj_path, amxd_status_permission_denied));

    if(resolved == NULL) {
        if(!amxa_is_operate_allowed(ctx, acls, obj_path, function)) {
            amxa_operate_add_result(retval, obj_path, amxd_status_permission_denied);
        } else {
            amxa_operate_add_result(retval, obj_path, amxd_status_ok);
        }
    } else {
        amxc_var_for_each(entry, resolved) {
            const char* instance_path = amxc_var_constcast(cstring_t, entry);
            if(!amxa_is_operate_allowed(ctx, acls, instance_path, function)) {
                amxa_operate_add_result(retval, instance_path, amxd_status_permission_denied);
            } else {
                amxa_operate_add_result(retval, instance_path, amxd_status_ok);
            }
        }
    }

exit:
    amxc_var_delete(&acls);
    free(fixed_part);
}

static void amxa_validate_operate_search_path(amxb_bus_ctx_t* ctx,
                                              amxd_path_t* search_path,
                                              const char* method,
                                              const char* acl_file,
                                              amxc_var_t* retval) {
    amxc_var_t resolved;
    amxc_var_init(&resolved);
    amxb_resolve(ctx, search_path, &resolved);
    if(amxc_var_type_of(&resolved) == AMXC_VAR_ID_NULL) {
        if(!amxa_command_is_supported(ctx, amxd_path_get(search_path, AMXD_OBJECT_TERMINATE), method)) {
            amxa_operate_add_result(retval, amxd_path_get(search_path, AMXD_OBJECT_TERMINATE), amxd_status_not_supported);
        } else {
            amxa_operate_add_result(retval, amxd_path_get(search_path, AMXD_OBJECT_TERMINATE), amxd_status_object_not_found);
        }
        goto exit;
    }
    amxa_validate_operate_impl(ctx, search_path, &resolved, method, acl_file, retval);

exit:
    amxc_var_clean(&resolved);
}

amxc_var_t* amxa_validate_operate(amxb_bus_ctx_t* ctx,
                                  const char* acl_file,
                                  const char* obj_path,
                                  const char* method) {
    amxc_var_t* retval = NULL;
    amxd_path_t path;

    amxd_path_init(&path, obj_path);
    amxc_var_new(&retval);

    when_null(ctx, exit);
    when_str_empty(acl_file, exit);
    when_str_empty(obj_path, exit);
    when_str_empty(method, exit);

    amxc_var_set_type(retval, AMXC_VAR_ID_LIST);

    if(amxd_path_is_search_path(&path)) {
        amxa_validate_operate_search_path(ctx, &path, method, acl_file, retval);
    } else {
        if(!amxa_object_is_instantiated(ctx, obj_path)) {
            if(!amxa_command_is_supported(ctx, obj_path, method)) {
                amxa_operate_add_result(retval, obj_path, amxd_status_not_supported);
            } else {
                amxa_operate_add_result(retval, obj_path, amxd_status_object_not_found);
            }
            goto exit;
        }
        amxa_validate_operate_impl(ctx, &path, NULL, method, acl_file, retval);
    }

exit:
    if(amxc_var_type_of(retval) == AMXC_VAR_ID_NULL) {
        amxc_var_set_type(retval, AMXC_VAR_ID_LIST);
        amxa_operate_add_result(retval, obj_path, amxd_status_unknown_error);
    }
    amxd_path_clean(&path);
    return retval;
}
