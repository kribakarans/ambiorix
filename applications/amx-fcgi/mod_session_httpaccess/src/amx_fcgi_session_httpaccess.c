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
#include <syslog.h>

#include <amxc/amxc_macros.h>
#include <amxc/amxc.h>
#include <amxm/amxm.h>
#include <amxp/amxp.h>
#include <amxd/amxd_types.h>
#include <amxb/amxb.h>
#include <debug/sahtrace.h>
#include <debug/sahtrace_macros.h>

#define MOD_SESSION "fcgi-session"

#define USERINTERFACE_OBJECT_PATH "UserInterface."
#define CHECK_CREDENTIALS_FOR_ACCESS_RPC "CheckCredentialsForAccess"
#define CREATE_WEB_SESSION_RPC "CreateWebSession"
#define CHECK_VALID_SESSION_RPC "CheckSessionValid"

static int httpaccess_check_credentials(UNUSED const char* const function_name,
                                        amxc_var_t* args,
                                        amxc_var_t* ret) {
    int status = 400;
    amxc_var_t result;
    uint32_t old_access = 0;
    amxb_bus_ctx_t* ctx = amxb_be_who_has(USERINTERFACE_OBJECT_PATH);
    amxc_var_t* result_ht = NULL;

    amxc_var_init(&result);

    when_null_status(ctx, exit, status = 503);
    old_access = ctx->access;
    amxb_set_access(ctx, AMXB_PROTECTED);

    when_failed(amxb_call(ctx, USERINTERFACE_OBJECT_PATH, CHECK_CREDENTIALS_FOR_ACCESS_RPC, args, &result, 1), exit);
    result_ht = amxc_var_get_first(&result);

    when_null(result_ht, exit);
    when_null(GET_ARG(result_ht, "Allowed"), exit);
    status = (GET_BOOL(result_ht, "Allowed")) ? 0 : 400;

    if(GET_ARG(result_ht, "LoginAttempts")) {
        amxc_var_add_key(uint32_t, args, "LoginAttempts", GET_UINT32(result_ht, "LoginAttempts"));
    }

exit:
    if(ctx != NULL) {
        amxb_set_access(ctx, old_access);
    }
    amxc_var_set(int32_t, ret, status);
    amxc_var_clean(&result);
    return 0;
}

static int httpaccess_create_session(UNUSED const char* const function_name,
                                     amxc_var_t* args,
                                     amxc_var_t* ret) {
    int status = 0;
    uint32_t old_access = 0;
    amxb_bus_ctx_t* ctx = amxb_be_who_has(USERINTERFACE_OBJECT_PATH);
    amxc_string_t dm_user_path;
    const char* username = GET_CHAR(args, "username");
    const char* httpaccess = GET_CHAR(args, "httpaccess");
    amxc_var_t result;

    amxc_var_init(&result);
    amxc_string_init(&dm_user_path, 0);

    when_null_status(ctx, exit, status = 503);
    when_null_status(username, exit, status = 503);
    when_null_status(httpaccess, exit, status = 503);

    old_access = ctx->access;
    amxb_set_access(ctx, AMXB_PROTECTED);

    amxc_string_setf(&dm_user_path, "Users.User.[Username==\"%s\"].", username);
    when_failed_status(amxc_var_push(cstring_t,
                                     amxc_var_add_new_key(args, "user"),
                                     amxc_string_take_buffer(&dm_user_path)),
                       exit, status = 500);
    when_failed_status(amxb_call(ctx, httpaccess, CREATE_WEB_SESSION_RPC, args, &result, 1),
                       exit, status = 500);

    amxc_var_move(ret, GETI_ARG(&result, 0));

exit:
    if(ctx != NULL) {
        amxb_set_access(ctx, old_access);
    }
    amxc_var_clean(&result);
    amxc_string_clean(&dm_user_path);
    return status;
}

static int httpaccess_delete_session(UNUSED const char* const function_name,
                                     amxc_var_t* args,
                                     UNUSED amxc_var_t* ret) {
    amxc_string_t dm_session_path;
    int status = 200;
    amxb_bus_ctx_t* ctx = amxb_be_who_has(USERINTERFACE_OBJECT_PATH);
    const char* httpaccess = GET_CHAR(args, "httpaccess");
    const char* session_id = GET_CHAR(args, "session_id");

    uint32_t old_access = 0;
    amxc_var_t funcargs;
    amxc_var_t result;

    amxc_var_init(&funcargs);
    amxc_var_init(&result);
    amxc_string_init(&dm_session_path, 0);

    when_null_status(ctx, exit, status = 503);
    old_access = ctx->access;
    amxb_set_access(ctx, AMXB_PROTECTED);

    when_failed(amxc_var_set_type(&funcargs, AMXC_VAR_ID_HTABLE), exit);
    amxc_string_setf(&dm_session_path, "%sSession.[ID==\"%s\"].", httpaccess, session_id);
    amxb_call(ctx, amxc_string_get(&dm_session_path, 0), "Delete", &funcargs, &result, 1);
    status = 0;

exit:
    if(ctx != NULL) {
        amxb_set_access(ctx, old_access);
    }
    amxc_var_clean(&funcargs);
    amxc_var_clean(&result);
    amxc_string_clean(&dm_session_path);

    return status;
}

static int httpaccess_is_valid_session(UNUSED const char* const function_name,
                                       amxc_var_t* args,
                                       UNUSED amxc_var_t* ret) {
    int status = -1;
    amxc_var_t result;

    amxc_var_t* http_access = GET_ARG(args, "httpaccess");
    amxb_bus_ctx_t* ctx = amxb_be_who_has(USERINTERFACE_OBJECT_PATH);
    uint32_t old_access = AMXB_PUBLIC;

    amxc_var_init(&result);

    when_null(ctx, exit);

    amxc_var_take_it(http_access);
    old_access = ctx->access;
    amxb_set_access(ctx, AMXB_PROTECTED);
    when_failed(amxb_call(ctx, GET_CHAR(http_access, NULL), CHECK_VALID_SESSION_RPC, args, &result, 1), exit);
    status = (GETI_BOOL(&result, 0)) ? 0 : -1;

    amxc_var_move(ret, GETI_ARG(&result, 0));

exit:
    if(ctx != NULL) {
        amxb_set_access(ctx, old_access);
    }
    amxc_var_delete(&http_access);
    amxc_var_clean(&result);
    return status;
}

static int httpaccess_get_acl_role(UNUSED const char* const function_name,
                                   amxc_var_t* args,
                                   amxc_var_t* ret) {
    int rv = -1;
    const char* httpaccess = GET_CHAR(args, "httpaccess");
    const char* session_id = GET_CHAR(args, "session_id");
    amxb_bus_ctx_t* ctx = amxb_be_who_has(USERINTERFACE_OBJECT_PATH);
    uint32_t old_access = AMXB_PUBLIC;
    amxc_string_t path;
    amxc_var_t result;

    when_failed(amxc_string_init(&path, 0), exit);
    when_failed(amxc_var_init(&result), exit);

    when_null(ctx, exit);

    old_access = ctx->access;
    amxb_set_access(ctx, AMXB_PROTECTED);

    amxc_string_setf(&path, "%sSession.[ID==\"%s\"].", httpaccess, session_id);
    when_failed_trace(amxb_get(ctx, amxc_string_get(&path, 0), 0, &result, 0), exit, WARNING, "Couldn't get session infos from bus");
    when_str_empty_trace(GETP_CHAR(&result, "0.0.Roles"), exit, WARNING, "Couldn't find role for this session");
    amxc_var_convert(ret, GETP_ARG(&result, "0.0.Roles"), AMXC_VAR_ID_LIST);

    rv = 0;
exit:
    if(ctx != NULL) {
        amxb_set_access(ctx, old_access);
    }
    amxc_var_clean(&result);
    amxc_string_clean(&path);
    return rv;
}

static AMXM_CONSTRUCTOR session_httpaccess_start(void) {
    amxm_module_t* mod = NULL;

    amxm_shared_object_t* so = amxm_so_get_current();

    amxm_module_register(&mod, so, MOD_SESSION);
    amxm_module_add_function(mod, "check_credentials", httpaccess_check_credentials);
    amxm_module_add_function(mod, "create_session", httpaccess_create_session);
    amxm_module_add_function(mod, "delete_session", httpaccess_delete_session);
    amxm_module_add_function(mod, "is_valid_session", httpaccess_is_valid_session);
    amxm_module_add_function(mod, "get_acl_role", httpaccess_get_acl_role);

    return 0;
}
