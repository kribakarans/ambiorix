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
#include <string.h>

#include <amxc/amxc_macros.h>
#include <amxc/amxc.h>
#include <amxm/amxm.h>

#define MOD_SESSION "fcgi-session"

static amxc_var_t sessions;

static int dummy_check_credentials(UNUSED const char* const function_name,
                                   amxc_var_t* args,
                                   amxc_var_t* ret) {
    if((strcmp(GET_CHAR(args, "httpaccess"), "UserInterface.HTTPAccess.1.") == 0) &&
       (strcmp(GET_CHAR(args, "username"), "admin") == 0) &&
       (strcmp(GET_CHAR(args, "password"), "admin") == 0)) {
        amxc_var_add_key(uint32_t, args, "LoginAttempts", 3);
        amxc_var_set(int32_t, ret, 0);
    } else {
        amxc_var_set(int32_t, ret, 400);
    }

    return 0;
}

static int dummy_create_session(UNUSED const char* const function_name,
                                amxc_var_t* args,
                                amxc_var_t* ret) {
    int status = 0;
    const char* username = GET_CHAR(args, "username");
    const char* ip = GET_CHAR(args, "ip");
    amxc_var_t* session = NULL;

    amxc_var_set_type(ret, AMXC_VAR_ID_HTABLE);
    when_false_status(strcmp(username, "admin") == 0, exit, status = 400);

    session = amxc_var_get_key(&sessions, ip, AMXC_VAR_FLAG_DEFAULT);
    if(session == NULL) {
        amxc_var_add_key(cstring_t, &sessions, ip, "J86mD3vA8hjFblCBaJUyggmcFXCbGr9RAeptigBVSRZXi7cDPOoZRsARgnkR1UwH");
        amxc_var_add_key(cstring_t, ret, "session_id", "J86mD3vA8hjFblCBaJUyggmcFXCbGr9RAeptigBVSRZXi7cDPOoZRsARgnkR1UwH");
    } else {
        amxc_var_add_key(cstring_t, ret, "session_id", GET_CHAR(session, NULL));
    }

exit:
    return status;
}

static int dummy_delete_session(UNUSED const char* const function_name,
                                amxc_var_t* args,
                                UNUSED amxc_var_t* ret) {
    int status = 0;
    const char* session_id = GET_CHAR(args, "session_id");
    const char* ip = GET_CHAR(args, "ip");
    amxc_var_t* stored_session = GET_ARG(&sessions, ip);
    const char* stored_session_id = GET_CHAR(stored_session, NULL);

    when_str_empty(session_id, exit);
    when_str_empty(ip, exit);
    when_str_empty(stored_session_id, exit);
    when_false(strcmp(stored_session_id, session_id) == 0, exit);

    amxc_var_delete(&stored_session);

exit:
    return status;
}

static int dummy_is_valid_session(UNUSED const char* const function_name,
                                  amxc_var_t* args,
                                  amxc_var_t* ret) {
    int status = -1;
    const char* session_id = GET_CHAR(args, "id");
    const char* ip = GET_CHAR(args, "ip");
    const char* stored_session_id = GET_CHAR(&sessions, ip);

    when_null(stored_session_id, exit);
    if(strcmp(session_id, stored_session_id) == 0) {
        amxc_var_set(bool, ret, true);
        status = 0;
    }

exit:
    if(status != 0) {
        amxc_var_set(bool, ret, false);
    }
    return status;
}

static int dummy_get_acl_role(UNUSED const char* const function_name,
                              UNUSED amxc_var_t* args,
                              amxc_var_t* ret) {
    amxc_var_add(cstring_t, ret, "admin");
    return 0;
}

static AMXM_CONSTRUCTOR session_dummy_start(void) {
    amxm_module_t* mod = NULL;
    amxm_shared_object_t* so = amxm_so_get_current();
    amxc_var_init(&sessions);
    amxc_var_set_type(&sessions, AMXC_VAR_ID_HTABLE);

    amxm_module_register(&mod, so, MOD_SESSION);
    amxm_module_add_function(mod, "check_credentials", dummy_check_credentials);
    amxm_module_add_function(mod, "create_session", dummy_create_session);
    amxm_module_add_function(mod, "delete_session", dummy_delete_session);
    amxm_module_add_function(mod, "is_valid_session", dummy_is_valid_session);
    amxm_module_add_function(mod, "get_acl_role", dummy_get_acl_role);

    return 0;
}

static AMXM_DESTRUCTOR session_dummy_stop(void) {
    amxc_var_clean(&sessions);

    return 0;
}
