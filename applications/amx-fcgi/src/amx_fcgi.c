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
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <stdlib.h>

#include "amx_fcgi.h"

#define SOCKET_BACKLOG 10
#define SOCKET_NAME    "/var/run/amx-fcgi.sock"
#define SESSION_CTRL   "session-httpaccess"

static amx_fcgi_t amx_fcgi;

static int amx_fcgi_load_session_crtl(const char* session_ctrl) {
    amxc_string_t mod_path;
    int rv = -1;
    amxm_shared_object_t* so = NULL;

    amxc_string_init(&mod_path, 0);
    amxc_string_setf(&mod_path, "${mod-path}/mod-%s.so", session_ctrl);
    amxc_string_resolve_var(&mod_path, &amx_fcgi.parser->config);

    rv = amxm_so_open(&so, session_ctrl, amxc_string_get(&mod_path, 0));

    amxc_string_clean(&mod_path);
    return rv;
}

static int amx_fcgi_init(amxd_dm_t* dm, amxo_parser_t* parser) {
    int retval = 0;
    const char* socket_name = NULL;
    const char* group_name = NULL;
    const char* user_name = NULL;
    amxc_var_t* session_ctrl = NULL;
    const char* str_session_ctrl = NULL;
    struct group* group_info = NULL;
    struct passwd* user_info = NULL;

    amx_fcgi.dm = dm;
    amx_fcgi.parser = parser;

    socket_name = GET_CHAR(amx_fcgi_get_conf_opt("fcgi-socket"), NULL);
    group_name = GET_CHAR(amx_fcgi_get_conf_opt("groupname"), NULL);
    user_name = GET_CHAR(amx_fcgi_get_conf_opt("username"), NULL);
    session_ctrl = amx_fcgi_get_conf_opt("session-ctrl");

    if(session_ctrl == NULL) {
        session_ctrl = amxc_var_add_key(cstring_t, &amx_fcgi.parser->config, "session-ctrl", SESSION_CTRL);
    }
    str_session_ctrl = GET_CHAR(session_ctrl, NULL);
    if((str_session_ctrl == NULL) || (*str_session_ctrl == 0)) {
        amxc_var_set(cstring_t, session_ctrl, SESSION_CTRL);
        str_session_ctrl = SESSION_CTRL;
    }

    if((socket_name == NULL) || (*socket_name == 0)) {
        socket_name = SOCKET_NAME;
    }

    retval = amx_fcgi_load_session_crtl(str_session_ctrl);
    when_failed(retval, exit);

    retval = EINVAL;
    when_str_empty(group_name, exit);
    group_info = getgrnam(group_name);
    when_str_empty(user_name, exit);
    user_info = getpwnam(user_name);
    when_null(group_info, exit);
    when_null(user_info, exit);
    when_failed(setgid(group_info->gr_gid), exit);
    when_failed(setuid(user_info->pw_uid), exit);

    retval = FCGX_Init();
    when_failed(retval, exit);

    amx_fcgi.socket = FCGX_OpenSocket(socket_name, SOCKET_BACKLOG);
    if(amx_fcgi.socket == -1) {
        retval = EINVAL;
    }

    amxc_llist_init(&amx_fcgi.requests);

    amxo_connection_add(parser, amx_fcgi.socket, amx_fcgi_handle, NULL, AMXO_CUSTOM, NULL);

exit:
    return retval;
}

static int amx_fcgi_clean(void) {
    const char* socket_name = GETP_CHAR(&amx_fcgi.parser->config, "fcgi-socket");

    if((socket_name == NULL) || (*socket_name == 0)) {
        socket_name = SOCKET_NAME;
    }

    amx_fcgi.dm = NULL;
    amx_fcgi.parser = NULL;

    amxc_llist_clean(&amx_fcgi.requests, amx_fcgi_finish_request);

    close(amx_fcgi.socket);
    OS_LibShutdown();

    unlink(socket_name);

    amxm_close_all();

    return 0;
}

amx_fcgi_t* amx_fcgi_get_app_data(void) {
    return &amx_fcgi;
}

amxc_var_t* amx_fcgi_get_conf_opt(const char* name) {
    return GETP_ARG(&amx_fcgi.parser->config, name);
}

int _amx_fcgi_main(int reason,
                   amxd_dm_t* dm,
                   amxo_parser_t* parser) {
    int retval = 0;
    switch(reason) {
    case 0: // START
        retval = amx_fcgi_init(dm, parser);
        break;
    case 1: // STOP
        retval = amx_fcgi_clean();
        break;
    }

    return retval;
}