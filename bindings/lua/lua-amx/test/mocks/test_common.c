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

/****************************************************************************
**
** Copyright (c) 2020 SoftAtHome
**
** Redistribution and use in source and binary forms, with or
** without modification, are permitted provided that the following
** conditions are met:
**
** 1. Redistributions of source code must retain the above copyright
** notice, this list of conditions and the following disclaimer.
**
** 2. Redistributions in binary form must reproduce the above
** copyright notice, this list of conditions and the following
** disclaimer in the documentation and/or other materials provided
** with the distribution.
**
** Subject to the terms and conditions of this license, each
** copyright holder and contributor hereby grants to those receiving
** rights under this license a perpetual, worldwide, non-exclusive,
** no-charge, royalty-free, irrevocable (except for failure to
** satisfy the conditions of this license) patent license to make,
** have made, use, offer to sell, sell, import, and otherwise
** transfer this software, where such license applies only to those
** patent claims, already acquired or hereafter acquired, licensable
** by such copyright holder or contributor that are necessarily
** infringed by:
**
** (a) their Contribution(s) (the licensed copyrights of copyright
** holders and non-copyrightable additions of contributors, in
** source or binary form) alone; or
**
** (b) combination of their Contribution(s) with the work of
** authorship to which such Contribution(s) was added by such
** copyright holder or contributor, if, at the time the Contribution
** is added, such addition causes such combination to be necessarily
** infringed. The patent license shall not apply to any other
** combinations which include the Contribution.
**
** Except as expressly stated above, no rights or licenses from any
** copyright holder or contributor is granted under this license,
** whether expressly, by implication, estoppel or otherwise.
**
** DISCLAIMER
**
** THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
** CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
** INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
** MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
** DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR
** CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
** SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
** LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
** USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
** AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
** LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
** ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
** POSSIBILITY OF SUCH DAMAGE.
**
****************************************************************************/

#include <sys/signalfd.h>
#include <stdlib.h>
#include <signal.h>
#include <stdio.h>
#include <setjmp.h>
#include <stdarg.h>
#include <cmocka.h>
#include <string.h>

#include <amxc/amxc_macros.h>
#include <amxc/amxc.h>
#include <amxp/amxp.h>
#include <amxd/amxd_dm.h>
#include <amxo/amxo.h>
#include <amxb/amxb.h>

#include "test_common.h"

static lua_State* lua_state = NULL;

static void* lua_get_func(lua_State* L, const char* type) {
    void* fn = NULL;

    lua_pushstring(L, type);
    lua_gettable(L, LUA_REGISTRYINDEX);

    fn = lua_touserdata(L, -1);

    lua_pop(L, 1);

    return fn;
}

static amxo_fn_ptr_t lua_action_fn_resolver(lua_State* L,
                                            amxo_parser_t* parser,
                                            const char* fn_name) {
    amxo_fn_ptr_t fn = NULL;

    // When using LUA to implement actions, the function name is set as data.
    // Only validate actions (3) are supported in LUA
    amxc_var_t* action = GET_ARG(&parser->config, "_current_action");
    when_null(action, exit);
    when_false(GET_UINT32(action, NULL) == 3, exit); // only validate actions

    amxc_var_new(&parser->data);
    amxc_var_set(cstring_t, parser->data, fn_name);

    fn = AMXO_FUNC(lua_get_func(L, MOD_LUA_AMX_ACTION_FUNC));
    if(fn != NULL) {
        amxd_dm_t* dm = amxd_object_get_dm(parser->object);
        if(dm != NULL) {
            lua_pushstring(L, MOD_LUA_AMX_DM);
            lua_pushlightuserdata(L, dm);
            lua_settable(L, LUA_REGISTRYINDEX);
        }
    }

exit:
    return fn;
}

amxo_fn_ptr_t lua_fn_resolver(UNUSED amxo_parser_t* parser,
                              const char* fn_name,
                              amxo_fn_type_t type,
                              const char* data,
                              UNUSED void* priv) {
    amxo_fn_ptr_t fn = NULL;
    amxc_string_t fn_str;

    amxc_string_init(&fn_str, 0);

    when_str_empty(data, exit);
    when_false((type == amxo_function_rpc ||
                type == amxo_function_event ||
                type == amxo_function_action), exit);

    lua_pushstring(lua_state, MOD_LUA_AMX_FNS);
    lua_gettable(lua_state, LUA_REGISTRYINDEX);
    amxc_string_setf(&fn_str, "return %s", data);

    if(luaL_dostring(lua_state, amxc_string_get(&fn_str, 0))) {
        printf("Lua error\n");
    } else {
        lua_setfield(lua_state, -2, fn_name);
        if(type == amxo_function_rpc) {
            fn = AMXO_FUNC(lua_get_func(lua_state, MOD_LUA_AMX_RPC_FUNC));
        } else if(type == amxo_function_event) {
            fn = AMXO_FUNC(lua_get_func(lua_state, MOD_LUA_AMX_EVENT_FUNC));
        } else if(type == amxo_function_action) {
            fn = lua_action_fn_resolver(lua_state, parser, fn_name);
        }
    }

exit:
    amxc_string_clean(&fn_str);
    lua_settop(lua_state, 0);
    return fn;
}

void set_lua_state(lua_State* L) {
    lua_state = L;
}

void handle_events(void) {
    printf("Handling events ");
    while(amxp_signal_read() == 0) {
        printf(".");
    }
    printf("\n");
}

void read_sigalrm(void) {
    sigset_t mask;
    int sfd;
    struct signalfd_siginfo fdsi;
    ssize_t s;

    sigemptyset(&mask);
    sigaddset(&mask, SIGALRM);

    sigprocmask(SIG_BLOCK, &mask, NULL);

    sfd = signalfd(-1, &mask, 0);
    s = read(sfd, &fdsi, sizeof(struct signalfd_siginfo));
    assert_int_equal(s, sizeof(struct signalfd_siginfo));
    if(fdsi.ssi_signo == SIGALRM) {
        printf("Got SIGALRM\n");
        amxp_timers_calculate();
        amxp_timers_check();
    } else {
        printf("Read unexpected signal\n");
    }
}

void block_sigalrm(void) {
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGALRM);

    sigprocmask(SIG_BLOCK, &mask, NULL);
}
