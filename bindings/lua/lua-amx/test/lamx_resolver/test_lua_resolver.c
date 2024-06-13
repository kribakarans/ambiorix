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
#include <sys/signalfd.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>

#include <stdlib.h>
#include <stdio.h>
#include <setjmp.h>
#include <stdarg.h>
#include <cmocka.h>
#include <string.h>

#include <amxc/amxc.h>
#include <amxp/amxp.h>
#include <amxd/amxd_dm.h>
#include <amxo/amxo.h>
#include <amxb/amxb_register.h>

#include "lua_amx.h"

#include "../mocks/dummy_be.h"
#include "../mocks/test_common.h"

#include "test_lua_resolver.h"

static lua_State* L;

static amxo_resolver_t lua_resolver = {
    .hit = { .ait = NULL, .key = NULL, .next = NULL },
    .get = NULL,
    .resolve = lua_fn_resolver,
    .clean = NULL,
    .priv = NULL
};

int test_lamx_setup(UNUSED void** state) {
    L = luaL_newstate();
    set_lua_state(L);

    luaL_openlibs(L);
    lua_pushstring(L, MOD_LUA_AMX_FNS);
    lua_newtable(L);
    lua_settable(L, LUA_REGISTRYINDEX);

    luaopen_lamx(L);

    lua_setglobal(L, "lamx");
    amxo_register_resolver("LUA", &lua_resolver);

    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "lamx.dm.create()"));

    return 0;
}

int test_lamx_teardown(UNUSED void** state) {
    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "lamx.dm.destroy()"));

    amxo_unregister_resolver("LUA");
    lua_close(L);
    set_lua_state(NULL);

    return 0;
}

void test_can_resolve_functions(UNUSED void** state) {
    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "lamx.dm.load(\"../test_data/odl/lua_resolver.odl\")"));
}

void test_can_call_rpc_lua_function(UNUSED void** state) {
    amxc_var_t args;
    amxc_var_t ret;

    amxd_dm_t* dm = lamx_get_dm(L);
    amxd_object_t* object = NULL;

    assert_non_null(dm);

    object = amxd_dm_findf(dm, "MyObject");
    assert_non_null(object);

    amxc_var_init(&args);
    amxc_var_init(&ret);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &args, "text", "HELLO");
    assert_int_equal(amxd_object_invoke_function(object, "myfunction", &args, &ret), 0);
    amxc_var_dump(&ret, STDOUT_FILENO);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &args, "text", "HELLO");
    assert_int_not_equal(amxd_object_invoke_function(object, "errorfunction", &args, &ret), 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&args);
}

void test_can_call_event_lua_function(UNUSED void** state) {
    amxd_dm_t* dm = lamx_get_dm(L);
    amxd_trans_t trans;

    amxd_trans_init(&trans);
    amxd_trans_select_pathf(&trans, "MyObject.");
    amxd_trans_set_value(cstring_t, &trans, "MyParam", "Test");
    amxd_trans_apply(&trans, dm);

    handle_events();

    amxd_trans_clean(&trans);
}
