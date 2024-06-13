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

#include "lua_amx.h"

typedef struct _lamx_subscription {
    amxb_subscription_t* subscription;
    lua_State* L;
} lamx_subscription_t;

static int lamx_subscription_mt_gc(lua_State* L) {
    lamx_subscription_t* amx_sub = (lamx_subscription_t*) luaL_checkudata(L, 1, lamx_subscription_mt);
    amxb_subscription_delete(&amx_sub->subscription);
    return 0;
}

static void lamx_bus_event_handler(UNUSED const char* const sig_name,
                                   const amxc_var_t* const data,
                                   void* const priv) {
    lamx_subscription_t* amx_sub = (lamx_subscription_t*) priv;
    amxc_var_t event_data;
    amxc_var_t* event_name = NULL;

    amxc_var_init(&event_data);
    amxc_var_copy(&event_data, data);
    event_name = GET_ARG(&event_data, "notification");
    amxc_var_take_it(event_name);

    lua_settop(amx_sub->L, 0);
    lua_pushlightuserdata(amx_sub->L, (void*) amx_sub);
    lua_gettable(amx_sub->L, LUA_REGISTRYINDEX);

    // push event name
    lua_pushstring(amx_sub->L, GET_CHAR(event_name, NULL));
    // push event data
    lamx_var2lua(&event_data, amx_sub->L);

    // call the function
    if(lua_pcall(amx_sub->L, 2, 0, 0) != 0) {
        lamx_lua_stack_dump(amx_sub->L);
    }

    amxc_var_delete(&event_name);
    amxc_var_clean(&event_data);
    lua_settop(amx_sub->L, 0);
}

int lamx_bus_subscribe(lua_State* L) {
    int nr_args = lua_gettop(L);
    const char* path = luaL_checkstring(L, 1);
    const char* filter = nr_args >= 3 ? luaL_checkstring(L, 3) : NULL;

    amxb_bus_ctx_t* ctx = NULL;
    amxd_path_t obj_path;
    char* p = NULL;

    if(!lua_isfunction(L, 2)) {
        luaL_error(L, "Expected function, got %s", luaL_typename(L, 2));
    }

    amxd_path_init(&obj_path, NULL);

    amxd_path_setf(&obj_path, false, "%s", path);
    p = amxd_path_get_fixed_part(&obj_path, false);

    ctx = amxb_be_who_has(p);
    if(ctx == NULL) {
        amxd_path_clean(&obj_path);
        free(p);
        luaL_error(L, "%s not found", path);
    } else {
        lamx_subscription_t* amx_sub = (lamx_subscription_t*) lua_newuserdata(L, sizeof(lamx_subscription_t));
        luaL_getmetatable(L, lamx_subscription_mt);
        lua_setmetatable(L, -2);
        amx_sub->L = L;

        lua_pushlightuserdata(L, (void*) amx_sub);
        lua_pushvalue(L, 2);   // put function on top of stack
        lua_settable(L, LUA_REGISTRYINDEX);

        amxb_subscription_new(&amx_sub->subscription, ctx,
                              p, filter,
                              lamx_bus_event_handler, amx_sub);

        amxd_path_clean(&obj_path);
        free(p);
    }

    return 1;
}

void lamx_push_subscription_fns(lua_State* L) {
    if(luaL_newmetatable(L, lamx_subscription_mt)) {
        static struct luaL_Reg metamethods[] = {
            {"__gc", lamx_subscription_mt_gc},
            {NULL, NULL}
        };

        luaL_setfuncs(L, metamethods, 0);
        lua_pop(L, 1);  // The table is saved in the Lua's registry.
    }
}
