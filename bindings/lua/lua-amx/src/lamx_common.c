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

#include <stdlib.h>
#include <string.h>

#include "lua_amx.h"

void lamx_lua_stack_dump(lua_State* L) {
    int i = lua_gettop(L);
    printf(" ----------------  Stack Dump ----------------\n");
    while(i) {
        int t = lua_type(L, i);
        switch(t) {
        case LUA_TSTRING:
            printf("%d:`%s'\n", i, lua_tostring(L, i));
            break;
        case LUA_TBOOLEAN:
            printf("%d: %s\n", i, lua_toboolean(L, i) ? "true" : "false");
            break;
        case LUA_TNUMBER:
            printf("%d: %g\n", i, lua_tonumber(L, i));
            break;
        default:
            printf("%d: %s\n", i, lua_typename(L, t));
            break;
        }
        i--;
    }
    printf("--------------- Stack Dump Finished ---------------\n");
    fflush(stdout);
}

// adds userdata dm object to top of stack
int lamx_push_object(lua_State* L, amxd_object_t* object) {
    lamx_dm_object_t* dm_object = NULL;

    dm_object = (lamx_dm_object_t*) lua_newuserdata(L, sizeof(lamx_dm_object_t));
    luaL_getmetatable(L, lamx_object_mt);
    lua_setmetatable(L, -2);
    dm_object->path = amxd_object_get_path(object, AMXD_OBJECT_INDEXED | AMXD_OBJECT_TERMINATE);

    return 1;
}

int lamx_push_param(lua_State* L, amxd_param_t* param) {
    lamx_dm_param_t* dm_param = NULL;

    dm_param = (lamx_dm_param_t*) lua_newuserdata(L, sizeof(lamx_dm_param_t));
    luaL_getmetatable(L, lamx_param_mt);
    lua_setmetatable(L, -2);
    dm_param->path = amxd_object_get_path(amxd_param_get_owner(param), AMXD_OBJECT_INDEXED | AMXD_OBJECT_TERMINATE);
    dm_param->name = strdup(amxd_param_get_name(param));

    return 1;
}

amxb_bus_ctx_t* lamx_get_ctx(const char* path) {
    amxb_bus_ctx_t* ctx = NULL;
    amxd_path_t obj_path;
    char* p = NULL;

    amxd_path_init(&obj_path, path);
    p = amxd_path_get_fixed_part(&obj_path, false);
    ctx = amxb_be_who_has(p);

    free(p);
    amxd_path_clean(&obj_path);
    return ctx;
}

amxd_dm_t* lamx_get_dm(lua_State* L) {
    amxd_dm_t* dm = NULL;
    lua_pushstring(L, MOD_LUA_AMX_DM);
    lua_gettable(L, LUA_REGISTRYINDEX);

    if(lua_islightuserdata(L, -1) == 1) {
        dm = (amxd_dm_t*) lua_touserdata(L, -1);
    }

    lua_pop(L, 1);

    return dm;
}

amxo_parser_t* lamx_get_parser(lua_State* L) {
    amxo_parser_t* parser = NULL;
    lua_pushstring(L, MOD_LUA_AMX_PARSER);
    lua_gettable(L, LUA_REGISTRYINDEX);

    if(lua_islightuserdata(L, -1) == 1) {
        parser = (amxo_parser_t*) lua_touserdata(L, -1);
    }

    lua_pop(L, 1);

    return parser;
}

lua_CFunction lamx_get_function(struct luaL_Reg* fns, const char* name) {
    int i = 0;
    lua_CFunction fn = NULL;

    while(fns[i].name != NULL) {
        if(strcmp(name, fns[i].name) == 0) {
            fn = fns[i].func;
            break;
        }
        i++;
    }

    return fn;
}