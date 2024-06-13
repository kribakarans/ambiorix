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
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "mod_lua.h"

/***
   Ambiorix LUA Data Model module
   @module lamx.dm
 */

typedef struct _mod_lua {
    amxd_dm_t* dm;
    amxo_parser_t* parser;
    lua_State* L;
} mod_lua_t;

static mod_lua_t mod;

static amxo_resolver_t lua_resolver = {
    .hit = { .ait = NULL, .key = NULL, .next = NULL },
    .get = NULL,
    .resolve = lua_fn_resolver,
    .clean = NULL,
    .priv = NULL
};

static int mod_lua_load_script(lua_State* L, const char* name, const char* script) {
    int retval = 0;
    struct stat sb;

    when_failed(stat(script, &sb), exit);

    if(luaL_loadfile(L, script) == 0) {
        if(lua_pcall(L, 0, 1, 0) != 0) {
            retval = 1;
            const char* msg = luaL_checkstring(L, 1);
            printf("ERROR: %s\n", msg);
            goto exit;
        }
        lua_setglobal(L, name);
    } else {
        const char* msg = luaL_checkstring(L, 1);
        printf("ERROR: %s\n", msg);
        retval = 1;
    }

exit:
    return retval;
}

static int mod_lua_init(amxd_dm_t* dm, amxo_parser_t* parser) {
    int retval = 0;
    amxc_string_t init_file;
    const char* cfg_dir = GET_CHAR(&parser->config, "cfg-dir");
    const char* name = GET_CHAR(&parser->config, "name");
    const char* init_script = GET_CHAR(&parser->config, "lua-script");
    mod.dm = dm;
    mod.parser = parser;

    amxc_string_init(&init_file, 0);

    lua_getglobal(mod.L, "lamx");
    if(lua_istable(mod.L, -1) != 1) {
        retval = -1;
        goto exit;
    }
    lua_settop(mod.L, 0);

    lua_pushstring(mod.L, MOD_LUA_AMX_DM);
    lua_pushlightuserdata(mod.L, dm);
    lua_settable(mod.L, LUA_REGISTRYINDEX);

    lua_pushstring(mod.L, MOD_LUA_AMX_PARSER);
    lua_pushlightuserdata(mod.L, parser);
    lua_settable(mod.L, LUA_REGISTRYINDEX);

    if((init_script != NULL) && (*init_script != 0)) {
        retval = mod_lua_load_script(mod.L, name, init_script);
    } else {
        amxc_string_setf(&init_file, "%s/%s/%s.lua", cfg_dir, name, name);
        retval = mod_lua_load_script(mod.L, name, amxc_string_get(&init_file, 0));
    }

exit:
    amxc_string_clean(&init_file);
    return retval;
}

lua_State* mod_lua_get_lua_state(void) {
    return mod.L;
}

int _mod_lua_main(int reason,
                  amxd_dm_t* dm,
                  amxo_parser_t* parser) {
    int retval = 0;
    switch(reason) {
    case 0:     // START
        retval = mod_lua_init(dm, parser);
        break;
    case 1:     // STOP
        mod.dm = NULL;
        mod.parser = NULL;
        break;
    }

    return retval;
}

CONSTRUCTOR_LVL(110) static int lua_resolver_init(void) {
    int rv = 0;
    mod.L = luaL_newstate();
    luaL_openlibs(mod.L);

    lua_pushstring(mod.L, MOD_LUA_AMX_FNS);
    lua_newtable(mod.L);
    lua_settable(mod.L, LUA_REGISTRYINDEX);

    rv += luaL_dostring(mod.L, "lamx = require 'lamx'");
    rv += luaL_dostring(mod.L, "lamx['eventloop']=nil");
    rv += luaL_dostring(mod.L, "lamx['dm'].create=nil");
    rv += luaL_dostring(mod.L, "lamx['dm'].destroy=nil");
    rv += luaL_dostring(mod.L, "lamx['bus'].register=nil");

    lua_settop(mod.L, 0);

    amxo_register_resolver("LUA", &lua_resolver);

    return rv;
}

DESTRUCTOR_LVL(110) static void lua_resolver_cleanup(void) {
    amxo_unregister_resolver("LUA");
    lua_close(mod.L);
}
