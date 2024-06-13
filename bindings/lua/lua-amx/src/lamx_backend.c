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

#include "lua_amx.h"

/***
   Ambiorix LUA Backend module
   @module lamx.backend
 */

/***
   Loads a bus specific backend.

   If the back-end was already loaded, the call to this method has not effect.

   @function lamx.backend.load

   @raise error when so file is not found or could not be loaded

   @usage
   lamx.backend.load("/usr/bin/mods/amxb/mod-amxb-ubus.so")

   @param sofile absolute or relative path to back-end so file
 */
static int lamx_be_load(lua_State* L) {
    const char* so_file = luaL_checkstring(L, 1);
    int rv = -1;

    rv = amxb_be_load(so_file);
    if(rv != 0) {
        luaL_error(L, "Failed to load backend %s (rv = %d)", so_file, rv);
    }

    return 0;
}

/***
   Removes a bus specific backend.

   When a back-end is removed, all open connections made with this back-end are
   closed.

   @function lamx.backend.remove

   @raise error when no loaded back-end is found with given name

   @usage
   lamx.backend.load("/usr/bin/mods/amxb/mod-amxb-ubus.so")

   @param name name of the back-end that must be unloaded
 */
static int lamx_be_remove(lua_State* L) {
    const char* be_name = luaL_checkstring(L, 1);
    int rv = -1;

    rv = amxb_be_remove(be_name);
    if(rv != 0) {
        luaL_error(L, "Failed to remove backend %s (rv = %d)", be_name, rv);
    }

    return 0;
}

/***
   Push config options to loaded backends.

   When backends are loaded the backend-specific configuration options
   can be pushed. It is recommended to call this before creating a connection.

   When used without argument, the loaded data model config is pushed, if any
   available.

   When providing a table the values of the key matching the name of the backend
   is pushed to the backend.

   @function lamx.backend.push_config

   @usage
   local lamx = require 'lamx'

   amx.backend.load("/usr/bin/mods/amxb/mod-amxb-ubus.so")
   amx.backend.load("/usr/bin/mods/amxb/mod-amxb-pcb.so")

   amx.backend.push_config({ ubus = { watch_events = true }, pcb = { register_name = "lua" }})

   @param config (optional)table containing config options.
 */
static int lamx_be_push_config(lua_State* L) {
    int nr_args = lua_gettop(L);
    amxo_parser_t* parser = lamx_get_parser(L);
    amxc_var_t* cfg = NULL;

    if(nr_args == 0) {
        if(parser != NULL) {
            amxb_set_config(&parser->config);
            return 0;
        }
    }

    lua_pushstring(L, MOD_LUA_AMX_CONFIG);
    lua_gettable(L, LUA_REGISTRYINDEX);

    cfg = (amxc_var_t*) lua_touserdata(L, -1);
    if(nr_args != 0) {
        luaL_checktype(L, 1, LUA_TTABLE);
        amxc_var_clean(cfg);
        lamx_lua2var(L, 1, cfg);
    }

    amxb_set_config(cfg);

    lua_pushstring(L, MOD_LUA_AMX_CONFIG);
    lua_pushlightuserdata(L, cfg);
    lua_settable(L, LUA_REGISTRYINDEX);

    return 0;
}

void lamx_push_be_fns(lua_State* L) {
    static struct luaL_Reg fns[] = {
        {"load", lamx_be_load},
        {"remove", lamx_be_remove},
        {"push_config", lamx_be_push_config},
        {NULL, NULL}
    };

    luaL_newlib(L, fns);  // Push a new table with fns key/vals.
    lua_setfield(L, -2, "backend");
}
