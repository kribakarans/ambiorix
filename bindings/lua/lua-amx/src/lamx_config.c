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
   Ambiorix LUA config module
   @module lamx.config
 */

/***
   Get a configuration option.

   Get a configuration option.

   Configuration options are often defined in the odl file in the %config section.

   @raise error the configuration option doesn't exist

   @usage
   local lamx = require 'lamx'

   lamx.dm.create()

   lamx.config.set("MyTable.MyKey1", "Some Data")
   lamx.config.set("MyTable.MyKey2", 101)

   cfg_opt = lamx.config.get("MyTable")
   table.dump(cfg_opt)

   lamx.dm.destroy()

   @function lamx.config.get

   @param path Config option path.
 */
static int lamx_config_get(lua_State* L) {
    const char* path = luaL_checkstring(L, 1);
    amxo_parser_t* parser = lamx_get_parser(L);
    amxc_var_t* config = NULL;
    amxc_var_t* ret = NULL;

    if(parser != NULL) {
        config = &parser->config;
    } else {
        lua_pushstring(L, MOD_LUA_AMX_CONFIG);
        lua_gettable(L, LUA_REGISTRYINDEX);

        config = (amxc_var_t*) lua_touserdata(L, -1);
    }

    ret = amxc_var_get_path(config, path, AMXC_VAR_FLAG_DEFAULT);
    if(ret == NULL) {
        luaL_error(L, "%s not found", path);
    }

    lamx_var2lua(ret, L);

    return 1;
}

/***
   Set a configuration option.

   A data model must be created before configuration options can be used.
   Configuration options are often defined in the odl file in the %config section.

   If the option doesn't exists, it will be added.

   @raise error not found if no data model is available

   @usage
   local lamx = require 'lamx'

   lamx.dm.create()

   lamx.config.set("MyTable.MyKey1", "Some Data")
   lamx.config.set("MyTable.MyKey2", 101)

   cfg_opt = lamx.config.get("MyTable")
   table.dump(cfg_opt)

   lamx.dm.destroy()

   @function lamx.config.set

   @param path Config option path.
   @param value The new value.
 */
static int lamx_config_set(lua_State* L) {
    int nr_args = lua_gettop(L);
    const char* path = luaL_checkstring(L, 1);
    amxo_parser_t* parser = lamx_get_parser(L);
    amxc_var_t* config = NULL;
    amxc_var_t value;

    if(parser != NULL) {
        config = &parser->config;
    } else {
        lua_pushstring(L, MOD_LUA_AMX_CONFIG);
        lua_gettable(L, LUA_REGISTRYINDEX);

        config = (amxc_var_t*) lua_touserdata(L, -1);
    }

    if(nr_args < 2) {
        luaL_error(L, "No value provided for %s", path);
    }

    amxc_var_init(&value);
    lamx_lua2var(L, 2, &value);

    amxc_var_set_path(config, path, &value, AMXC_VAR_FLAG_UPDATE | AMXC_VAR_FLAG_AUTO_ADD);

    amxc_var_clean(&value);

    return 0;
}

/***
   Dump all configuration options.

   Dump all configuration options to stdout.

   @usage
   local lamx = require 'lamx'

   lamx.config.set("MyTable.MyKey1", "Some Data")
   lamx.config.set("MyTable.MyKey2", 101)

   lamx.config.dump()

   @function lamx.config.dump

 */
static int lamx_config_dump(lua_State* L) {
    amxo_parser_t* parser = lamx_get_parser(L);
    amxc_var_t* config = NULL;

    if(parser != NULL) {
        config = &parser->config;
    } else {
        lua_pushstring(L, MOD_LUA_AMX_CONFIG);
        lua_gettable(L, LUA_REGISTRYINDEX);

        config = (amxc_var_t*) lua_touserdata(L, -1);
    }

    amxc_var_dump(config, STDOUT_FILENO);

    return 0;
}

void lamx_push_config_fns(lua_State* L) {
    static struct luaL_Reg fns[] = {
        {"get", lamx_config_get},
        {"set", lamx_config_set},
        {"dump", lamx_config_dump},
        {NULL, NULL}
    };

    luaL_newlib(L, fns);  // Push a new table with fns key/vals.
    lua_setfield(L, -2, "config");
}
