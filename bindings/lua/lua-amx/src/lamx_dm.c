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

#include "lua_amx.h"

static void config_add_dir(amxc_var_t* var_dirs, const char* dir) {
    bool found = false;
    const amxc_llist_t* dirs = amxc_var_constcast(amxc_llist_t, var_dirs);

    amxc_llist_for_each(it, dirs) {
        amxc_var_t* var_dir = amxc_var_from_llist_it(it);
        const char* stored_dir = amxc_var_constcast(cstring_t, var_dir);
        if((stored_dir != NULL) && (strcmp(dir, stored_dir) == 0)) {
            found = true;
            break;
        }
    }

    if(!found) {
        amxc_var_add(cstring_t, var_dirs, dir);
    }
}

static void lamx_config_set_default_dirs(amxo_parser_t* parser) {
    amxc_var_t* inc_dirs = amxo_parser_claim_config(parser, COPT_INCDIRS);
    amxc_var_t* lib_dirs = amxo_parser_claim_config(parser, COPT_LIBDIRS);
    amxc_var_t* mib_dirs = amxo_parser_claim_config(parser, COPT_MIBDIRS);

    config_add_dir(inc_dirs, ".");
    config_add_dir(inc_dirs, "${prefix}${cfg-dir}/${name}");
    config_add_dir(inc_dirs, "${prefix}${cfg-dir}/modules");

    config_add_dir(lib_dirs, "${prefix}${plugin-dir}/${name}");
    config_add_dir(lib_dirs, "${prefix}${plugin-dir}/modules");
    config_add_dir(lib_dirs, "${prefix}/usr/local/lib/amx/${name}");
    config_add_dir(lib_dirs, "${prefix}/usr/local/lib/amx/modules");

    config_add_dir(mib_dirs, "${prefix}${cfg-dir}/${name}/mibs");

    amxc_var_add_key(cstring_t, &parser->config, COPT_PLUGIN_DIR, PLUGIN_DIR);
}

/***
   Ambiorix LUA Data Model module
   @module lamx.dm
 */

/***
   Search object in the local data model.

   When multiple matching objects are found, this function fails.

   @raise error when no data model available

   @usage
   function(dm_object, args)
       local obj = lamx.dm.find("MyObject.Info.1.")
       print("MyParam = " .. tostring(obj.MyParam))
   end

   @function lamx.dm.find

   @param path data model object path. This path can be a a search path or an object path.
   This path must be an absolute path.

   @return
   Data Model object class instance or nil when object not found or multiple available
 */
static int lamx_dm_find(lua_State* L) {
    const char* path = luaL_checkstring(L, 1);
    amxd_dm_t* dm = lamx_get_dm(L);
    amxd_object_t* obj = amxd_dm_findf(dm, "%s", path);

    if(dm == NULL) {
        luaL_error(L, "No data model available, did you forget to call dm.create()");
    }

    if(obj == NULL) {
        lua_pushnil(L);
    } else {
        lamx_push_object(L, obj);
    }

    return 1;
}

/***
   Loads one or more odl files.

   Before loading an odl file a data model must be created.

   @raise error when no data model or odl parser available or when failed to load odl file.

   @usage
   lamx.dm.load("/etc/amx/greeter/greeter.odl")

   @param path Path to a directory containing odl files or a single odl file.

   @function lamx.dm.load
 */
static int lamx_dm_load(lua_State* L) {
    const char* path = luaL_checkstring(L, 1);
    amxd_dm_t* dm = lamx_get_dm(L);
    amxo_parser_t* parser = lamx_get_parser(L);
    amxd_object_t* root = amxd_dm_get_root(dm);

    if((dm == NULL) || (parser == NULL)) {
        luaL_error(L, "No data model or odl parser available, did you forget to call dm.create()");
    }

    if(amxo_parser_parse_file(parser, path, root) != 0) {
        amxc_var_dump(&parser->config, STDOUT_FILENO);
        luaL_error(L, "Failed to load '%s'", path);
    }

    return 0;
}

/***
   Saves persistent objects and parameters to odl file.

   @raise error when no data model or odl parser available or when failed to data model to odl file.

   @usage
   lamx.dm.save("/tmp/greeter_saved.odl")

   @param file Filename of the file where data must be stored
   @param object Object that nust be saved

   @function lamx.dm.save
 */
static int lamx_dm_save(lua_State* L) {
    const char* filename = luaL_checkstring(L, 1);
    const char* path = luaL_checkstring(L, 2);
    amxd_dm_t* dm = lamx_get_dm(L);
    amxo_parser_t* parser = lamx_get_parser(L);
    amxd_object_t* object = amxd_dm_findf(dm, "%s", path);

    if((dm == NULL) || (parser == NULL)) {
        luaL_error(L, "No data model or odl parser available, did you forget to call dm.create()");
    }

    if(amxo_parser_save_object(parser, filename, object, false) != 0) {
        amxc_var_dump(&parser->config, STDOUT_FILENO);
        luaL_error(L, "Failed to save object '%s' in file '%s'", path, filename);
    }

    return 0;
}

/***
   Creates a data model.

   Only one data model can be created. If it was already created this method
   has no effect.

   Optionaly a directory path containing odl files or an odl file can be passed,
   the odl files in the directory or the given odl file wil be loaded.

   Data model definition (odl files) can be loaded after creating the data model
   using lamx.dm.load

   A data model can be made public by registering it on a bus system, using
   lamx.bus.register

   @raise error when data model was already created or when failed to load odl file.

   @usage
   lamx.dm.create()

   @param path (optional) Directory or odl file.

   @function lamx.dm.create
 */
static int lamx_dm_create(lua_State* L) {
    amxd_dm_t* dm = NULL;
    amxo_parser_t* parser = NULL;
    amxc_var_t* config = NULL;

    lua_pushstring(L, MOD_LUA_AMX_CONFIG);
    lua_gettable(L, LUA_REGISTRYINDEX);

    config = (amxc_var_t*) lua_touserdata(L, -1);

    dm = lamx_get_dm(L);
    if(dm != NULL) {
        luaL_error(L, "Data model was already created.");
    }

    amxd_dm_new(&dm);
    amxo_parser_new(&parser);

    lua_pushstring(L, MOD_LUA_AMX_DM);
    lua_pushlightuserdata(L, dm);
    lua_settable(L, LUA_REGISTRYINDEX);

    lua_pushstring(L, MOD_LUA_AMX_PARSER);
    lua_pushlightuserdata(L, parser);
    lua_settable(L, LUA_REGISTRYINDEX);

    // Move LUA registry config options to parser config options
    amxc_var_for_each(opt, config) {
        amxc_var_set_key(&parser->config, amxc_var_key(opt), opt, AMXC_VAR_FLAG_DEFAULT);
    }

    lamx_config_set_default_dirs(parser);

    if(lua_isstring(L, 1) == 1) {
        lamx_dm_load(L);
    }

    lua_settop(L, 0);

    return 0;
}

/***
   Destroys a data model.

   Destroys a previously created data model. If the data model was registerd
   to bus system(s), it will be unregistered automatically.

   @usage
   lamx.dm.destroy()

   @function lamx.dm.destroy
 */
static int lamx_dm_destroy(lua_State* L) {
    amxd_dm_t* dm = lamx_get_dm(L);
    amxo_parser_t* parser = lamx_get_parser(L);

    amxo_parser_delete(&parser);
    amxd_dm_delete(&dm);

    lua_pushstring(L, MOD_LUA_AMX_DM);
    lua_pushnil(L);
    lua_settable(L, LUA_REGISTRYINDEX);

    lua_pushstring(L, MOD_LUA_AMX_PARSER);
    lua_pushnil(L);
    lua_settable(L, LUA_REGISTRYINDEX);

    return 0;
}

void lamx_push_dm_mt(lua_State* L) {
    static struct luaL_Reg fns[] = {
        {"find", lamx_dm_find},
        {"create", lamx_dm_create},
        {"destroy", lamx_dm_destroy},
        {"load", lamx_dm_load},
        {"save", lamx_dm_save},
        {NULL, NULL}
    };

    luaL_newlib(L, fns);  // Push a new table with fns key/vals.
    lua_setfield(L, -2, "dm");
}