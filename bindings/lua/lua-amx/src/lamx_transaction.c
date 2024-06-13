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

/***
   Ambiorix LUA Data Model Transaction Class.

   A data model transaction performs a set of actions in sequence on the local
   data model.

   The sequence of actions done by the transaction can be considered "atomic".
   Either all actions succeed or none are executed.

   When the transaction completed successful, events are emitted.

   @classmod dmtransaction
 */

/***
   Selects the active data model object.

   A transaction performs actions on a data model object. This method selects
   the data model object on which the actions must be performed.

   When providing a data model path, it may be absolute or relative. When using
   a relative path, it must start with a "." (dot). Use "^" to go up in the
   data model hierarchy.

   @usage
   local transaction = lamx.transaction.new()
   transaction:select("Greeter.")

   @function dmtransaction:select

   @param object either a string containing the data model object path or a
   data model object instance (see @{dmobject})
 */
static int dm_transaction_select(lua_State* L) {
    lamx_dm_transaction_t* dm_transaction = (lamx_dm_transaction_t*) luaL_checkudata(L, 1, lamx_transaction_mt);
    const char* path = NULL;

    if(lua_isstring(L, 2) == 1) {
        path = luaL_checkstring(L, 2);
    } else {
        lamx_dm_object_t* dm_object = (lamx_dm_object_t*) luaL_checkudata(L, 2, lamx_object_mt);
        path = dm_object->path;
    }
    amxd_trans_select_pathf(dm_transaction->transaction, "%s", path);

    return 0;
}

/***
   Sets a parameter value of the selected data model object.

   @usage
   local transaction = lamx.transaction.new()
   transaction:select("Greeter.")
   transaction:set("MaxHistory", 20)

   @function dmtransaction:set

   @param parameter_name Name of the parameter of the data model object
   @param value The value that needs to be set
 */
static int dm_transaction_set(lua_State* L) {
    lamx_dm_transaction_t* dm_transaction = (lamx_dm_transaction_t*) luaL_checkudata(L, 1, lamx_transaction_mt);
    const char* param_name = luaL_checkstring(L, 2);
    amxc_var_t value;

    amxc_var_init(&value);
    lamx_lua2var(L, 3, &value);

    amxd_trans_set_param(dm_transaction->transaction, param_name, &value);

    amxc_var_clean(&value);
    return 0;
}

/***
   Adds a data model object instance.

   The selected data model object must be a multi-instance object.

   The newly created instance becomes the selected data model object.

   @usage
   local transaction = lamx.transaction.new()
   transaction:select("Greeter.History.")
   transaction:add_instance()
   transaction:set("From", "Me")
   transaction:set("Message", "Hello World")
   transaction:set("Retain", false)

   @function dmtransaction:add_instance

   @param index (optional) The index for the new instance (must be unique)
   @param name (optional) The name for the new instance (must be unique). If
   the an "Alias" parameter is defined, the name is set as the value for the
   "Alias" parameter.
 */
static int dm_transaction_add_inst(lua_State* L) {
    int nr_args = lua_gettop(L);
    lamx_dm_transaction_t* dm_transaction = (lamx_dm_transaction_t*) luaL_checkudata(L, 1, lamx_transaction_mt);
    lua_Integer index = nr_args >= 2 ? lua_tointeger(L, 2) : 0;
    const char* name = nr_args >= 3 ? luaL_checkstring(L, 3) : NULL;

    amxd_trans_add_inst(dm_transaction->transaction, index, name);

    return 0;
}

/***
   Deletes a data model object instance.

   The selected data model object must be a multi-instance object.

   Either an index or a name must be provided.

   @raise error invalid arguments when no index or no name is provided.

   @usage
   local transaction = lamx.transaction.new()
   transaction:select("Greeter.History.")
   transaction:del_instance(1)

   @function dmtransaction:del_instance

   @param index (optional) The index for the new instance (must be unique)
   @param name (optional) The name for the new instance (must be unique). If
   the an "Alias" parameter is defined, the name is set as the value for the
   "Alias" parameter.
 */
static int dm_transaction_del_inst(lua_State* L) {
    int nr_args = lua_gettop(L);
    lamx_dm_transaction_t* dm_transaction = (lamx_dm_transaction_t*) luaL_checkudata(L, 1, lamx_transaction_mt);
    lua_Integer index = nr_args >= 2 ? lua_tointeger(L, 2) : 0;
    const char* name = nr_args >= 3 ? luaL_checkstring(L, 3) : NULL;

    if((index == 0) && (name == NULL)) {
        luaL_error(L, "Invalid arguments, specify index or name");
    }
    amxd_trans_del_inst(dm_transaction->transaction, index, name);

    return 0;
}

/***
   Adds a mib to the selected object

   @usage
   local transaction = lamx.transaction.new()
   transaction:select("Greeter.History.1.")
   transaction:add_mib("info")

   @function dmtransaction:add_mib

   @param name The name of the mib.
 */
static int dm_transaction_add_mib(lua_State* L) {
    lamx_dm_transaction_t* dm_transaction = (lamx_dm_transaction_t*) luaL_checkudata(L, 1, lamx_transaction_mt);
    const char* name = luaL_checkstring(L, 2);

    amxd_trans_add_mib(dm_transaction->transaction, name);

    return 0;
}

/***
   Apply the transaciton.

   Performs all actions set in the transaction.

   When all actions are successful, events will be emitted.

   @usage
   local transaction = lamx.transaction.new()
   transaction:select("Greeter.History.")
   transaction:del_instance(1)
   if transaction:apply() ~= 0 then
       print("Failed to apply transaction")
   end

   @function dmtransaction:apply

   @return
   0 when transaction was applied successful.
 */
static int dm_transaction_apply(lua_State* L) {
    lamx_dm_transaction_t* dm_transaction = (lamx_dm_transaction_t*) luaL_checkudata(L, 1, lamx_transaction_mt);
    amxd_dm_t* dm = lamx_get_dm(L);
    amxd_status_t status = amxd_status_ok;

    status = amxd_trans_apply(dm_transaction->transaction, dm);

    lua_pushinteger(L, status);

    return 1;
}

// lua meta-table implementation
static lua_CFunction mod_lua_is_function(const char* name) {
    lua_CFunction fn = NULL;

    static struct luaL_Reg dm_trans_funcs[] = {
        {"select", dm_transaction_select},
        {"set", dm_transaction_set},
        {"add_instance", dm_transaction_add_inst},
        {"del_instance", dm_transaction_del_inst},
        {"add_mib", dm_transaction_add_mib},
        {"apply", dm_transaction_apply},
        {NULL, NULL}
    };

    fn = lamx_get_function(dm_trans_funcs, name);

    return fn;
}

static int lamx_transaction_mt_index(lua_State* L) {
    //lamx_dm_transaction_t* dm_transaction = (lamx_dm_transaction_t*) luaL_checkudata(L, 1, lamx_transaction_mt);
    const char* name = luaL_checkstring(L, 2);
    lua_CFunction fn = NULL;
    int args = 1;

    fn = mod_lua_is_function(name);
    if(fn != NULL) {
        lua_pushcfunction(L, fn);
    } else {
        luaL_error(L, "Failed to fetch '%s'", name);
    }

    return args;
}

static int lamx_transaction_mt_gc(lua_State* L) {
    lamx_dm_transaction_t* dm_transaction
        = (lamx_dm_transaction_t*) luaL_checkudata(L, 1, lamx_transaction_mt);
    amxd_trans_delete(&dm_transaction->transaction);
    return 0;
}

/***
   Create a new transaction

   @usage
   local transaction = lamx.transaction.new()

   @function lamx.transaction.new

   @param set_read_only (optional, default = false) When set to true, the
   transaction can change read-only parameters.
   @param access (optional, default = "public"). Sets the access level of the
   transaction. This can be "public", "protected", "private" and indicates which
   parameters can be changed.

   @return
   Data Model transaction class instance.
 */
static int lamx_transaction_new(lua_State* L) {
    int args = lua_gettop(L);
    lamx_dm_transaction_t* dm_transaction = NULL;
    bool set_read_only = false;
    const char* access = args >= 2 ? luaL_checkstring(L, 2) : NULL;

    if(args >= 1) {
        luaL_checktype(L, 1, LUA_TBOOLEAN);
        set_read_only = lua_toboolean(L, 1);
    }

    dm_transaction = (lamx_dm_transaction_t*) lua_newuserdata(L,
                                                              sizeof(lamx_dm_transaction_t));
    luaL_getmetatable(L, lamx_transaction_mt);
    lua_setmetatable(L, -2);
    amxd_trans_new(&dm_transaction->transaction);
    amxd_trans_set_attr(dm_transaction->transaction, amxd_tattr_change_ro, set_read_only);
    if(access == NULL) {
        amxd_trans_set_attr(dm_transaction->transaction, amxd_tattr_change_pub, true);
    } else if(strcmp(access, "protected") == 0) {
        amxd_trans_set_attr(dm_transaction->transaction, amxd_tattr_change_prot, true);
    } else if(strcmp(access, "private") == 0) {
        amxd_trans_set_attr(dm_transaction->transaction, amxd_tattr_change_priv, true);
    } else {
        amxd_trans_set_attr(dm_transaction->transaction, amxd_tattr_change_pub, true);
    }

    return 1;
}

void lamx_push_transaction_mt(lua_State* L) {
    if(luaL_newmetatable(L, lamx_transaction_mt)) {
        static struct luaL_Reg metamethods[] = {
            {"__index", lamx_transaction_mt_index},
            {"__gc", lamx_transaction_mt_gc},
            {NULL, NULL}
        };

        luaL_setfuncs(L, metamethods, 0);
        lua_pop(L, 1);  // The table is saved in the Lua's registry.
    }

    static struct luaL_Reg fns[] = {
        {"new", lamx_transaction_new},
        {NULL, NULL}
    };

    luaL_newlib(L, fns);  // Push a new table with fns key/vals.
    lua_setfield(L, -2, "transaction");

}