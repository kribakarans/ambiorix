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

/***
   Ambiorix LUA Data Model Parameter Class.

   Data model parameters have a LUA representation.

   <ul>
   <li>@{dmparameter:get_owner}</li>
   <li>@{dmparameter:get_type}</li>
   <li>@{dmparameter:get_value}</li>
   <li>@{dmparameter:set_value}</li>
   <li>@{dmparameter:get_name}</li>
   </ul>

   Object parameters can be read or set using the LUA index notation.
   When set using the index notation, no change event is emitted.

   @classmod dmparameter
 */

/***
   Get owner object of parameter.

   @raise error when object represented by object class instance is not in data model anymore.

   @usage
   function(dm_param)
       local dm_object = dm_param:get_owner()
       print("Onwer object = " .. dm_object:get_path())
   end

   @function dmparameter:get_owner

   @return
   Data Model object class instance
 */
static int dm_param_get_owner(lua_State* L) {
    lamx_dm_param_t* dm_param = (lamx_dm_param_t*) luaL_checkudata(L, 1, lamx_param_mt);
    amxd_dm_t* dm = lamx_get_dm(L);
    amxd_object_t* obj = amxd_dm_findf(dm, "%s", dm_param->path);

    lamx_push_object(L, obj);

    return 1;
}

/***
   Get parameter type name

   @raise error when object represented by object class instance is not in data model anymore.

   @usage
   function(dm_param)
       print("Onwer object = " .. dm_param:get_type())
   end

   @function dmparameter:get_type

   @return
   Data model parameter type name
 */
static int dm_param_get_type(lua_State* L) {
    lamx_dm_param_t* dm_param = (lamx_dm_param_t*) luaL_checkudata(L, 1, lamx_param_mt);
    amxd_dm_t* dm = lamx_get_dm(L);
    amxd_object_t* obj = amxd_dm_findf(dm, "%s", dm_param->path);
    amxd_param_t* param = amxd_object_get_param_def(obj, dm_param->name);

    lua_pushstring(L, amxc_var_get_type_name_from_id(amxd_param_get_type(param)));

    return 1;
}

/***
   Get parameter value

   @raise error when object represented by object class instance is not in data model anymore.

   @usage
   function(dm_param)
       print("Parameter value = " .. tostring(dm_param:get_value()))
   end

   @function dmparameter:get_value

   @return
   Data model parameter value
 */
static int dm_param_get_value(lua_State* L) {
    lamx_dm_param_t* dm_param = (lamx_dm_param_t*) luaL_checkudata(L, 1, lamx_param_mt);
    amxd_dm_t* dm = lamx_get_dm(L);
    amxd_object_t* obj = amxd_dm_findf(dm, "%s", dm_param->path);
    amxd_param_t* param = amxd_object_get_param_def(obj, dm_param->name);

    lamx_var2lua(&param->value, L);

    return 1;
}

/***
   Set parameter value

   @raise error when object represented by object class instance is not in data model anymore or
          when parameter represented by parameter class instance is not in data model anymore.

   Setting the parameter value using this method will bypass the parameter value
   validation.

   @usage
   function(dm_param, value)
       dm_param:set_value(value);
   end

   @param value The new value that needs to be set.

   @function dmparameter:set_value
 */
static int dm_param_set_value(lua_State* L) {
    lamx_dm_param_t* dm_param = (lamx_dm_param_t*) luaL_checkudata(L, 1, lamx_param_mt);
    amxd_dm_t* dm = lamx_get_dm(L);
    amxd_object_t* obj = amxd_dm_findf(dm, "%s", dm_param->path);
    amxd_param_t* param = amxd_object_get_param_def(obj, dm_param->name);
    amxc_var_t new_value;

    luaL_checkany(L, 2);

    amxc_var_init(&new_value);

    lamx_lua2var(L, 2, &new_value);
    amxc_var_convert(&param->value, &new_value, amxd_param_get_type(param));
    amxc_var_clean(&new_value);

    return 0;
}

/***
   Get parameter name

   @raise error when object represented by object class instance is not in data model anymore.

   @usage
   function(dm_param)
       print("Onwer object = " .. dm_param:get_type())
   end

   @function dmparameter:get_name

   @return
   Data model parameter name or an emty string if parameter is not found
 */
static int dm_param_get_name(lua_State* L) {
    lamx_dm_param_t* dm_param = (lamx_dm_param_t*) luaL_checkudata(L, 1, lamx_param_mt);
    amxd_dm_t* dm = lamx_get_dm(L);
    amxd_object_t* obj = amxd_dm_findf(dm, "%s", dm_param->path);
    amxd_param_t* param = amxd_object_get_param_def(obj, dm_param->name);

    lua_pushstring(L, amxd_param_get_name(param));

    return 1;
}

// lua parameter meta-table implementation
static lua_CFunction lamx_is_param_function(const char* name) {
    lua_CFunction fn = NULL;

    static struct luaL_Reg dm_param_funcs[] = {
        {"get_owner", dm_param_get_owner},
        {"get_type", dm_param_get_type},
        {"get_value", dm_param_get_value},
        {"set_value", dm_param_set_value},
        {"get_name", dm_param_get_name},
        {NULL, NULL}
    };

    fn = lamx_get_function(dm_param_funcs, name);

    return fn;
}

static int dm_param_mt_index(lua_State* L) {
    lamx_dm_param_t* dm_param = (lamx_dm_param_t*) luaL_checkudata(L, 1, lamx_param_mt);
    const char* name = luaL_checkstring(L, 2);
    amxd_dm_t* dm = lamx_get_dm(L);
    amxd_object_t* obj = amxd_dm_findf(dm, "%s", dm_param->path);
    amxd_param_t* param = amxd_object_get_param_def(obj, dm_param->name);
    lua_CFunction fn = NULL;

    if(obj == NULL) {
        luaL_error(L, "Object not found '%s'", dm_param->path);
    }
    if(param == NULL) {
        luaL_error(L, "Parameter not found '%s%s'", dm_param->path, dm_param->name);
    }

    fn = lamx_is_param_function(name);
    if(fn != NULL) {
        lua_pushcfunction(L, fn);
    } else {
        luaL_error(L, "Invalid function for parameter '%s%s'", dm_param->path, dm_param->name);
    }

    return 1;
}

static int dm_param_mt_gc(lua_State* L) {
    lamx_dm_param_t* dm_param = (lamx_dm_param_t*) luaL_checkudata(L, 1, lamx_param_mt);
    free(dm_param->path);
    free(dm_param->name);
    return 0;
}

void lamx_push_param_mt(lua_State* L) {
    if(luaL_newmetatable(L, lamx_param_mt)) {
        static struct luaL_Reg metamethods[] = {
            {"__index", dm_param_mt_index},
            {"__gc", dm_param_mt_gc},
            {NULL, NULL}
        };

        luaL_setfuncs(L, metamethods, 0);
        lua_pop(L, 1);  // The table is saved in the Lua's registry.
    }
}