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

/***
   Ambiorix LUA Data Model Object Class.

   Data model objects have a LUA representation. Depending on the object type
   some functions are available or not.

   All object types:
   <ul>
   <li>@{dmobject:get_parent}</li>
   <li>@{dmobject:find}</li>
   <li>@{dmobject:forall}</li>
   <li>@{dmobject:get_name}</li>
   <li>@{dmobject:get_path}</li>
   <li>@{dmobject:add_mib}</li>
   <li>@{dmobject:remove_mib}</li>
   <li>@{dmobject:send_changed}</li>
   <li>@{dmobject:get_parameter}</li>
   </ul>

   Multi-instance objects:
   <ul>
   <li>@{dmobject:add_instance}</li>
   <li>@{dmobject:del_instance}</li>
   <li>@{dmobject:instances}</li>
   <li>@{dmobject:get_instance_count}</li>
   </ul>

   Instance objects
   <ul>
   <li>@{dmobject:del}</li>
   <li>@{dmobject:get_index}</li>
   </ul>

   Object parameters can be read or set using the LUA index notation.
   When set using the index notation, no change event is emitted.

   @usage
   print("MyParam = " .. tostring(object["MyParam"])
   print("MyParam = " .. tostring(object.MyParam))
   object["MyParam"] = 123
   object.MyParam = 999

   Object methods can be called as a normal LUA method, the method arguments must
   be passed in a table

   @usage
   object:MyFunc({arg1 = "hello", arg2 = 10})

   @classmod dmobject
 */

static int dm_object_do(UNUSED amxd_object_t* object,
                        amxd_object_t* mobject,
                        void* priv) {
    lua_State* L = (lua_State*) priv;

    lua_pushvalue(L, 3);   // put function on top of stack

    // put matching object on top of stack
    lamx_push_object(L, mobject);

    // call the function
    lua_pcall(L, 1, 0, 0);

    return 0;
}

/***
   Gets the parent object.

   @raise error when object represented by object class instance is not in data model anymore.

   @usage
   function(dm_object, args)
       local parent = dm_object:get_parent()
   end

   @function dmobject:get_parent

   @return
   Data Model object class instance and nill if the object doesn't have a parent
 */
static int dm_object_get_parent(lua_State* L) {
    lamx_dm_object_t* dm_object = (lamx_dm_object_t*) luaL_checkudata(L, 1, lamx_object_mt);
    amxd_dm_t* dm = lamx_get_dm(L);
    amxd_object_t* obj = amxd_dm_findf(dm, "%s", dm_object->path);

    obj = amxd_object_get_parent(obj);
    if((obj == NULL) || (amxd_object_get_type(obj) == amxd_object_root)) {
        lua_pushnil(L);
    } else {
        lamx_push_object(L, obj);
    }

    return 1;
}

/***
   Get a child object.

   @raise error when object represented by object class instance is not in data model anymore.

   @usage
   function(dm_object, args)
       local parent = dm_object:find("SubObject.[MyNumber > 100].")
   end

   @function dmobject:find

   @param path relative data model object path. This path can be a search
   path or an object path and is relative to the current object.

   @return
   Data Model object class instance or nill when no object or multiple objects are found
 */
static int dm_object_find(lua_State* L) {
    lamx_dm_object_t* dm_object = (lamx_dm_object_t*) luaL_checkudata(L, 1, lamx_object_mt);
    const char* rel_path = luaL_checkstring(L, 2);
    amxd_dm_t* dm = lamx_get_dm(L);
    amxd_object_t* obj = amxd_dm_findf(dm, "%s", dm_object->path);

    obj = amxd_object_findf(obj, "%s", rel_path);
    if(obj == NULL) {
        lua_pushnil(L);
    } else {
        lamx_push_object(L, obj);
    }

    return 1;
}

/***
   Searches matching objects and call a function for each of them.

   @raise error when object represented by object class instance is not in data model anymore.
          or when function argument is not a function.

   @usage
   function(dm_object, args)
       dm_object:forall("SubObject.[MyNumber > 100].",
           function(matching_object)
               print(matching_object:get_path())
           end
       )
   end

   @function dmobject:forall

   @param path relative data model object path. This path can be a search
   path or an object path and is relative to the current object.
   @param function function that will be called for each found object
 */
static int dm_object_for_all(lua_State* L) {
    lamx_dm_object_t* dm_object = (lamx_dm_object_t*) luaL_checkudata(L, 1, lamx_object_mt);
    const char* rel_path = luaL_checkstring(L, 2);
    amxd_dm_t* dm = lamx_get_dm(L);
    amxd_object_t* obj = amxd_dm_findf(dm, "%s", dm_object->path);

    if(lua_isfunction(L, 3)) {
        amxd_object_for_all(obj, rel_path, dm_object_do, L);
    } else {
        luaL_error(L, "Expected function, got %s", luaL_typename(L, 3));
    }

    return 0;
}

/***
   Gets the name of the object.

   If the object is an instance object and it contains an "Alias" parameter,
   the value of the "Alias" parameter is returned as the name.

   If the object is an instance object without an "Alias" parameter it either
   returns the internal object name or the index as a string.

   @raise error when object represented by object class instance is not in data model anymore.

   @usage
   function(dm_object, args)
       print("Path = " .. dm_object:get_name())
   end

   @function dmobject:get_name

   @return
   The data model object name.
 */
static int dm_object_get_name(lua_State* L) {
    lamx_dm_object_t* dm_object = (lamx_dm_object_t*) luaL_checkudata(L, 1, lamx_object_mt);
    amxd_dm_t* dm = lamx_get_dm(L);
    amxd_object_t* obj = amxd_dm_findf(dm, "%s", dm_object->path);

    lua_pushstring(L, amxd_object_get_name(obj, AMXD_OBJECT_NAMED));

    return 1;
}

/***
   Gets the full path of the object.

   @usage
   function(dm_object, args)
       print("Path = " .. dm_object:get_path())
   end

   @function dmobject:get_path

   @return
   The absolute data model object path.
 */
static int dm_object_get_path(lua_State* L) {
    lamx_dm_object_t* dm_object = (lamx_dm_object_t*) luaL_checkudata(L, 1, lamx_object_mt);

    lua_pushstring(L, dm_object->path);

    return 1;
}

/***
   Adds a mib to the object.

   When the mib is not yet loaded in memory, it will load the mib from the
   odl file.

   @raise error when object represented by object class instance is not in data model anymore.
          or when failed to apply mib

   @usage
   function(dm_object, args)
       dm_object:add_mib("ipv4")
   end

   @function dmobject:add_mib

   @param name The mib name.
 */
static int dm_object_add_mib(lua_State* L) {
    lamx_dm_object_t* dm_object = (lamx_dm_object_t*) luaL_checkudata(L, 1, lamx_object_mt);
    const char* name = luaL_checkstring(L, 2);
    amxo_parser_t* parser = lamx_get_parser(L);
    amxd_dm_t* dm = lamx_get_dm(L);
    amxd_object_t* obj = amxd_dm_findf(dm, "%s", dm_object->path);
    int rv = 0;

    rv = amxo_parser_apply_mib(parser, obj, name);
    if(rv != 0) {
        luaL_error(L, "Failed to apply mib %s on %s (%d)", name, dm_object->path, rv);
    }

    return 0;
}

/***
   Removes a mib from the object.

   @raise error when object represented by object class instance is not in data model anymore.
          or when failed to remove mib

   @usage
   function(dm_object, args)
       dm_object:remove_mib("ipv4")
   end

   @function dmobject:remove_mib

   @param name The mib name.
 */
static int dm_object_remove_mib(lua_State* L) {
    lamx_dm_object_t* dm_object = (lamx_dm_object_t*) luaL_checkudata(L, 1, lamx_object_mt);
    const char* name = luaL_checkstring(L, 2);
    amxd_dm_t* dm = lamx_get_dm(L);
    amxd_object_t* obj = amxd_dm_findf(dm, "%s", dm_object->path);
    int rv = 0;

    rv = amxd_object_remove_mib(obj, name);
    if(rv != 0) {
        luaL_error(L, "Failed to remove mib %s from %s (%d)", name, dm_object->path, rv);
    }

    return 0;
}

/***
   Get a parameter definition.

   @raise error when object represented by object class instance is not in data model anymore.

   @usage
   function(dm_object, args)
       local parent = dm_object:get_parameter("Alias")
   end

   @function dmobject:get_parameter

   @param name Parameter name.

   @return
   Data Model parameter class instance or nil when parameter not found
 */
static int dm_object_get_param(lua_State* L) {
    lamx_dm_object_t* dm_object = (lamx_dm_object_t*) luaL_checkudata(L, 1, lamx_object_mt);
    const char* param_name = luaL_checkstring(L, 2);
    amxd_dm_t* dm = lamx_get_dm(L);
    amxd_object_t* obj = amxd_dm_findf(dm, "%s", dm_object->path);
    amxd_param_t* param = amxd_object_get_param_def(obj, param_name);

    if(param == NULL) {
        lua_pushnil(L);
    } else {
        lamx_push_param(L, param);
    }

    return 1;
}

/***
   Send a data model object changed event

   @raise error when object represented by object class instance is not in data model anymore.

   @usage
   function(dm_object, old_values)
       dm_object:send_changed(old_values)
   end

   @function dmobject:send_changed

   @param old_values table containing the old object values,
                     only changed values are included in the event

 */
static int dm_object_send_changed(lua_State* L) {
    lamx_dm_object_t* dm_object = (lamx_dm_object_t*) luaL_checkudata(L, 1, lamx_object_mt);
    amxd_dm_t* dm = lamx_get_dm(L);
    amxd_object_t* obj = amxd_dm_findf(dm, "%s", dm_object->path);
    amxc_var_t old_values;

    luaL_checkany(L, 2);

    amxc_var_init(&old_values);

    lamx_lua2var(L, 2, &old_values);

    amxd_object_send_changed(obj, &old_values, false);

    amxc_var_clean(&old_values);

    return 0;
}

/***
   Adds a new instance.

   Can only be called on multi-instance objects.

   @raise error when object represented by object class instance is not in data model anymore.

   @usage
   function(dm_object, args)
       dm_object:add_instance({MyParam = 123, MyString = "abc"})
   end

   @function dmobject:add_instance

   @param parameters (optional) A table containing parameter names and their values.
   @param index (optional) Index for the new instance.
   @param name (optional) Name for the new instance.

   @return
   Data Model object class instance or nil when failed to add the instance.
 */
static int dm_object_add_instance(lua_State* L) {
    int nr_args = lua_gettop(L);
    lamx_dm_object_t* dm_object = (lamx_dm_object_t*) luaL_checkudata(L, 1, lamx_object_mt);
    lua_Integer index = nr_args >= 3 ? lua_tointeger(L, 3) : 0;
    const char* name = nr_args >= 4 ? luaL_checkstring(L, 4) : NULL;
    amxc_var_t params;
    amxd_dm_t* dm = lamx_get_dm(L);
    amxd_object_t* obj = amxd_dm_findf(dm, "%s", dm_object->path);
    amxd_object_t* instance = NULL;
    amxd_status_t retval = amxd_status_unknown_error;

    amxc_var_init(&params);
    amxc_var_set_type(&params, AMXC_VAR_ID_HTABLE);
    if(nr_args >= 2) {
        luaL_checktype(L, 2, LUA_TTABLE);
        lamx_lua2var(L, 2, &params);
    }

    retval = amxd_object_add_instance(&instance, obj, name, index, &params);
    amxc_var_clean(&params);

    if(retval == amxd_status_ok) {
        lamx_push_object(L, instance);
    } else {
        lua_pushnil(L);
    }

    return 1;
}

/***
   Deletes an instance.

   Can only be called on multi-instance objects.

   @raise error when object represented by object class instance is not in data model anymore.

   @usage
   function(dm_object, args)
       dm_object:del_instance(5)
   end

   @function dmobject:del_instance

   @param index Index of the instance that must be deleted. Can be 0 if name is provided
   @param name (optional) Name of the instance that must be deleted.
 */

/***
   Deletes the instance.

   Can only be called on instance objects.

   After the call to this method, the LUA representation of the data model object
   can not be used anymore.

   @raise error when object represented by object class instance is not in data model anymore.

   @usage
   function(dm_object, args)
       local instance = dm_object:find("Info.1.")
       instance:del()
   end

   @function dmobject:del
 */

static int dm_object_del_instance(lua_State* L) {
    int nr_args = lua_gettop(L);
    lamx_dm_object_t* dm_object = (lamx_dm_object_t*) luaL_checkudata(L, 1, lamx_object_mt);
    amxd_dm_t* dm = lamx_get_dm(L);
    amxd_object_t* obj = amxd_dm_findf(dm, "%s", dm_object->path);

    if(amxd_object_get_type(obj) == amxd_object_template) {
        lua_Integer index = luaL_checkinteger(L, 2);
        const char* name = nr_args >= 3 ? luaL_checkstring(L, 3) : NULL;
        obj = amxd_object_get_instance(obj, name, index);
    } else {
        free(dm_object->path);
        dm_object->path = NULL;
    }

    amxd_object_delete(&obj);

    return 0;
}

static int dm_object_next_instance(lua_State* L) {
    lamx_dm_object_t* dm_object = (lamx_dm_object_t*) luaL_checkudata(L, 1, lamx_object_mt);
    amxd_dm_t* dm = lamx_get_dm(L);
    amxd_object_t* templ = amxd_dm_findf(dm, "%s", dm_object->path);
    amxd_object_t* instance = NULL;
    amxc_llist_it_t* it = NULL;

    if(lua_isnil(L, -1)) {
        it = amxd_object_first_instance(templ);
    } else {
        dm_object = (lamx_dm_object_t*) luaL_checkudata(L, -1, lamx_object_mt);
        instance = amxd_dm_findf(dm, "%s", dm_object->path);
        if(instance != NULL) {
            it = amxc_llist_it_get_next(&instance->it);
        }
    }
    lua_pop(L, 1);

    if(it != NULL) {
        instance = (amxd_object_t*) amxc_container_of(it, amxd_object_t, it);
        lamx_push_object(L, instance);
    } else {
        lua_pushnil(L);
    }

    return 1;
}

/***
   Instance interator.

   This method can only be used on multi-instance objects.


   @usage
   for instance in object:instances() do
       print(instance:get_name())
   end

   @function dmobject:instances

   @return
   Loop iterator
 */
static int dm_object_instances(lua_State* L) {
    lua_pushcfunction(L, dm_object_next_instance);
    lua_pushvalue(L, 1);
    lua_pushnil(L); // instance

    return 3;
}

/***
   Gets the number of instances created

   Can only be called on multi-instance objects.

   @raise error when object represented by object class instance is not in data model anymore.

   @usage
   function(dm_object)
       print(tostring(dm_object:get_instance_count()))
   end

   @function dmobject:get_instance_count

   @return
   Number of created instances
 */
static int dm_object_get_instance_count(lua_State* L) {
    lamx_dm_object_t* dm_object = (lamx_dm_object_t*) luaL_checkudata(L, 1, lamx_object_mt);
    amxd_dm_t* dm = lamx_get_dm(L);
    amxd_object_t* obj = amxd_dm_findf(dm, "%s", dm_object->path);

    lua_pushinteger(L, amxd_object_get_instance_count(obj));

    return 1;
}


/***
   Gets the index of the object.

   Only instance objects have an index.

   Will return 0 on all other types of objects.

   @raise error when object represented by object class instance is not in data model anymore.

   @usage
   function(dm_object, args)
       print("Path = " .. dm_object:get_index())
   end

   @function dmobject:get_index

   @return
   The data model object index.
 */
static int dm_object_get_index(lua_State* L) {
    lamx_dm_object_t* dm_object = (lamx_dm_object_t*) luaL_checkudata(L, 1, lamx_object_mt);
    amxd_dm_t* dm = lamx_get_dm(L);
    amxd_object_t* obj = amxd_dm_findf(dm, "%s", dm_object->path);

    lua_pushinteger(L, amxd_object_get_index(obj));

    return 1;
}

static char* rpc_name = NULL;

static int dm_object_call_rpc(lua_State* L) {
    lamx_dm_object_t* dm_object = (lamx_dm_object_t*) luaL_checkudata(L, 1, lamx_object_mt);
    amxd_dm_t* dm = lamx_get_dm(L);
    amxd_object_t* obj = amxd_dm_findf(dm, "%s", dm_object->path);
    amxd_status_t status = amxd_status_ok;
    const char* err_msg = NULL;

    amxc_var_t args;
    amxc_var_t ret;

    amxc_var_init(&args);
    amxc_var_init(&ret);

    lamx_lua2var(L, 2, &args);

    if(amxc_var_type_of(&args) != AMXC_VAR_ID_HTABLE) {
        err_msg = "Invalid argument - expected table";
        goto exit;
    }

    status = amxd_object_invoke_function(obj, rpc_name, &args, &ret);

    if(status == amxd_status_ok) {
        lamx_var2lua(&ret, L);
        lamx_var2lua(&args, L);
    } else {
        err_msg = "RPC call failed";
        goto exit;
    }

exit:
    amxc_var_clean(&args);
    amxc_var_clean(&ret);
    free(rpc_name);
    rpc_name = NULL;
    if(err_msg != NULL) {
        luaL_error(L, err_msg);
    }

    return 2;
}

// lua object meta-table implementation
static lua_CFunction lamx_is_object_function(amxd_object_t* obj, const char* name) {
    lua_CFunction fn = NULL;

    static struct luaL_Reg dm_obj_funcs[] = {
        {"get_parent", dm_object_get_parent},
        {"find", dm_object_find},
        {"forall", dm_object_for_all},
        {"get_name", dm_object_get_name},
        {"get_path", dm_object_get_path},
        {"add_mib", dm_object_add_mib},
        {"remove_mib", dm_object_remove_mib},
        {"get_parameter", dm_object_get_param},
        {"send_changed", dm_object_send_changed},
        {NULL, NULL}
    };

    static struct luaL_Reg dm_obj_templ_funcs[] = {
        {"add_instance", dm_object_add_instance},
        {"del_instance", dm_object_del_instance},
        {"instances", dm_object_instances },
        {"get_instance_count", dm_object_get_instance_count },
        {NULL, NULL}
    };

    static struct luaL_Reg dm_obj_inst_funcs[] = {
        {"del", dm_object_del_instance},
        {"get_index", dm_object_get_index},
        {NULL, NULL}
    };

    fn = lamx_get_function(dm_obj_funcs, name);
    if((fn == NULL) && (amxd_object_get_type(obj) == amxd_object_template)) {
        fn = lamx_get_function(dm_obj_templ_funcs, name);
    }
    if((fn == NULL) && (amxd_object_get_type(obj) == amxd_object_instance)) {
        fn = lamx_get_function(dm_obj_inst_funcs, name);
    }
    if(fn == NULL) {
        amxd_function_t* func_def = amxd_object_get_function(obj, name);
        if(func_def != NULL) {
            rpc_name = strdup(name);
            fn = dm_object_call_rpc;
        }
    }

    return fn;
}

static int dm_object_mt_index(lua_State* L) {
    lamx_dm_object_t* dm_object = (lamx_dm_object_t*) luaL_checkudata(L, 1, lamx_object_mt);
    const char* name = luaL_checkstring(L, 2);
    amxd_dm_t* dm = lamx_get_dm(L);
    amxd_object_t* obj = amxd_dm_findf(dm, "%s", dm_object->path);
    amxd_status_t status = amxd_status_ok;
    amxc_var_t value;
    lua_CFunction fn = NULL;

    amxc_var_init(&value);
    if(obj == NULL) {
        amxc_var_clean(&value);
        luaL_error(L, "Object not found '%s'", dm_object->path);
    }

    fn = lamx_is_object_function(obj, name);
    if(fn != NULL) {
        lua_pushcfunction(L, fn);
    } else {
        status = amxd_object_get_param(obj, name, &value);
        if(status != amxd_status_ok) {
            amxc_var_clean(&value);
            luaL_error(L, "Parameter not found '%s' of '%s' (%d)", name, dm_object->path, status);
        }

        lamx_var2lua(&value, L);
    }

    amxc_var_clean(&value);
    return 1;
}

static int dm_object_mt_newindex(lua_State* L) {
    lamx_dm_object_t* dm_object = (lamx_dm_object_t*) luaL_checkudata(L, 1, lamx_object_mt);
    const char* name = luaL_checkstring(L, 2);
    amxd_dm_t* dm = lamx_get_dm(L);
    amxd_object_t* obj = amxd_dm_findf(dm, "%s", dm_object->path);
    amxd_param_t* param = NULL;
    amxc_var_t value;

    amxc_var_init(&value);
    lamx_lua2var(L, 3, &value);

    param = amxd_object_get_param_def(obj, name);
    if(param == NULL) {
        amxc_var_clean(&value);
        luaL_error(L, "Parameter not found '%s' of '%s'", name, dm_object->path);
    }

    amxd_param_set_value(param, &value);

    amxc_var_clean(&value);
    return 0;
}

static int dm_object_mt_gc(lua_State* L) {
    lamx_dm_object_t* dm_object = (lamx_dm_object_t*) luaL_checkudata(L, 1, lamx_object_mt);
    free(dm_object->path);
    return 0;
}

void lamx_push_object_mt(lua_State* L) {
    if(luaL_newmetatable(L, lamx_object_mt)) {
        static struct luaL_Reg metamethods[] = {
            {"__index", dm_object_mt_index},
            {"__newindex", dm_object_mt_newindex},
            {"__gc", dm_object_mt_gc},
            {NULL, NULL}
        };

        luaL_setfuncs(L, metamethods, 0);
        lua_pop(L, 1);  // The table is saved in the Lua's registry.
    }
}