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

#include <string.h>
#include <stdlib.h>
#include "lua_amx.h"

typedef struct _lamx_wait {
    lua_State* L;
} lamx_wait_t;

/***
   Ambiorix LUA Bus module
   @module lamx.bus
 */

/***
   Opens a connection to a bus system.

   Before opening a connection the correct bus back-end must be loaded

   @raise error failed to connect to the bus

   @usage
   lamx.backend.load("/usr/bin/mods/amxb/mod-amxb-ubus.so")
   lamx.bus.open("ubus:")

   @function lamx.bus.open

   @param uri the bus uri used to open the connection
   @param mode (optional, default = "public") is a string and must be either "public" or "protected"
 */
static int lamx_bus_open(lua_State* L) {
    const char* uri = luaL_checkstring(L, 1);
    amxb_bus_ctx_t* ctx = NULL;
    int nr_args = lua_gettop(L);
    const char* mode = nr_args >= 2 ? luaL_checkstring(L, 2) : "public";

    int rv = -1;

    rv = amxb_connect(&ctx, uri);
    if(rv != 0) {
        luaL_error(L, "Failed to open %s (rv = %d)", uri, rv);
    }

    if(strcmp(mode, "protected") == 0) {
        amxb_set_access(ctx, AMXB_PROTECTED);
    } else {
        amxb_set_access(ctx, AMXB_PUBLIC);
    }

    return 0;
}

static void lamx_bus_add_object(UNUSED const amxb_bus_ctx_t* bus_ctx,
                                const amxc_var_t* const data,
                                void* priv) {
    amxc_set_t* set = (amxc_set_t*) priv;
    when_null(data, exit);
    amxc_var_for_each(var_path, data) {
        const char* str_path = amxc_var_constcast(cstring_t, var_path);
        amxc_set_add_flag(set, str_path);
    }

exit:
    return;
}

static int lamx_bus_list_objects(amxb_bus_ctx_t* bus_ctx,
                                 UNUSED const amxc_var_t* args,
                                 void* priv) {
    amxc_set_t* set = (amxc_set_t*) priv;

    amxb_list(bus_ctx, "", AMXB_FLAG_OBJECTS |
              AMXB_FLAG_INSTANCES |
              AMXB_FLAG_FIRST_LVL |
              AMXB_FLAG_EXISTS, lamx_bus_add_object, set);

    return 0;
}

/***
   List available root objects.

   Uses all of the open bus connection to fetch a list of all available root objects.

   @raise error not found or general error when failed

   @usage
   lamx = require "lamx"
   lamx.auto_connect()
   table.dump(lamx.bus.list())
   lamx.disconnect_all()

   --[[
   [
      "Greeter.",
      "Process.",
      "Debug.",
      "Bus."
   ]
   ]]--

   @function lamx.bus.list

   @return
   A table containing a list of all available root objects.
   The list can be empty.
 */
static int lamx_bus_list(lua_State* L) {
    amxc_set_t* set = NULL;
    uint32_t length = 0;
    uint32_t index = 1;
    amxc_set_new(&set, true);

    amxb_be_for_all_connections(lamx_bus_list_objects, NULL, set);
    length = amxc_llist_size(&set->list);

    lua_createtable(L, length, 4);

    amxc_llist_for_each(it, &set->list) {
        amxc_flag_t* f = amxc_container_of(it, amxc_flag_t, it);
        lua_pushinteger(L, index);
        lua_pushstring(L, f->flag);
        lua_settable(L, -3);
        index++;
    }

    amxc_set_delete(&set);
    return 1;
}

/***
   Get data model objects.

   Uses any of the open bus connection to fetch one or more objects from the data model.

   @raise error not found or general error when failed

   @usage
   local lamx = require 'lamx'

   lamx.backend.load("/usr/bin/mods/amxb/mod-amxb-ubus.so")
   lamx.bus.open("ubus:")

   data = lamx.bus.get("Greeter.History.1.", 0)
   table.dump(data)

   lamx.backend.remove("ubus")

   --[[
   {
     ["Greeter.History.1."] = {
       From = "odl parser",
       Message = "Welcome to the Greeter App",
       NumberOfInfoEntries = 4,
       Retain = 1
     }
   }
   ]]--

   @function lamx.bus.get

   @param path data model object path. This path can be a parameter path, a search
   path or an object path.
   @param depth (optional, default = INFINITE). The number of levels to fetch in the
   object hierarchy, starting from the given path
   @param timeout (option, default = 5). Timeout in seconds.

   @return
   A table containing each matching object as the key and as value a table containing
   all the objects parameters names and values.
   If the requested path was a parameter path, only the requested parameter is in
   the reply.
 */
static int lamx_bus_get(lua_State* L) {
    int nr_args = lua_gettop(L);
    const char* path = luaL_checkstring(L, 1);
    lua_Integer depth = nr_args >= 2 ? lua_tointeger(L, 2) : -1;
    lua_Integer timeout = nr_args >= 3 ? lua_tointeger(L, 3) : 5;
    int rv = -1;
    amxb_bus_ctx_t* ctx = NULL;
    amxc_var_t ret;

    amxc_var_init(&ret);

    ctx = lamx_get_ctx(path);

    if(ctx == NULL) {
        amxc_var_clean(&ret);
        luaL_error(L, "%s not found", path);
    }

    rv = amxb_get(ctx, path, depth, &ret, timeout);
    if(rv != 0) {
        amxc_var_clean(&ret);
        luaL_error(L, "Get failed for %s (rv = %d))", path, rv);
    }

    lamx_var2lua(GETI_ARG(&ret, 0), L);

    amxc_var_clean(&ret);
    return 1;
}

/***
   Get supported data model.

   Uses any of the open bus connection to fetch the supported data model.

   Use this function for introspection purposes.

   This function does not return any instance, it only indicates which objects are
   multi-instance objects. The place in the object path where normally an
   instance identifier (index) is set, the place holder "{i}" is used.

   The object argument must be in this supported data model notation.

   @raise error not found or general error when failed

   @usage
   local lamx = require 'lamx'

   lamx.auto_connect()

   data = lamx.bus.get_supported_dm("Greeter.")
   table.dump(data)

   lamx.disconnect_all()

   --[[
   ]]--

   @function lamx.bus.get_supported_dm

   @param path data model object path. This path can be a parameter path, a search
   path or an object path.
   @param flags (optional table, default = { first_level = true, functions = true, parameters = true, events = true}).
   Indicates which information is requested.
   @param timeout (option, default = 5). Timeout in seconds.

   @return
   A table containing each matching object as the key and as value a table containing
   all the objects requested information.
 */
static int lamx_bus_get_supported_dm(lua_State* L) {
    int nr_args = lua_gettop(L);
    const char* path = luaL_checkstring(L, 1);
    lua_Integer timeout = nr_args >= 3 ? lua_tointeger(L, 3) : 5;
    int rv = -1;
    amxc_var_t lflags;
    amxb_bus_ctx_t* ctx = NULL;
    amxc_var_t ret;
    uint32_t flags = 0;

    if(nr_args >= 2) {
        luaL_checktype(L, 2, LUA_TTABLE);
        amxc_var_init(&lflags);
        lamx_lua2var(L, 2, &lflags);
    } else {
        amxc_var_init(&lflags);
    }

    amxc_var_init(&ret);

    ctx = lamx_get_ctx(path);
    if(ctx == NULL) {
        amxc_var_clean(&ret);
        amxc_var_clean(&lflags);
        luaL_error(L, "%s not found", path);
    }

    if((GET_ARG(&lflags, "first_level") == NULL) || GET_BOOL(&lflags, "first_level")) {
        flags |= AMXB_FLAG_FIRST_LVL;
    }
    if((GET_ARG(&lflags, "functions") == NULL) || GET_BOOL(&lflags, "functions")) {
        flags |= AMXB_FLAG_FUNCTIONS;
    }
    if((GET_ARG(&lflags, "parameters") == NULL) || GET_BOOL(&lflags, "parameters")) {
        flags |= AMXB_FLAG_PARAMETERS;
    }
    if((GET_ARG(&lflags, "events") == NULL) || GET_BOOL(&lflags, "events")) {
        flags |= AMXB_FLAG_EVENTS;
    }

    rv = amxb_get_supported(ctx, path, flags, &ret, timeout);
    if(rv != 0) {
        amxc_var_clean(&ret);
        amxc_var_clean(&lflags);
        luaL_error(L, "Get failed for %s (rv = %d))", path, rv);
    }

    lamx_var2lua(GETI_ARG(&ret, 0), L);

    amxc_var_clean(&lflags);
    amxc_var_clean(&ret);
    return 1;
}

/***
   Get instantiated data model.

   Uses any of the open bus connection to fetch the instantiated data model.

   Use this function for introspection purposes.

   This method will return all instances and their key parameters and values.

   @usage
   local lamx = require 'lamx'

   lamx.auto_connect()

   data = lamx.bus.get_instantiated_dm("Greeter.")
   table.dump(data)

   lamx.disconnect_all()

   --[[
   ]]--

   @function lamx.bus.get_instantiated_dm

   @param path data model object path. This path can be a parameter path, a search
   path or an object path.
   @param first_level (optional boolean, default = false) When set to true only the first level is returned.
   @param timeout (optional integer, default = 5). Timeout in seconds.

   @return
   A table containing each matching object as the key and as value a table containing
   all the instance key parameters with their values.
 */
static int lamx_bus_get_instantiated_dm(lua_State* L) {
    int nr_args = lua_gettop(L);
    const char* path = luaL_checkstring(L, 1);
    lua_Integer timeout = nr_args >= 3 ? lua_tointeger(L, 3) : 5;
    int rv = -1;
    bool first_level = false;
    amxb_bus_ctx_t* ctx = NULL;
    amxc_var_t ret;

    if(nr_args >= 2) {
        luaL_checktype(L, 2, LUA_TBOOLEAN);
        first_level = lua_toboolean(L, 2);
    }

    amxc_var_init(&ret);

    ctx = lamx_get_ctx(path);
    if(ctx == NULL) {
        amxc_var_clean(&ret);
        luaL_error(L, "%s not found", path);
    }

    rv = amxb_get_instances(ctx, path, first_level? 0:-1, &ret, timeout);
    if(rv != 0) {
        amxc_var_clean(&ret);
        luaL_error(L, "Get failed for %s (rv = %d))", path, rv);
    }

    lamx_var2lua(GETI_ARG(&ret, 0), L);

    amxc_var_clean(&ret);
    return 1;
}

/***
   Describe data model objects.

   Uses any of the open bus connection to fetch one or more object descriptions
   from the data model.

   @raise error not found or general error when failed

   @usage
   local lamx = require 'lamx'

   lamx.backend.load("/usr/bin/mods/amxb/mod-amxb-ubus.so")
   lamx.bus.open("ubus:")

   data = lamx.bus.describe("Greeter.History.1.", 0)
   table.dump(data)

   lamx.backend.remove("ubus")

   --[[
    {
        attributes = {
            locked = 0,
            persistent = 1,
            private = 0,
            protected = 0,
            read-only = 1
        },
        events = {
        },
        functions = {
        },
        index = 1,
        name = "1",
        object = "Greeter.History.",
        parameters = {
            From = {
                attributes = {
                    counter = 0,
                    instance = 1,
                    key = 0,
                    mutable = 0,
                    persistent = 1,
                    private = 0,
                    protected = 0,
                    read-only = 1,
                    template = 0,
                    unique = 0,
                    volatile = 0
                },
                flags = [
                    "pcm"
                ],
                name = "From",
                type_id = 1,
                type_name = "cstring_t",
                value = "odl parser"
            },
            Message = {
                attributes = {
                    counter = 0,
                    instance = 1,
                    key = 0,
                    mutable = 0,
                    persistent = 1,
                    private = 0,
                    protected = 0,
                    read-only = 1,
                    template = 0,
                    unique = 0,
                    volatile = 0
                },
                flags = [
                    "pcm"
                ],
                name = "Message",
                type_id = 1,
                type_name = "cstring_t",
                value = "Welcome to the Greeter App"
            },
            NumberOfInfoEntries = {
                attributes = {
                    counter = 1,
                    instance = 1,
                    key = 0,
                    mutable = 0,
                    persistent = 0,
                    private = 0,
                    protected = 0,
                    read-only = 1,
                    template = 0,
                    unique = 0,
                    volatile = 0
                },
                flags = {
                },
                name = "NumberOfInfoEntries",
                type_id = 8,
                type_name = "uint32_t",
                value = 0
            },
            Retain = {
                attributes = {
                    counter = 0,
                    instance = 1,
                    key = 0,
                    mutable = 0,
                    persistent = 1,
                    private = 0,
                    protected = 0,
                    read-only = 0,
                    template = 0,
                    unique = 0,
                    volatile = 0
                },
                flags = {
                },
                name = "Retain",
                type_id = 12,
                type_name = "bool",
                value = 1
            }
        },
        path = "Greeter.History.",
        type_id = 3,
        type_name = "instance"
    }
   ]]--

   @function lamx.bus.describe

   @param path data model object path. This path can only be an object path.
   @param timeout (option, default = 5). Timeout in seconds.

   @return
   Returns a table containing all meta-data (description) of the object, including
   parameters, events and functions.
 */
static int lamx_bus_describe(lua_State* L) {
    int nr_args = lua_gettop(L);
    const char* path = luaL_checkstring(L, 1);
    lua_Integer timeout = nr_args >= 2 ? lua_tointeger(L, 2) : 5;
    int rv = -1;
    amxb_bus_ctx_t* ctx = NULL;
    amxc_var_t ret;

    amxc_var_init(&ret);

    ctx = lamx_get_ctx(path);

    if(ctx == NULL) {
        amxc_var_clean(&ret);
        luaL_error(L, "%s not found", path);
    }

    rv = amxb_describe(ctx, path, AMXB_FLAG_FUNCTIONS | AMXB_FLAG_PARAMETERS | AMXB_FLAG_EVENTS, &ret, timeout);
    if(rv != 0) {
        amxc_var_clean(&ret);
        luaL_error(L, "Describe failed for %s (rv = %d))", path, rv);
    }

    lamx_var2lua(GETI_ARG(&ret, 0), L);

    amxc_var_clean(&ret);
    return 1;
}

/***
   Set data model object parameters.

   Uses any of the open bus connection to set parameters of an object in the data model.

   @raise error not found or general error when failed

   @usage
   local lamx = require 'lamx'

   lamx.backend.load("/usr/bin/mods/amxb/mod-amxb-ubus.so")
   lamx.bus.open("ubus:")
   data = lamx.bus.set("Greeter.History.1.Info.*", { Text = "Hallo" })
   table.dump(data)

   lamx.backend.remove("ubus")

   --[[
   {
     ["Greeter.History.1.Info.1."] = {
       Text = "Hallo"
     },
     ["Greeter.History.1.Info.2."] = {
       Text = "Hallo"
     },
     ["Greeter.History.1.Info.3."] = {
       Text = "Hallo"
     },
     ["Greeter.History.1.Info.4."] = {
       Text = "Hallo"
     }
   }
   ]]--

   @function lamx.bus.set

   @param path data model object path. This path can be a a search path or an object path.
   When a search path is used, all resolved objects must contain the parameters
   that will be set.
   @param parameters A table containing the parameters and the values that needs to be set.
   @param timeout (option, default = 5). Timeout in seconds.

   @return
   A table containing each changed object and its parameters that are set
 */
static int lamx_bus_set(lua_State* L) {
    int nr_args = lua_gettop(L);
    const char* path = luaL_checkstring(L, 1);
    lua_Integer timeout = nr_args >= 3 ? lua_tointeger(L, 3) : 5;
    int rv = -1;
    amxb_bus_ctx_t* ctx = NULL;
    amxc_var_t ret;
    amxc_var_t params;

    luaL_checktype(L, 2, LUA_TTABLE);

    amxc_var_init(&ret);
    amxc_var_init(&params);

    lamx_lua2var(L, 2, &params);

    ctx = lamx_get_ctx(path);
    if(ctx == NULL) {
        amxc_var_clean(&params);
        amxc_var_clean(&ret);
        luaL_error(L, "%s not found", path);
    }

    rv = amxb_set(ctx, path, &params, &ret, timeout);
    if(rv != 0) {
        amxc_var_clean(&params);
        amxc_var_clean(&ret);
        luaL_error(L, "Set failed for %s (rv = %d))", path, rv);
    }

    lamx_var2lua(GETI_ARG(&ret, 0), L);

    amxc_var_clean(&params);
    amxc_var_clean(&ret);
    return 1;
}

/***
   Check if a data model object exists.

   Uses any of the open bus connection to check if the object exists in the data model.

   @usage
   local lamx = require 'lamx'

   lamx.backend.load("/usr/bin/mods/amxb/mod-amxb-ubus.so")
   lamx.bus.open("ubus:")

   data = lamx.bus.exists("Greeter.History.1.")
   print(data)

   lamx.backend.remove("ubus")

   --[[
   true
   ]]--

   @function lamx.bus.exists

   @param path data model object path. Only object paths are supported by this call.
   @param timeout (optional, default = 5). Timeout in seconds.

   @return
   This function returns true when the object exists in the data model or false
   if no such object is available
 */
static int lamx_bus_object_exists(lua_State* L) {
    int nr_args = lua_gettop(L);
    const char* path = luaL_checkstring(L, 1);
    bool exists = false;
    lua_Integer timeout = nr_args >= 2 ? lua_tointeger(L, 2) : 5;
    int rv = -1;
    amxb_bus_ctx_t* ctx = NULL;
    amxc_var_t ret;
    amxd_path_t obj_path;

    amxc_var_init(&ret);
    amxd_path_init(&obj_path, path);

    if(amxd_path_get_type(&obj_path) != amxd_path_object) {
        amxc_var_clean(&ret);
        amxd_path_clean(&obj_path);
        luaL_error(L, "Invalid path %s", path);
    }

    ctx = lamx_get_ctx(path);
    when_null(ctx, exit);

    rv = amxb_describe(ctx, path, AMXB_FLAG_EXISTS, &ret, timeout);
    when_failed(rv, exit);
    exists = GETI_BOOL(&ret, 0);

exit:
    lua_pushboolean(L, exists);
    amxd_path_clean(&obj_path);
    amxc_var_clean(&ret);
    return 1;
}

/***
   Resolves a search path.

   Uses any of the open bus connection to resolve a search path into a list of
   matching objects.

   @usage
   local lamx = require 'lamx'

   lamx.backend.load("/usr/bin/mods/amxb/mod-amxb-ubus.so")
   lamx.bus.open("ubus:")

   data = lamx.bus.resolve("Greeter.History.[From=='me'].")
   table.dump(data)

   lamx.backend.remove("ubus")

   --[[
    {
    "Greeter.History.4."
    }
   ]]--

   @function lamx.bus.resolve

   @param path data model object search path.

   @return
   This function returns a list of matching objects.
 */
static int lamx_bus_resolve(lua_State* L) {
    const char* path = luaL_checkstring(L, 1);
    int rv = -1;
    amxb_bus_ctx_t* ctx = NULL;
    amxc_var_t ret;
    amxd_path_t obj_path;

    amxd_path_init(&obj_path, NULL);
    amxc_var_init(&ret);
    amxc_var_set_type(&ret, AMXC_VAR_ID_LIST);
    amxd_path_setf(&obj_path, true, "%s", path);

    ctx = lamx_get_ctx(path);
    when_null(ctx, exit);

    rv = amxb_resolve(ctx, &obj_path, &ret);
    when_failed(rv, exit);

exit:
    lamx_var2lua(&ret, L);
    amxc_var_clean(&ret);
    amxd_path_clean(&obj_path);
    return 1;
}

/***
   Search the bus uri that provides the specified object path.

   Searches which bus connection is providing the specified object path.

   When a uri is returned there is no guarantee that the object exists in the data model.

   @usage
   local lamx = require 'lamx'

   lamx.auto_connect("protected")

   data = lamx.bus.who_has("Greeter.History.[From=='me'].")
   print(data)

   lamx.disconnect_all()

   --[[
   ubus:/var/run/ubus/ubus.sock
   ]]--

   @function lamx.bus.who_has

   @param path data model object path. All kinds of paths are supported

   @return
   This function returns the uri of the bus connection that provides the object or
   an empty string if no such connection is found.
 */
static int lamx_bus_who_has(lua_State* L) {
    const char* path = luaL_checkstring(L, 1);
    const char* uri = "";
    amxb_bus_ctx_t* ctx = NULL;

    ctx = lamx_get_ctx(path);
    when_null(ctx, exit);
    uri = amxc_htable_it_get_key(&ctx->hit);

exit:
    lua_pushstring(L, uri);
    return 1;
}

/***
   Adds a instance object.

   Uses any of the open bus connection to set parameters of an object in the data model.

   @raise error not found or general error when failed

   @usage
   local lamx = require 'lamx'

   lamx.backend.load("/usr/bin/mods/amxb/mod-amxb-ubus.so")
   lamx.bus.open("ubus:")

   data = lamx.bus.add("Greeter.History.1.Info.")
   table.dump(data)

   lamx.backend.remove("ubus")

   --[[
   {
     index = 5,
     name = "cpe-Info-5",
     object = "Greeter.History.1.Info.cpe-Info-5.",
     parameters = {
       Alias = "cpe-Info-5"
     },
     path = "Greeter.History.1.Info.5."
   }
   ]]--

   @function lamx.bus.add

   @param path data model object path. This path can be a a search path or an object path.
   When a search path is used, all resolved objects must contain the parameters
   that will be set.
   @param parameters (optional) A table containing the parameters and the values
   that needs to be set.
   @param timeout (option, default = 5). Timeout in seconds.

   @return
   A table containing the new instance info
 */
static int lamx_bus_add(lua_State* L) {
    int nr_args = lua_gettop(L);
    const char* path = luaL_checkstring(L, 1);
    lua_Integer timeout = nr_args >= 3 ? lua_tointeger(L, 3) : 5;
    int rv = -1;
    amxb_bus_ctx_t* ctx = NULL;
    amxc_var_t ret;
    amxc_var_t params;

    if(nr_args >= 2) {
        luaL_checktype(L, 2, LUA_TTABLE);
        amxc_var_init(&params);
        lamx_lua2var(L, 2, &params);
    } else {
        amxc_var_init(&params);
    }

    amxc_var_init(&ret);

    ctx = lamx_get_ctx(path);
    if(ctx == NULL) {
        amxc_var_clean(&params);
        amxc_var_clean(&ret);
        luaL_error(L, "%s not found", path);
    }

    rv = amxb_add(ctx, path, 0, NULL, &params, &ret, timeout);
    if(rv != 0) {
        amxc_var_clean(&params);
        amxc_var_clean(&ret);
        luaL_error(L, "Add failed for %s (rv = %d))", path, rv);
    }

    lamx_var2lua(GETI_ARG(&ret, 0), L);

    amxc_var_clean(&params);
    amxc_var_clean(&ret);
    return 1;
}

/***
   Deletes a instance objects.

   Uses any of the open bus connection to set parameters of an object in the data model.

   @raise error not found or general error when failed

   @usage
   local lamx = require 'lamx'

   lamx.backend.load("/usr/bin/mods/amxb/mod-amxb-ubus.so")
   lamx.bus.open("ubus:")

   data = lamx.bus.del("Greeter.History.1.Info.*.")
   table.dump(data)

   lamx.backend.remove("ubus")

   --[[
   {
     "Greeter.History.1.Info.1.",
     "Greeter.History.1.Info.2.",
     "Greeter.History.1.Info.3.",
     "Greeter.History.1.Info.4."
   }
   ]]--

   @function lamx.bus.del

   @param path data model object path. This path can be a a search path or an
   object instance path. When a search path is used it must resolve to instance
   objects.
   @param timeout (option, default = 5). Timeout in seconds.

   @return
   A table containing each deleted instance object path
 */
static int lamx_bus_del(lua_State* L) {
    int nr_args = lua_gettop(L);
    const char* path = luaL_checkstring(L, 1);
    lua_Integer timeout = nr_args >= 2 ? lua_tointeger(L, 2) : 5;
    int rv = -1;
    amxb_bus_ctx_t* ctx = NULL;
    amxc_var_t ret;

    amxc_var_init(&ret);

    ctx = lamx_get_ctx(path);
    if(ctx == NULL) {
        amxc_var_clean(&ret);
        luaL_error(L, "%s not found", path);
    }

    rv = amxb_del(ctx, path, 0, NULL, &ret, timeout);
    if(rv != 0) {
        amxc_var_clean(&ret);
        luaL_error(L, "Del failed for %s (rv = %d))", path, rv);
    }

    lamx_var2lua(&ret, L);

    amxc_var_clean(&ret);
    return 1;
}

/***
   Invokes a data model RPC method (aka command).

   Uses any of the open bus connection to call the data model RPC.

   @raise error not found or general error when failed

   @usage
   local lamx = require 'lamx'

   lamx.backend.load("/usr/bin/mods/amxb/mod-amxb-ubus.so")
   lamx.bus.open("ubus:")

   data = lamx.bus.get("Greeter.State", 0)
   if data["Greeter."].State == "Idle" then
     data = lamx.bus.set("Greeter.", { State = "Start" })
   end

   data = lamx.bus.call("Greeter.", "say", {from = "lua", message = "Hello from lua"})
   table.dump(data)

   lamx.backend.remove("ubus")

   --[[
   {
     "Hello from lua"
   }
   ]]--

   @function lamx.bus.call

   @param path data model object path. This path can be a a search path or an object path
   @param method The method name.
   @param arguments Table containing the RPC method arguments. When the RPC doesn't have
   any mandatory arguments, this is optional.
   @param timeout (option, default = 5). Timeout in seconds.

   @return
   See documentation of the RPC method
 */
static int lamx_bus_call(lua_State* L) {
    int nr_args = lua_gettop(L);
    const char* path = luaL_checkstring(L, 1);
    const char* method = luaL_checkstring(L, 2);
    lua_Integer timeout = nr_args >= 4 ? lua_tointeger(L, 4) : 5;
    int rv = -1;
    amxb_bus_ctx_t* ctx = NULL;
    amxc_var_t ret;
    amxc_var_t args;

    if(nr_args >= 3) {
        luaL_checktype(L, 3, LUA_TTABLE);
        amxc_var_init(&args);
        lamx_lua2var(L, 3, &args);
    } else {
        amxc_var_init(&args);
    }

    amxc_var_init(&ret);

    ctx = lamx_get_ctx(path);
    if(ctx == NULL) {
        amxc_var_clean(&args);
        amxc_var_clean(&ret);
        luaL_error(L, "%s not found", path);
    }

    rv = amxb_call(ctx, path, method, &args, &ret, timeout);
    if(rv != 0) {
        amxc_var_clean(&args);
        amxc_var_clean(&ret);
        luaL_error(L, "Call failed for %s%s() (rv = %d))", path, method, rv);
    }

    lamx_var2lua(&ret, L);

    amxc_var_clean(&args);
    amxc_var_clean(&ret);
    return 1;
}

static int lamx_register_dm(amxb_bus_ctx_t* bus_ctx,
                            UNUSED const amxc_var_t* args,
                            void* priv) {
    amxd_dm_t* dm = (amxd_dm_t*) priv;
    return amxb_register(bus_ctx, dm);
}

/***
   Registers the data model on all opened bus connection.

   @usage
   local lamx = require 'lamx'

   lamx.backend.load("/usr/bin/mods/amxb/mod-amxb-ubus.so")
   lamx.bus.open("ubus:")
   lamx.dm.create()
   lamx.dm.load("/etc/mydm/mydm.odl")
   lamx.bus.register()

   el:start()

   lamx.dm.desroy()
   lamx.backend.remove("ubus")

   @function lamx.bus.register
 */
static int lamx_bus_register(lua_State* L) {
    amxd_dm_t* dm = lamx_get_dm(L);

    if(dm == NULL) {
        luaL_error(L, "No data model available, did you forget to call dm.create()");
    }

    if(amxb_be_for_all_connections(lamx_register_dm, NULL, dm) != 0) {
        luaL_error(L, "Failed to register data model");
    }

    return 0;
}

static void lamx_bus_invoke_wait_cb(UNUSED const amxc_var_t* const data,
                                    void* const priv) {
    lamx_wait_t* amx_wait = (lamx_wait_t*) priv;
    lua_State* L = amx_wait->L;

    lua_settop(L, 0);
    lua_pushlightuserdata(L, (void*) amx_wait);
    lua_gettable(L, LUA_REGISTRYINDEX);

    // call the function
    if(lua_pcall(L, 0, 0, 0) != 0) {
        lamx_lua_stack_dump(L);
    }

    lua_pushlightuserdata(L, (void*) amx_wait);
    lua_pushnil(L);
    lua_settable(L, LUA_REGISTRYINDEX);

    free(amx_wait);
    lua_settop(L, 0);
}

static void lamx_bus_wait_for_done(UNUSED const char* const sig_name,
                                   UNUSED const amxc_var_t* const data,
                                   void* const priv) {
    amxp_sigmngr_deferred_call(NULL, lamx_bus_invoke_wait_cb, NULL, priv);
    amxp_slot_disconnect_with_priv(NULL, lamx_bus_wait_for_done, priv);
}

/***
   Waits until a data model object comes available.

   Uses any of the open bus connections to wait until an object becomes available.

   It is possible to wait on multiple objects, by calling this method multiple times.

   An eventloop must be started before the callback function(s) can be called.

   @raise general error when failed

   @usage
   local lamx = require 'lamx'

   lamx.backend.load("/usr/bin/mods/amxb/mod-amxb-ubus.so")
   lamx.bus.open("ubus:")

   local el = lamx.eventloop.new()

   local objects_available = function()
       el:stop()
   end

   lamx.bus.wait_for("Greeter.", objects_available)
   lamx.bus.wait_for("NetModel.")

   el:start()

   print("Objects available")

   @function lamx.bus.wait_for

   @param path data model object path(s). This must be an object path as a single
               string or an array of strings.
   @param method (optional) Method that is called when object(s) are available.

 */
static int lamx_bus_wait_for(lua_State* L) {
    int nr_args = lua_gettop(L);
    int rv = -1;
    lamx_wait_t* amx_wait = NULL;
    amxc_var_t paths;

    amxc_var_init(&paths);
    lamx_lua2var(L, 1, &paths);

    if((amxc_var_type_of(&paths) != AMXC_VAR_ID_CSTRING) &&
       (amxc_var_type_of(&paths) != AMXC_VAR_ID_LIST)) {
        luaL_error(L, "Expected string or array, got %s", luaL_typename(L, 1));
    }

    if(nr_args >= 2) {
        if(!lua_isfunction(L, 2)) {
            amxc_var_clean(&paths);
            luaL_error(L, "Expected function, got %s", luaL_typename(L, 2));
        }

        amx_wait = (lamx_wait_t*) calloc(1, sizeof(lamx_wait_t));
        amx_wait->L = L;

        lua_pushlightuserdata(L, (void*) amx_wait);
        lua_pushvalue(L, 2); // put function on top of stack
        lua_settable(L, LUA_REGISTRYINDEX);

        amxp_slot_connect(NULL, "wait:done", NULL, lamx_bus_wait_for_done, amx_wait);
    }

    if(amxc_var_type_of(&paths) == AMXC_VAR_ID_CSTRING) {
        rv = amxb_wait_for_object(amxc_var_constcast(cstring_t, &paths));
        if(rv != 0) {
            amxc_var_clean(&paths);
            luaL_error(L, "Failed to wait for object (%d)", rv);
        }
    } else {
        amxc_var_for_each(path, &paths) {
            if(amxc_var_type_of(path) != AMXC_VAR_ID_CSTRING) {
                const char* type_name = amxc_var_type_name_of(path);
                amxc_var_clean(&paths);
                luaL_error(L, "Expected string, got %s", type_name);
            }
            rv = amxb_wait_for_object(amxc_var_constcast(cstring_t, path));
            if(rv != 0) {
                amxc_var_clean(&paths);
                luaL_error(L, "Failed to wait for object (%d)", rv);
            }
        }
    }

    amxc_var_clean(&paths);
    return 0;
}

/***
   Take subscription on data model object.

   Uses any of the open bus connection to call the data model RPC.
   Subscribes for all events of a data model object tree.
   An eventloop must be started to receive events.

   The subscriptions is removed when the returned object is garbage collected.

   @raise error not found or general error when failed to take subscription

   @usage
   local lamx = require 'lamx'

   lamx.backend.load("/usr/bin/mods/amxb/mod-amxb-ubus.so")
   lamx.bus.open("ubus:")

   local el = lamx.eventloop.new()
   local print_event = function(event, data)
      print("Event " .. tostring(event))
      table.dump(data)
      el:stop()
   end

   local sub = lamx.bus.subscribe("Greeter.", print_event);

   el:start()

   lamx.backend.remove("ubus")

   @function lamx.bus.subscribe

   @param path data model object path. This path can be a a search path or an object path
   @param function the function is called whenever an event is recieved.
   @param filter (optional) Event filter expression. When provided the function
   is only called when the event data matches the filter

   @return
   Subscription object, can be garbage collected.
 */

void lamx_push_bus_fns(lua_State* L) {
    static struct luaL_Reg fns[] = {
        {"open", lamx_bus_open},
        {"list", lamx_bus_list},
        {"get", lamx_bus_get},
        {"set", lamx_bus_set},
        {"add", lamx_bus_add},
        {"del", lamx_bus_del},
        {"call", lamx_bus_call},
        {"subscribe", lamx_bus_subscribe},
        {"register", lamx_bus_register},
        {"wait_for", lamx_bus_wait_for},
        {"exists", lamx_bus_object_exists},
        {"resolve", lamx_bus_resolve},
        {"who_has", lamx_bus_who_has},
        {"describe", lamx_bus_describe},
        {"get_supported_dm", lamx_bus_get_supported_dm},
        {"get_instantiated_dm", lamx_bus_get_instantiated_dm},
        {NULL, NULL}
    };

    luaL_newlib(L, fns);  // Push a new table with fns key/vals.
    lua_setfield(L, -2, "bus");
}
