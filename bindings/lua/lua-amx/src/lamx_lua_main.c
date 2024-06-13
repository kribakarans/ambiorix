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

#include <dirent.h>
#include <string.h>
#include <sys/stat.h>

#include <amxp/amxp_dir.h>

#include "lua_amx.h"

static lua_State* lua = NULL;
static amxc_var_t* cfg = NULL;

static amxd_status_t lua_rpc_impl(amxd_object_t* object,
                                  amxd_function_t* func,
                                  amxc_var_t* args,
                                  amxc_var_t* ret) {
    amxd_status_t status = amxd_status_ok;
    lua_State* L = lua;
    lua_pushstring(L, MOD_LUA_AMX_FNS);
    lua_gettable(L, LUA_REGISTRYINDEX);

    // push function on stack
    lua_getfield(L, -1, amxd_function_get_name(func));

    // push object
    lamx_push_object(L, object);
    // push function arguments
    lamx_var2lua(args, L);

    lua_remove(L, 1);

    // call the function
    if(lua_pcall(L, 2, 2, 0) == 0) {
        // handle return value and out arguments
        lamx_lua2var(L, 1, ret);
        lamx_lua2var(L, 2, args);
    } else {
        lamx_lua_stack_dump(L);
        status = amxd_status_unknown_error;
    }

    lua_settop(L, 0);
    return status;
}

static void lua_event_handler(const char* const sig_name,
                              const amxc_var_t* const data,
                              void* const priv) {
    lua_State* L = lua;
    amxd_object_t* object = amxd_dm_signal_get_object(lamx_get_dm(L), data);
    amxc_string_t* fn_name = (amxc_string_t*) priv;

    lua_pushstring(L, MOD_LUA_AMX_FNS);
    lua_gettable(L, LUA_REGISTRYINDEX);

    // push function on stack
    lua_getfield(L, -1, amxc_string_get(fn_name, 0));

    // push object
    if(object != NULL) {
        lamx_push_object(L, object);
    } else {
        lua_pushnil(L);
    }
    // push event name
    lua_pushstring(L, sig_name);
    // push event data
    lamx_var2lua(data, L);

    lua_remove(L, 1);

    // call the function
    if(lua_pcall(L, 3, 0, 0) != 0) {
        lamx_lua_stack_dump(L);
    }

    lua_settop(L, 0);
}

static amxd_status_t lua_action_handler(amxd_object_t* const object,
                                        amxd_param_t* const param,
                                        amxd_action_t reason,
                                        const amxc_var_t* const args,
                                        amxc_var_t* const retval,
                                        void* priv) {
    lua_State* L = lua;
    amxc_var_t* fn_name = (amxc_var_t*) priv;
    amxd_status_t s = amxd_status_ok;
    amxc_var_t status;

    amxc_var_init(&status);

    lua_pushstring(L, MOD_LUA_AMX_FNS);
    lua_gettable(L, LUA_REGISTRYINDEX);

    // push function on stack
    lua_getfield(L, -1, GET_CHAR(fn_name, NULL));
    // push object
    lamx_push_object(L, object);

    // push parameter
    if(param != NULL) {
        lamx_push_param(L, param);
    } else {
        lua_pushnil(L);
    }
    // push reason
    lua_pushinteger(L, reason);
    // push args
    lamx_var2lua(args, L);
    // push retval
    lamx_var2lua(retval, L);

    lua_remove(L, 1);

    if(lua_pcall(L, 5, 2, 0) == 0) {
        // handle status and retval
        lamx_lua2var(L, 1, &status);
        lamx_lua2var(L, 2, retval);
    } else {
        lamx_lua_stack_dump(L);
    }

    lua_settop(L, 0);

    s = (amxd_status_t) GET_UINT32(&status, NULL);

    amxc_var_clean(&status);
    return s;
}

static int lamx_add_backend(const char* name, UNUSED void* priv) {
    const char* extension = strstr(name, ".so");
    if((extension == NULL) || (extension[3] != 0)) {
        goto exit;
    }

    amxb_be_load(name);

exit:
    return 0;
}

static bool lamx_list_contains(amxc_var_t* list, const char* value) {
    bool retval = false;
    amxc_var_for_each(v, list) {
        const char* stored = GET_CHAR(v, NULL);
        if(strcmp(stored, value) == 0) {
            retval = true;
            break;
        }
    }

    return retval;
}

static void lamx_filter_uris(const amxc_llist_t* uris, const amxc_llist_t* exclude_uris) {
    int cresult = 0;
    amxc_var_t* euri_var = NULL;
    amxc_var_t* uri_var = NULL;

    amxc_llist_for_each(eit, exclude_uris) {
        euri_var = amxc_var_from_llist_it(eit);
        amxc_llist_for_each(it, uris) {
            uri_var = amxc_var_from_llist_it(it);
            if((amxc_var_compare(uri_var, euri_var, &cresult) == 0) && (cresult == 0)) {
                amxc_llist_it_take(it);
                variant_list_it_free(it);
            }
        }
    }
}

static void lamx_move_backend_uris(amxc_var_t* config, amxc_var_t* backend_settings) {
    amxc_var_t* uris = GET_ARG(config, "uris");
    amxc_var_t* data_uris = GET_ARG(config, "data-uris");
    amxc_var_t* be_uris = GET_ARG(backend_settings, "uris");
    amxc_var_t* be_data_uris = GET_ARG(backend_settings, "data-uris");

    amxc_var_for_each(uri, be_uris) {
        const char* u = GET_CHAR(uri, NULL);
        if(!lamx_list_contains(data_uris, u) &&
           !lamx_list_contains(uris, u)) {
            amxc_var_set_index(uris, 0, uri, AMXC_VAR_FLAG_DEFAULT);
        }
    }

    amxc_var_for_each(uri, be_data_uris) {
        const char* u = GET_CHAR(uri, NULL);
        if(!lamx_list_contains(data_uris, u) &&
           !lamx_list_contains(uris, u)) {
            amxc_var_set_index(data_uris, 0, uri, AMXC_VAR_FLAG_DEFAULT);
        }
    }

    amxc_var_delete(&be_uris);
    amxc_var_delete(&be_data_uris);
}

static int lamx_connect_all_type(const amxc_llist_t* uris, uint32_t access) {
    int retval = 0;
    amxc_llist_for_each(it, uris) {
        amxb_bus_ctx_t* bus_ctx = NULL;
        const char* uri = amxc_var_constcast(cstring_t, amxc_var_from_llist_it(it));

        if(amxb_find_uri(uri) == NULL) {
            retval = amxb_connect(&bus_ctx, uri);
            when_failed(retval, leave);
            amxb_set_access(bus_ctx, access);
        }
    }

leave:
    return retval;
}

static int lamx_connect_all(amxc_var_t* config, uint32_t access) {
    int retval = 0;
    const amxc_llist_t* uris = amxc_var_constcast(amxc_llist_t, GET_ARG(config, "uris"));
    const amxc_llist_t* data_uris = amxc_var_constcast(amxc_llist_t, GET_ARG(config, "data-uris"));

    lamx_filter_uris(uris, data_uris);
    retval = lamx_connect_all_type(uris, access);
    when_failed(retval, leave);
    retval = lamx_connect_all_type(data_uris, access);

leave:
    return retval;
}

static int lamx_detect_sockets(amxc_var_t* config, uint32_t access) {
    amxc_array_t* backends = amxb_be_list();
    size_t size = amxc_array_size(backends);

    // take all default sockets provided by backends
    for(size_t i = 0; i < size; i++) {
        const char* be_name = (const char*) amxc_array_get_data_at(backends, i);
        amxc_var_t* backend_settings = GET_ARG(config, be_name);
        lamx_move_backend_uris(config, backend_settings);
    }

    return lamx_connect_all(config, access);
}

static int lamx_auto_connect(lua_State* L) {
    int rv = 0;
    int nr_args = lua_gettop(L);
    const char* mode = nr_args >= 1 ? luaL_checkstring(L, 1) : "public";
    amxo_parser_t* parser = lamx_get_parser(L);
    amxc_var_t* config = NULL;
    amxp_dir_scan("/usr/bin/mods/amxb", NULL, false, lamx_add_backend, NULL);

    if(parser != NULL) {
        config = &parser->config;
        amxb_set_config(config);
    } else {
        lua_pushstring(L, MOD_LUA_AMX_CONFIG);
        lua_gettable(L, LUA_REGISTRYINDEX);

        config = (amxc_var_t*) lua_touserdata(L, -1);
        amxb_set_config(config);
    }

    if(amxc_var_is_null(config)) {
        amxc_var_set_type(config, AMXC_VAR_ID_HTABLE);
    }
    amxc_var_add_key(amxc_llist_t, config, "uris", NULL);
    amxc_var_add_key(amxc_llist_t, config, "data-uris", NULL);

    rv = lamx_detect_sockets(config, strcmp(mode, "protected") == 0? AMXB_PROTECTED:AMXB_PUBLIC);
    if(rv != 0) {
        luaL_error(L, "Failed to connect (rv = %d)", rv);
    }

    return 0;
}

static int lamx_disconnect_all(UNUSED lua_State* L) {
    amxb_be_remove_all();

    return 0;
}

/***
   lamx is a Lua library developed to make use of the Ambiorix bus API.
   With this library it is possible to load bus specific back-ends, open
   a connection to a bus system and send USP like requests

   @module lamx
 */
int luaopen_lamx(lua_State* L) {
    amxc_var_new(&cfg);
    amxc_var_set_type(cfg, AMXC_VAR_ID_HTABLE);

    lua = L;

    lua_pushstring(L, MOD_LUA_AMX_RPC_FUNC);
    lua_pushlightuserdata(L, (void*) lua_rpc_impl);
    lua_settable(L, LUA_REGISTRYINDEX);

    lua_pushstring(L, MOD_LUA_AMX_EVENT_FUNC);
    lua_pushlightuserdata(L, (void*) lua_event_handler);
    lua_settable(L, LUA_REGISTRYINDEX);

    lua_pushstring(L, MOD_LUA_AMX_ACTION_FUNC);
    lua_pushlightuserdata(L, (void*) lua_action_handler);
    lua_settable(L, LUA_REGISTRYINDEX);

    lua_pushstring(L, MOD_LUA_AMX_CONFIG);
    lua_pushlightuserdata(L, cfg);
    lua_settable(L, LUA_REGISTRYINDEX);

    lua_settop(L, 0);

    lamx_add_table_fns(L);

    lua_newtable(L);
    lamx_push_bus_fns(L);
    lamx_push_subscription_fns(L);
    lamx_push_be_fns(L);
    lamx_push_el_fns(L);
    lamx_push_json_fns(L);
    lamx_push_dm_mt(L);
    lamx_push_object_mt(L);
    lamx_push_param_mt(L);
    lamx_push_transaction_mt(L);
    lamx_push_config_fns(L);

    lua_pushcfunction(L, lamx_auto_connect);
    lua_setfield(L, -2, "auto_connect");

    lua_pushcfunction(L, lamx_disconnect_all);
    lua_setfield(L, -2, "disconnect_all");

    amxp_sigmngr_add_signal(NULL, "wait:done");

    return 1;  // Return the empty table.
}

/***
   Loads all available back-ends and connects to all available known bus sockets.

   Loads all back-ends that are installed in the default location "/usr/bin/mods/amxb".

   Opens all detected known bus sockets.

   @usage
   local lamx = require 'lamx'

   lamx.auto_connect("public")

   @function lamx.auto_connect

   @param access (optional, default = "public") Can be "public" or "protected"

 */

/***
   Closes all open sockets and unloads all loaded back-ends.

   This method is typically called at the end of the lua scripts.

   @usage
   local lamx = require 'lamx'

   lamx.auto_connect("public")

   -- do something

   lamx.disconnect_all()

   @function lamx.disconnect_all
 */

DESTRUCTOR static void luaclose_lamx(void) {
    amxc_var_delete(&cfg);
}

