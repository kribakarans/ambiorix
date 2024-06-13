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

#include <event2/event.h>

#include "lua_amx.h"

/***
   Ambiorix LUA eventloop class
   @classmod eventloop
 */

typedef struct _el_data {
    struct event* read;
    amxc_llist_it_t it;
} el_data_t;

typedef struct _lua_amx_el {
    struct event_base* base;
    struct event* signal_int;
    struct event* signal_term;
    struct event* signal_alrm;
    struct event* amxp_sig;
    amxc_llist_t event_handlers;
} lua_amx_el_t;

static void lamx_el_signal_cb(UNUSED evutil_socket_t fd,
                              UNUSED short event,
                              void* arg) {
    lua_amx_el_t* el = (lua_amx_el_t*) arg;

    event_base_loopbreak(el->base);
}

static void lamx_el_amxp_signal_read_cb(UNUSED evutil_socket_t fd,
                                        UNUSED short flags,
                                        UNUSED void* arg) {
    amxp_signal_read();
}

static void lamx_el_read_cb(UNUSED evutil_socket_t fd,
                            UNUSED short flags,
                            void* arg) {
    amxb_bus_ctx_t* ctx = (amxb_bus_ctx_t*) arg;
    amxb_read(ctx);
}

static void lamx_el_signal_timers(UNUSED evutil_socket_t fd,
                                  UNUSED short event,
                                  UNUSED void* arg) {
    amxp_timers_calculate();
    amxp_timers_check();
}

static void lamx_el_remove_bus_event_handler(amxc_llist_it_t* it) {
    el_data_t* el_data = amxc_container_of(it, el_data_t, it);
    event_del(el_data->read);
    free(el_data->read);
    free(el_data);
}

static void lamx_el_add_bus_fds(lua_amx_el_t* el) {
    amxc_array_t* uris = amxb_list_uris();
    uint32_t size = amxc_array_size(uris);

    for(uint32_t i = 0; i < size; i++) {
        amxb_bus_ctx_t* ctx = amxb_find_uri((const char*) amxc_array_get_data_at(uris, i));
        el_data_t* el_data = (el_data_t*) calloc(1, sizeof(el_data_t));
        int fd = amxb_get_fd(ctx);
        el_data->read = event_new(el->base, fd, EV_READ | EV_PERSIST,
                                  lamx_el_read_cb, ctx);
        event_add(el_data->read, NULL);
        amxc_llist_append(&el->event_handlers, &el_data->it);
    }

    amxc_array_delete(&uris, NULL);
}

static int lamx_el_create(lua_amx_el_t* el) {
    int retval = -1;

    el->base = event_base_new();
    when_null(el->base, exit)

    el->signal_int = evsignal_new(el->base, SIGINT, lamx_el_signal_cb, el);
    event_add(el->signal_int, NULL);

    el->signal_term = evsignal_new(el->base, SIGTERM, lamx_el_signal_cb, el);
    event_add(el->signal_term, NULL);

    el->amxp_sig = event_new(el->base, amxp_signal_fd(), EV_READ | EV_PERSIST,
                             lamx_el_amxp_signal_read_cb, NULL);
    event_add(el->amxp_sig, NULL);

    el->signal_alrm = evsignal_new(el->base, SIGALRM, lamx_el_signal_timers, NULL);
    event_add(el->signal_alrm, NULL);

    amxc_llist_init(&el->event_handlers);

    retval = 0;

exit:
    return retval;
}

static int lamx_el_destroy(lua_amx_el_t* el) {
    amxc_llist_clean(&el->event_handlers, lamx_el_remove_bus_event_handler);

    event_del(el->signal_int);
    event_del(el->signal_term);
    event_del(el->amxp_sig);
    event_del(el->signal_alrm);
    event_base_free(el->base);

    el->base = NULL;

    free(el->signal_term);
    el->signal_term = NULL;
    free(el->signal_int);
    el->signal_int = NULL;
    free(el->amxp_sig);
    el->amxp_sig = NULL;
    free(el->signal_alrm);
    el->signal_alrm = NULL;

    return 0;
}

/***
   Starts the eventloop.

   When the eventloop is started, all open bus connections are monitored for
   events.

   @usage
   local lamx = require 'lamx'
   local el = lamx.eventloop.new()

   lamx.backend.load("/usr/bin/mods/amxb/mod-amxb-ubus.so")
   lamx.bus.open("ubus:")

   el:start()

   lamx.backend.remove("ubus")

   @function eventloop:start
 */
static int lamx_el_start(lua_State* L) {
    lua_amx_el_t* amx_el = (lua_amx_el_t*) luaL_checkudata(L, 1, lamx_el_mt);
    amxd_dm_t* dm = lamx_get_dm(L);
    amxo_parser_t* parser = lamx_get_parser(L);

    lamx_el_add_bus_fds(amx_el);

    if((parser != NULL) && (dm != NULL)) {
        bool handle_events = GET_BOOL(&parser->config, COPT_HANDLE_EVENTS);
        if(parser->post_includes != NULL) {
            amxo_parser_invoke_entry_points(parser, dm, AMXO_START);
            amxo_parser_invoke_entry_points(parser, dm, AMXO_ODL_LOADED);
        } else {
            amxo_parser_invoke_entry_points(parser, dm, AMXO_START);
        }

        if(handle_events) {
            while(amxp_signal_read() == 0) {
            }
        }

        amxp_sigmngr_trigger_signal(&dm->sigmngr, "app:start", NULL);
    }

    event_base_dispatch(amx_el->base);

    if((parser != NULL) && (dm != NULL)) {
        amxo_parser_rinvoke_entry_points(parser, dm, AMXO_STOP);
    }

    return 0;
}

/***
   Stops the eventloop.

   @function eventloop:stop
 */
static int lamx_el_stop(lua_State* L) {
    lua_amx_el_t* amx_el = (lua_amx_el_t*) luaL_checkudata(L, 1, lamx_el_mt);

    event_base_loopbreak(amx_el->base);
    amxc_llist_clean(&amx_el->event_handlers, lamx_el_remove_bus_event_handler);

    return 0;
}

static lua_CFunction lamx_el_get_function(const char* name) {
    lua_CFunction fn = NULL;
    int i = 0;

    static struct luaL_Reg funcs[] = {
        {"start", lamx_el_start},
        {"stop", lamx_el_stop},
        {NULL, NULL}
    };

    while(funcs[i].name != NULL) {
        if(strcmp(name, funcs[i].name) == 0) {
            fn = funcs[i].func;
            break;
        }
        i++;
    }

    return fn;
}

static int lamx_el_mt_index(lua_State* L) {
    const char* name = luaL_checkstring(L, 2);
    lua_CFunction fn = NULL;

    fn = lamx_el_get_function(name);
    if(fn != NULL) {
        lua_pushcfunction(L, fn);
    } else {
        luaL_error(L, "Failed to fetch 'eventloop.%s'", name);
    }

    return 1;
}

static int lamx_el_mt_gc(lua_State* L) {
    lua_amx_el_t* amx_el = (lua_amx_el_t*) luaL_checkudata(L, 1, lamx_el_mt);
    lamx_el_destroy(amx_el);
    return 0;
}

/***
   Create eventloop.

   @usage
   local lamx = require 'lamx'
   local el = lamx.eventloop.new()

   lamx.backend.load("/usr/bin/mods/amxb/mod-amxb-ubus.so")
   lamx.bus.open("ubus:")

   el:start()

   lamx.backend.remove("ubus")

   @function lamx.eventloop.new

   @return
   Eventloop instance.
 */
static int lamx_el_new(lua_State* L) {
    lua_amx_el_t* amx_el = NULL;

    amx_el = (lua_amx_el_t*) lua_newuserdata(L, sizeof(lua_amx_el_t));
    luaL_getmetatable(L, lamx_el_mt);
    lua_setmetatable(L, -2);

    lamx_el_create(amx_el);

    return 1;
}

void lamx_push_el_fns(lua_State* L) {
    if(luaL_newmetatable(L, lamx_el_mt)) {
        static struct luaL_Reg metamethods[] = {
            {"__index", lamx_el_mt_index},
            {"__gc", lamx_el_mt_gc},
            {NULL, NULL}
        };

        luaL_setfuncs(L, metamethods, 0);
        lua_pop(L, 1);  // The table is saved in the Lua's registry.
    }

    static struct luaL_Reg fns[] = {
        {"new", lamx_el_new},
        {NULL, NULL}
    };

    luaL_newlib(L, fns);  // Push a new table with fns key/vals.
    lua_setfield(L, -2, "eventloop");
}
