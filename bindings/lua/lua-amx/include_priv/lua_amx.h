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
#if !defined(__AMX_LUA_H__)
#define __AMX_LUA_H__

#ifdef __cplusplus
extern "C"
{
#endif

#if defined(LUA_VERSION_5_1)
#include "lamx_lua5.1.h"
#elif defined(LUA_VERSION_5_3)
#include "lamx_lua5.3.h"
#else
// lua version not defined
// so we will guess it from the headers

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#if defined(LUA_VERSION_NUM)
#if LUA_VERSION_NUM == 501
#include "lamx_lua5.1.h"
#elif LUA_VERSION_NUM == 503
#include "lamx_lua5.3.h"
#endif
#endif

#endif

#include <yajl/yajl_gen.h>
#include <amxc/amxc_macros.h>
#include <amxc/amxc.h>
#include <amxj/amxj_variant.h>
#include <amxp/amxp.h>
#include <amxd/amxd_types.h>
#include <amxd/amxd_dm.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_object_event.h>
#include <amxd/amxd_function.h>
#include <amxd/amxd_transaction.h>
#include <amxd/amxd_path.h>

#include <amxo/amxo.h>
#include <amxo/amxo_mibs.h>
#include <amxo/amxo_save.h>

#include <amxb/amxb.h>
#include <amxb/amxb_register.h>

#define MOD_LUA_AMX_FNS         "amx:lua_functions"
#define MOD_LUA_AMX_DM          "amx:lua_dm"
#define MOD_LUA_AMX_PARSER      "amx:lua_parser"
#define MOD_LUA_AMX_RPC_FUNC    "amx:rpc_func"
#define MOD_LUA_AMX_EVENT_FUNC  "amx:event_func"
#define MOD_LUA_AMX_EP_FUNC     "amx:ep_func"
#define MOD_LUA_AMX_ACTION_FUNC "amx:action_func"
#define MOD_LUA_AMX_CONFIG      "amx:config"

#define lamx_el_mt           "AMX.Eventloop"
#define lamx_subscription_mt "AMX.Subscription"
#define lamx_object_mt       "AMX.DMObject"
#define lamx_transaction_mt  "AMX.DMTransaction"
#define lamx_param_mt        "AMX.DMParam"

#define COPT_INCDIRS "include-dirs"
#define COPT_LIBDIRS "import-dirs"
#define COPT_MIBDIRS "mib-dirs"
#define COPT_PLUGIN_DIR "plugin-dir"
#define COPT_HANDLE_EVENTS "dm-events-before-start"

#define PLUGIN_DIR "/usr/lib/amx"

typedef struct _lamx_dm_object {
    char* path;
} lamx_dm_object_t;

typedef struct _lamx_dm_param {
    char* path;
    char* name;
} lamx_dm_param_t;

typedef struct _lamx_dm_transaction {
    amxd_trans_t* transaction;
} lamx_dm_transaction_t;

int luaopen_lamx(lua_State* L);

PRIVATE void lamx_lua_stack_dump(lua_State* L);

PRIVATE int lamx_push_object(lua_State* L, amxd_object_t* object);

PRIVATE int lamx_push_param(lua_State* L, amxd_param_t* param);

PRIVATE amxb_bus_ctx_t* lamx_get_ctx(const char* path);
PRIVATE amxd_dm_t* lamx_get_dm(lua_State* L);
PRIVATE amxo_parser_t* lamx_get_parser(lua_State* L);
PRIVATE lua_CFunction lamx_get_function(struct luaL_Reg* fns, const char* name);

PRIVATE void lamx_push_be_fns(lua_State* L);
PRIVATE void lamx_push_bus_fns(lua_State* L);
PRIVATE void lamx_push_subscription_fns(lua_State* L);
PRIVATE void lamx_push_el_fns(lua_State* L);
PRIVATE void lamx_push_json_fns(lua_State* L);
PRIVATE void lamx_add_table_fns(lua_State* L);
PRIVATE void lamx_push_dm_mt(lua_State* L);
PRIVATE void lamx_push_object_mt(lua_State* L);
PRIVATE void lamx_push_param_mt(lua_State* L);
PRIVATE void lamx_push_transaction_mt(lua_State* L);
PRIVATE void lamx_push_config_fns(lua_State* L);

PRIVATE int lamx_bus_subscribe(lua_State* L);

PRIVATE void lamx_var2lua(const amxc_var_t* data, lua_State* L);
PRIVATE void lamx_lua2var(lua_State* L, int index, amxc_var_t* data);

#ifdef __cplusplus
}
#endif

#endif // __AMX_LUA_H__
