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

static void lamx_var_list2lua_table(const amxc_var_t* list, lua_State* L) {
    int index = 1;
    uint32_t length = amxc_llist_size(amxc_var_constcast(amxc_llist_t, list));

    // create a table on the stack
    lua_createtable(L, length, 4);

    amxc_var_for_each(var, list) {
        // push the index
        lua_pushinteger(L, index);
        // push the value
        lamx_var2lua(var, L);
        // add to table
        lua_settable(L, -3);

        index++;
    }
}

static void lamx_var_table2lua_table(const amxc_var_t* table, lua_State* L) {
    uint32_t length = amxc_htable_size(amxc_var_constcast(amxc_htable_t, table));

    // create a table on the stack
    lua_createtable(L, length, 4);

    amxc_var_for_each(var, table) {
        // push the key
        lua_pushstring(L, amxc_var_key(var));
        // push the value
        lamx_var2lua(var, L);
        // add to table
        lua_settable(L, -3);
    }
}

void lamx_var2lua(const amxc_var_t* data, lua_State* L) {
    switch(amxc_var_type_of(data)) {
    default:
    case AMXC_VAR_ID_NULL:
        lua_pushnil(L);
        break;
    case AMXC_VAR_ID_CSTRING:
    case AMXC_VAR_ID_CSV_STRING:
    case AMXC_VAR_ID_SSV_STRING:
        lua_pushstring(L, GET_CHAR(data, NULL));
        break;
    case AMXC_VAR_ID_INT8:
    case AMXC_VAR_ID_INT16:
    case AMXC_VAR_ID_INT32:
    case AMXC_VAR_ID_INT64:
    case AMXC_VAR_ID_UINT8:
    case AMXC_VAR_ID_UINT16:
    case AMXC_VAR_ID_UINT32:
    case AMXC_VAR_ID_UINT64:
        lua_pushinteger(L, amxc_var_dyncast(int64_t, data));
        break;
    case AMXC_VAR_ID_BOOL:
        lua_pushboolean(L, amxc_var_constcast(bool, data));
        break;
    case AMXC_VAR_ID_LIST:
        lamx_var_list2lua_table(data, L);
        break;
    case AMXC_VAR_ID_HTABLE:
        lamx_var_table2lua_table(data, L);
        break;
    case AMXC_VAR_ID_DOUBLE:
        lua_pushnumber(L, amxc_var_constcast(double, data));
        break;
    }
}
