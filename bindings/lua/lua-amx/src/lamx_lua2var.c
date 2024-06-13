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

static void lamx_lua_table2var(lua_State* L, int index, amxc_var_t* data) {
    bool isArray = false;

    /* a lua table can be an array,
       by convention we assume that when the first element in the table has a numeric key it is an array
     */

    if(index < 0) {
        index--;
    }
    lua_pushnil(L);  /* first key */

    if(lua_next(L, index) == 0) {
        // the table is empty, leave
        amxc_var_set_type(data, AMXC_VAR_ID_HTABLE);
        goto exit;
    }

    if(lua_type(L, -2) == LUA_TNUMBER) {
        /* we assume this is an array */
        isArray = true;
        amxc_var_set_type(data, AMXC_VAR_ID_LIST);
    } else {
        amxc_var_set_type(data, AMXC_VAR_ID_HTABLE);
    }

    // remove first key and value from the stack
    lua_pop(L, 2);

    lua_pushnil(L);  /* first key */
    while(lua_next(L, index) != 0) {
        /* uses 'key' (at index -2) and 'value' (at index -1) */

        // duplicate key
        lua_pushvalue(L, -2); // set key on top of the stack and value as second

        // skip functions
        if(lua_type(L, -2) != LUA_TFUNCTION) {
            // add element to variant list or variant map
            if(isArray) {
                amxc_var_t* item = amxc_var_add_new(data);
                lamx_lua2var(L, -2, item);
            } else {
                const char* key = lua_tostring(L, -1);
                amxc_var_t* item = amxc_var_add_new_key(data, key);
                lamx_lua2var(L, -2, item);
            }
        }

        /* removes 'value' and duplicated 'key'; keeps orignal 'key' for next iteration */
        /* pop 2 elements from the stack */
        lua_pop(L, 2);
    }

    // pop the key from the stack
    if(index < 0) {
        index++;
    }

exit:
    return;
}

void lamx_lua2var(lua_State* L, int index, amxc_var_t* data) {
    int type = lua_type(L, index);
    switch(type) {
    case LUA_TFUNCTION:
    case LUA_TUSERDATA:
    case LUA_TTHREAD:
    case LUA_TLIGHTUSERDATA:
    case LUA_TNIL:
        amxc_var_set_type(data, AMXC_VAR_ID_NULL);
        break;
    case LUA_TNUMBER: {
        int i = lua_tointeger(L, index);
        double d = lua_tonumber(L, index);
        if(d != (double) i) {
            amxc_var_set(double, data, d);
        } else {
            amxc_var_set(int64_t, data, i);
        }
    }
    break;
    case LUA_TBOOLEAN:
        amxc_var_set(bool, data, lua_toboolean(L, index));
        break;
    case LUA_TSTRING:
        amxc_var_set(cstring_t, data, lua_tostring(L, index));
        break;
    case LUA_TTABLE:
        lamx_lua_table2var(L, index, data);
        break;
    }
}
