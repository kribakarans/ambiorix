/****************************************************************************
**
** Copyright (c) 2020 SoftAtHome
**
** Redistribution and use in source and binary forms, with or
** without modification, are permitted provided that the following
** conditions are met:
**
** 1. Redistributions of source code must retain the above copyright
** notice, this list of conditions and the following disclaimer.
**
** 2. Redistributions in binary form must reproduce the above
** copyright notice, this list of conditions and the following
** disclaimer in the documentation and/or other materials provided
** with the distribution.
**
** Subject to the terms and conditions of this license, each
** copyright holder and contributor hereby grants to those receiving
** rights under this license a perpetual, worldwide, non-exclusive,
** no-charge, royalty-free, irrevocable (except for failure to
** satisfy the conditions of this license) patent license to make,
** have made, use, offer to sell, sell, import, and otherwise
** transfer this software, where such license applies only to those
** patent claims, already acquired or hereafter acquired, licensable
** by such copyright holder or contributor that are necessarily
** infringed by:
**
** (a) their Contribution(s) (the licensed copyrights of copyright
** holders and non-copyrightable additions of contributors, in
** source or binary form) alone; or
**
** (b) combination of their Contribution(s) with the work of
** authorship to which such Contribution(s) was added by such
** copyright holder or contributor, if, at the time the Contribution
** is added, such addition causes such combination to be necessarily
** infringed. The patent license shall not apply to any other
** combinations which include the Contribution.
**
** Except as expressly stated above, no rights or licenses from any
** copyright holder or contributor is granted under this license,
** whether expressly, by implication, estoppel or otherwise.
**
** DISCLAIMER
**
** THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
** CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
** INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
** MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
** DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR
** CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
** SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
** LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
** USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
** AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
** LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
** ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
** POSSIBILITY OF SUCH DAMAGE.
**
****************************************************************************/

#include <stdlib.h>
#include <string.h>

#include "lua_amx.h"

/***
   Ambiorix LUA JSON creation and parsing
   @classmod JSON
 */

/***
   Create JSON string.

   @usage
   local lamx = require 'lamx'
   local data = { "key1" = "value1", "key2" = "value2" }

   local json_string = lamx.json.create(data)
   print(json_string)

   @function lamx.json.create

   @param data any kind of data that must bew transformed to a json string.

   @return
   A string containing the JSON representation of the given data.
 */
static int lamx_json_create(lua_State* L) {
    amxc_var_t data;
    char* json_string = NULL;
    amxc_var_init(&data);

    lamx_lua2var(L, 1, &data);
    amxc_var_cast(&data, AMXC_VAR_ID_JSON);
    amxc_var_cast(&data, AMXC_VAR_ID_CSTRING);
    json_string = amxc_var_take(cstring_t, &data);
    lua_pushstring(L, json_string);

    free(json_string);
    amxc_var_clean(&data);
    return 1;
}

/***
   Parse JSON string.

   @usage
   local lamx = require 'lamx'
   local json_string = '{ "key1" = "value1", "key2" = "value2" }'

   local data = lamx.json.parse(data)
   print(json_string)

   @function lamx.json.parse

   @param json_string a string containing a valid json string.

   @return
   An lua object representing the parsed json string.
 */
static int lamx_json_parse(lua_State* L) {
    amxc_var_t data;
    const char* json_string = luaL_checkstring(L, 1);

    amxc_var_init(&data);

    amxc_var_set(jstring_t, &data, json_string);
    amxc_var_cast(&data, AMXC_VAR_ID_ANY);
    lamx_var2lua(&data, L);

    amxc_var_clean(&data);
    return 1;
}

void lamx_push_json_fns(lua_State* L) {
    static struct luaL_Reg fns[] = {
        {"create", lamx_json_create},
        {"parse", lamx_json_parse},
        {NULL, NULL}
    };

    luaL_newlib(L, fns);  // Push a new table with fns key/vals.
    lua_setfield(L, -2, "json");
}
