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

#include <event2/event.h>

#include "lua_amx.h"

/***
   Ambiorix LUA table extensions functions
   @classmod table
 */

static int is_quote(int c) {
    if(c == '\'') {
        return 1;
    } else {
        return 0;
    }
}

/***
   Find an entry in a table by path.

   The use of this function is similar to the use of the dot operator in Lua.
   Often this function is used in combination with table.filter which returns
   a list of paths to the items that match a given criteria.

   @usage
   local lamx = require 'lamx'
   local mytable = { key1 = "value1", key2 = "value2", key3 = { 20, 40 }, key4 = { s1 = "text", s2 = true} }
   local data = table.get(mytable, "key3.1") -- is the same as mytable["key3"][2] or mytable.key3[2]
   print(data)
   data = table.get(mytable, "key4.s1") -- is the same as mytable["key4"]["s1"] or mytable.key4.s1
   print(data)

   @function table.get

   @param table the table to search in
   @param path the path to the item to get

   @return
   the value of the item or nil if not found
 */
static int lamx_table_get(lua_State* L) {
    const char* path = luaL_checkstring(L, 2);
    amxc_string_t path_str;
    amxc_var_t data;
    amxc_llist_t parts;
    luaL_checktype(L, 1, LUA_TTABLE);

    amxc_var_init(&data);
    amxc_string_init(&path_str, 0);
    amxc_string_set(&path_str, path);
    amxc_llist_init(&parts);

    lua_pushvalue(L, 1);
    amxc_string_split_to_llist(&path_str, &parts, '.');

    amxc_llist_for_each(it, &parts) {
        amxc_string_t* part = amxc_container_of(it, amxc_string_t, it);
        amxc_string_trim(part, is_quote);
        if(amxc_string_is_numeric(part)) {
            lua_rawgeti(L, -1, strtol(amxc_string_get(part, 0), NULL, 10) + 1);
        } else {
            lua_getfield(L, -1, amxc_string_get(part, 0));
        }
    }

    amxc_var_clean(&data);
    amxc_llist_clean(&parts, amxc_string_list_it_free);
    amxc_string_clean(&path_str);
    return 1;
}

/***
   Find matching items in a table.

   To get the values of the matching items, use table.get.

   @usage
   local lamx = require 'lamx'
   local mytable = {
      ["00:01:02:03:44:f0"] = { },
      ["94:83:c4:06:da:66"] = {
          {
              Extender = true,
              MACAddress = "00:01:02:03:44:f0"
          },
          {
              Extender = false,
              MACAddress = "00:00:55:3b:05",
          }
      }
   }
   local matching = table.filter(mytable, "94:83:c4:06:da:66.[MACAddress == '00:01:02:03:44:f0'].Extender")

   @function table.filter

   @param table the table to search in
   @param filter the filter expression

   @return
   A table containing the paths to the matching items
 */
static int lamx_table_filter(lua_State* L) {
    const char* filter = luaL_checkstring(L, 2);
    amxc_var_t data;
    amxc_llist_t paths;
    uint32_t length = 0;
    uint32_t index = 1;
    luaL_checktype(L, 1, LUA_TTABLE);

    amxc_llist_init(&paths);
    amxc_var_init(&data);
    lamx_lua2var(L, 1, &data);
    amxp_expr_find_var_paths(&data, &paths, filter);

    length = amxc_llist_size(&paths);

    // create a table on the stack
    lua_createtable(L, length, 4);

    amxc_llist_for_each(it, &paths) {
        amxc_string_t* path = amxc_container_of(it, amxc_string_t, it);
        // push the index
        lua_pushinteger(L, index);
        // push the value
        lua_pushstring(L, amxc_string_get(path, 0));
        // add to table
        lua_settable(L, -3);

        index++;
    }

    amxc_llist_clean(&paths, amxc_string_list_it_free);
    amxc_var_clean(&data);
    return 1;
}

/***
   Dumps the content of a table in human-readable json like format.

   @usage
   local lamx = require 'lamx'
   local mytable = { key1 = "value1", key2 = "value2", key3 = { 20, 40 }, key4 = { s1 = "text", s2 = true} }
   table.dump(mytable)

   @function table.dump

   @param table the table to dump
 */
static int lamx_table_dump(lua_State* L) {
    amxc_var_t data;
    luaL_checktype(L, 1, LUA_TTABLE);

    amxc_var_init(&data);
    lamx_lua2var(L, 1, &data);
    amxc_var_dump(&data, STDOUT_FILENO);
    amxc_var_clean(&data);

    return 0;
}

/***
   Compare two tables

   @usage
   local lamx = require 'lamx'
   local a1 = { b = { c = 10 } }
   local a2 = { b = { c = 20 } }
   local result = table.compare(a1, a2)

   if (result == 0) then
       print("a1 equals a2")
   elseif (result < 0) then
       print("a1 is less than a2")
   else
       print("a1 is greater than a2")
   end

   @function table.compare

   @param table1 the first table
   @param table2 the second table

   @return
   0 when the tables are equal
   -1 when the first table is less than the second table
   1 when the first table is greater than the second table
 */
static int lamx_table_compare(lua_State* L) {
    amxc_var_t ldata;
    amxc_var_t rdata;
    int result = 0;
    luaL_checktype(L, 1, LUA_TTABLE);
    luaL_checktype(L, 2, LUA_TTABLE);

    amxc_var_init(&ldata);
    amxc_var_init(&rdata);
    lamx_lua2var(L, 1, &ldata);
    lamx_lua2var(L, 2, &rdata);
    amxc_var_compare(&ldata, &rdata, &result);
    amxc_var_clean(&ldata);
    amxc_var_clean(&rdata);

    lua_pushinteger(L, result);

    return 1;
}

void lamx_add_table_fns(lua_State* L) {
    lua_getglobal(L, "table");

    lua_pushliteral(L, "get");
    lua_pushcfunction(L, lamx_table_get);
    lua_settable(L, -3);
    lua_pushliteral(L, "dump");
    lua_pushcfunction(L, lamx_table_dump);
    lua_settable(L, -3);
    lua_pushliteral(L, "compare");
    lua_pushcfunction(L, lamx_table_compare);
    lua_settable(L, -3);
    lua_pushliteral(L, "filter");
    lua_pushcfunction(L, lamx_table_filter);
    lua_settable(L, -3);

    lua_settop(L, 0);
}