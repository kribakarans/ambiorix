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
#include <sys/signalfd.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>

#include <stdlib.h>
#include <stdio.h>
#include <setjmp.h>
#include <stdarg.h>
#include <cmocka.h>
#include <string.h>

#include <amxc/amxc.h>
#include <amxp/amxp.h>
#include <amxd/amxd_dm.h>
#include <amxo/amxo.h>
#include <amxb/amxb_register.h>

#include "lua_amx.h"

#include "../mocks/dummy_be.h"
#include "../mocks/test_common.h"

#include "test_transaction.h"

static lua_State* L;

int test_lamx_setup(UNUSED void** state) {
    L = luaL_newstate();
    luaL_openlibs(L);
    luaopen_lamx(L);
    lua_setglobal(L, "lamx");

    block_sigalrm();

    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "lamx.dm.create()"));
    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "lamx.dm.load(\"../test_data/odl/greeter_definition.odl\")"));
    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "lamx.dm.load(\"../test_data/odl/mib.odl\")"));

    return 0;
}

int test_lamx_teardown(UNUSED void** state) {
    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "lamx.dm.destroy()"));

    lua_close(L);

    return 0;
}

void test_can_set_values(UNUSED void** state) {
    amxc_var_t data;
    amxc_var_init(&data);

    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "trans = lamx.transaction.new()"));
    assert_false(luaL_dostring(L, "trans:select(\"Greeter.History.1.Info.1.\")"));
    assert_false(luaL_dostring(L, "trans:set(\"Text\",\"Hallo\")"));
    assert_false(luaL_dostring(L, "trans:select(\"Greeter.History.1.Info.2.\")"));
    assert_false(luaL_dostring(L, "trans:set(\"Text\",\"Hallo\")"));
    assert_false(luaL_dostring(L, "obj = lamx.dm.find(\"Greeter.History.1.Info.3.\")"));
    assert_false(luaL_dostring(L, "trans:select(obj)"));
    assert_false(luaL_dostring(L, "trans:set(\"Text\",\"Hallo\")"));
    assert_false(luaL_dostring(L, "status = trans:apply()"));

    lua_getglobal(L, "status");
    lamx_lua2var(L, 1, &data);
    assert_int_equal(amxc_var_type_of(&data), AMXC_VAR_ID_INT64);
    assert_int_equal(GET_UINT32(&data, NULL), 0);

    amxc_var_clean(&data);
}

void test_can_set_read_only_values(UNUSED void** state) {
    amxc_var_t data;
    amxc_var_init(&data);

    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "trans = lamx.transaction.new(true)"));
    assert_false(luaL_dostring(L, "trans:select(\"Greeter.History.1.Info.1.\")"));
    assert_false(luaL_dostring(L, "trans:set(\"RText\",\"Hallo\")"));
    assert_false(luaL_dostring(L, "status = trans:apply()"));

    lua_getglobal(L, "status");
    lamx_lua2var(L, 1, &data);
    assert_int_equal(amxc_var_type_of(&data), AMXC_VAR_ID_INT64);
    assert_int_equal(GET_UINT32(&data, NULL), 0);

    amxc_var_clean(&data);
}

void test_can_set_protected_values(UNUSED void** state) {
    amxc_var_t data;
    amxc_var_init(&data);

    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "trans = lamx.transaction.new(false, \"protected\")"));
    assert_false(luaL_dostring(L, "trans:select(\"Greeter.History.1.Info.1.\")"));
    assert_false(luaL_dostring(L, "trans:set(\"PText\",\"Hallo\")"));
    assert_false(luaL_dostring(L, "status = trans:apply()"));

    lua_getglobal(L, "status");
    lamx_lua2var(L, 1, &data);
    assert_int_equal(amxc_var_type_of(&data), AMXC_VAR_ID_INT64);
    assert_int_equal(GET_UINT32(&data, NULL), 0);

    amxc_var_clean(&data);
}

void test_can_set_private_values(UNUSED void** state) {
    amxc_var_t data;
    amxc_var_init(&data);

    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "trans = lamx.transaction.new(false, \"private\")"));
    assert_false(luaL_dostring(L, "trans:select(\"Greeter.History.1.Info.1.\")"));
    assert_false(luaL_dostring(L, "trans:set(\"PrivText\",\"Hallo\")"));
    assert_false(luaL_dostring(L, "status = trans:apply()"));

    lua_getglobal(L, "status");
    lamx_lua2var(L, 1, &data);
    assert_int_equal(amxc_var_type_of(&data), AMXC_VAR_ID_INT64);
    assert_int_equal(GET_UINT32(&data, NULL), 0);

    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "trans = lamx.transaction.new(false, \"protected\")"));
    assert_false(luaL_dostring(L, "trans:select(\"Greeter.History.1.Info.1.\")"));
    assert_false(luaL_dostring(L, "trans:set(\"PrivText\",\"Hallo\")"));
    assert_false(luaL_dostring(L, "status = trans:apply()"));

    lua_getglobal(L, "status");
    lamx_lua2var(L, 1, &data);
    assert_int_equal(amxc_var_type_of(&data), AMXC_VAR_ID_INT64);
    assert_int_not_equal(GET_UINT32(&data, NULL), 0);

    amxc_var_clean(&data);
}

void test_can_add_instance(UNUSED void** state) {
    amxc_var_t data;
    amxc_var_init(&data);

    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "trans = lamx.transaction.new(false, \"public\")"));
    assert_false(luaL_dostring(L, "trans:select(\"Greeter.History.1.Info.\")"));
    assert_false(luaL_dostring(L, "trans:add_instance()"));
    assert_false(luaL_dostring(L, "status = trans:apply()"));

    lua_getglobal(L, "status");
    lamx_lua2var(L, 1, &data);
    assert_int_equal(amxc_var_type_of(&data), AMXC_VAR_ID_INT64);
    assert_int_equal(GET_UINT32(&data, NULL), 0);

    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "trans = lamx.transaction.new(false, \"public\")"));
    assert_false(luaL_dostring(L, "trans:select(\"Greeter.History.1.Info.\")"));
    assert_false(luaL_dostring(L, "trans:add_instance(0, \"MyAlias\")"));
    assert_false(luaL_dostring(L, "status = trans:apply()"));

    amxc_var_clean(&data);
}

void test_can_del_instance(UNUSED void** state) {
    amxc_var_t data;
    amxc_var_init(&data);

    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "trans = lamx.transaction.new()"));
    assert_false(luaL_dostring(L, "trans:select(\"Greeter.History.1.Info.\")"));
    assert_false(luaL_dostring(L, "trans:del_instance(1)"));
    assert_false(luaL_dostring(L, "trans:del_instance(0, \"MyAlias\")"));
    assert_false(luaL_dostring(L, "status = trans:apply()"));

    lua_getglobal(L, "status");
    lamx_lua2var(L, 1, &data);
    assert_int_equal(amxc_var_type_of(&data), AMXC_VAR_ID_INT64);
    assert_int_equal(GET_UINT32(&data, NULL), 0);

    amxc_var_clean(&data);
}

void test_del_instance_fails_if_no_index_or_name(UNUSED void** state) {
    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "trans = lamx.transaction.new()"));
    assert_false(luaL_dostring(L, "trans:select(\"Greeter.History.1.Info.\")"));
    assert_true(luaL_dostring(L, "trans:del_instance()"));
}

void test_can_add_mib(UNUSED void** state) {
    amxc_var_t data;
    amxc_var_init(&data);

    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "trans = lamx.transaction.new()"));
    assert_false(luaL_dostring(L, "trans:select(\"Greeter.History.1.\")"));
    assert_false(luaL_dostring(L, "trans:add_mib(\"TestMib\")"));
    assert_false(luaL_dostring(L, "trans:set(\"Extra\",\"Test\")"));
    assert_false(luaL_dostring(L, "status = trans:apply()"));

    lua_getglobal(L, "status");
    lamx_lua2var(L, 1, &data);
    assert_int_equal(amxc_var_type_of(&data), AMXC_VAR_ID_INT64);
    assert_int_equal(GET_UINT32(&data, NULL), 0);

    amxc_var_clean(&data);
}

void test_calling_invalid_function_on_trans_class_fails(UNUSED void** state) {
    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "trans = lamx.transaction.new()"));
    assert_true(luaL_dostring(L, "trans:slct(\"Greeter.History.1.\")"));
}