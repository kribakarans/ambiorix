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

#include "test_json.h"

static lua_State* L;

int test_lamx_setup(UNUSED void** state) {
    amxb_bus_ctx_t* bus_ctx = NULL;

    L = luaL_newstate();
    luaL_openlibs(L);
    luaopen_lamx(L);
    lua_setglobal(L, "lamx");

    block_sigalrm();

    assert_int_equal(test_register_dummy_be(), 0);
    assert_int_equal(amxb_connect(&bus_ctx, "dummy:/tmp/dummy.sock"), 0);
    amxb_set_access(bus_ctx, amxd_dm_access_public);

    handle_events();

    assert_int_equal(test_load_dummy_remote("../test_data/odl/greeter_definition.odl"), 0);

    return 0;
}

int test_lamx_teardown(UNUSED void** state) {
    test_unregister_dummy_be();

    lua_close(L);

    return 0;
}

void test_can_create_and_parse_json(UNUSED void** state) {
    amxc_var_t data;
    amxc_var_init(&data);

    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "data = lamx.bus.get(\"Greeter.History.*.\")"));
    lua_getglobal(L, "data");
    lamx_lua2var(L, 1, &data);

    amxc_var_dump(&data, STDOUT_FILENO);
    assert_int_equal(amxc_var_type_of(&data), AMXC_VAR_ID_HTABLE);

    assert_false(luaL_dostring(L, "json = lamx.json.create(data)"));
    assert_false(luaL_dostring(L, "parsed = lamx.json.parse(json)"));
    assert_false(luaL_dostring(L, "result = table.compare(data, parsed)"));

    lua_settop(L, 0);
    lua_getglobal(L, "result");
    lamx_lua2var(L, 1, &data);

    amxc_var_dump(&data, STDOUT_FILENO);
    assert_int_equal(amxc_var_type_of(&data), AMXC_VAR_ID_INT64);
    assert_int_equal(GET_INT32(&data, 0), 0);

    amxc_var_clean(&data);
}
