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

#include "test_dm.h"

static lua_State* L;

static amxd_status_t test_rpc_func(UNUSED amxd_object_t* object,
                                   UNUSED amxd_function_t* func,
                                   UNUSED amxc_var_t* args,
                                   UNUSED amxc_var_t* ret) {
    return amxd_status_ok;
}

int test_lamx_setup(UNUSED void** state) {
    L = luaL_newstate();
    luaL_openlibs(L);
    luaopen_lamx(L);
    lua_setglobal(L, "lamx");

    block_sigalrm();

    return 0;
}

int test_lamx_teardown(UNUSED void** state) {
    lua_close(L);

    return 0;
}

void test_get_config_without_datamodel_created(UNUSED void** state) {
    lua_settop(L, 0);
    // when option does not exist, fail
    assert_true(luaL_dostring(L, "option = lamx.config.get(\"TestOption\")"));
    // it must be possible to set a new config option
    assert_false(luaL_dostring(L, "lamx.config.set(\"TestOption\", \"Text\")"));
    // it must be possible to retrieve the value
    assert_false(luaL_dostring(L, "option = lamx.config.get(\"TestOption\")"));
}

void test_can_create_dm(UNUSED void** state) {
    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "lamx.dm.create()"));
    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "lamx.dm.destroy()"));
    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "lamx.dm.create(\"../test_data/odl/mib.odl\")"));
    lua_settop(L, 0);
    assert_true(luaL_dostring(L, "lamx.dm.create()"));
}

void test_can_load_odl(UNUSED void** state) {
    amxo_parser_t* parser = lamx_get_parser(L);

    amxo_resolver_ftab_add(parser,
                           "test_func",
                           AMXO_FUNC(test_rpc_func));

    amxo_resolver_ftab_add(parser,
                           "test_func2",
                           AMXO_FUNC(test_rpc_func));
    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "lamx.dm.load(\"../test_data/odl/greeter_definition.odl\")"));
}

void test_load_odl_can_fail(UNUSED void** state) {
    lua_settop(L, 0);
    assert_true(luaL_dostring(L, "lamx.dm.load(\"../test_data/odl/not_existing.odl\")"));
}

void test_can_get_config_option(UNUSED void** state) {
    amxc_var_t data;
    amxc_var_init(&data);

    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "option = lamx.config.get(\"TestOption\")"));
    lua_getglobal(L, "option");
    lamx_lua2var(L, 1, &data);
    amxc_var_dump(&data, STDOUT_FILENO);
    assert_int_equal(amxc_var_type_of(&data), AMXC_VAR_ID_INT64);
    assert_int_equal(GET_INT32(&data, NULL), 123);

    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "option = lamx.config.get(\"TestTable\")"));
    lua_getglobal(L, "option");
    lamx_lua2var(L, 1, &data);
    amxc_var_dump(&data, STDOUT_FILENO);
    assert_int_equal(amxc_var_type_of(&data), AMXC_VAR_ID_HTABLE);

    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "option = lamx.config.get(\"TestArray\")"));
    lua_getglobal(L, "option");
    lamx_lua2var(L, 1, &data);
    amxc_var_dump(&data, STDOUT_FILENO);
    assert_int_equal(amxc_var_type_of(&data), AMXC_VAR_ID_LIST);

    amxc_var_clean(&data);
}

void test_can_get_config_option_fails_if_not_existing(UNUSED void** state) {
    amxc_var_t data;
    amxc_var_init(&data);

    lua_settop(L, 0);
    assert_true(luaL_dostring(L, "option = lamx.config.get(\"NotExisting\")"));
    lua_getglobal(L, "option");
    lamx_lua2var(L, 1, &data);
    amxc_var_dump(&data, STDOUT_FILENO);

    amxc_var_clean(&data);
}

void test_can_set_config_option(UNUSED void** state) {
    amxc_var_t data;
    amxc_var_init(&data);

    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "lamx.config.set(\"TestOption\", \"Hello World\")"));

    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "lamx.config.set(\"NumberOption\", 3.1415)"));

    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "lamx.config.set(\"IntegerOption\", 3)"));

    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "option = lamx.config.get(\"TestOption\")"));
    lua_getglobal(L, "option");
    lamx_lua2var(L, 1, &data);
    amxc_var_dump(&data, STDOUT_FILENO);
    assert_int_equal(amxc_var_type_of(&data), AMXC_VAR_ID_CSTRING);
    assert_string_equal(GET_CHAR(&data, NULL), "Hello World");

    amxc_var_clean(&data);
}

void test_set_config_option_fails_without_value(UNUSED void** state) {
    lua_settop(L, 0);
    assert_true(luaL_dostring(L, "lamx.config.set(\"TestOption\")"));
}

void test_set_adds_config_option_if_not_existing(UNUSED void** state) {
    amxc_var_t data;
    amxc_var_init(&data);

    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "lamx.config.set(\"NotExisting\", \"Hello World\")"));

    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "option = lamx.config.get(\"NotExisting\")"));
    lua_getglobal(L, "option");
    lamx_lua2var(L, 1, &data);
    amxc_var_dump(&data, STDOUT_FILENO);
    assert_int_equal(amxc_var_type_of(&data), AMXC_VAR_ID_CSTRING);
    assert_string_equal(GET_CHAR(&data, NULL), "Hello World");

    amxc_var_clean(&data);
}

void test_can_get_dm_object(UNUSED void** state) {
    amxc_var_t data;
    amxc_var_init(&data);

    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "greeter_obj = lamx.dm.find(\"Greeter.\")"));
    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "history_obj = greeter_obj:find(\"History.\")"));
    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "history_obj = greeter_obj:find(\"NotExisting.\")"));
    lua_getglobal(L, "history_obj");
    lamx_lua2var(L, 1, &data);
    amxc_var_dump(&data, STDOUT_FILENO);
    assert_int_equal(amxc_var_type_of(&data), AMXC_VAR_ID_NULL);

    amxc_var_clean(&data);
}

void test_get_dm_object_fails_if_not_existing(UNUSED void** state) {
    amxc_var_t data;
    amxc_var_init(&data);

    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "not_existing = lamx.dm.find(\"Greeter.NotExisting.\")"));
    lua_getglobal(L, "not_existing");
    lamx_lua2var(L, 1, &data);

    amxc_var_dump(&data, STDOUT_FILENO);
    assert_int_equal(amxc_var_type_of(&data), AMXC_VAR_ID_NULL);

    amxc_var_clean(&data);
}

void test_can_get_dm_object_name(UNUSED void** state) {
    amxc_var_t data;
    amxc_var_init(&data);

    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "name = greeter_obj:get_name()"));

    lua_getglobal(L, "name");
    lamx_lua2var(L, 1, &data);

    amxc_var_dump(&data, STDOUT_FILENO);
    assert_int_equal(amxc_var_type_of(&data), AMXC_VAR_ID_CSTRING);
    assert_string_equal(GET_CHAR(&data, NULL), "Greeter");

    amxc_var_clean(&data);
}

void test_can_get_dm_child_object(UNUSED void** state) {
    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "history_obj = greeter_obj:find('History.1.')"));
}

void test_can_get_dm_child_object_name(UNUSED void** state) {
    amxc_var_t data;
    amxc_var_init(&data);

    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "name = history_obj:get_name()"));

    lua_getglobal(L, "name");
    lamx_lua2var(L, 1, &data);

    amxc_var_dump(&data, STDOUT_FILENO);
    assert_int_equal(amxc_var_type_of(&data), AMXC_VAR_ID_CSTRING);
    assert_string_equal(GET_CHAR(&data, NULL), "1");

    amxc_var_clean(&data);
}

void test_can_get_dm_path(UNUSED void** state) {
    amxc_var_t data;
    amxc_var_init(&data);

    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "path = history_obj:get_path()"));

    lua_getglobal(L, "path");
    lamx_lua2var(L, 1, &data);

    amxc_var_dump(&data, STDOUT_FILENO);
    assert_int_equal(amxc_var_type_of(&data), AMXC_VAR_ID_CSTRING);
    assert_string_equal(GET_CHAR(&data, NULL), "Greeter.History.1.");

    amxc_var_clean(&data);
}

void test_can_get_dm_index(UNUSED void** state) {
    amxc_var_t data;
    amxc_var_init(&data);

    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "index = history_obj:get_index()"));

    lua_getglobal(L, "index");
    lamx_lua2var(L, 1, &data);

    amxc_var_dump(&data, STDOUT_FILENO);
    assert_int_equal(GET_UINT32(&data, NULL), 1);

    lua_settop(L, 0);
    assert_true(luaL_dostring(L, "index = greeter_obj:get_index()"));

    amxc_var_clean(&data);
}

void test_can_get_parent(UNUSED void** state) {
    amxc_var_t data;
    amxc_var_init(&data);

    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "parent = history_obj:get_parent()"));
    assert_false(luaL_dostring(L, "path = parent:get_path()"));

    lua_getglobal(L, "path");
    lamx_lua2var(L, 1, &data);

    amxc_var_dump(&data, STDOUT_FILENO);
    assert_int_equal(amxc_var_type_of(&data), AMXC_VAR_ID_CSTRING);
    assert_string_equal(GET_CHAR(&data, NULL), "Greeter.History.");

    amxc_var_clean(&data);
}

void test_can_loop_over_instances(UNUSED void** state) {
    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "for instance in parent:instances() do print(instance:get_name()) end"));
}

void test_can_use_for_all(UNUSED void** state) {
    amxc_var_t data;
    amxc_var_init(&data);

    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "counter = 0 greeter_obj:forall('History.*.Info.*.', function(mo) print(mo:get_name()) counter = counter + 1 end)"));

    lua_getglobal(L, "counter");
    lamx_lua2var(L, 1, &data);

    amxc_var_dump(&data, STDOUT_FILENO);
    assert_int_equal(amxc_var_dyncast(uint32_t, &data), 5);

    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "counter = 0 greeter_obj:forall('History.2.Info.*.', function(mo) print(mo:get_name()) counter = counter + 1 end)"));

    lua_getglobal(L, "counter");
    lamx_lua2var(L, 1, &data);

    amxc_var_dump(&data, STDOUT_FILENO);
    assert_int_equal(amxc_var_dyncast(uint32_t, &data), 1);

    amxc_var_clean(&data);
}

void test_for_all_fails_if_no_function(UNUSED void** state) {
    lua_settop(L, 0);
    assert_true(luaL_dostring(L, "counter = 0 greeter_obj:forall('History.*.Info.*.', 10)"));

    lua_settop(L, 0);
    assert_true(luaL_dostring(L, "counter = 0 greeter_obj:forall('History.2.Info.*.', 'Hello')"));
}

void test_can_add_instance(UNUSED void** state) {
    amxc_var_t data;
    amxc_var_init(&data);

    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "new_instance = parent:add_instance()"));

    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "path = new_instance:get_path()"));

    lua_getglobal(L, "path");
    lamx_lua2var(L, 1, &data);

    amxc_var_dump(&data, STDOUT_FILENO);
    assert_int_equal(amxc_var_type_of(&data), AMXC_VAR_ID_CSTRING);
    assert_string_equal(GET_CHAR(&data, NULL), "Greeter.History.3.");

    amxc_var_clean(&data);
}

void test_can_add_instance_with_args(UNUSED void** state) {
    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "info_templ = new_instance:find(\"Info.\")"));

    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "info_instance = info_templ:add_instance({Text = \"Hello\"},1,\"MyAlias\")"));
}

void test_add_instance_can_fail(UNUSED void** state) {
    amxc_var_t data;
    amxc_var_init(&data);

    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "info_instance = info_templ:add_instance({},1,\"MyAlias\")"));
    lua_getglobal(L, "info_instance");
    lamx_lua2var(L, 1, &data);

    amxc_var_dump(&data, STDOUT_FILENO);
    assert_int_equal(amxc_var_type_of(&data), AMXC_VAR_ID_NULL);

    amxc_var_clean(&data);
}

void test_can_add_mib(UNUSED void** state) {
    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "new_instance:add_mib('TestMib')"));
}

void test_add_mib_fails_when_dupicate_param(UNUSED void** state) {
    lua_settop(L, 0);
    assert_true(luaL_dostring(L, "new_instance:add_mib('ErrorMib')"));
}

void test_can_set_and_read_param(UNUSED void** state) {
    amxc_var_t data;
    amxc_var_init(&data);

    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "new_instance['From'] = 'me'"));
    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "new_instance['Extra'] = 'test'"));
    lua_settop(L, 0);
    assert_true(luaL_dostring(L, "new_instance['Invalid'] = 'test'"));

    lua_settop(L, 0);
    assert_true(luaL_dostring(L, "from = new_instance['Invalid']"));
    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "from = new_instance['From']"));

    lua_getglobal(L, "from");
    lamx_lua2var(L, 1, &data);

    amxc_var_dump(&data, STDOUT_FILENO);
    assert_int_equal(amxc_var_type_of(&data), AMXC_VAR_ID_CSTRING);
    assert_string_equal(GET_CHAR(&data, NULL), "me");

    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "extra = new_instance['Extra']"));

    lua_getglobal(L, "extra");
    lamx_lua2var(L, 1, &data);

    amxc_var_dump(&data, STDOUT_FILENO);
    assert_int_equal(amxc_var_type_of(&data), AMXC_VAR_ID_CSTRING);
    assert_string_equal(GET_CHAR(&data, NULL), "test");

    amxc_var_clean(&data);
}

void test_can_get_instance_count(UNUSED void** state) {
    amxc_var_t data;
    amxc_var_init(&data);

    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "nr_of_instances = parent:get_instance_count()"));

    lua_getglobal(L, "nr_of_instances");
    lamx_lua2var(L, 1, &data);
    amxc_var_dump(&data, STDOUT_FILENO);
    assert_int_equal(GET_UINT32(&data, NULL), 3);

    amxc_var_clean(&data);
}

void test_can_save_dm(UNUSED void** state) {
    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "lamx.dm.save('/tmp/save.odl', 'Greeter.')"));
}

void test_save_dm_can_fail(UNUSED void** state) {
    lua_settop(L, 0);
    assert_true(luaL_dostring(L, "lamx.dm.save('/blabla/save.odl', 'Greeter.')"));
    lua_settop(L, 0);
    assert_true(luaL_dostring(L, "lamx.dm.save('/tmp/save.odl', 'NotExisting.')"));
}

void test_can_remove_mib(UNUSED void** state) {
    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "new_instance:remove_mib('TestMib')"));
}

void test_remove_mib_fails_if_mib_not_found(UNUSED void** state) {
    lua_settop(L, 0);
    assert_true(luaL_dostring(L, "new_instance:remove_mib('NotExistingMib')"));
}

void test_can_del_instance(UNUSED void** state) {
    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "info_instance = info_templ:del_instance(0,\"MyAlias\")"));

    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "new_instance:del()"));

    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "parent:del_instance(2)"));
}

void test_get_parent_fails_if_object_deleted(UNUSED void** state) {
    lua_settop(L, 0);
    assert_true(luaL_dostring(L, "new_instance:get_parent()"));
}

void test_can_add_instance_with_params(UNUSED void** state) {
    amxc_var_t data;
    amxc_var_init(&data);

    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "params = { From = 'me' } parent:add_instance(params)"));

    amxc_var_clean(&data);
}

void test_fetch_parent_fails(UNUSED void** state) {
    lua_settop(L, 0);
    assert_true(luaL_dostring(L, "new_instance:get_parent()"));

    lua_settop(L, 0);
    assert_true(luaL_dostring(L, "greeter_obj:get_parent():get_parent()"));
}

void test_can_fetch_parameter_def(UNUSED void** state) {
    amxc_var_t data;
    amxc_var_init(&data);

    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "state_param = greeter_obj:get_parameter('State')"));
    assert_false(luaL_dostring(L, "name = state_param:get_name()"));

    lua_getglobal(L, "name");
    lamx_lua2var(L, 1, &data);

    amxc_var_dump(&data, STDOUT_FILENO);
    assert_int_equal(amxc_var_type_of(&data), AMXC_VAR_ID_CSTRING);
    assert_string_equal(GET_CHAR(&data, NULL), "State");

    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "owner = state_param:get_owner()"));
    assert_false(luaL_dostring(L, "path = owner:get_path()"));
    lua_getglobal(L, "path");
    lamx_lua2var(L, 1, &data);
    amxc_var_dump(&data, STDOUT_FILENO);
    assert_int_equal(amxc_var_type_of(&data), AMXC_VAR_ID_CSTRING);
    assert_string_equal(GET_CHAR(&data, NULL), "Greeter.");

    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "type = state_param:get_type()"));
    lua_getglobal(L, "type");
    lamx_lua2var(L, 1, &data);
    amxc_var_dump(&data, STDOUT_FILENO);
    assert_int_equal(amxc_var_type_of(&data), AMXC_VAR_ID_CSTRING);
    assert_string_equal(GET_CHAR(&data, NULL), "cstring_t");

    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "param = greeter_obj:get_parameter('NotExisting')"));
    lua_getglobal(L, "param");
    lamx_lua2var(L, 1, &data);
    amxc_var_dump(&data, STDOUT_FILENO);
    assert_int_equal(amxc_var_type_of(&data), AMXC_VAR_ID_NULL);

    amxc_var_clean(&data);
}

void test_can_set_value_using_parameter_def(UNUSED void** state) {
    amxc_var_t data;
    amxc_var_init(&data);

    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "state_param = greeter_obj:get_parameter('State')"));
    assert_false(luaL_dostring(L, "value = state_param:get_value()"));
    lua_getglobal(L, "value");
    lamx_lua2var(L, 1, &data);
    amxc_var_dump(&data, STDOUT_FILENO);
    assert_int_equal(amxc_var_type_of(&data), AMXC_VAR_ID_CSTRING);
    assert_string_equal(GET_CHAR(&data, NULL), "Idle");

    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "state_param:set_value('Test')"));
    assert_false(luaL_dostring(L, "value = state_param:get_value()"));
    lua_getglobal(L, "value");
    lamx_lua2var(L, 1, &data);
    amxc_var_dump(&data, STDOUT_FILENO);
    assert_int_equal(amxc_var_type_of(&data), AMXC_VAR_ID_CSTRING);
    assert_string_equal(GET_CHAR(&data, NULL), "Test");

    amxc_var_clean(&data);
}

void test_param_methods_fail_when_owner_is_deleted(UNUSED void** state) {
    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "history_obj = lamx.dm.find(\"Greeter.History.\")"));

    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "new_instance = history_obj:add_instance()"));

    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "param = new_instance:get_parameter('From')"));
    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "name = param:get_name()"));

    assert_false(luaL_dostring(L, "new_instance:del()"));

    lua_settop(L, 0);
    assert_true(luaL_dostring(L, "param:get_name()"));
    assert_true(luaL_dostring(L, "param:get_owner()"));
    assert_true(luaL_dostring(L, "param:get_type()"));
    assert_true(luaL_dostring(L, "param:get_value()"));
    assert_true(luaL_dostring(L, "param:set_value(\"Test\")"));
}

void test_param_methods_fail_when_parameter_is_deleted(UNUSED void** state) {
    amxd_dm_t* dm = lamx_get_dm(L);
    amxd_object_t* obj = NULL;
    amxd_param_t* param = NULL;

    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "history_obj = lamx.dm.find(\"Greeter.History.\")"));

    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "new_instance = history_obj:add_instance()"));

    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "param = new_instance:get_parameter('From')"));
    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "name = param:get_name()"));

    obj = amxd_dm_findf(dm, "Greeter.History.6.");
    param = amxd_object_get_param_def(obj, "From");
    amxd_param_delete(&param);

    lua_settop(L, 0);
    assert_true(luaL_dostring(L, "a = param:get_name()"));

    lua_settop(L, 0);
    assert_true(luaL_dostring(L, "a = param:get_owner()"));

    lua_settop(L, 0);
    assert_true(luaL_dostring(L, "a = param:get_type()"));

    lua_settop(L, 0);
    assert_true(luaL_dostring(L, "a = param:get_value()"));

    lua_settop(L, 0);
    assert_true(luaL_dostring(L, "a = param:set_value(\"Test\")"));
}

void test_dm_functions_throws_error_when_referenced_dm_object_is_gone(UNUSED void** state) {
    amxc_var_t data;
    amxc_var_init(&data);

    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "greeter_history = lamx.dm.find(\"Greeter.History.\")"));
    assert_false(luaL_dostring(L, "new_instance = greeter_history:add_instance()"));
    assert_false(luaL_dostring(L, "path = new_instance:get_path()"));
    lua_getglobal(L, "path");
    lamx_lua2var(L, 1, &data);
    amxc_var_dump(&data, STDOUT_FILENO);
    assert_string_equal(GET_CHAR(&data, NULL), "Greeter.History.7.");

    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "instance = lamx.dm.find(path)"));
    assert_false(luaL_dostring(L, "path = instance:get_path()"));
    lua_getglobal(L, "path");
    lamx_lua2var(L, 1, &data);
    amxc_var_dump(&data, STDOUT_FILENO);
    assert_string_equal(GET_CHAR(&data, NULL), "Greeter.History.7.");

    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "param = instance:get_parameter('From')"));
    assert_false(luaL_dostring(L, "name = param:get_name()"));
    lua_getglobal(L, "name");
    lamx_lua2var(L, 1, &data);
    amxc_var_dump(&data, STDOUT_FILENO);
    assert_string_equal(GET_CHAR(&data, NULL), "From");

    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "new_instance:del()"));

    lua_settop(L, 0);
    assert_true(luaL_dostring(L, "path = instance:get_path()"));
    lua_getglobal(L, "name");
    lamx_lua2var(L, 1, &data);
    amxc_var_dump(&data, STDOUT_FILENO);
    assert_string_not_equal(GET_CHAR(&data, NULL), "Greeter.History.7.");

    lua_settop(L, 0);
    assert_true(luaL_dostring(L, "name = instance:get_name()"));
    lua_getglobal(L, "name");
    lamx_lua2var(L, 1, &data);
    amxc_var_dump(&data, STDOUT_FILENO);

    lua_settop(L, 0);
    assert_true(luaL_dostring(L, "name = param:get_name()"));
    lua_getglobal(L, "name");
    lamx_lua2var(L, 1, &data);
    amxc_var_dump(&data, STDOUT_FILENO);

    lua_settop(L, 0);
    assert_true(luaL_dostring(L, "owner = param:get_owner()"));
    lua_getglobal(L, "owner");
    lamx_lua2var(L, 1, &data);
    amxc_var_dump(&data, STDOUT_FILENO);

    lua_settop(L, 0);
    assert_true(luaL_dostring(L, "type = param:get_type()"));
    lua_getglobal(L, "type");
    lamx_lua2var(L, 1, &data);
    amxc_var_dump(&data, STDOUT_FILENO);

    lua_settop(L, 0);
    assert_true(luaL_dostring(L, "value = param:get_value()"));
    lua_getglobal(L, "value");
    lamx_lua2var(L, 1, &data);
    amxc_var_dump(&data, STDOUT_FILENO);

    amxc_var_clean(&data);
}

void test_call_not_existing_param_method_fails(UNUSED void** state) {
    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "history_obj = lamx.dm.find(\"Greeter.History.\")"));

    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "new_instance = history_obj:add_instance()"));

    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "param = new_instance:get_parameter('From')"));

    assert_true(luaL_dostring(L, "param:not_existing()"));
}

void test_can_send_change_event(UNUSED void** state) {
    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "greeter_obj:send_changed({Sate = \"Idle\"})"));
}

void test_can_call_rpc_method(UNUSED void** state) {
    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "greeter_obj:test_func({data = \"text\"})"));
}

void test_call_rpc_method_fails_when_args_not_in_table(UNUSED void** state) {
    lua_settop(L, 0);
    assert_true(luaL_dostring(L, "greeter_obj:test_func(\"text\")"));
}

void test_call_rpc_method_fails_when_rpc_fails(UNUSED void** state) {
    lua_settop(L, 0);
    assert_true(luaL_dostring(L, "greeter_obj:test_func2({})"));
}

void test_can_destroy_dm(UNUSED void** state) {
    lua_settop(L, 0);
    assert_false(luaL_dostring(L, "lamx.dm.destroy()"));
}

void test_load_fails_if_no_dm_available(UNUSED void** state) {
    lua_settop(L, 0);
    assert_true(luaL_dostring(L, "lamx.dm.load(\"../test_data/odl/greeter_definition.odl\")"));
}

void test_save_fails_if_no_dm_available(UNUSED void** state) {
    lua_settop(L, 0);
    assert_true(luaL_dostring(L, "lamx.dm.save(\"/tmp/save.odl\", \"Greeter.\")"));
}
