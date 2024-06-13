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

#include <stdlib.h>
#include <stdio.h>
#include <setjmp.h>
#include <stdarg.h>
#include <cmocka.h>
#include <string.h>

#include <amxa/amxa_merger.h>
#include <amxp/amxp.h>
#include <amxd/amxd_object_event.h>

#include "common_mock.h"
#include "tty_mock.h"
#include "dummy_backend.h"

#include "test_mod_pcb_cli_acl.h"

static sigset_t mask;
static amxo_parser_t parser;

static amxd_status_t _function_dump(amxd_object_t* object,
                                    amxd_function_t* func,
                                    amxc_var_t* args,
                                    amxc_var_t* ret) {
    char* path = amxd_object_get_path(object, AMXD_OBJECT_NAMED);
    printf("Function call: \n");
    printf("Object   - %s\n", path);
    printf("Function - %s\n", amxd_function_get_name(func));
    amxc_var_copy(ret, args);
    if(args != NULL) {
        fflush(stdout);
        amxc_var_dump(args, STDOUT_FILENO);
    }
    free(path);
    return amxd_status_ok;
}

int test_mod_pcb_cli_setup(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    amxd_object_t* root_obj = NULL;
    amxb_bus_ctx_t* bus_ctx = NULL;
    amxc_var_t* connection = NULL;
    amxc_var_t* acls = NULL;
    amxc_var_t acl_dir;
    amxc_var_t acl_enabled;
    amxc_var_t role;

    sigemptyset(&mask);
    sigaddset(&mask, SIGALRM);

    int rv = sigprocmask(SIG_BLOCK, &mask, NULL);
    assert_false(rv < 0);

    ba_cli->so = (amxm_shared_object_t*) calloc(1, sizeof(amxm_shared_object_t));
    amxc_llist_init(&ba_cli->so->amxm_module_llist);
    strncpy(ba_cli->so->name, "test_shared_object", AMXM_MODULE_NAME_LENGTH);
    strncpy(ba_cli->so->file, "test_shared_object.so", AMXM_MODULE_NAME_LENGTH);

    amxo_parser_init(&parser);
    amxd_dm_init(&ba_cli->dm);

    amxo_resolver_ftab_add(&parser, "SSH.Server.test_function", AMXO_FUNC(_function_dump));

    root_obj = amxd_dm_get_root(&ba_cli->dm);
    amxo_parser_parse_file(&parser, "./ssh_server.odl", root_obj);
    assert_int_equal(amxt_tty_open(&ba_cli->tty, fileno(stdin)), 0);

    amxp_sigmngr_add_signal(ba_cli->tty->sigmngr, "tty:docomplete");
    amxp_slot_connect(ba_cli->tty->sigmngr, "tty:docomplete", NULL, test_complete_cb, NULL);

    assert_int_equal(test_register_dummy_be(), 0);
    assert_int_equal(amxb_connect(&bus_ctx, "dummy:/tmp/dummy.sock"), 0);
    connection = amxt_tty_claim_config(ba_cli->tty, "connection");
    amxc_var_set(cstring_t, connection, "dummy:/tmp/dummy.sock");
    amxt_tty_claim_config(ba_cli->tty, "rv");
    amxb_register(bus_ctx, &ba_cli->dm);
    amxb_set_access(bus_ctx, amxd_dm_access_public);

    amxc_var_init(&acl_enabled);
    amxc_var_set(bool, &acl_enabled, true);
    amxt_tty_set_config(ba_cli->tty, "acl-enabled", &acl_enabled);

    amxc_var_init(&acl_dir);
    amxc_var_set(cstring_t, &acl_dir, "./acl/");
    amxt_tty_set_config(ba_cli->tty, "acl-dir", &acl_dir);

    amxc_var_init(&role);
    amxc_var_set(cstring_t, &role, "operator");
    amxt_tty_set_config(ba_cli->tty, "role", &role);

    acls = amxa_parse_files("./acl/operator/ssh_server.json");
    assert_non_null(acls);
    assert_int_equal(amxa_merge_rules(acls, "./acl/merged/operator.json"), 0);

    handle_events();

    mod_pcb_cli_start(ba_cli->so);

    amxc_var_clean(&acl_enabled);
    amxc_var_clean(&acl_dir);
    amxc_var_clean(&role);
    amxc_var_delete(&acls);
    return 0;
}

int test_mod_pcb_cli_teardown(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();

    mod_pcb_cli_stop(ba_cli->so);

    handle_events();

    amxt_tty_close(&ba_cli->tty);
    amxo_parser_clean(&parser);
    amxd_dm_clean(&ba_cli->dm);

    amxc_llist_clean(&ba_cli->so->amxm_module_llist, amxm_test_so_remove_mod);
    free(ba_cli->so);

    test_unregister_dummy_be();

    return 0;
}

void test_can_activate(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    amxt_prompt_t* prompt = NULL;
    char* prompt_txt = NULL;
    amxc_var_t* cli_name = amxt_tty_claim_config(ba_cli->tty, "cli-name");

    int cmd_rv = 0;
    const char* expected =
        "\n${color.green}$(USER)${color.reset} - "
        "${color.blue}${connection}${color.reset} - [pcb-cli] (${rv})\n"
        "${path} > ${color.white}";
    amxc_string_t p;
    amxc_var_t ret;
    amxc_var_t tty_args;

    amxc_var_init(&ret);
    amxc_var_init(&tty_args);
    amxc_string_init(&p, 0);
    amxc_string_setf(&p, "%s", expected);
    amxc_string_resolve(&p, &ba_cli->tty->config);
    amxc_var_set(cstring_t, cli_name, "pcb-cli");

    amxt_cli_build_args(&tty_args, "");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__activate", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);
    prompt = amxt_tty_get_prompt(ba_cli->tty);

    prompt_txt = amxt_prompt_get(prompt);
    printf("expected: %s\n", amxc_string_get(&p, 0));
    printf("got: %s\n", prompt_txt);
    assert_string_equal(amxc_string_get(&p, 0), prompt_txt);
    free(prompt_txt);

    amxc_string_clean(&p);
    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_get_ssh_server_filtered(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "SSH.?");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__execute", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    amxt_cli_build_args(&tty_args, "SSH.Server.2.?");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__execute", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_set_allowed_parameters(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;
    amxd_object_t* server = NULL;
    char* txt = NULL;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "SSH.Server.[Port==1001].Port = 1970");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__execute", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    server = amxd_dm_findf(&ba_cli->dm, "SSH.Server.1.");
    assert_int_equal(amxd_object_get_value(uint32_t, server, "Port", NULL), 1970);

    amxt_cli_build_args(&tty_args, "SSH.Server.1.{Port = 2020,AllowPasswordLogin=false, TestParam\t='TestValue'}");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__execute", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    server = amxd_dm_findf(&ba_cli->dm, "SSH.Server.1.");
    assert_int_equal(amxd_object_get_value(uint32_t, server, "Port", NULL), 2020);
    assert_false(amxd_object_get_value(bool, server, "AllowPasswordLogin", NULL));
    txt = amxd_object_get_value(cstring_t, server, "TestParam", NULL);
    assert_string_equal(txt, "TestValue");

    free(txt);
    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_cannot_set_disallowed_parameters(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;
    amxd_object_t* server = NULL;
    char* txt = NULL;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "SSH.Server.2.Port = 1970");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__execute", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    server = amxd_dm_findf(&ba_cli->dm, "SSH.Server.2.");
    assert_int_equal(amxd_object_get_value(uint32_t, server, "Port", NULL), 1002);

    amxt_cli_build_args(&tty_args, "SSH.Server.2.{Port = 2020,AllowPasswordLogin=false, TestParam\t='TestValue'}");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__execute", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    server = amxd_dm_findf(&ba_cli->dm, "SSH.Server.2.");
    assert_int_equal(amxd_object_get_value(uint32_t, server, "Port", NULL), 1002);
    assert_true(amxd_object_get_value(bool, server, "AllowPasswordLogin", NULL));
    txt = amxd_object_get_value(cstring_t, server, "TestParam", NULL);
    assert_string_equal(txt, "testing");

    free(txt);
    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_add_instance_if_allowed(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;
    amxd_object_t* server = NULL;
    char* txt = NULL;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "SSH.Server.+");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__execute", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    server = amxd_dm_findf(&ba_cli->dm, "SSH.Server.3.");
    assert_non_null(server);

    amxt_cli_build_args(&tty_args, "SSH.Server.+{Port = 1234,AllowPasswordLogin=false, TestParam\t='TestValue'}");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__execute", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    server = amxd_dm_findf(&ba_cli->dm, "SSH.Server.4.");
    assert_int_equal(amxd_object_get_value(uint32_t, server, "Port", NULL), 1234);
    assert_false(amxd_object_get_value(bool, server, "AllowPasswordLogin", NULL));
    txt = amxd_object_get_value(cstring_t, server, "TestParam", NULL);
    assert_string_equal(txt, "TestValue");

    free(txt);
    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_cannot_add_instance_if_disallowed(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;
    amxd_object_t* server = NULL;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "SSH.Server.1.TemplateObject.+");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__execute", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    server = amxd_dm_findf(&ba_cli->dm, "SSH.Server.1.TemplateObject.1.");
    assert_null(server);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_cannot_add_instance_if_setting_params_is_forbidden(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;
    amxd_object_t* template = NULL;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "SSH.Server.4.TemplateObject.+{Number = 5}");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__execute", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    template = amxd_dm_findf(&ba_cli->dm, "SSH.Server.4.TemplateObject.1.");
    assert_null(template);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_cannot_invoke_get_with_search_path(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    amxd_object_t* obj = amxd_dm_findf(&ba_cli->dm, "SSH.Server.4.TemplateObject");
    amxd_object_t* template = NULL;
    amxc_var_t args;
    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_t* params = NULL;
    int cmd_rv = 0;

    amxc_var_init(&tty_args);
    amxc_var_init(&ret);
    amxc_var_init(&args);
    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    params = amxc_var_add_key(amxc_htable_t, &args, "parameters", NULL);
    amxc_var_add_key(uint32_t, params, "Number", 888);

    assert_non_null(obj);
    assert_int_equal(amxd_object_invoke_function(obj, "_add", &args, &ret), 0);
    amxc_var_dump(&ret, STDOUT_FILENO);

    handle_events();

    template = amxd_dm_findf(&ba_cli->dm, "SSH.Server.4.TemplateObject.1.");
    assert_non_null(template);

    amxt_cli_build_args(&tty_args, "SSH.Server.4.TemplateObject.[Number==888].?");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__execute", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&tty_args);
    amxc_var_clean(&ret);
    amxc_var_clean(&args);
}

void test_can_del_instance_if_allowed(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;
    amxd_object_t* server = NULL;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "SSH.Server.3.-");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__execute", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    server = amxd_dm_findf(&ba_cli->dm, "SSH.Server.3.");
    assert_null(server);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_cannot_del_instance_if_not_allowed(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;
    amxd_object_t* server = NULL;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "SSH.Server.2.-");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__execute", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    server = amxd_dm_findf(&ba_cli->dm, "SSH.Server.2.");
    assert_non_null(server);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_subscribe(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    // clear all events
    handle_events();

    amxt_cli_build_args(&tty_args, "SSH.?&");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__execute", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_receive_allowed_changed_events(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;
    amxc_var_t* raw = NULL;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "SSH.Server.1.Port = 6666");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__execute", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    handle_events();

    raw = amxt_tty_claim_config(ba_cli->tty, "raw-event");
    amxc_var_set(bool, raw, true);

    amxt_cli_build_args(&tty_args, "SSH.Server.1. { Port = 2021, ActivationDuration = 30 }");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__execute", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    handle_events();

    amxc_var_set(bool, raw, false);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_cannot_receive_disallowed_changed_events(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    amxd_object_t* obj = amxd_dm_findf(&ba_cli->dm, "SSH.Server.2.");
    amxc_var_t args;
    amxc_var_t ret;
    amxc_var_t* params;

    amxc_var_init(&ret);
    amxc_var_init(&args);
    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    params = amxc_var_add_key(amxc_htable_t, &args, "parameters", NULL);
    amxc_var_add_key(uint32_t, params, "Port", 456);

    assert_non_null(obj);
    assert_int_equal(amxd_object_invoke_function(obj, "_set", &args, &ret), 0);
    amxc_var_dump(&ret, STDOUT_FILENO);

    handle_events();

    amxc_var_clean(&ret);
    amxc_var_clean(&args);
}

void test_can_receive_allowed_add_events(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;
    amxc_var_t* raw = NULL;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "SSH.Server.+");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__execute", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    handle_events();

    raw = amxt_tty_claim_config(ba_cli->tty, "raw-event");
    amxc_var_set(bool, raw, true);

    amxt_cli_build_args(&tty_args, "SSH.Server. +");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__execute", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    handle_events();

    amxc_var_set(bool, raw, false);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_cannot_receive_disallowed_add_events(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    amxd_object_t* obj = amxd_dm_findf(&ba_cli->dm, "SSH.Server.2.TemplateObject");
    amxc_var_t args;
    amxc_var_t ret;

    amxc_var_init(&ret);
    amxc_var_init(&args);
    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);

    assert_non_null(obj);
    assert_int_equal(amxd_object_invoke_function(obj, "_add", &args, &ret), 0);
    amxc_var_dump(&ret, STDOUT_FILENO);

    handle_events();

    amxc_var_clean(&ret);
    amxc_var_clean(&args);
}

void test_can_receive_allowed_del_events(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;
    amxc_var_t* raw = NULL;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "SSH.Server.5-");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__execute", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    handle_events();

    raw = amxt_tty_claim_config(ba_cli->tty, "raw-event");
    amxc_var_set(bool, raw, true);

    amxt_cli_build_args(&tty_args, "SSH.Server.6 -");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__execute", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    handle_events();

    amxc_var_set(bool, raw, false);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_cannot_receive_disallowed_del_events(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    amxd_object_t* obj = amxd_dm_findf(&ba_cli->dm, "SSH.Server.2.TemplateObject.1.");
    amxc_var_t args;
    amxc_var_t ret;

    amxc_var_init(&ret);
    amxc_var_init(&args);
    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);

    assert_non_null(obj);
    assert_int_equal(amxd_object_invoke_function(obj, "_del", &args, &ret), 0);
    amxc_var_dump(&ret, STDOUT_FILENO);

    handle_events();

    amxc_var_clean(&ret);
    amxc_var_clean(&args);
}

void test_can_receive_allowed_custom_event(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    amxd_object_t* server = amxd_dm_findf(&ba_cli->dm, "SSH.Server.1.");
    amxc_var_t data;

    amxc_var_init(&data);
    amxc_var_set_type(&data, AMXC_VAR_ID_HTABLE);

    amxc_var_add_key(cstring_t, &data, "Key1", "test data");

    assert_non_null(server);
    amxd_object_emit_signal(server, "test-event", &data);
    handle_events();

    amxc_var_clean(&data);
}

void test_cannot_receive_disallowed_custom_event(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    amxd_object_t* server = amxd_dm_findf(&ba_cli->dm, "SSH.Server.2.");
    amxc_var_t data;

    amxc_var_init(&data);
    amxc_var_set_type(&data, AMXC_VAR_ID_HTABLE);

    amxc_var_add_key(cstring_t, &data, "Key1", "test data");

    assert_non_null(server);
    amxd_object_emit_signal(server, "test-event", &data);
    handle_events();

    amxc_var_clean(&data);
}

void test_can_invoke_allowed_function(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "SSH.Server.1.test_function()");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__execute", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    handle_events();

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_cannot_invoke_disallowed_function(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "SSH.Server.2.test_function()");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__execute", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

