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

#include "common_mock.h"
#include "tty_mock.h"
#include "dummy_backend.h"

#include <amxp/amxp_timer.h>
#include <amxd/amxd_object_event.h>

#include "test_mod_pcb_cli.h"

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
    amxc_var_t acl_enabled;

    sigemptyset(&mask);
    sigaddset(&mask, SIGALRM);
    amxo_parser_init(&parser);

    int rv = sigprocmask(SIG_BLOCK, &mask, NULL);
    assert_false(rv < 0);

    ba_cli->so = (amxm_shared_object_t*) calloc(1, sizeof(amxm_shared_object_t));
    amxc_llist_init(&ba_cli->so->amxm_module_llist);
    strncpy(ba_cli->so->name, "test_shared_object", AMXM_MODULE_NAME_LENGTH);
    strncpy(ba_cli->so->file, "test_shared_object.so", AMXM_MODULE_NAME_LENGTH);

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
    amxc_var_set(bool, &acl_enabled, false);
    amxt_tty_set_config(ba_cli->tty, "acl-enabled", &acl_enabled);

    handle_events();

    mod_pcb_cli_start(ba_cli->so);

    amxc_var_clean(&acl_enabled);
    return 0;
}

int test_mod_pcb_cli_teardown(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();

    mod_pcb_cli_stop(ba_cli->so);

    amxt_tty_close(&ba_cli->tty);
    amxo_parser_clean(&parser);
    amxd_dm_clean(&ba_cli->dm);

    amxc_llist_clean(&ba_cli->so->amxm_module_llist, amxm_test_so_remove_mod);
    free(ba_cli->so);

    test_unregister_dummy_be();

    return 0;
}

void test_can_invoke_help(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "");

    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "help", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_describe(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__describe", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);
    assert_int_equal(amxc_var_type_of(&ret), AMXC_VAR_ID_CSTRING);
    assert_string_equal(amxc_var_constcast(cstring_t, &ret), "Bus Agnostic cli.");
    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
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
    printf("expected -> %s\n", amxc_string_get(&p, 0));
    printf("got -> %s\n", prompt_txt);
    assert_string_equal(amxc_string_get(&p, 0), prompt_txt);
    free(prompt_txt);

    amxc_string_clean(&p);
    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_cd_into_object(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;
    amxc_var_t* variable = NULL;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "SSH.");

    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "cd", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    variable = amxt_tty_claim_config(ba_cli->tty, "path");
    assert_int_equal(amxc_var_type_of(variable), AMXC_VAR_ID_CSTRING);
    assert_string_equal(amxc_var_constcast(cstring_t, variable), "SSH.");

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_cd_to_root(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;
    amxc_var_t* variable = NULL;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, ".");

    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "cd", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    variable = amxt_tty_claim_config(ba_cli->tty, "path");
    assert_int_equal(amxc_var_type_of(variable), AMXC_VAR_ID_CSTRING);
    assert_string_equal(amxc_var_constcast(cstring_t, variable), "");

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_cd_fails_when_invalid_path(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "SSH.Server.{i}.*.");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "cd", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxt_cli_build_args(&tty_args, "SSH.Server.*.");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "cd", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_cd_not_existing_object_fails(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;
    amxc_var_t* variable = NULL;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "InvalidObject");

    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "cd", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    variable = amxt_tty_claim_config(ba_cli->tty, "path");
    assert_int_equal(amxc_var_type_of(variable), AMXC_VAR_ID_CSTRING);
    assert_string_equal(amxc_var_constcast(cstring_t, variable), "");

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_list_objects(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "-rpfn SSH.Server.");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "ls", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    amxt_cli_build_args(&tty_args, "-pf SSH.");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "list", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    amxt_cli_build_args(&tty_args, "SSH.Server.*.");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "list", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    amxt_cli_build_args(&tty_args, "-r");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "list", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_complete_list_options(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;
    amxc_var_t* cmd_parts = NULL;
    amxc_var_t* ret = NULL;
    amxc_var_t tty_args;
    amxc_var_t check_var;

    amxc_var_init(&tty_args);
    amxc_var_init(&check_var);

    amxc_var_new(&ret);
    amxc_var_set_type(ret, AMXC_VAR_ID_LIST);
    amxt_cli_build_args(&tty_args, "ls --rec");
    cmd_parts = GET_ARG(&tty_args, "cmd");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__complete_ls", cmd_parts, ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_set_type(&check_var, AMXC_VAR_ID_LIST);
    amxc_var_add(cstring_t, &check_var, "--recursive");
    expect_check(test_complete_cb, data, test_check_completion_list, &check_var);
    handle_events();

    amxc_var_clean(&tty_args);
    amxc_var_clean(&check_var);
}

void test_complete_always_provides_all_options(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;
    amxc_var_t* cmd_parts = NULL;
    amxc_var_t* ret = NULL;
    amxc_var_t tty_args;
    amxc_var_t check_var;

    amxc_var_init(&tty_args);
    amxc_var_init(&check_var);

    amxc_var_new(&ret);
    amxc_var_set_type(ret, AMXC_VAR_ID_LIST);
    amxt_cli_build_args(&tty_args, "ls --recursive --");
    cmd_parts = GET_ARG(&tty_args, "cmd");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__complete_ls", cmd_parts, ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_set_type(&check_var, AMXC_VAR_ID_LIST);
    amxc_var_add(cstring_t, &check_var, "--recursive");
    amxc_var_add(cstring_t, &check_var, "--named");
    amxc_var_add(cstring_t, &check_var, "--parameters");
    amxc_var_add(cstring_t, &check_var, "--functions");
    expect_check(test_complete_cb, data, test_check_completion_list, &check_var);
    handle_events();

    amxc_var_clean(&tty_args);
    amxc_var_clean(&check_var);
}

void test_can_dump_object(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "-rpfn SSH.Server.");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "dump", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    amxt_cli_build_args(&tty_args, "SSH.Server.");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "dump", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    amxt_cli_build_args(&tty_args, "--parameters --functions --recursive SSH.Server.");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "dump", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_dump_protected_members(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;
    amxb_bus_ctx_t* bus_ctx = amxb_find_uri("dummy:/tmp/dummy.sock");

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxb_set_access(bus_ctx, AMXB_PROTECTED);
    amxt_cli_build_args(&tty_args, "-rpfn SSH.");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "dump", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);
    amxb_set_access(bus_ctx, AMXB_PUBLIC);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_dump_invalid_object_fails(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "InvalidObject");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "dump", &tty_args, &ret);
    assert_int_equal(cmd_rv, -1);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_get_supported_dm(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "-pf SSH.Server.");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "gsdm", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    amxt_cli_build_args(&tty_args, "SSH.Server.");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "gsdm", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    amxt_cli_build_args(&tty_args, "--parameters --functions --first_lvl_only SSH.Server.");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "gsdm", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_gsdm_invalid_object_fails(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "InvalidObject");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "gsdm", &tty_args, &ret);
    assert_int_equal(cmd_rv, -1);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_get_instances(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "SSH.Server.");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "gi", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_execute_fails_when_missing_operator(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);
    amxt_cli_build_args(&tty_args, "SSH.");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__execute", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_execute_fails_when_missing_path(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "?");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__execute", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxt_cli_build_args(&tty_args, "+");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__execute", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}


void test_can_complete_object_path(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;
    amxc_var_t* cmd_parts = NULL;
    amxc_var_t* ret = NULL;
    amxc_var_t tty_args;
    amxc_var_t check_var;

    amxc_var_init(&tty_args);
    amxc_var_init(&check_var);

    amxc_var_new(&ret);
    amxc_var_set_type(ret, AMXC_VAR_ID_LIST);
    amxt_cli_build_args(&tty_args, "SSH.");
    cmd_parts = GET_ARG(&tty_args, "cmd");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__complete", cmd_parts, ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_set_type(&check_var, AMXC_VAR_ID_LIST);
    amxc_var_add(cstring_t, &check_var, "SSH.Enable");
    amxc_var_add(cstring_t, &check_var, "SSH.ServerNumberOfEntries");
    amxc_var_add(cstring_t, &check_var, "SSH.Server");
    amxc_var_add(cstring_t, &check_var, "SSH.S");
    expect_check(test_complete_cb, data, test_check_completion_list, &check_var);
    handle_events();

    amxc_var_new(&ret);
    amxc_var_set_type(ret, AMXC_VAR_ID_LIST);
    amxt_cli_build_args(&tty_args, "SSH.Serv");
    cmd_parts = GET_ARG(&tty_args, "cmd");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__complete", cmd_parts, ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_set_type(&check_var, AMXC_VAR_ID_LIST);
    amxc_var_add(cstring_t, &check_var, "SSH.ServerNumberOfEntries");
    amxc_var_add(cstring_t, &check_var, "SSH.Server");
    expect_check(test_complete_cb, data, test_check_completion_list, &check_var);
    handle_events();

    amxc_var_new(&ret);
    amxc_var_set_type(ret, AMXC_VAR_ID_LIST);
    amxt_cli_build_args(&tty_args, "SSH.Server.");
    cmd_parts = GET_ARG(&tty_args, "cmd");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__complete", cmd_parts, ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_set_type(&check_var, AMXC_VAR_ID_LIST);
    amxc_var_add(cstring_t, &check_var, "SSH.Server.1.");
    amxc_var_add(cstring_t, &check_var, "SSH.Server.2.");
    amxc_var_add(cstring_t, &check_var, "SSH.Server.test-server-1.");
    amxc_var_add(cstring_t, &check_var, "SSH.Server.test-server-2.");
    expect_check(test_complete_cb, data, test_check_completion_list, &check_var);
    handle_events();

    amxc_var_clean(&tty_args);
    amxc_var_clean(&check_var);
}

void test_can_complete_object_path_in_cd_context(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;
    amxc_var_t* cmd_parts = NULL;
    amxc_var_t* ret = NULL;
    amxc_var_t* variable = NULL;
    amxc_var_t tty_args;
    amxc_var_t check_var;

    amxc_var_init(&tty_args);
    amxc_var_init(&check_var);

    variable = amxt_tty_claim_config(ba_cli->tty, "path");
    amxc_var_set(cstring_t, variable, "SSH.Server.");

    amxc_var_new(&ret);
    amxc_var_set_type(ret, AMXC_VAR_ID_LIST);
    amxt_cli_build_args(&tty_args, "");
    cmd_parts = GET_ARG(&tty_args, "cmd");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__complete", cmd_parts, ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_set_type(&check_var, AMXC_VAR_ID_LIST);
    amxc_var_add(cstring_t, &check_var, "1.");
    amxc_var_add(cstring_t, &check_var, "2.");
    amxc_var_add(cstring_t, &check_var, "test-server-1.");
    amxc_var_add(cstring_t, &check_var, "test-server-2.");
    expect_check(test_complete_cb, data, test_check_completion_list, &check_var);
    handle_events();

    amxc_var_new(&ret);
    amxc_var_set_type(ret, AMXC_VAR_ID_LIST);
    amxt_cli_build_args(&tty_args, ".SSH.");
    cmd_parts = GET_ARG(&tty_args, "cmd");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__complete", cmd_parts, ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_set_type(&check_var, AMXC_VAR_ID_LIST);
    amxc_var_add(cstring_t, &check_var, ".SSH.Enable");
    amxc_var_add(cstring_t, &check_var, ".SSH.ServerNumberOfEntries");
    amxc_var_add(cstring_t, &check_var, ".SSH.Server");
    amxc_var_add(cstring_t, &check_var, ".SSH.S");
    expect_check(test_complete_cb, data, test_check_completion_list, &check_var);
    handle_events();

    amxc_var_set(cstring_t, variable, "");

    amxc_var_clean(&tty_args);
    amxc_var_clean(&check_var);
}

void test_completes_is_empty_when_not_found(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;
    amxc_var_t* cmd_parts = NULL;
    amxc_var_t* ret = NULL;
    amxc_var_t tty_args;
    amxc_var_t check_var;
    amxc_var_t* connection = NULL;

    amxc_var_init(&tty_args);
    amxc_var_init(&check_var);

    amxc_var_new(&ret);
    amxc_var_set_type(ret, AMXC_VAR_ID_LIST);
    amxt_cli_build_args(&tty_args, "MQTT.");
    cmd_parts = GET_ARG(&tty_args, "cmd");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__complete", cmd_parts, ret);
    assert_int_equal(cmd_rv, 0);

    expect_check(test_complete_cb, data, test_check_completion_list, NULL);
    expect_check(test_complete_cb, data, test_check_completion_list, NULL);
    handle_events();

    connection = amxt_tty_claim_config(ba_cli->tty, "connection");
    amxc_var_delete(&connection);

    amxc_var_new(&ret);
    amxc_var_set_type(ret, AMXC_VAR_ID_LIST);
    amxt_cli_build_args(&tty_args, "MQTT.");
    cmd_parts = GET_ARG(&tty_args, "cmd");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__complete", cmd_parts, ret);
    assert_int_equal(cmd_rv, 0);

    handle_events();

    connection = amxt_tty_claim_config(ba_cli->tty, "connection");
    amxc_var_set(cstring_t, connection, "dummy:/tmp/dummy.sock");

    handle_events();

    amxc_var_clean(&tty_args);
    amxc_var_clean(&check_var);
}

void test_can_complete_object_parameters(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;
    amxc_var_t cmd_parts;
    amxc_var_t* ret = NULL;
    amxc_var_t check_var;
    char* cmd_to_complete1 = strdup("SSH.Server.+ {Allow");
    char* cmd_to_complete2 = strdup("SSH.Server.{AllowPasswordLogin = ");
    uint32_t len = strlen(cmd_to_complete1);

    amxc_var_init(&cmd_parts);
    amxc_var_init(&check_var);

    amxc_var_new(&ret);
    amxc_var_set_type(ret, AMXC_VAR_ID_LIST);

    amxt_cmd_parse_line(cmd_to_complete1, len, &cmd_parts, NULL);
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__complete", &cmd_parts, ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_set_type(&check_var, AMXC_VAR_ID_LIST);
    amxc_var_add(cstring_t, &check_var, "AllowRootLogin = ");
    amxc_var_add(cstring_t, &check_var, "AllowPasswordLogin = ");
    amxc_var_add(cstring_t, &check_var, "AllowRootPasswordLogin = ");
    expect_check(test_complete_cb, data, test_check_completion_list, &check_var);
    handle_events();

    len = strlen(cmd_to_complete2);
    amxt_cmd_parse_line(cmd_to_complete2, len, &cmd_parts, NULL);
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__complete", &cmd_parts, ret);
    assert_int_equal(cmd_rv, 0);

    handle_events();

    free(cmd_to_complete1);
    free(cmd_to_complete2);
    amxc_var_clean(&cmd_parts);
    amxc_var_clean(&check_var);
}

void test_parameter_complete_skips_used_parameters(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;
    amxc_var_t cmd_parts;
    amxc_var_t* ret = NULL;
    amxc_var_t check_var;
    char* cmd_to_complete = strdup("SSH.Server.+ {AllowRootLogin=false,Allow");
    uint32_t len = strlen(cmd_to_complete);

    amxc_var_init(&cmd_parts);
    amxc_var_init(&check_var);

    amxc_var_new(&ret);
    amxc_var_set_type(ret, AMXC_VAR_ID_LIST);

    amxt_cmd_parse_line(cmd_to_complete, len, &cmd_parts, NULL);
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__complete", &cmd_parts, ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_set_type(&check_var, AMXC_VAR_ID_LIST);
    amxc_var_add(cstring_t, &check_var, "AllowPasswordLogin = ");
    amxc_var_add(cstring_t, &check_var, "AllowRootPasswordLogin = ");
    expect_check(test_complete_cb, data, test_check_completion_list, &check_var);
    handle_events();

    free(cmd_to_complete);
    amxc_var_clean(&cmd_parts);
    amxc_var_clean(&check_var);
}

void test_can_complete_function_arguments(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;
    amxc_var_t cmd_parts;
    amxc_var_t* ret = NULL;
    amxc_var_t check_var;
    char* cmd_to_complete1 = strdup("SSH.Server.1.test_function(");
    uint32_t len = strlen(cmd_to_complete1);

    amxc_var_init(&cmd_parts);
    amxc_var_init(&check_var);

    amxc_var_new(&ret);
    amxc_var_set_type(ret, AMXC_VAR_ID_LIST);

    amxt_cmd_parse_line(cmd_to_complete1, len, &cmd_parts, NULL);
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__complete", &cmd_parts, ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_set_type(&check_var, AMXC_VAR_ID_LIST);
    amxc_var_add(cstring_t, &check_var, "foo = ");
    amxc_var_add(cstring_t, &check_var, "bar = ");
    expect_check(test_complete_cb, data, test_check_completion_list, &check_var);
    handle_events();

    free(cmd_to_complete1);
    amxc_var_clean(&cmd_parts);
    amxc_var_clean(&check_var);
}

void test_can_get_objects(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;
    amxc_var_t* output_fmt = NULL;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "SSH.?");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__execute", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    amxt_cli_build_args(&tty_args, "SSH.Server.*.?");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__execute", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    output_fmt = amxc_var_add_key(cstring_t, &ba_cli->tty->config, "output-format", "json");
    amxt_cli_build_args(&tty_args, "SSH.Server.[Alias == 'test-server-2'].?");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__execute", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    amxt_cli_build_args(&tty_args, "SSH.Server.test-server-2.?");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__execute", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    amxt_cli_build_args(&tty_args, "SSH.?0");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__execute", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_delete(&output_fmt);
    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_get_referenced_object(UNUSED void** state) {
    amxb_bus_ctx_t* bus_ctx = amxb_find_uri("dummy:/tmp/dummy.sock");
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxb_set_access(bus_ctx, AMXB_PROTECTED);
    amxt_cli_build_args(&tty_args, "SSH.Server.2.TestReference.Reference+.?");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__execute", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);
    amxb_set_access(bus_ctx, AMXB_PUBLIC);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_get_fails_when_object_does_not_exist(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    amxc_var_t* connection = NULL;
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "MQTT.Server.?");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__execute", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    connection = amxt_tty_claim_config(ba_cli->tty, "connection");
    amxc_var_delete(&connection);

    amxt_cli_build_args(&tty_args, "MQTT.Server.?");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__execute", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    connection = amxt_tty_claim_config(ba_cli->tty, "connection");
    amxc_var_set(cstring_t, connection, "dummy:/tmp/dummy.sock");

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_set_parameters(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;
    amxd_object_t* server = NULL;
    char* txt = NULL;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "SSH.Server.1.Port = 1970");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__execute", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    server = amxd_dm_findf(&ba_cli->dm, "SSH.Server.1.");
    assert_int_equal(amxd_object_get_value(uint32_t, server, "Port", NULL), 1970);

    amxt_cli_build_args(&tty_args, "SSH.Server.2.{Port = 2020,AllowPasswordLogin=false, TestParam\t='TestValue'}");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__execute", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    server = amxd_dm_findf(&ba_cli->dm, "SSH.Server.2.");
    assert_int_equal(amxd_object_get_value(uint32_t, server, "Port", NULL), 2020);
    assert_false(amxd_object_get_value(bool, server, "AllowPasswordLogin", NULL));
    txt = amxd_object_get_value(cstring_t, server, "TestParam", NULL);
    assert_string_equal(txt, "TestValue");
    free(txt);

    amxt_cli_build_args(&tty_args, "SSH.Server.1.{Port=1024, Status='Stopped'}");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__execute", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_set_fails_when_invalid_syntax_is_used(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "SSH.Server.1.=[Port,TestParam]");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__execute", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxt_cli_build_args(&tty_args, "SSH.Server.1.={Port=1024}");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__execute", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxt_cli_build_args(&tty_args, "SSH.Server.1.{Port:1024}");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__execute", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_set_fails_when_setting_unknown_parameters(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "SSH.Server.1.InvalidParam='Hello'");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__execute", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_add_instance(UNUSED void** state) {
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

    amxt_cli_build_args(&tty_args, "SSH.Server.+{Port = 2020,AllowPasswordLogin=false, TestParam\t='TestValue'}");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__execute", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    server = amxd_dm_findf(&ba_cli->dm, "SSH.Server.4.");
    assert_int_equal(amxd_object_get_value(uint32_t, server, "Port", NULL), 2020);
    assert_false(amxd_object_get_value(bool, server, "AllowPasswordLogin", NULL));
    txt = amxd_object_get_value(cstring_t, server, "TestParam", NULL);
    assert_string_equal(txt, "TestValue");

    free(txt);
    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_add_instance_fails_when_invalid_syntax_used(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "SSH.Server.+Port=1919");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__execute", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxt_cli_build_args(&tty_args, "SSH.Server.+[Port,AllowPasswordLogin]");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__execute", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_add_instance_fails_on_invalid_object(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "SSH.+");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__execute", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxt_cli_build_args(&tty_args, "SSH.Server.1.");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__execute", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_del_instance(UNUSED void** state) {
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

void test_del_instance_fails_on_invalid_object(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "SSH.Server.-");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__execute", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxt_cli_build_args(&tty_args, "SSH.-");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__execute", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxt_cli_build_args(&tty_args, "SSH.Server.4.TestObject.-");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__execute", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxt_cli_build_args(&tty_args, "SSH.NotExisting.-");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__execute", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_invoke_function(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "SSH.Server.1.test_function()");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__execute", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_invoke_function_with_search_path(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "SSH.Server.*.test_function()");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__execute", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_list_pending_invokes(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "SSH.Server.1.test_function()");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__execute", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_clean(&tty_args);
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "requests", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    handle_events();
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "requests", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_invoke_fails_when_rpc_fails(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "SSH.Server.1.close_sessions()");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__execute", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);
    handle_events();
    ba_cli->tty->interactive = true;
    amxt_cli_build_args(&tty_args, "SSH.Server.1.close_sessions()");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__execute", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);
    handle_events();
    assert_int_not_equal(GET_UINT32(amxt_tty_get_config(ba_cli->tty, "rv"), NULL), 0);
    ba_cli->tty->interactive = false;

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_invoke_fails_when_request_can_not_be_created(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "SSH.NotExisting.1.close_sessions()");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__execute", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_invoke_fails_on_invalid_syntax(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "SSH.Server.1.test_function('test','test')");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__execute", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_parser_fails_on_invalid_operator(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "SSH.Server.1.!");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__execute", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_list_empty_subscriptions(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "subscriptions", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

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

void test_can_subscribe_using_search_path(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    // clear all events
    handle_events();

    amxt_cli_build_args(&tty_args, "SSH.Server.*.?&");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__execute", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_subscribe_on_parameter(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    // clear all events
    handle_events();

    amxt_cli_build_args(&tty_args, "SSH.Server.1.Enable?&");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__execute", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_subscribe_with_filter(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    // clear all events
    handle_events();

    amxt_cli_build_args(&tty_args, "SSH.Server.1.?& contains('Enable')");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__execute", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_subscribe_can_fail(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    // clear all events
    handle_events();

    amxt_cli_build_args(&tty_args, "SSH.Server.99.Enable?&");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__execute", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_receive_changed_events(UNUSED void** state) {
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

void test_can_receive_add_events(UNUSED void** state) {
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

void test_can_receive_del_events(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;
    amxc_var_t* raw = NULL;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "SSH.Server.4-");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__execute", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    handle_events();

    raw = amxt_tty_claim_config(ba_cli->tty, "raw-event");
    amxc_var_set(bool, raw, true);

    amxt_cli_build_args(&tty_args, "SSH.Server.5 -");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__execute", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    handle_events();

    amxc_var_set(bool, raw, false);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_receive_periodic_inform(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    amxd_object_t* server = amxd_dm_findf(&ba_cli->dm, "SSH.Server.1.");
    amxc_var_t* raw = NULL;

    amxd_object_new_pi(server, 1);

    amxp_timers_calculate();
    amxp_timers_check();
    sleep(1);
    amxp_timers_calculate();
    amxp_timers_check();
    handle_events();

    raw = amxt_tty_claim_config(ba_cli->tty, "raw-event");
    amxc_var_set(bool, raw, true);

    sleep(1);
    amxp_timers_calculate();
    amxp_timers_check();
    handle_events();

    amxc_var_set(bool, raw, false);

    amxd_object_delete_pi(server);
}

void test_can_receive_custom_event(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    amxd_object_t* server = amxd_dm_findf(&ba_cli->dm, "SSH.Server.1.");
    amxc_var_t data;

    amxc_var_init(&data);
    amxc_var_set_type(&data, AMXC_VAR_ID_HTABLE);

    amxc_var_add_key(cstring_t, &data, "Key1", "test data");

    amxd_object_emit_signal(server, "test-event", &data);
    handle_events();

    amxc_var_clean(&data);
}

void test_can_list_subscriptions(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "subscriptions", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_unsubscribe(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "SSH.?$");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__execute", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_unsubscribe_can_fail(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "SSH.Server.99.?$");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__execute", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_unsubscribe_on_search_path_fails(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "SSH.Server.*.?$");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__execute", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_del_instance_prints_message_if_nothing_deleted(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    amxt_cli_build_args(&tty_args, "SSH.Server.*.-");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__execute", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    amxt_cli_build_args(&tty_args, "SSH.Server.*.-");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__execute", &tty_args, &ret);
    assert_int_not_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_can_resolve_paths(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;
    amxb_bus_ctx_t* ctx = NULL;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    ctx = amxb_be_who_has("SSH.");
    assert_non_null(ctx);

    amxt_cli_build_args(&tty_args, "SSH.Server.[Status=='Stopped'].");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "resolve", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    amxt_cli_build_args(&tty_args, "SSH.Server.*.");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "resolve", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}

void test_pending_invokes_are_closed_when_connection_is_closed(UNUSED void** state) {
    ba_cli_t* ba_cli = ba_cli_get_data();
    int cmd_rv = 0;
    amxb_bus_ctx_t* ctx = NULL;

    amxc_var_t ret;
    amxc_var_t tty_args;
    amxc_var_init(&ret);
    amxc_var_init(&tty_args);

    ctx = amxb_be_who_has("SSH.");
    assert_non_null(ctx);

    amxt_cli_build_args(&tty_args, "SSH.Server.+");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__execute", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    amxt_cli_build_args(&tty_args, "SSH.Server.7.test_function()");
    cmd_rv = amxm_so_execute_function(ba_cli->so, "cli", "__execute", &tty_args, &ret);
    assert_int_equal(cmd_rv, 0);

    assert_int_equal(amxb_disconnect(ctx), 0);

    amxb_free(&ctx);
    amxc_var_clean(&ret);
    amxc_var_clean(&tty_args);
}
