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
#include <stdio.h>
#include <setjmp.h>
#include <stdarg.h>
#include <cmocka.h>

#include <amxc/amxc_macros.h>
#include <amxc/amxc.h>
#include <amxp/amxp.h>

#include <amxd/amxd_dm.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_transaction.h>

#include <amxo/amxo.h>

#include "greeter.h"
#include "dm_greeter.h"
#include "test_greeter_dump.h"

#define GET_KEY(v, k) amxc_var_get_key(v, k, AMXC_VAR_FLAG_DEFAULT)
#define CHAR(v) amxc_var_constcast(cstring_t, v)

static amxd_dm_t dm;
static amxo_parser_t parser;
static const char* odl_defs = "greeter_test.odl";

static void handle_events(void) {
    printf("Handling events ");
    while(amxp_signal_read() == 0) {
        printf(".");
    }
    printf("\n");
}

static void read_sigalrm(void) {
    sigset_t mask;
    int sfd;
    struct signalfd_siginfo fdsi;
    ssize_t s;

    sigemptyset(&mask);
    sigaddset(&mask, SIGALRM);

    sigprocmask(SIG_BLOCK, &mask, NULL);

    sfd = signalfd(-1, &mask, 0);
    s = read(sfd, &fdsi, sizeof(struct signalfd_siginfo));
    assert_int_equal(s, sizeof(struct signalfd_siginfo));
    if(fdsi.ssi_signo == SIGALRM) {
        printf("Got SIGALRM\n");
        amxp_timers_calculate();
        amxp_timers_check();
    } else {
        printf("Read unexpected signal\n");
    }
}

int test_greeter_setup(UNUSED void** state) {
    amxd_object_t* root_obj = NULL;
    amxd_trans_t trans;

    assert_int_equal(amxd_dm_init(&dm), amxd_status_ok);
    assert_int_equal(amxo_parser_init(&parser), 0);

    root_obj = amxd_dm_get_root(&dm);
    assert_non_null(root_obj);

    assert_int_equal(amxo_resolver_ftab_add(&parser, "check_change", AMXO_FUNC(_State_check_change)), 0);
    assert_int_equal(amxo_resolver_ftab_add(&parser, "enable_greeter", AMXO_FUNC(_enable_greeter)), 0);
    assert_int_equal(amxo_resolver_ftab_add(&parser, "disable_greeter", AMXO_FUNC(_disable_greeter)), 0);
    assert_int_equal(amxo_resolver_ftab_add(&parser, "greeter_main", AMXO_FUNC(_greeter_main)), 0);
    assert_int_equal(amxo_resolver_ftab_add(&parser, "print_event", AMXO_FUNC(_print_event)), 0);
    assert_int_equal(amxo_resolver_ftab_add(&parser, "Greeter.say", AMXO_FUNC(_Greeter_say)), 0);
    assert_int_equal(amxo_resolver_ftab_add(&parser, "Greeter.echo", AMXO_FUNC(_function_dump)), 0);
    assert_int_equal(amxo_resolver_ftab_add(&parser, "Greeter.deferred_echo", AMXO_FUNC(_deferred_echo)), 0);

    assert_int_equal(amxo_parser_parse_file(&parser, odl_defs, root_obj), 0);

    _greeter_main(0, &dm, &parser);

    handle_events();

    amxd_trans_init(&trans);
    amxd_trans_select_pathf(&trans, "Greeter");
    amxd_trans_set_value(cstring_t, &trans, "State", "Start");
    assert_int_equal(amxd_trans_apply(&trans, &dm), amxd_status_ok);
    amxd_trans_clean(&trans);

    handle_events();

    return 0;
}

int test_greeter_teardown(UNUSED void** state) {
    _greeter_main(1, &dm, &parser);

    amxo_parser_clean(&parser);
    amxd_dm_clean(&dm);

    return 0;
}

void test_can_call_echo(UNUSED void** state) {
    amxd_object_t* greeter = amxd_dm_findf(&dm, "Greeter");
    amxc_var_t args;
    amxc_var_t ret;

    assert_non_null(greeter);

    amxc_var_init(&args);
    amxc_var_init(&ret);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &args, "data", "tests");

    assert_int_equal(amxd_object_invoke_function(greeter, "echo", &args, &ret), amxd_status_ok);

    handle_events();

    amxc_var_clean(&args);
    amxc_var_clean(&ret);
}

static void test_deferred_echo_returns(const amxc_var_t* const data,
                                       void* const priv) {
    uint32_t* counter = (uint32_t*) priv;
    assert_non_null(data);
    assert_non_null(priv);

    fflush(stdout);
    amxc_var_dump(data, STDOUT_FILENO);
    assert_non_null(GETP_ARG(data, "retval.data"));
    assert_non_null(GETP_ARG(data, "retval.time"));
    assert_non_null(GETP_ARG(data, "status"));
    (*counter)++;
}

void test_can_call_deferred_echo(UNUSED void** state) {
    amxd_object_t* greeter = amxd_dm_findf(&dm, "Greeter");
    amxc_var_t args;
    amxc_var_t ret;
    uint64_t call_id = 0;
    uint32_t counter = 0;

    assert_non_null(greeter);

    amxc_var_init(&args);
    amxc_var_init(&ret);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &args, "data", "tests");
    amxc_var_add_key(uint32_t, &args, "time", 1);

    assert_int_equal(amxd_object_invoke_function(greeter, "deferred_echo", &args, &ret), amxd_status_deferred);
    call_id = amxc_var_constcast(uint64_t, &ret);
    assert_int_equal(amxd_function_set_deferred_cb(call_id, test_deferred_echo_returns, &counter), 0);

    handle_events();
    read_sigalrm();
    handle_events();

    assert_int_equal(counter, 1);

    amxc_var_clean(&args);
    amxc_var_clean(&ret);
}

void test_can_cancel_deferred_echo(UNUSED void** state) {
    amxd_object_t* greeter = amxd_dm_findf(&dm, "Greeter");
    amxc_var_t args;
    amxc_var_t ret;
    uint64_t call_id = 0;

    amxc_var_init(&args);
    amxc_var_init(&ret);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &args, "data", "tests");
    amxc_var_add_key(uint32_t, &args, "time", 1);

    assert_int_equal(amxd_object_invoke_function(greeter, "deferred_echo", &args, &ret), amxd_status_deferred);
    call_id = amxc_var_constcast(uint64_t, &ret);
    amxd_function_deferred_remove(call_id);

    handle_events();

    amxc_var_clean(&args);
    amxc_var_clean(&ret);
}