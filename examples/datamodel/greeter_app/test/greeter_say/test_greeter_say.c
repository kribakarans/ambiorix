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

#include <amxc/amxc.h>
#include <amxp/amxp.h>

#include <amxd/amxd_dm.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_transaction.h>

#include <amxo/amxo.h>

#include "greeter.h"
#include "greeter_dm_funcs.h"
#include "test_greeter_say.h"

static greeter_stats_t stats;

greeter_stats_t* greeter_get_stats(void) {
    return &stats;
}

static void handle_events(void) {
    printf("Handling events ");
    while(amxp_signal_read() == 0) {
        printf(".");
    }
    printf("\n");
}

int test_greeter_setup(UNUSED void** state) {
    amxd_trans_t trans;
    amxc_var_t* config = NULL;
    amxd_dm_t* dm = NULL;
    amxo_parser_t* parser = NULL;

    amxrt_new();

    config = amxrt_get_config();
    dm = amxrt_get_dm();
    parser = amxrt_get_parser();

    amxc_var_add_key(cstring_t, config, AMXRT_COPT_NAME, "greeter");

    amxo_resolver_ftab_add(parser, "check_change", AMXO_FUNC(_State_check_change));
    amxo_resolver_ftab_add(parser, "Greeter.Statistics.stats_read", AMXO_FUNC(_stats_read));
    amxo_resolver_ftab_add(parser, "Greeter.Statistics.stats_list", AMXO_FUNC(_stats_list));
    amxo_resolver_ftab_add(parser, "Greeter.Statistics.stats_describe", AMXO_FUNC(_stats_describe));

    // event handlers
    amxo_resolver_ftab_add(parser, "enable_greeter", AMXO_FUNC(_enable_greeter));
    amxo_resolver_ftab_add(parser, "disable_greeter", AMXO_FUNC(_disable_greeter));
    amxo_resolver_ftab_add(parser, "print_event", AMXO_FUNC(_print_event));

    // datamodel RPC funcs
    amxo_resolver_ftab_add(parser, "Greeter.echo", AMXO_FUNC(_function_dump));
    amxo_resolver_ftab_add(parser, "Greeter.say", AMXO_FUNC(_Greeter_say));
    amxo_resolver_ftab_add(parser, "Greeter.History.clear", AMXO_FUNC(_History_clear));
    amxo_resolver_ftab_add(parser, "Greeter.setMaxHistory", AMXO_FUNC(_Greeter_setMaxHistory));
    amxo_resolver_ftab_add(parser, "Greeter.save", AMXO_FUNC(_Greeter_save));
    amxo_resolver_ftab_add(parser, "Greeter.load", AMXO_FUNC(_Greeter_load));
    amxo_resolver_ftab_add(parser, "Greeter.Statistics.periodic_inform", AMXO_FUNC(_periodic_inform));
    amxo_resolver_ftab_add(parser, "Greeter.Statistics.reset", AMXO_FUNC(_Statistics_reset));

    assert_int_equal(amxo_parser_parse_file(parser, "../../odl/greeter.odl", amxd_dm_get_root(dm)), 0);
    amxp_sigmngr_enable(&dm->sigmngr, true);

    amxd_trans_init(&trans);
    amxd_trans_select_pathf(&trans, "Greeter");
    amxd_trans_set_value(cstring_t, &trans, "State", "Start");
    assert_int_equal(amxd_trans_apply(&trans, dm), amxd_status_ok);
    amxd_trans_clean(&trans);

    handle_events();

    return 0;
}

int test_greeter_teardown(UNUSED void** state) {
    amxrt_delete();
    return 0;
}

void test_can_call_say(UNUSED void** state) {
    amxd_dm_t* dm = amxrt_get_dm();
    amxd_object_t* greeter = amxd_dm_findf(dm, "Greeter");
    amxc_var_t args;
    amxc_var_t ret;

    assert_non_null(greeter);

    amxc_var_init(&args);
    amxc_var_init(&ret);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &args, "from", "tests");
    amxc_var_add_key(cstring_t, &args, "message", "hello from testing");

    assert_int_equal(amxd_object_invoke_function(greeter, "say", &args, &ret), amxd_status_ok);

    handle_events();

    amxc_var_clean(&args);
    amxc_var_clean(&ret);
}

void test_calling_say_fails_when_not_running(UNUSED void** state) {
    amxd_dm_t* dm = amxrt_get_dm();
    amxd_object_t* greeter = amxd_dm_findf(dm, "Greeter");
    amxd_trans_t trans;
    amxc_var_t args;
    amxc_var_t ret;

    assert_non_null(greeter);

    amxc_var_init(&args);
    amxc_var_init(&ret);

    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &args, "from", "tests");
    amxc_var_add_key(cstring_t, &args, "message", "hello from testing");

    amxd_trans_init(&trans);
    amxd_trans_select_object(&trans, greeter);
    amxd_trans_set_value(cstring_t, &trans, "State", "Stop");
    assert_int_equal(amxd_trans_apply(&trans, dm), amxd_status_ok);
    amxd_trans_clean(&trans);

    handle_events();

    assert_int_not_equal(amxd_object_invoke_function(greeter, "say", &args, &ret), amxd_status_ok);

    amxd_trans_init(&trans);
    amxd_trans_select_object(&trans, greeter);
    amxd_trans_set_value(cstring_t, &trans, "State", "Start");
    assert_int_equal(amxd_trans_apply(&trans, dm), amxd_status_ok);
    amxd_trans_clean(&trans);

    handle_events();

    amxc_var_clean(&args);
    amxc_var_clean(&ret);
    amxd_trans_clean(&trans);
}

