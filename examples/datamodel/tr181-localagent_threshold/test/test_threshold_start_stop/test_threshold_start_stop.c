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

#include <amxo/amxo.h>

#include "threshold.h"
#include "dm_threshold.h"
#include "test_threshold_start_stop.h"

#define UNUSED __attribute__((unused))
#define GET_KEY(v, k) amxc_var_get_key(v, k, AMXC_VAR_FLAG_DEFAULT)
#define CHAR(v) amxc_var_constcast(cstring_t, v)
#define UINT32(v) amxc_var_constcast(uint32_t, v)

static amxd_dm_t dm;
static amxo_parser_t parser;
static const char* odl_defs = "../../odl/la_threshold_definition.odl";

static void handle_events(void) {
    printf("Handling events ");
    while(amxp_signal_read() == 0) {
        printf(".");
    }
    printf("\n");
}

int test_threshold_setup(UNUSED void** state) {
    amxd_object_t* root_obj = NULL;
    int retval = 0;

    assert_int_equal(amxd_dm_init(&dm), amxd_status_ok);
    assert_int_equal(amxo_parser_init(&parser), 0);

    root_obj = amxd_dm_get_root(&dm);
    assert_non_null(root_obj);

    retval = amxo_parser_parse_file(&parser, odl_defs, root_obj);
    printf("PARSER MESSAGE = %s\n", amxc_string_get(&parser.msg, 0));
    assert_int_equal(retval, 0);

    handle_events();

    return 0;
}

int test_threshold_teardown(UNUSED void** state) {
    amxo_parser_clean(&parser);
    amxd_dm_clean(&dm);

    return 0;
}

void test_can_start_plugin(UNUSED void** state) {
    assert_int_equal(_threshold_main(0, &dm, &parser), 0);
}

void test_can_stop_plugin(UNUSED void** state) {
    assert_int_equal(_threshold_main(1, &dm, &parser), 0);
}

void test_entry_point_ignores_unhandled_reasons(UNUSED void** state) {
    assert_int_equal(_threshold_main(99, &dm, &parser), 0);
}

void test_actions_check_reason_codes(UNUSED void** state) {
    amxd_trans_t transaction;
    amxd_object_t* threshold = NULL;
    amxc_var_t retval;

    amxc_var_init(&retval);

    amxd_trans_init(&transaction);
    amxd_trans_select_pathf(&transaction, "LocalAgent.Threshold.");
    amxd_trans_add_inst(&transaction, 0, NULL);
    assert_int_equal(amxd_trans_apply(&transaction, &dm), 0);
    amxd_trans_clean(&transaction);

    threshold = amxd_dm_findf(&dm, "LocalAgent.Threshold.1.");

    assert_int_equal(_threshold_instance_is_valid(threshold, NULL, action_object_destroy, NULL, &retval, NULL),
                     amxd_status_function_not_implemented);
    assert_int_equal(_threshold_instance_cleanup(threshold, NULL, action_object_validate, NULL, &retval, NULL),
                     amxd_status_function_not_implemented);

    amxc_var_clean(&retval);
}