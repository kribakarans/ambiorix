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

#include "threshold.h"
#include "dm_threshold.h"
#include "test_threshold_events.h"

amxd_dm_t dm;
amxb_bus_ctx_t* bus_ctx = NULL;

static amxo_parser_t parser;
static const char* odl_defs = "../../odl/la_threshold_definition.odl";

void handle_events(void) {
    printf("Handling events\n");
    while(amxp_signal_read() == 0) {
    }
}

void connection_read(UNUSED int fd, UNUSED void* priv) {
    // Do nothing
}

static void test_build_localagent_threshold_dm(amxd_object_t* root_obj) {
    int retval = 0;
    assert_int_equal(amxo_resolver_ftab_add(&parser, "threshold_instance_is_valid", AMXO_FUNC(_threshold_instance_is_valid)), 0);
    assert_int_equal(amxo_resolver_ftab_add(&parser, "threshold_instance_cleanup", AMXO_FUNC(_threshold_instance_cleanup)), 0);
    assert_int_equal(amxo_resolver_ftab_add(&parser, "threshold_changed", AMXO_FUNC(_threshold_changed)), 0);
    assert_int_equal(amxo_resolver_ftab_add(&parser, "threshold_added", AMXO_FUNC(_threshold_added)), 0);
    assert_int_equal(amxo_resolver_ftab_add(&parser, "print_event", AMXO_FUNC(_print_event)), 0);

    retval = amxo_parser_parse_file(&parser, odl_defs, root_obj);
    printf("PARSER MESSAGE = %s\n", amxc_string_get(&parser.msg, 0));
    assert_int_equal(retval, 0);

    _threshold_main(0, &dm, &parser);

    handle_events();
}

static void test_build_ethernet_interface_dm(amxd_object_t* root_obj) {
    amxd_trans_t trans;

    int retval = amxo_parser_parse_file(&parser, "./test.odl", root_obj);
    printf("PARSER MESSAGE = %s\n", amxc_string_get(&parser.msg, 0));
    assert_int_equal(retval, 0);

    amxd_trans_init(&trans);
    amxd_trans_select_pathf(&trans, "Ethernet.Interface");
    amxd_trans_add_inst(&trans, 0, NULL);                   // 1
    amxd_trans_set_value(bool, &trans, "Enable", true);
    amxd_trans_select_pathf(&trans, ".^");
    amxd_trans_add_inst(&trans, 0, NULL);                   // 2
    amxd_trans_select_pathf(&trans, ".^");
    amxd_trans_add_inst(&trans, 0, NULL);                   // 3
    amxd_trans_set_value(bool, &trans, "Enable", true);
    amxd_trans_select_pathf(&trans, ".^");
    amxd_trans_add_inst(&trans, 0, NULL);                   // 4

    assert_int_equal(amxd_trans_apply(&trans, &dm), 0);

    amxd_trans_clean(&trans);
}

int test_threshold_setup(UNUSED void** state) {
    amxd_object_t* root_obj = NULL;
    int retval = 0;

    assert_int_equal(amxd_dm_init(&dm), amxd_status_ok);
    assert_int_equal(amxo_parser_init(&parser), 0);

    assert_int_equal(test_threshold_register_dummy_be(), 0);

    root_obj = amxd_dm_get_root(&dm);
    assert_non_null(root_obj);

    // Data model under test
    test_build_localagent_threshold_dm(root_obj);
    // Dummy data model for testing
    test_build_ethernet_interface_dm(root_obj);

    // Create dummy/fake bus connections
    assert_int_equal(amxb_connect(&bus_ctx, "dummy:/tmp/dummy.sock"), 0);
    amxo_connection_add(&parser, 101, connection_read, "dummy:/tmp/dummy.sock", AMXO_BUS, bus_ctx);
    // Register data model
    amxb_register(bus_ctx, &dm);

    handle_events();

    return retval;
}

int test_threshold_teardown(UNUSED void** state) {
    _threshold_main(1, &dm, &parser);

    amxb_free(&bus_ctx);

    amxo_parser_clean(&parser);
    amxd_dm_clean(&dm);

    test_threshold_unregister_dummy_be();

    return 0;
}
