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
#include <sys/stat.h>

#include <stdlib.h>
#include <stdio.h>
#include <setjmp.h>
#include <stdarg.h>
#include <cmocka.h>
#include <unistd.h>

#include "threshold.h"
#include "dm_threshold.h"
#include "test_threshold_events_pcb.h"

amxd_dm_t dm;
amxb_bus_ctx_t* bus_ctx = NULL;

static amxb_bus_ctx_t* bus_ctx_dummy = NULL;

static amxo_parser_t parser;
static const char* odl_defs = "../../odl/la_threshold_definition.odl";

static amxp_subproc_t* amxrt = NULL;

static bool file_exists(char* filename) {
    struct stat buffer;
    return (stat(filename, &buffer) == 0);
}

void handle_events(void) {
    printf("Handling events\n");
    if(amxb_read(bus_ctx) == 0) {
        usleep(500);
        amxb_read(bus_ctx);
    }
    while(amxp_signal_read() == 0) {
    }
}

void connection_read(UNUSED int fd, void* priv) {
    amxb_bus_ctx_t* bus_ctx = (amxb_bus_ctx_t*) priv;
    amxb_read(bus_ctx);
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

static void test_build_ethernet_interface_dm(void) {
    amxc_var_t params;
    amxc_var_t ret;
    int rv = -1;

    amxc_var_init(&params);
    amxc_var_init(&ret);

    assert_int_equal(amxp_subproc_start(amxrt, "amxrt", "./test.odl", NULL), 0);
    assert_true(amxp_subproc_is_running(amxrt));
    while(rv != 0) {
        rv = amxb_get(bus_ctx, "Ethernet.", 0, &ret, 5);
        printf("Try to get Ethernet. object from bus, rv = %d\n", rv);
        sleep(1);
    }

    printf("test_plugin pid = %d\n", amxp_subproc_get_pid(amxrt));
    system("pcb_cli pcb://ipc:[/tmp/test.sock] ?");

    assert_int_equal(amxb_add(bus_ctx, "Ethernet.Interface", 0, NULL, NULL, &ret, 5), 0);
    amxc_var_set_type(&params, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(bool, &params, "Enable", true);
    assert_int_equal(amxb_set(bus_ctx, "Ethernet.Interface.1", &params, &ret, 5), 0);
    assert_int_equal(amxb_add(bus_ctx, "Ethernet.Interface", 0, NULL, NULL, &ret, 5), 0);
    assert_int_equal(amxb_add(bus_ctx, "Ethernet.Interface", 0, NULL, NULL, &ret, 5), 0);
    amxc_var_set_type(&params, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(bool, &params, "Enable", true);
    assert_int_equal(amxb_set(bus_ctx, "Ethernet.Interface.3", &params, &ret, 5), 0);
    assert_int_equal(amxb_add(bus_ctx, "Ethernet.Interface", 0, NULL, NULL, &ret, 5), 0);
    system("pcb_cli pcb://ipc:[/tmp/test.sock] ?");

    amxc_var_clean(&params);
    amxc_var_clean(&ret);
}

int test_threshold_setup(UNUSED void** state) {
    amxd_object_t* root_obj = NULL;
    int retval = 0;

    if(!file_exists("/usr/bin/mods/amxb/mod-amxb-pcb.so")) {
        return 0;
    }

    assert_int_equal(amxd_dm_init(&dm), amxd_status_ok);
    assert_int_equal(amxo_parser_init(&parser), 0);

    assert_int_equal(test_threshold_register_dummy_be(), 0);
    assert_int_equal(amxb_connect(&bus_ctx_dummy, "dummy:/tmp/dummy.sock"), 0);
    amxo_connection_add(&parser, 101, connection_read, "dummy:/tmp/dummy.sock", AMXO_BUS, bus_ctx_dummy);

    root_obj = amxd_dm_get_root(&dm);
    assert_non_null(root_obj);

    amxp_subproc_new(&amxrt);

    system("killall test_bus");
    system("pcb_sysbus -n test_bus -I /tmp/test.sock");
    assert_int_equal(amxb_be_load("/usr/bin/mods/amxb/mod-amxb-pcb.so"), 0);

    // Data model under test
    test_build_localagent_threshold_dm(root_obj);

    // Create dummy/fake bus connections
    assert_int_equal(amxb_connect(&bus_ctx, "pcb:/tmp/test.sock"), 0);
    amxo_connection_add(&parser, amxb_get_fd(bus_ctx), connection_read, "pcb:/tmp/test.sock", AMXO_BUS, bus_ctx);

    // Dummy data model for testing
    test_build_ethernet_interface_dm();

    // Register data model
    amxb_register(bus_ctx, &dm);

    handle_events();

    return retval;
}

int test_threshold_teardown(UNUSED void** state) {
    if(!file_exists("/usr/bin/mods/amxb/mod-amxb-pcb.so")) {
        return 0;
    }
    amxp_subproc_kill(amxrt, SIGTERM);
    amxp_subproc_delete(&amxrt);

    system("killall test_bus");

    _threshold_main(1, &dm, &parser);

    amxb_free(&bus_ctx_dummy);
    amxb_free(&bus_ctx);

    amxo_parser_clean(&parser);
    amxd_dm_clean(&dm);

    test_threshold_unregister_dummy_be();

    amxb_be_remove_all();

    return 0;
}
