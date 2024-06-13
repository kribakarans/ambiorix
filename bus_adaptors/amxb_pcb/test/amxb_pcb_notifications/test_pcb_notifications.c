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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <signal.h>

#include <amxc/amxc.h>
#include <amxp/amxp.h>

#include <amxd/amxd_dm.h>

#include <amxb/amxb.h>

#include "test_pcb_notifications.h"

static amxb_bus_ctx_t* bus_ctx = NULL;
static amxc_var_t events;

static void event_handler(const char* const sig_name,
                          const amxc_var_t* const data,
                          void* const priv) {
    int* event_count = (int*) priv;
    amxc_var_t* event = NULL;
    printf("Event recieved = %s\n", sig_name);
    fflush(stdout);
    amxc_var_dump(data, STDOUT_FILENO);

    check_expected(sig_name);

    event = amxc_var_add_new(&events);
    amxc_var_copy(event, data);

    (*event_count)++;
}

static void handle_events(void) {
    printf("Handling events \n");
    while(amxb_read(bus_ctx) > 0) {
        printf("R");
    }
    while(amxp_signal_read() == 0) {
        printf(".");
    }
    sleep(1);
    while(amxb_read(bus_ctx) > 0) {
        printf("R");
    }
    while(amxp_signal_read() == 0) {
        printf(".");
    }
    printf("\n");
    fflush(stdout);
}

static void reset_events() {
    amxc_var_clean(&events);
    amxc_var_set_type(&events, AMXC_VAR_ID_LIST);
}

static bool test_verify_data(const amxc_var_t* data, const char* field, const char* value) {
    bool rv = false;
    char* field_value = NULL;
    amxc_var_t* field_data = GETP_ARG(data, field);

    printf("Verify event data: check field [%s] contains [%s]\n", field, value);
    fflush(stdout);
    assert_non_null(field_data);

    field_value = amxc_var_dyncast(cstring_t, field_data);
    assert_non_null(field_data);

    rv = (strcmp(field_value, value) == 0);

    free(field_value);
    return rv;
}

static void test_generic_setup() {
    amxc_string_t txt;
    amxc_string_init(&txt, 0);
    amxc_var_init(&events);
    amxc_var_set_type(&events, AMXC_VAR_ID_LIST);

    amxc_string_setf(&txt, "pcb_sysbus -n test_bus -I /tmp/test.sock");
    system(amxc_string_get(&txt, 0));
    sleep(1);

    amxc_string_clean(&txt);
}

static void test_generic_teardown() {
    amxc_string_t txt;
    amxc_string_init(&txt, 0);

    amxc_string_setf(&txt, "killall test_bus");
    system(amxc_string_get(&txt, 0));
    amxc_var_clean(&events);
    amxc_string_clean(&txt);
}

int test_pcb_setup(UNUSED void** state) {
    amxc_string_t txt;

    test_generic_setup();

    amxc_string_init(&txt, 0);
    amxc_string_setf(&txt, "pcb_app -u pcb://ipc:[/tmp/test.sock] -n nemo_test -c ../test_data/test_nemo_pcb.odl");
    system(amxc_string_get(&txt, 0));
    amxc_string_setf(&txt, "pcb_app -u pcb://ipc:[/tmp/test.sock] -n greeter_test -c ../pcb_greeter/greeter.odl");
    system(amxc_string_get(&txt, 0));

    amxc_string_clean(&txt);

    assert_int_equal(amxb_be_load("../mod-amxb-test-pcb.so"), 0);
    assert_int_equal(amxb_connect(&bus_ctx, "pcb:/tmp/test.sock"), 0);

    sleep(1);

    return 0;
}

int test_pcb_teardown(UNUSED void** state) {
    amxb_disconnect(bus_ctx);
    amxb_free(&bus_ctx);

    system("killall nemo_test");
    system("killall greeter_test");

    amxb_be_remove_all();

    test_generic_teardown();
    return 0;
}

int test_amx_setup(UNUSED void** state) {
    amxc_string_t txt;

    test_generic_setup();

    amxc_string_init(&txt, 0);

    setenv("PCB_SERIALIZERS", "libpcb_serialize_ddw.so:libpcb_serialize_odl.so", 1);
    amxc_string_setf(&txt, "pcb_app -u pcb://ipc:[/tmp/test.sock] -n greeter_test -c ../pcb_greeter/greeter.odl");
    system(amxc_string_get(&txt, 0));

    unlink("test_config.odl");
    int fd = open("test_config.odl", O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IRGRP | S_IROTH);
    assert_int_not_equal(fd, -1);
    amxc_string_reset(&txt);
    amxc_string_setf(&txt, "%%config { %%global backends = ['../mod-amxb-test-pcb.so']; %%global uris = [ 'pcb:/tmp/test.sock' ]; }\n");
    write(fd, amxc_string_get(&txt, 0), amxc_string_text_length(&txt));
    close(fd);

    amxc_string_reset(&txt);
    amxc_string_setf(&txt, "amxrt -A -D test_config.odl ../test_data/test_nemo.odl");
    system(amxc_string_get(&txt, 0));

    sleep(1);

    amxc_string_clean(&txt);

    assert_int_equal(amxb_be_load("../mod-amxb-test-pcb.so"), 0);
    assert_int_equal(amxb_connect(&bus_ctx, "pcb:/tmp/test.sock"), 0);

    sleep(1);

    return 0;
}

int test_amx_teardown(UNUSED void** state) {
    amxb_disconnect(bus_ctx);
    amxb_free(&bus_ctx);

    system("killall amxrt");
    system("killall greeter_test");

    amxb_be_remove_all();
    unlink("test_config.odl");
    test_generic_teardown();

    return 0;
}

void test_pcb_subscribe_index_path(UNUSED void** state) {
    const char* path = "NeMo.Intf.1.Query.100.";
    int event_count = 0;
    amxc_string_t txt;
    amxc_var_t* event = NULL;
    amxc_string_init(&txt, 128);

    handle_events();

    assert_int_equal(amxb_subscribe(bus_ctx, path, NULL, event_handler, &event_count), 0);

    amxc_string_setf(&txt, "pcb_cli -i pcb://ipc:[/tmp/test.sock] NeMo.Intf.1.Query.100.ResultString=\"test\"");
    system(amxc_string_get(&txt, 0));
    expect_string(event_handler, sig_name, "NeMo.Intf.1.Query.100");
    handle_events();

    assert_int_equal(event_count, 1);
    event = GETI_ARG(&events, 0);
    assert_true(test_verify_data(event, "notification", "dm:object-changed"));
    assert_true(test_verify_data(event, "object", "NeMo.Intf.lan.Query.100."));
    assert_true(test_verify_data(event, "path", "NeMo.Intf.1.Query.100."));
    assert_true(test_verify_data(event, "parameters.ResultString.from", "ok"));
    assert_true(test_verify_data(event, "parameters.ResultString.to", "test"));
    event_count = 0;
    reset_events();

    amxc_string_setf(&txt, "pcb_cli pcb://ipc:[/tmp/test.sock] NeMo.Intf.lan.Query.100.ResultString=\"ok\"");
    system(amxc_string_get(&txt, 0));
    expect_string(event_handler, sig_name, "NeMo.Intf.1.Query.100");
    handle_events();
    assert_int_equal(event_count, 1);
    event = GETI_ARG(&events, 0);
    assert_true(test_verify_data(event, "notification", "dm:object-changed"));
    assert_true(test_verify_data(event, "object", "NeMo.Intf.lan.Query.100."));
    assert_true(test_verify_data(event, "path", "NeMo.Intf.1.Query.100."));
    assert_true(test_verify_data(event, "parameters.ResultString.from", "test"));
    assert_true(test_verify_data(event, "parameters.ResultString.to", "ok"));
    event_count = 0;
    reset_events();

    assert_int_equal(amxb_unsubscribe(bus_ctx, path, event_handler, &event_count), 0);
    amxc_string_setf(&txt, "pcb_cli -i pcb://ipc:[/tmp/test.sock] NeMo.Intf.1.Query.100.ResultString=\"123\"");
    system(amxc_string_get(&txt, 0));
    handle_events();
    assert_int_equal(event_count, 0);

    amxc_string_setf(&txt, "pcb_cli pcb://ipc:[/tmp/test.sock] NeMo.Intf.lan.Query.100.ResultString=\"ok\"");
    system(amxc_string_get(&txt, 0));
    handle_events();
    assert_int_equal(event_count, 0);

    amxc_string_clean(&txt);
}

void test_pcb_subscribe_key_path(UNUSED void** state) {
    const char* path = "NeMo.Intf.lan.Query.100.";
    int event_count = 0;
    amxc_string_t txt;
    amxc_var_t* event = NULL;
    amxc_string_init(&txt, 128);

    handle_events();

    assert_int_equal(amxb_subscribe(bus_ctx, path, NULL, event_handler, &event_count), 0);

    amxc_string_setf(&txt, "pcb_cli -i pcb://ipc:[/tmp/test.sock] NeMo.Intf.1.Query.100.ResultString=\"test\"");
    system(amxc_string_get(&txt, 0));
    expect_string(event_handler, sig_name, "NeMo.Intf.1.Query.100");
    handle_events();
    assert_int_equal(event_count, 1);
    event = GETI_ARG(&events, 0);
    assert_true(test_verify_data(event, "notification", "dm:object-changed"));
    assert_true(test_verify_data(event, "object", "NeMo.Intf.lan.Query.100."));
    assert_true(test_verify_data(event, "path", "NeMo.Intf.1.Query.100."));
    assert_true(test_verify_data(event, "parameters.ResultString.from", "ok"));
    assert_true(test_verify_data(event, "parameters.ResultString.to", "test"));
    event_count = 0;
    reset_events();

    amxc_string_setf(&txt, "pcb_cli pcb://ipc:[/tmp/test.sock] NeMo.Intf.lan.Query.100.ResultString=\"ok\"");
    system(amxc_string_get(&txt, 0));
    expect_string(event_handler, sig_name, "NeMo.Intf.1.Query.100");
    handle_events();
    assert_int_equal(event_count, 1);
    event = GETI_ARG(&events, 0);
    assert_true(test_verify_data(event, "notification", "dm:object-changed"));
    assert_true(test_verify_data(event, "object", "NeMo.Intf.lan.Query.100."));
    assert_true(test_verify_data(event, "path", "NeMo.Intf.1.Query.100."));
    assert_true(test_verify_data(event, "parameters.ResultString.from", "test"));
    assert_true(test_verify_data(event, "parameters.ResultString.to", "ok"));
    event_count = 0;
    reset_events();

    assert_int_equal(amxb_unsubscribe(bus_ctx, path, event_handler, &event_count), 0);
    amxc_string_setf(&txt, "pcb_cli -i pcb://ipc:[/tmp/test.sock] NeMo.Intf.1.Query.100.ResultString=\"123\"");
    system(amxc_string_get(&txt, 0));
    handle_events();
    assert_int_equal(event_count, 0);

    amxc_string_setf(&txt, "pcb_cli pcb://ipc:[/tmp/test.sock] NeMo.Intf.lan.Query.100.ResultString=\"ok\"");
    system(amxc_string_get(&txt, 0));
    handle_events();
    assert_int_equal(event_count, 0);

    amxc_string_clean(&txt);
}

void test_pcb_add_notification(UNUSED void** state) {
    const char* path = "NeMo.Intf.";
    int event_count = 0;
    amxc_string_t txt;
    amxc_var_t* event = NULL;
    amxc_string_init(&txt, 128);

    handle_events();

    assert_int_equal(amxb_subscribe(bus_ctx, path, NULL, event_handler, &event_count), 0);

    amxc_string_setf(&txt, "pcb_cli -i pcb://ipc:[/tmp/test.sock] NeMo.Intf+");
    system(amxc_string_get(&txt, 0));
    expect_string_count(event_handler, sig_name, "NeMo.Intf", 5);
    handle_events();
    assert_int_equal(event_count, 5);
    event = GETI_ARG(&events, 0);
    assert_true(test_verify_data(event, "notification", "dm:instance-added"));
    assert_true(test_verify_data(event, "object", "NeMo.Intf."));
    assert_true(test_verify_data(event, "path", "NeMo.Intf."));
    assert_true(test_verify_data(event, "index", "5"));
    assert_true(test_verify_data(event, "name", "5"));
    assert_true(test_verify_data(event, "parameters.Enable", "false"));
    assert_true(test_verify_data(event, "parameters.Flags", "colors"));
    assert_true(test_verify_data(event, "parameters.Name", ""));
    assert_true(test_verify_data(event, "parameters.Status", "false"));
    event = GETI_ARG(&events, 1);
    assert_true(test_verify_data(event, "notification", "dm:object-added"));
    assert_true(test_verify_data(event, "object", "NeMo.Intf.5.ULIntf."));
    assert_true(test_verify_data(event, "path", "NeMo.Intf.5.ULIntf."));
    event = GETI_ARG(&events, 2);
    assert_true(test_verify_data(event, "notification", "dm:object-added"));
    assert_true(test_verify_data(event, "object", "NeMo.Intf.5.LLIntf."));
    assert_true(test_verify_data(event, "path", "NeMo.Intf.5.LLIntf."));
    event = GETI_ARG(&events, 3);
    assert_true(test_verify_data(event, "notification", "dm:object-added"));
    assert_true(test_verify_data(event, "object", "NeMo.Intf.5.Query."));
    assert_true(test_verify_data(event, "path", "NeMo.Intf.5.Query."));
    event = GETI_ARG(&events, 4);
    assert_true(test_verify_data(event, "notification", "dm:object-added"));
    assert_true(test_verify_data(event, "object", "NeMo.Intf.5.Query.TestObject."));
    assert_true(test_verify_data(event, "path", "NeMo.Intf.5.Query.TestObject."));
    event_count = 0;
    reset_events();

    amxc_string_setf(&txt, "pcb_cli pcb://ipc:[/tmp/test.sock] \"NeMo.Intf+{key:TEST, Name:HALLO}\"");
    system(amxc_string_get(&txt, 0));
    expect_string_count(event_handler, sig_name, "NeMo.Intf", 5);
    handle_events();
    assert_int_equal(event_count, 5);
    event = GETI_ARG(&events, 0);
    assert_true(test_verify_data(event, "notification", "dm:instance-added"));
    assert_true(test_verify_data(event, "object", "NeMo.Intf."));
    assert_true(test_verify_data(event, "path", "NeMo.Intf."));
    assert_true(test_verify_data(event, "index", "6"));
    assert_true(test_verify_data(event, "name", "TEST"));
    assert_true(test_verify_data(event, "parameters.Enable", "false"));
    assert_true(test_verify_data(event, "parameters.Flags", "colors"));
    assert_true(test_verify_data(event, "parameters.Name", "HALLO"));
    assert_true(test_verify_data(event, "parameters.Status", "false"));
    event = GETI_ARG(&events, 1);
    assert_true(test_verify_data(event, "notification", "dm:object-added"));
    assert_true(test_verify_data(event, "object", "NeMo.Intf.TEST.ULIntf."));
    assert_true(test_verify_data(event, "path", "NeMo.Intf.6.ULIntf."));
    event = GETI_ARG(&events, 2);
    assert_true(test_verify_data(event, "notification", "dm:object-added"));
    assert_true(test_verify_data(event, "object", "NeMo.Intf.TEST.LLIntf."));
    assert_true(test_verify_data(event, "path", "NeMo.Intf.6.LLIntf."));
    event = GETI_ARG(&events, 3);
    assert_true(test_verify_data(event, "notification", "dm:object-added"));
    assert_true(test_verify_data(event, "object", "NeMo.Intf.TEST.Query."));
    assert_true(test_verify_data(event, "path", "NeMo.Intf.6.Query."));
    event = GETI_ARG(&events, 4);
    assert_true(test_verify_data(event, "notification", "dm:object-added"));
    assert_true(test_verify_data(event, "object", "NeMo.Intf.TEST.Query.TestObject."));
    assert_true(test_verify_data(event, "path", "NeMo.Intf.6.Query.TestObject."));
    event_count = 0;
    reset_events();

    amxc_string_setf(&txt, "pcb_cli -i pcb://ipc:[/tmp/test.sock] NeMo.Intf.6.Query+");
    system(amxc_string_get(&txt, 0));
    expect_string_count(event_handler, sig_name, "NeMo.Intf", 2);
    handle_events();
    assert_int_equal(event_count, 2);
    event = GETI_ARG(&events, 0);
    assert_true(test_verify_data(event, "notification", "dm:instance-added"));
    assert_true(test_verify_data(event, "object", "NeMo.Intf.TEST.Query."));
    assert_true(test_verify_data(event, "path", "NeMo.Intf.6.Query."));
    assert_true(test_verify_data(event, "index", "1"));
    assert_true(test_verify_data(event, "name", "1"));
    assert_true(test_verify_data(event, "parameters.Description", ""));
    assert_true(test_verify_data(event, "parameters.Subscribers", ""));
    assert_true(test_verify_data(event, "parameters.ResultString", ""));
    event = GETI_ARG(&events, 1);
    assert_true(test_verify_data(event, "notification", "dm:object-added"));
    assert_true(test_verify_data(event, "object", "NeMo.Intf.TEST.Query.1.TestObject."));
    assert_true(test_verify_data(event, "path", "NeMo.Intf.6.Query.1.TestObject."));
    event_count = 0;
    reset_events();

    amxc_string_setf(&txt, "pcb_cli pcb://ipc:[/tmp/test.sock] NeMo.Intf.TEST.Query+");
    system(amxc_string_get(&txt, 0));
    expect_string_count(event_handler, sig_name, "NeMo.Intf", 2);
    handle_events();
    assert_int_equal(event_count, 2);
    event = GETI_ARG(&events, 0);
    assert_true(test_verify_data(event, "notification", "dm:instance-added"));
    assert_true(test_verify_data(event, "object", "NeMo.Intf.TEST.Query."));
    assert_true(test_verify_data(event, "path", "NeMo.Intf.6.Query."));
    assert_true(test_verify_data(event, "index", "2"));
    assert_true(test_verify_data(event, "name", "2"));
    assert_true(test_verify_data(event, "parameters.Description", ""));
    assert_true(test_verify_data(event, "parameters.Subscribers", ""));
    assert_true(test_verify_data(event, "parameters.ResultString", ""));
    event = GETI_ARG(&events, 1);
    assert_true(test_verify_data(event, "notification", "dm:object-added"));
    assert_true(test_verify_data(event, "object", "NeMo.Intf.TEST.Query.2.TestObject."));
    assert_true(test_verify_data(event, "path", "NeMo.Intf.6.Query.2.TestObject."));
    event_count = 0;
    reset_events();

    assert_int_equal(amxb_unsubscribe(bus_ctx, path, event_handler, &event_count), 0);

    amxc_string_clean(&txt);
}

void test_pcb_del_notification(UNUSED void** state) {
    const char* path = "NeMo.Intf.";
    int event_count = 0;
    amxc_string_t txt;
    amxc_var_t* event = NULL;
    amxc_string_init(&txt, 128);

    handle_events();

    assert_int_equal(amxb_subscribe(bus_ctx, path, NULL, event_handler, &event_count), 0);

    amxc_string_setf(&txt, "pcb_cli -i pcb://ipc:[/tmp/test.sock] NeMo.Intf.5-");
    system(amxc_string_get(&txt, 0));
    expect_string_count(event_handler, sig_name, "NeMo.Intf", 5);
    handle_events();
    assert_int_equal(event_count, 5);
    event = GETI_ARG(&events, 0);
    assert_true(test_verify_data(event, "notification", "dm:object-removed"));
    assert_true(test_verify_data(event, "path", "NeMo.Intf.5.ULIntf."));
    event = GETI_ARG(&events, 1);
    assert_true(test_verify_data(event, "notification", "dm:object-removed"));
    assert_true(test_verify_data(event, "path", "NeMo.Intf.5.LLIntf."));
    event = GETI_ARG(&events, 2);
    assert_true(test_verify_data(event, "notification", "dm:object-removed"));
    assert_true(test_verify_data(event, "path", "NeMo.Intf.5.Query.TestObject."));
    event = GETI_ARG(&events, 3);
    assert_true(test_verify_data(event, "notification", "dm:object-removed"));
    assert_true(test_verify_data(event, "path", "NeMo.Intf.5.Query."));
    event = GETI_ARG(&events, 4);
    assert_true(test_verify_data(event, "notification", "dm:instance-removed"));
    assert_true(test_verify_data(event, "path", "NeMo.Intf."));
    assert_true(test_verify_data(event, "index", "5"));
    event_count = 0;
    reset_events();

    amxc_string_setf(&txt, "pcb_cli pcb://ipc:[/tmp/test.sock] NeMo.Intf.TEST-");
    system(amxc_string_get(&txt, 0));
    expect_string_count(event_handler, sig_name, "NeMo.Intf", 9);
    handle_events();
    assert_int_equal(event_count, 9);
    event = GETI_ARG(&events, 0);
    assert_true(test_verify_data(event, "notification", "dm:object-removed"));
    assert_true(test_verify_data(event, "path", "NeMo.Intf.6.ULIntf."));
    event = GETI_ARG(&events, 1);
    assert_true(test_verify_data(event, "notification", "dm:object-removed"));
    assert_true(test_verify_data(event, "path", "NeMo.Intf.6.LLIntf."));
    event = GETI_ARG(&events, 2);
    assert_true(test_verify_data(event, "notification", "dm:object-removed"));
    assert_true(test_verify_data(event, "path", "NeMo.Intf.6.Query.TestObject."));
    event = GETI_ARG(&events, 3);
    assert_true(test_verify_data(event, "notification", "dm:object-removed"));
    assert_true(test_verify_data(event, "path", "NeMo.Intf.6.Query.1.TestObject."));
    event = GETI_ARG(&events, 4);
    assert_true(test_verify_data(event, "notification", "dm:instance-removed"));
    assert_true(test_verify_data(event, "path", "NeMo.Intf.6.Query."));
    assert_true(test_verify_data(event, "index", "1"));
    event = GETI_ARG(&events, 5);
    assert_true(test_verify_data(event, "notification", "dm:object-removed"));
    assert_true(test_verify_data(event, "path", "NeMo.Intf.6.Query.2.TestObject."));
    event = GETI_ARG(&events, 6);
    assert_true(test_verify_data(event, "notification", "dm:instance-removed"));
    assert_true(test_verify_data(event, "path", "NeMo.Intf.6.Query."));
    assert_true(test_verify_data(event, "index", "2"));
    event = GETI_ARG(&events, 7);
    assert_true(test_verify_data(event, "notification", "dm:object-removed"));
    assert_true(test_verify_data(event, "path", "NeMo.Intf.6.Query."));
    event = GETI_ARG(&events, 8);
    assert_true(test_verify_data(event, "notification", "dm:instance-removed"));
    assert_true(test_verify_data(event, "path", "NeMo.Intf."));
    assert_true(test_verify_data(event, "index", "6"));
    event_count = 0;
    reset_events();

    assert_int_equal(amxb_unsubscribe(bus_ctx, path, event_handler, &event_count), 0);

    amxc_string_clean(&txt);
}

void test_pcb_disconnect(UNUSED void** state) {
    const char* path = "NeMo.Intf.";
    int event_count = 0;
    amxc_string_t txt;
    amxc_string_init(&txt, 128);

    handle_events();

    assert_int_equal(amxb_subscribe(bus_ctx, path, NULL, event_handler, &event_count), 0);

    assert_int_equal(amxb_disconnect(bus_ctx), 0);
    amxb_free(&bus_ctx);
    assert_int_equal(amxb_connect(&bus_ctx, "pcb:/tmp/test.sock"), 0);

    amxc_string_setf(&txt, "pcb_cli -i pcb://ipc:[/tmp/test.sock] NeMo.Intf+");
    system(amxc_string_get(&txt, 0));
    handle_events();

    amxc_string_clean(&txt);
}

void test_pcb_custom_notification(UNUSED void** state) {
    const char* path = "Greeter.History.1.";
    int event_count = 0;
    amxc_string_t txt;
    amxc_var_t* event = NULL;
    amxc_string_init(&txt, 128);

    handle_events();

    expect_string_count(event_handler, sig_name, "Greeter.History.1", 2);

    assert_int_equal(amxb_subscribe(bus_ctx, path, NULL, event_handler, &event_count), 0);

    amxc_string_setf(&txt, "pcb_cli -i pcb://ipc:[/tmp/test.sock] 'Greeter.History.1.sendNotification()'");
    system(amxc_string_get(&txt, 0));
    handle_events();
    assert_int_equal(event_count, 1);
    event = GETI_ARG(&events, 0);
    assert_true(test_verify_data(event, "notification", "greeter:test"));
    assert_true(test_verify_data(event, "TestData", "Hallo"));
    assert_true(test_verify_data(event, "path", "Greeter.History.1."));
    assert_true(test_verify_data(event, "object", "Greeter.History.Welcome."));
    event_count = 0;
    reset_events();

    amxc_string_setf(&txt, "pcb_cli pcb://ipc:[/tmp/test.sock] 'Greeter.History.Welcome.sendNotification()'");
    system(amxc_string_get(&txt, 0));
    handle_events();
    sleep(1);
    handle_events();
    assert_int_equal(event_count, 1);
    event = GETI_ARG(&events, 0);
    assert_true(test_verify_data(event, "notification", "greeter:test"));
    assert_true(test_verify_data(event, "TestData", "Hallo"));
    assert_true(test_verify_data(event, "path", "Greeter.History.1."));
    assert_true(test_verify_data(event, "object", "Greeter.History.Welcome."));
    event_count = 0;
    reset_events();

    assert_int_equal(amxb_unsubscribe(bus_ctx, path, event_handler, &event_count), 0);

    amxc_string_clean(&txt);
}

void test_pcb_notification_unsubscribe_while_waiting_for_event(UNUSED void** state) {
    const char* path = "Greeter.History.1.";
    int event_count = 0;
    amxc_string_t txt;
    amxc_string_init(&txt, 128);

    handle_events();

    assert_int_equal(amxb_subscribe(bus_ctx, path, NULL, event_handler, &event_count), 0);
    amxc_string_setf(&txt, "pcb_cli pcb://ipc:[/tmp/test.sock] 'Greeter.History.Welcome.sendNotification()'");
    system(amxc_string_get(&txt, 0));
    assert_int_equal(amxb_unsubscribe(bus_ctx, path, event_handler, &event_count), 0);
    handle_events();
    assert_int_equal(event_count, 0);

    amxc_string_clean(&txt);
}

/*
   Scenario:
   - Subscribe to native pcb data model
   - Update a parameter in the data model from this process using a set
   - While waiting for the set response, the notification associated with the subscription arrives
   - This notification is pushed on a queue to be handled later, after the set response
   - The set response arrives and is handled
   - The notification(s) on the queue were no longer handled
   - This test checks that they are handled
 */
void test_pcb_subscribe_and_set_sends_event(UNUSED void** state) {
    const char* path = "NeMo.Intf.1.";
    int event_count = 0;
    bool enable = false;
    amxc_var_t values;
    amxc_var_t ret;

    amxc_var_init(&values);
    amxc_var_init(&ret);

    assert_int_equal(amxb_subscribe(bus_ctx, path, NULL, event_handler, &event_count), 0);
    handle_events();

    // Get current value of Enable
    assert_int_equal(amxb_get(bus_ctx, path, 0, &ret, 5), 0);
    amxc_var_dump(&ret, STDOUT_FILENO);
    enable = GETP_BOOL(&ret, "0.0.Enable");

    // Toggle Enable
    amxc_var_set_type(&values, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(bool, &values, "Enable", !enable);
    assert_int_equal(amxb_set(bus_ctx, path, &values, &ret, 5), 0);
    amxc_var_dump(&ret, STDOUT_FILENO);

    /*
       Notification should arrive.

       Don't call handle_events, because this will call amxb_read, which
       doesn't reflect the real behavior.

       The notification data has already been read from the file descriptor
       and is stored somewhere on an internal queue. The data should be
       processed by calling peer_needRead followed by peer_handleRead
       which is done by the deferred amxb_pcb_empty_queue function.
       Reading the signal file descriptor will call this deferred function.

       When handle_events is called, amxb_read will be called which will also
       call the peer_needRead and peer_handleRead, but in reality this won't
       happen (there is nothing to read), so this doesn't reflect the real
       behavior.
     */
    expect_string(event_handler, sig_name, "NeMo.Intf.1");
    while(amxp_signal_read() == 0) {
        printf(".");
    }

    assert_int_equal(amxb_unsubscribe(bus_ctx, path, event_handler, &event_count), 0);
    handle_events();

    amxc_var_clean(&values);
    amxc_var_clean(&ret);
}
