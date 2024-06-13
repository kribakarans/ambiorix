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
#include <sys/time.h>
#include <sys/resource.h>

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <inttypes.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <cmocka.h>

#include <amxc/amxc_macros.h>
#include <amxc/amxc.h>
#include <amxp/amxp_signal.h>
#include <amxp/amxp_slot.h>
#include <amxp/amxp_connection.h>

#include "test_connection.h"

static int fds[2];
static char* el_data = "Some Data";

static void reader(UNUSED int fd, UNUSED void* priv) {

}

static void writer(UNUSED int fd, UNUSED void* priv) {

}

static void connection_check_signal(const char* const sig_name,
                                    const amxc_var_t* const data,
                                    UNUSED void* const priv) {
    uint32_t data_type = amxc_var_type_of(data);
    uint32_t data_value = GET_UINT32(data, NULL);

    check_expected(sig_name);
    check_expected(data_type);
    check_expected(data_value);
}

int test_connection_setup(UNUSED void** state) {
    assert_int_equal(pipe(fds), 0);

    while(amxp_signal_read() == 0) {
    }

    amxp_slot_connect(NULL, "connection-added", NULL, connection_check_signal, NULL);
    amxp_slot_connect(NULL, "connection-deleted", NULL, connection_check_signal, NULL);
    amxp_slot_connect(NULL, "listen-added", NULL, connection_check_signal, NULL);
    amxp_slot_connect(NULL, "listen-deleted", NULL, connection_check_signal, NULL);
    amxp_slot_connect(NULL, "connection-wait-write", NULL, connection_check_signal, NULL);

    return 0;
}

int test_connection_teardown(UNUSED void** state) {
    amxp_slot_disconnect_all(connection_check_signal);
    close(fds[0]);
    close(fds[1]);
    return 0;
}

void test_can_add_connection(UNUSED void** state) {
    expect_string(connection_check_signal, sig_name, "connection-added");
    expect_value(connection_check_signal, data_type, AMXC_VAR_ID_FD);
    expect_value(connection_check_signal, data_value, fds[0]);

    assert_int_equal(amxp_connection_add(fds[0], reader, "test://localhost:1700", AMXP_CONNECTION_CUSTOM, NULL), 0);
    assert_int_equal(amxc_llist_size(amxp_connection_get_connections()), 1);
    assert_int_equal(amxc_llist_size(amxp_connection_get_listeners()), 0);
}

void test_can_fetch_connection(UNUSED void** state) {
    amxp_connection_t* con = amxp_connection_get(fds[0]);

    assert_non_null(con);
    assert_int_equal(con->fd, fds[0]);
    assert_ptr_equal(con->reader, reader);
    assert_string_equal(con->uri, "test://localhost:1700");
    assert_int_equal(con->type, AMXP_CONNECTION_CUSTOM);
}

void test_can_add_wait_write_connection(UNUSED void** state) {
    expect_string(connection_check_signal, sig_name, "connection-wait-write");
    expect_value(connection_check_signal, data_type, AMXC_VAR_ID_FD);
    expect_value(connection_check_signal, data_value, fds[0]);

    assert_int_equal(amxp_connection_wait_write(fds[0], writer), 0);
    assert_int_equal(amxc_llist_size(amxp_connection_get_connections()), 1);
    assert_int_equal(amxc_llist_size(amxp_connection_get_listeners()), 0);
}

void test_can_store_event_loop_data(UNUSED void** state) {
    amxp_connection_t* con = amxp_connection_get(fds[0]);
    assert_int_equal(amxp_connection_set_el_data(fds[0], el_data), 0);
    assert_int_not_equal(amxp_connection_set_el_data(fds[1], el_data), 0);

    assert_ptr_equal(con->el_data, el_data);
}

void test_can_iterate_connections(UNUSED void** state) {
    amxp_connection_t* con = NULL;

    expect_string(connection_check_signal, sig_name, "connection-added");
    expect_value(connection_check_signal, data_type, AMXC_VAR_ID_FD);
    expect_value(connection_check_signal, data_value, fds[1]);

    assert_int_equal(amxp_connection_add(fds[1], reader, "test://localhost:1700", AMXP_CONNECTION_BUS, NULL), 0);
    assert_int_equal(amxc_llist_size(amxp_connection_get_connections()), 2);
    assert_int_equal(amxc_llist_size(amxp_connection_get_listeners()), 0);

    con = amxp_connection_get_first(AMXP_CONNECTION_CUSTOM);
    assert_non_null(con);
    assert_int_equal(con->fd, fds[0]);
    assert_ptr_equal(con->reader, reader);
    assert_string_equal(con->uri, "test://localhost:1700");
    assert_int_equal(con->type, AMXP_CONNECTION_CUSTOM);
    assert_non_null(con);
    con = amxp_connection_get_next(con, AMXP_CONNECTION_CUSTOM);
    assert_null(con);
}

void test_can_remove_connection(UNUSED void** state) {
    expect_string(connection_check_signal, sig_name, "connection-deleted");
    expect_value(connection_check_signal, data_type, AMXC_VAR_ID_FD);
    expect_value(connection_check_signal, data_value, fds[0]);

    assert_int_equal(amxp_connection_remove(fds[0]), 0);
    assert_null(amxp_connection_get(fds[0]));

    assert_int_equal(amxc_llist_size(amxp_connection_get_connections()), 1);
    assert_int_equal(amxc_llist_size(amxp_connection_get_listeners()), 0);

    expect_string(connection_check_signal, sig_name, "connection-deleted");
    expect_value(connection_check_signal, data_type, AMXC_VAR_ID_FD);
    expect_value(connection_check_signal, data_value, fds[1]);

    assert_int_equal(amxp_connection_remove(fds[1]), 0);
    assert_null(amxp_connection_get(fds[1]));

    assert_int_equal(amxc_llist_size(amxp_connection_get_connections()), 0);
    assert_int_equal(amxc_llist_size(amxp_connection_get_listeners()), 0);
}

void test_can_add_listener(UNUSED void** state) {
    expect_string(connection_check_signal, sig_name, "listen-added");
    expect_value(connection_check_signal, data_type, AMXC_VAR_ID_FD);
    expect_value(connection_check_signal, data_value, fds[0]);

    assert_int_equal(amxp_connection_add(fds[0], reader, "test://localhost:1700", AMXP_CONNECTION_LISTEN, NULL), 0);
    assert_int_equal(amxc_llist_size(amxp_connection_get_connections()), 0);
    assert_int_equal(amxc_llist_size(amxp_connection_get_listeners()), 1);
}

void test_can_fetch_listener(UNUSED void** state) {
    amxp_connection_t* con = amxp_connection_get(fds[0]);

    assert_non_null(con);
    assert_int_equal(con->fd, fds[0]);
    assert_ptr_equal(con->reader, reader);
    assert_string_equal(con->uri, "test://localhost:1700");
    assert_int_equal(con->type, AMXP_CONNECTION_LISTEN);
}

void test_can_remove_listener(UNUSED void** state) {
    expect_string(connection_check_signal, sig_name, "listen-deleted");
    expect_value(connection_check_signal, data_type, AMXC_VAR_ID_FD);
    expect_value(connection_check_signal, data_value, fds[0]);

    assert_int_equal(amxp_connection_remove(fds[0]), 0);
    assert_null(amxp_connection_get(fds[0]));

    assert_int_equal(amxc_llist_size(amxp_connection_get_connections()), 0);
    assert_int_equal(amxc_llist_size(amxp_connection_get_listeners()), 0);
}
