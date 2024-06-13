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
#include <stdlib.h>
#include <stdio.h>
#include <setjmp.h>
#include <stdarg.h>
#include <cmocka.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <event2/event.h>

#include "tty_mock.h"
#include "test_cli_eloop.h"

int test_cli_el_setup(UNUSED void** state) {
    cli_app_t* amx_cli = amx_cli_get_data();
    amxt_tty_open(&amx_cli->tty, -1);

    amxc_var_init(&amx_cli->aliases);
    amxc_var_set_type(&amx_cli->aliases, AMXC_VAR_ID_HTABLE);

    amx_cli->shared_object = NULL;
    amx_cli->module = NULL;

    amxp_sigmngr_add_signal(amx_cli->tty->sigmngr, "tty:docomplete");
    amxp_slot_connect(amx_cli->tty->sigmngr, "tty:docomplete", NULL, test_complete_cb, NULL);

    return 0;
}

int test_cli_el_teardown(UNUSED void** state) {
    cli_app_t* amx_cli = amx_cli_get_data();

    amxm_close_all();
    if(amx_cli->tty) {
        amx_cli->tty->priv = NULL;
    }
    amxc_var_clean(&amx_cli->aliases);
    amxt_tty_hide_prompt(amx_cli->tty);
    amxt_tty_close(&amx_cli->tty);
    free(amx_cli->shared_object);
    free(amx_cli->module);

    return 0;
}

static void test_stop_eventloop(UNUSED amxp_timer_t* timer, void* priv) {
    int* counter = (int*) priv;
    amxt_tty_t* tty = amx_cli_get_tty();

    assert_int_equal(amx_cli_el_stop(tty), 0);
    (*counter)++;
}

static void test_amxp_signal(UNUSED const char* const sig_name,
                             UNUSED const amxc_var_t* const data,
                             void* const priv) {
    int* counter = (int*) priv;
    amxt_tty_t* tty = amx_cli_get_tty();

    assert_int_equal(amx_cli_el_stop(tty), 0);
    printf("AMXP-TEST-SIGNAL OK\n");
    fflush(stdout);
    (*counter)++;
}

void test_eventloop_is_working(UNUSED void** state) {
    amxp_timer_t* timer = NULL;
    int counter = 0;
    amxt_tty_t* tty = amx_cli_get_tty();

    amxp_sigmngr_add_signal(NULL, "AMXP-TEST-SIGNAL");
    amxp_slot_connect(NULL, "AMXP-TEST-SIGNAL", NULL, test_amxp_signal, &counter);
    amxp_sigmngr_emit_signal(NULL, "AMXP-TEST-SIGNAL", NULL);

    amxp_timer_new(&timer, test_stop_eventloop, &counter);
    amxp_timer_start(timer, 1000);

    printf("Create eventloop\n");
    fflush(stdout);
    assert_int_equal(amx_cli_el_create(tty), 0);
    amx_cli_add_sig_handlers(tty);

    printf("Start eventloop\n");
    fflush(stdout);
    assert_int_equal(amx_cli_el_start(tty), 0);
    printf("eventloop stopped - because of AMXP-TEST-SIGNAL\n");
    fflush(stdout);
    assert_int_equal(counter, 1);
    printf("Start eventloop\n");
    fflush(stdout);
    assert_int_equal(amx_cli_el_start(tty), 0);
    printf("eventloop stopped - because of timer\n");
    fflush(stdout);
    assert_int_equal(counter, 2);

    amxp_timer_delete(&timer);
    amx_cli_el_delete(tty);
}

static void test_reader(int fd, UNUSED void* priv) {
    char buf[10];
    amxt_tty_t* tty = amx_cli_get_tty();

    printf("Read from file descriptor (%d)\n", fd);
    fflush(stdout);

    read(fd, buf, 10);

    amx_cli_el_stop(tty);
    return;
}

static void test_add_fd(UNUSED amxp_timer_t* timer, void* priv) {
    int* fd = (int*) priv;

    printf("Adding file descriptor (%d) to eventloop\n", *fd);
    fflush(stdout);

    amxp_connection_add(*fd, test_reader, "test://127.0.0.1:5001", AMXP_CONNECTION_CUSTOM, NULL);
}

static void test_write_fd(UNUSED amxp_timer_t* timer, void* priv) {
    int* fd = (int*) priv;

    printf("Write byte to file descriptor (%d)\n", *fd);
    fflush(stdout);

    write(*fd, "A", 1);
}

static amxp_connection_t* test_get_connection(amxc_llist_t* cons, int fd) {
    amxp_connection_t* con = NULL;
    amxc_llist_for_each(it, cons) {
        con = amxc_llist_it_get_data(it, amxp_connection_t, it);
        if(con->fd == fd) {
            break;
        }
        con = NULL;
    }

    return con;
}

void test_can_add_fds(UNUSED void** state) {
    amxp_timer_t* timer = NULL;
    amxp_timer_t* timer_write = NULL;
    int data_pipe[2];
    amxt_tty_t* tty = amx_cli_get_tty();

    int retval = pipe(data_pipe);
    assert_int_equal(retval, 0);

    amxp_sigmngr_add_signal(NULL, "connection-added");
    amxp_sigmngr_add_signal(NULL, "connection-deleted");

    amxp_timer_new(&timer, test_add_fd, data_pipe);
    amxp_timer_start(timer, 1000);

    amxp_timer_new(&timer_write, test_write_fd, data_pipe + 1);
    amxp_timer_set_interval(timer_write, 2000);
    amxp_timer_start(timer_write, 1000);

    assert_int_equal(amx_cli_el_create(tty), 0);
    amx_cli_add_sig_handlers(tty);
    assert_int_equal(amx_cli_el_start(tty), 0);

    assert_non_null(test_get_connection(amxp_connection_get_connections(), data_pipe[0]));
    assert_null(test_get_connection(amxp_connection_get_connections(), data_pipe[1]));

    amxp_connection_remove(data_pipe[0]);

    assert_int_equal(amx_cli_el_delete(tty), 0);

    amxp_timer_delete(&timer);
    amxp_timer_delete(&timer_write);

    close(data_pipe[0]);
    close(data_pipe[1]);
}
