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

#include "test_amxrt_eloop.h"
#include "amxrt_priv.h"

typedef struct _event_cb_fns {
    event_callback_fn fn;
    amxc_llist_it_t it;
} event_cb_fns_t;

static amxc_llist_t functions;

struct event_base* __wrap_event_base_new(void);
struct event_base* __real_event_base_new(void);
int __wrap_event_base_dispatch(struct event_base* base);
int __real_event_base_dispatch(struct event_base* base);
int __wrap_event_new(struct event_base* base, evutil_socket_t fd, short events, event_callback_fn callback, void* callback_arg);
int __real_event_new(struct event_base* base, evutil_socket_t fd, short events, event_callback_fn callback, void* callback_arg);
int __wrap_event_add(struct event* ev, const struct timeval* timeout);
int __real_event_add(struct event* ev, const struct timeval* timeout);

struct event_base* __wrap_event_base_new(void) {
    int call = (int) mock();
    if(call == 0) {
        return __real_event_base_new();
    }

    return NULL;
}

int __wrap_event_add(struct event* ev, const struct timeval* timeout) {
    int call = (int) mock();
    if(call == 0) {
        return __real_event_add(ev, timeout);
    }
    return 0;
}

int __wrap_event_base_dispatch(struct event_base* base) {
    int call = (int) mock();
    if(call == 0) {
        return __real_event_base_dispatch(base);
    } else if(call > 0) {
        amxc_llist_it_t* it = amxc_llist_get_at(&functions, call - 1);
        if(it != NULL) {
            event_cb_fns_t* fn = amxc_container_of(it, event_cb_fns_t, it);
            fn->fn(0, 0, NULL);
            return 0;
        } else {
            return -1;
        }
    }

    return call;
}

int __wrap_event_new(struct event_base* base, evutil_socket_t fd, short events, event_callback_fn callback, void* callback_arg) {
    int call = (int) mock();

    switch(call) {
    case 0:
        return __real_event_new(base, fd, events, callback, callback_arg);
        break;
    case 1: {
        event_cb_fns_t* fn = calloc(1, sizeof(event_cb_fns_t));
        fn->fn = callback;
        amxc_llist_append(&functions, &fn->it);
    }
    break;
    }
    return 0;
}

static void remove_cb_fns(amxc_llist_it_t* it) {
    event_cb_fns_t* fn = amxc_container_of(it, event_cb_fns_t, it);
    free(fn);
}

int test_amxrt_el_setup(UNUSED void** state) {
    amxc_llist_init(&functions);
    return 0;
}

int test_amxrt_el_teardown(UNUSED void** state) {
    amxd_dm_t* dm = amxrt_get_dm();
    amxc_llist_clean(&functions, remove_cb_fns);

    amxd_dm_clean(dm);
    return 0;
}

static void test_stop_eventloop(UNUSED amxp_timer_t* timer, void* priv) {
    int* counter = (int*) priv;
    assert_int_equal(amxrt_el_stop(), 0);
    (*counter)++;
}

static void test_amxp_signal(UNUSED const char* const sig_name,
                             UNUSED const amxc_var_t* const data,
                             void* const priv) {
    int* counter = (int*) priv;
    assert_int_equal(amxrt_el_stop(), 0);
    printf("AMXP-TEST-SIGNAL OK\n");
    fflush(stdout);
    (*counter)++;
}

void test_eventloop_is_working(UNUSED void** state) {
    amxp_timer_t* timer = NULL;
    int counter = 0;

    will_return_always(__wrap_event_base_new, 0);
    will_return_always(__wrap_event_new, 0);
    will_return_always(__wrap_event_add, 0);
    will_return_always(__wrap_event_base_dispatch, 0);

    amxp_sigmngr_add_signal(NULL, "AMXP-TEST-SIGNAL");
    amxp_slot_connect(NULL, "AMXP-TEST-SIGNAL", NULL, test_amxp_signal, &counter);
    amxp_sigmngr_emit_signal(NULL, "AMXP-TEST-SIGNAL", NULL);

    amxp_timer_new(&timer, test_stop_eventloop, &counter);
    amxp_timer_start(timer, 1000);

    printf("Create eventloop\n");
    fflush(stdout);
    assert_int_equal(amxrt_el_create(), 0);
    printf("Start eventloop\n");
    fflush(stdout);
    assert_int_equal(amxrt_el_start(), 0);
    printf("eventloop stopped - because of AMXP-TEST-SIGNAL\n");
    fflush(stdout);
    assert_int_equal(counter, 1);
    printf("Start eventloop\n");
    fflush(stdout);
    assert_int_equal(amxrt_el_start(), 0);
    printf("eventloop stopped - because of timer\n");
    fflush(stdout);
    assert_int_equal(counter, 2);
    assert_int_equal(amxrt_el_destroy(), 0);

    amxp_timer_delete(&timer);
}

static void test_reader(int fd, UNUSED void* priv) {
    char buf[10];

    printf("Read from file descriptor (%d)\n", fd);
    fflush(stdout);

    memset(buf, 0, 10);
    read(fd, buf, 10);
    printf("Buffer = %s\n", buf);
    fflush(stdout);

    amxrt_el_stop();
    return;
}

static void test_add_fd(UNUSED amxp_timer_t* timer, void* priv) {
    int* fd = (int*) priv;

    printf("Adding file descriptor (%d) to eventloop\n", *fd);
    fflush(stdout);

    amxp_connection_add(*fd, test_reader, "test://127.0.0.1:5001", AMXO_CUSTOM, NULL);
}

static void test_write_fd(UNUSED amxp_timer_t* timer, void* priv) {
    int* fd = (int*) priv;

    printf("Write byte to file descriptor (%d)\n", *fd);
    fflush(stdout);

    write(*fd, "A", 1);
}

void test_can_add_fds(UNUSED void** state) {
    amxp_timer_t* timer = NULL;
    amxp_timer_t* timer_write = NULL;
    int data_pipe[2];
    int retval = pipe(data_pipe);
    assert_int_equal(retval, 0);

    will_return_always(__wrap_event_base_new, 0);
    will_return_always(__wrap_event_new, 0);
    will_return_always(__wrap_event_add, 0);
    will_return_always(__wrap_event_base_dispatch, 0);

    amxp_sigmngr_add_signal(NULL, "connection-added");
    amxp_sigmngr_add_signal(NULL, "connection-deleted");

    amxp_timer_new(&timer, test_add_fd, data_pipe);
    amxp_timer_start(timer, 1000);

    amxp_timer_new(&timer_write, test_write_fd, data_pipe + 1);
    amxp_timer_set_interval(timer_write, 2000);
    amxp_timer_start(timer_write, 1000);

    assert_int_equal(amxrt_el_create(), 0);
    assert_int_equal(amxrt_el_start(), 0);

    assert_non_null(amxrt_el_get_connection(amxp_connection_get_connections(), data_pipe[0]));
    assert_null(amxrt_el_get_connection(amxp_connection_get_connections(), data_pipe[1]));

    assert_int_equal(amxrt_el_destroy(), 0);

    amxp_timer_delete(&timer);
    amxp_timer_delete(&timer_write);

    amxp_connection_remove(data_pipe[0]);
    amxp_connection_remove(data_pipe[1]);

    close(data_pipe[0]);
    close(data_pipe[1]);
}

void test_can_add_fds_before_el_start(UNUSED void** state) {
    amxp_timer_t* timer_write = NULL;
    int data_pipe[2];
    int retval = pipe(data_pipe);
    assert_int_equal(retval, 0);

    will_return_always(__wrap_event_base_new, 0);
    will_return_always(__wrap_event_new, 0);
    will_return_always(__wrap_event_add, 0);
    will_return_always(__wrap_event_base_dispatch, 0);

    amxp_sigmngr_add_signal(NULL, "connection-added");
    amxp_sigmngr_add_signal(NULL, "connection-deleted");

    assert_int_equal(amxrt_el_create(), 0);

    amxp_timer_new(&timer_write, test_write_fd, data_pipe + 1);
    amxp_timer_set_interval(timer_write, 2000);
    amxp_timer_start(timer_write, 1000);

    printf("Adding connection\n");
    amxp_connection_add(data_pipe[0], test_reader, "test://127.0.0.1:5001", AMXO_CUSTOM, NULL);

    assert_int_equal(amxrt_el_start(), 0);

    assert_non_null(amxrt_el_get_connection(amxp_connection_get_connections(), data_pipe[0]));
    assert_null(amxrt_el_get_connection(amxp_connection_get_connections(), data_pipe[1]));

    assert_int_equal(amxrt_el_destroy(), 0);

    amxp_timer_delete(&timer_write);

    amxp_connection_remove(data_pipe[0]);
    amxp_connection_remove(data_pipe[1]);

    close(data_pipe[0]);
    close(data_pipe[1]);
}

static void test_ready_write(int fd, UNUSED void* priv) {
    printf("READY_WRITE: Write byte to file descriptor (%d)\n", fd);
    fflush(stdout);

    write(fd, "BB", 2);
}

static void test_add_wait_for_write(UNUSED amxp_timer_t* timer, void* priv) {
    int* fd = (int*) priv;
    amxp_connection_t* con = amxrt_el_get_connection(amxp_connection_get_connections(), *fd);

    printf("Adding wait for write descriptor (%d) to eventloop\n", *fd);
    fflush(stdout);
    assert_non_null(con->el_data);

    amxp_connection_wait_write(*fd, test_ready_write);
}

void test_can_wait_ready_write(UNUSED void** state) {
    int data_pipe[2];
    int retval = pipe(data_pipe);
    assert_int_equal(retval, 0);
    amxp_timer_t* timer = NULL;

    will_return_always(__wrap_event_base_new, 0);
    will_return_always(__wrap_event_new, 0);
    will_return_always(__wrap_event_add, 0);
    will_return_always(__wrap_event_base_dispatch, 0);

    amxp_sigmngr_add_signal(NULL, "connection-wait-write");

    amxp_connection_add(data_pipe[0], test_reader, "test://127.0.0.1:5001", AMXO_CUSTOM, NULL);
    amxp_connection_add(data_pipe[1], test_reader, "test://127.0.0.1:5001", AMXO_CUSTOM, NULL);

    amxp_timer_new(&timer, test_add_wait_for_write, data_pipe + 1);
    amxp_timer_start(timer, 1000);

    assert_int_equal(amxrt_el_create(), 0);
    assert_int_equal(amxrt_el_start(), 0);

    assert_non_null(amxrt_el_get_connection(amxp_connection_get_connections(), data_pipe[0]));
    assert_non_null(amxrt_el_get_connection(amxp_connection_get_connections(), data_pipe[1]));

    assert_int_equal(amxrt_el_destroy(), 0);

    amxp_connection_remove(data_pipe[0]);
    amxp_connection_remove(data_pipe[1]);

    close(data_pipe[0]);
    close(data_pipe[1]);
}

static void test_remove_fd(UNUSED amxp_timer_t* timer, void* priv) {
    int* fd = (int*) priv;

    printf("Adding file descriptor (%d) to eventloop\n", *fd);
    fflush(stdout);

    amxp_connection_remove(*fd);
    amxrt_el_stop();
}

void test_can_remove_fds(UNUSED void** state) {
    amxp_timer_t* timer = NULL;
    int data_pipe[2];
    int retval = pipe(data_pipe);
    assert_int_equal(retval, 0);

    will_return_always(__wrap_event_base_new, 0);
    will_return_always(__wrap_event_new, 0);
    will_return_always(__wrap_event_add, 0);
    will_return_always(__wrap_event_base_dispatch, 0);

    amxp_sigmngr_add_signal(NULL, "connection-added");
    amxp_sigmngr_add_signal(NULL, "connection-deleted");

    amxp_timer_new(&timer, test_remove_fd, data_pipe);
    amxp_timer_start(timer, 1000);

    amxp_connection_add(data_pipe[0], test_reader, "test://127.0.0.1:5001", AMXO_CUSTOM, NULL);

    assert_int_equal(amxrt_el_create(), 0);
    assert_int_equal(amxrt_el_start(), 0);

    assert_null(amxrt_el_get_connection(amxp_connection_get_connections(), data_pipe[0]));
    assert_null(amxrt_el_get_connection(amxp_connection_get_connections(), data_pipe[1]));

    assert_int_equal(amxrt_el_destroy(), 0);

    amxp_timer_delete(&timer);

    close(data_pipe[0]);
    close(data_pipe[1]);
}

void test_can_destroy_el_without_create(UNUSED void** state) {
    assert_int_equal(amxrt_el_destroy(), 0);
}

void test_runtime_run_creates_el(UNUSED void** state) {
    amxp_timer_t* timer = NULL;
    int counter = 0;

    amxp_timer_new(&timer, test_stop_eventloop, &counter);
    amxp_timer_start(timer, 1000);

    will_return_always(__wrap_event_base_new, 0);
    will_return_always(__wrap_event_new, 0);
    will_return_always(__wrap_event_add, 0);
    will_return_always(__wrap_event_base_dispatch, 0);

    assert_int_equal(amxrt_el_create(), 0);
    assert_int_equal(amxrt_run(), 0);
    assert_int_equal(amxrt_el_destroy(), 0);
}

void test_eventloop_cbs(UNUSED void** state) {
    will_return_always(__wrap_event_base_new, 0);
    will_return_always(__wrap_event_new, 1);
    will_return_always(__wrap_event_add, 1);

    assert_int_equal(amxrt_el_create(), 0);
    will_return(__wrap_event_base_dispatch, 1);
    assert_int_equal(amxrt_el_start(), 0);
    will_return(__wrap_event_base_dispatch, 2);
    assert_int_equal(amxrt_el_start(), 0);

    assert_int_equal(amxrt_el_destroy(), 0);
}

void test_eventloop_event_base_new_fails(UNUSED void** state) {
    will_return_always(__wrap_event_base_new, 1);
    assert_int_not_equal(amxrt_el_create(), 0);
    assert_int_not_equal(amxrt_el_start(), 0);
    assert_int_not_equal(amxrt_el_stop(), 0);
    assert_int_equal(amxrt_el_destroy(), 0);
}
