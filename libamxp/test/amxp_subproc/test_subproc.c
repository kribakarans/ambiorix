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
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <cmocka.h>

#include <amxc/amxc_variant.h>
#include <amxc/amxc_lqueue.h>

#include <amxp/amxp_subproc.h>
#include <amxp/amxp_syssig.h>
#include <amxp/amxp_slot.h>

#include "test_subproc.h"

#include <amxc/amxc_macros.h>
static bool subproc_is_running = false;

static void slot_test_subproc_stop(UNUSED const char* const sig_name,
                                   UNUSED const amxc_var_t* const data,
                                   UNUSED void* const priv) {
    subproc_is_running = false;
}


static void handle_events(void) {
    printf("Handling events ");
    while(amxp_signal_read() == 0) {
        printf(".");
    }
    printf("\n");
}

void test_subproc_new_delete(UNUSED void** state) {
    amxp_subproc_t* subproc = NULL;

    assert_int_not_equal(amxp_subproc_new(NULL), 0);
    assert_int_not_equal(amxp_subproc_delete(NULL), 0);

    assert_int_equal(amxp_subproc_new(&subproc), 0);
    assert_ptr_not_equal(subproc, NULL);
    assert_int_not_equal(amxp_subproc_new(&subproc), 0);

    assert_false(subproc->is_running);
    assert_false(amxp_subproc_is_running(subproc));
    assert_false(amxp_subproc_is_running(NULL));
    assert_int_equal(subproc->pid, 0);
    assert_int_equal(amxp_subproc_get_pid(subproc), 0);
    assert_int_equal(amxp_subproc_get_pid(NULL), -1);
    for(int i = 0; i < 3; i++) {
        for(int j = 0; j < 2; j++) {
            assert_int_equal(subproc->fd[i][j], -1);
        }
    }

    assert_int_equal(amxp_subproc_delete(&subproc), 0);
    assert_ptr_equal(subproc, NULL);
}

void test_subproc_open_fd(UNUSED void** state) {
    amxp_subproc_t* subproc = NULL;
    int fd = -1;

    assert_int_equal(amxp_subproc_new(&subproc), 0);
    assert_ptr_not_equal(subproc, NULL);

    assert_int_equal(amxp_subproc_open_fd(NULL, STDIN_FILENO), -1);

    fd = amxp_subproc_open_fd(subproc, STDOUT_FILENO);
    assert_int_not_equal(fd, -1);
    assert_int_equal(amxp_subproc_open_fd(subproc, STDOUT_FILENO), fd);
    assert_int_not_equal(amxp_subproc_open_fd(subproc, STDERR_FILENO), -1);
    assert_int_not_equal(amxp_subproc_open_fd(subproc, STDIN_FILENO), -1);
    assert_int_equal(amxp_subproc_open_fd(subproc, 999), -1);
    assert_int_equal(amxp_subproc_open_fd(subproc, -1), -1);

    assert_int_equal(amxp_subproc_delete(&subproc), 0);
    assert_ptr_equal(subproc, NULL);
}

void test_subproc_vstart(UNUSED void** state) {
    amxp_subproc_t* subproc = NULL;
    char* cmd[] = { "ls", "-la", NULL };
    char* cmd2[] = { NULL };

    assert_int_equal(amxp_subproc_new(&subproc), 0);
    assert_ptr_not_equal(subproc, NULL);

    amxp_slot_connect(amxp_subproc_get_sigmngr(subproc), "stop", NULL, slot_test_subproc_stop, NULL);
    assert_int_equal(amxp_subproc_vstart(subproc, cmd), 0);
    subproc_is_running = true;
    assert_true(amxp_subproc_is_running(subproc));
    assert_int_equal(amxp_subproc_vstart(subproc, cmd), -1);

    while(amxp_syssig_read() == -1) {
        printf("Waiting for sigchld");
        sleep(1);
    }

    handle_events();

    assert_false(subproc_is_running);
    assert_false(amxp_subproc_is_running(subproc));

    assert_int_equal(amxp_subproc_vstart(NULL, NULL), -1);
    assert_int_equal(amxp_subproc_vstart(subproc, NULL), -1);
    assert_int_equal(amxp_subproc_vstart(subproc, cmd2), -1);

    assert_int_equal(amxp_subproc_delete(&subproc), 0);
    assert_ptr_equal(subproc, NULL);
}

void test_subproc_astart(UNUSED void** state) {
    amxp_subproc_t* subproc = NULL;
    amxc_array_t cmd;

    amxc_array_init(&cmd, 2);
    amxc_array_append_data(&cmd, "ls");
    amxc_array_append_data(&cmd, "-la");

    assert_int_equal(amxp_subproc_new(&subproc), 0);
    assert_ptr_not_equal(subproc, NULL);

    amxp_slot_connect(amxp_subproc_get_sigmngr(subproc), "stop", NULL, slot_test_subproc_stop, NULL);
    assert_int_equal(amxp_subproc_astart(subproc, &cmd), 0);
    subproc_is_running = true;
    assert_true(amxp_subproc_is_running(subproc));
    assert_int_equal(amxp_subproc_astart(subproc, &cmd), -1);

    while(amxp_syssig_read() == -1) {
        printf("Waiting for sigchld");
        sleep(1);
    }

    handle_events();

    assert_false(subproc_is_running);
    assert_false(amxp_subproc_is_running(subproc));

    assert_int_equal(amxp_subproc_astart(NULL, NULL), -1);
    assert_int_equal(amxp_subproc_astart(subproc, NULL), -1);

    amxc_array_clean(&cmd, NULL);
    assert_int_equal(amxp_subproc_astart(subproc, &cmd), -1);

    assert_int_equal(amxp_subproc_delete(&subproc), 0);
    assert_ptr_equal(subproc, NULL);
}

void test_subproc_vstart_read_stdout(UNUSED void** state) {
    amxp_subproc_t* subproc = NULL;
    char buffer[1024] = "";
    int fd = -1;
    char* cmd[] = { "ls", "-la", NULL };

    assert_int_equal(amxp_subproc_new(&subproc), 0);
    assert_ptr_not_equal(subproc, NULL);

    fd = amxp_subproc_open_fd(subproc, STDOUT_FILENO);
    assert_int_not_equal(fd, -1);
    amxp_slot_connect(amxp_subproc_get_sigmngr(subproc), "stop", NULL, slot_test_subproc_stop, NULL);

    for(int i = 0; i < 2; i++) {
        assert_int_equal(amxp_subproc_vstart(subproc, cmd), 0);
        subproc_is_running = true;
        assert_true(amxp_subproc_is_running(subproc));

        while(amxp_syssig_read() == -1) {
            while(read(fd, buffer, 1023) > 0) {
                printf("%s", buffer);
            }
        }

        handle_events();

        assert_false(subproc_is_running);
        assert_false(amxp_subproc_is_running(subproc));
    }

    assert_int_equal(amxp_subproc_delete(&subproc), 0);
    assert_ptr_equal(subproc, NULL);
}

void test_subproc_start_read_stdout(UNUSED void** state) {
    amxp_subproc_t* subproc = NULL;
    char buffer[1024] = "";
    int fd = -1;

    assert_int_equal(amxp_subproc_new(&subproc), 0);
    assert_ptr_not_equal(subproc, NULL);

    fd = amxp_subproc_open_fd(subproc, STDOUT_FILENO);
    assert_int_not_equal(fd, -1);
    amxp_slot_connect(amxp_subproc_get_sigmngr(subproc), "stop", NULL, slot_test_subproc_stop, NULL);

    assert_ptr_equal(amxp_subproc_find(subproc->pid - 1), NULL);

    for(int i = 0; i < 2; i++) {
        assert_int_equal(amxp_subproc_start(subproc, "ls", "-la", NULL), 0);
        subproc_is_running = true;
        assert_true(amxp_subproc_is_running(subproc));

        while(amxp_syssig_read() == -1) {
            while(read(fd, buffer, 1023) > 0) {
                printf("%s", buffer);
            }
        }

        handle_events();

        assert_false(subproc_is_running);
        assert_false(amxp_subproc_is_running(subproc));
    }

    assert_int_equal(amxp_subproc_delete(&subproc), 0);
    assert_ptr_equal(subproc, NULL);
}

void test_subproc_start_crashing_app(UNUSED void** state) {
    amxp_subproc_t* subproc = NULL;

    assert_int_equal(amxp_subproc_new(&subproc), 0);
    assert_ptr_not_equal(subproc, NULL);

    amxp_slot_connect(amxp_subproc_get_sigmngr(subproc), "stop", NULL, slot_test_subproc_stop, NULL);

    assert_int_equal(amxp_subproc_start(subproc, "test_app/a.out", "crash", NULL), 0);
    subproc_is_running = true;
    assert_true(amxp_subproc_is_running(subproc));

    while(amxp_syssig_read() == -1) {
        sleep(1);
    }

    handle_events();

    assert_false(subproc_is_running);
    assert_false(amxp_subproc_is_running(subproc));

    assert_int_equal(amxp_subproc_delete(&subproc), 0);
    assert_ptr_equal(subproc, NULL);
}

void test_subproc_kill(UNUSED void** state) {
    amxp_subproc_t* subproc = NULL;

    assert_int_equal(amxp_subproc_new(&subproc), 0);
    assert_ptr_not_equal(subproc, NULL);

    amxp_slot_connect(amxp_subproc_get_sigmngr(subproc), "stop", NULL, slot_test_subproc_stop, NULL);

    assert_int_equal(amxp_subproc_start(subproc, "test_app/a.out", "wsignal", NULL), 0);
    subproc_is_running = true;
    assert_true(amxp_subproc_is_running(subproc));

    while(amxp_syssig_read() == -1) {
        amxp_subproc_kill(subproc, SIGTERM);
        sleep(1);
    }

    handle_events();

    assert_false(subproc_is_running);
    assert_false(amxp_subproc_is_running(subproc));

    assert_int_equal(amxp_subproc_delete(&subproc), 0);
    assert_ptr_equal(subproc, NULL);
}

void test_subproc_wait(UNUSED void** state) {
    int err;

    amxp_subproc_t* subproc_sleep_10 = NULL;
    char* cmd_sleep_10[] = { "sleep", "10", NULL};

    amxp_subproc_t* subproc_sleep_2 = NULL;
    char* cmd_sleep_2[] = { "sleep", "2", NULL};

    assert_int_equal(amxp_subproc_new(&subproc_sleep_10), 0);
    assert_ptr_not_equal(subproc_sleep_10, NULL);

    assert_int_equal(amxp_subproc_new(&subproc_sleep_2), 0);
    assert_ptr_not_equal(subproc_sleep_2, NULL);

    // Test general behaviour (-1 --> no timeout)
    err = amxp_subproc_vstart_wait(subproc_sleep_2, -1, cmd_sleep_2);
    assert_int_equal(err, 0);
    assert_false(amxp_subproc_is_running(subproc_sleep_2));

    // Test timeout (500ms)
    err = amxp_subproc_vstart_wait(subproc_sleep_2, 500, cmd_sleep_2);
    assert_int_equal(err, 1);
    assert_true(amxp_subproc_is_running(subproc_sleep_2));

    // wait for (sleep 2) child to finish
    err = amxp_subproc_wait(subproc_sleep_2, -1);
    assert_int_equal(err, 0);
    assert_false(amxp_subproc_is_running(subproc_sleep_2));

    // test for case of short running async child and long running sync child
    // --> short running child
    err = amxp_subproc_vstart(subproc_sleep_2, cmd_sleep_2);
    assert_int_equal(err, 0);
    assert_true(amxp_subproc_is_running(subproc_sleep_2));

    // --> long running child (no timeout)
    err = amxp_subproc_vstart_wait(subproc_sleep_10, -1, cmd_sleep_10);
    assert_int_equal(err, 0);
    assert_false(amxp_subproc_is_running(subproc_sleep_2));
    assert_false(amxp_subproc_is_running(subproc_sleep_10));

    // test for case of short running async child and long running sync child
    // --> short running child
    err = amxp_subproc_vstart(subproc_sleep_2, cmd_sleep_2);
    assert_int_equal(err, 0);
    assert_true(amxp_subproc_is_running(subproc_sleep_2));

    // --> long running child (with timeout but will finish normally)
    err = amxp_subproc_vstart_wait(subproc_sleep_10, 15000, cmd_sleep_10);
    assert_int_equal(err, 0);
    assert_false(amxp_subproc_is_running(subproc_sleep_2));
    assert_false(amxp_subproc_is_running(subproc_sleep_10));

    // test for case of short running async child and long running sync child
    // --> short running child
    err = amxp_subproc_vstart(subproc_sleep_2, cmd_sleep_2);
    assert_int_equal(err, 0);
    assert_true(amxp_subproc_is_running(subproc_sleep_2));

    // --> long running child (with timeout)
    err = amxp_subproc_vstart_wait(subproc_sleep_10, 7500, cmd_sleep_10);
    assert_int_equal(err, 1);
    assert_false(amxp_subproc_is_running(subproc_sleep_2));
    assert_true(amxp_subproc_is_running(subproc_sleep_10));

    // wait for (sleep 10) child to finish
    err = amxp_subproc_wait(subproc_sleep_10, -1);
    assert_int_equal(err, 0);
    assert_false(amxp_subproc_is_running(subproc_sleep_2));

    // argument checking
    err = amxp_subproc_vstart_wait(NULL, 4000, cmd_sleep_2);
    assert_int_not_equal(err, 0);

    err = amxp_subproc_vstart_wait(subproc_sleep_2, 4000, NULL);
    assert_int_not_equal(err, 0);

    // amxp_subproc_start_wait
    err = amxp_subproc_start_wait(subproc_sleep_2, 4000, "sleep", "1", NULL);
    assert_int_equal(err, 0);
    assert_false(amxp_subproc_is_running(subproc_sleep_2));

    // argument checking
    err = amxp_subproc_start_wait(NULL, 4000, "sleep", "1", NULL);
    assert_int_not_equal(err, 0);

    // argument checking -- unfortunately doesnt detect non existing commands
    err = amxp_subproc_start_wait(subproc_sleep_2, 4000, "non_existing_command", "1", NULL);
    assert_int_equal(err, 0);

    // cleanup test
    assert_int_equal(amxp_subproc_delete(&subproc_sleep_10), 0);
    assert_ptr_equal(subproc_sleep_10, NULL);

    assert_int_equal(amxp_subproc_delete(&subproc_sleep_2), 0);
    assert_ptr_equal(subproc_sleep_2, NULL);
}

void test_subproc_helper_functions(UNUSED void** state) {
    int result;
    int err;
    amxp_subproc_t* subproc = NULL;
    char* cmd_sleep_1[] = { "sleep", "2", NULL};


    result = amxp_subproc_ifexited(NULL);
    assert_int_equal(result, -1);

    result = amxp_subproc_ifsignaled(NULL);
    assert_int_equal(result, -1);

    result = amxp_subproc_get_exitstatus(NULL);
    assert_int_equal(result, -1);

    result = amxp_subproc_get_termsig(NULL);
    assert_int_equal(result, -1);

    assert_int_equal(amxp_subproc_new(&subproc), 0);
    assert_ptr_not_equal(subproc, NULL);

    err = amxp_subproc_vstart(subproc, cmd_sleep_1);
    assert_int_equal(err, 0);
    assert_true(amxp_subproc_is_running(subproc));

    err = amxp_subproc_wait(subproc, -1);
    assert_int_equal(err, 0);
    assert_false(amxp_subproc_is_running(subproc));

    result = amxp_subproc_ifexited(subproc);
    assert_int_equal(result, 1);

    result = amxp_subproc_get_exitstatus(subproc);
    assert_int_equal(result, 0);

    assert_int_equal(amxp_subproc_delete(&subproc), 0);
    assert_int_equal(amxp_subproc_new(&subproc), 0);

    assert_int_equal(amxp_subproc_start(subproc, "test_app/a.out", "crash", NULL), 0);
    assert_true(amxp_subproc_is_running(subproc));

    err = amxp_subproc_wait(subproc, -1);
    assert_int_equal(err, 0);
    assert_false(amxp_subproc_is_running(subproc));

    result = amxp_subproc_ifexited(subproc);
    assert_int_equal(result, 0);

    assert_int_equal(amxp_subproc_delete(&subproc), 0);
    assert_int_equal(amxp_subproc_new(&subproc), 0);

    assert_int_equal(amxp_subproc_start(subproc, "test_app/a.out", "wsignal", NULL), 0);
    assert_true(amxp_subproc_is_running(subproc));

    amxp_subproc_kill(subproc, SIGTERM);

    err = amxp_subproc_wait(subproc, -1);
    assert_int_equal(err, 0);
    assert_false(amxp_subproc_is_running(subproc));

    result = amxp_subproc_ifexited(subproc);
    assert_int_equal(result, 0);

    result = amxp_subproc_ifsignaled(subproc);
    assert_int_equal(result, 1);

    result = amxp_subproc_get_termsig(subproc);
    assert_int_equal(result, SIGTERM);

    assert_int_equal(amxp_subproc_delete(&subproc), 0);
    assert_ptr_equal(subproc, NULL);
}
