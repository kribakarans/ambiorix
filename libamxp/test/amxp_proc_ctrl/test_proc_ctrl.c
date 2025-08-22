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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdlib.h>
#include <stdio.h>
#include <setjmp.h>
#include <stdarg.h>
#include <cmocka.h>
#include <string.h>

#include <amxc/amxc.h>
#include <amxp/amxp.h>

#include "test_proc_ctrl.h"

static amxc_string_t path;

#include <amxc/amxc_macros.h>
int __wrap_kill(pid_t pid, int sig);

FILE* __wrap_fopen(const char* pathname, const char* mode);
FILE* __real_fopen(const char* pathname, const char* mode);

ssize_t __wrap_getline(char** lineptr, size_t* n, FILE* stream);
ssize_t __real_getline(char** lineptr, size_t* n, FILE* stream);

int __wrap_amxc_var_init(amxc_var_t* const var);
int __real_amxc_var_init(amxc_var_t* const var);

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
    } else {
        printf("Read unexpected signal\n");
    }
}

static void handle_events(void) {
    printf("Handling events ");
    while(amxp_signal_read() == 0) {
        printf(".");
    }
    printf("\n");
}

static int test_cmd_builder(amxc_array_t* cmd, UNUSED amxc_var_t* settings) {
    int rv = mock();

    if(rv == 0) {
        amxc_array_append_data(cmd, strdup("sleep "));
        amxc_array_append_data(cmd, strdup("10m"));
    }

    return rv;
}

int __wrap_kill(UNUSED pid_t pid, UNUSED int sig) {
    return 0;
}

FILE* __wrap_fopen(const char* pathname, const char* mode) {
    const char* f = amxc_string_get(&path, 0);
    if(f != NULL) {
        if(strcmp(pathname, f) == 0) {
            return __real_fopen("./test_child_pids.txt", mode);
        } else {
            return __real_fopen(pathname, mode);
        }
    } else {
        return __real_fopen(pathname, mode);
    }
}

int __wrap_amxc_var_init(amxc_var_t* const var) {
    int rv = mock();

    if(rv == 0) {
        rv = __real_amxc_var_init(var);
    }

    return rv;
}

ssize_t __wrap_getline(char** lineptr, size_t* n, FILE* stream) {
    ssize_t rv = mock();

    if(rv == 0) {
        return __real_getline(lineptr, n, stream);
    }

    return rv;
}

void test_proc_ctrl_new_delete(UNUSED void** state) {
    amxp_proc_ctrl_t* ctrl = NULL;

    will_return(__wrap_amxc_var_init, 0);
    assert_int_equal(amxp_proc_ctrl_new(&ctrl, test_cmd_builder), 0);
    assert_non_null(ctrl);
    assert_non_null(ctrl->proc);
    assert_non_null(ctrl->timer);
    assert_int_equal(amxc_var_type_of(&ctrl->child_proc_pids), AMXC_VAR_ID_NULL);

    amxp_proc_ctrl_delete(&ctrl);
    assert_null(ctrl);

    will_return(__wrap_amxc_var_init, -1);
    assert_int_not_equal(amxp_proc_ctrl_new(&ctrl, test_cmd_builder), 0);
    assert_null(ctrl);

    assert_int_not_equal(amxp_proc_ctrl_new(NULL, test_cmd_builder), 0);
    assert_int_not_equal(amxp_proc_ctrl_new(&ctrl, NULL), 0);
    assert_null(ctrl);
    amxp_proc_ctrl_delete(NULL);
}

void test_proc_ctrl_start_stop(UNUSED void** state) {
    amxc_var_t settings;
    amxp_proc_ctrl_t* ctrl = NULL;

    will_return_always(__wrap_amxc_var_init, 0);
    will_return_always(__wrap_getline, 0);

    amxc_var_init(&settings);

    assert_int_equal(amxp_proc_ctrl_new(&ctrl, test_cmd_builder), 0);

    will_return(test_cmd_builder, 0);
    assert_int_equal(amxp_proc_ctrl_start(ctrl, 0, &settings), 0);
    assert_true(ctrl->proc->is_running);

    assert_int_equal(amxp_proc_ctrl_stop(ctrl), 0);
    assert_false(ctrl->proc->is_running);

    will_return(test_cmd_builder, -1);
    assert_int_not_equal(amxp_proc_ctrl_start(ctrl, 0, &settings), 0);

    will_return(test_cmd_builder, 0);
    assert_int_equal(amxp_proc_ctrl_start(ctrl, 0, NULL), 0);
    assert_true(ctrl->proc->is_running);

    assert_int_equal(amxp_proc_ctrl_stop(ctrl), 0);
    handle_events();
    assert_false(ctrl->proc->is_running);

    amxp_proc_ctrl_delete(&ctrl);

    assert_int_not_equal(amxp_proc_ctrl_start(NULL, 0, &settings), 0);
    assert_int_not_equal(amxp_proc_ctrl_stop(NULL), 0);

    amxc_var_clean(&settings);
}

void test_proc_is_stopped_when_timer_expires(UNUSED void** state) {
    amxc_var_t settings;
    amxp_proc_ctrl_t* ctrl = NULL;

    will_return_always(__wrap_amxc_var_init, 0);
    will_return_always(__wrap_getline, 0);

    amxc_var_init(&settings);

    assert_int_equal(amxp_proc_ctrl_new(&ctrl, test_cmd_builder), 0);

    will_return(test_cmd_builder, 0);
    assert_int_equal(amxp_proc_ctrl_start(ctrl, 1, &settings), 0);
    assert_true(ctrl->proc->is_running);

    read_sigalrm();
    amxp_timers_calculate();
    amxp_timers_check();
    handle_events();

    assert_false(amxp_subproc_is_running(ctrl->proc));

    amxp_proc_ctrl_delete(&ctrl);
    amxc_var_clean(&settings);
}

void test_proc_is_stopped_when_timer_is_set_after_start(UNUSED void** state) {
    amxc_var_t settings;
    amxp_proc_ctrl_t* ctrl = NULL;

    will_return_always(__wrap_amxc_var_init, 0);
    will_return_always(__wrap_getline, 0);

    amxc_var_init(&settings);

    assert_int_equal(amxp_proc_ctrl_new(&ctrl, test_cmd_builder), 0);

    will_return(test_cmd_builder, 0);
    assert_int_equal(amxp_proc_ctrl_start(ctrl, 0, &settings), 0);
    assert_true(ctrl->proc->is_running);

    amxp_proc_ctrl_set_active_duration(ctrl, 1);

    read_sigalrm();
    amxp_timers_calculate();
    amxp_timers_check();
    handle_events();

    assert_false(amxp_subproc_is_running(ctrl->proc));

    amxp_proc_ctrl_delete(&ctrl);
    amxc_var_clean(&settings);
}

void test_proc_can_stop_timer(UNUSED void** state) {
    amxc_var_t settings;
    amxp_proc_ctrl_t* ctrl = NULL;

    will_return_always(__wrap_amxc_var_init, 0);
    will_return_always(__wrap_getline, 0);

    amxc_var_init(&settings);

    assert_int_equal(amxp_proc_ctrl_new(&ctrl, test_cmd_builder), 0);

    will_return(test_cmd_builder, 0);
    assert_int_equal(amxp_proc_ctrl_start(ctrl, 1, &settings), 0);
    assert_true(ctrl->proc->is_running);
    assert_int_equal(amxp_timer_get_state(ctrl->timer), amxp_timer_running);
    amxp_timers_calculate();
    amxp_timers_check();
    assert_int_equal(amxp_timer_get_state(ctrl->timer), amxp_timer_running);

    amxp_proc_ctrl_set_active_duration(ctrl, 0);
    assert_int_equal(amxp_timer_get_state(ctrl->timer), amxp_timer_off);

    amxp_proc_ctrl_delete(&ctrl);
    amxc_var_clean(&settings);
}

void test_proc_can_stop_children(UNUSED void** state) {
    amxc_var_t settings;
    amxp_proc_ctrl_t* ctrl = NULL;

    amxc_string_init(&path, 0);
    will_return_always(__wrap_amxc_var_init, 0);
    will_return_always(__wrap_getline, 0);
    will_return_always(test_cmd_builder, 0);

    amxc_var_init(&settings);

    assert_int_equal(amxp_proc_ctrl_new(&ctrl, test_cmd_builder), 0);
    assert_int_equal(amxp_proc_ctrl_start(ctrl, 0, &settings), 0);

    amxc_string_setf(&path, "/proc/%d/task/%d/children", ctrl->proc->pid, ctrl->proc->pid);
    assert_int_equal(amxp_proc_ctrl_get_child_pids(ctrl), 3);
    amxp_proc_ctrl_stop_childs(ctrl);

    amxp_proc_ctrl_delete(&ctrl);
    amxc_string_clean(&path);
    amxc_var_clean(&settings);
}