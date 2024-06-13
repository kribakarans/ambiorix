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
#include <string.h>
#include <unistd.h>

#include <event2/event.h>

#include <amxc/amxc.h>
#include <amxp/amxp_signal.h>
#include <amxp/amxp_slot.h>
#include <amxp/amxp_syssig.h>
#include <amxp/amxp_subproc.h>

#define UNUSED __attribute__((unused))

static struct event_base* base = NULL;

static void signal_cb(UNUSED evutil_socket_t fd,
                      UNUSED short event,
                      UNUSED void* arg) {
    amxp_syssig_read();
}

static void child_stdout_cb(evutil_socket_t fd,
                            UNUSED short event,
                            UNUSED void* arg) {
    char buffer[1024] = {0};
    ssize_t size = read(fd, buffer, 1023);

    if(size > 0) {
        buffer[size + 1] = 0;
        printf("%s", buffer);
    }
}

static void slot_proc_stop(const char* const sig_name,
                           const amxc_var_t* const data,
                           UNUSED void* priv) {
    int pid = amxc_var_dyncast(int64_t, amxc_var_get_key(data, "PID", AMXC_VAR_FLAG_DEFAULT));
    printf("AMX Signal recieved : %s\n", sig_name);
    printf(" => process id = %d\n", pid);
    event_base_loopbreak(base);
}

int main(void) {
    int ret = 0;
    int sig_fd = -1;
    struct event* sig_event = NULL;

    int child_stdout_fd = -1;
    struct event* child_stdout_event = NULL;
    amxp_subproc_t* proc = NULL;
    char* cmd[] = { "ls", "-la", NULL };

    // allocate new proc object and connect to stop signal
    if(amxp_subproc_new(&proc) != 0) {
        exit(1);
    }
    amxp_slot_connect(amxp_subproc_get_sigmngr(proc), "stop", NULL, slot_proc_stop, NULL);

    // allocate new eventloop
    base = event_base_new();
    if(base == NULL) {
        exit(2);
    }

    // add file descriptors to event loop
    // add signal fd to eventloop
    sig_fd = amxp_syssig_get_fd(); // needed for SIGCHLD
    sig_event = event_new(base, sig_fd, EV_READ | EV_PERSIST, signal_cb, NULL);
    event_add(sig_event, NULL);
    // add child proc stdout to eventloop
    child_stdout_fd = amxp_subproc_open_fd(proc, STDOUT_FILENO);
    child_stdout_event = event_new(base, child_stdout_fd, EV_READ | EV_PERSIST, child_stdout_cb, NULL);
    event_add(child_stdout_event, NULL);

    // launch the process
    amxp_subproc_vstart(proc, cmd);
    printf("Child process started pid = %d\n", amxp_subproc_get_pid(proc));

    // start the eventloop
    event_base_dispatch(base);

    // process is stopped, delete proc object
    amxp_subproc_delete(&proc);

    // cleanup event loop
    event_del(sig_event);
    event_free(sig_event);
    event_del(child_stdout_event);
    event_free(child_stdout_event);
    event_base_free(base);

    return ret;
}
