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
#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <signal.h>

#include <amxc/amxc.h>
#include <amxc/amxc_llist.h>
#include <amxp/amxp_subproc.h>
#include <amxp/amxp_signal.h>
#include <amxp/amxp_slot.h>

#include <unistd.h>

static void slot_sigchild_recieved(const char* const sig_name,
                                   const amxc_var_t* const data,
                                   void* const priv) {

    (void) priv;
    (void) data;
    printf("AMX SIGNAL %s received\n", sig_name);
}

static void slot_child_proc_stopped(const char* const sig_name,
                                    const amxc_var_t* const data,
                                    void* const priv) {
    amxp_subproc_t* subproc = (amxp_subproc_t*) priv;
    printf("AMX Signal = %s\n", sig_name);
    amxc_var_dump(data, STDOUT_FILENO);

    printf("Stopped process pid = %d\n", subproc->pid);
}

int main(void) {
    int err;

    amxp_subproc_t* subproc1 = NULL;
    amxp_subproc_t* subproc2 = NULL;
    char* cmd_sleep1[] = { "sleep", "2", NULL};
    char* cmd_sleep2[] = { "sleep", "20", NULL};

    err = amxp_subproc_new(&subproc1);
    printf("amxp_subproc_new: %d\n", err);
    err = amxp_subproc_new(&subproc2);
    printf("amxp_subproc_new: %d\n", err);

    amxp_slot_connect(amxp_subproc_get_sigmngr(subproc1), "stop", NULL, slot_child_proc_stopped, subproc1);
    amxp_slot_connect(amxp_subproc_get_sigmngr(subproc2), "stop", NULL, slot_child_proc_stopped, subproc2);

    amxp_slot_connect(NULL,
                      strsignal(SIGCHLD),
                      NULL,
                      slot_sigchild_recieved,
                      NULL);


    err = amxp_subproc_vstart(subproc1, cmd_sleep1);
    printf("Started process pid = %d\n", subproc1->pid);
    printf("amxp_subproc_vstart: %d\n", err);
    err = amxp_subproc_vstart(subproc2, cmd_sleep2);
    printf("Started process pid = %d\n", subproc2->pid);
    printf("amxp_subproc_vstart: %d\n", err);

    err = amxp_subproc_wait(subproc2, 100);
    printf("amxp_subproc_wait: %d\n", err);


    return 0;
}
