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
#include <string.h>
#include <stdio.h>
#include <limits.h>
#include <sys/inotify.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <amxc/amxc.h>
#include <amxc/amxc_macros.h>
#include <amxp/amxp.h>

#define PROC_CHILDREN "/proc/%d/task/%d/children"

static void amxp_proc_ctrl_free_char(amxc_array_it_t* it) {
    char* txt = (char*) amxc_array_it_get_data(it);
    free(txt);
}

static void amxp_proc_ctrl_timer_callback(UNUSED amxp_timer_t* const timer,
                                          void* data) {
    amxp_proc_ctrl_t* proc = (amxp_proc_ctrl_t*) data;
    amxc_var_t pid;
    amxc_var_init(&pid);
    amxc_var_set(uint32_t, &pid, proc->proc->pid);
    amxp_sigmngr_emit_signal(NULL, "proc:disable", &pid);
    amxp_proc_ctrl_stop(proc);

    amxc_var_clean(&pid);
}

static void amxp_proc_ctrl_stopped(UNUSED const char* const event_name,
                                   UNUSED const amxc_var_t* const event_data,
                                   void* const priv) {
    amxp_proc_ctrl_t* proc = (amxp_proc_ctrl_t*) priv;
    amxc_var_t pid;
    amxc_var_init(&pid);

    when_null(proc, leave);

    amxc_var_set(uint32_t, &pid, proc->proc->pid);
    amxp_timer_stop(proc->timer);
    amxp_proc_ctrl_stop_childs(proc);

    amxp_sigmngr_emit_signal(NULL, "proc:stopped", &pid);

leave:
    amxc_var_clean(&pid);
}

static int amxp_proc_ctrl_get_child_pids_proc_children(amxp_proc_ctrl_t* proc) {
    int retval = -1;
    FILE* fp = NULL;
    amxc_string_t file;
    pid_t ppid = 0;
    ssize_t read = 0;
    char* line = NULL;
    size_t len = 0;

    amxc_string_init(&file, 0);

    ppid = amxp_subproc_get_pid(proc->proc);
    amxc_var_set_type(&proc->child_proc_pids, AMXC_VAR_ID_LIST);

    amxc_string_setf(&file, PROC_CHILDREN, ppid, ppid);
    fp = fopen(amxc_string_get(&file, 0), "r");
    if(fp == NULL) {
        goto leave;
    }

    read = getline(&line, &len, fp);
    if(read == -1) {
        free(line);
        goto leave;
    }

    amxc_var_push(ssv_string_t, &proc->child_proc_pids, line);
    amxc_var_cast(&proc->child_proc_pids, AMXC_VAR_ID_LIST);

    retval = 0;

leave:
    if(fp != NULL) {
        fclose(fp);
    }
    amxc_string_clean(&file);
    return retval;
}

static int amxp_proc_ctrl_get_child_pids_scan_proc(amxp_proc_ctrl_t* proc) {
    int retval = -1;
    amxc_llist_t children;

    amxc_llist_init(&children);
    retval = amxp_proci_findf(&children,
                              "ppid == %d", amxp_subproc_get_pid(proc->proc));

    when_failed(retval, leave);
    amxc_var_set_type(&proc->child_proc_pids, AMXC_VAR_ID_LIST);

    amxc_llist_iterate(it, (&children)) {
        amxp_proc_info_t* pi = amxc_container_of(it, amxp_proc_info_t, it);
        amxc_var_add(int32_t, &proc->child_proc_pids, pi->pid);
    }

leave:
    amxc_llist_clean(&children, amxp_proci_free_it);
    return retval;
}

int amxp_proc_ctrl_new(amxp_proc_ctrl_t** proc, amxp_proc_ctrl_cmd_t cmd_build_fn) {
    int retval = -1;
    when_null(proc, leave);
    when_null(cmd_build_fn, leave);

    *proc = (amxp_proc_ctrl_t*) calloc(1, sizeof(amxp_proc_ctrl_t));
    when_null(*proc, leave);

    when_failed(amxp_subproc_new(&(*proc)->proc), leave);
    when_failed(amxp_timer_new(&(*proc)->timer, amxp_proc_ctrl_timer_callback, *proc), leave);
    when_failed(amxc_array_init(&(*proc)->cmd, 10), leave);
    when_failed(amxc_var_init(&(*proc)->child_proc_pids), leave);

    (*proc)->build = cmd_build_fn;
    amxp_slot_connect((*proc)->proc->sigmngr, "stop", NULL, amxp_proc_ctrl_stopped, *proc);

    retval = 0;

leave:
    if((retval != 0) &&
       ((proc != NULL) && (*proc != NULL))) {
        amxp_subproc_delete(&(*proc)->proc);
        amxp_timer_delete(&(*proc)->timer);
        amxc_array_clean(&(*proc)->cmd, NULL);
        amxc_var_clean(&(*proc)->child_proc_pids);
        free(*proc);
        *proc = NULL;
    }
    return retval;
}

void amxp_proc_ctrl_delete(amxp_proc_ctrl_t** proc) {
    when_null(proc, leave);
    when_null(*proc, leave);

    amxp_slot_disconnect((*proc)->proc->sigmngr, "stop", amxp_proc_ctrl_stopped);

    amxp_proc_ctrl_stop(*proc);
    amxp_subproc_delete(&(*proc)->proc);
    amxp_timer_delete(&(*proc)->timer);
    amxc_array_clean(&(*proc)->cmd, amxp_proc_ctrl_free_char);
    amxc_var_clean(&(*proc)->child_proc_pids);

    free(*proc);
    *proc = NULL;

leave:
    return;
}

int amxp_proc_ctrl_start(amxp_proc_ctrl_t* proc, uint32_t minutes, amxc_var_t* settings) {
    int retval = -1;
    when_null(proc, leave);

    amxc_array_clean(&proc->cmd, amxp_proc_ctrl_free_char);
    retval = proc->build(&proc->cmd, settings);
    when_failed(retval, leave);
    when_true(amxc_array_is_empty(&proc->cmd), leave);

    retval = amxp_subproc_astart(proc->proc, &proc->cmd);
    when_failed(retval, leave);

    if(minutes != 0) {
        amxp_timer_start(proc->timer, minutes * 60 * 1000);
    }

    retval = 0;

leave:
    return retval;
}

int amxp_proc_ctrl_stop(amxp_proc_ctrl_t* proc) {
    int retval = -1;
    when_null(proc, leave);

    amxp_timer_stop(proc->timer);

    amxp_proc_ctrl_get_child_pids(proc);
    amxp_proc_ctrl_stop_childs(proc);

    amxp_subproc_kill(proc->proc, SIGTERM);
    retval = amxp_subproc_wait(proc->proc, 2000);
    if(retval == 1) {
        // not stopped after waiting for 2 seconds
        // forcekill
        amxp_subproc_kill(proc->proc, SIGKILL);
        retval = amxp_subproc_wait(proc->proc, 2000);
    }

leave:
    return retval;
}

void amxp_proc_ctrl_set_active_duration(amxp_proc_ctrl_t* proc, uint32_t minutes) {
    when_null(proc, leave);

    if(minutes == 0) {
        amxp_timer_stop(proc->timer);
    } else {
        if(amxp_subproc_is_running(proc->proc)) {
            // reset timer to new duration time
            amxp_timer_start(proc->timer, minutes * 60 * 1000);
        }
    }

leave:
    return;
}

void amxp_proc_ctrl_stop_childs(amxp_proc_ctrl_t* proc) {
    when_null(proc, leave);

    if(amxc_var_type_of(&proc->child_proc_pids) == AMXC_VAR_ID_LIST) {
        amxc_var_for_each(child_pid, (&proc->child_proc_pids)) {
            pid_t pid = amxc_var_dyncast(uint32_t, child_pid);
            kill(pid, SIGTERM);
        }
    }

leave:
    return;
}

int amxp_proc_ctrl_get_child_pids(amxp_proc_ctrl_t* proc) {
    int retval = -1;
    when_null(proc, leave);

    when_false(amxp_subproc_is_running(proc->proc), leave);
    retval = amxp_proc_ctrl_get_child_pids_proc_children(proc);
    if(retval == 0) {
        goto leave;
    }

    retval = amxp_proc_ctrl_get_child_pids_scan_proc(proc);

leave:
    if(retval == 0) {
        const amxc_llist_t* list = amxc_var_constcast(amxc_llist_t, &proc->child_proc_pids);
        retval = amxc_llist_size(list);
    }
    return retval;
}