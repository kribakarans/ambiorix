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
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <poll.h>
#include <time.h>

#include <amxc/amxc_macros.h>
#include <amxc/amxc.h>
#include <amxp/amxp.h>

#define AMXP_SUB_PROC_NR_PIPES  3

#define AMXP_SUBPROC_FD_PARENT 0
#define AMXP_SUBPROC_FD_CHILD  1

static amxc_llist_t amxp_subprocs;

static int amxp_subproc_child_status(amxp_subproc_t* subproc, int status) {
    int retval = -1;
    amxc_var_t* exit_info = NULL;
    amxc_var_t data;

    subproc->is_running = false;
    subproc->status = status;

    amxc_var_init(&data);
    amxc_var_new(&exit_info);
    amxc_var_set_type(exit_info, AMXC_VAR_ID_HTABLE);

    amxc_var_set(int64_t, &data, subproc->pid);
    amxc_var_set_key(exit_info, "PID", &data, AMXC_VAR_FLAG_COPY);

    if(WIFEXITED(status)) {
        amxc_var_set(int64_t, &data, WEXITSTATUS(status));
        amxc_var_set_key(exit_info, "ExitCode", &data, AMXC_VAR_FLAG_COPY);
    } else if(WIFSIGNALED(status)) {
        if(WCOREDUMP(status)) {
            amxc_var_set(bool, &data, true);
            amxc_var_set_key(exit_info, "CoreDump", &data, AMXC_VAR_FLAG_COPY);
        } else {
            amxc_var_set(bool, &data, true);
            amxc_var_set_key(exit_info, "CoreDump", &data, AMXC_VAR_FLAG_COPY);
        }
        amxc_var_set(bool, &data, true);
        amxc_var_set_key(exit_info, "Signalled", &data, AMXC_VAR_FLAG_COPY);
        amxc_var_set(int64_t, &data, WTERMSIG(status));
        amxc_var_set_key(exit_info, "Signal", &data, AMXC_VAR_FLAG_COPY);
    } else {
        goto exit;
    }


    amxp_sigmngr_emit_signal(subproc->sigmngr, "stop", exit_info);
    amxc_var_delete(&exit_info);

    retval = 0;

exit:
    return retval;
}

static void amxp_subproc_close_fds(void) {
    struct rlimit limit;
    int max_files = 1024;

    int ret = getrlimit(RLIMIT_NOFILE, &limit);
    if(ret == 0) {
        max_files = limit.rlim_cur;
    }

    for(int i = 3; i < max_files; i++) {
        close(i);
    }
}

static void amxp_subproc_exec_child(amxp_subproc_t* const subproc,
                                    char** argv) {
    int fd_null = -1;
    sigset_t sig_set;

    prctl(PR_SET_PDEATHSIG, SIGKILL);

    fd_null = open("/dev/null", O_RDWR);
    for(int i = 0; i < AMXP_SUB_PROC_NR_PIPES; i++) {
        if(subproc->fd[i][AMXP_SUBPROC_FD_CHILD] >= 0) {
            if(i != subproc->fd[i][AMXP_SUBPROC_FD_CHILD]) {
                close(i);
                dup2(subproc->fd[i][AMXP_SUBPROC_FD_CHILD], i);
            }
        } else {
            dup2(fd_null, i);
        }
    }

    amxp_subproc_close_fds();

    pthread_sigmask(SIG_SETMASK, NULL, &sig_set);
    pthread_sigmask(SIG_UNBLOCK, &sig_set, NULL);

    execvp(argv[0], argv);

    _exit(EXIT_FAILURE);
}

static void amxp_subproc_sigchild(UNUSED const char* const sig_name,
                                  UNUSED const amxc_var_t* const data,
                                  UNUSED void* const priv) {
    int status = -1;
    pid_t ret = -1;
    amxp_subproc_t* subproc;

    while((ret = waitpid(-1, &status, WNOHANG)) > 0) {
        subproc = amxp_subproc_find(ret);
        if(subproc == NULL) {
            continue;
        }

        amxp_subproc_child_status(subproc, status);
    }

    return;
}

static int amxp_recalculate_timeout(struct timespec* start, int timeout_msec) {
    int err;
    struct timespec stop;
    int remaining_timeout = 0;

    int msec_passed;
    time_t sec_to_msec;
    long nsec_to_msec;

    err = clock_gettime(CLOCK_REALTIME, &stop);
    when_failed(err, exit);

    sec_to_msec = (( stop.tv_sec - start->tv_sec ) * ((time_t) 1000));
    nsec_to_msec = (( stop.tv_nsec - start->tv_nsec) / ((long) 1000000));

    msec_passed = (int) sec_to_msec + (int) nsec_to_msec;
    remaining_timeout = timeout_msec - msec_passed;

    if(remaining_timeout < 0) {
        // this is to avoid that a timeout gets converted
        // to wait indefinitely
        remaining_timeout = 0;
    }

exit:
    return remaining_timeout;
}

int amxp_subproc_new(amxp_subproc_t** subproc) {
    int retval = -1;
    when_null(subproc, exit);
    when_not_null(*subproc, exit);

    *subproc = (amxp_subproc_t*) calloc(1, sizeof(amxp_subproc_t));
    when_null(*subproc, exit);

    for(int i = 0; i < AMXP_SUB_PROC_NR_PIPES; i++) {
        (*subproc)->fd[i][AMXP_SUBPROC_FD_PARENT] = -1;
        (*subproc)->fd[i][AMXP_SUBPROC_FD_CHILD] = -1;
    }

    amxp_sigmngr_new(&(*subproc)->sigmngr);
    amxp_sigmngr_add_signal((*subproc)->sigmngr, "stop");

    amxc_llist_append(&amxp_subprocs, &(*subproc)->it);

    retval = 0;

exit:
    return retval;
}

int amxp_subproc_delete(amxp_subproc_t** subproc) {
    int retval = -1;
    when_null(subproc, exit);
    when_null(*subproc, exit);

    for(int i = 0; i < AMXP_SUB_PROC_NR_PIPES; i++) {
        if((*subproc)->fd[i][AMXP_SUBPROC_FD_PARENT] >= 0) {
            close((*subproc)->fd[i][AMXP_SUBPROC_FD_PARENT]);
        }
        if((*subproc)->fd[i][AMXP_SUBPROC_FD_CHILD] >= 0) {
            close((*subproc)->fd[i][AMXP_SUBPROC_FD_CHILD]);
        }
    }

    amxc_llist_it_take(&(*subproc)->it);
    amxp_sigmngr_delete(&(*subproc)->sigmngr);
    free(*subproc);
    *subproc = NULL;

    retval = 0;
exit:
    return retval;
}

int amxp_subproc_open_fd(amxp_subproc_t* subproc, int requested) {
    int retval = -1;
    when_null(subproc, exit);
    when_true(requested < STDIN_FILENO ||
              requested > STDERR_FILENO, exit)

    if(subproc->fd[requested][AMXP_SUBPROC_FD_PARENT] < 0) {
        if(pipe2(subproc->fd[requested], O_NONBLOCK | O_CLOEXEC) < 0) {
            return -1;
        }
        if(requested == STDIN_FILENO) {
            int swap = subproc->fd[STDIN_FILENO][0];
            subproc->fd[STDIN_FILENO][0] = subproc->fd[STDIN_FILENO][1];
            subproc->fd[STDIN_FILENO][1] = swap;
        }
        retval = subproc->fd[requested][AMXP_SUBPROC_FD_PARENT];
    } else {
        retval = subproc->fd[requested][AMXP_SUBPROC_FD_PARENT];
    }

exit:
    return retval;
}


int amxp_subproc_vstart(amxp_subproc_t* const subproc,
                        char** argv) {
    int retval = -1;
    pid_t pid = 0;
    sigset_t original_mask;
    sigset_t block_mask;

    when_null(subproc, exit);
    when_null(argv, exit);
    when_null(*argv, exit);
    when_true(subproc->is_running, exit);

    sigfillset(&block_mask);
    sigprocmask(SIG_SETMASK, &block_mask, &original_mask);

    pid = fork();
    if(pid > 0) {
        waitpid(pid, NULL, WNOHANG);
        sigprocmask(SIG_SETMASK, &original_mask, NULL);
        amxp_syssig_enable(SIGCHLD, true);
        amxp_slot_connect(NULL,
                          strsignal(SIGCHLD),
                          NULL,
                          amxp_subproc_sigchild,
                          NULL);
        subproc->pid = pid;
        subproc->is_running = true;
        subproc->status = 0;
        retval = 0;
        goto exit;
    } else if(pid == -1) {
        goto exit;
    }

    amxp_subproc_exec_child(subproc, argv);

    retval = 0;

exit:
    return retval;
}

int amxp_subproc_start(amxp_subproc_t* const subproc,
                       char* cmd,
                       ...) {
    int retval = -1;
    va_list ap;
    int argc = 0;
    char** argv = NULL;
    when_null(subproc, exit);
    when_null(cmd, exit);
    when_true(subproc->is_running, exit);

    va_start(ap, cmd);
    while(va_arg(ap, char*)) {
        argc++;
    }
    va_end(ap);

    argv = (char**) calloc(argc + 2, sizeof(char*));
    when_null(argv, exit);

    va_start(ap, cmd);
    // By convention, the first argument is always the executable name
    argv[0] = cmd;
    for(int i = 1; i <= argc; i++) {
        argv[i] = va_arg(ap, char*);
    }
    va_end(ap);

    retval = amxp_subproc_vstart(subproc, argv);
    free(argv);

exit:
    return retval;
}

int amxp_subproc_astart(amxp_subproc_t* const subproc,
                        amxc_array_t* cmd) {
    int retval = -1;
    char** argv = NULL;
    when_null(subproc, exit);
    when_null(cmd, exit);
    when_true(amxc_array_is_empty(cmd), exit);
    when_true(subproc->is_running, exit);

    argv = (char**) calloc(amxc_array_capacity(cmd) + 1, sizeof(char*));
    when_null(argv, exit);

    for(size_t i = 0; i < amxc_array_capacity(cmd); i++) {
        if(amxc_array_get_data_at(cmd, i) == NULL) {
            break;
        }
        argv[i] = (char*) amxc_array_get_data_at(cmd, i);
    }

    retval = amxp_subproc_vstart(subproc, argv);
    free(argv);

exit:
    return retval;
}

int amxp_subproc_kill(const amxp_subproc_t* const subproc, const int sig) {
    int retval = -1;
    when_null(subproc, exit);
    when_true(!subproc->is_running, exit);

    retval = kill(subproc->pid, sig);

exit:
    return retval;
}

amxp_subproc_t* amxp_subproc_find(const int pid) {
    amxp_subproc_t* subproc = NULL;
    amxc_llist_for_each(it, (&amxp_subprocs)) {
        subproc = amxc_llist_it_get_data(it, amxp_subproc_t, it);
        if(subproc->pid == pid) {
            break;
        }
        subproc = NULL;
    }

    return subproc;
}

pid_t amxp_subproc_get_pid(const amxp_subproc_t* const subproc) {
    return subproc != NULL ? subproc->pid : -1;
}

amxp_signal_mngr_t* amxp_subproc_get_sigmngr(const amxp_subproc_t* const subproc) {
    return subproc != NULL ? subproc->sigmngr : NULL;
}

bool amxp_subproc_is_running(const amxp_subproc_t* const subproc) {
    return subproc != NULL ? subproc->is_running : false;
}

// return code: error = -1 ; success (child exited) = 0 ; timeout reached (child still running) = 1
int amxp_subproc_wait(amxp_subproc_t* subproc, int timeout_msec) {
    int retval = -1;
    int err;
    struct pollfd pollfd;
    struct timespec start;
    int remaining_timeout_msec = timeout_msec;

    when_null(subproc, exit);

    pollfd.fd = amxp_syssig_get_fd();
    pollfd.events = POLLIN;

    err = clock_gettime(CLOCK_REALTIME, &start);
    when_failed(err, exit);

    while(amxp_subproc_is_running(subproc)) {
        err = poll(&pollfd, 1, remaining_timeout_msec);
        if(err == 0) {
            retval = 1;
            goto exit;
        } else if(err > 0) {
            amxp_syssig_read();
            if(!amxp_subproc_is_running(subproc)) {
                break;
            }
        }

        if(remaining_timeout_msec > 0) {
            remaining_timeout_msec = amxp_recalculate_timeout(&start, timeout_msec);
        }
    }

    retval = 0;

exit:
    return retval;
}

int amxp_subproc_vstart_wait(amxp_subproc_t* subproc, int timeout_msec, char** cmd) {
    int retval = -1;

    retval = amxp_subproc_vstart(subproc, cmd);
    when_failed(retval, exit);

    retval = amxp_subproc_wait(subproc, timeout_msec);
    when_failed(retval, exit);

    retval = 0;
exit:
    return retval;
}

int amxp_subproc_start_wait(amxp_subproc_t* subproc, int timeout_msec, char* cmd, ...) {
    int retval = -1;

    va_list ap;
    int argc = 0;
    char** argv = NULL;

    when_null(subproc, exit);
    when_null(cmd, exit);

    va_start(ap, cmd);
    while(va_arg(ap, char*)) {
        argc++;
    }
    va_end(ap);

    argv = (char**) calloc(argc + 2, sizeof(char*));
    when_null(argv, exit);

    va_start(ap, cmd);
    // By convention, the first argument is always the executable name
    argv[0] = cmd;
    for(int i = 1; i <= argc; i++) {
        argv[i] = va_arg(ap, char*);
    }
    va_end(ap);

    retval = amxp_subproc_vstart_wait(subproc, timeout_msec, argv);
    when_failed(retval, exit_free);

    retval = 0;
exit_free:
    free(argv);
exit:
    return retval;
}

int amxp_subproc_ifexited(amxp_subproc_t* subproc) {
    int retval = -1;

    when_null(subproc, exit);

    retval = WIFEXITED(subproc->status);
exit:
    return retval;
}

int amxp_subproc_ifsignaled(amxp_subproc_t* subproc) {
    int retval = -1;

    when_null(subproc, exit);

    retval = WIFSIGNALED(subproc->status);
exit:
    return retval;
}

int amxp_subproc_get_exitstatus(amxp_subproc_t* subproc) {
    int retval = -1;

    when_null(subproc, exit);

    retval = WEXITSTATUS(subproc->status);
exit:
    return retval;
}

int amxp_subproc_get_termsig(amxp_subproc_t* subproc) {
    int retval = -1;

    when_null(subproc, exit);

    retval = WTERMSIG(subproc->status);
exit:
    return retval;
}
