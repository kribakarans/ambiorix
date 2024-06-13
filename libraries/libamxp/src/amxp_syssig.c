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
#include <unistd.h>
#include <string.h>

#include <amxc/amxc_macros.h>
#include <amxc/amxc.h>
#include <amxp/amxp.h>

static int sig_fd = -1;
static sigset_t mask;

int amxp_syssig_enable(const int sigid, const bool enable) {
    int retval = -1;
    amxp_signal_t* signal = NULL;
    sigset_t change_mask;
    when_true(sigid > AMXP_SYSSIG_MAX, exit);
    when_true(sigid == SIGKILL || sigid == SIGSTOP, exit);

    sigemptyset(&change_mask);
    sigaddset(&change_mask, sigid);

    amxp_signal_new(NULL, &signal, strsignal(sigid));

    if(enable) {
        when_failed(sigprocmask(SIG_BLOCK, &change_mask, NULL), exit);
        sigaddset(&mask, sigid);
    } else {
        when_failed(sigprocmask(SIG_UNBLOCK, &change_mask, NULL), exit);
        sigdelset(&mask, sigid);
    }

    sig_fd = signalfd(sig_fd, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
    retval = 0;

exit:
    return retval;
}

bool amxp_syssig_is_enabled(const int sigid) {
    bool enabled = false;
    int inset = -1;
    when_true(sigid > AMXP_SYSSIG_MAX, exit);

    inset = sigismember(&mask, sigid);
    when_true(inset < 0, exit);

    enabled = (inset == 1);
exit:
    return enabled;
}

int amxp_syssig_get_fd(void) {
    return sig_fd;
}

int amxp_syssig_read(void) {
    int retval = -1;
    struct signalfd_siginfo si;
    ssize_t res = 0;
    amxc_var_t sig_var;
    int len = sizeof(amxp_siginfo_t);
    amxp_signal_t* signal = NULL;

    amxc_var_init(&sig_var);

    res = read(sig_fd, &si, len);
    when_true(res != len, exit);

    amxc_var_set(amxp_siginfo_t, &sig_var, &si);

    signal = amxp_sigmngr_find_signal(NULL, strsignal(si.ssi_signo));
    when_null(signal, exit);
    amxp_signal_trigger(signal, &sig_var);

    retval = 0;

exit:
    amxc_var_clean(&sig_var);
    return retval;
}

CONSTRUCTOR_LVL(200) static void amxp_syssig_init(void) {
    sigemptyset(&mask);
    sig_fd = signalfd(sig_fd, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
}

DESTRUCTOR_LVL(200) static void amxp_syssig_cleanup(void) {
    close(sig_fd);
    sigemptyset(&mask);
}
