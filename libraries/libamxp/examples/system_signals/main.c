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

#include <event2/event.h>

#include <amxc/amxc.h>

#include <amxp/amxp_signal.h>
#include <amxp/variant_siginfo.h>
#include <amxp/amxp_syssig.h>
#include <amxp/amxp_slot.h>

#define UNUSED __attribute__((unused))

static struct event_base* base = NULL;

static void signal_cb(UNUSED evutil_socket_t fd,
                      UNUSED short event,
                      UNUSED void* arg) {
    amxp_syssig_read();
}

static void slot_sigint(UNUSED const char* const sig_name,
                        UNUSED const amxc_var_t* const data,
                        UNUSED void* priv) {
    printf("Signal SIGINT recieved\n\n");
}

static void slot_sigterm(UNUSED const char* const sig_name,
                         UNUSED const amxc_var_t* const data,
                         UNUSED void* priv) {
    printf("Signal SIGTERM recieved - stop eventloop\n\n");
    event_base_loopbreak(base);
}

static void slot_system_signal(const char* const sig_name,
                               const amxc_var_t* const data,
                               UNUSED void* priv) {
    const amxp_siginfo_t* siginfo = amxc_var_constcast(amxp_siginfo_t, data);
    printf("Signal recieved [%s]\n", sig_name);
    printf("\tssi_signo         = %u\n", siginfo->ssi_signo);
    printf("\tssi_errno         = %d\n", siginfo->ssi_errno);
    printf("\tssi_code          = %d\n", siginfo->ssi_code);
    printf("\tssi_pid           = %u\n", siginfo->ssi_pid);
    printf("\tssi_uid           = %u\n", siginfo->ssi_uid);
    printf("\tssi_fd            = %d\n", siginfo->ssi_fd);
    printf("\tssi_tid           = %u\n", siginfo->ssi_tid);
    printf("\tssi_band          = %u\n", siginfo->ssi_band);
    printf("\tssi_overrun       = %u\n", siginfo->ssi_overrun);
    printf("\tssi_trapno        = %u\n", siginfo->ssi_trapno);
    printf("\tssi_status        = %u\n", siginfo->ssi_status);
    printf("\tssi_int           = %u\n", siginfo->ssi_int);
    printf("\n");
}

int main(void) {
    int ret = 0;
    int sig_fd = -1;
    struct event* sig_event = NULL;

    base = event_base_new();
    if(base == NULL) {
        exit(1);
    }

    sig_fd = amxp_syssig_get_fd();
    sig_event = event_new(base, sig_fd, EV_READ | EV_PERSIST, signal_cb, NULL);

    amxp_syssig_enable(SIGINT, true);
    amxp_syssig_enable(SIGTERM, true);

    amxp_slot_connect(NULL, strsignal(SIGINT), NULL, slot_system_signal, NULL);
    amxp_slot_connect(NULL, strsignal(SIGTERM), NULL, slot_system_signal, NULL);

    amxp_slot_connect(NULL, strsignal(SIGINT), NULL, slot_sigint, NULL);
    amxp_slot_connect(NULL, strsignal(SIGTERM), NULL, slot_sigterm, NULL);

    event_add(sig_event, NULL);

    event_base_dispatch(base);

    event_del(sig_event);
    event_free(sig_event);
    event_base_free(base);

    return ret;
}
