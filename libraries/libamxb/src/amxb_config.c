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

#include <amxc/amxc.h>
#include <amxp/amxp.h>

#include <amxd/amxd_types.h>

#include <amxb/amxb.h>
#include <amxb/amxb_be_intf.h>

#include "amxb_priv.h"

static amxb_be_logger_t log_cb_fn = NULL;
static int internal_timeout = 30;
static int minimal_timeout = 10;

void amxb_set_log_cb(amxb_be_logger_t log_fn) {
    if(log_fn == NULL) {
        log_cb_fn = NULL;
    } else if(log_cb_fn == NULL) {
        log_cb_fn = log_fn;
    }
}

void amxb_log(amxb_bus_ctx_t* ctx,
              const char* dm_op,
              const char* path,
              int result) {
    const char* bus_name = NULL;

    when_null(log_cb_fn, exit);
    when_null(ctx, exit);

    bus_name = ctx->bus_fn->name;
    log_cb_fn(bus_name, dm_op, path, result);

exit:
    return;
}

void amxb_set_internal_timeout(int seconds) {
    internal_timeout = seconds;
}

void amxb_set_minimal_timeout(int seconds) {
    minimal_timeout = seconds;
}

int amxb_get_internal_timeout(void) {
    return internal_timeout;
}

int amxb_get_minimal_timeout(int timeout) {
    return minimal_timeout > timeout? minimal_timeout:timeout;
}