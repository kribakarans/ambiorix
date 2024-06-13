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

#include <string.h>

#include "ba_cli_priv.h"

#include "mod_connection.h"
#include "mod_backend.h"
#include "mod_pcb_cli.h"

typedef struct _ba_cli {
    amxm_shared_object_t* so;
    amxt_tty_t* tty;
} ba_cli_t;

static ba_cli_t ba_cli;

static int ba_cli_init(UNUSED const char* function_name,
                       amxc_var_t* args,
                       UNUSED amxc_var_t* ret) {
    amxt_tty_t* tty = GET_TTY(args);
    amxc_var_t* cli_name = amxt_tty_claim_config(tty, "cli-name");
    const char* n = amxc_var_constcast(cstring_t, cli_name);

    if(n == NULL) {
        amxc_var_set(cstring_t, cli_name, "bus-cli");
    }

    ba_cli.tty = tty;
    return 0;
}

static int ba_cli_exit(UNUSED const char* function_name,
                       UNUSED amxc_var_t* args,
                       UNUSED amxc_var_t* ret) {
    mod_pcb_cli_stop(ba_cli.so);
    mod_connection_stop(ba_cli.so);
    mod_backend_stop(ba_cli.so);

    return 0;
}

static AMXM_CONSTRUCTOR ba_cli_start(void) {
    amxm_module_t* mod = NULL;
    ba_cli.so = amxm_so_get_current();

    amxm_module_register(&mod, ba_cli.so, "__shared_object");
    amxm_module_add_function(mod, "init", ba_cli_init);
    amxm_module_add_function(mod, "exit", ba_cli_exit);

    mod_backend_start(ba_cli.so);
    mod_connection_start(ba_cli.so);
    mod_pcb_cli_start(ba_cli.so);

    return 0;
}

amxm_shared_object_t* ba_cli_get_so(void) {
    return ba_cli.so;
}

amxt_tty_t* ba_cli_get_tty(void) {
    return ba_cli.tty;
}
