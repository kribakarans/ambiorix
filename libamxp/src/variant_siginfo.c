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
#include <string.h>

#include <amxc/amxc_macros.h>
#include <amxc/amxc.h>
#include <amxp/variant_siginfo.h>

static int variant_siginfo_init(amxc_var_t* const var) {
    int retval = -1;
    amxp_siginfo_t* var_siginfo = (amxp_siginfo_t*) calloc(1, sizeof(amxp_siginfo_t));
    when_null(var_siginfo, exit);

    var->data.data = var_siginfo;
    retval = 0;

exit:
    return retval;
}

static void variant_siginfo_delete(amxc_var_t* var) {
    amxp_siginfo_t* var_siginfo = (amxp_siginfo_t*) var->data.data;
    var->data.data = NULL;
    free(var_siginfo);
}

static int variant_siginfo_copy(amxc_var_t* const dest,
                                const amxc_var_t* const src) {
    int retval = -1;
    const amxp_siginfo_t* src_var_siginfo = (amxp_siginfo_t*) src->data.data;
    amxp_siginfo_t* dest_var_siginfo = (amxp_siginfo_t*) dest->data.data;

    memcpy(dest_var_siginfo, src_var_siginfo, sizeof(amxp_siginfo_t));

    retval = 0;

    return retval;
}

static int variant_siginfo_move(amxc_var_t* const dest,
                                amxc_var_t* const src) {
    dest->data = src->data;
    src->data.data = NULL;
    return 0;
}

static amxc_var_type_t variant_siginfo = {
    .init = variant_siginfo_init,
    .del = variant_siginfo_delete,
    .copy = variant_siginfo_copy,
    .move = variant_siginfo_move,
    .convert_from = NULL,
    .convert_to = NULL,
    .compare = NULL,
    .get_key = NULL,
    .set_key = NULL,
    .get_index = NULL,
    .set_index = NULL,
    .add_value = NULL,
    .type_id = 0,
    .hit = { .ait = NULL, .key = NULL, .next = NULL },
    .name = AMXC_VAR_NAME_SIGINFO
};

CONSTRUCTOR_LVL(200) static void variant_siginfo_register(void) {
    amxc_var_register_type(&variant_siginfo);
}

DESTRUCTOR_LVL(200) static void variant_siginfo_unregister(void) {
    amxc_var_unregister_type(&variant_siginfo);
}

const amxp_siginfo_t* amxc_var_get_const_amxp_siginfo_t(const amxc_var_t* const var) {
    const amxp_siginfo_t* retval = NULL;


    when_null(var, exit);
    when_true(var->type_id != AMXC_VAR_ID_SIGINFO, exit);

    retval = (amxp_siginfo_t*) var->data.data;
exit:
    return retval;

}

int amxc_var_set_amxp_siginfo_t(amxc_var_t* const var, const amxp_siginfo_t* const val) {
    int retval = -1;

    when_null(var, exit);
    when_null(val, exit);
    when_failed(amxc_var_set_type(var, AMXC_VAR_ID_SIGINFO), exit);

    memcpy(var->data.data, val, sizeof(amxp_siginfo_t));

    retval = 0;

exit:
    return retval;
}

