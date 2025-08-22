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

#include <amxc/amxc.h>
#include <amxp/amxp.h>

#include <amxd/amxd_common.h>
#include <amxd/amxd_dm.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_path.h>

#include <amxb/amxb.h>
#include <amxb/amxb_operators.h>
#include "amxb/amxb_be_intf.h"

#include "amxb_priv.h"

typedef struct _amxb_resolve {
    amxc_var_t* ret;
    amxd_path_t* path;
} amxb_resolve_t;

static int amxb_ba_resolve_path(amxb_bus_ctx_t* bus_ctx,
                                UNUSED const amxc_var_t* args,
                                void* priv) {
    int retval = -1;
    amxb_resolve_t* resolver = (amxb_resolve_t*) priv;
    uint32_t caps = 0;

    caps = amxb_be_get_capabilities(bus_ctx);
    if(((caps & AMXB_BE_DISCOVER_RESOLVE) != AMXB_BE_DISCOVER_RESOLVE)) {
        goto exit;
    }
    retval = amxb_resolve(bus_ctx, resolver->path, resolver->ret);

exit:
    return retval;
}

static void amxb_ba_get_all_matching(amxd_path_t* path,
                                     amxc_var_t* ret) {
    amxc_var_t args;
    amxb_resolve_t resolver = {
        .ret = ret,
        .path = path
    };
    amxc_var_init(&args);
    amxc_var_set_type(&args, AMXC_VAR_ID_HTABLE);

    amxb_be_for_all_connections(amxb_ba_resolve_path, &args, &resolver);

    amxc_var_clean(&args);
}

static amxp_expr_status_t amxb_ba_value_spath(UNUSED amxp_expr_t* expr,
                                              amxc_var_t* args,
                                              amxc_var_t* ret) {

    amxp_expr_status_t status = amxp_expr_status_invalid_value;
    amxc_llist_it_t* it = amxc_llist_get_first(&args->data.vl);
    amxc_var_t* data = amxc_var_from_llist_it(it);
    const char* str_path = NULL;
    amxd_path_t path;

    amxd_path_init(&path, NULL);

    when_null(it, exit);
    when_true(amxc_var_type_of(data) != AMXC_VAR_ID_CSTRING, exit);

    str_path = amxc_var_constcast(cstring_t, data);
    when_failed(amxd_path_setf(&path, false, "%s", str_path), exit);

    amxc_var_set_type(ret, AMXC_VAR_ID_LIST);
    amxb_ba_get_all_matching(&path, ret);

    status = amxp_expr_status_ok;

exit:
    amxd_path_clean(&path);
    return status;
}

CONSTRUCTOR_LVL(102) static void amxp_expr_functions_init(void) {
    amxp_expr_add_value_fn("search_path", amxb_ba_value_spath);
}
