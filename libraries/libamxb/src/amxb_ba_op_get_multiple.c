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
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>

#include <amxc/amxc.h>
#include <amxp/amxp.h>

#include <amxd/amxd_common.h>
#include <amxd/amxd_dm.h>
#include <amxd/amxd_path.h>
#include <amxd/amxd_object.h>

#include <amxb/amxb_be_intf.h>
#include <amxb/amxb.h>

#include "amxb_priv.h"

int amxb_get_multiple(amxb_bus_ctx_t* const bus_ctx,
                      amxc_var_t* req_paths,
                      int32_t depth,
                      amxc_var_t* ret,
                      int timeout) {
    int retval = amxd_status_ok;
    amxc_var_set_type(ret, AMXC_VAR_ID_HTABLE);
    timeout = amxb_get_minimal_timeout(timeout);

    when_false(amxc_var_type_of(req_paths) == AMXC_VAR_ID_LIST, exit);

    amxc_var_for_each(path, req_paths) {
        int rv = 0;
        amxc_var_t* sub_ret = NULL;
        amxc_var_t* sub_ret_result = NULL;
        const char* path_string = NULL;

        path_string = amxc_var_constcast(cstring_t, path);
        sub_ret = amxc_var_add_key(amxc_htable_t, ret, path_string, NULL);
        sub_ret_result = amxc_var_add_new_key(sub_ret, "result");
        rv = amxb_get(bus_ctx, path_string, depth, sub_ret_result, timeout);
        if(amxc_var_type_of(sub_ret_result) == AMXC_VAR_ID_NULL) {
            amxc_var_set_type(sub_ret_result, AMXC_VAR_ID_LIST);
            amxc_var_add(amxc_htable_t, sub_ret_result, NULL);
            rv = amxd_status_object_not_found;
        }
        amxc_var_add_key(uint32_t, sub_ret, "status", rv);
    }

    retval = amxd_status_ok;

exit:
    return retval;

}
