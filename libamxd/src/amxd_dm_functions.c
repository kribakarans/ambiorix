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
#include <stdlib.h>

#include "amxd_priv.h"

#include <amxd/amxd_dm.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_path.h>
#include <amxd/amxd_dm_functions.h>
#include <amxd/amxd_transaction.h>

#include "amxd_priv.h"
#include "amxd_assert.h"
#include "amxd_object_priv.h"
#include "amxd_dm_priv.h"

void amxd_def_funcs_remove_args(amxc_var_t* args) {
    amxc_var_t* access = GET_ARG(args, "access");
    uint32_t iaccess = amxc_var_dyncast(uint32_t, access);
    const char* invalid_args[] = {
        "set_read_only",
        NULL
    };

    for(int i = 0; invalid_args[i] != NULL; i++) {
        amxc_var_t* arg = GET_ARG(args, invalid_args[i]);
        amxc_var_delete(&arg);
    }

    if(iaccess > amxd_dm_access_protected) {
        amxc_var_set(uint32_t, access, amxd_dm_access_protected);
    }
}

amxd_status_t amxd_object_func_list(amxd_object_t* object,
                                    UNUSED amxd_function_t* func,
                                    amxc_var_t* args,
                                    amxc_var_t* ret) {
    amxd_status_t retval = amxd_status_unknown_error;
    const char* rel_path = GET_CHAR(args, "rel_path");
    amxd_def_funcs_remove_args(args);

    if((rel_path != NULL) && (*rel_path != 0)) {
        object = amxd_object_findf(object, "%s", rel_path);
        when_null_status(object, exit, retval = amxd_status_object_not_found);
    }

    retval = amxd_dm_invoke_action(object,
                                   NULL,
                                   action_object_list,
                                   args,
                                   ret);

exit:
    return retval;
}

amxd_status_t amxd_object_func_describe(amxd_object_t* object,
                                        UNUSED amxd_function_t* func,
                                        amxc_var_t* args,
                                        amxc_var_t* ret) {

    amxd_status_t retval = amxd_status_unknown_error;
    amxc_var_t* var_rel_path = GET_ARG(args, "rel_path");
    const char* rel_path = GET_CHAR(var_rel_path, NULL);
    amxc_var_t* exists = GET_ARG(args, "exists");
    amxd_def_funcs_remove_args(args);

    amxc_var_take_it(var_rel_path);
    if((rel_path != NULL) && (*rel_path != 0)) {
        object = amxd_object_findf(object, "%s", rel_path);
    }

    if((exists != NULL) && amxc_var_dyncast(bool, exists)) {
        retval = amxd_status_ok;
        amxc_var_set(bool, ret, object != NULL);
        goto exit;
    }

    when_null_status(object, exit, retval = amxd_status_object_not_found);

    retval = amxd_dm_invoke_action(object,
                                   NULL,
                                   action_object_describe,
                                   args,
                                   ret);

exit:

    amxc_var_delete(&var_rel_path);
    return retval;
}

amxd_status_t amxd_object_func_exec(amxd_object_t* object,
                                    UNUSED amxd_function_t* func,
                                    amxc_var_t* args,
                                    amxc_var_t* ret) {
    amxd_status_t retval = amxd_status_unknown_error;
    amxc_var_t* var_rel_path = GET_ARG(args, "rel_path");
    const char* rel_path = GET_CHAR(var_rel_path, NULL);
    const char* method = GET_CHAR(args, "method");
    amxc_var_t* method_args = GET_ARG(args, "args");

    amxd_def_funcs_remove_args(args);

    amxc_var_take_it(var_rel_path);
    if((rel_path != NULL) && (*rel_path != 0)) {
        object = amxd_object_findf(object, "%s", rel_path);
    }

    if(object != NULL) {
        retval = amxd_object_invoke_function(object, method, method_args, ret);
        if(amxc_var_is_null(method_args) ||
           amxc_htable_is_empty(amxc_var_constcast(amxc_htable_t, method_args))) {
            amxc_var_delete(&method_args);
        }
    } else {
        retval = amxd_status_object_not_found;
    }

    amxc_var_delete(&var_rel_path);
    return retval;

}

