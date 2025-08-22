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
#include <amxp/amxp_signal.h>

#include <amxd/amxd_types.h>
#include <amxd/amxd_dm.h>
#include <amxd/amxd_action.h>
#include <amxd/amxd_parameter.h>

#include "amxd_priv.h"
#include "amxd_assert.h"

amxd_status_t amxd_action_param_read(UNUSED amxd_object_t* object,
                                     amxd_param_t* param,
                                     amxd_action_t reason,
                                     UNUSED const amxc_var_t* const args,
                                     amxc_var_t* const retval,
                                     UNUSED void* priv) {
    amxd_status_t status = amxd_status_unknown_error;

    when_null(param, exit);
    when_true_status(reason != action_param_read,
                     exit,
                     status = amxd_status_function_not_implemented);

    when_failed(amxc_var_copy(retval, &param->value), exit);

    status = amxd_status_ok;

exit:
    return status;
}

amxd_status_t amxd_action_param_read_hidden_value(amxd_object_t* object,
                                                  amxd_param_t* param,
                                                  amxd_action_t reason,
                                                  const amxc_var_t* const args,
                                                  amxc_var_t* const retval,
                                                  void* priv) {
    amxd_status_t status = amxd_status_unknown_error;
    amxd_dm_access_t access = amxd_dm_access_public;

    when_null(param, exit);
    when_null(retval, exit);
    when_true_status(reason != action_param_read,
                     exit,
                     status = amxd_status_function_not_implemented);


    access = (amxd_dm_access_t) GET_UINT32(args, "access");
    if(access > amxd_dm_access_public) {
        status = amxd_action_param_read(object, param, reason, args, retval, priv);
    } else {
        amxc_var_set(cstring_t, retval, "");
        status = amxd_status_ok;
    }

exit:
    return status;
}


amxd_status_t amxd_param_get_value(amxd_param_t* const param,
                                   amxc_var_t* const value) {
    amxd_status_t retval = amxd_status_unknown_error;
    amxd_object_t* object = NULL;
    when_null(param, exit);

    object = amxd_param_get_owner(param);

    retval = amxd_dm_invoke_action(object, param, action_param_read, NULL, value);

exit:
    return retval;
}
