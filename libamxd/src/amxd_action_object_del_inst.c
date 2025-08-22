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

#include "amxd_priv.h"

#include <amxd/amxd_dm.h>
#include <amxd/amxd_action.h>
#include <amxd/amxd_object.h>

#include "amxd_assert.h"

static amxd_status_t amxd_action_del_inst(amxd_object_t* const templ,
                                          const char* name,
                                          uint32_t index,
                                          amxd_dm_access_t access,
                                          bool set_ro) {
    amxd_status_t status = amxd_status_unknown_error;
    amxd_object_t* instance = NULL;

    when_true_status(amxd_object_get_type(templ) != amxd_object_template,
                     exit,
                     status = amxd_status_invalid_type);
    when_true_status(amxd_object_is_attr_set(templ, amxd_oattr_read_only) &&
                     !set_ro,
                     exit,
                     status = amxd_status_invalid_action);

    when_true_status(amxd_object_is_attr_set(templ, amxd_oattr_private) &&
                     access != amxd_dm_access_private,
                     exit,
                     status = amxd_status_invalid_action);

    instance = amxd_object_get_instance(templ, name, index);
    when_null_status(instance, exit, status = amxd_status_object_not_found);

    when_true_status(amxd_object_is_attr_set(instance, amxd_oattr_private) &&
                     access != amxd_dm_access_private,
                     exit,
                     status = amxd_status_invalid_action);

    status = amxd_status_ok;

exit:
    return status;
}

amxd_status_t amxd_action_object_del_inst(amxd_object_t* const object,
                                          UNUSED amxd_param_t* const p,
                                          amxd_action_t reason,
                                          const amxc_var_t* const args,
                                          UNUSED amxc_var_t* const retval,
                                          UNUSED void* priv) {
    amxd_status_t status = amxd_status_unknown_error;
    uint32_t index = 0;
    char* key = NULL;
    amxc_var_t* temp = NULL;
    amxd_dm_access_t access = amxd_dm_access_public;
    bool set_ro = false;

    when_null(object, exit);
    when_true_status(reason != action_object_del_inst,
                     exit,
                     status = amxd_status_function_not_implemented);

    temp = amxc_var_get_key(args, "index", AMXC_VAR_FLAG_DEFAULT);
    index = amxc_var_is_null(temp) ? 0 : amxc_var_dyncast(uint32_t, temp);
    temp = amxc_var_get_key(args, "name", AMXC_VAR_FLAG_DEFAULT);
    key = amxc_var_is_null(temp) ? NULL : amxc_var_dyncast(cstring_t, temp);
    access = (amxd_dm_access_t) amxc_var_dyncast(uint32_t, GET_ARG(args, "access"));
    temp = amxc_var_get_key(args, "set_read_only", AMXC_VAR_FLAG_DEFAULT);
    set_ro = amxc_var_is_null(temp) ? false : amxc_var_dyncast(bool, temp);

    when_true_status(!amxd_action_verify_access(object, access),
                     exit,
                     status = amxd_status_object_not_found);

    status = amxd_action_del_inst(object, key, index, access, set_ro);

exit:
    free(key);
    return status;
}
