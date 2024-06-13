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

#include <debug/sahtrace.h>

#include "aclm.h"
#include "dm_role.h"
#include "aclm_utils.h"
#include "aclm_merge.h"

int aclm_role_add(const char* role_name) {
    int retval = -1;
    amxd_trans_t trans;

    when_str_empty(role_name, exit);

    amxd_trans_init(&trans);
    amxd_trans_select_pathf(&trans, "ACLManager.Role.");
    amxd_trans_add_inst(&trans, 0, NULL);
    amxd_trans_set_value(cstring_t, &trans, "Name", role_name);
    retval = amxd_trans_apply(&trans, aclm_get_dm());
    amxd_trans_clean(&trans);

exit:
    return retval;
}

int aclm_role_del(const char* role_name) {
    int retval = -1;
    amxd_object_t* inst = amxd_dm_findf(aclm_get_dm(), "ACLManager.Role.[Name == '%s'].", role_name);
    amxd_trans_t trans;

    when_str_empty(role_name, exit);
    when_null(inst, exit);

    amxd_trans_init(&trans);
    amxd_trans_select_pathf(&trans, "ACLManager.Role.");
    amxd_trans_del_inst(&trans, inst->index, NULL);
    retval = amxd_trans_apply(&trans, aclm_get_dm());
    amxd_trans_clean(&trans);

exit:
    return retval;
}

amxd_status_t _Role_UpdateACL(amxd_object_t* object,
                              UNUSED amxd_function_t* func,
                              UNUSED amxc_var_t* args,
                              UNUSED amxc_var_t* ret) {
    amxc_var_t params;
    const char* type = NULL;
    const char* name = NULL;
    amxd_status_t status = amxd_status_ok;
    amxc_string_t combined_from;
    amxc_llist_t parts;
    int retval = -1;

    amxc_string_init(&combined_from, 0);
    amxc_llist_init(&parts);
    amxc_var_init(&params);

    amxd_object_get_params(object, &params, amxd_dm_access_public);

    type = GET_CHAR(&params, "Type");
    name = GET_CHAR(&params, "Name");
    if(strcmp(type, "Single") == 0) {
        amxc_string_t* role_dir = aclm_dir_from_role(name);
        retval = aclm_merge(amxc_string_get(role_dir, 0), name);
        if(retval != 0) {
            SAH_TRACEZ_ERROR(ME, "Failed to update acls for role: %s", name);
            status = amxd_status_unknown_error;
        }
        amxc_string_delete(&role_dir);
        goto exit;
    }

    amxc_string_set(&combined_from, GETP_CHAR(&params, "CombinedFrom"));
    SAH_TRACEZ_INFO(ME, "Combining roles: %s", amxc_string_get(&combined_from, 0));
    amxc_string_split_to_llist(&combined_from, &parts, ',');

    retval = aclm_merge_roles(name, &parts);
    if(retval != 0) {
        SAH_TRACEZ_ERROR(ME, "Failed to combine roles: %s", amxc_string_get(&combined_from, 0));
        status = amxd_status_unknown_error;
    }

exit:
    amxc_var_clean(&params);
    amxc_string_clean(&combined_from);
    amxc_llist_clean(&parts, amxc_string_list_it_free);

    return status;
}
