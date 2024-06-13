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

#include <debug/sahtrace.h>

#include <string.h>

#include "dm_role_events.h"
#include "aclm_utils.h"
#include "aclm_merge.h"

void _aclm_role_added(UNUSED const char* const sig_name,
                      const amxc_var_t* const data,
                      UNUSED void* const priv) {
    const char* name = GETP_CHAR(data, "parameters.Name");
    const char* type = GETP_CHAR(data, "parameters.Type");
    amxc_string_t combined_from;
    amxc_llist_t parts;
    int retval = -1;

    amxc_string_init(&combined_from, 0);
    amxc_llist_init(&parts);

    if(strcmp(type, "Single") == 0) {
        aclm_create_role_dir(name);
        goto exit;
    }

    amxc_string_set(&combined_from, GETP_CHAR(data, "parameters.CombinedFrom"));
    SAH_TRACEZ_INFO(ME, "Combining roles: %s", amxc_string_get(&combined_from, 0));
    amxc_string_split_to_llist(&combined_from, &parts, ',');

    retval = aclm_merge_roles(name, &parts);
    if(retval != 0) {
        SAH_TRACEZ_ERROR(ME, "Failed to combine roles: %s", amxc_string_get(&combined_from, 0));
    }

exit:
    amxc_string_clean(&combined_from);
    amxc_llist_clean(&parts, amxc_string_list_it_free);
}

void _aclm_role_removed(UNUSED const char* const sig_name,
                        const amxc_var_t* const data,
                        UNUSED void* const priv) {
    const char* name = GETP_CHAR(data, "parameters.Name");
    const char* type = GETP_CHAR(data, "parameters.Type");

    if(strcmp(type, "Single") == 0) {
        aclm_remove_role_dir(name);
    }

    aclm_merged_remove(name);
}
