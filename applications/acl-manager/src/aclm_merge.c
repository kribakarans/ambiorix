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

#include <stdio.h>

#include <debug/sahtrace.h>

#include <amxa/amxa_merger.h>

#include "aclm.h"
#include "aclm_merge.h"
#include "aclm_utils.h"

int aclm_merge(const char* role_dir, const char* role) {
    amxc_var_t* acl_rules = amxa_parse_files(role_dir);
    amxc_string_t merged_file;
    amxo_parser_t* parser = aclm_get_parser();
    int retval = -1;
    const char* acl_dir = NULL;
    SAH_TRACEZ_INFO(ME, "Merging ACLs for role %s in directory %s", role, role_dir);

    amxc_string_init(&merged_file, 0);

    when_str_empty(role_dir, exit);
    when_str_empty(role, exit);
    when_null(acl_rules, exit);

    acl_dir = GET_CHAR(&parser->config, "acl_dir");
    when_str_empty(acl_dir, exit);

    amxc_string_setf(&merged_file, "%s/%s/%s.json", acl_dir, ACLM_MERGE_DIR, role);

    retval = amxa_merge_rules(acl_rules, amxc_string_get(&merged_file, 0));
    when_failed(retval, exit);

exit:
    amxc_string_clean(&merged_file);
    amxc_var_delete(&acl_rules);
    return retval;
}

int aclm_merged_remove(const char* role_name) {
    amxc_string_t merged_file;
    amxo_parser_t* parser = aclm_get_parser();
    int retval = -1;
    const char* acl_dir = NULL;

    amxc_string_init(&merged_file, 0);

    when_str_empty(role_name, exit);

    acl_dir = GET_CHAR(&parser->config, "acl_dir");
    when_str_empty(acl_dir, exit);

    amxc_string_setf(&merged_file, "%s/%s/%s.json", acl_dir, ACLM_MERGE_DIR, role_name);

    retval = remove(amxc_string_get(&merged_file, 0));
    if(retval == 0) {
        SAH_TRACEZ_INFO(ME, "Successfully removed file %s", amxc_string_get(&merged_file, 0));
    } else {
        SAH_TRACEZ_ERROR(ME, "Failed to removed file %s", amxc_string_get(&merged_file, 0));
    }

exit:
    amxc_string_clean(&merged_file);
    return retval;
}

int aclm_merge_roles(const char* name, amxc_llist_t* roles) {
    amxo_parser_t* parser = aclm_get_parser();
    amxc_var_t merged;
    const char* acl_dir = NULL;
    amxc_string_t role_dir;
    int retval = -1;

    amxc_string_init(&role_dir, 0);
    amxc_var_init(&merged);
    amxc_var_set_type(&merged, AMXC_VAR_ID_HTABLE);

    when_str_empty(name, exit);
    when_null(roles, exit);

    acl_dir = GET_CHAR(&parser->config, "acl_dir");
    when_str_empty(acl_dir, exit);

    amxc_llist_iterate(it, roles) {
        amxc_string_t* role_name = amxc_string_from_llist_it(it);
        amxc_var_t* rules = NULL;

        amxc_string_setf(&role_dir, "%s/%s/%s.json", acl_dir, ACLM_MERGE_DIR,
                         amxc_string_get(role_name, 0));
        rules = amxa_parse_files(amxc_string_get(&role_dir, 0));

        SAH_TRACEZ_INFO(ME, "Merging %s into %s.json", amxc_string_get(&role_dir, 0), name);
        retval = amxa_combine_roles(&merged, rules, NULL);
        amxc_var_delete(&rules);
        when_failed(retval, exit);
        amxc_string_reset(&role_dir);
    }

    amxc_string_setf(&role_dir, "%s/%s/%s.json", acl_dir, ACLM_MERGE_DIR, name);
    aclm_write_json_var(&merged, amxc_string_get(&role_dir, 0));

exit:
    amxc_string_clean(&role_dir);
    amxc_var_clean(&merged);
    return retval;
}
