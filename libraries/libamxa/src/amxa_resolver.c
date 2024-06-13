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
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <regex.h>

#include <amxc/amxc.h>
#include <amxc/amxc_macros.h>
#include <amxp/amxp.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_path.h>
#include <amxb/amxb.h>

#include "amxa/amxa_resolver.h"
#include "amxa/amxa_merger.h"

#include "amxa_utils_priv.h"

// Add new rule in case resolved search path resulted in a new rule
static void add_new_rule(amxc_var_t* new_rule,
                         const char* resolved_path,
                         uint32_t bitmask,
                         uint32_t order) {
    amxc_string_split_status_t status = AMXC_STRING_SPLIT_OK;
    amxc_string_t full_path;
    amxc_llist_t parts;
    amxc_var_t* current_branch = NULL;

    amxc_llist_init(&parts);
    amxc_string_init(&full_path, 0);
    amxc_string_setf(&full_path, "%s", resolved_path);
    status = amxc_string_split_to_llist(&full_path, &parts, '.');
    when_true(status != AMXC_STRING_SPLIT_OK, exit);

    current_branch = new_rule;
    amxc_llist_iterate(it, &parts) {
        amxc_var_t* next_branch = NULL;
        const char* current_str = amxc_string_get(amxc_string_from_llist_it(it), 0);
        if(*current_str == 0) {
            break;
        }

        next_branch = GET_ARG(current_branch, current_str);
        if(next_branch == NULL) {
            amxc_var_add_key(amxc_htable_t, current_branch, current_str, NULL);
        }
        current_branch = GET_ARG(current_branch, current_str);
    }

    amxc_var_add_key(uint32_t, current_branch, "\%Order", order);
    amxc_var_add_key(uint32_t, current_branch, "\%ACL", bitmask);
    branch_add_bitmask(current_branch, bitmask);

exit:
    amxc_string_clean(&full_path);
    amxc_llist_clean(&parts, amxc_string_list_it_free);
}

// Add new rule or update existing rule based on resolved search path
static void add_or_update_resolved_path(amxc_var_t* root,
                                        const char* resolved_path,
                                        uint32_t order,
                                        uint32_t bitmask) {
    amxc_var_t* existing = NULL;
    // If path ends in dot, this dot must be removed before GETP_ARG
    char* path = path_remove_dot(resolved_path);

    existing = amxc_var_get_path(root, path, AMXC_VAR_FLAG_DEFAULT | AMXC_VAR_FLAG_NO_INDEX);
    if(existing != NULL) {
        amxc_var_t* existing_order = GET_ARG(existing, "\%Order");
        if(order > amxc_var_dyncast(uint32_t, existing_order)) {
            branch_add_bitmask(existing, bitmask);
            amxc_var_set(uint32_t, existing_order, order);
        }
    } else {
        add_new_rule(root, path, bitmask, order);
    }

    free(path);
}

static void delete_var_and_parent(amxc_var_t* branch) {
    amxc_var_t* parent = amxc_var_get_parent(branch);
    while(parent != NULL) {
        const amxc_htable_t* parent_table = amxc_var_constcast(amxc_htable_t, parent);
        if(amxc_htable_size(parent_table) == 1) {
            branch = parent;
        } else {
            break;
        }
        parent = amxc_var_get_parent(branch);
    }
    // If top level variant: reset it
    if(parent == NULL) {
        amxc_var_set_type(branch, AMXC_VAR_ID_HTABLE);
    } else { // else, just delete the current branch
        amxc_var_delete(&branch);
    }
}

static void remove_search_paths(amxc_var_t* branch, const char* path) {
    amxd_path_t current_path;
    amxd_path_init(&current_path, path);
    amxd_path_setf(&current_path, true, "%s", path);

    if(amxd_path_is_search_path(&current_path)) {
        delete_var_and_parent(branch);
        goto exit;
    }

    amxc_var_for_each(value, branch) {
        const char* key = amxc_var_key(value);
        amxd_path_t next_path;

        if(amxc_var_type_of(value) != AMXC_VAR_ID_HTABLE) {
            continue;
        }

        amxd_path_init(&next_path, NULL);
        amxd_path_setf(&next_path, true, "%s%s",
                       amxd_path_get(&current_path, AMXD_OBJECT_TERMINATE), key);
        remove_search_paths(value, amxd_path_get(&next_path, AMXD_OBJECT_TERMINATE));
        amxd_path_clean(&next_path);
    }

exit:
    amxd_path_clean(&current_path);
}

/**
   If the ACL permissions are applied to a search path, it is important that they are applied to
   the resolved objects at the same depth as the search path. However, if the provided path is
   a search path that ends in a multi-instance object, the resolved path will have a higher depth
   (the depth of the resolved instance is added). Therefore this function will compute the depth
   of the original search path and the resolved paths and will reduce the length of the resolved
   path if needed.
 */
static void resolve_path_and_update_rules(amxb_bus_ctx_t* ctx,
                                          amxc_var_t* root,
                                          const char* search_path,
                                          amxc_var_t* branch) {
    amxc_var_t resolved;
    amxd_path_t path;
    uint32_t bitmask = 0;
    uint32_t order = 0;
    const char* param = NULL;
    int sp_depth = 0;

    amxc_var_init(&resolved);
    amxd_path_init(&path, search_path);
    sp_depth = amxd_path_get_depth(&path);

    // Try to resolve object path
    amxb_resolve(ctx, &path, &resolved);
    if(amxc_var_type_of(&resolved) != AMXC_VAR_ID_LIST) {
        // Try to resolve parameter path
        char* param_path = strndup(search_path, strlen(search_path) - 1);
        amxd_path_setf(&path, false, "%s", param_path);
        amxb_resolve(ctx, &path, &resolved);
        free(param_path);
        when_true(amxc_var_type_of(&resolved) != AMXC_VAR_ID_LIST, exit);
        param = amxd_path_get_param(&path);
    }

    bitmask = GET_UINT32(branch, "\%ACL");
    order = GET_UINT32(branch, "\%Order");

    amxc_var_for_each(var, (&resolved)) {
        amxd_path_t resolved_path;
        int resolved_depth = 0;

        amxd_path_init(&resolved_path, NULL);
        amxd_path_setf(&resolved_path, false, "%s%s", amxc_var_constcast(cstring_t, var), param == NULL ? "" : param);
        resolved_depth = amxd_path_get_depth(&resolved_path);
        while(resolved_depth > sp_depth) {
            char* last = amxd_path_get_last(&resolved_path, true);
            free(last);
            resolved_depth--;
        }

        if(param != NULL) {
            char* param_path = amxd_path_get_param_path(&resolved_path);
            add_or_update_resolved_path(root, param_path, order, bitmask);
            free(param_path);
        } else {
            add_or_update_resolved_path(root, amxd_path_get(&resolved_path, AMXD_OBJECT_TERMINATE), order, bitmask);
        }
        amxd_path_clean(&resolved_path);
    }

exit:
    amxd_path_clean(&path);
    amxc_var_clean(&resolved);
}

// Loop over nested tables and look for search paths. If a search path is found, resolve it and
// update ACL rules or add new rules.
static void loop_and_resolve(amxb_bus_ctx_t* ctx,
                             amxc_var_t* root,
                             amxc_var_t* branch,
                             const char* path) {
    amxd_path_t current_path;
    amxd_path_init(&current_path, path);
    amxd_path_setf(&current_path, true, "%s", path);

    if(amxd_path_is_search_path(&current_path)) {
        amxc_var_t* access = GET_ARG(branch, "\%ACL");
        if(access != NULL) {
            resolve_path_and_update_rules(ctx, root,
                                          amxd_path_get(&current_path, AMXD_OBJECT_TERMINATE),
                                          branch);
        }
    }
    amxc_var_for_each(value, branch) {
        const char* key = amxc_var_key(value);

        if((strcmp(key, "\%ACL") == 0) || (strcmp(key, "\%Order") == 0)) {
            continue;
        } else {
            amxd_path_t next_path;
            amxd_path_init(&next_path, NULL);
            amxd_path_setf(&next_path, true, "%s%s",
                           amxd_path_get(&current_path, AMXD_OBJECT_TERMINATE), key);
            loop_and_resolve(ctx, root, value, amxd_path_get(&next_path, AMXD_OBJECT_TERMINATE));
            amxd_path_clean(&next_path);
        }
    }
    amxd_path_clean(&current_path);
}

int amxa_resolve_search_paths(amxb_bus_ctx_t* ctx, amxc_var_t* acl_rules, const char* fixed_part) {
    int retval = -1;
    amxd_path_t current_path;
    amxc_var_t* root_branch = NULL;

    amxd_path_init(&current_path, fixed_part);

    when_null(ctx, exit);
    when_null(acl_rules, exit);
    when_true(amxc_var_type_of(acl_rules) != AMXC_VAR_ID_HTABLE, exit);
    when_str_empty(fixed_part, exit);
    retval = 0;

    root_branch = amxc_var_get_path(acl_rules, amxd_path_get(&current_path, 0),
                                    AMXC_VAR_FLAG_DEFAULT | AMXC_VAR_FLAG_NO_INDEX);
    while(root_branch == NULL) {
        char* part = amxd_path_get_last(&current_path, true);
        const char* path = amxd_path_get(&current_path, 0);
        if((path == NULL) || (*path == 0) ||
           ((strlen(path) == 6) && (strncmp(path, "Device", 6) == 0))) {
            free(part);
            retval = 0;
            break;
        }
        free(part);
        root_branch = amxc_var_get_path(acl_rules, path,
                                        AMXC_VAR_FLAG_DEFAULT | AMXC_VAR_FLAG_NO_INDEX);
    }
    when_null(root_branch, exit);

    loop_and_resolve(ctx, acl_rules, root_branch, amxd_path_get(&current_path, 0));
    remove_search_paths(root_branch, fixed_part);

    retval = 0;
exit:
    amxd_path_clean(&current_path);
    return retval;
}
