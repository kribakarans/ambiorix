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

#include <amxc/amxc.h>
#include <amxc/amxc_macros.h>
#include <amxp/amxp.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_path.h>

#include "amxa/amxa_permissions.h"
#include "amxa/amxa_merger.h"
#include "amxa/amxa_resolver.h"
#include "amxa/amxa_validator.h"

#include "amxa_utils_priv.h"

typedef struct _event_mapper {
    const char* notification_type;
    int bit;
} event_mapper_t;

static int amxa_get_filters_impl(amxc_var_t* acl_rules,
                                 uint32_t bitmask,
                                 amxc_llist_t* filters,
                                 const char* requested_path,
                                 int child_depth);

static void path_remove_last(amxd_path_t* path) {
    const char* param = amxd_path_get_param(path);

    if(param == NULL) {
        char* last = amxd_path_get_last(path, true);
        free(last);
    }
}

static int string_strip_dot(int c) {
    if(c == '.') {
        return 1;
    } else {
        return 0;
    }
}

static void filters_add_string(amxc_llist_t* filters, const char* path) {
    amxc_string_t* new_filter = NULL;

    amxc_string_new(&new_filter, 0);
    amxc_string_setf(new_filter, "%s", path);
    amxc_string_trimr(new_filter, string_strip_dot);
    amxc_llist_append(filters, &new_filter->it);
}

static void update_filters(amxc_var_t* acls,
                           uint32_t bitmask,
                           amxc_llist_t* filters,
                           const char* path) {
    uint32_t permissions = amxc_var_dyncast(uint32_t, acls);

    if((permissions & bitmask) == 0) {
        filters_add_string(filters, path);
    }

    return;
}

static int amxa_get_filters_from_parent(amxc_var_t* acl_rules,
                                        uint32_t bitmask,
                                        amxc_llist_t* filters,
                                        const char* requested_path) {
    int retval = 0;
    amxd_path_t path;
    amxd_path_init(&path, requested_path);

    path_remove_last(&path);
    if(amxd_path_is_valid(&path) && (*amxd_path_get(&path, AMXD_OBJECT_TERMINATE) != 0)) {
        const char* parent_path = amxd_path_get(&path, AMXD_OBJECT_TERMINATE);
        amxc_var_t* acls = NULL;

        acls = amxc_var_get_path(acl_rules, parent_path, AMXC_VAR_FLAG_DEFAULT | AMXC_VAR_FLAG_NO_INDEX);

        if(acls == NULL) {
            retval = amxa_get_filters_from_parent(acl_rules, bitmask, filters, parent_path);
        } else {
            retval = amxa_get_filters_impl(acl_rules, bitmask, filters, parent_path, UINT32_MAX);
        }
    } else {
        retval = -1;
    }

    amxd_path_clean(&path);
    return retval;
}

static void amxa_get_filters_from_child(amxc_var_t* current_branch,
                                        uint32_t bitmask,
                                        amxc_llist_t* filters,
                                        const char* current_path,
                                        int depth) {
    depth--;
    amxc_var_for_each(next_branch, current_branch) {
        const char* key = amxc_var_key(next_branch);
        amxc_var_t* acls = NULL;
        amxd_path_t next_path;

        if(amxc_var_type_of(next_branch) != AMXC_VAR_ID_HTABLE) {
            continue;
        }

        amxd_path_init(&next_path, NULL);
        amxd_path_setf(&next_path, true, "%s%s",
                       current_path, key);

        acls = GET_ARG(next_branch, "\%ACL");
        if(acls != NULL) {
            update_filters(acls, bitmask, filters,
                           amxd_path_get(&next_path, 0));
        }
        if(depth > 0) {
            amxa_get_filters_from_child(next_branch, bitmask, filters,
                                        amxd_path_get(&next_path, AMXD_OBJECT_TERMINATE), depth);
        }
        amxd_path_clean(&next_path);
    }
}

static bool starts_with_path(const char* path,
                             amxc_llist_t* list) {
    bool ret = false;

    amxc_llist_iterate(it, list) {
        amxc_string_t* key = amxc_container_of(it, amxc_string_t, it);
        if(strncmp(amxc_string_get(key, 0), path, strlen(amxc_string_get(key, 0))) == 0) {
            ret = true;
            goto exit;
        }
    }

exit:
    return ret;
}

static void amxa_filter_response_params(amxc_var_t* entry,
                                        const char* object_path,
                                        amxc_llist_t* filters) {
    amxc_var_for_each(param, entry) {
        const char* param_name = amxc_var_key(param);
        bool allowed = false;

        allowed = amxa_is_get_param_allowed(object_path, param_name, filters);
        if(!allowed) {
            amxc_htable_it_take(&param->hit);
            amxc_var_delete(&param);
        }
    }
}

static int amxa_filter_gsdm_params(const char* requested_path,
                                   amxc_var_t* response,
                                   amxc_var_t* acl_rules) {
    amxc_llist_t filters;
    int retval = -1;

    amxc_llist_init(&filters);

    retval = amxa_get_filters_impl(acl_rules, AMXA_PERMIT_GET, &filters,
                                   requested_path, INT32_MAX);
    when_failed(retval, exit);

    amxc_var_for_each(entry, response) {
        const char* object_path = amxc_var_key(entry);
        bool remove = false;

        remove = starts_with_path(object_path, &filters);
        if(remove) {
            amxc_var_t* supported_params = GET_ARG(entry, "supported_params");
            amxc_var_delete(&supported_params);
        }
    }

    retval = 0;
exit:
    amxc_llist_clean(&filters, amxc_string_list_it_free);
    return retval;
}

static int amxa_filter_gsdm_obj(const char* requested_path,
                                amxc_var_t* response,
                                amxc_var_t* acl_rules) {
    amxc_llist_t filters;
    int retval = -1;

    amxc_llist_init(&filters);

    retval = amxa_get_filters_impl(acl_rules, AMXA_PERMIT_OBJ_INFO, &filters,
                                   requested_path, INT32_MAX);
    when_failed(retval, exit);

    amxc_var_for_each(entry, response) {
        const char* object_path = amxc_var_key(entry);
        bool remove = false;

        remove = starts_with_path(object_path, &filters);
        if(remove) {
            amxc_var_t* access = GET_ARG(entry, "access");
            amxc_var_t* is_multi_instance = GET_ARG(entry, "is_multi_instance");
            amxc_var_delete(&access);
            amxc_var_delete(&is_multi_instance);
        }
    }

    retval = 0;
exit:
    amxc_llist_clean(&filters, amxc_string_list_it_free);
    return retval;
}

static int amxa_filter_gsdm_cmds_events(const char* requested_path,
                                        amxc_var_t* response,
                                        amxc_var_t* acl_rules) {
    amxc_llist_t filters;
    int retval = -1;

    amxc_llist_init(&filters);

    retval = amxa_get_filters_impl(acl_rules, AMXA_PERMIT_CMD_INFO, &filters,
                                   requested_path, INT32_MAX);
    when_failed(retval, exit);

    amxc_var_for_each(entry, response) {
        const char* object_path = amxc_var_key(entry);
        bool remove = false;

        remove = starts_with_path(object_path, &filters);
        if(remove) {
            amxc_var_t* supported = GET_ARG(entry, "supported_commands");
            amxc_var_delete(&supported);
            supported = GET_ARG(entry, "supported_events");
            amxc_var_delete(&supported);
        }
    }

    retval = 0;
exit:
    amxc_llist_clean(&filters, amxc_string_list_it_free);
    return retval;
}

static int amxa_get_filters_impl(amxc_var_t* acl_rules,
                                 uint32_t bitmask,
                                 amxc_llist_t* filters,
                                 const char* requested_path,
                                 int child_depth) {
    int retval = -1;
    char* path = path_remove_dot(requested_path);
    amxc_var_t* requested_var = amxc_var_get_path(acl_rules, path,
                                                  AMXC_VAR_FLAG_DEFAULT |
                                                  AMXC_VAR_FLAG_NO_INDEX);

    // If no variant is found for the request, look at parents of the tree
    if(requested_var == NULL) {
        retval = amxa_get_filters_from_parent(acl_rules, bitmask, filters, requested_path);
        // If no ACLs are found for parents, add requested_path to filters
        if(retval != 0) {
            filters_add_string(filters, path);
            retval = 0;
        }
    } else {
        // Look for permissions at current level
        amxc_var_t* acls = GET_ARG(requested_var, "\%ACL");
        if(acls != NULL) {
            update_filters(acls, bitmask, filters, path);
        } else {
            // If no permissions were found look at parents of the tree
            retval = amxa_get_filters_from_parent(acl_rules, bitmask, filters, requested_path);
            // If no ACLs are found for parents, add requested_path to filters
            when_failed(retval, exit);
        }
        // There could be further restrictions on lower levels, but there is no need to check if
        // you have no access for current or parent level
        if((amxc_llist_is_empty(filters)) && (child_depth > 0)) {
            amxa_get_filters_from_child(requested_var, bitmask, filters, requested_path, child_depth);
        }
        retval = 0;
    }

exit:
    free(path);
    return retval;
}

static bool amxa_validate_add_del(amxb_bus_ctx_t* ctx,
                                  amxc_var_t* acl_rules,
                                  const char* requested_path,
                                  int bitmask) {
    int retval = -1;
    amxc_llist_t filters;
    bool allowed = false;
    amxc_var_t ret;
    amxd_path_t path;

    amxc_var_init(&ret);
    amxc_llist_init(&filters);
    amxd_path_init(&path, requested_path);

    when_null(ctx, exit);
    when_null(acl_rules, exit);
    when_str_empty(requested_path, exit);

    if(amxd_path_is_search_path(&path)) {
        retval = amxb_resolve(ctx, &path, &ret);
        when_failed(retval, exit);
        when_null(amxc_var_get_first(&ret), exit);
        amxc_var_for_each(resolved_path, &ret) {
            retval = amxa_get_filters_impl(acl_rules, bitmask, &filters, GET_CHAR(resolved_path, NULL), 0);
            when_failed(retval, exit);
            when_false(amxc_llist_is_empty(&filters), exit);
        }
    } else {
        retval = amxb_describe(ctx, requested_path, AMXB_FLAG_EXISTS, &ret, 3);
        when_failed(retval, exit);
        retval = amxa_get_filters_impl(acl_rules, bitmask, &filters, requested_path, 0);
        when_failed(retval, exit);
        when_false(amxc_llist_is_empty(&filters), exit);
    }

    allowed = true;
exit:
    amxc_llist_clean(&filters, amxc_string_list_it_free);
    amxc_var_clean(&ret);
    amxd_path_clean(&path);
    return allowed;
}

static bool amxa_validate_set_oper(amxb_bus_ctx_t* ctx,
                                   amxc_var_t* acl_rules,
                                   const char* obj_path,
                                   const char* param,
                                   int bitmask) {
    int retval = -1;
    amxc_llist_t filters;
    bool allowed = false;
    amxc_var_t ret;
    amxc_string_t full_path;
    amxd_path_t path;

    amxc_var_init(&ret);
    amxc_llist_init(&filters);
    amxc_string_init(&full_path, 0);
    amxd_path_init(&path, obj_path);

    when_null(ctx, exit);
    when_null(acl_rules, exit);
    when_str_empty(obj_path, exit);
    when_str_empty(param, exit);

    if(amxd_path_is_search_path(&path)) {
        retval = amxb_resolve(ctx, &path, &ret);
        when_failed(retval, exit);
        when_null(amxc_var_get_first(&ret), exit);
        amxc_var_for_each(resolved_path, &ret) {
            amxc_string_setf(&full_path, "%s%s", GET_CHAR(resolved_path, NULL), param);
            retval = amxa_get_filters_impl(acl_rules, bitmask, &filters, amxc_string_get(&full_path, 0), 0);
            when_failed(retval, exit);
            when_false(amxc_llist_is_empty(&filters), exit);
        }
    } else {
        retval = amxb_describe(ctx, obj_path, AMXB_FLAG_EXISTS, &ret, 3);
        when_failed(retval, exit);
        amxc_string_setf(&full_path, "%s%s", obj_path, param);
        retval = amxa_get_filters_impl(acl_rules, bitmask, &filters, amxc_string_get(&full_path, 0), 0);
        when_failed(retval, exit);
        when_false(amxc_llist_is_empty(&filters), exit);
    }

    allowed = true;
exit:
    amxc_string_clean(&full_path);
    amxc_llist_clean(&filters, amxc_string_list_it_free);
    amxc_var_clean(&ret);
    amxd_path_clean(&path);
    return allowed;
}

static int amxa_bitmask_from_notif_data(amxc_var_t* notif_data) {
    int bitmask = 0;
    const char* notification = GET_CHAR(notif_data, "notification");
    event_mapper_t mapper[] = {
        {"dm:object-changed", AMXA_PERMIT_SUBS_VAL_CHANGE},
        {"dm:instance-added", AMXA_PERMIT_SUBS_OBJ_ADD},
        {"dm:instance-removed", AMXA_PERMIT_SUBS_OBJ_DEL},
        {NULL, 0},
    };

    when_null(notification, exit);

    for(int i = 0; mapper[i].notification_type != NULL; i++) {
        if(strcmp(mapper[i].notification_type, notification) == 0) {
            bitmask = mapper[i].bit;
            goto exit;
        }
    }

    // If none of the default events is found, assume it is a data model Event or an OperationComplete
    bitmask = AMXA_PERMIT_SUBS_EVT_OPER_COMP;

exit:
    return bitmask;
}

static int trim_dot(int c) {
    if(c == '.') {
        return 1;
    } else {
        return 0;
    }
}

static void amxa_notif_filter_params(amxc_var_t* notif_data,
                                     amxc_llist_t* filters,
                                     const char* path) {
    amxc_llist_iterate(it, filters) {
        amxc_string_t* filter_path = amxc_string_from_llist_it(it);
        amxd_path_t param_path;
        const char* param = NULL;
        amxc_var_t* param_var = NULL;

        // Filter everything if the filter path is shorter than the event path
        if(amxc_string_text_length(filter_path) <= strlen(path)) {
            amxc_var_add_key(bool, notif_data, "filter-all", true);
            goto exit;
        }

        // Filter a specific parameter from the list of parameters if needed
        amxc_string_trimr(filter_path, trim_dot);
        amxd_path_init(&param_path, amxc_string_get(filter_path, 0));
        param = amxd_path_get_param(&param_path);
        param_var = GET_ARG(notif_data, "parameters");
        param_var = GET_ARG(param_var, param);
        if(param_var != NULL) {
            amxc_var_delete(&param_var);
        }
        amxd_path_clean(&param_path);
    }
exit:
    return;
}

static void amxa_notif_filter_all(amxc_var_t* notif_data,
                                  amxc_llist_t* filters,
                                  const char* path) {
    amxc_llist_iterate(it, filters) {
        amxc_string_t* filter_path = amxc_string_from_llist_it(it);

        // Filter everything if the filter path is shorter than the event path
        if(amxc_string_text_length(filter_path) <= strlen(path)) {
            amxc_var_add_key(bool, notif_data, "filter-all", true);
            break;
        }
    }
}

bool amxa_is_search_path_allowed(amxb_bus_ctx_t* ctx,
                                 amxc_var_t* acl_rules,
                                 const char* requested_path) {
    bool allowed = false;
    amxd_path_t path;
    amxc_var_t resolved;
    amxc_llist_t filters;
    int retval = -1;

    amxd_path_init(&path, NULL);
    amxc_var_init(&resolved);
    amxc_llist_init(&filters);

    when_null(ctx, exit);
    when_null(acl_rules, exit);
    when_str_empty(requested_path, exit);

    amxd_path_setf(&path, false, "%s", requested_path);
    if(!amxd_path_is_search_path(&path)) {
        allowed = true;
        goto exit;
    }

    retval = amxb_resolve(ctx, &path, &resolved);
    when_failed(retval, exit);

    // Exit with false when nothing can be resolved instead of figuring out if resolving is allowed
    when_true(amxc_var_type_of(&resolved) == AMXC_VAR_ID_NULL, exit);

    amxc_var_for_each(var, &resolved) {
        amxd_path_reset(&path);
        amxd_path_setf(&path, true, "%s", amxc_var_constcast(cstring_t, var));
        free(amxd_path_get_last(&path, true));
        retval = amxa_get_filters_impl(acl_rules, AMXA_PERMIT_GET_INST, &filters,
                                       amxd_path_get(&path, AMXD_OBJECT_TERMINATE), 0);
        when_failed(retval, exit);
    }

    if(amxc_llist_is_empty(&filters)) {
        allowed = true;
    }

exit:
    amxc_llist_clean(&filters, amxc_string_list_it_free);
    amxc_var_clean(&resolved);
    amxd_path_clean(&path);
    return allowed;
}

int amxa_get_filters(amxc_var_t* acl_rules,
                     uint32_t bitmask,
                     amxc_llist_t* filters,
                     const char* requested_path) {
    int retval = -1;

    when_null(acl_rules, exit);
    when_null(filters, exit);
    when_str_empty(requested_path, exit);
    when_true(bitmask == 0, exit);

    retval = amxa_get_filters_impl(acl_rules, bitmask, filters, requested_path, INT32_MAX);
    if(retval != 0) {
        filters_add_string(filters, requested_path);
        retval = 0;
    }

exit:
    return retval;
}

int amxa_filter_get_resp(amxc_var_t* response, amxc_llist_t* filters) {
    int retval = -1;
    amxc_var_t* first = NULL;

    when_null(response, exit);
    when_null(filters, exit);
    when_true(amxc_var_type_of(response) != AMXC_VAR_ID_LIST, exit);

    if(amxc_llist_is_empty(filters)) {
        retval = 0;
        goto exit;
    }

    first = GETI_ARG(response, 0);
    amxc_var_for_each(entry, first) {
        const char* object_path = amxc_var_key(entry);
        bool remove = false;

        remove = starts_with_path(object_path, filters);
        if(remove) {
            amxc_htable_it_take(&entry->hit);
            amxc_var_delete(&entry);
        } else {
            amxa_filter_response_params(entry, object_path, filters);
        }
    }

    retval = 0;
exit:
    return retval;
}

int amxa_filter_get_inst_resp(amxc_var_t* response, amxc_llist_t* filters) {
    return amxa_filter_get_resp(response, filters);
}

bool amxa_is_get_allowed(amxc_llist_t* filters, const char* requested_path) {
    bool allowed = false;

    when_null(filters, exit);
    when_str_empty(requested_path, exit);

    if(amxc_llist_is_empty(filters)) {
        allowed = true;
        goto exit;
    }

    amxc_llist_iterate(it, filters) {
        amxc_string_t* filter_path = amxc_string_from_llist_it(it);
        if(strncmp(amxc_string_get(filter_path, 0), requested_path,
                   amxc_string_text_length(filter_path)) == 0) {
            goto exit;
        }
    }

    allowed = true;
exit:
    return allowed;
}

bool amxa_is_get_inst_allowed(amxc_llist_t* filters, const char* requested_path) {
    return amxa_is_get_allowed(filters, requested_path);
}

bool amxa_is_get_param_allowed(const char* object, const char* param, amxc_llist_t* filters) {
    bool ret = true;
    amxc_string_t full_path;

    amxc_string_init(&full_path, 0);

    when_str_empty(object, exit);
    when_str_empty(param, exit);
    when_null(filters, exit);

    amxc_string_setf(&full_path, "%s%s", object, param);

    ret = starts_with_path(amxc_string_get(&full_path, 0), filters);

exit:
    amxc_string_clean(&full_path);
    return !ret;
}

int amxa_filter_get_supported_resp(const char* requested_path,
                                   amxc_var_t* response,
                                   amxc_var_t* acl_rules) {
    int retval = -1;
    amxc_var_t* first = NULL;

    when_null(response, exit);
    when_str_empty(requested_path, exit);
    when_null(acl_rules, exit);
    when_true(amxc_var_type_of(response) != AMXC_VAR_ID_LIST, exit);

    first = GETI_ARG(response, 0);

    retval = amxa_filter_gsdm_params(requested_path, first, acl_rules);
    when_failed(retval, exit);
    retval = amxa_filter_gsdm_obj(requested_path, first, acl_rules);
    when_failed(retval, exit);
    retval = amxa_filter_gsdm_cmds_events(requested_path, first, acl_rules);
    when_failed(retval, exit);

    retval = 0;
exit:
    return retval;
}

bool amxa_is_add_allowed(amxb_bus_ctx_t* ctx, amxc_var_t* acl_rules, const char* requested_path) {
    return amxa_validate_add_del(ctx, acl_rules, requested_path, AMXA_PERMIT_ADD);
}

bool amxa_is_del_allowed(amxb_bus_ctx_t* ctx, amxc_var_t* acl_rules, const char* requested_path) {
    return amxa_validate_add_del(ctx, acl_rules, requested_path, AMXA_PERMIT_DEL);
}

bool amxa_is_set_allowed(amxb_bus_ctx_t* ctx,
                         amxc_var_t* acl_rules,
                         const char* obj_path,
                         const char* param) {
    return amxa_validate_set_oper(ctx, acl_rules, obj_path, param, AMXA_PERMIT_SET);
}

bool amxa_is_operate_allowed(amxb_bus_ctx_t* ctx,
                             amxc_var_t* acl_rules,
                             const char* obj_path,
                             const char* method) {
    return amxa_validate_set_oper(ctx, acl_rules, obj_path, method, AMXA_PERMIT_OPER);
}

bool amxa_is_subs_allowed(amxc_var_t* acl_rules, const char* path, int flag) {
    int retval = -1;
    amxc_llist_t filters;
    bool allowed = false;
    amxc_var_t ret;

    amxc_var_init(&ret);
    amxc_llist_init(&filters);

    when_null(acl_rules, exit);
    when_str_empty(path, exit);
    when_true(flag <= 0, exit);

    retval = amxa_get_filters_impl(acl_rules, flag, &filters, path, 0);
    when_failed(retval, exit);

    if(amxc_llist_is_empty(&filters)) {
        allowed = true;
    }

exit:
    amxc_llist_clean(&filters, amxc_string_list_it_free);
    amxc_var_clean(&ret);
    return allowed;
}

int amxa_filter_notif(amxc_var_t* notif_data, amxc_var_t* acl_rules) {
    int bitmask = 0;
    int retval = -1;
    const char* path = NULL;
    amxc_llist_t filters;

    amxc_llist_init(&filters);

    when_null(notif_data, exit);
    when_null(acl_rules, exit);

    bitmask = amxa_bitmask_from_notif_data(notif_data);
    when_true(bitmask <= 0, exit);

    // Event or OperationComplete should always contain the object path for retrieving correct filters.
    // Not sure if this is currently the case.
    path = GET_CHAR(notif_data, "path");
    when_null(path, exit);

    retval = amxa_get_filters_impl(acl_rules, bitmask, &filters, path, 1);
    when_failed(retval, exit);

    when_true(amxc_llist_is_empty(&filters), exit);

    if(bitmask == AMXA_PERMIT_SUBS_VAL_CHANGE) {
        amxa_notif_filter_params(notif_data, &filters, path);
    } else {
        amxa_notif_filter_all(notif_data, &filters, path);
    }

exit:
    amxc_llist_clean(&filters, amxc_string_list_it_free);
    return retval;
}
