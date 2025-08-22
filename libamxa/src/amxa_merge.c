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

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <yajl/yajl_gen.h>

#include <amxc/amxc.h>
#include <amxc/amxc_macros.h>
#include <amxj/amxj_variant.h>

#include "amxa/amxa_merger.h"

#include "amxa_merger_priv.h"
#include "amxa_utils_priv.h"
#include "amxa/amxa_utils.h"
#include "amxa/amxa_permissions.h"

// Get bitmask from Param, Obj, InstantiatedObj and CommandEvent
static uint32_t get_bitmask(amxc_var_t* rules) {
    uint32_t bitmask = 0;
    const char* param = GET_CHAR(rules, "Param");
    const char* obj = GET_CHAR(rules, "Obj");
    const char* instantiated = GET_CHAR(rules, "InstantiatedObj");
    const char* cmd_event = GET_CHAR(rules, "CommandEvent");

    if(param != NULL) {
        bitmask |= (strchr(param, 'r') == NULL) ? 0 : AMXA_PERMIT_GET;
        bitmask |= (strchr(param, 'w') == NULL) ? 0 : AMXA_PERMIT_SET;
        bitmask |= (strchr(param, 'n') == NULL) ? 0 : AMXA_PERMIT_SUBS_VAL_CHANGE;
    }

    if(obj != NULL) {
        bitmask |= (strchr(obj, 'r') == NULL) ? 0 : AMXA_PERMIT_OBJ_INFO;
        bitmask |= (strchr(obj, 'w') == NULL) ? 0 : AMXA_PERMIT_ADD;
        bitmask |= (strchr(obj, 'n') == NULL) ? 0 : AMXA_PERMIT_SUBS_OBJ_ADD;
    }

    if(instantiated != NULL) {
        bitmask |= (strchr(instantiated, 'r') == NULL) ? 0 : AMXA_PERMIT_GET_INST;
        bitmask |= (strchr(instantiated, 'w') == NULL) ? 0 : AMXA_PERMIT_DEL;
        bitmask |= (strchr(instantiated, 'n') == NULL) ? 0 : AMXA_PERMIT_SUBS_OBJ_DEL;
    }

    if(cmd_event != NULL) {
        bitmask |= (strchr(cmd_event, 'r') == NULL) ? 0 : AMXA_PERMIT_CMD_INFO;
        bitmask |= (strchr(cmd_event, 'x') == NULL) ? 0 : AMXA_PERMIT_OPER;
        bitmask |= (strchr(cmd_event, 'n') == NULL) ? 0 : AMXA_PERMIT_SUBS_EVT_OPER_COMP;
    }

    return bitmask;
}

static int acl_rule_new(acl_rule_t** rule) {
    int retval = -1;

    *rule = (acl_rule_t*) calloc(1, sizeof(acl_rule_t));
    when_null(*rule, exit);
    amxc_llist_new(&(*rule)->parts);
    retval = 0;

exit:
    return retval;
}

static void acl_rule_delete(acl_rule_t** rule) {
    if((*rule)->parts != NULL) {
        amxc_llist_delete(&(*rule)->parts, amxc_string_list_it_free);
    }
    free(*rule);
    *rule = NULL;

    return;
}

static void rule_list_it_free(amxc_llist_it_t* it) {
    acl_rule_t* rule = amxc_llist_it_get_data(it, acl_rule_t, it);
    acl_rule_delete(&rule);
}

static void branch_set_bitmask(amxc_var_t* current_branch, uint32_t bitmask) {
    amxc_string_t string_mask;
    amxc_string_init(&string_mask, 0);

    amxc_string_setf(&string_mask, "0x%X", bitmask);

    amxc_var_set(cstring_t, current_branch, amxc_string_get(&string_mask, 0));
    amxc_string_clean(&string_mask);
}

static void process_rule(amxc_var_t* tree, acl_rule_t* rule) {
    uint32_t order = GET_UINT32(rule->var, "Order");
    uint32_t bitmask = 0;
    amxc_string_t* current_str = NULL;
    amxc_string_t full_path;
    amxc_llist_it_t* current_it = NULL;
    amxc_var_t* branch = NULL;
    amxc_var_t* current_branch = NULL;
    size_t loop_count = 0;

    amxc_string_init(&full_path, 0);
    current_str = amxc_string_from_llist_it(amxc_llist_get_last(rule->parts));
    // If there is nothing behind last dot, then there is no param to add
    if(*amxc_string_get(current_str, 0) == 0) {
        loop_count = amxc_llist_size(rule->parts) - 1;
    } else {
        loop_count = amxc_llist_size(rule->parts);
    }

    // Walk tree until no children can be found
    current_branch = tree;
    for(size_t i = 0; i < loop_count; i++) {
        current_it = amxc_llist_get_at(rule->parts, i);
        current_str = amxc_string_from_llist_it(current_it);
        branch = GET_ARG(current_branch, amxc_string_get(current_str, 0));
        if(branch == NULL) {
            amxc_var_add_key(amxc_htable_t, current_branch, amxc_string_get(current_str, 0), NULL);
        } else {
            uint32_t existing_order = GET_UINT32(branch, "\%Order");
            when_true(existing_order > order, exit);
        }
        current_branch = GET_ARG(current_branch, amxc_string_get(current_str, 0));
    }

    bitmask = get_bitmask(rule->var);
    branch_add_bitmask(current_branch, bitmask);
    amxc_var_add_key(uint32_t, current_branch, "\%Order", order);

exit:
    return;
}

static int split_parts(const char* path, amxc_var_t* var, amxc_llist_t* rule_list) {
    int retval = -1;
    amxc_string_split_status_t status = AMXC_STRING_SPLIT_OK;
    amxc_string_t full_path;
    acl_rule_t* rule = NULL;

    amxc_string_init(&full_path, 0);
    when_failed(acl_rule_new(&rule), exit);

    amxc_string_setf(&full_path, "%s", path);
    status = amxc_string_split_to_llist(&full_path, rule->parts, '.');
    if(status != AMXC_STRING_SPLIT_OK) {
        acl_rule_delete(&rule);
        goto exit;
    }

    // There must be at least one dot to split, so at least 2 elements
    if(amxc_llist_size(rule->parts) < 2) {
        acl_rule_delete(&rule);
        goto exit;
    }
    rule->var = var;
    amxc_llist_append(rule_list, &rule->it);
    retval = 0;

exit:
    amxc_string_clean(&full_path);
    return retval;
}

static int compare_path_lengths(amxc_llist_it_t* it1, amxc_llist_it_t* it2) {
    acl_rule_t* rule1 = amxc_llist_it_get_data(it1, acl_rule_t, it);
    acl_rule_t* rule2 = amxc_llist_it_get_data(it2, acl_rule_t, it);
    uint32_t len1 = amxc_llist_size(rule1->parts);
    uint32_t len2 = amxc_llist_size(rule2->parts);

    if(len1 == len2) {
        return 0;
    } else if(len1 < len2) {
        return -1;
    } else {
        return 1;
    }
}

static void write_merged_rules(amxc_var_t* tree, const char* dest_file) {
    variant_json_t* writer = NULL;
    int fd = -1;

    amxj_writer_new(&writer, tree);

    fd = open(dest_file, O_WRONLY | O_CREAT | O_TRUNC, AMXA_FILE_PERMISSIONS);
    when_true(fd < 0, exit);

    amxj_write(writer, fd);

    when_failed(chown(dest_file, amxa_utils_get_owner_uid(), amxa_utils_get_group_gid()), exit);

exit:
    amxj_writer_delete(&writer);
    close(fd);
}

static amxc_string_t* add_quotes_to_string(const char* string) {
    amxc_string_t* result = NULL;

    amxc_string_new(&result, 0);
    amxc_string_setf(result, "'%s'", string);

    return result;
}

static void amxa_combine_roles_impl(amxc_var_t* combined_role, amxc_var_t* new_role) {
    amxc_var_for_each(var, new_role) {
        const char* key = amxc_var_key(var);
        amxc_var_t* next_level = GET_ARG(combined_role, key);
        if(next_level == NULL) {
            amxc_var_set_key(combined_role, key, var, AMXC_VAR_FLAG_COPY);
            continue;
        }

        if(strcmp(key, "\%ACL") == 0) {
            uint32_t acl1 = amxc_var_dyncast(uint32_t, var);
            uint32_t acl2 = amxc_var_dyncast(uint32_t, next_level);
            branch_set_bitmask(next_level, acl1 | acl2);
            continue;
        }
        amxa_combine_roles_impl(next_level, var);
    }
}

amxc_var_t* data_from_json(const char* filename) {
    int fd = -1;
    variant_json_t* reader = NULL;
    amxc_var_t* data = NULL;

    // create a json reader
    amxj_reader_new(&reader);

    when_str_empty(filename, exit);

    // open the json file
    fd = open(filename, O_RDONLY);
    if(fd == -1) {
        goto exit;
    }

    // read the json file and parse the json text
    while(amxj_read(reader, fd) > 0) {
    }

    // get the variant
    data = amxj_reader_result(reader);

    // delete the reader and close the file
    close(fd);

exit:
    amxj_reader_delete(&reader);
    return data;
}

amxc_var_t* amxa_parse_files(const char* path) {
    amxc_var_t* data = NULL;
    struct stat sb;
    DIR* dp = NULL;
    struct dirent* ep;
    amxc_string_t full_path;
    amxc_string_init(&full_path, 0);

    when_null(path, exit);
    when_failed(stat(path, &sb), exit);

    if(!S_ISDIR(sb.st_mode)) {
        data = data_from_json(path);
        goto exit;
    }

    dp = opendir(path);
    if(dp == NULL) {
        goto exit;
    }

    for(ep = readdir(dp); ep; ep = readdir(dp)) {
        amxc_var_t* new_data = NULL;

        if((strcmp(ep->d_name, ".") == 0) || (strcmp(ep->d_name, "..") == 0)) {
            continue;
        }
        amxc_string_setf(&full_path, "%s/%s", path, ep->d_name);

        new_data = data_from_json(amxc_string_get(&full_path, 0));
        if(data == NULL) {
            data = new_data;
        } else {
            amxa_combine_rules(data, new_data);
            amxc_var_delete(&new_data);
        }
        amxc_string_reset(&full_path);
    }

exit:
    amxc_string_clean(&full_path);
    if(dp != NULL) {
        closedir(dp);
    }
    return data;
}

int amxa_combine_rules(amxc_var_t* dst, amxc_var_t* src) {
    int retval = -1;

    when_null(dst, exit);
    when_null(src, exit);
    when_true(amxc_var_type_of(dst) != AMXC_VAR_ID_HTABLE, exit);
    when_true(amxc_var_type_of(src) != AMXC_VAR_ID_HTABLE, exit);

    amxc_var_for_each(rule, src) {
        const char* key = amxc_var_key(rule);
        amxc_string_t* key_with_quotes = add_quotes_to_string(key);
        amxc_var_t* existing_rule = GETP_ARG(dst, amxc_string_get(key_with_quotes, 0));
        uint32_t order = 0;
        uint32_t existing_order = 0;

        if(existing_rule == NULL) {
            amxc_var_set_key(dst, key, rule, AMXC_VAR_FLAG_COPY);
        } else {
            order = GETP_UINT32(rule, "Order");
            existing_order = GETP_UINT32(existing_rule, "Order");
            if(order > existing_order) {
                amxc_var_set_key(dst, key, rule, AMXC_VAR_FLAG_UPDATE);
            }
        }
        amxc_string_delete(&key_with_quotes);
    }

    retval = 0;
exit:
    return retval;
}

int amxa_merge_rules(const amxc_var_t* data, const char* dest_file) {
    int retval = -1;
    amxc_var_t tree;
    amxc_llist_t rule_list;

    amxc_var_init(&tree);
    amxc_var_set_type(&tree, AMXC_VAR_ID_HTABLE);
    amxc_llist_init(&rule_list);

    when_null(data, exit);
    when_null(dest_file, exit);

    amxc_var_for_each(var, data) {
        const char* path = amxc_var_key(var);
        retval = split_parts(path, var, &rule_list);
        when_failed(retval, exit);
    }


    amxc_llist_sort(&rule_list, compare_path_lengths);

    amxc_llist_for_each(it, &rule_list) {
        acl_rule_t* rule = amxc_llist_it_get_data(it, acl_rule_t, it);
        process_rule(&tree, rule);
    }

    write_merged_rules(&tree, dest_file);

    retval = 0;
exit:
    amxc_llist_clean(&rule_list, rule_list_it_free);
    amxc_var_clean(&tree);
    return retval;
}

int amxa_combine_roles(amxc_var_t* combined_role, amxc_var_t* new_role, const char* dest_file) {
    int retval = -1;

    when_null(combined_role, exit);
    when_null(new_role, exit);
    amxa_combine_roles_impl(combined_role, new_role);

    if(dest_file != NULL) {
        write_merged_rules(combined_role, dest_file);
    }

    retval = 0;
exit:
    return retval;
}
