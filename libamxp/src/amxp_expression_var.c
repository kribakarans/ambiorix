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

#include <sys/resource.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <regex.h>

#include <amxc/amxc.h>
#include <amxc/amxc_macros.h>

#include "amxp_expr_priv.h"

typedef struct _var_collector {
    amxc_string_t* path;
    const amxc_var_t* var;
    amxc_llist_it_t it;
} var_collector_t;

static void var_collector_it_free(amxc_llist_it_t* it) {
    var_collector_t* c = amxc_container_of(it, var_collector_t, it);
    amxc_string_delete(&c->path);
    free(c);
}

static var_collector_t* var_collector_new(const char* path,
                                          const amxc_var_t* var,
                                          amxc_llist_t* vars) {
    var_collector_t* c = (var_collector_t*) calloc(1, sizeof(var_collector_t));
    when_null(c, exit);
    amxc_string_new(&c->path, 0);
    amxc_string_setf(c->path, "%s", path);
    c->var = var;

    amxc_llist_append(vars, &c->it);

exit:
    return c;
}

static void var_path_add(amxc_string_t* path, const char* name, uint32_t index) {
    const char* sep = amxc_string_is_empty(path) ? "" : ".";
    if(name != NULL) {
        amxc_string_appendf(path, "%s'%s'", sep, name);
    } else {
        amxc_string_appendf(path, "%s%d", sep, index);
    }
}

static void var_update_entry(var_collector_t* c, const char* token) {
    int index = 0;
    bool isindex = false;
    char* endptr = NULL;
    amxc_var_t* temp = NULL;

    index = strtol(token, &endptr, 0);
    if(*endptr == 0) {
        temp = amxc_var_get_index(c->var, index, AMXC_VAR_FLAG_DEFAULT);
    }
    if(temp == NULL) {
        temp = amxc_var_get_key(c->var, token, AMXC_VAR_FLAG_DEFAULT);
    } else {
        isindex = true;
    }

    if(temp != NULL) {
        c->var = temp;
        var_path_add(c->path, isindex ? NULL : token, index);
    } else {
        amxc_llist_it_take(&c->it);
        var_collector_it_free(&c->it);
    }
}

static void var_add_filtered_entry(amxc_var_t* item,
                                   const char* base_path,
                                   const char* token,
                                   amxp_expr_t* expr,
                                   amxc_llist_t* new_entries,
                                   const char* name,
                                   uint32_t index) {
    var_collector_t* nc = NULL;

    if(token[0] == '*') {
        nc = var_collector_new(base_path, item, new_entries);
        var_path_add(nc->path, name, index);
    } else {
        if(amxp_expr_eval_var(expr, item, NULL)) {
            nc = var_collector_new(base_path, item, new_entries);
            var_path_add(nc->path, name, index);
        }
    }
}

static void var_update_filtered_list(var_collector_t* current,
                                     amxc_llist_t* new_entries,
                                     const char* token) {
    const amxc_llist_t* items = amxc_var_constcast(amxc_llist_t, current->var);
    const char* base = amxc_string_get(current->path, 0);
    uint32_t index = 0;
    amxp_expr_t expr;

    if(token[0] == '[') {
        amxp_expr_init(&expr, token + 1);
    }
    amxc_llist_iterate(it, items) {
        amxc_var_t* item = amxc_var_from_llist_it(it);
        if(index != 0) {
            var_add_filtered_entry(item, base, token, &expr, new_entries, NULL, index);
        }
        index++;
    }

    if(token[0] == '*') {
        var_path_add(current->path, NULL, 0);
        current->var = amxc_var_get_index(current->var, 0, AMXC_VAR_FLAG_DEFAULT);
    } else {
        amxc_var_t* item = amxc_var_get_index(current->var, 0, AMXC_VAR_FLAG_DEFAULT);
        if(!amxp_expr_eval_var(&expr, item, NULL)) {
            amxc_llist_it_take(&current->it);
            var_collector_it_free(&current->it);
        } else {
            var_path_add(current->path, NULL, 0);
            current->var = item;
        }
    }

    if(token[0] == '[') {
        amxp_expr_clean(&expr);
    }
}

static void var_update_filtered_table(var_collector_t* current,
                                      amxc_llist_t* new_entries,
                                      const char* token) {
    const amxc_htable_t* items = amxc_var_constcast(amxc_htable_t, current->var);
    const char* first = NULL;
    const char* base = amxc_string_get(current->path, 0);
    amxp_expr_t expr;

    if(token[0] == '[') {
        amxp_expr_init(&expr, token + 1);
    }

    amxc_htable_iterate(it, items) {
        const char* name = amxc_htable_it_get_key(it);
        amxc_var_t* item = amxc_var_from_htable_it(it);
        if(first != NULL) {
            var_add_filtered_entry(item, base, token, &expr, new_entries, name, 0);
        } else {
            first = name;
        }
    }

    if(token[0] == '*') {
        var_path_add(current->path, first, 0);
        current->var = amxc_var_get_key(current->var, first, AMXC_VAR_FLAG_DEFAULT);
    } else {
        amxc_var_t* item = amxc_var_get_key(current->var, first, AMXC_VAR_FLAG_DEFAULT);
        if(!amxp_expr_eval_var(&expr, item, NULL)) {
            amxc_llist_it_take(&current->it);
            var_collector_it_free(&current->it);
        } else {
            var_path_add(current->path, first, 0);
            current->var = item;
        }
    }

    if(token[0] == '[') {
        amxp_expr_clean(&expr);
    }
}

static void var_update_filtered(var_collector_t* current,
                                amxc_llist_t* new_entries,
                                const char* token) {

    if((amxc_var_type_of(current->var) != AMXC_VAR_ID_HTABLE) &&
       ( amxc_var_type_of(current->var) != AMXC_VAR_ID_LIST)) {
        amxc_llist_it_take(&current->it);
        var_collector_it_free(&current->it);
        goto exit;
    }

    if(amxc_var_type_of(current->var) == AMXC_VAR_ID_LIST) {
        var_update_filtered_list(current, new_entries, token);
    } else {
        var_update_filtered_table(current, new_entries, token);
    }

exit:
    return;
}

static void var_update_collection(amxc_llist_t* vars, amxc_string_t* part) {
    size_t len = amxc_string_text_length(part);
    uint32_t offset = 0;
    char* token = amxc_string_take_buffer(part);
    amxc_llist_t new_entries;
    amxc_llist_init(&new_entries);

    if((token[0] == '\'') || (token[0] == '"') || (token[0] == '[')) {
        token[len - 1] = 0;
        offset = 1;
    }

    amxc_llist_for_each(it1, vars) {
        var_collector_t* c = amxc_container_of(it1, var_collector_t, it);

        if((token[0] == '*') || (token[0] == '[')) {
            var_update_filtered(c, &new_entries, token);
        } else {
            var_update_entry(c, token + offset);
        }

        c = NULL;
    }

    amxc_llist_for_each(it2, &new_entries) {
        amxc_llist_append(vars, it2);
    }

    free(token);
}

static void var_collect(amxc_llist_t* vars, amxc_llist_t* parts) {
    amxc_llist_for_each(it, parts) {
        amxc_string_t* part = amxc_container_of(it, amxc_string_t, it);
        var_update_collection(vars, part);
        amxc_string_delete(&part);
    }
}

static int var_build_parts(amxc_llist_t* parts, const char* path) {
    int retval = 0;
    amxc_string_t search_path;
    amxc_string_init(&search_path, 0);

    amxc_string_set(&search_path, path);
    amxc_string_trim(&search_path, NULL);

    retval = amxc_string_split_to_llist(&search_path, parts, '.');
    when_failed(retval, exit);
    if((search_path.buffer != NULL) && (search_path.buffer[0] == '[')) {
        amxc_string_t* fp = amxc_string_from_llist_it(amxc_llist_get_first(parts));
        if((fp != NULL) && (fp->buffer != NULL) && (fp->buffer[0] != '[')) {
            amxc_string_prepend(fp, "[", 1);
            amxc_string_append(fp, "]", 1);
        }
    }

exit:
    amxc_string_clean(&search_path);
    return retval;
}

bool amxp_expr_eval_var(amxp_expr_t* expr,
                        const amxc_var_t* const data,
                        amxp_expr_status_t* status) {
    bool rv = false;
    when_null(data, exit);
    when_true(amxc_var_type_of(data) != AMXC_VAR_ID_HTABLE, exit);

    rv = amxp_expr_evaluate(expr, amxp_expr_get_field_var, (void*) data, status);

exit:
    return rv;
}

amxp_expr_status_t amxp_expr_get_field_var(UNUSED amxp_expr_t* expr,
                                           amxc_var_t* value,
                                           const char* path,
                                           void* priv) {
    amxp_expr_status_t status = amxp_expr_status_unknown_error;
    amxc_var_t* data = (amxc_var_t*) priv;
    amxc_var_t* field = NULL;

    if(path && (path[0] == '.')) {
        field = amxc_var_get_path(data, path + 1, AMXC_VAR_FLAG_DEFAULT);
    } else {
        field = amxc_var_get_path(data, path, AMXC_VAR_FLAG_DEFAULT);
    }
    if(amxc_var_copy(value, field) == 0) {
        status = amxp_expr_status_ok;
    }

    return status;
}

int amxp_expr_find_var_paths(const amxc_var_t* const var,
                             amxc_llist_t* paths,
                             const char* path) {
    int retval = 0;
    amxc_llist_t parts;
    amxc_llist_t vars;

    amxc_llist_init(&parts);
    amxc_llist_init(&vars);

    when_null(var, exit);
    when_null(paths, exit);
    when_str_empty(path, exit);

    retval = var_build_parts(&parts, path);
    when_failed(retval, exit);
    var_collector_new("", var, &vars);
    var_collect(&vars, &parts);

    amxc_llist_for_each(it, &vars) {
        var_collector_t* c = amxc_container_of(it, var_collector_t, it);
        amxc_llist_append(paths, &c->path->it);
        c->path = NULL;
    }

exit:
    amxc_llist_clean(&parts, amxc_string_list_it_free);
    amxc_llist_clean(&vars, var_collector_it_free);
    return retval;
}

int amxp_expr_find_var_values(const amxc_var_t* const var,
                              amxc_htable_t* values,
                              const char* path) {
    int retval = 0;
    amxc_llist_t parts;
    amxc_llist_t vars;

    amxc_llist_init(&parts);
    amxc_llist_init(&vars);

    when_null(var, exit);
    when_null(values, exit);
    when_str_empty(path, exit);

    retval = var_build_parts(&parts, path);
    when_failed(retval, exit);
    var_collector_new("", var, &vars);
    var_collect(&vars, &parts);

    amxc_llist_for_each(it, &vars) {
        var_collector_t* c = amxc_container_of(it, var_collector_t, it);
        amxc_var_t* value = NULL;
        amxc_var_new(&value);
        amxc_var_copy(value, c->var);
        amxc_htable_insert(values, amxc_string_get(c->path, 0), &value->hit);
    }

exit:
    amxc_llist_clean(&parts, amxc_string_list_it_free);
    amxc_llist_clean(&vars, var_collector_it_free);
    return retval;
}

amxc_var_t* amxp_expr_find_var(const amxc_var_t* const var,
                               const char* path) {
    const amxc_var_t* retval = NULL;
    int rv = 0;
    var_collector_t* first = NULL;
    amxc_llist_t parts;
    amxc_llist_t vars;

    amxc_llist_init(&parts);
    amxc_llist_init(&vars);

    when_null(var, exit);
    when_str_empty(path, exit);

    rv = var_build_parts(&parts, path);
    when_failed(rv, exit);

    var_collector_new("", var, &vars);
    var_collect(&vars, &parts);

    if(amxc_llist_is_empty(&vars)) {
        goto exit;
    }

    first = amxc_container_of(amxc_llist_get_first(&vars), var_collector_t, it);
    if((first == NULL) || (amxc_llist_it_get_next(&first->it) != NULL)) {
        goto exit;
    }

    retval = first->var;

exit:
    amxc_llist_clean(&parts, amxc_string_list_it_free);
    amxc_llist_clean(&vars, var_collector_it_free);
    return (amxc_var_t*) retval;
}
