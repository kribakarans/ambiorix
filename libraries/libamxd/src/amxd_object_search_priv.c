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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <amxc/amxc.h>
#include <amxp/amxp.h>

#include <amxd/amxd_types.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_object_expression.h>
#include <amxd/amxd_dm.h>
#include <amxd/amxd_dm_functions.h>

#include "amxd_priv.h"
#include "amxd_dm_priv.h"
#include "amxd_object_priv.h"
#include "amxd_assert.h"

static amxd_status_t amxd_object_resolve_next(amxd_object_t* const object,
                                              bool* key_path,
                                              amxc_llist_t* paths,
                                              amxc_llist_it_t* part);

static
amxd_object_t* amxd_template_find(amxd_object_t* const object,
                                  bool* key_path,
                                  const char* const path,
                                  amxd_status_t* status) {
    amxd_object_t* result = NULL;
    size_t length = strlen(path);
    int64_t index = 0;
    int offset = 0;
    char* endptr = NULL;

    if(path[length - 1] == '.') {
        length--;
    }
    if(path[0] == '[') {
        offset = 1;
        length -= 2;
    }

    when_true_status(length == 0,
                     exit,
                     *status = amxd_status_invalid_path);

    index = strtoll(path + offset, &endptr, 0);

    if((endptr != path) && ((*endptr == '.') || (*endptr == '\0') || (*endptr == ']'))) {
        result = amxd_object_get_instance(object, NULL, index);
    } else {
        char* copy_path = strdup(path + offset);
        copy_path[length] = 0;
        result = amxd_object_get_instance(object, copy_path, 0);
        if(result != NULL) {
            *key_path = true;
        }
        free(copy_path);
    }
    if(result == NULL) {
        *status = amxd_status_object_not_found;
    }

exit:
    return result;
}

static
amxd_object_t* amxd_object_find(amxd_object_t* const object,
                                bool* key_path,
                                const char* path,
                                amxd_status_t* status) {
    amxd_object_t* result = object;
    amxd_object_t* child = NULL;
    size_t length = strlen(path);
    when_true(length == 0, exit);

    child = amxd_object_get_child(result, path);
    if(child != NULL) {
        result = child;
    } else {
        result = amxd_template_find(object, key_path, path, status);
    }

exit:
    if(result == NULL) {
        *status = amxd_status_object_not_found;
    }
    return result;
}

static
amxd_object_t* amxd_template_find_instance(amxd_object_t* templ,
                                           bool* key_path,
                                           char* str_part,
                                           amxd_status_t* status) {
    amxd_object_t* result = NULL;
    amxd_object_t* tmp = NULL;
    amxp_expr_t expr;
    int length = 0;
    int offset = 0;

    length = strlen(str_part);
    tmp = amxd_template_find(templ, key_path, str_part, status);
    if(tmp != NULL) {
        result = tmp;
        goto exit;
    }

    when_true(*status != amxd_status_object_not_found, exit);

    if(str_part[0] == '[') {
        length = strlen(str_part);
        offset = 1;
        str_part[length - 1] = 0;
    }

    if(amxp_expr_init(&expr, str_part + offset) != 0) {
        *status = amxd_status_invalid_path;
        goto exit;
    }

    result = amxd_object_find_instance(templ, &expr);
    if(result == NULL) {
        if(expr.status != amxp_expr_status_ok) {
            *status = amxd_status_invalid_path;
        } else {
            *status = amxd_status_ok;
        }
        amxp_expr_clean(&expr);
        goto exit;
    }

    tmp = amxd_object_find_next_instance(result, &expr);
    if(tmp != NULL) {
        *status = amxd_status_duplicate;
        result = NULL;
    }

    amxp_expr_clean(&expr);

exit:
    if(str_part[0] == '[') {
        str_part[length - 1] = ']';
    }

    return result;
}

static
amxd_status_t amxd_resolve_add_path_or_continue(amxd_object_t* object,
                                                bool* key_path,
                                                amxc_llist_t* paths,
                                                amxc_llist_it_t* next) {
    amxd_status_t status = amxd_status_ok;
    if(next == NULL) {
        amxc_string_t* obj_path = NULL;
        char* path = amxd_object_get_path(object, AMXD_OBJECT_INDEXED | AMXD_OBJECT_TERMINATE);
        if(path == NULL) {
            status = amxd_status_invalid_path;
            goto exit;
        }
        amxc_string_new(&obj_path, 0);
        amxc_string_push_buffer(obj_path, path, strlen(path) + 1);
        amxc_llist_append(paths, &obj_path->it);
    } else {
        status = amxd_object_resolve_next(object, key_path, paths, next);
    }

exit:
    return status;
}

static
amxd_status_t amxd_template_add_all_instances(amxd_object_t* object,
                                              bool* key_path,
                                              amxc_llist_t* paths,
                                              amxc_llist_it_t* part) {
    amxd_status_t status = amxd_status_object_not_found;
    uint32_t count = 0;
    amxd_object_for_each(instance, it, object) {
        amxd_object_t* instance = amxc_container_of(it, amxd_object_t, it);
        status = amxd_resolve_add_path_or_continue(instance, key_path, paths, part->next);
        if(status == amxd_status_ok) {
            count++;
        }
    }

    status = (count > 0 || amxc_llist_is_empty(&object->instances)) ?
        amxd_status_ok:amxd_status_object_not_found;

    return status;
}

static
amxd_status_t amxd_template_add_matching_instances(amxd_object_t* object,
                                                   bool* key_path,
                                                   amxc_llist_t* paths,
                                                   amxc_llist_it_t* part) {
    amxd_status_t status = amxd_status_object_not_found;
    amxc_var_t* var_part = amxc_var_from_llist_it(part);
    char* txt_part = amxc_var_dyncast(cstring_t, var_part);
    amxd_object_t* tmp = NULL;
    amxp_expr_t expr;
    int length = strlen(txt_part);

    tmp = amxd_template_find(object, key_path, txt_part, &status);
    if(tmp != NULL) {
        status = amxd_resolve_add_path_or_continue(tmp, key_path, paths, part->next);
        goto exit;
    }

    if(status != amxd_status_object_not_found) {
        goto exit;
    }

    txt_part[length - 1] = 0;
    if(amxp_expr_init(&expr, txt_part + 1) != 0) {
        status = amxd_status_invalid_path;
        goto exit;
    }

    status = amxd_status_ok;
    object = amxd_object_find_instance(object, &expr);

    while(object != NULL) {
        status = amxd_resolve_add_path_or_continue(object, key_path, paths, part->next);
        when_failed_status(status, exit, amxp_expr_clean(&expr));
        object = amxd_object_find_next_instance(object, &expr);
    }

    amxp_expr_clean(&expr);

exit:
    free(txt_part);
    return status;
}

static
amxd_status_t amxd_object_resolve_instances(amxd_object_t* const object,
                                            bool* key_path,
                                            amxc_llist_t* paths,
                                            amxc_llist_it_t* part) {
    amxd_status_t status = amxd_status_ok;
    amxc_var_t* var_part = amxc_var_from_llist_it(part);
    const char* str_part = amxc_var_constcast(cstring_t, var_part);

    if(str_part[0] == '*') {
        status = amxd_template_add_all_instances(object, key_path, paths, part);
    } else {
        status = amxd_template_add_matching_instances(object, key_path, paths, part);
    }

    return status;
}

static
amxd_status_t amxd_object_resolve_next(amxd_object_t* const object,
                                       bool* key_path,
                                       amxc_llist_t* paths,
                                       amxc_llist_it_t* part) {
    amxd_status_t status = amxd_status_ok;
    amxd_object_t* result = object;
    amxc_var_t* var_part = NULL;
    const char* str_part = NULL;

    var_part = amxc_var_from_llist_it(part);
    str_part = amxc_var_constcast(cstring_t, var_part);

    switch(str_part[0]) {
    case '[':
    case '*':
        if(amxd_object_get_type(object) != amxd_object_template) {
            status = amxd_status_invalid_path;
            goto exit;
        }
        status = amxd_object_resolve_instances(object, key_path, paths, part);
        break;
    case '.':
        status = amxd_resolve_add_path_or_continue(result, key_path, paths, part->next);
        break;
    case '^':
        result = amxd_object_get_parent(result);
        status = amxd_resolve_add_path_or_continue(result, key_path, paths, part->next);
        break;
    default:
        if(amxd_object_get_type(result) == amxd_object_template) {
            result = amxd_object_find(result, key_path, str_part, &status);
            if(result == NULL) {
                status = amxd_status_ok;
            }
        } else {
            result = amxd_object_find(result, key_path, str_part, &status);
        }
        if(result != NULL) {
            status = amxd_resolve_add_path_or_continue(result, key_path, paths, part->next);
        }
        break;
    }

exit:
    return status;
}

amxd_object_t* amxd_object_find_internal(amxd_object_t* const object,
                                         bool* key_path,
                                         amxd_path_t* path,
                                         amxd_status_t* status) {
    amxd_object_t* result = object;
    char* str_part = NULL;

    amxc_var_for_each(var, (&path->parts)) {
        str_part = amxc_var_take(cstring_t, var);
        switch(str_part[0]) {
        case '*':
            *status = amxd_status_invalid_path;
            result = NULL;
            break;
        case '{':
            if(amxd_object_get_type(result) != amxd_object_template) {
                *status = amxd_status_invalid_path;
                result = NULL;
            }
            break;
        case '[':
            if(amxd_object_get_type(result) != amxd_object_template) {
                *status = amxd_status_invalid_path;
                result = NULL;
            } else {
                result = amxd_template_find_instance(result, key_path, str_part, status);
            }
            break;
        case '.':
            break;
        case '^':
            result = amxd_object_get_parent(result);
            break;
        default:
            result = amxd_object_find(result, key_path, str_part, status);
            break;
        }
        amxc_var_push(cstring_t, var, str_part);

        when_null(result, exit);
    }

exit:
    return result;
}

amxd_status_t amxd_object_resolve_internal(amxd_object_t* const object,
                                           bool* key_path,
                                           amxc_llist_t* paths,
                                           amxd_path_t* path) {
    amxd_status_t status = amxd_status_ok;
    amxc_llist_it_t* path_part_it = NULL;
    const amxc_llist_t* lparts = NULL;

    lparts = amxc_var_constcast(amxc_llist_t, &path->parts);
    path_part_it = amxc_llist_get_first(lparts);
    if(path_part_it != NULL) {
        status = amxd_object_resolve_next(object, key_path, paths, path_part_it);
    } else {
        status = amxd_resolve_add_path_or_continue(object, key_path, paths, NULL);
    }
    when_failed(status, exit);

exit:
    if(status != amxd_status_ok) {
        amxc_llist_clean(paths, amxc_string_list_it_free);
    }
    return status;
}
