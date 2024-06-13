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
#include <stdio.h>
#include <ctype.h>
#include <limits.h>
#include <errno.h>

#include <amxc/amxc.h>
#include <amxp/amxp.h>

#include <amxd/amxd_object.h>
#include <amxd/amxd_path.h>

#include "amxd_priv.h"
#include "amxd_object_priv.h"
#include "amxd_assert.h"

static bool amxd_build_path_common(amxc_string_t* path_part, amxc_var_t* path_parts,
                                   const char* token, bool* quotes, bool* sb, bool* cb) {
    bool dot = false;
    switch(token[0]) {
    case '"':
    case '\'':
        amxc_string_append(path_part, token, 1);
        (*quotes) = !(*quotes);
        break;
    case '*':
        amxc_string_append(path_part, token, 1);
        if(!(*quotes)) {
            amxc_var_add(cstring_t, path_parts, amxc_string_get(path_part, 0));
            amxc_string_reset(path_part);
        }
        break;
    case '[':
        if(!(*quotes)) {
            *sb = true;
        }
        amxc_string_append(path_part, token, 1);
        break;
    case ']':
        amxc_string_append(path_part, token, 1);
        if(!(*quotes)) {
            amxc_var_add(cstring_t, path_parts, amxc_string_get(path_part, 0));
            amxc_string_reset(path_part);
            *sb = false;
        }
        break;
    case '{':
        *cb = true;
        amxc_string_append(path_part, token, 1);
        break;
    case '}':
        amxc_string_append(path_part, token, 1);
        amxc_var_add(cstring_t, path_parts, amxc_string_get(path_part, 0));
        amxc_string_reset(path_part);
        *cb = false;
        break;
    case '.':
        amxc_string_append(path_part, token, 1);
        dot = !(*quotes) && !(*sb);
        break;
    case '+':
    case '#':
        if(!(*quotes) && !(*sb)) {
            amxc_var_add(cstring_t, path_parts, amxc_string_get(path_part, 0));
            amxc_string_reset(path_part);
            amxc_string_append(path_part, token, 1);
            dot = !(*quotes) && !(*sb);
        } else if(*sb) {
            amxc_string_append(path_part, token, 1);
        }
        break;
    default:
        amxc_string_append(path_part, token, 1);
        break;
    }
    return dot;
}

static amxc_string_split_status_t amxd_build_path_parts(amxc_llist_t* all,
                                                        amxc_var_t* path_parts) {
    bool quotes = false;
    bool sb = false;
    bool cb = false;
    amxc_string_t path_part;

    amxc_var_set_type(path_parts, AMXC_VAR_ID_LIST);

    amxc_string_init(&path_part, 0);
    amxc_llist_for_each(it, all) {
        amxc_string_t* part = amxc_string_from_llist_it(it);
        const char* txt_part = amxc_string_get(part, 0);
        if(amxc_string_text_length(part) == 1) {
            if(amxd_build_path_common(&path_part, path_parts, txt_part, &quotes, &sb, &cb)) {
                amxc_var_add(cstring_t, path_parts, amxc_string_get(&path_part, 0));
                amxc_string_reset(&path_part);
            }
        } else {
            amxc_string_append(&path_part, amxc_string_get(part, 0), amxc_string_text_length(part));
        }
    }
    if(amxc_string_text_length(&path_part) > 0) {
        amxc_var_add(cstring_t, path_parts, amxc_string_get(&path_part, 0));
    }
    amxc_string_clean(&path_part);
    return AMXC_STRING_SPLIT_OK;
}

static amxd_path_type_t amxd_path_is(amxd_path_t* path) {
    bool has_supported = false;
    bool has_search = false;
    bool has_ref_index = false;
    amxd_path_type_t type = amxd_path_object;

    path->ref_index = 1;

    amxc_var_for_each(part, (&path->parts)) {
        const char* path_str = amxc_var_constcast(cstring_t, part);
        if(has_ref_index) {
            char* endptr = NULL;
            path->ref_index = labs(strtol(path_str, &endptr, 0));
            when_true_status(((errno == ERANGE) && ((path->ref_index == 0) || (path->ref_index == ULONG_MAX))) ||
                             ((errno != 0) && (path->ref_index == 0)),
                             exit,
                             type = amxd_path_invalid);
            when_true_status((endptr == path_str) || (*endptr != '\0'),
                             exit,
                             type = amxd_path_invalid);
            has_ref_index = false;
            continue;
        }
        switch(path_str[0]) {
        case '{':
            if(strncmp(path_str, "{i}", 3) != 0) {
                type = amxd_path_invalid;
                goto exit;
            }
            has_supported = true;
            break;
        case '*':
        case '[':
            has_search = true;
            break;
        case '"':
        case '\'':
            type = amxd_path_invalid;
            goto exit;
            break;
        case '+':
            type = amxd_path_reference;
            goto exit;
            break;
        case '#':
            has_ref_index = true;
            break;
        }
    }

    if(path->param != NULL) {
        if((path->param[0] == '{') && has_search) {
            type = amxd_path_invalid;
            goto exit;
        }
    }

    if(has_supported && !has_search) {
        type = amxd_path_supported;
    } else if(!has_supported && has_search) {
        type = amxd_path_search;
    } else if(has_supported && has_search) {
        type = amxd_path_invalid;
    }

    path->ref_index = (type != amxd_path_reference)? 0:path->ref_index;

exit:
    return type;
}

static amxd_status_t amxd_path_take_param(amxd_path_t* path) {
    amxd_status_t status = amxd_status_ok;
    amxc_llist_it_t* last = amxc_llist_get_last(&path->parts.data.vl);
    amxc_var_t* last_part = amxc_var_from_llist_it(last);
    const char* name = amxc_var_constcast(cstring_t, last_part);
    int length = 0;

    when_str_empty(name, exit);
    length = strlen(name);

    if(name[length - 1] != '.') {
        path->param = amxc_var_take(cstring_t, last_part);

        if(path->param[0] == '[') {
            status = amxd_status_invalid_path;
            amxc_var_push(cstring_t, last_part, path->param);
            path->param = NULL;
            goto exit;
        }

        amxc_llist_it_take(last);

        if(amxc_llist_is_empty(&path->parts.data.vl)) {
            amxc_var_set(cstring_t, last_part, ".");
            amxc_llist_append(&path->parts.data.vl, last);
        } else {
            amxc_var_delete(&last_part);
        }

        amxc_string_reset(&path->path);
        amxc_string_join_var(&path->path, &path->parts, "");
    }

exit:
    return status;
}

static amxd_status_t amxd_path_split(amxd_path_t* path,
                                     amxc_string_split_builder_t fn) {
    amxd_status_t status = amxd_status_unknown_error;

    amxc_var_set_type(&path->parts, AMXC_VAR_ID_LIST);
    when_true_status(amxc_string_is_empty(&path->path),
                     exit,
                     status = amxd_status_ok);

    if(fn == NULL) {
        fn = amxd_build_path_parts;
    }

    if(amxc_string_split(&path->path,
                         &path->parts,
                         fn,
                         &path->reason) != AMXC_STRING_SPLIT_OK) {
        status = amxd_status_invalid_path;
        amxc_var_clean(&path->parts);
        goto exit;
    }
    status = amxd_path_take_param(path);

exit:
    return status;
}

static int isdot(int c) {
    return (c == '.') ? 1 : 0;
}

static void amxd_path_add_dot(amxd_path_t* path, bool add_dot) {
    if(!amxc_string_is_empty(&path->path) && add_dot) {
        if(path->path.buffer[path->path.last_used - 1] != '.') {
            amxc_string_append(&path->path, ".", 1);
        }
    }
}

static amxd_status_t amxd_path_validate(amxd_path_t* path) {
    amxd_status_t status = amxd_status_ok;
    if((path->path.last_used > 0) &&
       ( path->path.buffer[path->path.last_used - 1] == '*')) {
        path->type = amxd_path_invalid;
        status = amxd_status_invalid_path;
        goto exit;
    }
    status = amxd_path_split(path, NULL);
    if(status != amxd_status_ok) {
        path->type = amxd_path_invalid;
    } else {
        path->type = amxd_path_is(path);
        status = path->type == amxd_path_invalid ? amxd_status_invalid_path : amxd_status_ok;
    }

exit:
    return status;
}

amxd_status_t amxd_path_init(amxd_path_t* path,
                             const char* object_path) {
    amxd_status_t status = amxd_status_unknown_error;

    when_null(path, exit);

    amxc_var_init(&path->parts);
    amxc_var_set_type(&path->parts, AMXC_VAR_ID_LIST);

    amxc_string_init(&path->path, 0);
    path->reason = NULL;
    path->param = NULL;

    if(object_path != NULL) {
        when_failed(amxc_string_setf(&path->path, "%s", object_path), exit);
    }

    status = amxd_path_validate(path);

exit:
    return status;
}

void amxd_path_clean(amxd_path_t* path) {
    when_null(path, exit);

    amxc_var_clean(&path->parts);
    amxc_string_clean(&path->path);
    path->reason = NULL;
    free(path->param);
    path->param = NULL;
    path->type = amxd_path_invalid;

exit:
    return;
}

amxd_status_t amxd_path_new(amxd_path_t** path,
                            const char* object_path) {
    amxd_status_t status = amxd_status_unknown_error;

    when_null(path, exit);
    *path = (amxd_path_t*) calloc(1, sizeof(amxd_path_t));

    status = amxd_path_init((*path), object_path);

exit:
    return status;
}

void amxd_path_delete(amxd_path_t** path) {
    when_null(path, exit);
    amxd_path_clean(*path);

    free(*path);
    *path = NULL;

exit:
    return;
}

void amxd_path_reset(amxd_path_t* path) {
    when_null(path, exit);

    amxc_string_reset(&path->path);
    amxc_var_clean(&path->parts);
    path->type = amxd_path_invalid;
    path->reason = NULL;
    free(path->param);
    path->param = NULL;

exit:
    return;
}

amxd_status_t amxd_path_vsetf(amxd_path_t* path,
                              bool add_dot,
                              const char* obj_path,
                              va_list args) {
    amxd_status_t status = amxd_status_unknown_error;

    when_null(path, exit);
    when_str_empty(obj_path, exit);

    amxd_path_reset(path);

    amxc_string_vsetf(&path->path, obj_path, args);

    amxd_path_add_dot(path, add_dot);

    status = amxd_path_validate(path);

exit:
    return status;
}

amxd_status_t amxd_path_setf(amxd_path_t* path,
                             bool add_dot,
                             const char* obj_path, ...) {
    amxd_status_t status = amxd_status_unknown_error;
    va_list args;

    when_null(path, exit);
    when_str_empty(obj_path, exit);

    va_start(args, obj_path);
    status = amxd_path_vsetf(path, add_dot, obj_path, args);
    va_end(args);

exit:
    return status;
}

amxd_status_t amxd_path_append(amxd_path_t* path, const char* extension, bool add_dot) {
    amxd_status_t status = amxd_status_unknown_error;

    when_null(path, exit);
    when_str_empty(extension, exit);

    amxc_string_appendf(&path->path, "%s", extension);
    amxd_path_add_dot(path, add_dot);

    status = amxd_path_validate(path);

exit:
    return status;
}

amxd_status_t amxd_path_prepend(amxd_path_t* path, const char* extension) {
    amxd_status_t status = amxd_status_unknown_error;

    when_null(path, exit);
    when_str_empty(extension, exit);

    amxc_string_prependf(&path->path, "%s", extension);

    status = amxd_path_validate(path);

exit:
    return status;
}

const char* amxd_path_get(amxd_path_t* path, int flags) {
    size_t length = 0;
    const char* obj_path = NULL;

    when_null(path, exit)
    when_true(amxc_string_is_empty(&path->path), exit);

    length = amxc_string_text_length(&path->path);
    obj_path = amxc_string_get(&path->path, 0);

    if(flags & AMXD_OBJECT_TERMINATE) {
        if(obj_path[length - 1] != '.') {
            amxc_string_append(&path->path, ".", 1);
        }
    } else {
        amxc_string_trimr(&path->path, isdot);
    }

    obj_path = amxc_string_get(&path->path, 0);

exit:
    if(obj_path == NULL) {
        obj_path = "";
    }
    return obj_path;
}

const char* amxd_path_get_param(amxd_path_t* path) {
    return path == NULL ? NULL : path->param;
}

char* amxd_path_get_first(amxd_path_t* path, bool remove) {
    amxc_string_t first_part;
    char* first = NULL;
    amxc_var_t* path_part = NULL;
    int length = 0;
    const char* path_str = NULL;
    amxc_string_init(&first_part, 0);

    when_null(path, exit);
    when_true(amxc_llist_is_empty(&path->parts.data.vl), exit);

    path_part = amxc_var_from_llist_it(amxc_llist_get_first(&path->parts.data.vl));
    path_str = amxc_var_constcast(cstring_t, path_part);
    length = strlen(path_str);
    amxc_string_append(&first_part, path_str, length);
    if(remove) {
        amxc_var_delete(&path_part);
    }

    if(remove) {
        amxc_string_reset(&path->path);
        amxc_string_join_var(&path->path, &path->parts, "");
    }

exit:
    first = amxc_string_take_buffer(&first_part);
    amxc_string_clean(&first_part);
    return first;
}

char* amxd_path_get_last(amxd_path_t* path, bool remove) {
    amxc_string_t last_part;
    char* last = NULL;
    amxc_var_t* path_part = NULL;
    int length = 0;
    const char* path_str = NULL;
    amxc_string_init(&last_part, 0);

    when_null(path, exit);
    when_true(amxc_llist_is_empty(&path->parts.data.vl), exit);

    path_part = amxc_var_from_llist_it(amxc_llist_get_last(&path->parts.data.vl));
    path_str = amxc_var_constcast(cstring_t, path_part);
    length = strlen(path_str);
    amxc_string_prepend(&last_part, path_str, length);

    if(path_str[0] == '.') {
        amxc_llist_it_t* prev = NULL;
        if(remove) {
            amxc_var_delete(&path_part);
            prev = amxc_llist_get_last(&path->parts.data.vl);
        } else {
            prev = amxc_llist_it_get_previous(amxc_llist_get_last(&path->parts.data.vl));
        }
        if(prev != NULL) {
            path_part = amxc_var_from_llist_it(prev);
            path_str = amxc_var_constcast(cstring_t, path_part);
            length = strlen(path_str);
            amxc_string_prepend(&last_part, path_str, length);
        }
    }

    if(remove) {
        amxc_var_delete(&path_part);
        amxc_string_reset(&path->path);
        amxc_string_join_var(&path->path, &path->parts, "");
    }
    path->type = amxd_path_is(path);

exit:
    last = amxc_string_take_buffer(&last_part);
    amxc_string_clean(&last_part);
    return last;
}

char* amxd_path_get_fixed_part(amxd_path_t* path, bool remove) {
    amxc_string_t fixed_part;
    char* fixed = NULL;
    amxc_string_init(&fixed_part, 0);

    when_null(path, exit);

    amxc_var_for_each(path_part, (&path->parts)) {
        int length = 0;
        const char* path_str = amxc_var_constcast(cstring_t, path_part);
        if((path_str[0] == '*') ||
           (path_str[0] == '[') ||
           (path_str[0] == '{') ||
           (path_str[0] == '+') ||
           (path_str[0] == '#')) {
            break;
        }
        length = strlen(path_str);
        amxc_string_append(&fixed_part, path_str, length);
        if(remove) {
            amxc_var_delete(&path_part);
        }
    }

    if(remove) {
        amxc_string_reset(&path->path);
        amxc_string_join_var(&path->path, &path->parts, "");
    }

exit:
    fixed = amxc_string_take_buffer(&fixed_part);
    amxc_string_clean(&fixed_part);
    return fixed;
}

char* amxd_path_get_supported_path(amxd_path_t* path) {
    amxc_string_t sup_path;
    char* supported = NULL;
    amxc_string_init(&sup_path, 0);

    when_null(path, exit);

    amxc_var_for_each(path_part, (&path->parts)) {
        int length = 0;
        const char* path_str = amxc_var_constcast(cstring_t, path_part);
        if(path_str[0] == '{') {
            continue;
        }
        if(isdigit(path_str[0])) {
            continue;
        }
        length = strlen(path_str);
        if((path_str[0] == '.') && (length == 1)) {
            continue;
        }
        amxc_string_append(&sup_path, path_str, strlen(path_str));
    }

exit:
    supported = amxc_string_take_buffer(&sup_path);
    amxc_string_clean(&sup_path);
    return supported;
}

char* amxd_path_get_reference_part(amxd_path_t* path, bool remove) {
    amxc_string_t ref_part;
    char* ref = NULL;
    bool has_ref_index = false;
    amxc_string_init(&ref_part, 0);

    when_null(path, exit);

    amxc_var_for_each(path_part, (&path->parts)) {
        int length = 0;
        const char* path_str = amxc_var_constcast(cstring_t, path_part);
        if(has_ref_index) {
            if(remove) {
                amxc_var_delete(&path_part);
            }
            has_ref_index = false;
            continue;
        }
        if(path_str[0] == '+') {
            if(remove) {
                amxc_var_delete(&path_part);
            }
            break;
        }
        if(path_str[0] == '#') {
            if(remove) {
                amxc_var_delete(&path_part);
            }
            has_ref_index = true;
            continue;
        }
        length = strlen(path_str);
        amxc_string_append(&ref_part, path_str, length);
        if(remove) {
            amxc_var_delete(&path_part);
        }
    }

    if(remove) {
        amxc_string_reset(&path->path);
        amxc_string_join_var(&path->path, &path->parts, "");
    }

exit:
    ref = amxc_string_take_buffer(&ref_part);
    amxc_string_clean(&ref_part);
    return ref;
}

uint32_t amxd_path_get_reference_index(amxd_path_t* path) {
    uint32_t index = 0;
    when_null(path, exit);

    index = path->ref_index;

exit:
    return index;
}

char* amxd_path_build_supported_path(amxd_path_t* path) {
    amxc_string_t sup_path;
    char* supported = NULL;
    char* endptr = NULL;

    amxc_string_init(&sup_path, 0);
    when_null(path, exit);

    amxc_var_for_each(path_part, (&path->parts)) {
        int length = 0;
        const char* path_str = amxc_var_constcast(cstring_t, path_part);
        if((path_str[0] == '*') || (path_str[0] == '[')) {
            amxc_string_append(&sup_path, "{i}.", 4);
            continue;
        }
        length = strlen(path_str);
        if((path_str[0] == '.') && (length == 1)) {
            continue;
        }

        strtoll(path_str, &endptr, 0);
        if((endptr == path_str) || (*endptr != '.')) {
            amxc_string_append(&sup_path, path_str, strlen(path_str));
        } else {
            amxc_string_append(&sup_path, "{i}.", 4);
        }
    }

exit:
    supported = amxc_string_take_buffer(&sup_path);
    amxc_string_clean(&sup_path);
    return supported;
}

char* amxd_path_build_search_path(amxd_path_t* path) {
    amxc_string_t search_path;
    char* search = NULL;

    amxc_string_init(&search_path, 0);
    when_null(path, exit);

    amxc_var_for_each(path_part, (&path->parts)) {
        const char* path_str = amxc_var_constcast(cstring_t, path_part);
        if((path_str[0] == '{')) {
            amxc_string_append(&search_path, "*", 1);
            continue;
        }
        amxc_string_append(&search_path, path_str, strlen(path_str));
    }
    if(path->param != NULL) {
        if((path->param[0] == '{')) {
            amxc_string_append(&search_path, "*.", 2);
        } else {
            amxc_string_append(&search_path, path->param, strlen(path->param));
        }
    }

exit:
    search = amxc_string_take_buffer(&search_path);
    amxc_string_clean(&search_path);
    return search;
}

uint32_t amxd_path_get_depth(const amxd_path_t* const path) {
    uint32_t level = 0;

    when_null(path, exit);
    when_true(amxc_var_type_of(&path->parts) != AMXC_VAR_ID_LIST, exit);

    amxc_var_for_each(path_part, (&path->parts)) {
        int length = 0;
        const char* path_str = amxc_var_constcast(cstring_t, path_part);
        length = strlen(path_str);
        if((path_str[0] == '.') && (length == 1)) {
            continue;
        }
        level++;
    }

exit:
    return level;
}

bool amxd_path_is_instance_path(const amxd_path_t* const path) {
    bool is_instance = false;
    const amxc_llist_t* parts = NULL;
    amxc_llist_it_t* part_it = NULL;
    const char* part_txt = NULL;
    char* endptr = NULL;

    when_null(path, exit);
    when_true(amxc_var_type_of(&path->parts) != AMXC_VAR_ID_LIST, exit);

    parts = amxc_var_constcast(amxc_llist_t, &path->parts);
    part_it = amxc_llist_get_last(parts);
    when_null(part_it, exit);

    part_txt = amxc_var_constcast(cstring_t, amxc_var_from_llist_it(part_it));
    if((part_txt != NULL) && (*part_txt == '.')) {
        part_it = amxc_llist_it_get_previous(part_it);
        when_null(part_it, exit);
        part_txt = amxc_var_constcast(cstring_t, amxc_var_from_llist_it(part_it));
    }
    when_null(part_txt, exit);

    strtoll(part_txt, &endptr, 0);
    if((endptr == NULL) || (*endptr == '.')) {
        is_instance = true;
    }
    if((part_txt[0] == '[') || (part_txt[0] == '*')) {
        is_instance = true;
    }

exit:
    return is_instance;
}

char* amxd_path_get_param_path(amxd_path_t* path) {
    char* result = NULL;
    amxc_string_t param_path;

    amxc_string_init(&param_path, 0);

    when_null(path, exit);
    when_true(amxc_string_is_empty(&path->path), exit);
    when_str_empty(path->param, exit);

    amxc_string_setf(&param_path, "%s%s", amxc_string_get(&path->path, 0), path->param);
    result = amxc_string_take_buffer(&param_path);

exit:
    amxc_string_clean(&param_path);
    return result;
}
