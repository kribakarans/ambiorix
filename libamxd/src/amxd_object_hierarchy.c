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
#include <string.h>
#include <stdarg.h>
#include <ctype.h>

#include "amxd_priv.h"

#include <amxd/amxd_common.h>
#include <amxd/amxd_dm.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_path.h>

#include "amxd_priv.h"
#include "amxd_dm_priv.h"
#include "amxd_object_priv.h"
#include "amxd_assert.h"

static void amxd_object_hierarchy_up(amxd_object_t* const object,
                                     amxd_object_filter_fn_t filter,
                                     amxd_object_cb_fn_t cb,
                                     int32_t depth,
                                     void* priv) {
    amxd_object_t* current = object;
    while(current != NULL && depth >= 0) {
        if((filter != NULL) && !filter(current, depth, priv)) {
            break;
        }
        cb(current, depth, priv);
        current = amxd_object_get_parent(current);
        depth = depth == INT32_MAX ? INT32_MAX : depth - 1;
    }
}

static void amxd_object_hierarchy_down(amxd_object_t* const object,
                                       const amxd_direction_t direction,
                                       amxd_object_filter_fn_t filter,
                                       amxd_object_cb_fn_t cb,
                                       int32_t depth,
                                       void* priv) {
    if(depth < 0) {
        return;
    }

    if((filter != NULL) && !filter(object, depth, priv)) {
        return;
    }
    if(direction == amxd_direction_down) {
        cb(object, depth, priv);
    }

    depth = depth == INT32_MAX ? INT32_MAX : depth - 1;
    amxd_object_for_each(child, it, object) {
        amxd_object_t* child = amxc_container_of(it, amxd_object_t, it);
        amxd_object_hierarchy_down(child, direction, filter, cb, depth, priv);
    }

    amxd_object_for_each(instance, it, object) {
        amxd_object_t* instance = amxc_container_of(it, amxd_object_t, it);
        amxd_object_hierarchy_down(instance, direction, filter, cb, depth, priv);
    }
    if(direction == amxd_direction_down_reverse) {
        cb(object, depth, priv);
    }
}

static void amxd_path_prepend_instance(const amxd_object_t* object,
                                       amxc_string_t* path,
                                       const char* name,
                                       uint32_t length,
                                       const uint32_t flags) {
    if((flags & AMXD_OBJECT_SUPPORTED) != AMXD_OBJECT_SUPPORTED) {
        if((flags & AMXD_OBJECT_EXTENDED) == AMXD_OBJECT_EXTENDED) {
            if((flags & AMXD_OBJECT_REGEXP) == AMXD_OBJECT_REGEXP) {
                amxc_string_prepend(path, "\\]", 2);
            } else {
                amxc_string_prepend(path, "]", 1);
            }
        }
        if((flags & AMXD_OBJECT_INDEXED) == AMXD_OBJECT_INDEXED) {
            amxc_string_prependf(path, "%" PRId32, object->index);
        } else {
            amxc_string_prepend(path, name, length);
        }
        if((flags & AMXD_OBJECT_EXTENDED) == AMXD_OBJECT_EXTENDED) {
            if((flags & AMXD_OBJECT_REGEXP) == AMXD_OBJECT_REGEXP) {
                amxc_string_prepend(path, "\\[", 2);
            } else {
                amxc_string_prepend(path, "[", 1);
            }
        }
    }
}

static char* amxd_object_build_path(const amxd_object_t* object,
                                    const amxd_object_t* stop,
                                    const uint32_t flags) {
    amxc_string_t path;
    const amxd_object_t* current = object;
    const char* sep = NULL;
    char* str_path = NULL;
    int sep_length = 0;

    if((flags & AMXD_OBJECT_REGEXP) == AMXD_OBJECT_REGEXP) {
        sep = "\\.";
        sep_length = 2;
    } else {
        sep = ".";
        sep_length = 1;
    }

    amxc_string_init(&path, 64);

    while(current != stop &&
          amxd_object_get_name(current, flags) != NULL) {
        const char* name = amxd_object_get_name(current, flags);
        int length = strlen(name);

        if(!amxc_string_is_empty(&path) &&
           ( strncmp(path.buffer, sep, sep_length) != 0)) {
            amxc_string_prepend(&path, sep, sep_length);
        }

        if(amxd_object_get_type(current) == amxd_object_instance) {
            amxd_path_prepend_instance(current, &path, name, length, flags);
        } else {
            if(((flags & AMXD_OBJECT_SUPPORTED) == AMXD_OBJECT_SUPPORTED) &&
               ( amxd_object_get_type(current) == amxd_object_template)) {
                amxc_string_prepend(&path, "{i}", 3);
                amxc_string_prepend(&path, sep, sep_length);
            }
            amxc_string_prepend(&path, name, length);
        }
        current = amxd_object_get_parent(current);
    }

    if((flags & AMXD_OBJECT_TERMINATE) == AMXD_OBJECT_TERMINATE) {
        amxc_string_append(&path, sep, sep_length);
    }

    str_path = amxc_string_take_buffer(&path);
    amxc_string_clean(&path);

    return str_path;
}

static amxd_object_t* amxd_object_is_supported_impl(amxd_object_t* object,
                                                    amxd_path_t* path) {
    char* part = NULL;

    if(amxd_object_get_type(object) == amxd_object_template) {
        part = amxd_path_get_first(path, true);
        free(part);
    }
    part = amxd_path_get_first(path, true);
    if((part != NULL) && (part[0] == '.')) {
        free(part);
        part = amxd_path_get_first(path, true);
    }
    when_null(part, exit);
    object = amxd_object_get(object, part);
    free(part);
    when_null(object, exit);
    object = amxd_object_is_supported_impl(object, path);

exit:
    return object;
}

amxd_object_t* amxd_object_get_parent(const amxd_object_t* const object) {
    amxd_object_t* parent = NULL;
    when_null(object, exit);
    when_true(amxd_object_is_base(object), exit);
    when_true(object->type == amxd_object_mib, exit);
    when_null(object->it.llist, exit);

    if(object->type == amxd_object_instance) {
        parent = amxc_container_of(object->it.llist, amxd_object_t, instances);
    } else {
        parent = amxc_container_of(object->it.llist, amxd_object_t, objects);
    }

exit:
    return parent;
}

amxd_object_t* amxd_object_get_root(const amxd_object_t* const object) {
    amxd_object_t* root = NULL;
    when_null(object, exit);
    when_true(amxd_object_is_base(object), exit);
    when_true(object->type == amxd_object_mib, exit);

    root = amxd_object_get_parent(object);
    when_null(root, exit);

    while(root && root->it.llist != NULL) {
        root = amxd_object_get_parent(root);
    }

    if((root != NULL) && (root->type != amxd_object_root)) {
        root = NULL;
    }

exit:
    return root;
}

amxd_dm_t* amxd_object_get_dm(const amxd_object_t* const object) {
    amxd_object_t* parent = NULL;
    amxd_dm_t* dm = NULL;

    when_null(object, exit);
    when_true(amxd_object_is_base(object), exit);

    if(amxd_object_get_type(object) == amxd_object_mib) {
        when_null(object->it.llist, exit);
        dm = amxc_container_of(object->it.llist, amxd_dm_t, mibs);
        goto exit;
    } else if(amxd_object_get_type(object) == amxd_object_root) {
        dm = amxc_container_of(object, amxd_dm_t, object);
        goto exit;
    }

    parent = amxd_object_get_parent(object);
    while(parent != NULL &&
          parent->type != amxd_object_mib &&
          parent->type != amxd_object_root) {
        parent = amxd_object_get_parent(parent);
    }

    if(amxd_object_get_type(parent) == amxd_object_mib) {
        when_null(parent->it.llist, exit);
        dm = amxc_container_of(parent->it.llist, amxd_dm_t, mibs);
    } else if(amxd_object_get_type(parent) == amxd_object_root) {
        dm = amxc_container_of(parent, amxd_dm_t, object);
    }

exit:
    return dm;
}

amxd_object_t* amxd_object_get_child(const amxd_object_t* object,
                                     const char* name) {
    amxd_object_t* result = NULL;
    int length = 0;
    when_null(object, exit);
    when_str_empty(name, exit);

    length = strlen(name);
    if(name[length - 1] == '.') {
        length--;
    }

    amxc_llist_for_each(it, (&object->objects)) {
        const char* n = NULL;
        int nlen = 0;
        result = amxc_llist_it_get_data(it, amxd_object_t, it);
        n = amxd_object_get_name(result, AMXD_OBJECT_NAMED);
        nlen = strlen(n);
        if((nlen == length) && (strncmp(n, name, length) == 0)) {
            break;
        }
        result = NULL;
    }

exit:
    return result;
}

amxd_object_t* amxd_object_get_instance(const amxd_object_t* object,
                                        const char* name,
                                        uint32_t index) {
    amxd_object_t* result = NULL;
    int length = 0;
    int offset = 0;
    when_null(object, exit);

    if((name != NULL) && (name[0] != 0)) {
        amxd_param_t* alias_param = amxd_object_get_param_def(object, "Alias");
        length = strlen(name);
        if(alias_param == NULL) {
            if(name[length - 1] == '.') {
                length--;
            }
            if(name[0] == '[') {
                length = strlen(name);
                length -= 2;
                offset = 1;
            }
        }
    }

    amxc_llist_for_each(it, (&object->instances)) {
        const char* n = NULL;
        result = amxc_llist_it_get_data(it, amxd_object_t, it);
        n = amxd_object_get_name(result, AMXD_OBJECT_NAMED);
        if(index != 0) {
            if(result->index == index) {
                break;
            }
        } else {
            if((name != NULL) && (name[0] != 0)) {
                int nlen = strlen(n);
                if((nlen == length) && (strncmp(n, name + offset, length) == 0)) {
                    break;
                }
            }
        }
        result = NULL;
    }

exit:
    return result;
}

amxd_object_t* amxd_object_get(const amxd_object_t* object, const char* name) {
    amxd_object_t* result = NULL;
    when_str_empty(name, exit);

    if(amxd_object_get_type(object) == amxd_object_template) {
        if(isdigit(name[0]) == 0) {
            result = amxd_object_get_instance(object, name, 0);
        } else {
            result = amxd_object_get_instance(object, NULL, atoi(name));
        }
    }
    if(result == NULL) {
        result = amxd_object_get_child(object, name);
    }

exit:
    return result;
}

amxd_object_t* amxd_object_findf(amxd_object_t* const object,
                                 const char* rel_path,
                                 ...) {
    amxd_object_t* result = NULL;
    amxd_dm_t* dm = NULL;
    amxd_status_t status = amxd_status_ok;
    amxd_path_t path;
    va_list args;
    bool key_path = false;

    amxd_path_init(&path, NULL);

    when_null(object, exit);
    when_str_empty(rel_path, exit);

    if(!amxd_object_is_base(object)) {
        dm = amxd_object_get_dm(object);
    }

    va_start(args, rel_path);
    status = amxd_path_vsetf(&path, true, rel_path, args);
    va_end(args);
    when_failed(status, exit);

    result = amxd_object_find_internal(object, &key_path, &path, &status);

exit:
    if(dm != NULL) {
        dm->status = status;
    }
    amxd_path_clean(&path);
    return result;
}

amxd_status_t amxd_object_resolve_pathf(amxd_object_t* object,
                                        amxc_llist_t* paths,
                                        const char* rel_path,
                                        ...) {
    amxd_status_t status = amxd_status_unknown_error;
    amxd_path_t path;
    va_list args;
    bool key_path = false;

    amxd_path_init(&path, NULL);

    when_null(object, exit);
    when_true(amxd_object_is_base(object), exit);
    when_str_empty(rel_path, exit);

    va_start(args, rel_path);
    status = amxd_path_vsetf(&path, true, rel_path, args);
    va_end(args);
    when_failed(status, exit);

    status = amxd_object_resolve_internal(object, &key_path, paths, &path);

exit:
    amxd_path_clean(&path);
    return status;
}

amxd_status_t amxd_object_resolve_pathf_ext(amxd_object_t* object,
                                            bool* key_path,
                                            amxc_llist_t* paths,
                                            const char* rel_path,
                                            ...) {
    amxd_status_t status = amxd_status_unknown_error;
    amxd_path_t path;
    va_list args;

    amxd_path_init(&path, NULL);

    when_null(key_path, exit);
    when_null(object, exit);
    when_true(amxd_object_is_base(object), exit);
    when_str_empty(rel_path, exit);

    *key_path = false;

    va_start(args, rel_path);
    status = amxd_path_vsetf(&path, true, rel_path, args);
    va_end(args);
    when_failed(status, exit);

    status = amxd_object_resolve_internal(object, key_path, paths, &path);

exit:
    amxd_path_clean(&path);
    return status;
}

char* amxd_object_get_path(const amxd_object_t* object,
                           const uint32_t flags) {
    char* path = NULL;
    when_null(object, exit);
    when_true(amxd_object_is_base(object), exit);
    when_null(amxd_object_get_name(object, flags), exit);

    path = amxd_object_build_path(object, NULL, flags);

exit:
    return path;
}

char* amxd_object_get_rel_path(const amxd_object_t* child,
                               const amxd_object_t* parent,
                               const uint32_t flags) {

    char* path = NULL;
    when_null(child, exit);
    when_true(amxd_object_is_base(child), exit);
    when_null(parent, exit);
    when_true(amxd_object_is_base(parent), exit);

    when_true(!amxd_object_is_child_of(child, parent), exit);
    when_null(amxd_object_get_name(child, flags), exit);

    path = amxd_object_build_path(child, parent, flags);

exit:
    return path;
}

bool amxd_object_is_child_of(const amxd_object_t* const child,
                             const amxd_object_t* const parent) {
    amxd_object_t* upper = NULL;
    when_null(child, exit);
    when_true(amxd_object_is_base(child), exit);
    when_null(parent, exit);
    when_true(amxd_object_is_base(parent), exit);

    upper = amxd_object_get_parent(child);
    while(upper != NULL) {
        if(upper == parent) {
            break;
        }
        upper = amxd_object_get_parent(upper);
    }

exit:
    return (upper != NULL);
}

void amxd_object_hierarchy_walk(amxd_object_t* const object,
                                const amxd_direction_t direction,
                                amxd_object_filter_fn_t filter,
                                amxd_object_cb_fn_t cb,
                                int32_t depth,
                                void* priv) {
    when_null(object, exit);
    when_null(cb, exit);

    if(direction == amxd_direction_up) {
        amxd_object_hierarchy_up(object, filter, cb, depth, priv);
    } else {
        amxd_object_hierarchy_down(object, direction, filter, cb, depth, priv);
    }

exit:
    return;
}

void amxd_object_for_all(amxd_object_t* object,
                         const char* rel_spath,
                         amxd_mobject_cb_t fn,
                         void* priv) {
    amxc_llist_t paths;
    amxd_dm_t* dm = NULL;

    amxc_llist_init(&paths);

    when_null(object, exit);
    when_true(amxd_object_is_base(object), exit);
    when_null(fn, exit);
    when_str_empty(rel_spath, exit);

    dm = amxd_object_get_dm(object);

    amxd_object_resolve_pathf(object, &paths, "%s", rel_spath);

    amxc_llist_for_each(it, (&paths)) {
        amxc_string_t* path = amxc_string_from_llist_it(it);
        amxd_object_t* mobject = amxd_dm_findf(dm, "%s", amxc_string_get(path, 0));
        if(mobject != NULL) {
            fn(object, mobject, priv);
        }
    }

exit:
    amxc_llist_clean(&paths, amxc_string_list_it_free);
    return;
}

bool amxd_object_is_supported(amxd_object_t* object,
                              const char* req_path) {
    amxd_object_t* sup_obj = NULL;
    amxd_path_t path;
    amxc_llist_t paths;
    bool retval = false;

    amxd_path_init(&path, req_path);
    amxc_llist_init(&paths);

    when_null(object, exit);
    when_true(amxd_object_is_base(object), exit);

    retval = true;
    when_str_empty(req_path, exit);

    sup_obj = amxd_object_is_supported_impl(object, &path);
    when_not_null(sup_obj, exit); // object is in supported data model

    // when objects are added using mibs, they will not be visible in the
    // supported data model part.
    // therefor when the object(s) exist (at least one is found),
    // also return true
    amxd_object_resolve_pathf(object, &paths, "%s", req_path);
    retval = !amxc_llist_is_empty(&paths);

exit:
    amxc_llist_clean(&paths, amxc_string_list_it_free);
    amxd_path_clean(&path);
    return retval;
}
