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

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

#include <amxc/amxc_string.h>
#include <amxc/amxc_string_split.h>
#include <amxc/amxc_variant_type.h>
#include <amxc_variant_priv.h>
#include <amxc/amxc_utils.h>
#include <amxc/amxc_macros.h>

static amxc_var_t* amxc_var_find(amxc_var_t* const var,
                                 const char* const path,
                                 const int flags) {
    amxc_var_t* retval = NULL;
    amxc_string_t str_path;
    amxc_llist_t parts;

    amxc_string_init(&str_path, 0);
    amxc_llist_init(&parts);

    amxc_string_set(&str_path, path);
    amxc_string_split_to_llist(&str_path, &parts, '.');
    amxc_string_clean(&str_path);

    retval = var;

    amxc_llist_for_each(it, &parts) {
        amxc_string_t* key = amxc_container_of(it, amxc_string_t, it);
        size_t len = amxc_string_text_length(key);
        uint32_t offset = 0;
        char* token = amxc_string_take_buffer(key);
        amxc_var_t* temp = NULL;

        // skip empty parts
        if((token == NULL) || (*token == 0)) {
            free(token);
            continue;
        }

        if((token[0] == '\'') || (token[0] == '"')) {
            token[len - 1] = 0;
            offset = 1;
        }

        temp = amxc_var_get_key(retval, token + offset, AMXC_VAR_FLAG_DEFAULT);
        if((temp == NULL) && ((flags & AMXC_VAR_FLAG_NO_INDEX) == 0)) {
            char* endptr = NULL;
            int index = strtol(token + offset, &endptr, 0);
            if(*endptr == 0) {
                temp = amxc_var_get_index(retval, index, AMXC_VAR_FLAG_DEFAULT);
            }
        }

        if((temp == NULL) && ((flags & AMXC_VAR_FLAG_AUTO_ADD) != 0)) {
            if(amxc_var_type_of(retval) == AMXC_VAR_ID_LIST) {
                temp = amxc_var_add_new(retval);
            } else if(amxc_var_type_of(retval) == AMXC_VAR_ID_HTABLE) {
                temp = amxc_var_add_new_key(retval, token + offset);
            } else if(amxc_var_type_of(retval) == AMXC_VAR_ID_NULL) {
                amxc_var_set_type(retval, AMXC_VAR_ID_HTABLE);
                temp = amxc_var_add_new_key(retval, token + offset);
            }
        }

        retval = temp;
        free(token);
        amxc_string_delete(&key);

        if(temp == NULL) {
            break;
        }
    }

    amxc_string_clean(&str_path);
    amxc_llist_clean(&parts, amxc_string_list_it_free);

    return (amxc_var_t*) retval;
}

int PRIVATE amxc_var_default_copy(amxc_var_t* const dest,
                                  const amxc_var_t* const src) {
    dest->data = src->data;
    return 0;
}

int PRIVATE amxc_var_default_move(amxc_var_t* const dest,
                                  amxc_var_t* const src) {
    dest->data = src->data;
    src->data.data = NULL;
    return 0;
}

int PRIVATE amxc_var_default_convert_to_null(amxc_var_t* const dest,
                                             UNUSED const amxc_var_t* const src) {
    dest->data.data = NULL;
    return 0;
}

int PRIVATE amxc_var_default_convert_to_list(amxc_var_t* const dest,
                                             const amxc_var_t* const src) {
    int retval = -1;
    amxc_var_t* var = NULL;

    if(amxc_var_new(&var) != 0) {
        amxc_llist_clean(&dest->data.vl, NULL);
        goto exit;
    }

    amxc_var_copy(var, src);
    amxc_llist_append(&dest->data.vl, &var->lit);

    retval = 0;

exit:
    return retval;
}

int PRIVATE amxc_var_default_convert_to_htable(amxc_var_t* const dest,
                                               const amxc_var_t* const src) {
    int retval = -1;
    amxc_var_t* var = NULL;

    if(amxc_var_new(&var) != 0) {
        amxc_htable_clean(&dest->data.vm, NULL);
        goto exit;
    }

    amxc_var_copy(var, src);
    amxc_htable_insert(&dest->data.vm, "1", &var->hit);

    retval = 0;

exit:
    return retval;
}


int amxc_var_new(amxc_var_t** var) {
    int retval = -1;
    when_null(var, exit);

    *var = (amxc_var_t*) calloc(1, sizeof(amxc_var_t));
    when_null(*var, exit);

    retval = amxc_var_init(*var);

exit:
    return retval;
}

void amxc_var_delete(amxc_var_t** var) {
    when_null(var, exit);

    if(*var != NULL) {
        amxc_var_clean(*var);
        amxc_llist_it_clean(&((*var)->lit), NULL);
        amxc_htable_it_clean(&((*var)->hit), NULL);
    }

    free(*var);
    *var = NULL;

exit:
    return;
}

int amxc_var_init(amxc_var_t* const var) {
    int retval = -1;
    when_null(var, exit);

    var->type_id = 0;
    var->data.data = NULL;
    when_failed(amxc_llist_it_init(&var->lit), exit);
    when_failed(amxc_htable_it_init(&var->hit), exit);
    retval = 0;

exit:
    return retval;
}

void amxc_var_clean(amxc_var_t* const var) {
    amxc_var_type_t* var_type = NULL;
    when_null(var, exit);

    var_type = amxc_var_get_type(var->type_id);
    // ISSUE: No type available anymore, probably unregister,
    //        dangling variant !!
    if(var_type == NULL) {
        goto clean;
    }

    if((var_type != NULL) &&
       (var_type->del != NULL)) {
        var_type->del(var);
    }

clean:
    var->type_id = 0;
    var->data.data = NULL;

exit:
    return;
}

int amxc_var_set_type(amxc_var_t* const var, const amxc_var_type_id_t type) {
    int retval = -1;
    amxc_var_type_t* var_type = NULL;
    when_null(var, exit);

    var_type = amxc_var_get_type(type);
    when_null(var_type, exit);

    // first clean the variant
    // this to make sure all allocated memory for the content of the variant
    // is freed
    amxc_var_clean(var);

    var->type_id = type;
    if(var_type->init != NULL) {
        retval = var_type->init(var);
    } else {
        retval = 0;
    }

exit:
    return retval;
}

int amxc_var_copy(amxc_var_t* const dest, const amxc_var_t* const src) {
    int retval = -1;
    amxc_var_type_t* type = NULL;
    when_null(dest, exit);
    when_null(src, exit);

    // reset destinationn variant
    amxc_var_clean(dest);
    // get the type function pointers of the src
    type = amxc_var_get_type(src->type_id);
    when_null(type, exit);
    when_null(type->copy, exit);

    when_failed(amxc_var_set_type(dest, src->type_id), exit);
    retval = type->copy(dest, src);
    if(retval != 0) {
        amxc_var_clean(dest);
    }

exit:
    return retval;
}

int amxc_var_move(amxc_var_t* const dest, amxc_var_t* const src) {
    int retval = -1;
    amxc_var_type_t* type = NULL;
    when_null(dest, exit);
    when_null(src, exit);

    // reset destinationn variant
    amxc_var_clean(dest);
    // get the type function pointers of the src
    type = amxc_var_get_type(src->type_id);
    when_null(type, exit);
    when_null(type->move, exit);

    when_failed(amxc_var_set_type(dest, src->type_id), exit);
    retval = type->move(dest, src);
    if(retval != 0) {
        amxc_var_clean(dest);
    } else {
        amxc_var_clean(src);
    }

exit:
    return retval;
}

int amxc_var_convert(amxc_var_t* const dest,
                     const amxc_var_t* const src,
                     amxc_var_type_id_t type_id) {
    int retval = -1;
    amxc_var_type_t* src_type = NULL;
    amxc_var_type_t* dst_type = NULL;
    when_null(dest, exit);
    when_null(src, exit);

    src_type = amxc_var_get_type(src->type_id);
    when_null(src_type, exit);

    if(type_id != AMXC_VAR_ID_ANY) {
        dst_type = amxc_var_get_type(type_id);
        when_null(dst_type, exit);
        when_failed(amxc_var_set_type(dest, type_id), exit);
    } else {
        when_failed(amxc_var_set_type(dest, AMXC_VAR_ID_NULL), exit);
        dest->type_id = AMXC_VAR_ID_ANY;
    }

    // try to convert src to dst using covert_to function from src type
    retval = src_type->convert_to != NULL ?
        src_type->convert_to(dest, src) : -1;
    when_true(retval == 0, exit);

    if(type_id != AMXC_VAR_ID_ANY) {
        // try to convert src to dst using covert_from function from dest type
        retval = dst_type->convert_from != NULL ?
            dst_type->convert_from(dest, src) : -1;
    }

exit:
    if(retval != 0) {
        amxc_var_clean(dest);
    }
    return retval;
}

int amxc_var_cast(amxc_var_t* const var,
                  const uint32_t type_id) {
    int retval = -1;
    amxc_var_t intermediate;

    amxc_var_init(&intermediate);
    when_null(var, exit);

    if(var->type_id == type_id) {
        retval = 0;
        goto exit;
    }

    retval = amxc_var_convert(&intermediate, var, type_id);
    when_failed(retval, exit);

    if(var->type_id != intermediate.type_id) {
        amxc_var_move(var, &intermediate);
    }

exit:
    amxc_var_clean(&intermediate);
    return retval;
}

int amxc_var_compare(const amxc_var_t* const var1,
                     const amxc_var_t* const var2,
                     int* result) {
    int retval = -1;
    amxc_var_type_t* var1_type = NULL;
    amxc_var_type_t* var2_type = NULL;
    amxc_var_t converted_var;
    amxc_var_init(&converted_var);
    when_null(result, exit);

    *result = 0;

    if((var1 == NULL) && (var2 == NULL)) {
        retval = 0;
        goto exit;
    }

    if((var1 != NULL) && (var2 == NULL)) {
        retval = 0;
        *result = 1;
        goto exit;
    }

    if(var1 == NULL) {
        retval = 0;
        *result = -1;
        goto exit;
    }

    var1_type = amxc_var_get_type(var1->type_id);
    var2_type = amxc_var_get_type(var2->type_id);

    when_null(var1_type, exit);
    when_null(var2_type, exit);

    if((var1_type->compare != NULL) &&
       ( amxc_var_convert(&converted_var,
                          var2,
                          amxc_var_type_of(var1)) == 0)) {
        retval = var1_type->compare(var1, &converted_var, result);
    } else if((var2_type->compare != NULL) &&
              ( amxc_var_convert(&converted_var,
                                 var1,
                                 amxc_var_type_of(var2)) == 0)) {
        retval = var2_type->compare(&converted_var, var2, result);
    }

exit:
    amxc_var_clean(&converted_var);
    return retval;
}

amxc_var_t* amxc_var_get_key(const amxc_var_t* const var,
                             const char* const key,
                             const int flags) {
    amxc_var_t* retval = NULL;
    amxc_var_type_t* var_type = NULL;
    when_null(var, exit);
    when_null(key, exit);
    when_true(*key == 0, exit);

    var_type = amxc_var_get_type(var->type_id);
    when_null(var_type, exit);

    retval = var_type->get_key != NULL ?
        var_type->get_key(var, key, flags) : NULL;

exit:
    return retval;
}

int amxc_var_set_key(amxc_var_t* const var,
                     const char* const key,
                     amxc_var_t* data,
                     const int flags) {
    int retval = -1;
    amxc_var_type_t* var_type = NULL;
    when_null(var, exit);
    when_null(key, exit);
    when_true(*key == 0, exit);
    when_null(data, exit);

    var_type = amxc_var_get_type(var->type_id);
    when_null(var_type, exit);

    retval = var_type->set_key != NULL ?
        var_type->set_key(var, data, key, flags) : -1;

exit:
    return retval;
}

amxc_var_t* amxc_var_get_index(const amxc_var_t* const var,
                               const int64_t index,
                               const int flags) {

    amxc_var_t* retval = NULL;
    amxc_var_type_t* var_type = NULL;
    when_null(var, exit);

    var_type = amxc_var_get_type(var->type_id);
    when_null(var_type, exit);

    retval = var_type->get_index != NULL ?
        var_type->get_index(var, index, flags) : NULL;

exit:
    return retval;
}

int amxc_var_set_index(amxc_var_t* const var,
                       const int64_t index,
                       amxc_var_t* data,
                       const int flags) {
    int retval = -1;
    amxc_var_type_t* var_type = NULL;
    when_null(var, exit);
    when_null(data, exit);

    var_type = amxc_var_get_type(var->type_id);
    when_null(var_type, exit);

    retval = var_type->set_index != NULL ?
        var_type->set_index(var, data, index, flags) : -1;

exit:
    return retval;
}

amxc_var_t* amxc_var_add_new_key(amxc_var_t* const var,
                                 const char* key) {
    amxc_var_t* data = NULL;
    amxc_var_type_t* var_type = NULL;
    int retval = -1;
    when_null(var, exit);
    when_null(key, exit);
    when_true(*key == 0, exit);

    var_type = amxc_var_get_type(var->type_id);
    when_null(var_type, exit);

    when_failed(amxc_var_new(&data), exit);
    retval = var_type->set_key != NULL ?
        var_type->set_key(var, data, key, AMXC_VAR_FLAG_DEFAULT) :
        -1;

    if(retval != 0) {
        amxc_var_delete(&data);
    }

exit:
    return data;
}

amxc_var_t* amxc_var_add_new(amxc_var_t* const var) {
    amxc_var_t* data = NULL;
    amxc_var_type_t* var_type = NULL;
    int retval = -1;
    when_null(var, exit);

    var_type = amxc_var_get_type(var->type_id);
    when_null(var_type, exit);

    when_failed(amxc_var_new(&data), exit);
    retval = var_type->set_index != NULL ?
        var_type->set_index(var, data, -1, AMXC_VAR_FLAG_DEFAULT) :
        -1;

    if(retval != 0) {
        amxc_var_delete(&data);
    }

exit:
    return data;
}

int amxc_var_add_value(amxc_var_t* const dest,
                       const amxc_var_t* const value) {
    int retval = -1;
    amxc_var_type_t* var_type = NULL;
    amxc_var_t intermediate;
    amxc_var_init(&intermediate);

    when_null(dest, exit);
    when_null(value, exit);

    var_type = amxc_var_get_type(dest->type_id);
    when_null(var_type, exit);
    when_null(var_type->add_value, exit);

    if(value->type_id != dest->type_id) {
        retval = amxc_var_convert(&intermediate, value, dest->type_id);
        when_failed(retval, exit);
        retval = var_type->add_value(dest, &intermediate);
    } else {
        retval = var_type->add_value(dest, value);
    }
    when_failed(retval, exit);

exit:
    if((retval != 0) && (dest != NULL)) {
        // Avoid having a result of a partial execution (especially for compound values)
        amxc_var_clean(dest);
    }
    amxc_var_clean(&intermediate);
    return retval;
}

amxc_var_t* amxc_var_get_path(const amxc_var_t* const var,
                              const char* const path,
                              const int flags) {
    amxc_var_t* retval = NULL;

    retval = amxc_var_find((amxc_var_t*) var, path, flags & ~AMXC_VAR_FLAG_AUTO_ADD);
    when_null(retval, exit);

    if((flags & AMXC_VAR_FLAG_COPY) == AMXC_VAR_FLAG_COPY) {
        amxc_var_t* copy = NULL;
        if(amxc_var_new(&copy) != 0) {
            retval = NULL;
            goto exit;
        }
        if(amxc_var_copy(copy, retval) != 0) {
            retval = NULL;
            free(copy);
            goto exit;
        }
        retval = copy;
    }

exit:
    return retval;
}

amxc_var_t* amxc_var_get_pathf(const amxc_var_t* const var,
                               const int flags,
                               const char* const fmt,
                               ...
                               ) {
    amxc_var_t* retval = NULL;
    amxc_string_t path;
    va_list args;

    amxc_string_init(&path, 0);
    when_null(var, exit);
    when_null(fmt, exit);

    va_start(args, fmt);
    amxc_string_vappendf(&path, fmt, args);
    va_end(args);

    retval = amxc_var_get_path(var, amxc_string_get(&path, 0), flags);

exit:
    amxc_string_clean(&path);
    return retval;
}

int amxc_var_set_path(amxc_var_t* const var,
                      const char* const path,
                      amxc_var_t* data,
                      const int flags) {
    amxc_var_t* variant = NULL;
    int retval = -1;

    variant = amxc_var_find(var, path, flags);
    when_null(variant, exit);

    if((flags & AMXC_VAR_FLAG_COPY) == AMXC_VAR_FLAG_COPY) {
        retval = amxc_var_copy(variant, data);
    } else {
        retval = amxc_var_move(variant, data);
    }

exit:
    return retval;
}

int amxc_var_set_pathf(amxc_var_t* const var,
                       amxc_var_t* data,
                       const int flags,
                       const char* const fmt,
                       ...
                       ) {
    int retval = -1;
    amxc_string_t path;
    va_list args;

    amxc_string_init(&path, 0);
    when_null(var, exit);
    when_null(fmt, exit);

    va_start(args, fmt);
    amxc_string_vappendf(&path, fmt, args);
    va_end(args);

    retval = amxc_var_set_path(var, amxc_string_get(&path, 0), data, flags);

exit:
    amxc_string_clean(&path);
    return retval;
}

amxc_var_type_id_t amxc_var_type_of(const amxc_var_t* const var) {
    return var != NULL ? var->type_id : AMXC_VAR_ID_INVALID;
}

const char* amxc_var_type_name_of(const amxc_var_t* const var) {
    return var != NULL ? amxc_var_get_type_name_from_id(var->type_id) : NULL;
}

amxc_string_t* amxc_var_take_amxc_string_t(amxc_var_t* const var) {
    amxc_string_t* retval = NULL;

    when_null(var, exit);
    when_true(amxc_var_type_of(var) != AMXC_VAR_ID_CSTRING &&
              amxc_var_type_of(var) != AMXC_VAR_ID_SSV_STRING &&
              amxc_var_type_of(var) != AMXC_VAR_ID_CSV_STRING, exit);
    when_null(var->data.s, exit);

    when_failed(amxc_string_new(&retval, 0), exit);
    when_null(retval, exit);

    amxc_string_push_buffer(retval, var->data.s, strlen(var->data.s) + 1);
    var->data.s = NULL;
    var->type_id = AMXC_VAR_ID_NULL;

exit:
    return retval;
}

int amxc_var_push_amxc_string_t(amxc_var_t* const var, amxc_string_t* val) {
    int retval = -1;
    char* buffer = NULL;

    when_null(var, exit);
    when_null(val, exit);

    amxc_var_clean(var);

    buffer = amxc_string_take_buffer(val);
    retval = amxc_var_push_cstring_t(var, buffer);

exit:
    return retval;
}

amxc_var_t* amxc_var_get_first(const amxc_var_t* const var) {
    amxc_var_t* first = NULL;

    when_null(var, exit);

    switch(amxc_var_type_of(var)) {
    case AMXC_VAR_ID_HTABLE: {
        amxc_htable_it_t* it = amxc_htable_get_first(&var->data.vm);
        when_null(it, exit);
        first = amxc_var_from_htable_it(it);
    }
    break;
    case AMXC_VAR_ID_LIST: {
        amxc_llist_it_t* it = amxc_llist_get_first(&var->data.vl);
        when_null(it, exit);
        first = amxc_var_from_llist_it(it);
    }
    break;
    default:
        break;
    }

exit:
    return first;
}

amxc_var_t* amxc_var_get_last(const amxc_var_t* const var) {
    amxc_var_t* last = NULL;

    when_null(var, exit);

    switch(amxc_var_type_of(var)) {
    case AMXC_VAR_ID_HTABLE: {
        amxc_htable_it_t* it = amxc_htable_get_last(&var->data.vm);
        when_null(it, exit);
        last = amxc_var_from_htable_it(it);
    }
    break;
    case AMXC_VAR_ID_LIST: {
        amxc_llist_it_t* it = amxc_llist_get_last(&var->data.vl);
        when_null(it, exit);
        last = amxc_var_from_llist_it(it);
    }
    break;
    default:
        break;
    }

exit:
    return last;
}

amxc_var_t* amxc_var_get_next(const amxc_var_t* const var) {
    amxc_var_t* next = NULL;

    when_null(var, exit);

    if(var->hit.ait != NULL) {
        amxc_htable_it_t* it = amxc_htable_it_get_next(&var->hit);
        when_null(it, exit);
        next = amxc_var_from_htable_it(it);
    } else if(var->lit.llist != NULL) {
        amxc_llist_it_t* it = amxc_llist_it_get_next(&var->lit);
        when_null(it, exit);
        next = amxc_var_from_llist_it(it);
    }

exit:
    return next;
}

amxc_var_t* amxc_var_get_previous(const amxc_var_t* const var) {
    amxc_var_t* prev = NULL;

    when_null(var, exit);

    if(var->hit.ait != NULL) {
        amxc_htable_it_t* it = amxc_htable_it_get_previous(&var->hit);
        when_null(it, exit);
        prev = amxc_var_from_htable_it(it);
    } else if(var->lit.llist != NULL) {
        amxc_llist_it_t* it = amxc_llist_it_get_previous(&var->lit);
        when_null(it, exit);
        prev = amxc_var_from_llist_it(it);
    }

exit:
    return prev;
}

amxc_var_t* amxc_var_get_parent(const amxc_var_t* const var) {
    amxc_var_t* parent = NULL;

    when_null(var, exit);

    if(var->hit.ait != NULL) {
        if(var->hit.ait->array != NULL) {
            amxc_htable_t* ptable = amxc_container_of(var->hit.ait->array, amxc_htable_t, table);
            parent = amxc_container_of(ptable, amxc_var_t, data);
        }
    } else if(var->lit.llist != NULL) {
        amxc_llist_t* plist = var->lit.llist;
        parent = amxc_container_of(plist, amxc_var_t, data);
    }

exit:
    return parent;
}

const char* amxc_var_key(const amxc_var_t* const var) {
    const char* key = NULL;

    when_null(var, exit);

    if(var->hit.ait != NULL) {
        key = amxc_htable_it_get_key(&var->hit);
    }

exit:
    return key;
}