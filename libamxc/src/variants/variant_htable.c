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
#include <stdio.h>

#include <amxc/amxc_string.h>
#include <amxc_variant_priv.h>

static int variant_htable_init(amxc_var_t* const var) {
    return amxc_htable_init(&var->data.vm, 10);
}

void variant_htable_it_free(UNUSED const char* key, amxc_htable_it_t* it) {
    amxc_var_t* var = amxc_var_from_htable_it(it);
    amxc_var_delete(&var);
}

static void variant_htable_delete(amxc_var_t* var) {
    amxc_htable_clean(&var->data.vm, variant_htable_it_free);
}

static int variant_htable_copy_htable(amxc_var_t* const dest,
                                      const amxc_htable_t* const src_htable) {
    int retval = -1;

    amxc_htable_for_each(it, src_htable) {
        amxc_var_t* var = NULL;
        amxc_var_t* item = amxc_var_from_htable_it(it);
        const char* key = amxc_htable_it_get_key(it);
        when_null(item, exit);
        when_failed(amxc_var_new(&var), exit);
        if(amxc_var_copy(var, item) != 0) {
            amxc_var_delete(&var);
            goto exit;
        }
        amxc_htable_insert(&dest->data.vm, key, &var->hit);
    }

    retval = 0;

exit:
    return retval;
}

static int variant_htable_copy(amxc_var_t* const dest,
                               const amxc_var_t* const src) {
    const amxc_htable_t* htable = &src->data.vm;
    return variant_htable_copy_htable(dest, htable);
}

static int variant_htable_move(amxc_var_t* const dest,
                               amxc_var_t* const src) {
    int retval = 0;
    amxc_htable_t* src_htable = &src->data.vm;
    amxc_htable_t* dst_htable = &dest->data.vm;
    retval = amxc_htable_move(dst_htable, src_htable);
    return retval;
}

// TODO - refactor function to long
static int variant_htable_to_string(amxc_var_t* const dest,
                                    const amxc_var_t* const src) {
    int retval = -1;
    const amxc_htable_t* htable = &src->data.vm;
    amxc_string_t string;
    amxc_var_t intermediate;
    const char* sep = "";

    amxc_var_init(&intermediate);
    when_failed(amxc_string_init(&string, 100), exit);

    amxc_htable_for_each(it, htable) {
        amxc_var_t* item = amxc_var_from_htable_it(it);
        const char* key = amxc_htable_it_get_key(it);
        size_t length = 0;
        size_t key_length = 0;
        if(amxc_var_convert(&intermediate, item, AMXC_VAR_ID_CSTRING) != 0) {
            amxc_string_clean(&string);
            goto exit;
        }
        if(*sep != 0) {
            if(amxc_string_append(&string, sep, strlen(sep)) != 0) {
                amxc_string_clean(&string);
                goto exit;
            }
        }
        key_length = strlen(key);
        if(key_length != 0) {
            if(amxc_string_append(&string, key, key_length) != 0) {
                amxc_string_clean(&string);
                goto exit;
            }
        }
        if(amxc_string_append(&string, ":", 1) != 0) {
            amxc_string_clean(&string);
            goto exit;
        }
        length = intermediate.data.s == NULL ? 0 : strlen(intermediate.data.s);
        if(length == 0) {
            continue;
        }
        if(amxc_string_append(&string, intermediate.data.s, length) != 0) {
            amxc_string_clean(&string);
            goto exit;
        }
        sep = ",";
    }

    string.buffer[string.last_used] = 0;
    dest->data.s = string.buffer;
    retval = 0;

exit:
    amxc_var_clean(&intermediate);
    return retval;
}

static int variant_htable_to_number(amxc_var_t* const dest,
                                    const amxc_var_t* const src) {
    int retval = -1;

    amxc_var_t intermediate;
    intermediate.type_id = AMXC_VAR_ID_UINT64;
    intermediate.data.ui64 = amxc_htable_size(&src->data.vm);

    retval = amxc_var_convert(dest, &intermediate, dest->type_id);

    return retval;
}

static int variant_htable_to_bool(amxc_var_t* const dest,
                                  const amxc_var_t* const src) {
    dest->data.b = !amxc_htable_is_empty(&src->data.vm);

    return 0;
}

static int variant_htable_to_llist(amxc_var_t* const dest,
                                   const amxc_var_t* const src) {
    int retval = -1;
    const amxc_htable_t* htable = &src->data.vm;

    amxc_htable_for_each(it, htable) {
        amxc_var_t* copy = NULL;
        amxc_var_t* item = amxc_var_from_htable_it(it);

        when_failed(amxc_var_new(&copy), exit);
        if(amxc_var_copy(copy, item) != 0) {
            amxc_var_delete(&copy);
            goto exit;
        }
        if(amxc_llist_append(&dest->data.vl, &copy->lit) != 0) {
            amxc_var_delete(&copy);
            goto exit;
        }
    }

    retval = 0;

exit:
    return retval;
}

static int variant_htable_convert_to(amxc_var_t* const dest,
                                     const amxc_var_t* const src) {
    int retval = -1;

    amxc_var_convert_fn_t convfn[AMXC_VAR_ID_CUSTOM_BASE] = {
        amxc_var_default_convert_to_null,
        variant_htable_to_string,
        variant_htable_to_number,
        variant_htable_to_number,
        variant_htable_to_number,
        variant_htable_to_number,
        variant_htable_to_number,
        variant_htable_to_number,
        variant_htable_to_number,
        variant_htable_to_number,
        variant_htable_to_number,
        variant_htable_to_number,
        variant_htable_to_bool,
        variant_htable_to_llist,
        variant_htable_copy,
        NULL,
        NULL,
        variant_htable_to_string,
        variant_htable_to_string,
        variant_htable_copy,
    };

    if(dest->type_id >= AMXC_VAR_ID_CUSTOM_BASE) {
        goto exit;
    }

    if(convfn[dest->type_id] != NULL) {
        if(dest->type_id == AMXC_VAR_ID_ANY) {
            amxc_var_set_type(dest, AMXC_VAR_ID_HTABLE);
        }
        retval = convfn[dest->type_id](dest, src);
    }

exit:
    return retval;
}

static amxc_var_t* variant_htable_get_key(const amxc_var_t* const src,
                                          const char* const key,
                                          int flags) {
    amxc_var_t* retval = NULL;
    const amxc_htable_t* htable = &src->data.vm;
    amxc_htable_it_t* hit = amxc_htable_get(htable, key);
    amxc_var_t* src_var = NULL;

    when_null(hit, exit);

    src_var = amxc_htable_it_get_data(hit, amxc_var_t, hit);
    if((flags & AMXC_VAR_FLAG_COPY) == AMXC_VAR_FLAG_COPY) {
        when_failed(amxc_var_new(&retval), exit);
        when_failed(amxc_var_copy(retval, src_var), exit);
    } else {
        retval = src_var;
    }

exit:
    return retval;
}

static int variant_htable_set_key(amxc_var_t* const dest,
                                  amxc_var_t* const src,
                                  const char* const key,
                                  int flags) {
    int retval = -1;
    amxc_var_t* dest_var = NULL;
    amxc_htable_t* htable = &dest->data.vm;
    amxc_htable_it_t* current_hit = amxc_htable_take(htable, key);

    if((current_hit != NULL) &&
       ((flags & AMXC_VAR_FLAG_UPDATE) == 0)) {
        amxc_htable_insert(htable, key, current_hit);
        goto exit;
    }

    if((flags & AMXC_VAR_FLAG_COPY) == AMXC_VAR_FLAG_COPY) {
        if(current_hit != NULL) {
            dest_var = amxc_htable_it_get_data(current_hit, amxc_var_t, hit);
        } else {
            when_failed(amxc_var_new(&dest_var), exit);
        }

        when_failed(amxc_htable_insert(htable, key, &dest_var->hit), exit);
        when_failed(amxc_var_copy(dest_var, src), exit);
    } else {
        when_failed(amxc_htable_insert(htable, key, &src->hit), exit);
        if(current_hit != NULL) {
            amxc_htable_it_clean(current_hit, variant_htable_it_free);
        }
    }

    retval = 0;

exit:
    if((current_hit == NULL) && (retval != 0)) {
        amxc_var_delete(&dest_var);
    }
    return retval;
}

static amxc_var_t* variant_htable_get_index(const amxc_var_t* const src,
                                            const int64_t index,
                                            int flags) {
    amxc_var_t* retval = NULL;
    const amxc_htable_t* htable = &src->data.vm;
    amxc_htable_it_t* found_hit = NULL;
    amxc_var_t* src_var = NULL;
    int64_t pos = 0;

    when_true(index < 0, exit);
    when_true(index > (int64_t) amxc_htable_size(htable), exit);
    amxc_htable_iterate(hit, htable) {
        if(pos == index) {
            found_hit = hit;
            break;
        }
        pos++;
    }
    when_null(found_hit, exit);

    src_var = amxc_var_from_htable_it(found_hit);
    if((flags & AMXC_VAR_FLAG_COPY) == AMXC_VAR_FLAG_COPY) {
        when_failed(amxc_var_new(&retval), exit);
        when_failed(amxc_var_copy(retval, src_var), exit);
    } else {
        retval = src_var;
    }

exit:
    return retval;
}

static int variant_htable_compare(const amxc_var_t* const lval,
                                  const amxc_var_t* const rval,
                                  int* const result) {
    int ret = 0;
    amxc_array_t* keys_l = amxc_htable_get_sorted_keys(amxc_var_constcast(amxc_htable_t, lval));
    amxc_array_t* keys_r = amxc_htable_get_sorted_keys(amxc_var_constcast(amxc_htable_t, rval));
    size_t size_l = amxc_array_size(keys_l);
    size_t size_r = amxc_array_size(keys_r);

    if(size_l > size_r) {
        *result = 1;
        goto exit;
    } else if(size_l < size_r) {
        *result = -1;
        goto exit;
    }

    for(size_t i = 0; i < size_l; i++) {
        const char* key_l = (const char*) amxc_array_get_data_at(keys_l, i);
        const char* key_r = (const char*) amxc_array_get_data_at(keys_r, i);

        if((key_l == NULL) || (key_r == NULL)) {
            continue;
        }
        *result = strcmp(key_l, key_r);
        when_false(*result == 0, exit);

        ret = amxc_var_compare(amxc_var_get_key(lval, key_l, AMXC_VAR_FLAG_DEFAULT),
                               amxc_var_get_key(rval, key_r, AMXC_VAR_FLAG_DEFAULT),
                               result);
        when_false((ret == 0) && (*result == 0), exit);
    }

exit:
    amxc_array_delete(&keys_l, NULL);
    amxc_array_delete(&keys_r, NULL);
    return ret;
}

static int variant_htable_add_value(amxc_var_t* const dest,
                                    const amxc_var_t* const value) {
    int retval = -1;
    when_false(dest != NULL
               && value != NULL
               && value->type_id == AMXC_VAR_ID_HTABLE
               && dest->type_id == dest->type_id,
               exit);

    amxc_htable_for_each(it, &value->data.vm) {
        // Note: amxc_htable_t allows mapping a key twice, but an amxc_var_t of type AMXC_VAR_ID_HTABLE
        // does not. So do not do `amxc_htable_insert(dest_table, amxc_htable_it_get_key(it), it);`.
        variant_htable_set_key(dest, amxc_var_from_htable_it(it), amxc_htable_it_get_key(it), AMXC_VAR_FLAG_UPDATE | AMXC_VAR_FLAG_COPY);
    }
    retval = 0;

exit:
    return retval;
}

static amxc_var_type_t amxc_variant_htable = {
    .init = variant_htable_init,
    .del = variant_htable_delete,
    .copy = variant_htable_copy,
    .move = variant_htable_move,
    .convert_from = NULL,
    .convert_to = variant_htable_convert_to,
    .compare = variant_htable_compare,
    .get_key = variant_htable_get_key,
    .set_key = variant_htable_set_key,
    .get_index = variant_htable_get_index,
    .set_index = NULL,
    .add_value = variant_htable_add_value,
    .type_id = 0,
    .hit = { .ait = NULL, .key = NULL, .next = NULL },
    .name = AMXC_VAR_NAME_HTABLE
};

CONSTRUCTOR static void amxc_var_htable_init(void) {
    amxc_var_add_type(&amxc_variant_htable, AMXC_VAR_ID_HTABLE);
}

DESTRUCTOR static void amxc_var_htable_cleanup(void) {
    amxc_var_remove_type(&amxc_variant_htable);
}

amxc_htable_t* amxc_var_get_amxc_htable_t(const amxc_var_t* const var) {
    amxc_htable_t* htable = NULL;
    amxc_htable_it_t* it = NULL;
    amxc_var_t variant;
    when_null(var, exit);

    amxc_var_init(&variant);
    when_failed(amxc_var_convert(&variant, var, AMXC_VAR_ID_HTABLE), exit);

    if(amxc_htable_new(&htable, amxc_htable_capacity(&variant.data.vm)) != 0) {
        amxc_var_clean(&variant);
        goto exit;
    }

    it = amxc_htable_take_first(&variant.data.vm);
    while(it != NULL) {
        const char* key = amxc_htable_it_get_key(it);
        amxc_htable_insert(htable, key, it);
        it = amxc_htable_take_first(&variant.data.vm);
    }

    amxc_var_clean(&variant);

exit:
    return htable;
}

const amxc_htable_t* amxc_var_get_const_amxc_htable_t(const amxc_var_t* const var) {
    const amxc_htable_t* retval = NULL;
    when_null(var, exit);
    when_true(var->type_id != AMXC_VAR_ID_HTABLE, exit);

    retval = &var->data.vm;

exit:
    return retval;
}

amxc_var_t* amxc_var_add_new_amxc_htable_t(amxc_var_t* const var,
                                           const amxc_htable_t* htable) {
    amxc_var_t* subvar = NULL;

    when_null(var, exit);
    subvar = amxc_var_add_new(var);
    when_null(subvar, exit);

    amxc_var_set_type(subvar, AMXC_VAR_ID_HTABLE);
    when_null(htable, exit);

    if(variant_htable_copy_htable(subvar, htable) != 0) {
        amxc_var_delete(&subvar);
    }

exit:
    return subvar;
}

amxc_var_t* amxc_var_add_new_key_amxc_htable_t(amxc_var_t* const var,
                                               const char* key,
                                               const amxc_htable_t* htable) {
    amxc_var_t* subvar = NULL;

    when_null(var, exit);
    subvar = amxc_var_add_new_key(var, key);
    when_null(subvar, exit);

    amxc_var_set_type(subvar, AMXC_VAR_ID_HTABLE);
    when_null(htable, exit);

    if(variant_htable_copy_htable(subvar, htable) != 0) {
        amxc_var_delete(&subvar);
    }

exit:
    return subvar;
}
