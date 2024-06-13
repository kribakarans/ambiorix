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

#include <amxc/amxc_string.h>
#include <amxc/amxc_string_join.h>
#include <amxc_variant_priv.h>

static int variant_list_init(amxc_var_t* const var) {
    return amxc_llist_init(&var->data.vl);
}

void variant_list_it_free(amxc_llist_it_t* it) {
    amxc_var_t* var = amxc_var_from_llist_it(it);
    amxc_var_delete(&var);
}

static void variant_list_delete(amxc_var_t* var) {
    amxc_llist_clean(&var->data.vl, variant_list_it_free);
}

static int variant_list_copy_list(amxc_var_t* const dest,
                                  const amxc_llist_t* source_list) {
    int retval = -1;

    amxc_llist_for_each(it, source_list) {
        amxc_var_t* var = NULL;
        amxc_var_t* item = amxc_var_from_llist_it(it);
        when_null(item, exit);
        when_failed(amxc_var_new(&var), exit);
        if(amxc_var_copy(var, item) != 0) {
            amxc_var_delete(&var);
            goto exit;
        }
        amxc_llist_append(&dest->data.vl, &var->lit);
    }

    retval = 0;

exit:
    return retval;
}

static int variant_list_copy(amxc_var_t* const dest,
                             const amxc_var_t* const src) {
    const amxc_llist_t* list = &src->data.vl;
    return variant_list_copy_list(dest, list);
}

static int variant_list_move(amxc_var_t* const dest,
                             amxc_var_t* const src) {
    amxc_llist_t* src_list = &src->data.vl;
    amxc_llist_t* dst_list = &dest->data.vl;
    return amxc_llist_move(dst_list, src_list);
}

static int variant_list_to_csv_string(amxc_var_t* const dest,
                                      const amxc_var_t* const src) {
    int retval = -1;
    amxc_string_t string;
    amxc_string_init(&string, 0);
    retval = amxc_string_csv_join_var(&string, src);
    free(dest->data.s);
    dest->data.s = amxc_string_take_buffer(&string);
    amxc_string_clean(&string);
    return retval;
}

static int variant_list_to_ssv_string(amxc_var_t* const dest,
                                      const amxc_var_t* const src) {
    int retval = -1;
    amxc_string_t string;
    amxc_string_init(&string, 0);
    retval = amxc_string_ssv_join_var(&string, src);
    free(dest->data.s);
    dest->data.s = amxc_string_take_buffer(&string);
    amxc_string_clean(&string);
    return retval;
}

static int variant_list_to_number(amxc_var_t* const dest,
                                  const amxc_var_t* const src) {
    int retval = -1;

    amxc_var_t intermediate;
    intermediate.type_id = AMXC_VAR_ID_UINT64;
    intermediate.data.ui64 = amxc_llist_size(&src->data.vl);

    retval = amxc_var_convert(dest, &intermediate, dest->type_id);

    return retval;
}

static int variant_list_to_bool(amxc_var_t* const dest,
                                const amxc_var_t* const src) {
    dest->data.b = !amxc_llist_is_empty(&src->data.vl);

    return 0;
}

static int variant_list_to_htable(amxc_var_t* const dest,
                                  const amxc_var_t* const src) {
    int retval = -1;
    amxc_var_t index;
    const amxc_llist_t* list = &src->data.vl;

    amxc_var_init(&index);
    index.type_id = AMXC_VAR_ID_UINT64;
    index.data.ui64 = 0;

    amxc_llist_for_each(it, list) {
        amxc_var_t* copy = NULL;
        amxc_var_t* item = amxc_var_from_llist_it(it);
        char* key = amxc_var_dyncast(cstring_t, &index);
        when_null(key, exit);

        if(amxc_var_new(&copy) != 0) {
            free(key);
            goto exit;
        }
        if(amxc_var_copy(copy, item) != 0) {
            amxc_var_delete(&copy);
            free(key);
            goto exit;
        }
        if(amxc_htable_insert(&dest->data.vm, key, &copy->hit) != 0) {
            amxc_var_delete(&copy);
            free(key);
            goto exit;
        }
        free(key);
        index.data.ui64++;
    }

    retval = 0;

exit:
    amxc_var_clean(&index);
    return retval;
}

static int variant_list_convert_to(amxc_var_t* const dest,
                                   const amxc_var_t* const src) {
    int retval = -1;

    amxc_var_convert_fn_t convfn[AMXC_VAR_ID_CUSTOM_BASE] = {
        amxc_var_default_convert_to_null,
        variant_list_to_csv_string,
        variant_list_to_number,
        variant_list_to_number,
        variant_list_to_number,
        variant_list_to_number,
        variant_list_to_number,
        variant_list_to_number,
        variant_list_to_number,
        variant_list_to_number,
        variant_list_to_number,
        variant_list_to_number,
        variant_list_to_bool,
        variant_list_copy,
        variant_list_to_htable,
        NULL,
        NULL,
        variant_list_to_csv_string,
        variant_list_to_ssv_string,
        variant_list_copy,
    };

    if(dest->type_id >= AMXC_VAR_ID_CUSTOM_BASE) {
        goto exit;
    }

    if(convfn[dest->type_id] != NULL) {
        if(dest->type_id == AMXC_VAR_ID_ANY) {
            amxc_var_set_type(dest, AMXC_VAR_ID_LIST);
        }
        retval = convfn[dest->type_id](dest, src);
    }

exit:
    return retval;
}

static amxc_var_t* variant_list_get_index(const amxc_var_t* const src,
                                          const int64_t index,
                                          int flags) {
    amxc_var_t* retval = NULL;
    const amxc_llist_t* llist = &src->data.vl;
    amxc_llist_it_t* lit = NULL;
    amxc_var_t* src_var = NULL;

    when_true(index < 0, exit);
    lit = amxc_llist_get_at(llist, index);
    when_null(lit, exit);

    src_var = amxc_llist_it_get_data(lit, amxc_var_t, lit);
    if((flags & AMXC_VAR_FLAG_COPY) == AMXC_VAR_FLAG_COPY) {
        when_failed(amxc_var_new(&retval), exit);
        when_failed(amxc_var_copy(retval, src_var), exit);
    } else {
        retval = src_var;
    }

exit:
    return retval;
}

static int variant_list_set_index(amxc_var_t* const dest,
                                  amxc_var_t* const src,
                                  const int64_t index,
                                  int flags) {
    int retval = -1;
    amxc_var_t* dest_var = NULL;
    amxc_llist_t* llist = &dest->data.vl;
    amxc_llist_it_t* current_lit = NULL;

    when_true(index > (int64_t) (amxc_llist_size(llist) + 1), exit);
    current_lit = amxc_llist_get_at(llist, index);

    if((flags & AMXC_VAR_FLAG_COPY) == AMXC_VAR_FLAG_COPY) {
        if(current_lit != NULL) {
            if((flags & AMXC_VAR_FLAG_UPDATE) == AMXC_VAR_FLAG_UPDATE) {
                dest_var = amxc_llist_it_get_data(current_lit, amxc_var_t, lit);
                when_failed(amxc_var_copy(dest_var, src), exit);
            } else {
                when_failed(amxc_var_new(&dest_var), exit);
                when_failed(amxc_var_copy(dest_var, src), exit);
                when_failed(amxc_llist_it_insert_before(current_lit, &dest_var->lit), exit);
            }
        } else {
            when_failed(amxc_var_new(&dest_var), exit);
            when_failed(amxc_var_copy(dest_var, src), exit);
            when_failed(amxc_llist_append(llist, &dest_var->lit), exit);
        }
    } else {
        if(current_lit != NULL) {
            if((flags & AMXC_VAR_FLAG_UPDATE) == AMXC_VAR_FLAG_UPDATE) {
                when_failed(amxc_llist_it_insert_before(current_lit, &src->lit), exit);
                amxc_llist_it_clean(current_lit, variant_list_it_free);
            } else {
                when_failed(amxc_llist_it_insert_before(current_lit, &src->lit), exit);
            }
        } else {
            when_failed(amxc_llist_append(llist, &src->lit), exit);
        }
    }
    retval = 0;

exit:
    if((current_lit == NULL) && (retval != 0)) {
        amxc_var_delete(&dest_var);
    }
    return retval;
}

static amxc_var_t* variant_list_get_key(const amxc_var_t* const src,
                                        const char* const key,
                                        int flags) {
    char* endptr = NULL;
    int64_t index = strtoll(key, &endptr, 0);
    if(*endptr != 0) {
        return NULL;
    } else {
        return variant_list_get_index(src, index, flags);
    }
}

static int variant_list_set_key(amxc_var_t* const dest,
                                amxc_var_t* const src,
                                const char* const key,
                                int flags) {
    char* endptr = NULL;
    int64_t index = strtoll(key, &endptr, 0);

    if(*endptr != 0) {
        return -1;
    } else {
        return variant_list_set_index(dest, src, index, flags);
    }
}

static int variant_list_compare(const amxc_var_t* const lval,
                                const amxc_var_t* const rval,
                                int* const result) {
    int ret = 0;
    amxc_llist_it_t* r_it = amxc_llist_get_first(amxc_var_constcast(amxc_llist_t, rval));

    amxc_llist_iterate(l_it, amxc_var_constcast(amxc_llist_t, lval)) {
        when_null_status(r_it, exit, *result = 1);

        ret = amxc_var_compare(amxc_llist_it_get_data(l_it, amxc_var_t, lit),
                               amxc_llist_it_get_data(r_it, amxc_var_t, lit),
                               result);
        when_false((ret == 0) && (*result == 0), exit);

        r_it = amxc_llist_it_get_next(r_it);
    }

    if(r_it != NULL) {
        *result = -1;
    }

exit:
    return ret;
}

static int variant_list_add_value(amxc_var_t* const dest,
                                  const amxc_var_t* const value) {
    int retval = -1;
    amxc_llist_t* dest_list = NULL;
    when_false(dest != NULL
               && value != NULL
               && value->type_id == AMXC_VAR_ID_LIST
               && dest->type_id == dest->type_id,
               exit);

    dest_list = &dest->data.vl;

    amxc_llist_for_each(it, &value->data.vl) {
        amxc_llist_append(dest_list, it);
    }
    retval = 0;

exit:
    return retval;
}

static amxc_var_type_t amxc_variant_list = {
    .init = variant_list_init,
    .del = variant_list_delete,
    .copy = variant_list_copy,
    .move = variant_list_move,
    .convert_from = NULL,
    .convert_to = variant_list_convert_to,
    .compare = variant_list_compare,
    .get_key = variant_list_get_key,
    .set_key = variant_list_set_key,
    .get_index = variant_list_get_index,
    .set_index = variant_list_set_index,
    .add_value = variant_list_add_value,
    .type_id = 0,
    .hit = { .ait = NULL, .key = NULL, .next = NULL },
    .name = AMXC_VAR_NAME_LIST
};

CONSTRUCTOR static void amxc_var_list_init(void) {
    amxc_var_add_type(&amxc_variant_list, AMXC_VAR_ID_LIST);
}

DESTRUCTOR static void amxc_var_list_cleanup(void) {
    amxc_var_remove_type(&amxc_variant_list);
}

amxc_llist_t* amxc_var_get_amxc_llist_t(const amxc_var_t* const var) {
    amxc_llist_t* llist = NULL;
    amxc_llist_it_t* it = NULL;
    amxc_var_t variant;
    when_null(var, exit);

    amxc_var_init(&variant);
    when_failed(amxc_var_convert(&variant, var, AMXC_VAR_ID_LIST), exit);

    if(amxc_llist_new(&llist) != 0) {
        amxc_var_clean(&variant);
        goto exit;
    }

    it = amxc_llist_take_first(&variant.data.vl);
    while(it != NULL) {
        amxc_llist_append(llist, it);
        it = amxc_llist_take_first(&variant.data.vl);
    }

    amxc_var_clean(&variant);

exit:
    return llist;
}

const amxc_llist_t* amxc_var_get_const_amxc_llist_t(const amxc_var_t* const var) {
    const amxc_llist_t* retval = NULL;
    when_null(var, exit);
    when_true(var->type_id != AMXC_VAR_ID_LIST, exit);

    retval = &var->data.vl;

exit:
    return retval;
}

amxc_var_t* amxc_var_add_new_amxc_llist_t(amxc_var_t* const var,
                                          const amxc_llist_t* list) {
    amxc_var_t* subvar = NULL;

    when_null(var, exit);
    subvar = amxc_var_add_new(var);
    when_null(subvar, exit);

    amxc_var_set_type(subvar, AMXC_VAR_ID_LIST);
    when_null(list, exit);

    if(variant_list_copy_list(subvar, list) != 0) {
        amxc_var_delete(&subvar);
    }

exit:
    return subvar;
}

amxc_var_t* amxc_var_add_new_key_amxc_llist_t(amxc_var_t* const var,
                                              const char* key,
                                              const amxc_llist_t* list) {
    amxc_var_t* subvar = NULL;

    when_null(var, exit);
    subvar = amxc_var_add_new_key(var, key);
    when_null(subvar, exit);

    amxc_var_set_type(subvar, AMXC_VAR_ID_LIST);
    when_null(list, exit);

    if(variant_list_copy_list(subvar, list) != 0) {
        amxc_var_delete(&subvar);
    }

exit:
    return subvar;
}
