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

#include <amxc/amxc.h>
#include <amxp/amxp_signal.h>
#include <amxp/amxp_slot.h>
#include <amxp/amxp_expression.h>

#include <amxd/amxd_types.h>
#include <amxd/amxd_object.h>
#include <amxd/amxd_path.h>
#include <amxd/amxd_object_expression.h>
#include <amxd/amxd_dm.h>

#include "amxd_priv.h"
#include "amxd_dm_priv.h"
#include "amxd_object_priv.h"
#include "amxd_assert.h"

static char* amxd_key_expr_get_value(const amxc_htable_t* const data,
                                     const char* name) {
    char* value = NULL;
    amxc_htable_it_t* hit = NULL;
    amxc_var_t* ht_data = NULL;

    hit = amxc_htable_get(data, name);
    when_null(hit, exit);
    ht_data = amxc_var_from_htable_it(hit);
    value = amxc_var_dyncast(cstring_t, ht_data);

exit:
    return value;
}

static amxd_status_t amxd_build_key_expr_string(amxc_var_t* const templ_params,
                                                const amxc_htable_t* const data,
                                                amxc_string_t* str_expr) {
    amxd_status_t status = amxd_status_unknown_error;
    const amxc_htable_t* ht_params = NULL;
    const char* unique_lop = ")";
    const char* key_lop = "(";

    ht_params = amxc_var_constcast(amxc_htable_t, templ_params);
    amxc_htable_for_each(it, ht_params) {
        const char* name = amxc_htable_it_get_key(it);
        amxc_var_t* param = amxc_var_from_htable_it(it);
        char* value = NULL;
        if(!amxc_var_constcast(bool, GET_FIELD(param, "attributes.key"))) {
            continue;
        }
        value = amxd_key_expr_get_value(data, name);
        when_null_status(value, exit, status = amxd_status_missing_key);
        if(amxc_var_constcast(bool, GET_FIELD(param, "attributes.unique"))) {
            if((unique_lop[0] == ')') && (key_lop[0] == '&')) {
                unique_lop = ")||";
            }
            amxc_string_prependf(str_expr, "%s==\"%s\"%s", name, value, unique_lop);
            unique_lop = "||";
        } else {
            if((key_lop[0] == '(') && (unique_lop[0] == '|')) {
                key_lop = "||(";
            }
            amxc_string_appendf(str_expr, "%s%s==\"%s\"", key_lop, name, value);
            key_lop = "&&";
        }
        free(value);
    }

    if(unique_lop[0] == '|') {
        amxc_string_prependf(str_expr, "(");
    }
    if(key_lop[0] == '&') {
        amxc_string_appendf(str_expr, ")");
    }
    status = amxd_status_ok;

exit:
    return status;
}

amxd_status_t PRIVATE amxd_object_build_key_expr(amxc_var_t* const templ_params,
                                                 amxp_expr_t** expr,
                                                 const amxc_htable_t* const data) {
    amxd_status_t status = amxd_status_unknown_error;
    amxp_expr_status_t expr_status = amxp_expr_status_ok;
    amxc_string_t str_expr;

    amxc_string_init(&str_expr, 64);

    when_null(templ_params, exit);
    when_null(expr, exit);

    status = amxd_build_key_expr_string(templ_params, data, &str_expr);

    if((status == amxd_status_ok) &&
       !amxc_string_is_empty(&str_expr)) {
        expr_status = amxp_expr_new(expr, amxc_string_get(&str_expr, 0));
        when_true_status(expr_status != amxp_expr_status_ok,
                         exit,
                         status = amxd_status_invalid_value);
    }

exit:
    amxc_string_clean(&str_expr);
    return status;
}

amxp_expr_status_t amxd_object_expr_get_field(UNUSED amxp_expr_t* expr,
                                              amxc_var_t* value,
                                              const char* path,
                                              void* priv) {
    amxp_expr_status_t status = amxp_expr_status_unknown_error;
    amxd_object_t* object = (amxd_object_t*) priv;
    amxd_path_t object_path;
    const char* op = NULL;
    const char* param = NULL;

    when_failed_status(amxd_path_init(&object_path, path),
                       exit,
                       status = amxp_expr_status_field_not_found);

    op = amxd_path_get(&object_path, AMXD_OBJECT_TERMINATE);
    param = amxd_path_get_param(&object_path);

    if(op != NULL) {
        if(op[0] == '.') {
            object = amxd_object_findf(object, "%s", op + 1);
        } else {
            object = amxd_object_findf(object, "%s", op);
        }
        when_null_status(object,
                         exit,
                         status = amxp_expr_status_field_not_found);
    }

    if(amxd_object_get_param(object, param, value) == amxd_status_ok) {
        status = amxp_expr_status_ok;
    } else {
        status = amxp_expr_status_field_not_found;
    }

exit:
    amxd_path_clean(&object_path);
    return status;
}

amxd_status_t amxd_object_new_key_expr(amxd_object_t* const templ,
                                       amxp_expr_t** expr,
                                       const amxc_var_t* const data) {
    amxd_status_t status = amxd_status_unknown_error;
    const amxc_htable_t* ht_data = NULL;
    amxc_var_t params;

    amxc_var_init(&params);
    when_null(data, exit);
    when_true(amxc_var_type_of(data) != AMXC_VAR_ID_HTABLE, exit);
    when_true(amxd_object_get_type(templ) != amxd_object_template, exit);

    when_failed(amxd_object_describe_key_params(templ, &params, amxd_dm_access_public), exit);
    ht_data = amxc_var_constcast(amxc_htable_t, data);
    status = amxd_object_build_key_expr(&params, expr, ht_data);

exit:
    amxc_var_clean(&params);
    return status;
}

amxd_object_t* amxd_object_find_instance(const amxd_object_t* const templ,
                                         amxp_expr_t* expr) {
    amxd_object_t* instance = NULL;

    when_null(templ, exit);
    when_true(amxd_object_get_type(templ) != amxd_object_template, exit);
    when_null(expr, exit);

    amxd_object_for_each(instance, it, templ) {
        instance = amxc_container_of(it, amxd_object_t, it);
        if(amxd_object_matches_expr(instance, expr)) {
            break;
        }
        instance = NULL;
    }

exit:
    return instance;
}

amxd_object_t* amxd_object_find_next_instance(const amxd_object_t* const instance,
                                              amxp_expr_t* expr) {
    amxd_object_t* inst = NULL;
    amxc_llist_it_t* it = NULL;

    when_null(instance, exit);
    when_true(amxd_object_get_type(instance) != amxd_object_instance, exit);
    when_null(expr, exit);

    it = amxc_llist_it_get_next(&instance->it);
    while(it) {
        inst = amxc_container_of(it, amxd_object_t, it);
        if(amxd_object_matches_expr(inst, expr)) {
            break;
        }
        it = amxc_llist_it_get_next(it);
        inst = NULL;
    }

exit:
    return inst;
}

bool amxd_object_has_matching_instances(const amxd_object_t* const templ,
                                        amxp_expr_t* expr) {
    bool retval = false;

    retval = (amxd_object_find_instance(templ, expr) != NULL);

    return retval;
}

bool amxd_object_has_keys(amxd_object_t* const instance) {
    bool retval = false;
    amxc_var_t params;
    const amxc_htable_t* ht_params = NULL;

    amxc_var_init(&params);

    when_null(instance, exit);
    when_true(amxd_object_get_type(instance) != amxd_object_instance &&
              amxd_object_get_type(instance) != amxd_object_template,
              exit);

    when_failed(amxd_object_describe_params(instance, &params, amxd_dm_access_public), exit);
    ht_params = amxc_var_constcast(amxc_htable_t, &params);
    amxc_htable_for_each(it, ht_params) {
        amxc_var_t* param = amxc_var_from_htable_it(it);
        if(amxc_var_constcast(bool, GET_FIELD(param, "attributes.key"))) {
            retval = true;
            break;
        }
    }

exit:
    amxc_var_clean(&params);
    return retval;
}

bool amxd_object_matches_expr(amxd_object_t* const object,
                              amxp_expr_t* expr) {
    bool retval = false;

    when_null(object, exit);
    when_null(expr, exit);

    retval = amxp_expr_evaluate(expr, amxd_object_expr_get_field, object, NULL);

exit:
    return retval;
}
