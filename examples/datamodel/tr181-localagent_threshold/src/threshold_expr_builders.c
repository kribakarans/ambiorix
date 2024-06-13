/****************************************************************************
**
** Copyright (c) 2020 SoftAtHome
**
** Redistribution and use in source and binary forms, with or
** without modification, are permitted provided that the following
** conditions are met:
**
** 1. Redistributions of source code must retain the above copyright
** notice, this list of conditions and the following disclaimer.
**
** 2. Redistributions in binary form must reproduce the above
** copyright notice, this list of conditions and the following
** disclaimer in the documentation and/or other materials provided
** with the distribution.
**
** Subject to the terms and conditions of this license, each
** copyright holder and contributor hereby grants to those receiving
** rights under this license a perpetual, worldwide, non-exclusive,
** no-charge, royalty-free, irrevocable (except for failure to
** satisfy the conditions of this license) patent license to make,
** have made, use, offer to sell, sell, import, and otherwise
** transfer this software, where such license applies only to those
** patent claims, already acquired or hereafter acquired, licensable
** by such copyright holder or contributor that are necessarily
** infringed by:
**
** (a) their Contribution(s) (the licensed copyrights of copyright
** holders and non-copyrightable additions of contributors, in
** source or binary form) alone; or
**
** (b) combination of their Contribution(s) with the work of
** authorship to which such Contribution(s) was added by such
** copyright holder or contributor, if, at the time the Contribution
** is added, such addition causes such combination to be necessarily
** infringed. The patent license shall not apply to any other
** combinations which include the Contribution.
**
** Except as expressly stated above, no rights or licenses from any
** copyright holder or contributor is granted under this license,
** whether expressly, by implication, estoppel or otherwise.
**
** DISCLAIMER
**
** THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
** CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
** INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
** MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
** DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR
** CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
** SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
** LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
** USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
** AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
** LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
** ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
** POSSIBILITY OF SUCH DAMAGE.
**
****************************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "threshold.h"
#include "dm_threshold.h"
#include "threshold_expr.h"

typedef void (* threshold_expr_fn_t) (amxc_string_t* expr_str,
                                      const char* ref_path,
                                      const char* ref_param,
                                      amxc_var_t* value);

static const char* operators[] = {
    "Rise",
    "Fall",
    "Cross",
    "Eq",
    "NotEq",
    NULL
};

static int threshold_get_operator_id(const char* oper) {
    int id = 0;
    for(id = 0; operators[id] != NULL; id++) {
        if(strcmp(operators[id], oper) == 0) {
            break;
        }
    }

    return id;
}

static bool threshold_value_is_number(amxc_var_t* value) {
    bool retval = false;
    amxc_var_t temp;

    amxc_var_init(&temp);
    if(amxc_var_convert(&temp, value, AMXC_VAR_ID_INT64) == 0) {
        retval = true;
    }
    amxc_var_clean(&temp);

    return retval;
}

static bool threshold_is_search_path(const char* ref_path) {
    amxd_path_t path;
    bool rv = false;

    amxd_path_init(&path, ref_path);
    rv = amxd_path_is_search_path(&path);
    amxd_path_clean(&path);

    return rv;
}

static void threshold_rise_expression(amxc_string_t* expr_str,
                                      const char* ref_path,
                                      const char* ref_param,
                                      amxc_var_t* value) {
    const char* rise_expr[] = {
        "{path} in search_path('%s') && {parameters.%s.from} <= '%s' && {parameters.%s.to} > '%s'",
        "{path} in search_path('%s') && {parameters.%s.from} <= %s && {parameters.%s.to} > %s",
        "{path} == '%s' && {parameters.%s.from} <= '%s' && {parameters.%s.to} > '%s'",
        "{path} == '%s' && {parameters.%s.from} <= %s && {parameters.%s.to} > %s",
    };
    int32_t index = threshold_is_search_path(ref_path) ? 0 : 2;
    const char* str_value = amxc_var_constcast(cstring_t, value);
    if(threshold_value_is_number(value)) {
        index++;
    }

    amxc_string_appendf(expr_str, rise_expr[index], ref_path,
                        ref_param, str_value,
                        ref_param, str_value);
}

static void threshold_fall_expression(amxc_string_t* expr_str,
                                      const char* ref_path,
                                      const char* ref_param,
                                      amxc_var_t* value) {
    const char* fall_expr[] = {
        "{path} in search_path('%s') && {parameters.%s.from} >= '%s' && {parameters.%s.to} < '%s'",
        "{path} in search_path('%s') && {parameters.%s.from} >= %s && {parameters.%s.to} < %s",
        "{path} == '%s' && {parameters.%s.from} >= '%s' && {parameters.%s.to} < '%s'",
        "{path} == '%s' && {parameters.%s.from} >= %s && {parameters.%s.to} < %s"
    };
    int32_t index = threshold_is_search_path(ref_path) ? 0 : 2;
    const char* str_value = amxc_var_constcast(cstring_t, value);
    if(threshold_value_is_number(value)) {
        index++;
    }
    amxc_string_appendf(expr_str, fall_expr[index], ref_path,
                        ref_param, str_value,
                        ref_param, str_value);
}

static void threshold_eq_expression(amxc_string_t* expr_str,
                                    const char* ref_path,
                                    const char* ref_param,
                                    amxc_var_t* value) {
    const char* eq_expr[] = {
        "{path} in search_path('%s') && {parameters.%s.from} != '%s' && {parameters.%s.to} == '%s'",
        "{path} == '%s' && {parameters.%s.from} != '%s' && {parameters.%s.to} == '%s'"
    };
    int32_t index = threshold_is_search_path(ref_path) ? 0 : 1;

    const char* str_value = amxc_var_constcast(cstring_t, value);
    amxc_string_appendf(expr_str, eq_expr[index], ref_path,
                        ref_param, str_value,
                        ref_param, str_value);
}

static void threshold_neq_expression(amxc_string_t* expr_str,
                                     const char* ref_path,
                                     const char* ref_param,
                                     amxc_var_t* value) {
    const char* neq_expr[] = {
        "{path} in search_path('%s') && {parameters.%s.from} == '%s' && {parameters.%s.to} != '%s'",
        "{path} == '%s' && {parameters.%s.from} == '%s' && {parameters.%s.to} != '%s'"
    };

    int32_t index = threshold_is_search_path(ref_path) ? 0 : 1;

    const char* str_value = amxc_var_constcast(cstring_t, value);
    amxc_string_appendf(expr_str, neq_expr[index], ref_path,
                        ref_param, str_value,
                        ref_param, str_value);
}

static threshold_expr_fn_t expr_fn[] = {
    threshold_rise_expression,
    threshold_fall_expression,
    NULL,
    threshold_eq_expression,
    threshold_neq_expression,
    NULL,
};

char* threshold_build_expression(const char* ref_path,
                                 const char* ref_param,
                                 const char* oper,
                                 amxc_var_t* value) {

    char* expr = NULL;
    amxc_string_t expr_str;
    amxc_string_init(&expr_str, 0);

    int op_id = threshold_get_operator_id(oper);
    if(expr_fn[op_id] != NULL) {
        expr_fn[op_id](&expr_str, ref_path, ref_param, value);
    }

    expr = amxc_string_take_buffer(&expr_str);
    amxc_string_clean(&expr_str);

    return expr;
}

