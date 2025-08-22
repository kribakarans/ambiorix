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
#include "amxp_expr.tab.h"

#define REGEXP_STORE_SIZE   40
typedef struct _amxp_expr_vfunc {
    amxc_htable_it_t hit;
    amxp_expr_value_func_t fn;
} amxp_expr_vfunc_t;

typedef struct _amxp_expr_bfunc {
    amxc_htable_it_t hit;
    amxp_expr_bool_func_t fn;
} amxp_expr_bfunc_t;

typedef struct _amxp_regexp {
    amxc_htable_it_t hit;
    amxc_llist_it_t lit;
    regex_t regexp;
} amxp_regexp_t;

static amxc_htable_t value_funcs;
static amxc_htable_t bool_funcs;
static amxc_htable_t regexp_store;
static amxc_llist_t regexp_store_list;

static void amxp_regexp_clean(amxc_llist_it_t* it) {
    amxp_regexp_t* amxp_regexp = (amxp_regexp_t*) amxc_container_of(it, amxp_regexp_t, lit);
    amxc_htable_it_clean(&amxp_regexp->hit, NULL);
    regfree(&amxp_regexp->regexp);
    free(amxp_regexp);
}

static amxp_regexp_t* amxp_regexp_get(const char* regexp_str) {
    amxp_regexp_t* regexp = NULL;
    amxc_htable_it_t* it = amxc_htable_get(&regexp_store, regexp_str);
    if(it != NULL) {
        regexp = amxc_container_of(it, amxp_regexp_t, hit);
        amxc_llist_append(&regexp_store_list, &regexp->lit);
    }

    return regexp;
}

CONSTRUCTOR static void amxp_regexp_store_init(void) {
    amxc_llist_init(&regexp_store_list);
    amxc_htable_init(&regexp_store, REGEXP_STORE_SIZE);
}

DESTRUCTOR static void amxp_regexp_store_cleanup(void) {
    amxc_llist_clean(&regexp_store_list, amxp_regexp_clean);
    amxc_htable_clean(&regexp_store, NULL);
}

static void amxp_expr_vfunc_hit_free(UNUSED const char* key,
                                     amxc_htable_it_t* it) {
    amxp_expr_vfunc_t* vfn = amxc_htable_it_get_data(it, amxp_expr_vfunc_t, hit);
    free(vfn);
}

static void amxp_expr_bfunc_hit_free(UNUSED const char* key,
                                     amxc_htable_it_t* it) {
    amxp_expr_bfunc_t* bfn = amxc_htable_it_get_data(it, amxp_expr_bfunc_t, hit);
    free(bfn);
}

static ssize_t amxp_expr_string_reader(amxp_expr_t* expr,
                                       void* buf,
                                       size_t max_size) {
    ssize_t result = 0;
    result = amxc_rbuffer_read(&expr->rbuffer, (char*) buf, max_size);
    errno = 0;

    return result;
}

static bool amxp_expr_match_regexp(amxp_expr_t* expr,
                                   amxc_var_t* lvalue,
                                   amxc_var_t* rvalue) {
    bool retval = false;
    amxp_regexp_t* regexp = NULL;
    char* regexp_str = NULL;
    char* value_str = NULL;

    regexp_str = amxc_var_dyncast(cstring_t, rvalue);
    value_str = amxc_var_dyncast(cstring_t, lvalue);

    regexp = amxp_regexp_get(regexp_str);
    if(regexp == NULL) {
        regexp = (amxp_regexp_t*) calloc(1, sizeof(amxp_regexp_t));
        when_null_status(regexp, exit, expr->status = amxp_expr_status_invalid_regexp);
        if(regcomp(&regexp->regexp, regexp_str, REG_EXTENDED) != 0) {
            expr->status = amxp_expr_status_invalid_regexp;
            free(regexp);
            goto exit;
        }
        amxc_htable_insert(&regexp_store, regexp_str, &regexp->hit);
        amxc_llist_append(&regexp_store_list, &regexp->lit);

        if(amxc_htable_size(&regexp_store) > REGEXP_STORE_SIZE) {
            amxc_llist_it_t* it = amxc_llist_take_first(&regexp_store_list);
            amxp_regexp_clean(it);
        }
    }

    if(regexec(&regexp->regexp, value_str, 0, NULL, 0) == 0) {
        retval = true;
    }

exit:
    free(regexp_str);
    free(value_str);

    return retval;
}

static bool amxp_expr_string_check(const char* lstr,
                                   size_t llength,
                                   const char* rstr,
                                   size_t rlength,
                                   amxp_expr_comp_t comperator) {
    size_t offset = 0;
    bool retval = false;

    when_true(rlength > llength, exit);

    if(comperator == amxp_expr_comp_starts_with) {
        offset = 0;
    } else {
        offset = llength - rlength;
    }
    retval = strncmp(lstr + offset, rstr, rlength) == 0;

exit:
    return retval;
}

static bool amxp_expr_string_head_tail_check(amxc_var_t* lvalue,
                                             amxc_var_t* rvalue,
                                             amxp_expr_comp_t comperator) {
    bool retval = false;
    char* lstr = amxc_var_dyncast(cstring_t, lvalue);
    char* rstr = NULL;
    size_t llength = strlen(lstr);

    if(amxc_var_type_of(rvalue) == AMXC_VAR_ID_LIST) {
        amxc_var_for_each(var, rvalue) {
            size_t rlength = 0;
            rstr = amxc_var_dyncast(cstring_t, var);
            rlength = strlen(rstr);
            retval = amxp_expr_string_check(lstr, llength, rstr, rlength, comperator);
            free(rstr);
            if(retval) {
                break;
            }
        }
    } else {
        size_t rlength = 0;
        rstr = amxc_var_dyncast(cstring_t, rvalue);
        rlength = strlen(rstr);
        retval = amxp_expr_string_check(lstr, llength, rstr, rlength, comperator);
        free(rstr);
    }
    free(lstr);
    return retval;
}

static bool amxp_expr_in_list(amxc_var_t* lvalue,
                              amxc_var_t* rvalue) {
    const amxc_llist_t* list = amxc_var_constcast(amxc_llist_t, rvalue);
    int result = 0;
    bool retval = false;

    amxc_llist_for_each(it, list) {
        amxc_var_t* item = amxc_var_from_llist_it(it);
        int amxc_rv = amxc_var_compare(lvalue, item, &result);
        if((amxc_rv == 0) && (result == 0)) {
            retval = true;
            break;
        }
    }

    return retval;
}

static bool amxp_expr_in_string(amxc_var_t* lvalue,
                                amxc_var_t* rvalue) {
    const char* string = amxc_var_constcast(cstring_t, rvalue);
    int rlength = strlen(string);
    char* lstr = amxc_var_dyncast(cstring_t, lvalue);
    int llength = strlen(lstr);
    bool retval = false;

    if(llength <= rlength) {
        for(int i = 0; i <= rlength - llength; i++) {
            if(strncmp(lstr, string + i, llength) == 0) {
                retval = true;
                break;
            }
        }
    }

    free(lstr);
    return retval;
}

static bool amxp_expr_equals_ignorecase(amxc_var_t* lvalue,
                                        amxc_var_t* rvalue) {
    bool retval = false;
    char* lvalue_str = NULL;
    char* rvalue_str = NULL;

    lvalue_str = amxc_var_dyncast(cstring_t, lvalue);
    rvalue_str = amxc_var_dyncast(cstring_t, rvalue);

    retval = 0 == strcasecmp(lvalue_str, rvalue_str);

    free(lvalue_str);
    free(rvalue_str);

    return retval;
}

static bool amxp_expr_is_simple_type(amxc_var_t* value) {
    int type = amxc_var_type_of(value);
    return !(type == AMXC_VAR_ID_HTABLE || type == AMXC_VAR_ID_LIST);
}

static bool amxp_expr_are_simple_types(amxc_var_t* lvalue,
                                       amxc_var_t* rvalue) {
    return (amxp_expr_is_simple_type(lvalue) &&
            amxp_expr_is_simple_type(rvalue));
}

static bool amxp_expr_in(amxp_expr_t* expr,
                         amxc_var_t* lvalue,
                         amxc_var_t* rvalue) {
    int rtype = amxc_var_type_of(rvalue);
    bool retval = false;

    if(!amxp_expr_is_simple_type(lvalue)) {
        expr->status = amxp_expr_status_invalid_value;
        goto exit;
    }

    switch(rtype) {
    case AMXC_VAR_ID_LIST:
        retval = amxp_expr_in_list(lvalue, rvalue);
        break;
    case AMXC_VAR_ID_CSTRING:
        retval = amxp_expr_in_string(lvalue, rvalue);
        break;
    case AMXC_VAR_ID_SSV_STRING:
    case AMXC_VAR_ID_CSV_STRING:
        amxc_var_cast(rvalue, AMXC_VAR_ID_LIST);
        retval = amxp_expr_in_list(lvalue, rvalue);
        break;
    case AMXC_VAR_ID_BOOL:
        if(!expr->verify) {
            expr->status = amxp_expr_status_invalid_value;
        }
        break;
    default:
        expr->status = amxp_expr_status_invalid_value;
        break;
    }

exit:
    return retval;
}

static bool amxp_expr_comperator(int result, amxp_expr_comp_t type) {
    bool retval = false;
    switch(type) {
    case amxp_expr_comp_equal:
        retval = (result == 0);
        break;
    case amxp_expr_comp_not_equal:
        retval = (result != 0);
        break;
    case amxp_expr_comp_lesser:
        retval = (result < 0);
        break;
    case amxp_expr_comp_bigger:
        retval = (result > 0);
        break;
    case amxp_expr_comp_lesser_equal:
        retval = (result <= 0);
        break;
    case amxp_expr_comp_bigger_equal:
        retval = (result >= 0);
        break;
    default:
        break;
    }
    return retval;
}

static amxp_expr_status_t _value_first_of(UNUSED amxp_expr_t* expr,
                                          amxc_var_t* args,
                                          amxc_var_t* ret) {
    amxp_expr_status_t status = amxp_expr_status_invalid_value;
    amxc_var_t* data = NULL;
    amxc_llist_for_each(it, (&args->data.vl)) {
        data = amxc_var_from_llist_it(it);
        if(!amxc_var_is_null(data)) {
            break;
        }
        data = NULL;
    }

    when_null(data, exit);
    amxc_var_copy(ret, data);

    status = amxp_expr_status_ok;

exit:
    return status;
}

static bool _bool_is_empty(UNUSED amxp_expr_t* expr,
                           amxc_var_t* args) {
    bool retval = false;
    amxc_llist_it_t* it = amxc_llist_get_first(&args->data.vl);
    amxc_var_t* data = amxc_var_from_llist_it(it);

    if(amxc_var_is_null(data)) {
        retval = true;
    }

    if((amxc_var_type_of(data) == AMXC_VAR_ID_LIST) &&
       amxc_llist_is_empty(&data->data.vl)) {
        retval = true;
    }

    if((amxc_var_type_of(data) == AMXC_VAR_ID_HTABLE) &&
       amxc_htable_is_empty(&data->data.vm)) {
        retval = true;
    }

    return retval;
}

static bool _bool_contains(amxp_expr_t* expr,
                           amxc_var_t* args) {
    bool retval = false;
    amxc_var_t* data = (amxc_var_t*) expr->priv;
    const char* path = NULL;
    amxc_var_t field_value;
    amxp_expr_status_t status = amxp_expr_status_ok;

    amxc_var_init(&field_value);
    when_null(data, exit);
    when_null(expr->get_field, exit);

    amxc_var_for_each(field_var, args) {
        if(amxc_var_type_of(field_var) != AMXC_VAR_ID_CSTRING) {
            // ignore invalid field paths - field paths must be strings
            continue;
        }
        path = amxc_var_constcast(cstring_t, field_var);
        status = expr->get_field(expr, &field_value, path, expr->priv);
        retval = (status == amxp_expr_status_ok);
        if(retval) {
            // found one, we can stop
            break;
        }
    }

exit:
    amxc_var_clean(&field_value);
    return retval;
}

static bool amxp_expr_is_safe_value(const char* string) {
    if(string == NULL) {
        return false;
    }
    for(const char* c = string; *c != '\0'; c++) {
        bool is_whitelisted =
            *c == ' '
            || *c == '!'
            || (*c >= '#' && *c <= '&')
            || (*c >= '(' && *c <= '[')
            || (*c >= ']' && *c <= '_')
            || (*c >= 'a' && *c <= '~');
        if(!is_whitelisted) {
            return false;
        }
    }
    return true;
}

static amxp_expr_status_t amxp_expr_parse(amxp_expr_t* expr) {
    int yyparse_rv = 0;
    int length = 0;
    when_null(expr, exit);
    when_null(expr->expression, exit);

    expr->status = amxp_expr_status_ok;
    length = strlen(expr->expression);
    if(length == 0) {
        goto exit;
    }
    amxc_rbuffer_write(&expr->rbuffer,
                       expr->expression,
                       length);
    if(expr->expression[length - 1] != ';') {
        amxc_rbuffer_write(&expr->rbuffer, ";", 2);
    }

    expr->reader = amxp_expr_string_reader;
    expr->status = amxp_expr_status_ok;

    amxp_expr_create_lex(expr);
    yyparse_rv = yyparse(expr->scanner);
    amxp_expr_destroy_lex(expr);

    if(yyparse_rv != 0) {
        amxp_expr_node_t* node = NULL;
        expr->status = amxp_expr_status_syntax_error;
        node = amxp_expr_node_pop(&expr->nodes);
        while(node != NULL) {
            amxp_expr_node_delete(&node);
            node = amxp_expr_node_pop(&expr->nodes);
        }
    }

    amxc_rbuffer_clean(&expr->rbuffer);

exit:
    return expr->status;
}


void amxp_expr_msg(amxp_expr_t* expr, const char* format, ...) {
    va_list args;
    va_start(args, format);
    amxc_string_vsetf(&expr->msg, format, args);
    va_end(args);
}

int amxp_expr_printf(const char* format, ...) {
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    return 0;
}

bool amxp_expr_compare(amxp_expr_t* expr,
                       amxc_var_t* lvalue,
                       amxc_var_t* rvalue,
                       amxp_expr_comp_t comperator) {
    int result = 0;
    bool retval = false;

    if((comperator != amxp_expr_comp_in) &&
       (comperator != amxp_expr_comp_starts_with) &&
       (comperator != amxp_expr_comp_ends_with) &&
       (comperator != amxp_expr_comp_contains)) {
        if(!amxp_expr_are_simple_types(lvalue, rvalue)) {
            expr->status = amxp_expr_status_invalid_value;
            goto exit;
        }
    }

    switch(comperator) {
    case amxp_expr_comp_matches:
        retval = amxp_expr_match_regexp(expr, lvalue, rvalue);
        break;
    case amxp_expr_comp_starts_with:
    case amxp_expr_comp_ends_with:
        retval = amxp_expr_string_head_tail_check(lvalue, rvalue, comperator);
        break;
    case amxp_expr_comp_in:
        retval = amxp_expr_in(expr, lvalue, rvalue);
        break;
    case amxp_expr_comp_contains:
        retval = amxp_expr_in(expr, rvalue, lvalue);
        break;
    case amxp_expr_comp_equals_ignorecase:
        retval = amxp_expr_equals_ignorecase(rvalue, lvalue);
        break;
    default:
        amxc_var_compare(lvalue, rvalue, &result);
        retval = amxp_expr_comperator(result, comperator);
        break;
    }

    if(expr->verify) {
        retval = true;
    }

exit:
    return retval;
}

amxp_expr_status_t amxp_expr_call_value_func(amxp_expr_t* expr,
                                             const char* func,
                                             amxc_var_t* args,
                                             amxc_var_t* ret) {
    amxc_htable_it_t* it = amxc_htable_get(&value_funcs, func);
    amxp_expr_vfunc_t* fn = amxc_htable_it_get_data(it, amxp_expr_vfunc_t, hit);

    expr->status = amxp_expr_status_function_not_found;
    when_null(it, exit);
    if(expr->verify) {
        expr->status = amxp_expr_status_ok;
    } else {
        expr->status = fn->fn(expr, args, ret);
    }

exit:
    return expr->status;
}

bool amxp_expr_call_bool_func(amxp_expr_t* expr,
                              const char* func,
                              amxc_var_t* args) {
    int retval = false;
    amxc_htable_it_t* it = amxc_htable_get(&bool_funcs, func);
    amxp_expr_bfunc_t* fn = amxc_htable_it_get_data(it, amxp_expr_bfunc_t, hit);

    expr->status = amxp_expr_status_function_not_found;
    when_null(it, exit);
    expr->status = amxp_expr_status_ok;
    if(expr->verify) {
        retval = true;
    } else {
        retval = fn->fn(expr, args);
    }

exit:
    return retval;
}

amxp_expr_status_t amxp_expr_get_field(amxp_expr_t* expr,
                                       amxc_var_t* value,
                                       const char* path) {
    amxp_expr_status_t retval = amxp_expr_status_unknown_error;
    amxp_expr_get_field_t fn = expr->get_field;

    amxc_var_clean(value);
    if(expr->verify) {
        amxc_var_set(bool, value, true);
        retval = amxp_expr_status_ok;
        goto exit;
    }

    if(fn != NULL) {
        retval = fn(expr, value, path, expr->priv);
    }

    if(amxc_var_is_null(value)) {
        retval = amxp_expr_status_field_not_found;
        amxp_expr_msg(expr, "Field not found - %s -", path);
    }
    expr->status = retval;

exit:
    return retval;
}

amxp_expr_status_t amxp_expr_new(amxp_expr_t** expr, const char* expression) {
    amxp_expr_status_t retval = amxp_expr_status_unknown_error;
    when_null(expr, exit);
    when_null(expression, exit);

    *expr = (amxp_expr_t*) calloc(1, sizeof(amxp_expr_t));
    when_null((*expr), exit);

    retval = amxp_expr_init(*expr, expression);

exit:
    if((retval != 0) && (expr != NULL) && (*expr != NULL)) {
        amxp_expr_clean(*expr);
        free(*expr);
        *expr = NULL;
    }
    return retval;
}

void amxp_expr_delete(amxp_expr_t** expr) {
    when_null(expr, exit);
    when_null(*expr, exit);

    amxp_expr_clean(*expr);
    free(*expr);
    *expr = NULL;

exit:
    return;
}

amxp_expr_status_t amxp_expr_vbuildf_new(amxp_expr_t** expr,
                                         const char* expr_fmt,
                                         va_list args) {
    amxp_expr_status_t retval = amxp_expr_status_unknown_error;
    when_null(expr, exit);
    when_null(expr_fmt, exit);

    *expr = (amxp_expr_t*) calloc(1, sizeof(amxp_expr_t));
    when_null((*expr), exit);

    retval = amxp_expr_vbuildf(*expr, expr_fmt, args);

exit:
    if((retval != 0) && (expr != NULL) && (*expr != NULL)) {
        amxp_expr_clean(*expr);
        free(*expr);
        *expr = NULL;
    }
    return retval;
}

amxp_expr_status_t amxp_expr_buildf_new(amxp_expr_t** expr,
                                        const char* expr_fmt,
                                        ...) {
    va_list args;
    amxp_expr_status_t retval = amxp_expr_status_unknown_error;
    va_start(args, expr_fmt);
    retval = amxp_expr_vbuildf_new(expr, expr_fmt, args);
    va_end(args);
    return retval;
}

amxp_expr_status_t amxp_expr_init(amxp_expr_t* expr,
                                  const char* expression) {
    amxp_expr_status_t retval = amxp_expr_status_unknown_error;
    when_null(expr, exit);

    expr->expression = NULL;
    expr->status = amxp_expr_status_ok;
    expr->verify = false;
    expr->get_field = NULL;
    amxc_rbuffer_init(&expr->rbuffer, 0);
    amxc_string_init(&expr->msg, 0);
    amxc_lstack_init(&expr->nodes);

    when_null(expression, exit);
    expr->expression = strdup(expression);
    when_null(expr->expression, exit);

    retval = amxp_expr_parse(expr);
    if(retval == 0) {
        expr->verify = true;
        amxp_expr_node_eval(expr, amxp_expr_get_node(expr));
        expr->verify = false;
        retval = expr->status;
    }

exit:
    if((retval != amxp_expr_status_ok) && (expr != NULL)) {
        amxp_expr_node_t* node = amxp_expr_get_node(expr);
        free(expr->expression);
        expr->expression = NULL;
        amxc_lqueue_clean(&expr->nodes, NULL);
        amxp_expr_node_delete(&node);
    }
    return retval;
}

amxp_expr_status_t amxp_expr_vbuildf(amxp_expr_t* expr,
                                     const char* expr_fmt,
                                     va_list args) {
    amxp_expr_status_t retval = amxp_expr_status_unknown_error;
    int status = -1;
    amxc_string_t expression;

    amxc_string_init(&expression, 0);

    when_null(expr, exit);
    when_null(expr_fmt, exit);

    memset(expr, 0, sizeof(amxp_expr_t));

    status = amxc_string_vappendf_checked(&expression, amxp_expr_is_safe_value, expr_fmt, args);
    when_failed_status(status, exit, expr->status = amxp_expr_status_syntax_error);
    retval = amxp_expr_init(expr, amxc_string_get(&expression, 0));

exit:
    amxc_string_clean(&expression);
    return retval;
}

amxp_expr_status_t amxp_expr_buildf(amxp_expr_t* expr,
                                    const char* expr_fmt,
                                    ...) {
    va_list args;
    amxp_expr_status_t retval = amxp_expr_status_unknown_error;
    va_start(args, expr_fmt);
    retval = amxp_expr_vbuildf(expr, expr_fmt, args);
    va_end(args);
    return retval;
}

void amxp_expr_clean(amxp_expr_t* expr) {
    amxp_expr_node_t* node = NULL;
    when_null(expr, exit);

    free(expr->expression);
    expr->expression = NULL;

    node = amxp_expr_get_node(expr);
    amxp_expr_node_delete(&node);
    amxc_lstack_clean(&expr->nodes, NULL);
    amxc_rbuffer_clean(&expr->rbuffer);
    amxc_string_clean(&expr->msg);

exit:
    return;
}

void amxp_expr_dump_tree(amxp_expr_t* expr) {
    amxp_expr_node_dump(expr, amxp_expr_get_node(expr), 0, 0);
}

bool amxp_expr_evaluate(amxp_expr_t* expr,
                        amxp_expr_get_field_t fn,
                        void* priv,
                        amxp_expr_status_t* status) {
    bool rv = true;
    amxp_expr_node_t* node = NULL;

    when_null_status(expr, exit, rv = false);

    expr->get_field = fn;
    expr->priv = priv;

    node = amxp_expr_get_node(expr);
    if(node == NULL) {
        if(expr->status != amxp_expr_status_ok) {
            rv = false;
        }
    } else {
        rv = amxp_expr_node_eval(expr, node);
    }

    if((status != NULL) && (expr != NULL)) {
        *status = expr->status;
    }

exit:
    return rv;
}

bool amxp_expr_eval(amxp_expr_t* expr, amxp_expr_status_t* status) {
    return amxp_expr_evaluate(expr, NULL, NULL, status);
}

int amxp_expr_add_value_fn(const char* fn_name,
                           amxp_expr_value_func_t fn) {
    int retval = -1;
    amxp_expr_vfunc_t* vfn = NULL;

    if(amxc_htable_capacity(&value_funcs) == 0) {
        amxc_htable_init(&value_funcs, 5);
    }
    when_true(amxc_htable_contains(&value_funcs, fn_name), exit);
    vfn = (amxp_expr_vfunc_t*) calloc(1, sizeof(amxp_expr_vfunc_t));
    when_null(vfn, exit);
    vfn->fn = fn;
    retval = amxc_htable_insert(&value_funcs, fn_name, &vfn->hit);

exit:
    return retval;
}

int amxp_expr_add_bool_fn(const char* fn_name,
                          amxp_expr_bool_func_t fn) {
    int retval = -1;
    amxp_expr_bfunc_t* bfn = NULL;

    if(amxc_htable_capacity(&bool_funcs) == 0) {
        amxc_htable_init(&bool_funcs, 5);
    }

    when_true(amxc_htable_contains(&bool_funcs, fn_name), exit);
    bfn = (amxp_expr_bfunc_t*) calloc(1, sizeof(amxp_expr_bfunc_t));
    when_null(bfn, exit);
    bfn->fn = fn;
    retval = amxc_htable_insert(&bool_funcs, fn_name, &bfn->hit);

exit:
    return retval;
}

const char* amxp_expr_get_string(amxp_expr_t* expr) {
    return expr ? expr->expression : NULL;
}

CONSTRUCTOR_LVL(101) static void amxp_expr_functions_init(void) {
    amxp_expr_add_value_fn("first_existing", _value_first_of);
    amxp_expr_add_bool_fn("is_empty", _bool_is_empty);
    amxp_expr_add_bool_fn("contains", _bool_contains);
}

DESTRUCTOR_LVL(101) static void amxp_expr_functions_cleanup(void) {
    amxc_htable_clean(&value_funcs, amxp_expr_vfunc_hit_free);
    amxc_htable_clean(&bool_funcs, amxp_expr_bfunc_hit_free);
}
