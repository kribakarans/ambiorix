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

#include <stdio.h>
#include <stdlib.h>
#include <amxc/amxc.h>

#include "amxp_expr_priv.h"

static void amxp_expr_node_clean_args(amxc_llist_it_t* it) {
    amxp_expr_node_t* node = amxc_container_of(it, amxp_expr_node_t, it);
    amxp_expr_node_delete(&node);
}

static void amxp_expr_node_build_args(amxp_expr_t* expr, amxc_var_t* value, amxc_llist_t* args) {
    amxc_var_set_type(value, AMXC_VAR_ID_LIST);
    amxc_llist_for_each(it, args) {
        amxp_expr_node_t* value_node = amxc_container_of(it, amxp_expr_node_t, it);
        amxc_var_t* v = amxp_expr_node_get_value(expr, value_node);
        amxc_var_set_index(value, -1, v, AMXC_VAR_FLAG_DEFAULT);
        expr->status = amxp_expr_status_ok;
    }
}

static const char* amxp_expr_compop2string(amxp_expr_comp_t op) {
    const char* string[] = {
        "==",
        "!=",
        "\\<",
        "\\>",
        "\\<=",
        "\\>=",
        "matches",
        "starts with",
        "in",
        "~=",
        "^=",
        "ends with"
    };

    return string[op];
}

void amxp_expr_node_new(amxp_expr_node_t** node, amxp_expr_node_type_t type) {
    *node = (amxp_expr_node_t*) calloc(1, sizeof(amxp_expr_node_t));
    (*node)->type = type;
}

void amxp_expr_node_delete(amxp_expr_node_t** node) {
    when_null(node, exit);
    when_null(*node, exit);

    amxc_llist_it_take(&(*node)->it);
    switch((*node)->type) {
    case amxp_expr_compare_oper:
    case amxp_expr_and:
    case amxp_expr_or:
        amxp_expr_node_delete(&(*node)->left.node);
        amxp_expr_node_delete(&(*node)->right.node);
        break;
    case amxp_expr_not:
        amxp_expr_node_delete(&(*node)->left.node);
        break;
    case amxp_expr_value:
        if((amxc_var_type_of((*node)->left.value) == AMXC_VAR_ID_LIST) ||
           ((*node)->left.value == NULL)) {
            amxc_llist_clean(&(*node)->right.args, amxp_expr_node_clean_args);
        }
        amxc_var_delete(&(*node)->left.value);
        break;
    case amxp_expr_value_func:
    case amxp_expr_bool_func:
        free((*node)->left.func_name);
        (*node)->left.func_name = NULL;
        amxc_var_delete(&(*node)->value);
        amxc_llist_clean(&(*node)->right.args, amxp_expr_node_clean_args);
        break;
    case amxp_expr_field:
        free((*node)->left.field);
        amxc_var_delete(&(*node)->value);
        break;
    }
    free(*node);
    *node = NULL;
exit:
    return;
}

void amxp_expr_node_push(amxc_lstack_t* stack, amxp_expr_node_t* node) {
    amxc_lstack_push(stack, &node->it);
}

amxp_expr_node_t* amxp_expr_node_pop(amxc_lstack_t* stack) {
    amxp_expr_node_t* node = NULL;
    amxc_lstack_it_t* it = amxc_lstack_pop(stack);

    when_null(it, exit);
    node = amxc_container_of(it, amxp_expr_node_t, it);

exit:
    return node;
}

void amxp_expr_node_set_left(amxp_expr_node_t* node, amxp_expr_node_t* left) {
    node->left.node = left;
    amxc_llist_it_take(&left->it);
}

void amxp_expr_node_set_right(amxp_expr_node_t* node, amxp_expr_node_t* right) {
    node->right.node = right;
    amxc_llist_it_take(&right->it);
}

void amxp_expr_node_set_value(amxp_expr_node_t* node, amxc_var_t* value) {
    node->left.value = value;
}

void amxp_expr_node_set_function(amxp_expr_node_t* node, char* func_name) {
    node->left.func_name = func_name;
}

void amxp_expr_node_set_field(amxp_expr_node_t* node, char* field) {
    node->left.field = field;
}

void amxp_expr_node_set_compop(amxp_expr_node_t* node, amxp_expr_comp_t comop) {
    node->compare = comop;
}

void amxp_expr_node_add_value(amxp_expr_node_t* node, amxp_expr_node_t* value) {
    amxc_llist_append(&node->right.args, &value->it);
}

amxp_expr_node_t* amxp_expr_get_node(amxp_expr_t* expr) {
    amxp_expr_node_t* node = NULL;
    amxc_llist_it_t* it = amxc_llist_get_first(&expr->nodes);
    when_null(it, exit);

    node = amxc_container_of(it, amxp_expr_node_t, it);

exit:
    return node;
}

amxc_var_t* amxp_expr_node_get_value(amxp_expr_t* expr, amxp_expr_node_t* node) {
    amxc_var_t* value = NULL;
    switch(node->type) {
    case amxp_expr_value:
        if((node->left.value == NULL) ||
           (amxc_var_type_of(node->left.value) == AMXC_VAR_ID_LIST)) {
            if(node->left.value == NULL) {
                amxc_var_new(&node->left.value);
            }
            value = node->left.value;
            amxc_llist_clean(&value->data.vl, NULL);
            amxp_expr_node_build_args(expr, value, &node->right.args);
        } else {
            value = node->left.value;
        }
        break;
    case amxp_expr_field:
        if(node->value == NULL) {
            amxc_var_new(&node->value);
        }
        amxp_expr_get_field(expr, node->value, node->left.field);
        if(expr->status == amxp_expr_status_ok) {
            value = node->value;
        } else {
            amxc_var_set_type(node->value, AMXC_VAR_ID_NULL);
            value = node->value;
        }
        break;
    case amxp_expr_value_func: {
        amxc_var_t args;
        amxc_var_init(&args);
        amxp_expr_node_build_args(expr, &args, &node->right.args);
        if(node->value == NULL) {
            amxc_var_new(&node->value);
        }
        amxp_expr_call_value_func(expr, node->left.func_name, &args, node->value);
        amxc_llist_clean(&args.data.vl, NULL);
        value = node->value;
    }
    break;
    default:
        break;
    }

    return value;
}

bool amxp_expr_node_eval(amxp_expr_t* expr, amxp_expr_node_t* node) {
    bool result = true;
    when_null(node, exit);

    switch(node->type) {
    case amxp_expr_and: {
        bool right = false;
        bool left = amxp_expr_node_eval(expr, node->left.node);
        if(!left) {
            result = left;
        } else {
            right = amxp_expr_node_eval(expr, node->right.node);
            result = (left && right);
        }
    }
    break;
    case amxp_expr_or: {
        bool right = false;
        bool left = amxp_expr_node_eval(expr, node->left.node);
        if(left) {
            result = left;
        } else {
            right = amxp_expr_node_eval(expr, node->right.node);
            result = (left || right);
        }
    }
    break;
    case amxp_expr_not:
        result = !amxp_expr_node_eval(expr, node->left.node);
        break;
    case amxp_expr_compare_oper: {
        amxc_var_t* left_value = amxp_expr_node_get_value(expr, node->left.node);
        amxc_var_t* right_value = amxp_expr_node_get_value(expr, node->right.node);
        if(!amxc_var_is_null(left_value) && !amxc_var_is_null(right_value)) {
            result = amxp_expr_compare(expr, left_value, right_value, node->compare);
        } else {
            result = false;
        }
    }
    break;
    case amxp_expr_value:
        if(amxc_var_type_of(node->left.value) != AMXC_VAR_ID_BOOL) {
            expr->status = amxp_expr_status_invalid_value;
            result = false;
        } else {
            result = amxc_var_constcast(bool, node->left.value);
        }
        break;
    case amxp_expr_field:
        if(node->value == NULL) {
            amxc_var_new(&node->value);
        }
        amxp_expr_get_field(expr, node->value, node->left.field);
        if(expr->status != amxp_expr_status_ok) {
            result = false;
        } else {
            result = amxc_var_constcast(bool, node->value);
        }
        break;
    case amxp_expr_bool_func: {
        amxc_var_t args;
        amxc_var_init(&args);
        amxp_expr_node_build_args(expr, &args, &node->right.args);
        result = amxp_expr_call_bool_func(expr, node->left.func_name, &args);
        amxc_llist_clean(&args.data.vl, NULL);
    }
    break;
    default:
        break;
    }

exit:
    return result;
}

void amxp_expr_node_dump(amxp_expr_t* expr, amxp_expr_node_t* node, uint32_t level, uint32_t parent_id) {
    static uint32_t id = 0;
    uint32_t current_id = 0;

    when_null(node, exit);

    if(level == 0) {
        amxc_string_t expr_txt;
        amxc_string_init(&expr_txt, 0);
        amxc_string_setf(&expr_txt, "%s", expr->expression);
        amxc_string_replace(&expr_txt, "\"", "\\\"", UINT32_MAX);
        printf("digraph D {\n");
        printf("graph [ordering=\"out\"];\n");
        printf("label = \"%s\";\n", amxc_string_get(&expr_txt, 0));
        printf("labelloc = \"t\";\n");
        id = 1;
        parent_id = 0;
        amxc_string_clean(&expr_txt);
    } else {
        id++;
    }

    current_id = id;

    printf("node_%d", current_id);
    switch(node->type) {
    case amxp_expr_compare_oper:
        printf("[shape=\"record\" label=\"{COMPARE|%s}\"];\n", amxp_expr_compop2string(node->compare));
        amxp_expr_node_dump(expr, node->left.node, level + 1, current_id);
        amxp_expr_node_dump(expr, node->right.node, level + 1, current_id);
        break;
    case amxp_expr_and:
        printf("[shape=\"box\" label=\"AND\"];\n");
        amxp_expr_node_dump(expr, node->left.node, level + 1, current_id);
        amxp_expr_node_dump(expr, node->right.node, level + 1, current_id);
        break;
    case amxp_expr_or:
        printf("[shape=\"box\" label=\"OR\"];\n");
        amxp_expr_node_dump(expr, node->left.node, level + 1, current_id);
        amxp_expr_node_dump(expr, node->right.node, level + 1, current_id);
        break;
    case amxp_expr_not:
        printf("[shape=\"box\" label=\"NOT\"];\n");
        amxp_expr_node_dump(expr, node->left.node, level + 1, current_id);
        break;
    case amxp_expr_value: {
        char* value = amxc_var_dyncast(cstring_t, node->left.value);
        printf("[shape=\"record\" label=\"{VALUE|%s}\"];\n", value);
        free(value);
    }
    break;
    case amxp_expr_value_func:
        printf("[shape=\"record\" label=\"{VALUE FUNCTION|%s}\"];\n", node->left.func_name);
        break;
    case amxp_expr_bool_func:
        printf("[shape=\"record\" label=\"{BOOL FUNCTION|%s}\"];\n", node->left.func_name);
        break;
    case amxp_expr_field:
        printf("[shape=\"record\" label=\"{FIELD|%s}\"];\n", node->left.field);
        break;
    }

    if(parent_id != 0) {
        printf("node_%d -> node_%d;\n", parent_id, current_id);
    }

    if(level == 0) {
        printf("}\n");
    }

exit:
    return;
}