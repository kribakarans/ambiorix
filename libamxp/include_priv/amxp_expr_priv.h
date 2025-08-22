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

#if !defined(__AMXP_EXPR_PRIV_H__)
#define __AMXO_EXPR_PRIV_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <amxc/amxc_macros.h>
#include <amxp/amxp_expression.h>
#include <amxp/amxp_expr_node.h>

enum amxp_expr_tokens_t {
    token_eof
};

typedef struct _amxp_txt {
    char* txt;
    int length;
} amxp_txt_t;

PRIVATE
void amxp_expr_create_lex(amxp_expr_t* expr);

PRIVATE
void amxp_expr_destroy_lex(amxp_expr_t* expr);

PRIVATE
void amxp_expr_msg(amxp_expr_t* expr, const char* format, ...) \
    __attribute__ ((format(printf, 2, 3)));

PRIVATE
int amxp_expr_printf(const char* format, ...) \
    __attribute__ ((format(printf, 1, 2)));

PRIVATE
bool amxp_expr_compare(amxp_expr_t* expr,
                       amxc_var_t* lvalue,
                       amxc_var_t* rvalue,
                       amxp_expr_comp_t comperator);

PRIVATE
amxp_expr_status_t amxp_expr_call_value_func(amxp_expr_t* expr,
                                             const char* func,
                                             amxc_var_t* args,
                                             amxc_var_t* ret);

PRIVATE
bool amxp_expr_call_bool_func(amxp_expr_t* expr,
                              const char* func,
                              amxc_var_t* args);

PRIVATE
amxp_expr_status_t amxp_expr_get_field(amxp_expr_t* expr,
                                       amxc_var_t* var,
                                       const char* path);


PRIVATE
void amxp_expr_node_new(amxp_expr_node_t** node, amxp_expr_node_type_t type);

PRIVATE
void amxp_expr_node_delete(amxp_expr_node_t** node);

PRIVATE
void amxp_expr_node_push(amxc_lstack_t* stack, amxp_expr_node_t* node);

PRIVATE
amxp_expr_node_t* amxp_expr_node_pop(amxc_lstack_t* stack);

PRIVATE
void amxp_expr_node_set_left(amxp_expr_node_t* node, amxp_expr_node_t* left);

PRIVATE
void amxp_expr_node_set_right(amxp_expr_node_t* node, amxp_expr_node_t* right);

PRIVATE
void amxp_expr_node_set_value(amxp_expr_node_t* node, amxc_var_t* value);

PRIVATE
void amxp_expr_node_set_function(amxp_expr_node_t* node, char* func_name);

PRIVATE
void amxp_expr_node_set_field(amxp_expr_node_t* node, char* field);

PRIVATE
void amxp_expr_node_set_compop(amxp_expr_node_t* node, amxp_expr_comp_t comop);

PRIVATE
void amxp_expr_node_add_value(amxp_expr_node_t* node, amxp_expr_node_t* value);

PRIVATE
void amxp_expr_node_dump(amxp_expr_t* expr, amxp_expr_node_t* node, uint32_t level, uint32_t parent_id);

#ifdef __cplusplus
}
#endif

#endif // __AMXP_EXPR_PRIV_H__

