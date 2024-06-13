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

#if !defined(__AMXP_EXPR_NODE_H__)
#define __AMXO_EXPR_NODE_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <amxc/amxc_macros.h>
#include <amxp/amxp_expression.h>

/**
   @file
   @brief
   Ambiorix binary expression tree node functions
 */

/**
   @ingroup amxp_expression
   @defgroup amxp_expr_node Expression Tree

   Functions to access node information in a binary expression tree
 */

/**
   @ingroup amxp_expr_node
   @brief
   Node types, corresponds to the expression parts introduced in @ref _amxp_expr expression
 */
typedef enum _amxp_expr_node_type {
    amxp_expr_compare_oper, /**< Node is a compare operator */
    amxp_expr_value,        /**< Node is a constant value */
    amxp_expr_value_func,   /**< Node is a function that returns a value */
    amxp_expr_bool_func,    /**< Node is a function that returns a boolean */
    amxp_expr_field,        /**< Node is a field value */
    amxp_expr_not,          /**< Node is a NOT logical operator ("not"/"!") */
    amxp_expr_and,          /**< Node is an AND logical operator ("and"/"&&") */
    amxp_expr_or            /**< Node is an OR logical operator ("or"/"||") */
} amxp_expr_node_type_t;

/**
   @ingroup amxp_expr_node
   @brief
   Compare operator types
   (associated to amxp_expr_compare_oper nodes).
 */
typedef enum _amxp_expr_comp {
    amxp_expr_comp_equal,             /**< Is equal comparison ("==") */
    amxp_expr_comp_not_equal,         /**< Is not equal comparison ("!=") */
    amxp_expr_comp_lesser,            /**< Is lesser comparison ("<") */
    amxp_expr_comp_bigger,            /**< Is bigger comparison (">") */
    amxp_expr_comp_lesser_equal,      /**< Is lesser or equal comparison ("<=") */
    amxp_expr_comp_bigger_equal,      /**< Is bigger or equal comparison (">=") */
    amxp_expr_comp_matches,           /**< Regular expression matching ("matches") */
    amxp_expr_comp_starts_with,       /**< Beginning of string comparison ("starts with") */
    amxp_expr_comp_in,                /**< Value is in array of values comparison ("in") */
    amxp_expr_comp_contains,          /**< Array of values contains a value comparison ("~=") */
    amxp_expr_comp_equals_ignorecase, /**< Case insensitive string comparison ("^=") */
    amxp_expr_comp_ends_with,         /**< End of string comparison ("ends with") */
} amxp_expr_comp_t;

/**
   @ingroup amxp_expr_node
   @brief
   Node entry in a binary expression tree

   Stores the type, the associated data if it exists,
   and pointers the next nodes in the tree.
 */
struct _amxp_expr_node {
    amxc_llist_it_t it;         /**< List iterator (for insertion in the tree) */
    amxp_expr_node_type_t type; /**< Type of the node */
    amxp_expr_comp_t compare;   /**< Type of compare operator if node is of type compare operator */
    amxc_var_t* value;          /**< Node value if node is a field value, constant value, or function that returns a value  */
    union {                     /**< Left node information */
        amxp_expr_node_t* node; /**< Link to another node */
        amxc_var_t* value;      /**< Value when node is a constant value */
        char* func_name;        /**< Name of function when node is a function */
        char* field;            /**< Name of field when node is a field value */
    } left;
    union {                     /* Right node information */
        amxp_expr_node_t* node; /**< Link to another node */
        amxc_llist_t args;      /**< Function arguments when node is a function that returns a value */
    } right;
};

/**
   @ingroup amxp_expr_node
   @brief
   Returns the top node of a binary expression tree

   Returns an amxp_expr_node_t pointer to the first entry
   in the internal stack of nodes of an amxp_expr_t structure

   @param expr pointer to an amxp_expr_t structure, should not be NULL

   @return
   A pointer to amxp_expr_node_t, or NULL if the amxp_expr_t structure
   has no entries in its internal stack of nodes
 */
amxp_expr_node_t* amxp_expr_get_node(amxp_expr_t* expr);

/**
   @ingroup amxp_expr_node
   @brief
   Gets the value attached to a node, if it exists

   The nodes of the following @ref amxp_expr_node_type_t types will redirect to a value :
   - amxp_expr_value
   - amxp_expr_field
   - amxp_expr_value_func
   The rest of the types will be ignored, returning NULL

   @param expr pointer to an amxp_expr_t structure, should not be NULL
   @param node pointer to an amxp_expr_node_t structure, should not be NULL

   @return
   A pointer to amxp_var_t, or NULL if the node does not point to a value
 */
amxc_var_t* amxp_expr_node_get_value(amxp_expr_t* expr, amxp_expr_node_t* node);

/**
   @ingroup amxp_expr_node
   @brief
   Evaluates an expression starting from a specific node

   @param expr pointer to an amxp_expr_t structure, should not be NULL
   @param node pointer to an amxp_expr_node_t structure

   @return
   - true when the expression evaluates to true
   - false when the expression evaluates to false
 */
bool amxp_expr_node_eval(amxp_expr_t* expr, amxp_expr_node_t* node);

#ifdef __cplusplus
}
#endif

#endif // __AMXP_EXPR_NODE_H__

