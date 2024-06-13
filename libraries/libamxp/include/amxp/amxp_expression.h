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

#if !defined(__AMXP_EXPR_H__)
#define __AMXP_EXPR_H__

#ifdef __cplusplus
extern "C"
{
#endif

/**
   @file
   @brief
   Ambiorix expression parser and evaluate API header file
 */

/**
   @defgroup amxp_expression Expressions
   @brief
   Logical expression parser and evaluator

   An logical expression evaluates to true or to false.

   An expression can consist out of multiple expression parts, concatenated with
   a logical "OR" or logical "AND"

   Syntax of an expression part
   @code{.c}
   VALUE COMPARE OPERATOR VALUE
   @endcode

   Each expression part has compare operator, a left value and a right value.

   An VALUE can be:
   - a field - name of a field, field names may be put between "{" and "}".
   - a constant value - string, number, array, boolean, ...
   - a function - must be a function that returns a value

   Boolean values are case insensitive. There will be a match for true, True or even TrUe.
   The same comment applies to false.

   The supported COMPARE OPERATORS are:
   - "==" - is equal to
   - "!=" - is not equal to
   - "<" - is lesser then
   - ">" - is bigger then
   - "<=" - is lesser then or equal to
   - ">=" - is bigger then or equal to
   - "matches" - matches a regular expression, right value must be a regular expression
   - "starts with" - string starts with a string, right value must be a string (text)
                     or a list of strings.
                     When the right value is a list of strings and the left value
                     starts with any of the strings in the list it is considered a
                     match.
   - "ends with" - string ends with a string, right value must be a string (text)
                     or a list of strings.
                     When the right value is a list of strings and the left value
                     ends with any of the strings in the list it is considered a
                     match.
   - "in" - value is in an array of values, right value must be an array
            When right value is a comma separated string or a space separated string
            the strings are used as an array of values.
            When the right value is a string, the check will verify if the value
            occurst at least once in the string.
   - "~=" - checks if an array of values contains a value, left value must be an array.
            When left value is a comma separated string or a space sperated string
            the strings are used as an array of values.
            If the left value is a string, the check will verify if the value occurs
            at least once in the string.
   - "^=" - string comparison ignoring uppercase/lowercase. Both the left value and the right value
            are converted to string before doing the comparison.

   Supported logical operators:
   - "not", "!" - not
   - "and", "&&" - and
   - "or", "||" - or

   @par Example
   @code{.c}
   first_name in ['Tess', 'Olivia', 'Abraham'] && age < 25
   @endcode

 */

typedef struct _amxp_expr amxp_expr_t;

/**
   @ingroup amxp_expression
   @brief
   Expression status/error codes.
 */
typedef enum _expr_status {
    amxp_expr_status_ok,                 /**< No error, all ok*/
    amxp_expr_status_unknown_error,      /**< Unknown error */
    amxp_expr_status_syntax_error,       /**< Expression has incorrect syntax */
    amxp_expr_status_field_not_found,    /**< Value field is not found */
    amxp_expr_status_invalid_regexp,     /**< Invalid regular expression provided (matches) */
    amxp_expr_status_invalid_value,      /**< Invalid value provided */
    amxp_expr_status_function_not_found, /**< Function not found */
} amxp_expr_status_t;


/**
   @ingroup amxp_expression
   @brief
   Expression reader function.

   A ringbuffer is used to store the expression and read from it during
   parsing of the expression.

   Currently it is not possible to implement a custom reader function and
   set that function pointer.
 */
typedef ssize_t (* amxp_expr_reader_t) (amxp_expr_t* expr,
                                        void* buf,
                                        size_t max_size);

/**
   @ingroup amxp_expression
   @brief
   Field fetcher function signature.

   An logical expression with only constant values is not very usefull.

   A field fetcher function can be implemented and is used during the
   expression evaluation to get values for the fields used in the expression.

   Depending on the situation or the specific problem a custom field fetcher is
   needed. When using libamxc variants as data, the field fetcher
   @ref amxp_expr_get_field_var can be used.

   @param expr pointer to the expression structure
   @param value the variant in which the value must be stored
   @param path the field
   @param priv the private user data

   @return
   An expression status, should be @ref amxp_expr_status_ok when the value for
   the field was fetched correctly.
 */
typedef  amxp_expr_status_t (* amxp_expr_get_field_t) (amxp_expr_t* expr,
                                                       amxc_var_t* value,
                                                       const char* path,
                                                       void* priv);

/**
   @ingroup amxp_expression
   @brief
   Callback function that can "calculate" a value

   Not all values can be expressed as a field or a constant, sometimes more
   complex operations are used. It is possible to define custom value calculation
   methods and register them using @ref amxp_expr_add_value_fn.

   Value functions can be used in any location in an expression where a value
   is needed.

   @param expr pointer to the expression structure
   @param args variant containing the arguments of the function
   @param ret The calculated value

   @return
   An expression status, should be @ref amxp_expr_status_ok when the value is
   calculated successfull.
 */
typedef  amxp_expr_status_t (* amxp_expr_value_func_t) (amxp_expr_t* expr,
                                                        amxc_var_t* args,
                                                        amxc_var_t* ret);

/**
   @ingroup amxp_expression
   @brief
   Callback function that evaluates to true or false

   Not all values can be expressed as a field or a constant, sometimes more
   complex operations are used. It is possible to define custom boolean
   method that evaluates the provided arguments and returns true or false.

   Boolean functions can be used in any location in an expression when
   a logical expression is needed.

   @param expr pointer to the expression structure
   @param args variant containing the arguments of the function

   @return
   Returns true or false
 */
typedef  bool (* amxp_expr_bool_func_t) (amxp_expr_t* expr,
                                         amxc_var_t* args);

typedef struct _amxp_expr_node amxp_expr_node_t;

/**
   @ingroup amxp_expression
   @brief
   Main expression data structure, used for expression storage and operations.
 */
struct _amxp_expr {
    void* scanner;                   /**< Flex scanner */
    char* expression;                /**< The expression */
    amxc_rbuffer_t rbuffer;          /**< Ring buffer */

    bool verify;                     /**< When set only verify syntax */
    amxp_expr_status_t status;       /**< Parser status */
    amxc_string_t msg;               /**< Parser message */
    amxp_expr_reader_t reader;       /**< Reader function */

    amxc_lstack_t nodes;             /**< internal use*/

    amxp_expr_get_field_t get_field; /**< callback function */
    void* priv;                      /**< User private data, passed as is to a field fetcher */
};

/**
   @ingroup amxp_expression
   @brief
   Allocates and initializes an expression

   Allocates memory on the heap to store the expression data structure.
   The provided expression is parsed and stored for later use.
   When the expression is invalid an error is returned and no memory is allocated.

   Once an expression structure is available, it can be reused many times.

   @note
   The allocated memory must be freed when not used anymore,
   use @ref amxp_expr_delete to free the memory

   @param expr a pointer to the location where the pointer to the new expression
               can be stored
   @param expression a string containing a logical expression.

   @return
   amxp_expr_status_ok if memory is allocated and the given expression is
   valid (syntax). When an error occurred the function will return any of the
   @ref amxp_expr_status_t values
 */
amxp_expr_status_t amxp_expr_new(amxp_expr_t** expr, const char* expression);

/**
   @ingroup amxp_expression
   @brief
   Allocates and initializes an expression with format-string and safety checks

   Allocates memory on the heap to store the expression data structure.

   The provided expression format string and the replacement values are used
   to build the expression string. In the expression format string the nth placeholders
   is replaced with the nth replacement value in the variadic arguments (`...`).

   The supported placeholders ('%s', '%i', ...) are the ones supported by amxc_string_appendf_escape.

   Example of a expression format string:
   @code
   "password == '%s' and user == '%s'"
   @endcode

   When the variadic arguments are:
   @code{.json}
   ["mypassword","admin"]
   @endcode

   The expression string that is build will be:
   @code
   "password == 'mypassword' and user == 'admin'"
   @endcode

   Each value in the values variant is verified to avoid the expression, or the
   context of the expression, being interpreted in an unintended way.

   Example of invalid values:
   @code{.json}
   ["mypassword' or true or '' = '", "admin"]
   @endcode

   This would resolve into the following expression string:
   @code
   "password == 'mypassword' or true or '' = '' and user == 'admin'"
   @endcode

   Which is not the intention, so the first value is considered invalid and
   the expression build will fail.

   The builded expression string is parsed and stored for later use.
   When the expression is invalid an error is returned and no memory is allocated.

   Once an expression structure is available, it can be reused many times.

   @note
   The allocated memory must be freed when not used anymore,
   use @ref amxp_expr_delete to free the memory

   @param expr a pointer to the location where the pointer to the new expression
               can be stored
   @param expr_fmt a string containing a logical expression with placeholders.

   @return
   amxp_expr_status_ok if memory is allocated and the given expression is
   valid (syntax). When an error occurred the function will return any of the
   @ref amxp_expr_status_t values
 */
amxp_expr_status_t amxp_expr_buildf_new(amxp_expr_t** expr,
                                        const char* expr_fmt,
                                        ...) \
    __attribute__ ((format(printf, 2, 3)));

/**
   @ingroup amxp_expression
   @brief
   va_list version of @ref amxp_expr_buildf_new

   @param expr a pointer to the location where the pointer to the new expression
               can be stored
   @param expr_fmt a string containing a logical expression with placeholders.
   @param args va list of arguments.

   @return
   amxp_expr_status_ok if memory is allocated and the given expression is
   valid (syntax). When an error occurred the function will return any of the
   @ref amxp_expr_status_t values
 */
amxp_expr_status_t amxp_expr_vbuildf_new(amxp_expr_t** expr,
                                         const char* expr_fmt,
                                         va_list args);

/**
   @ingroup amxp_expression
   @brief
   Deletes a previously allocated expression structure

   Frees memory previously allocated.

   @param expr a pointer to the location where the pointer to the allocated expression
 */
void amxp_expr_delete(amxp_expr_t** expr);

/**
   @ingroup amxp_expression
   @brief
   Initializes an expression structure

   The same as @ref amxp_expr_buildf_new but without new heap-allocation.

   @note
   Make sure that @ref amxp_expr_clean (and not @ref amxp_expr_delete) is called when the
   expression is not needed anymore. It is possible that the expression parser allocates
   memory at initialization time, which must be freed when the expression is not needed anymore.

   @param expr a pointer to the location where the pointer to the new expression
               can be stored
   @param expr_fmt a string containing a logical expression with placeholders.

   @return
   amxp_expr_status_ok if memory is allocated and the given expression is
   valid (syntax). When an error occurred the function will return any of the
   @ref amxp_expr_status_t values
 */
amxp_expr_status_t amxp_expr_buildf(amxp_expr_t* expr,
                                    const char* expr_fmt,
                                    ...) \
    __attribute__ ((format(printf, 2, 3)));

/**
   @ingroup amxp_expression
   @brief
   va_list version of @ref amxp_expr_buildf

   @param expr a pointer to the location where the pointer to the new expression
               can be stored
   @param expr_fmt a string containing a logical expression with placeholders.
   @param args va list of arguments.

   @return
   amxp_expr_status_ok if memory is allocated and the given expression is
   valid (syntax). When an error occurred the function will return any of the
   @ref amxp_expr_status_t values
 */
amxp_expr_status_t amxp_expr_vbuildf(amxp_expr_t* expr,
                                     const char* expr_fmt,
                                     va_list args);

/**
   @ingroup amxp_expression
   @brief
   Initializes an expression structure

   The provided expression is parsed and stored for later use.
   When the expression is invalid an error is returned.

   Once an expression structure is initialized, it can be reused many times.

   @note
   Make sure that @ref amxp_expr_clean is called when the expression is not needed
   anymore. It is possible that the expression parser allocates memory at initialization
   time, which must be freed when the expression is not needed anymore.

   @param expr a pointer to the expression structure
   @param expression a string containing a logical expression.

   @return
   amxp_expr_status_ok if the given expression is valid (syntax).
   When an error occurred the function will return any of the
   @ref amxp_expr_status_t values
 */
amxp_expr_status_t amxp_expr_init(amxp_expr_t* expr, const char* expression);

/**
   @ingroup amxp_expression
   @brief
   Clean-up the expression structure

   Cleans up all internally allocated memory.
   After calling this function the expression data structure must be re-initialized
   before use.

   @param expr a pointer to the expression structure
 */
void amxp_expr_clean(amxp_expr_t* expr);

/**
   @ingroup amxp_expression
   @brief
   Dumps the binary tree in dot formatted text file to stdout.

   Using the output as input to the dot tool a graph can be created the represents
   the builded binary tree by the expression parser.

   @param expr a pointer to the expression structure
 */
void amxp_expr_dump_tree(amxp_expr_t* expr);

/**
   @ingroup amxp_expression
   @brief
   Evaluates an expression

   If the expression provided (see @ref amxp_expr_init or @ref amxp_expr_new)
   contains fields, the field fetcher callback is called for each field encountered
   in the expression. The field fetcher callback function must return the
   value represented by the field.

   How the field fetcher works depends on the implementation.

   If no field fetcher callback is set  and the expression contains fields,
   the expression will evaluate to false and the status code is set to
   @ref amxp_expr_status_field_not_found.

   @note
   When an error occurs while evaluating the expression the return value will be
   false, check the status parameter to get the error code.

   @param expr a pointer to the expression structure
   @param fn a field fetcher callback function.
   @param priv private data pointer, is passed as is to the field fetcher callback function
   @param status will contain the status code,

   @return
   - true when the expression evaluates to true (status will be amxp_expr_status_ok)
   - false when the expression evaluates to false (status can be an error code)
 */
bool amxp_expr_evaluate(amxp_expr_t* expr,
                        amxp_expr_get_field_t fn,
                        void* priv,
                        amxp_expr_status_t* status);

/**
   @ingroup amxp_expression
   @brief
   Evaluates an expression

   Calls @ref amxp_expr_evaluate without a field fetcher callback function.

   Can only be used with expressions that don't contain any fields

   @param expr a pointer to the expression structure
   @param status will contain the status code,

   @return
   - true when the expression evaluates to true (status will be amxp_expr_status_ok)
   - false when the expression evaluates to false (status can be an error code)
 */
bool amxp_expr_eval(amxp_expr_t* expr, amxp_expr_status_t* status);

/**
   @ingroup amxp_expression
   @brief
   Evaluates an expression against a composite variant

   Calls @ref amxp_expr_evaluate with a field fetcher callback function (see
   @ref amxp_expr_get_field_var)
   The values of the fields in the expression are fetched from the given variant.

   @param expr a pointer to the expression structure
   @param data a variant
   @param status will contain the status code,

   @return
   - true when the expression evaluates to true (status will be amxp_expr_status_ok)
   - false when the expression evaluates to false (status can be an error code)
 */
bool amxp_expr_eval_var(amxp_expr_t* expr,
                        const amxc_var_t* const data,
                        amxp_expr_status_t* status);

/**
   @ingroup amxp_expression
   @brief
   Search matching variant paths in a composite variant

   Using expressions or a wildcard '*' at the position of a list variant or a
   table variant the mathcing variants are filtered out. The expressions must be
   put between square brackets.

   All matching variant paths are added to the linked list. The value of each
   matching variant can be fetched using the GET macros provided in libamxc

   Example:

   Data set in json notation
   @code{.json}
   {
      "00:01:02:03:44:f0": [
      ],
      "94:83:c4:06:da:66": [
          {
              "Extender": true,
              "MACAddress": "00:01:02:03:44:f0"
          },
          {
              "Extender": false,
              "MACAddress" : "00:00:55:3b:05",
          }
      ]
   }
   @endcode

   Search path: "94:83:c4:06:da:66.[MACAddress == '00:01:02:03:44:f0'].Extender"
   Result: ["'94:83:c4:06:da:66'.0.'Extender'"]

   Search path: "94:83:c4:06:da:66.*.Extender"
   Result: ["'94:83:c4:06:da:66'.0.'Extender'", "'94:83:c4:06:da:66'.1.'Extender'"]

   @param var the composite variant
   @param paths a linked list that will be filled with all paths to the variants
                that match
   @param path the variant path, it may contain wildcards or expressions

   @return
   0 when successfull, any other value indicates an error.
 */
int amxp_expr_find_var_paths(const amxc_var_t* const var,
                             amxc_llist_t* paths,
                             const char* path);

/**
   @ingroup amxp_expression
   @brief
   Search matching variant paths in a composite variant

   Using expressions or a wildcard '*' at the position of a list variant or a
   table variant the mathcing variants are filtered out. The expressions must be
   put between square brackets.

   All matching variant paths are added to the hash table. The keys in the table
   are the matching variant paths, the values are copies of the mathcing variants.

   Example:

   Data set in json notation
   @code{.json}
   {
      "00:01:02:03:44:f0": [
      ],
      "94:83:c4:06:da:66": [
          {
              "Extender": true,
              "MACAddress": "00:01:02:03:44:f0"
          },
          {
              "Extender": false,
              "MACAddress" : "00:00:55:3b:05",
          }
      ]
   }
   @endcode

   Search path: "94:83:c4:06:da:66.[MACAddress == '00:01:02:03:44:f0'].Extender"
   Result: {"'94:83:c4:06:da:66'.0.'Extender'" = true}

   Search path: "94:83:c4:06:da:66.*.Extender"
   Result: {"'94:83:c4:06:da:66'.0.'Extender'" = true, "'94:83:c4:06:da:66'.1.'Extender'" = false }

   @param var the composite variant
   @param values a htable that will be filled with all paths and values of the variants
                that match the given path
   @param path the variant path, it may contain wildcards or expressions

   @return
   0 when successfull, any other value indicates an error.
 */
int amxp_expr_find_var_values(const amxc_var_t* const var,
                              amxc_htable_t* values,
                              const char* path);

/**
   @ingroup amxp_expression
   @brief
   Search a matching variant and returns a pointer to that variant

   Using expressions or a wildcard '*' at the position of a list variant or a
   table variant the mathcing variants are filtered out. The expressions must be
   put between square brackets.

   When multiple variants are matching the path, a NULL pointer is returned.

   When multiple variants paths can match you can use @ref amxp_expr_find_var_values
   or @ref amxp_expr_find_var_paths instead.

   @param var the composite variant
   @param path the variant path, it may contain wildcards or expressions

   @return
   NULL when zero or more then one variants are matching, or a pointer to a
   variant is there is exactly one matching.
 */
amxc_var_t* amxp_expr_find_var(const amxc_var_t* const var,
                               const char* path);
/**
   @ingroup amxp_expression
   @brief
   Variant field fetcher implementation

   Used by @ref amxp_expr_eval_var.
   This function should not be called directly.

   @param expr a pointer to the expression structure
   @param value the value of the field, filled by this function
   @param path the field name
   @param priv the private data as provided to @ref amxp_expr_evaluate

   @return
   The status code
 */
amxp_expr_status_t amxp_expr_get_field_var(amxp_expr_t* expr,
                                           amxc_var_t* value,
                                           const char* path,
                                           void* priv);

/**
   @ingroup amxp_expression
   @brief
   Evaluates an expression against a set

   Calls @ref amxp_expr_evaluate with a field fetcher callback function (see
   @ref amxp_expr_get_field_set)
   The values of the fields in the expression are flags that are or are not in the
   given set.

   @param expr a pointer to the expression structure
   @param data a set
   @param status will contain the status code,

   @return
   - true when the expression evaluates to true
   - false when the expression evaluates to false
 */
bool amxp_expr_eval_set(amxp_expr_t* expr,
                        const amxc_set_t* const data,
                        amxp_expr_status_t* status);

/**
   @ingroup amxp_expression
   @brief
   Flag field fetcher implementation for sets

   Used by @ref amxp_expr_eval_set.
   This function should not be called directly.

   @param expr a pointer to the expression structure
   @param value the value of the field, filled by this function
   @param path the flag name
   @param priv the private data as provided to @ref amxp_expr_evaluate

   @return
   The status code
 */
amxp_expr_status_t amxp_expr_get_field_set(amxp_expr_t* expr,
                                           amxc_var_t* value,
                                           const char* path,
                                           void* priv);

/**
   @ingroup amxp_expression
   @brief
   Adds a value calculation function

   Adds a callback function with a given name to the possible value calculation
   functions.

   @param fn_name name of the function with which it can be used in the expressions
   @param fn the function pointer and must match @ref amxp_expr_value_func_t signature

   @return
   0 when the function is added, any other value otherwise
 */
int amxp_expr_add_value_fn(const char* fn_name,
                           amxp_expr_value_func_t fn);

/**
   @ingroup amxp_expression
   @brief
   Adds a boolean evaluation function

   Adds a callback function with a given name to the possible boolean
   evaluation functions.

   @param fn_name name of the function with which it can be used in the expressions
   @param fn the function pointer and must match @ref amxp_expr_bool_func_t signature

   @return
   0 when the function is added, any other value otherwise
 */
int amxp_expr_add_bool_fn(const char* fn_name,
                          amxp_expr_bool_func_t fn);

/**
   @ingroup amxp_expression
   @brief
   Returns the string representation of the given expression.

   @param expr a pointer to the expression structure

   @return
   The string representation of the expression, or NULL if there is none.
 */
const char* amxp_expr_get_string(amxp_expr_t* expr);

#ifdef __cplusplus
}
#endif

#endif // __AMXP_EXPR_H__

