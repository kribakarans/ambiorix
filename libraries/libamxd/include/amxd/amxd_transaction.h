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

#if !defined(__AMXD_TRANSACTION_H__)
#define __AMXD_TRANSACTION_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <amxd/amxd_types.h>

/**
   @file
   @brief
   Ambiorix Data Model API header file
 */

/**
   @defgroup amxd_transaction Transactions

   @brief
   A transaction is a sequence of actions that needs to be performed on
   one or more objects.

   The squence of actions (transaction) can be considered as an atomic operation.
   Either all actions succeed or none is applied.

   Typically an object is selected to work on with @ref amxd_trans_select_pathf
   or @ref amxd_trans_select_object, and the a set of actions is added.

   Adding action to a transaction have no effect immediatly. The actions are
   executed as soon as @ref amxd_trans_apply is called.

   When @ref amxd_trans_apply fails no changes are done.
   When @ref amxd_trans_apply succeeds all changes are applied and events are
   send.

   In one transaction it is possible to change many objects.
 */


/**
   @ingroup amxd_transaction
   @brief
   Transaction attributes.

   Transaction attributes can be set using @ref amxd_trans_set_attr
 */
typedef enum _amxd_tattr_id {
    amxd_tattr_change_ro,           /**< When set transaction can change read-only params or object */
    amxd_tattr_change_pub,          /**< Set transaction access level to public */
    amxd_tattr_change_prot,         /**< Set transaction access level to protected */
    amxd_tattr_change_priv,         /**< Set transaction access level to private */
} amxd_tattr_id_t;

typedef struct _amxd_trans_attr {
    uint32_t read_only : 1;         // can change read-only parameters
} amxd_trans_attr_t;

typedef struct _amxd_trans_action {
    amxc_llist_it_t it;
    amxd_action_t action;
    amxc_var_t data;
} amxd_trans_action_t;

typedef struct _amxd_transaction {
    amxc_llist_t actions;           // list of actions to do when transaction is applied
    amxc_llist_t validate;          // objects or object trees that needs validation
    amxc_llist_t garbage;           // list of objects that need to be destroyed when transaction is done
    amxd_object_t* current;         // current selected object
    amxd_trans_attr_t attr;         // transaction attributes
    amxd_dm_access_t access;        // transaction access
    amxc_var_t retvals;             // list of return values of actions
    amxd_status_t status;           // transaction status code
    int fail_index;                 // index of failed action
} amxd_trans_t;

/**
   @ingroup amxd_transaction
   @brief
   Helper macro for setting a value

   This helper macro sets a value, using a type indicator

   @param type the data type, must be a valid parameter type,
               or must be convertable to a valid parameter type
   @param trans pointer to a transaction object
   @param name parameter name of the current selected object
   @param value the new value, must match the type
 */
#define amxd_trans_set_value(type, trans, name, value) \
    amxd_trans_set_ ## type(trans, name, value)

/**
   @ingroup amxd_transaction
   @brief
   Initializes a transaction object.

   Sets the internal transaction fields to a default value:

   - Sets current object to NULL
   - Transaction can not change read-only parameters
   - The transaction can change public and protected parameters
   - Initializes internal bookkeeping objects (garbage collection, rollback info, ...)

   @param trans pointer to a transaction object

   @return
   amxd_status_ok if the transaction object is correctly initialized.
 */
amxd_status_t amxd_trans_init(amxd_trans_t* const trans);

/**
   @ingroup amxd_transaction
   @brief
   Cleans the transaction object.

   After cleaning the transaction obnject, it is ready to be re-used.

   This function will reset all internal bookkeeping objects, but keeps
   the current selected object and the transaction attributes

   @param trans pointer to a transaction object
 */
void amxd_trans_clean(amxd_trans_t* const trans);

/**
   @ingroup amxd_transaction
   @brief
   Allocates a transaction object on the heap and initializes it.

   Allocates memory for a transaction object and then calls @ref amxd_trans_init

   @note
   A transaction object allocated on the heap must be freed using
   @ref amxd_trans_delete

   @param trans pointer to pointer to a transaction object

   @return
   amxd_status_ok if the transaction object is allocated and correctly initialized.
 */
amxd_status_t amxd_trans_new(amxd_trans_t** trans);

/**
   @ingroup amxd_transaction
   @brief
   Frees the memory previously allocated for a transaction object.

   First calls @ref amxd_trans_clean and then frees the memory allocated for
   the transaction object.

   @note
   Only call this function on transaction objects previously allocated with
   @ref amxd_trans_new

   @param trans pointer to pointer to a transaction object
 */
void amxd_trans_delete(amxd_trans_t** trans);

/**
   @ingroup amxd_transaction
   @brief
   Set the transaction attributes

   Using the transaction attributes it is possible to change the behavior of
   a transaction.

   By default a transaction can not change or update read-only parameters
   or objects and only works on public or protected parameters and objects.

   The following attributes can be set:
   - @ref amxd_tattr_change_ro, enables changing of read-only parameters and objects
   - @ref amxd_tattr_change_pub, only change public parameters or objects
   - @ref amxd_tattr_change_prot, can change public or protected
     parameters and objects
   - @ref amxd_tattr_change_priv, can change public, protected and
     private parameters and objects

   @note
   - Set the transaction attributes before adding actions
   - @ref amxd_tattr_change_pub, @ref amxd_tattr_change_prot, @ref amxd_tattr_change_priv
     are mutually exclusive, only set one of these, by default @ref amxd_tattr_change_prot
     is set.
   - when specifying @ref amxd_tattr_change_pub, the enable flag has no effect
   - when specifying @ref amxd_tattr_change_prot or @ref amxd_tattr_change_priv
     with enable equal to false, @ref amxd_tattr_change_pub is set.

   @param trans pointer to a transaction object
   @param attr one of @ref amxd_tattr_id_t
   @param enable enable or disables the attrivbute

   @return
   amxd_status_ok if the attribute is set or unset.
 */
amxd_status_t amxd_trans_set_attr(amxd_trans_t* trans,
                                  amxd_tattr_id_t attr,
                                  bool enable);

/**
   @ingroup amxd_transaction
   @brief
   Adds an action to a transaction

   Adds an action to a transaction, providing the action data.

   This function is mostly no called directly, some convience wrapper
   functions are provide to make it easier to add an action to a transaction.

   Use one of these methods instead
   - @ref amxd_trans_select_pathf
   - @ref amxd_trans_select_object
   - @ref amxd_trans_set_param or @ref amxd_trans_set_value
   - @ref amxd_trans_add_inst
   - @ref amxd_trans_del_inst

   @param trans pointer to a transaction object
   @param reason the action identifier
   @param data the action data

   @return
   amxd_status_ok when the atcion is added to the transaction.
 */
amxd_status_t amxd_trans_add_action(amxd_trans_t* const trans,
                                    const amxd_action_t reason,
                                    const amxc_var_t* data);

/**
   @ingroup amxd_transaction
   @brief
   Selects an object using a absolute or relative path

   Selects an object on which the next actions must be applied. The object is
   selected using a path. This path can be absolute or relative.

   A relative path must start with a '.' and is relative to the currently
   selected object in the transaction.

   The path may be a search path. The search path must only return one object.

   This function supports printf formatting.

   To go up in the hierarchy of objects, relative from the current object the
   symbol '^' can be used.

   @param trans pointer to a transaction object
   @param path relative or abosule path, can be a search path

   @return
   amxd_status_ok when the select atcion is added to the transaction.
 */
amxd_status_t amxd_trans_select_pathf(amxd_trans_t* const trans,
                                      const char* path,
                                      ...) __attribute__ ((format(printf, 2, 3)));

/**
   @ingroup amxd_transaction
   @brief
   Selects an object using an object pointer

   Selects an object on which the next actions must be applied.

   The path of the object is stored in the select action, not the object itself.

   @param trans pointer to a transaction object
   @param object pointer to an object in the data model

   @return
   amxd_status_ok when the select atcion is added to the transaction.
 */
amxd_status_t amxd_trans_select_object(amxd_trans_t* trans,
                                       const amxd_object_t* const object);

/**
   @ingroup amxd_transaction
   @brief
   Adds a set value action to a transaction

   The set action works on the currently selected object.

   When mutiple set actions are added to the transaction in sequence, the
   transaction will combine these as one write action on the selected
   object.

   When invalid paranmeters are set, an invalid transaction is created. This
   function will return an error and the @ref amxd_trans_apply will also fail.
   Invalid parameters are:
   - parameters with no name (empty string or NULL pointer as param_name)
   - parameters with no value (NULL pointer as value).

   @param trans pointer to a transaction object
   @param param_name name of the parameter
   @param value the new value

   @return
   amxd_status_ok when the set atcion is added to the transaction.
 */
amxd_status_t amxd_trans_set_param(amxd_trans_t* const trans,
                                   const char* param_name,
                                   amxc_var_t* const value);

/**
   @ingroup amxd_transaction
   @brief
   Adds an instance add action to a transaction

   The instance add action works on the currently selected object. The
   currently selected object must be a multi-instance object.

   The newly added instance will become the currently selected object.

   @param trans pointer to a transaction object
   @param index the index for the instance, no other instance should exist with
                this index, or 0 to automatically assing an index
   @param name name of the instance or NULL. If the multi-instance object
               contains a "Alias" parameter the name is stored in that
               parameter. No other instance of the selected multi-instance object
               should have the same name. When no names need to be set, use a
               NULL pointer for this argument

   @return
   amxd_status_ok when the instance add atcion is added to the transaction.
 */
amxd_status_t amxd_trans_add_inst(amxd_trans_t* const trans,
                                  const uint32_t index,
                                  const char* name);

/**
   @ingroup amxd_transaction
   @brief
   Adds an instance delete action to a transaction

   The instance delete action works on the currently selected object. The
   currently selected object must be a multi-instance object.

   The deleted instance is selected by index or by name. When both are specified,
   the index takes precedence over the name. At least one of them should be
   specified.

   The transaction will fail if no instance is found with the index or name
   specified.

   @note
   The instance is added to the garbage collector and is really deleted when
   all actions of the transaction are applied successful. The reason for this
   implementation is that it would otherwise not be possible to rollback
   the executed actions when on failure.


   @param trans pointer to a transaction object
   @param index the index for the instance that will be deleted or 0
   @param name name of the instance that will be deleted or NULL.

   @return
   amxd_status_ok when the instance add atcion is added to the transaction.
 */
amxd_status_t amxd_trans_del_inst(amxd_trans_t* const trans,
                                  const uint32_t index,
                                  const char* name);

amxd_status_t amxd_trans_add_mib(amxd_trans_t* const trans,
                                 const char* mib_name);

/**
   @ingroup amxd_transaction
   @brief
   Applies all previously added actions

   Executes all actions of the transaction in the order the actions were added.
   During execution, a reverse transaction is created. Whenever the execution
   of one of the actions fail, the reverse transaction is executed to
   restore the original state.

   Either all actions of a transaction are applied, or none.

   When the transaction succeeds (all actions executed) the transaction will
   send events for all changed/adds/deletes done.

   @param trans pointer to a transaction object
   @param dm the data model the transaction needs to be applied on

   @return
   amxd_status_ok when the all actions are applied, otherwise an other
   error code and no changes in the data model are done.
 */
amxd_status_t amxd_trans_apply(amxd_trans_t* const trans,
                               amxd_dm_t* const dm);

/**
   @ingroup amxd_transaction
   @brief
   Dumps the transaction to a file descriptor

   Dumps in human readable text format all actions of a transaction in the
   order the actions were added.

   This function can be used for debugging purposes.

   @param trans pointer to a transaction object
   @param fd a valid file descriptor
   @param reverse when set to true, dumps the action in reverse order
 */
void amxd_trans_dump(const amxd_trans_t* const trans,
                     const int fd,
                     const bool reverse);

// helper functions
static inline
amxd_status_t amxd_trans_set_cstring_t(amxd_trans_t* const trans,
                                       const char* name,
                                       const char* value) {
    amxd_status_t status = amxd_status_unknown_error;
    amxc_var_t new_value;

    amxc_var_init(&new_value);
    amxc_var_set(cstring_t, &new_value, value);
    status = amxd_trans_set_param(trans, name, &new_value);

    amxc_var_clean(&new_value);
    return status;
}

static inline
amxd_status_t amxd_trans_set_csv_string_t(amxd_trans_t* const trans,
                                          const char* name,
                                          const char* value) {
    amxd_status_t status = amxd_status_unknown_error;
    amxc_var_t new_value;

    amxc_var_init(&new_value);
    amxc_var_set(csv_string_t, &new_value, value);
    status = amxd_trans_set_param(trans, name, &new_value);

    amxc_var_clean(&new_value);
    return status;
}

static inline
amxd_status_t amxd_trans_set_ssv_string_t(amxd_trans_t* const trans,
                                          const char* name,
                                          const char* value) {
    amxd_status_t status = amxd_status_unknown_error;
    amxc_var_t new_value;

    amxc_var_init(&new_value);
    amxc_var_set(ssv_string_t, &new_value, value);
    status = amxd_trans_set_param(trans, name, &new_value);

    amxc_var_clean(&new_value);
    return status;
}

static inline
amxd_status_t amxd_trans_set_bool(amxd_trans_t* const trans,
                                  const char* name,
                                  bool value) {
    amxd_status_t status = amxd_status_unknown_error;
    amxc_var_t new_value;

    amxc_var_init(&new_value);
    amxc_var_set(bool, &new_value, value);
    status = amxd_trans_set_param(trans, name, &new_value);

    amxc_var_clean(&new_value);
    return status;
}

static inline
amxd_status_t amxd_trans_set_int8_t(amxd_trans_t* const trans,
                                    const char* name,
                                    int8_t value) {
    amxd_status_t status = amxd_status_unknown_error;
    amxc_var_t new_value;

    amxc_var_init(&new_value);
    amxc_var_set(int8_t, &new_value, value);
    status = amxd_trans_set_param(trans, name, &new_value);

    amxc_var_clean(&new_value);
    return status;
}

static inline
amxd_status_t amxd_trans_set_uint8_t(amxd_trans_t* const trans,
                                     const char* name,
                                     uint8_t value) {
    amxd_status_t status = amxd_status_unknown_error;
    amxc_var_t new_value;

    amxc_var_init(&new_value);
    amxc_var_set(uint8_t, &new_value, value);
    status = amxd_trans_set_param(trans, name, &new_value);

    amxc_var_clean(&new_value);
    return status;
}

static inline
amxd_status_t amxd_trans_set_int16_t(amxd_trans_t* const trans,
                                     const char* name,
                                     int16_t value) {
    amxd_status_t status = amxd_status_unknown_error;
    amxc_var_t new_value;

    amxc_var_init(&new_value);
    amxc_var_set(int16_t, &new_value, value);
    status = amxd_trans_set_param(trans, name, &new_value);

    amxc_var_clean(&new_value);
    return status;
}

static inline
amxd_status_t amxd_trans_set_uint16_t(amxd_trans_t* const trans,
                                      const char* name,
                                      uint16_t value) {
    amxd_status_t status = amxd_status_unknown_error;
    amxc_var_t new_value;

    amxc_var_init(&new_value);
    amxc_var_set(uint16_t, &new_value, value);
    status = amxd_trans_set_param(trans, name, &new_value);

    amxc_var_clean(&new_value);
    return status;
}

static inline
amxd_status_t amxd_trans_set_int32_t(amxd_trans_t* const trans,
                                     const char* name,
                                     int32_t value) {
    amxd_status_t status = amxd_status_unknown_error;
    amxc_var_t new_value;

    amxc_var_init(&new_value);
    amxc_var_set(int32_t, &new_value, value);
    status = amxd_trans_set_param(trans, name, &new_value);

    amxc_var_clean(&new_value);
    return status;
}

static inline
amxd_status_t amxd_trans_set_uint32_t(amxd_trans_t* const trans,
                                      const char* name,
                                      uint32_t value) {
    amxd_status_t status = amxd_status_unknown_error;
    amxc_var_t new_value;

    amxc_var_init(&new_value);
    amxc_var_set(uint32_t, &new_value, value);
    status = amxd_trans_set_param(trans, name, &new_value);

    amxc_var_clean(&new_value);
    return status;
}

static inline
amxd_status_t amxd_trans_set_int64_t(amxd_trans_t* const trans,
                                     const char* name,
                                     int64_t value) {
    amxd_status_t status = amxd_status_unknown_error;
    amxc_var_t new_value;

    amxc_var_init(&new_value);
    amxc_var_set(int64_t, &new_value, value);
    status = amxd_trans_set_param(trans, name, &new_value);

    amxc_var_clean(&new_value);
    return status;
}

static inline
amxd_status_t amxd_trans_set_uint64_t(amxd_trans_t* const trans,
                                      const char* name,
                                      uint64_t value) {
    amxd_status_t status = amxd_status_unknown_error;
    amxc_var_t new_value;

    amxc_var_init(&new_value);
    amxc_var_set(uint64_t, &new_value, value);
    status = amxd_trans_set_param(trans, name, &new_value);

    amxc_var_clean(&new_value);
    return status;
}

static inline
amxd_status_t amxd_trans_set_double(amxd_trans_t* const trans,
                                    const char* name,
                                    double value) {
    amxd_status_t status = amxd_status_unknown_error;
    amxc_var_t new_value;

    amxc_var_init(&new_value);
    amxc_var_set(double, &new_value, value);
    status = amxd_trans_set_param(trans, name, &new_value);

    amxc_var_clean(&new_value);
    return status;
}

static inline
amxd_status_t amxd_trans_set_amxc_ts_t(amxd_trans_t* const trans,
                                       const char* name,
                                       amxc_ts_t* value) {
    amxd_status_t status = amxd_status_unknown_error;
    amxc_var_t new_value;

    amxc_var_init(&new_value);
    amxc_var_set(amxc_ts_t, &new_value, value);
    status = amxd_trans_set_param(trans, name, &new_value);

    amxc_var_clean(&new_value);
    return status;
}

#ifdef __cplusplus
}
#endif

#endif // __AMXD_TRANSACTION_H__


