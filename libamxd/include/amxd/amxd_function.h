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

#if !defined(__AMXD_FUNCTION_H__)
#define __AMXD_FUNCTION_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>
#include <amxd/amxd_types.h>


/**
   @file
   @brief
   Ambiorix Data Model RPC methods API header file
 */

/**
   @defgroup amxd_rpc_methods Define RPC methods
 */

typedef void (* amxd_deferred_cancel_t) (uint64_t call_id, void* const priv);

/**
   @ingroup amxd_rpc_methods
   @brief
   Data model RPC method constructor function

   Allocates memory for a new data model rpc method and initializes the struct
   @ref _amxd_function.

   Creates a RPC method definition. Each RPC method has a return type and must
   be one of the available amxc variant types. A name must be provided as well.

   When adding the rpc method to an object using @ref amxd_object_add_function the
   name of the RPC method should not exist in that object as a RPC method.

   Optionally a function pointer can be provided. If no function implementation
   is set, the function definition exists, but calling the function will fail.

   Function implementation must match with this prototype definition:

   @code
   typedef amxd_status_t (* amxd_object_fn_t) (amxd_object_t* object,
                                               amxd_function_t* func,
                                               amxc_var_t* args,
                                               amxc_var_t* ret);

   @endcode

   To be able to call the function it must be added to an object.

   When the RPC method definition is not added to any data model object, the
   pointer must be freed using @ref amxd_function_delete.

   When the RPC method definition is added to a data model object, it will be
   automatically freed when the object that contains the method is deleted.

   @param func pointer to a pointer to the new RPC method definition
   @param name the name of the RPC method
   @param ret_type the return type of the RPC method, must be a valid amxc variant type
   @param impl pointer to the implementation function

   @return
   amxd_status_ok when the function definition is created, or another status when
   an error has occurred.
 */
amxd_status_t amxd_function_new(amxd_function_t** func,
                                const char* name,
                                const uint32_t ret_type,
                                amxd_object_fn_t impl);

/**
   @ingroup amxd_rpc_methods
   @brief
   Data model RPC method destructor function

   Frees all memory allocated to store the RPC method definition.

   If the RPC method was added to a data model object using
   @ref amxd_object_add_function, the RPC method is removed from that object.

   @warning
   Removing a RPC method from an object will affect all derived objects as well.

   @param func pointer to a pointer to the RPC method definition
 */
void amxd_function_delete(amxd_function_t** func);

/**
   @ingroup amxd_rpc_methods
   @brief
   Data model RPC method copy constructor function

   Makes an exact deep copy a RPC method definition.

   The newly created RPC method definition will not be added to any data model
   object, that can be done using @ref amxd_object_add_function

   @note
   Derived objects are always inheriting the methods.

   @param dest pointer to a pointer to the new RPC method definition (the copy)
   @param source pointer to a RPC method definition

   @return
   amxd_status_ok when the function definition is created, or another status when
   an error has occurred.
 */
amxd_status_t amxd_function_copy(amxd_function_t** dest,
                                 const amxd_function_t* const source);

/**
   @ingroup amxd_rpc_methods
   @brief
   Get the object pointer of the object containing the function definition

   When using a derived object, the object containing the function defintion
   can be different than the object where the function definition pointer
   was retrieved from.

   It is possible to change the implementation of the method in a derived object.
   This can be done using @ref amxd_object_change_function. When changing the
   implementation in a derived object, a copy of the function definition is
   created and stored in the derived object. To retrieve the base implementation
   use @ref amxd_function_get_base.

   @param func pointer to a function definition

   @return
   The object pointer containing the method definition, or NULL if the
   object definition is not owned by an object.
 */
amxd_object_t* amxd_function_get_owner(const amxd_function_t* const func);


/**
   @ingroup amxd_rpc_methods
   @brief
   Get the base function definition of an overridden function

   In derived objects it is possible to override methods and set a different
   implementation. Using this function the base definition from which the method
   is derived is returned.

   @param func pointer to a function definition

   @return
   The function definition pointer of the base definition, if there is no
   base definition, the given definition pointer is returned.
 */
amxd_function_t* amxd_function_get_base(const amxd_function_t* const func);

/**
   @ingroup amxd_rpc_methods
   @brief
   Call the base function of an overridden function

   In derived objects it is possible to override methods and set a different
   implementation. Using this function the base implementation from which the method
   is derived is called.

   @param func pointer to a function definition
   @param object the object on which the function must be called
   @param args htable variant containing the function arguments
   @param ret variant that can be filled with the function return data

   @return
   amxd_status_ok when function was successful, or an other status when an error
   occured
 */
amxd_status_t amxd_function_call_base(const amxd_function_t* const func,
                                      amxd_object_t* const object,
                                      amxc_var_t* const args,
                                      amxc_var_t* const ret);

/**
   @ingroup amxd_rpc_methods
   @brief
   Get the name of a method

   Returns the name of the method. There is no need to free the returned pointer.

   @param func pointer to a function definition

   @return
   The name of the method.
 */
const char* amxd_function_get_name(const amxd_function_t* const func);

/**
   @ingroup amxd_rpc_methods
   @brief
   Gets the return type of a method

   Returns the return type of a method. The return type matches with a
   amxc variant type.

   @param func pointer to a function definition

   @return
   The return type of the method.
 */
static inline
uint32_t amxd_function_get_type(const amxd_function_t* const func) {
    return func == NULL ? AMXC_VAR_ID_NULL : func->ret_type;
}

/**
   @ingroup amxd_rpc_methods
   @brief
   Sets or unsets a method attribute

   The following attributes can be set - unset:
   - @ref amxd_fattr_template
   - @ref amxd_fattr_instance
   - @ref amxd_fattr_private
   - @ref amxd_fattr_protected

   @note
   The attributes @ref amxd_fattr_template and @ref amxd_fattr_instance are
   ignored when the method is added to a singleton object.

   @param func pointer to a function definition
   @param attr the attribute id
   @param enable when true, sets the attribute, when false unsets the attribute

   @return
   Returns amxd_status_ok when attribute is changed, any other when failed
 */
amxd_status_t amxd_function_set_attr(amxd_function_t* func,
                                     const amxd_fattr_id_t attr,
                                     const bool enable);

/**
   @ingroup amxd_rpc_methods
   @brief
   Sets or unsets method attributes using a bitmap

   The following attributes can be set - unset:
   - @ref amxd_fattr_template
   - @ref amxd_fattr_instance
   - @ref amxd_fattr_private
   - @ref amxd_fattr_protected

   Use the macro @ref SET_BIT to transform the attribute id to a bit.
   The bits can be joined together using the bitwise or operator '|'

   @code{.c}
       amxd_function_set_attrs(func,
                               SET_BIT(amxd_fattr_template) |
                               SET_BIT(amxd_fattr_instance),
                               true);
   @endcode

   When setting or unsetting one single attribute the function
   @ref amxd_function_set_attr can be used.

   @note
   The attributes @ref amxd_fattr_template and @ref amxd_fattr_instance are
   ignored when the method is added to a singleton object.

   @param func pointer to a function definition
   @param bitmask the function attribute bitmask
   @param enable when true, sets the attributes, when false unsets the attributes

   @return
   Returns amxd_status_ok when attributes are changed, any other status when failed
 */
amxd_status_t amxd_function_set_attrs(amxd_function_t* func,
                                      const uint32_t bitmask,
                                      bool enable);

/**
   @ingroup amxd_rpc_methods
   @brief
   Gets the set attributes of a RPC method

   This function returns the set attributes of a method as a bitmask.
   To verify if a certain attribute is set, use the macro @ref IS_BIT_SET.

   @code{.c}
       uint32_t attrs = amxd_function_get_attrs(func);

       if(IS_BIT_SET(attrs, amxd_fattr_instance)) {
           // do something
       }
   @endcode

   To verify that one single attribute is set the function
   @ref amxd_function_is_attr_set can be used.

   @param func pointer to a function definition

   @return
   Returns the attributes set on the method as a bitmask.
 */
uint32_t amxd_function_get_attrs(const amxd_function_t* const func);

/**
   @ingroup amxd_rpc_methods
   @brief
   Checks if a method attribute is set

   The following attribute identifiers can be checked
   - @ref amxd_fattr_template
   - @ref amxd_fattr_instance
   - @ref amxd_fattr_private
   - @ref amxd_fattr_protected

   @param func pointer to a function definition
   @param attr the method attribute id

   @return
   Returns true if attribute is set and false when unset
 */
bool amxd_function_is_attr_set(const amxd_function_t* const func,
                               const amxd_fattr_id_t attr);

/**
   @ingroup amxd_rpc_methods
   @brief
   Sets a flag on a function

   A flag is any arbitrary string and can be set or unset.

   The flags set on a function can be seen in the description data of the
   function.

   When a derived object overrides a function, the flags are reset for that
   derived object.

   @param func pointer to a function definition
   @param flag the flag name
 */
void amxd_function_set_flag(amxd_function_t* func, const char* flag);

/**
   @ingroup amxd_rpc_methods
   @brief
   Removes a flag from a function

   A flag is any arbitrary string and can be set or unset.

   The flags set on a function can be seen in the description data of the
   function.

   When a derived object overrides a function, the flags are reset for that
   derived object.

   @param func pointer to a function definition
   @param flag the flag name
 */
void amxd_function_unset_flag(amxd_function_t* func, const char* flag);

/**
   @ingroup amxd_rpc_methods
   @brief
   Checks if a flag is set

   A flag is any arbitrary string and can be set or unset.

   The flags set on a function can be seen in the description data of the
   function.

   When a derived object overrides a function, the flags are reset for that
   derived object.

   @param func pointer to a function definition
   @param flag the flag name

   @return
   true when the flag is set
 */
bool amxd_function_has_flag(const amxd_function_t* const func, const char* flag);

/**
   @ingroup amxd_rpc_methods
   @brief
   Set an implementation for a RPC method.

   Data model object can contain methods. Remote clients can invoke these methods.
   An implementation must be set, the implementation must match with this
   prototype:

   @code{.c}
   amxd_status_t <FUNCTION NAME>(amxd_object_t* object,
                                 amxd_function_t* func,
                                 amxc_var_t* args,
                                 amxc_var_t* ret);
   @endcode

   @note
   When changing the method implementation with this function, and the method
   is added to an object that has derived objects the implementation is changed
   for all these object. To change the implementation for one single derived
   object use @ref amxd_object_change_function.

   @param func pointer to a function definition
   @param impl function pointer to the implementation

   @return
   Returns amxd_status_ok when implementation is set, any other status code
   when failed.
 */
amxd_status_t amxd_function_set_impl(amxd_function_t* const func,
                                     amxd_object_fn_t impl);

/**
   @ingroup amxd_rpc_methods
   @brief
   Fetches the full RPC method definition in a variant

   It can be very handy to get the full definition of the RPC method.

   This function is mainly intended for introspection.

   @param func pointer to a function definition
   @param value variant where the RPC method defintion can be stored

   @return
   amxd_status_ok when the function implementation is set, or another status when
   an error has occurred.
 */
amxd_status_t amxd_function_describe(amxd_function_t* const func,
                                     amxc_var_t* const value);

/**
   @ingroup amxd_rpc_methods
   @brief
   Creates a deferred RPC context

   If an RPC method can take a while before it can return the result, it can
   reply the result later (ie asynchronous I/O). To indicate the result will
   be available later, the RPC method must return status @ref amxd_status_deferred
   and must call this function before returning.

   When the result is available (ie asynchronous I/O is done), the method
   @ref amxd_function_deferred_done must be called.

   It is also possible to remove the deferred call by calling
   @ref amxd_function_deferred_remove. This will send an error back to the caller.

   @param func pointer to a function definition
   @param call_id each deferred method gets a call_id, it will be filled in this
                  integer. The call_id is needed in all other calls related
                  to deferred RPC methods
   @param ret The call id will also be filled in the return value of the RPC method.
              This will enable the caller to add a callback function to get informed
              when the result is available.
   @param cancel_fn Optionally a cancel callback function can be given. This
                    will be called when the deferred function is removed.
   @param priv Some private data for the callee, will be provided to the
               cancel callback function. Typically used to be able to free
               allocated memory when the deferred function is canceled.

   @return
   amxd_status_ok when the deferred context is created or another status when
   an error has occurred.
 */
amxd_status_t amxd_function_defer(const amxd_function_t* const func,
                                  uint64_t* call_id,
                                  amxc_var_t* const ret,
                                  amxd_deferred_cancel_t cancel_fn,
                                  void* priv);

/**
   @ingroup amxd_rpc_methods
   @brief
   Removes a deferred RPC context

   A deferred function context can be removed by the caller or the callee.

   When the caller wants to remove a deferred function its deferred callback
   must be removed first.

   If the callee wants to remove a deferred function its cancel callback must
   be removed first.

   @param call_id The id of the deferred function.
 */
void amxd_function_deferred_remove(uint64_t call_id);

/**
   @ingroup amxd_rpc_methods
   @brief
   Gets the callee private data of an deferred function

   When a callee creates a deferred function contexts it can provide private data.
   Using this method it can retrieve the private data using the deferred call id.

   @param call_id The id of the deferred function.

   @return
   The private data that was set with @ref amxd_function_defer
 */
void* amxd_function_deferred_get_priv(uint64_t call_id);

/**
   @ingroup amxd_rpc_methods
   @brief
   Sets a callback function to get the result of the deferred call.

   When a caller invokes an object method with @ref amxd_object_invoke_function
   and gets `amxd_status_defer` as  status code, the caller can set a callback
   function that will be called when the deferred methods finishes.

   The call identifier will be provided in the return value.

   @param call_id The id of the deferred function.
   @param cb The callback function
   @param priv Some private data, will be passed to the callback function

   @return
   amxd_status_ok when the callback function is set or another status when
   an error has occurred.
 */
amxd_status_t amxd_function_set_deferred_cb(uint64_t call_id,
                                            amxp_deferred_fn_t cb,
                                            void* priv);

/**
   @ingroup amxd_rpc_methods
   @brief
   Finishes a deferred method and removes the deferred function context

   When the result is available, a callee can finish the deferred method by calling
   this function. It must provide the final status and the return value.

   This will trigger the callback function registered by the caller. The callback
   function will be called from the eventloop, in other words the callback
   function is scheduled to be called and is not called immediately.

   @param call_id The id of the deferred function.
   @param status The final status of the RPC method
   @param out_args Out arguments if any (can be NULL)
   @param ret The return value of the RPC method

   @return
   amxd_status_ok if the reply was send or another status when an error has
   occured.
 */
amxd_status_t amxd_function_deferred_done(uint64_t call_id,
                                          amxd_status_t status,
                                          amxc_var_t* out_args,
                                          amxc_var_t* ret);

/**
   @ingroup amxd_rpc_methods
   @brief
   Finishes a deferred method and removes the deferred function context

   When the result is available, a callee can finish the deferred method by calling
   this function. It must provide the final status and the return value.

   This will trigger the callback function registered by the caller. The callback
   function will be called immediately.

   @param call_id The id of the deferred function.
   @param status The final status of the RPC method
   @param out_args Out arguments if any (can be NULL)
   @param ret The return value of the RPC method

   @return
   amxd_status_ok if the reply was sent or another status when an error has
   occured.
 */
amxd_status_t amxd_function_deferred_call_done(uint64_t call_id,
                                               amxd_status_t status,
                                               amxc_var_t* out_args,
                                               amxc_var_t* ret);
/**
   @ingroup amxd_rpc_methods
   @brief
   Adds an argument definition to a RPC method definition.

   @param func pointer to a function definition
   @param name the argument name
   @param type the argument type, must be one of the amxc variant types
   @param default_value a default value for the argument

   @return
   amxd_status_ok when the argument is added to the RPC method, or another
   status when an error has occurred.
 */
amxd_status_t amxd_function_new_arg(amxd_function_t* func,
                                    const char* name,
                                    const uint32_t type,
                                    amxc_var_t* default_value);

/**
   @ingroup amxd_rpc_methods
   @brief
   Removes an argument definition from a RPC method definition.

   @param func pointer to a function definition
   @param name the argument name
 */
void amxd_function_del_arg(amxd_function_t* func, const char* name);

/**
   @ingroup amxd_rpc_methods
   @brief
   Gets the argument definition of a RPC method.

   @param func pointer to a function definition
   @param name the argument name

   @return
   amxd_status_ok when the argument is removed from the RPC method, or another
   status when an error has occurred.
 */
amxd_func_arg_t* amxd_function_get_arg(const amxd_function_t* const func,
                                       const char* name);

/**
   @ingroup amxd_rpc_methods
   @brief
   Sets or unsets a method argument attribute

   The following attributes can be set - unset:
   - @ref amxd_aattr_in
   - @ref amxd_aattr_out
   - @ref amxd_aattr_mandatory
   - @ref amxd_aattr_strict

   @param func pointer to a function definition
   @param name the argument name
   @param attr the attribute id
   @param enable when true, sets the attribute, when false unsets the attribute

   @return
   Returns amxd_status_ok when attribute is changed, any other when failed
 */
amxd_status_t amxd_function_arg_set_attr(amxd_function_t* const func,
                                         const char* name,
                                         const amxd_aattr_id_t attr,
                                         const bool enable);

/**
   @ingroup amxd_rpc_methods
   @brief
   Sets or unsets method argument attributes using a bitmap

   The following attributes can be set - unset:
   - @ref amxd_aattr_in
   - @ref amxd_aattr_out
   - @ref amxd_aattr_mandatory
   - @ref amxd_aattr_strict

   Use the macro @ref SET_BIT to transform the attribute id to a bit.
   The bits can be joined together using the bitwise or operator '|'

   @code{.c}
       amxd_function_arg_set_attrs(func,
                                   "number",
                                   SET_BIT(amxd_aattr_in) |
                                   SET_BIT(amxd_aattr_strict),
                                   true);
   @endcode

   When setting or unsetting one single attribute the function
   @ref amxd_function_arg_set_attr can be used.

   @param func pointer to a function definition
   @param name the argument name
   @param bitmask the function attribute bitmask
   @param enable when true, sets the attributes, when false unsets the attributes

   @return
   Returns amxd_status_ok when attributes are changed, any other status when failed
 */
amxd_status_t amxd_function_arg_set_attrs(amxd_function_t* func,
                                          const char* name,
                                          const uint32_t bitmask,
                                          bool enable);

/**
   @ingroup amxd_rpc_methods
   @brief
   Checks if a method argument attribute is set

   The following attribute identifiers can be checked
   - @ref amxd_aattr_in
   - @ref amxd_aattr_out
   - @ref amxd_aattr_mandatory
   - @ref amxd_aattr_strict

   @param func pointer to a function definition
   @param name the argument name
   @param attr the method attribute id

   @return
   Returns true if attribute is set and false when unset
 */
bool amxd_function_arg_is_attr_set(const amxd_function_t* const func,
                                   const char* name,
                                   const amxd_aattr_id_t attr);

/**
   @ingroup amxd_rpc_methods
   @brief
   Fetches the argument definition in a variant

   It can be very handy to get the full definition of the argument.

   This function is mainly intended for introspection.

   @param arg pointer to a argument definition
   @param value variant where the argument defintion can be stored

   @return
   amxd_status_ok when the function implementation is set, or another status when
   an error has occurred.
 */
amxd_status_t amxd_function_arg_describe(amxd_func_arg_t* const arg,
                                         amxc_var_t* const value);

/**
   @ingroup amxd_rpc_methods
   @brief
   Validates that the input arguments are valid

   The arguments must be provided as a htable variant, where each argument
   is an entry in the hash table.

   This function will check that:
   1. all mandatory in arguments are provided
   2. all strict typed arguments have the correct type information.

   Missing optional arguments with a default value defined will be added to the
   htable variant.

   @note
   This function is not validating that the values of each individual argument
   are valid, it only verifies that all mandatory arguments with the correct
   type are present in the provided htable variant.

   @param func pointer to a function definition
   @param args variant containing a htable with function arguments

   @return
   true when the argument hash table is valid.
   false when the provided arguments are not valid, or NULL pointers are provided
   for the function definition or arguments variant.
 */

bool amxd_function_are_args_valid(amxd_function_t* func,
                                  amxc_var_t* args);

#ifdef __cplusplus
}
#endif

#endif // __AMXD_FUNCTION_H__
