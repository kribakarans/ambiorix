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

#if !defined(__AMXD_OBJECT_FUNCTION_H__)
#define __AMXD_OBJECT_FUNCTION_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>
#include <amxp/amxp_signal.h>
#include <amxd/amxd_types.h>
#include <amxd/amxd_function.h>

/**
   @file
   @brief
   Ambiorix Data Model API header file
 */

/**
   @ingroup amxd_object
   @defgroup amxd_object_rpc RPC Methods
 */

/**
   @ingroup amxd_object_rpc
   @brief
   Adds an RPC method definition to the object definition

   After defining a RPC method using @ref amxd_function_new, the function can be
   added to an object.

   All derived objects will inherit the method. It is possible to change the
   implementation on derived objects using @ref amxd_object_change_function.

   RPC methods added to template objects (multi-instance) objects will be
   available on all instances, if the attribute @ref amxd_fattr_instance
   (default) is set in the RPC method definition. If the attribute
   @ref amxd_fattr_template is set the RPC method can be called on the template
   object.

   @param object the object where the function must be added.
   @param func the name of the RPC method

   @return
   amxd_status_ok when the function is added to the object definition, or another
   status when an error has occurred.
 */
amxd_status_t amxd_object_add_function(amxd_object_t* const object,
                                       amxd_function_t* const func);

/**
   @ingroup amxd_object_rpc
   @brief
   Changes the implementation of an object's RPC method

   Using this function it is possible to change the implementation of a RPC
   method in an object.

   If the implementation is changed for a certain object which has derived
   objects, the implementation is changed for all these derived objects as well.
   When changing the implementation of a derived object (like an instance object),
   the implementation is only changed for this object (or any object derived from
   that object).

   @param object the object pointer
   @param name the name of the RPC method
   @param impl function pointer to the new implementation

   @return
   amxd_status_ok when the function implementation is set, or another status when
   an error has occurred.
 */
amxd_status_t amxd_object_change_function(amxd_object_t* const object,
                                          const char* name,
                                          amxd_object_fn_t impl);

/**
   @ingroup amxd_object_rpc
   @brief
   Get the definition of a RPC method from an object

   Returns the RPC method definition, if found, with the given name.

   When using a derived object, it is possible that the RPC method definition
   is not owned by the object, use @ref amxd_function_get_owner to get a pointer
   to the data model object that owns the RPC method definition.

   The returned RPC method can be removed from the object using
   @ref amxd_function_delete. If the object has derived objects, the method is
   also removed from the derrived objects, unless it was overriden in the
   derived object using @ref amxd_object_change_function

   @param object the object pointer
   @param name the name of the RPC method

   @return
   returns the function definition if found, NULL otherwise
 */
amxd_function_t* amxd_object_get_function(const amxd_object_t* const object,
                                          const char* name);

/**
   @ingroup amxd_object_rpc
   @brief
   Builds a linked list variant containing all function names available in the object

   Initializes the variant to amxc_llist_t type and adds all function names
   available in the object.

   The list also includes the functions of the objects from which this object is
   derived.

   It is possible to filter the functions on access. Access token can be one of
   - @ref amxd_dm_access_public
   - @ref amxd_dm_access_protected (includes public)
   - @ref amxd_dm_access_private (includes protected and public)

   @param object the object pointer
   @param list an initialized variant, will be filled with the RPC method names
   @param access filter functions at a certain access level

   @return
   amxd_status_ok when the function implementation is set, or another status when
   an error has occurred.
 */
amxd_status_t amxd_object_list_functions(amxd_object_t* const object,
                                         amxc_var_t* const list,
                                         amxd_dm_access_t access);

/**
   @ingroup amxd_object_rpc
   @brief
   Fetches the full object RPC method definitions in a variant

   It can be very handy to get the full definitions of the object RPC methods.

   This function is mainly intended for introspection.

   @param object the object pointer
   @param value variant where the RPC method defintions can be stored
   @param access must be one of @ref amxd_dm_access_t

   @return
   amxd_status_ok when the function implementation is set, or another status when
   an error has occurred.
 */
amxd_status_t amxd_object_describe_functions(amxd_object_t* const object,
                                             amxc_var_t* const value,
                                             amxd_dm_access_t access);

/**
   @ingroup amxd_object_rpc
   @brief
   Calls an object RPC method

   Using this function a RPC method of an object in the local data model
   can be called (that is an object in the data model of the process you
   are running in).

   To call a function of a remote data model (data model in another process),
   use the amxb (BAAPI) function amxb_invoke.

   When status amxd_status_deferred is returned, the ret will contain the call id
   and the real return value and status will be returned later. Use @ref
   amxd_function_set_deferred_cb to register a callback function.

   @param object the object pointer
   @param func_name name of the function
   @param args a hash table variant containing the function arguments
   @param ret a variant pointer where the return value can be stored

   @return
   amxd_status_ok when the function implementation is set, or another status when
   an error has occurred.
 */
amxd_status_t amxd_object_invoke_function(amxd_object_t* const object,
                                          const char* func_name,
                                          amxc_var_t* const args,
                                          amxc_var_t* const ret);

/**
   @ingroup amxd_object_rpc
   @brief
   Retruns the number of RPC methods available in an object


   @param object the object pointer
   @param access must be one of @ref amxd_dm_access_t

   @return
   amxd_status_ok when the function implementation is set, or another status when
   an error has occurred.
 */
uint32_t amxd_object_get_function_count(amxd_object_t* const object,
                                        amxd_dm_access_t access);

#ifdef __cplusplus
}
#endif

#endif // __AMXD_OBJECT_FUNCTION_H__
