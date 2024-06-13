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

#if !defined(__AMXD_DM_H__)
#define __AMXD_DM_H__

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
   @defgroup amxd_dm Data Model
 */

/**
   @ingroup amxd_dm
   @brief
   Instantiate a new data model.

   Allocates and initializes memory to store a data model object hierarchy.
   This function allocates memory from the heap,

   Typically only one data model is allocated/created for an application,
   preferable as a static variable, see @ref amxd_dm_init

   @note
   The allocated memory must be freed when not used anymore,
   use @ref amxd_dm_delete to free the memory

   @param dm a pointer to the location where the pointer to the new data model
             structure can be stored

   @return
   Returns amxd_status_ok if successful.
 */
amxd_status_t amxd_dm_new(amxd_dm_t** dm);

/**
   @ingroup amxd_dm
   @brief
   Deletes a data model structure.

   This function frees the allocated memory for the data model structure and
   the full data model itself. It is not needed to free all individual
   allocated objects that are part of the data model object hierarchy.

   @note
   When calling this function all store references to the data model pointer
   become invalid.

   @param dm a pointer to the location where the pointer to the data model is
             store.
 */
void amxd_dm_delete(amxd_dm_t** dm);

/**
   @ingroup amxd_dm
   @brief
   Initializes a data model structure.

   Typically only one data model is allocated/created for an application,
   preferable as a static variable, and initialized with this function

   @note
   To build a dynamic data model, some parts are allocated on the heap.
   To make sure the all allocated memory is freed, it is best to clean the
   created data model using @ref amxd_dm_clean.

   @param dm the pointer to the data model structure

   @return
   Returns amxd_status_ok if successful.
 */
amxd_status_t amxd_dm_init(amxd_dm_t* dm);

/**
   @ingroup amxd_dm
   @brief
   Cleans a data model structure.

   This function frees the full data model itself.
   It is not needed to free all individual  allocated objects that are part of
   the data model object hierarchy.

   @param dm the pointer to the data model structure
 */
void amxd_dm_clean(amxd_dm_t* dm);

amxd_status_t amxd_dm_store_mib(amxd_dm_t* const dm,
                                amxd_object_t* const object);

amxd_object_t* amxd_dm_get_mib(amxd_dm_t* const dm,
                               const char* name);

/**
   @ingroup amxd_dm
   @brief
   Adds an object to the root of the data model.

   A data model object can be created with @ref amxd_object_new and added
   to either the data model itself using this function, or added to another
   object using @ref amxd_object_add_object

   @note
   There is not need to keep a pointer to objects that are added to the data
   model, using functions @ref amxd_object_get and @ref amxd_object_findf it
   is posisble to retrieve the object pointers at any time.

   @param dm the pointer to the data model structure
   @param object the pointer to an object

   @return
   Returns amxd_status_ok if successful.
 */
amxd_status_t amxd_dm_add_root_object(amxd_dm_t* const dm,
                                      amxd_object_t* const object);

/**
   @ingroup amxd_dm
   @brief
   Removes an object from the root of the data model.

   This function removes the object from the data model root and does delete
   the memory allocated for the object.

   After calling this function the object is not accessible anymore.

   @param dm the pointer to the data model structure
   @param name the name of the object

   @return
   Returns amxd_status_ok if successful.
 */
amxd_status_t amxd_dm_remove_root_object(amxd_dm_t* const dm, const char* name);

/**
   @ingroup amxd_dm
   @brief
   Fetches the root object of the data model.

   The root object has no name, it is used to add other objects to the
   data model using @ref amxd_object_add_object

   @param dm the pointer to the data model structure

   @return
   Returns the pointer to the root object of the data model or NULL if the
   data model pointer (dm) is NULL.
 */
amxd_object_t* amxd_dm_get_root(amxd_dm_t* const dm);

amxd_object_t* amxd_dm_get_object(amxd_dm_t* const dm, const char* name);

amxd_object_t* amxd_dm_findf(amxd_dm_t* const dm,
                             const char* abs_path,
                             ...) __attribute__ ((format(printf, 2, 3)));

amxd_status_t amxd_dm_resolve_pathf(amxd_dm_t* const dm,
                                    amxc_llist_t* paths,
                                    const char* abs_path,
                                    ...)  __attribute__ ((format(printf, 3, 4)));

amxd_status_t amxd_dm_resolve_pathf_ext(amxd_dm_t* const dm,
                                        bool* key_path,
                                        amxc_llist_t* paths,
                                        const char* abs_path,
                                        ...) __attribute__ ((format(printf, 4, 5)));
/**
   @ingroup amxd_dm
   @brief
   Get the object path from a data model signal

   The data model emits amxp signals (see libamxp) for different kind of
   events, like object added, object deleted, ...

   Each of these events contain an object path, with this function the path
   can be extracted from the signal.

   If you need the pointer to the object in the data model use
   @ref amxd_dm_signal_get_object.

   @note
   - For all object deleted signals, it is not possible to retrieve the object.
   The object will be removed and deleted when the signal is recieved.
   - To be able to get the data model signals, you need to have an event loop and
   connect to the signals you are interested in.

   @param dm the pointer to the data model structure
   @param signal_data the signal data

   @return
   The path to the object, or NULL
 */
const char* amxd_dm_signal_get_path(amxd_dm_t* const dm,
                                    const amxc_var_t* const signal_data);

/**
   @ingroup amxd_dm
   @brief
   Get the object from a data model using the path in the recieved signal

   The data model emits amxp signals (see libamxp) for different kind of
   events, like object added, object deleted, ...

   Each of these events contain an object path, with this function the object
   referenced by the path in the signal is retrieved,

   If you need the path to the object in the data model use
   @ref amxd_dm_signal_get_path.

   @note
   - For all object deleted signals, it is not possible to retrieve the object.
   The object will be removed and deleted when the signal is recieved.
   - To be able to get the data model signals, you need to have an event loop and
   connect to the signals you are interested in.

   @param dm the pointer to the data model structure
   @param signal_data the signal data

   @return
   Pointer to the data model object or NULL.
 */
amxd_object_t* amxd_dm_signal_get_object(amxd_dm_t* const dm,
                                         const amxc_var_t* const signal_data);

amxd_status_t amxd_dm_invoke_action(amxd_object_t* object,
                                    amxd_param_t* param,
                                    amxd_action_t reason,
                                    const amxc_var_t* const args,
                                    amxc_var_t* const retval);
static inline
amxd_status_t amxd_dm_get_status(amxd_dm_t* dm) {
    return dm == NULL ? amxd_status_invalid_arg : dm->status;
}

#ifdef __cplusplus
}
#endif

#endif // __AMXD_DM_H__

