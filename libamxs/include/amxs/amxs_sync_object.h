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

#if !defined(__AMXS_SYNC_OBJECT_H__)
#define __AMXS_SYNC_OBJECT_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <amxs/amxs_types.h>

/**
   @file
   @brief
   Ambiorix Object Synchronization API header file
 */

/**
   @ingroup amxs_sync
   @defgroup amxs_sync_object Object synchronization API
 */

/**
   @ingroup amxs_sync_object
   @brief
   Synchronization object constructor function

   Allocates memory for a new synchronization object and initializes this object.

   Use @ref amxs_sync_object_delete to remove the synchronization object and free all allocated
   memory.

   @param object Pointer to a synchronization object pointer. The address of the new allocated
                 synchronization object is stored in this pointer.
   @param object_a Name of the object in object A
   @param object_b Name of the object in object B
   @param attributes Bitwise OR of zero or more of the following attributes:
                     - @ref AMXS_SYNC_DEFAULT
                     - @ref AMXS_SYNC_ONLY_B_TO_A
                     - @ref AMXS_SYNC_ONLY_A_TO_B
                     - @ref AMXS_SYNC_INIT_B
   @param translation_cb Callback function to translate data coming from an object event.
                         The output data of this function will be passed to the action callback
                         function if this function executes succesfully.
                         If this argument is NULL, the data from the event will be passed
                         directly to the action callback function.
   @param action_cb Callback function to act on an object event.
   @param priv Pointer to user data which will be passed to the translation and action callbacks.

   @return
   amxs_status_ok when the synchronization object is created, or another status code when
   failed to create the synchronization object.
 */
amxs_status_t amxs_sync_object_new(amxs_sync_object_t** object,
                                   const char* object_a,
                                   const char* object_b,
                                   int attributes,
                                   amxs_translation_cb_t translation_cb,
                                   amxs_action_cb_t action_cb,
                                   void* priv);

/**
   @ingroup amxs_sync_object
   @brief
   Synchronization object constructor function

   Allocates memory for a new synchronization object and initializes this object.

   Use @ref amxs_sync_object_delete to remove the synchronization object and free all allocated
   memory.

   Uses default translation @ref amxs_sync_object_copy_trans_cb and action @ref amxs_sync_object_copy_action_cb
   callbacks.

   @param object Pointer to a synchronization object pointer. The address of the new allocated
                 synchronization object is stored in this pointer.
   @param object_a Name of the object in object A
   @param object_b Name of the object in object B
   @param attributes Bitwise OR of zero or more of the following attributes:
                     - @ref AMXS_SYNC_DEFAULT
                     - @ref AMXS_SYNC_ONLY_B_TO_A
                     - @ref AMXS_SYNC_ONLY_A_TO_B
                     - @ref AMXS_SYNC_INIT_B

   @return
   amxs_status_ok when the synchronization object is created, or another status code when
   failed to create the synchronization object.
 */
amxs_status_t amxs_sync_object_new_copy(amxs_sync_object_t** object,
                                        const char* object_a,
                                        const char* object_b,
                                        int attributes);

/**
   @ingroup amxs_sync_object
   @brief
   Synchronization object destructor function

   Frees all memory allocated for a synchronization object.
   Also removes the synchronization object from any synchronization object or context
   it was attached to.
   All attached synchronization objects and parameters will be freed as well.

   @param object Pointer to a synchronization object pointer.
 */
void amxs_sync_object_delete(amxs_sync_object_t** object);

/**
   @ingroup amxs_sync_object
   @brief
   Adds a synchronization parameter to a synchronization object.

   The synchronization parameter can be be created using @ref amxs_sync_param_new.

   Adding the synchronization parameter fails when:
   - The parameter was already added to the object.
   - The parameter attributes are conflicting with those of the object.
     E.g. The object has the @ref AMXS_SYNC_ONLY_B_TO_A attribute set,
     and the parameter has @ref AMXS_SYNC_ONLY_A_TO_B set.

   If the object attributes are more strict than those of the parameter, the parameter attributes
   will be updated to match those of the object.

   @param object Pointer to a synchronization object.
   @param param Pointer to a synchronization parameter.

   @return
   - amxs_status_ok: the synchronization parameter is added to the synchronization object
   - amxs_status_duplicate: another synchronization parameter with the same direction and
                            parameter names already exists for this synchronization object
   - amxs_status_invalid_attr: the attributes of the synchronization parameter are conflicting
                               with those of the synchronization object
   - amxs_status_unknown_error: any other error
 */
amxs_status_t amxs_sync_object_add_param(amxs_sync_object_t* object, amxs_sync_param_t* param);

/**
   @ingroup amxs_sync_object
   @brief
   Creates and adds a synchronization parameter to a synchronization object.

   Allocates memory for a new synchronization parameter and initializes this parameter.
   Then adds it to the synchronization object.

   Adding the synchronization parameter fails when:
   - The parameter was already added to the object.
   - The parameter attributes are conflicting with those of the object.
     E.g. The object has the @ref AMXS_SYNC_ONLY_B_TO_A attribute set,
     and the parameter has @ref AMXS_SYNC_ONLY_A_TO_B set.

   If the object attributes are more strict than those of the parameter, the parameter attributes
   will be updated to match those of the object.

   @param object Pointer to a synchronization object.
   @param param_a Name of the parameter in object A
   @param param_b Name of the parameter in object B
   @param attributes Bitwise OR of zero or more of the following attributes:
                     - @ref AMXS_SYNC_DEFAULT
                     - @ref AMXS_SYNC_ONLY_B_TO_A
                     - @ref AMXS_SYNC_ONLY_A_TO_B
                     - @ref AMXS_SYNC_INIT_B
   @param translation_cb Callback function to translate data coming from a parameter
                         changed event. The output data of this function will be passed to
                         the action callback function if this function executes succesfully.
                         If this argument is NULL, the data from the event will be passed
                         directly to the action callback function.
   @param action_cb Callback function to act on a parameter changed event.
   @param priv Pointer to user data which will be passed to the translation and action callbacks.

   @return
   - amxs_status_ok: the synchronization parameter is added to the synchronization object
   - amxs_status_duplicate: another synchronization parameter with the same direction and
                            parameter names already exists for this synchronization object
   - amxs_status_invalid_attr: the attributes of the synchronization parameter are conflicting
                               with those of the synchronization object
   - amxs_status_unknown_error: any other error
 */
amxs_status_t amxs_sync_object_add_new_param(amxs_sync_object_t* object,
                                             const char* param_a,
                                             const char* param_b,
                                             int attributes,
                                             amxs_translation_cb_t translation_cb,
                                             amxs_action_cb_t action_cb,
                                             void* priv);

/**
   @ingroup amxs_sync_object
   @brief
   Creates and adds a synchronization parameter to a synchronization object.

   Allocates memory for a new synchronization parameter and initializes this parameter.
   Then adds it to the synchronization object.

   Adding the synchronization parameter fails when:
   - The parameter was already added to the object.
   - The parameter attributes are conflicting with those of the object.
     E.g. The object has the @ref AMXS_SYNC_ONLY_B_TO_A attribute set,
     and the parameter has @ref AMXS_SYNC_ONLY_A_TO_B set.

   If the object attributes are more strict than those of the parameter, the parameter attributes
   will be updated to match those of the object.

   Uses default translation @ref amxs_sync_batch_param_copy_trans_cb and action @ref amxs_sync_param_copy_action_cb
   callbacks.

   @param object Pointer to a synchronization object.
   @param param_a Name of the parameter in object A
   @param param_b Name of the parameter in object B
   @param attributes Bitwise OR of zero or more of the following attributes:
                     - @ref AMXS_SYNC_DEFAULT
                     - @ref AMXS_SYNC_ONLY_B_TO_A
                     - @ref AMXS_SYNC_ONLY_A_TO_B
                     - @ref AMXS_SYNC_INIT_B

   @return
   - amxs_status_ok: the synchronization parameter is added to the synchronization object
   - amxs_status_duplicate: another synchronization parameter with the same direction and
                            parameter names already exists for this synchronization object
   - amxs_status_invalid_attr: the attributes of the synchronization parameter are conflicting
                               with those of the synchronization object
   - amxs_status_unknown_error: any other error
 */
amxs_status_t amxs_sync_object_add_new_copy_param(amxs_sync_object_t* object,
                                                  const char* param_a,
                                                  const char* param_b,
                                                  int attributes);

/**
   @ingroup amxs_sync_object
   @brief
   Adds a synchronization object to a synchronization object.

   The synchronization object can be be created using @ref amxs_sync_object_new.

   Adding the synchronization object fails when:
   - The child object was already added to the parent object.
   - The child object attributes are conflicting with those of the parent object.
     E.g. The child object has the @ref AMXS_SYNC_ONLY_B_TO_A attribute set,
     and the parent object has @ref AMXS_SYNC_ONLY_A_TO_B set.

   If the parent attributes are more strict than those of the child, the child attributes
   will be updated to match those of the parent.

   @param parent Pointer to the parent synchronization object.
   @param child Pointer to the child synchronization object.

   @return
   - amxs_status_ok: the child object is added to the parent object
   - amxs_status_duplicate: another child object with the same direction and
                            object names already exists for the parent object
   - amxs_status_invalid_attr: the attributes of the child object are conflicting
                               with those of the parent object
   - amxs_status_unknown_error: any other error
 */
amxs_status_t amxs_sync_object_add_object(amxs_sync_object_t* parent, amxs_sync_object_t* child);

/**
   @ingroup amxs_sync_object
   @brief
   Creates and adds a synchronization object to a synchronization object.

   Allocates memory for a new synchronization object and initializes this object.
   Then adds it to the parent synchronization object.

   Adding the synchronization object fails when:
   - The child object was already added to the parent object.
   - The child object attributes are conflicting with those of the parent object.
     E.g. The child object has the @ref AMXS_SYNC_ONLY_B_TO_A attribute set,
     and the parent object has @ref AMXS_SYNC_ONLY_A_TO_B set.

   If the parent attributes are more strict than those of the child, the child attributes
   will be updated to match those of the parent.

   @param parent Pointer to the parent synchronization object.
   @param object_a Name of the object in object A
   @param object_b Name of the object in object B
   @param attributes Bitwise OR of zero or more of the following attributes:
                     - @ref AMXS_SYNC_DEFAULT
                     - @ref AMXS_SYNC_ONLY_B_TO_A
                     - @ref AMXS_SYNC_ONLY_A_TO_B
                     - @ref AMXS_SYNC_INIT_B
   @param translation_cb Callback function to translate data coming from an object event.
                         The output data of this function will be passed to the action callback
                         function if this function executes succesfully.
                         If this argument is NULL, the data from the event will be passed
                         directly to the action callback function.
   @param action_cb Callback function to act on an object event.
   @param priv Pointer to user data which will be passed to the translation and action callbacks.
   @return
   - amxs_status_ok: the new child object is added to the parent object
   - amxs_status_duplicate: another child object with the same direction and
                            object names already exists for the parent object
   - amxs_status_invalid_attr: the attributes of the child object are conflicting
                               with those of the parent object
   - amxs_status_unknown_error: any other error
 */
amxs_status_t amxs_sync_object_add_new_object(amxs_sync_object_t* parent,
                                              const char* object_a,
                                              const char* object_b,
                                              int attributes,
                                              amxs_translation_cb_t translation_cb,
                                              amxs_action_cb_t action_cb,
                                              void* priv);

/**
   @ingroup amxs_sync_object
   @brief
   Creates and adds a synchronization object to a synchronization object.

   Allocates memory for a new synchronization object and initializes this object.
   Then adds it to the parent synchronization object.

   Adding the synchronization object fails when:
   - The child object was already added to the parent object.
   - The child object attributes are conflicting with those of the parent object.
     E.g. The child object has the @ref AMXS_SYNC_ONLY_B_TO_A attribute set,
     and the parent object has @ref AMXS_SYNC_ONLY_A_TO_B set.

   If the parent attributes are more strict than those of the child, the child attributes
   will be updated to match those of the parent.

   Uses default translation @ref amxs_sync_object_copy_trans_cb and action @ref amxs_sync_object_copy_action_cb
   callbacks.

   @param parent Pointer to the parent synchronization object.
   @param object_a Name of the object in object A
   @param object_b Name of the object in object B
   @param attributes Bitwise OR of zero or more of the following attributes:
                     - @ref AMXS_SYNC_DEFAULT
                     - @ref AMXS_SYNC_ONLY_B_TO_A
                     - @ref AMXS_SYNC_ONLY_A_TO_B
                     - @ref AMXS_SYNC_INIT_B

   @return
   - amxs_status_ok: the new child object is added to the parent object
   - amxs_status_duplicate: another child object with the same direction and
                            object names already exists for the parent object
   - amxs_status_invalid_attr: the attributes of the child object are conflicting
                               with those of the parent object
   - amxs_status_unknown_error: any other error
 */
amxs_status_t amxs_sync_object_add_new_copy_object(amxs_sync_object_t* parent,
                                                   const char* object_a,
                                                   const char* object_b,
                                                   int attributes);
#ifdef __cplusplus
}
#endif

#endif // __AMXS_SYNC_OBJECT_H__

