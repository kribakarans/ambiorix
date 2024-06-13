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

#if !defined(__AMXS_SYNC_CTX_H__)
#define __AMXS_SYNC_CTX_H__

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
   @brief
   Synchronization context constructor function

   Allocates memory for a new synchronization context and initializes the context.

   Use @ref amxs_sync_ctx_delete to remove the synchronizaion context and free all allocated
   memory.

   The object paths that can be used in a synchronization context must be an absolute path to:
   - singleton objects
   - instance objects

   Search paths (key addressing) can be used but must resolve to exatly one object.
   Key paths can be used as well, but are not recomended.

   Creating a synchronization context using template objects paths (ending with a multi-instance object)
   are not allowed, in this case creation will fail.

   @param ctx Pointer to a synchronization context pointer. The address of the new allocated
              synchronization context is stored in this pointer.
   @param object_a Path to the first object to be synchronized, hereafter referenced as object A.
   @param object_b Path to the second object to be synchronized, hereafter referenced as object B.
   @param attributes Bitwise OR of zero or more of the following attributes:
                     - @ref AMXS_SYNC_DEFAULT
                     - @ref AMXS_SYNC_ONLY_B_TO_A
                     - @ref AMXS_SYNC_ONLY_A_TO_B
                     - @ref AMXS_SYNC_INIT_B

   @return
   amxs_status_ok when the synchronization context is created, or another status code when
   failed to create the synchronization context.
 */
amxs_status_t amxs_sync_ctx_new(amxs_sync_ctx_t** ctx,
                                const char* object_a,
                                const char* object_b,
                                int attributes);
/**
   @ingroup amxs_sync
   @brief
   Synchronization context destructor function

   Frees all memory allocated for a synchronization context.

   If the synchronization context has any synchronization objects or parameters attached to it,
   these will be removed and freed as well.

   @param ctx Pointer to a synchronization context pointer.
 */
void amxs_sync_ctx_delete(amxs_sync_ctx_t** ctx);

/**
   @ingroup amxs_sync
   @brief
   Synchronization context initialization function

   Initializes a synchronization context that was allocated on the stack.

   Allocates memory for a new synchronization context and initializes this context.

   Use @ref amxs_sync_ctx_clean to make sure that all allocated memory to store the data is freed.

   Please note that the attributes that are set on the synchronization context will always override those
   that are set on syncronization objects or parameters. E.g. when setting the @ref AMXS_SYNC_ONLY_B_TO_A
   attribute on the context, and setting @ref AMXS_SYNC_DEFAULT on a parameter, the syncronyzation will
   only be executed from object B to object A.

   @param ctx Pointer to a synchronization context.
   @param object_a Path to the first object to be synchronized, hereafter referenced as object A.
   @param object_b Path to the second object to be synchronized, hereafter referenced as object B.
   @param attributes Bitwise OR of zero or more of the following attributes:
                     - @ref AMXS_SYNC_DEFAULT
                     - @ref AMXS_SYNC_ONLY_B_TO_A
                     - @ref AMXS_SYNC_ONLY_A_TO_B
                     - @ref AMXS_SYNC_INIT_B

   @return
   amxs_status_ok when the synchronization context is initialized, or another status code when
   failed to initialize the synchronization context.
 */
amxs_status_t amxs_sync_ctx_init(amxs_sync_ctx_t* ctx,
                                 const char* object_a,
                                 const char* object_b,
                                 int attributes);

/**
   @ingroup amxs_sync
   @brief
   Synchronization context cleanup function

   Frees any memory that was allocated to store data in this synchronization context.

   If the synchronization context has any synchronization objects or parameters attached to it,
   these will be removed and freed.

   @param ctx Pointer to a synchronization context.
 */
void amxs_sync_ctx_clean(amxs_sync_ctx_t* ctx);

/**
   @ingroup amxs_sync
   @brief
   Copies an existing synchronization context to a new synchronization context.

   When the copy is successful the synchronization object paths must be updated
   using @ref amxs_sync_ctx_set_paths before starting the synchronization context

   @param dest Pointer to a synchronization context pointer, will contain the copy.
   @param src The synchronization context that will be copied.
   @param priv Private data.

   @return
   amxs_status_ok when the synchronization context is created, or another status code when
   failed to create the synchronization context.
 */
amxs_status_t amxs_sync_ctx_copy(amxs_sync_ctx_t** dest, amxs_sync_ctx_t* src, void* priv);

/**
   @ingroup amxs_sync
   @brief
   Starts the object synchronization.

   Starts the synchronization by looking up the initial values and then subscribing for changes
   on the configured objects and parameters. Synchronization will fail if no objects or parameters
   are attached to the context.

   @param ctx Pointer to a synchronization context.

   @return
   amxs_status_ok when the synchronization is started succesfully, or another status code when
   failed to start the synchronization.
 */
amxs_status_t amxs_sync_ctx_start_sync(amxs_sync_ctx_t* ctx);

/**
   @ingroup amxs_sync
   @brief
   Stops the object synchronization.

   Stops the synchronization by unsubscribing for changes on the configured objects and parameters.

   @param ctx Pointer to a synchronization context.
 */
void amxs_sync_ctx_stop_sync(amxs_sync_ctx_t* ctx);

/**
   @ingroup amxs_sync
   @brief
   Checks is the synchronization context is running.

   Checks if the synchronization context was already startued

   @param ctx Pointer to a synchronization context.

   @return
   - true: when started
   - false: when not started yet.
 */
static inline
bool amxs_sync_ctx_is_started(const amxs_sync_ctx_t* const ctx) {
    return ctx == NULL? false:!amxc_llist_is_empty(&ctx->subscriptions);
}


/**
   @ingroup amxs_sync
   @brief
   Updates the object paths of the synchronization context.

   When a copy is made of a synchronization context using @ref amxs_sync_ctx_copy,
   the object paths of the new synchronization context can be set using this function.

   The new set object paths must match the original object paths at supported data
   model level.

   @param ctx Pointer to a synchronization context.
   @param object_a The new path to object a.
   @param object_b The new path to object b.

   @return
   - amxs_status_ok: the new paths are set.
   - amxs_status_invalid_arg: an invalid path has been provided.
   - amxs_status_object_not_found: object A or object B was not found.
   - amxs_status_unknown_error: any other error
 */
amxs_status_t amxs_sync_ctx_set_paths(amxs_sync_ctx_t* const ctx,
                                      const char* object_a,
                                      const char* object_b);

/**
   @ingroup amxs_sync
   @brief
   Adds a synchronization parameter to a synchronization context.

   The synchronization parameter can be be created using @ref amxs_sync_param_new.

   Adding the synchronization parameter fails when:
   - The parameter was already added to the context
   - The parameter attributes are conflicting with those of the context.
     E.g. The context has the @ref AMXS_SYNC_ONLY_B_TO_A attribute set,
     and the parameter has @ref AMXS_SYNC_ONLY_A_TO_B set.

   If the context attributes are more strict than those of the parameter, the parameter attributes
   will be updated to match those of the context.

   @param ctx Pointer to a synchronization context.
   @param param Pointer to a synchronization parameter.

   @return
   - amxs_status_ok: the synchronization parameter is added to the synchronization context
   - amxs_status_duplicate: another synchronization parameter with the same direction and
                            parameter names already exists for this synchronization context
   - amxs_status_invalid_attr: the attributes of the synchronization parameter are conflicting
                               with those of the synchronization context
   - amxs_status_unknown_error: any other error
 */
amxs_status_t amxs_sync_ctx_add_param(amxs_sync_ctx_t* ctx, amxs_sync_param_t* param);

/**
   @ingroup amxs_sync
   @brief
   Creates and adds a synchronization parameter to a synchronization context.

   Allocates memory for a new synchronization parameter and initializes this parameter.
   Then adds it to the synchronization context.

   Adding the synchronization parameter fails when:
   - The parameter was already added to the context
   - The parameter attributes are conflicting with those of the context.
     E.g. The context has the @ref AMXS_SYNC_ONLY_B_TO_A attribute set,
     and the parameter has @ref AMXS_SYNC_ONLY_A_TO_B set.

   If the context attributes are more strict than those of the parameter, the parameter attributes
   will be updated to match those of the context.

   @param ctx Pointer to a synchronization context.
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
   - amxs_status_ok: the new synchronization parameter is added to the synchronization context
   - amxs_status_duplicate: another synchronization parameter with the same direction and
                            parameter names already exists for this synchronization context
   - amxs_status_invalid_attr: the attributes of the synchronization parameter are conflicting
                               with those of the synchronization context
   - amxs_status_unknown_error: any other error
 */
amxs_status_t amxs_sync_ctx_add_new_param(amxs_sync_ctx_t* ctx,
                                          const char* param_a,
                                          const char* param_b,
                                          int attributes,
                                          amxs_translation_cb_t translation_cb,
                                          amxs_action_cb_t action_cb,
                                          void* priv);

/**
   @ingroup amxs_sync
   @brief
   Creates and adds a synchronization parameter to a synchronization context.

   Allocates memory for a new synchronization parameter and initializes this parameter.
   Then adds it to the synchronization context.

   Adding the synchronization parameter fails when:
   - The parameter was already added to the context
   - The parameter attributes are conflicting with those of the context.
     E.g. The context has the @ref AMXS_SYNC_ONLY_B_TO_A attribute set,
     and the parameter has @ref AMXS_SYNC_ONLY_A_TO_B set.

   If the context attributes are more strict than those of the parameter, the parameter attributes
   will be updated to match those of the context.

   Uses default translation @ref amxs_sync_batch_param_copy_trans_cb and action @ref amxs_sync_param_copy_action_cb
   callbacks.

   @param ctx Pointer to a synchronization context.
   @param param_a Name of the parameter in object A
   @param param_b Name of the parameter in object B
   @param attributes Bitwise OR of zero or more of the following attributes:
                     - @ref AMXS_SYNC_DEFAULT
                     - @ref AMXS_SYNC_ONLY_B_TO_A
                     - @ref AMXS_SYNC_ONLY_A_TO_B
                     - @ref AMXS_SYNC_INIT_B

   @return
   - amxs_status_ok: the new synchronization parameter is added to the synchronization context
   - amxs_status_duplicate: another synchronization parameter with the same direction and
                            parameter names already exists for this synchronization context
   - amxs_status_invalid_attr: the attributes of the synchronization parameter are conflicting
                               with those of the synchronization context
   - amxs_status_unknown_error: any other error
 */
amxs_status_t amxs_sync_ctx_add_new_copy_param(amxs_sync_ctx_t* ctx,
                                               const char* param_a,
                                               const char* param_b,
                                               int attributes);

/**
   @ingroup amxs_sync
   @brief
   Adds a synchronization object to a synchronization context.

   The synchronization object can be be created using @ref amxs_sync_object_new.

   Adding the synchronization object fails when:
   - The object was already added to the context
   - The object attributes are conflicting with those of the context.
     E.g. The context has the @ref AMXS_SYNC_ONLY_B_TO_A attribute set,
     and the object has @ref AMXS_SYNC_ONLY_A_TO_B set.

   If the context attributes are more strict than those of the object, the object attributes
   will be updated to match those of the context.

   @param ctx Pointer to a synchronization context.
   @param object Pointer to a synchronization object.

   @return
   - amxs_status_ok: the synchronization object is added to the synchronization context
   - amxs_status_duplicate: another synchronization object with the same direction and
                            object names already exists for this synchronization context
   - amxs_status_invalid_attr: the attributes of the synchronization object are conflicting
                               with those of the synchronization context
   - amxs_status_unknown_error: any other error
 */
amxs_status_t amxs_sync_ctx_add_object(amxs_sync_ctx_t* ctx, amxs_sync_object_t* object);

/**
   @ingroup amxs_sync
   @brief
   Creates and adds a synchronization object to a synchronization context.

   Allocates memory for a new synchronization object and initializes this object.
   Then adds it to the synchronization context.

   Adding the synchronization object fails when:
   - The object was already added to the context
   - The object attributes are conflicting with those of the context.
     E.g. The context has the @ref AMXS_SYNC_ONLY_B_TO_A attribute set,
     and the object has @ref AMXS_SYNC_ONLY_A_TO_B set.

   If the context attributes are more strict than those of the object, the object attributes
   will be updated to match those of the context.

   @param ctx Pointer to a synchronization context.
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
   - amxs_status_ok: the new synchronization object is added to the synchronization context
   - amxs_status_duplicate: another synchronization object with the same direction and
                            object names already exists for this synchronization context
   - amxs_status_invalid_attr: the attributes of the synchronization object are conflicting
                               with those of the synchronization context
   - amxs_status_unknown_error: any other error
 */
amxs_status_t amxs_sync_ctx_add_new_object(amxs_sync_ctx_t* ctx,
                                           const char* object_a,
                                           const char* object_b,
                                           int attributes,
                                           amxs_translation_cb_t translation_cb,
                                           amxs_action_cb_t action_cb,
                                           void* priv);

/**
   @brief
   Creates and adds a synchronization object to a synchronization context.

   Allocates memory for a new synchronization object and initializes this object.
   Then adds it to the synchronization context.

   Adding the synchronization object fails when:
   - The object was already added to the context
   - The object attributes are conflicting with those of the context.
     E.g. The context has the @ref AMXS_SYNC_ONLY_B_TO_A attribute set,
     and the object has @ref AMXS_SYNC_ONLY_A_TO_B set.

   If the context attributes are more strict than those of the object, the object attributes
   will be updated to match those of the context.

   Uses default translation @ref amxs_sync_object_copy_trans_cb and action @ref amxs_sync_object_copy_action_cb
   callbacks.

   @param ctx Pointer to a synchronization context.
   @param object_a Name of the object in object A
   @param object_b Name of the object in object B
   @param attributes Bitwise OR of zero or more of the following attributes:
                     - @ref AMXS_SYNC_DEFAULT
                     - @ref AMXS_SYNC_ONLY_B_TO_A
                     - @ref AMXS_SYNC_ONLY_A_TO_B
                     - @ref AMXS_SYNC_INIT_B

   @return
   - amxs_status_ok: the new synchronization object is added to the synchronization context
   - amxs_status_duplicate: another synchronization object with the same direction and
                            object names already exists for this synchronization context
   - amxs_status_invalid_attr: the attributes of the synchronization object are conflicting
                               with those of the synchronization context
   - amxs_status_unknown_error: any other error
 */
amxs_status_t amxs_sync_ctx_add_new_copy_object(amxs_sync_ctx_t* ctx,
                                                const char* object_a,
                                                const char* object_b,
                                                int attributes);
/**
   @brief
   Set the local datamodel pointer for the sync root objects

   If one or both root objects for the synchronization are located in the same process as
   the synchronization code, it is possible to add read-only parameters to the sync.

   Having access to the datamodel enables the writing of read-only parameters.

   The datamodel pointer should only be set if the synchronization needs to write the object.

   @param ctx Pointer to a synchronization context.
   @param dm_a Pointer to the local datamodel which contains object A, may be NULL
   @param dm_b Pointer to the local datamodel which contains object B, may be NULL

   @return
   - amxs_status_ok: the datamodel pointers have been set successfully
   - amxs_status_unknown_error: any other error
 */
amxs_status_t amxs_sync_ctx_set_local_dm(amxs_sync_ctx_t* ctx,
                                         amxd_dm_t* dm_a,
                                         amxd_dm_t* dm_b);

#ifdef __cplusplus
}
#endif

#endif // __AMXS_SYNC_CTX_H__

