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

#if !defined(__AMXS_SYNC_PARAM_H__)
#define __AMXS_SYNC_PARAM_H__

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
   @defgroup amxs_sync_param Parameter synchronization API
 */

/**
   @ingroup amxs_sync_param
   @brief
   Synchronization parameter constructor function

   Allocates memory for a new synchronization parameter and initializes this parameter.

   Use @ref amxs_sync_param_delete to remove the synchronization parameter and free all allocated
   memory.

   @param param Pointer to a synchronization parameter pointer. The address of the new allocated
                synchronization parameter is stored in this pointer.
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
   amxs_status_ok when the synchronization parameter is created, or another status code when
   failed to create the synchronization parameter.
 */
amxs_status_t amxs_sync_param_new(amxs_sync_param_t** param,
                                  const char* param_a,
                                  const char* param_b,
                                  int attributes,
                                  amxs_translation_cb_t translation_cb,
                                  amxs_action_cb_t action_cb,
                                  void* priv);

/**
   @ingroup amxs_sync_param
   @brief
   Synchronization parameter constructor function

   Allocates memory for a new synchronization parameter and initializes this parameter.

   Use @ref amxs_sync_param_delete to remove the synchronization parameter and free all allocated
   memory.

   Uses default translation @ref amxs_sync_param_copy_trans_cb and action @ref amxs_sync_param_copy_action_cb
   callbacks.

   @param param Pointer to a synchronization parameter pointer. The address of the new allocated
                synchronization parameter is stored in this pointer.
   @param param_a Name of the parameter in object A
   @param param_b Name of the parameter in object B
   @param attributes Bitwise OR of zero or more of the following attributes:
                     - @ref AMXS_SYNC_DEFAULT
                     - @ref AMXS_SYNC_ONLY_B_TO_A
                     - @ref AMXS_SYNC_ONLY_A_TO_B
                     - @ref AMXS_SYNC_INIT_B

   @return
   amxs_status_ok when the synchronization parameter is created, or another status code when
   failed to create the synchronization parameter.
 */
amxs_status_t amxs_sync_param_new_copy(amxs_sync_param_t** param,
                                       const char* param_a,
                                       const char* param_b,
                                       int attributes);

/**
   @ingroup amxs_sync_param
   @brief
   Synchronization parameter destructor function

   Frees all memory allocated for a synchronization parameter.
   Also removes the synchronization parameter from any synchronization object or context
   it was attached to.

   @param param Pointer to a synchronization parameter pointer.
 */
void amxs_sync_param_delete(amxs_sync_param_t** param);

#ifdef __cplusplus
}
#endif

#endif // __AMXS_SYNC_PARAM_H__

