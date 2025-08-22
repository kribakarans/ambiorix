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

#if !defined(__AMXS_UTIL_H__)
#define __AMXS_UTIL_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <amxs/amxs_types.h>
#include <amxs/amxs_sync_ctx.h>
#include <amxs/amxs_sync_object.h>
#include <amxs/amxs_sync_param.h>

/**
   @ingroup amxs_sync
   @defgroup amxs_sync_utils synchronization API Utility functions
 */

bool amxs_sync_entry_remove_bidrection_object(const amxs_sync_entry_t* entry,
                                              amxs_sync_direction_t direction,
                                              const char* path);

bool amxs_sync_entry_check_bidrection_object(const amxs_sync_entry_t* entry,
                                             amxs_sync_direction_t direction,
                                             const char* path,
                                             const char* opposite_path);

bool amxs_sync_entry_check_bidirectional_loop(const amxs_sync_entry_t* entry,
                                              amxs_sync_direction_t direction,
                                              amxc_var_t* value,
                                              const char* path,
                                              const char* opposite_path);

bool amxs_sync_entry_is_bidirectional(const amxs_sync_entry_t* entry);

bool amxs_sync_entry_direction_allowed(const amxs_sync_entry_t* entry,
                                       amxs_sync_direction_t direction);

bool amxs_sync_entry_is_batch_param(const amxs_sync_entry_t* const entry);

const char* amxs_sync_entry_get_name(const amxs_sync_entry_t* entry,
                                     amxs_sync_direction_t direction);

const char* amxs_sync_entry_get_opposite_name(const amxs_sync_entry_t* entry,
                                              amxs_sync_direction_t direction);

amxs_sync_entry_t* amxs_sync_entry_get_parent(const amxs_sync_entry_t* entry);

amxs_sync_ctx_t* amxs_sync_entry_get_ctx(const amxs_sync_entry_t* entry);

amxp_signal_mngr_t* amxs_sync_entry_get_signal_manager(const amxs_sync_entry_t* const entry);

amxb_bus_ctx_t* amxs_sync_ctx_get_opposite_bus_ctx(const amxs_sync_ctx_t* ctx,
                                                   amxs_sync_direction_t direction);

amxb_bus_ctx_t* amxs_sync_ctx_get_bus_ctx(const amxs_sync_ctx_t* ctx,
                                          amxs_sync_direction_t direction);

amxd_dm_t* amxs_sync_ctx_get_opposite_dm(const amxs_sync_ctx_t* ctx,
                                         amxs_sync_direction_t direction);

amxd_dm_t* amxs_sync_ctx_get_dm(const amxs_sync_ctx_t* ctx,
                                amxs_sync_direction_t direction);

unsigned int amxs_sync_entry_get_opposite_index(const amxs_sync_entry_t* entry,
                                                amxs_sync_direction_t direction,
                                                unsigned int index);

char* amxs_sync_entry_get_opposite_path(const amxs_sync_entry_t* entry,
                                        amxs_sync_direction_t direction,
                                        const char* old_path);

char* amxs_sync_entry_get_opposite_parent_path(const amxs_sync_entry_t* entry,
                                               amxs_sync_direction_t direction,
                                               const char* old_path);

char* amxs_sync_entry_get_regex_path(const amxs_sync_entry_t* const entry,
                                     amxs_sync_direction_t direction);

char* amxs_sync_entry_get_regex_parent_path(const amxs_sync_entry_t* const entry,
                                            amxs_sync_direction_t direction);

amxs_status_t amxs_sync_entry_get_batch_params(const amxs_sync_entry_t* const entry,
                                               amxc_var_t* params,
                                               amxs_sync_direction_t direction);

/**
   @ingroup amxs_sync_utils
   @brief
   Translates data from a dm:object-changed event to data suited for an amxb_set call for a single parameter.

   @param entry Pointer to the synchronization entry for which the callback is triggered.
   @param direction Direction in which the synchronization is triggered.
   @param input Variant containing the incoming event data.
   @param output Variant to store the converted data, this data will be passed to the action callback.
   @param priv Pointer to user data which was given when the entry was created.

   @return amxs_status_ok when the parameter data is translated successfully.
 */
amxs_status_t amxs_sync_param_copy_trans_cb(const amxs_sync_entry_t* entry,
                                            amxs_sync_direction_t direction,
                                            const amxc_var_t* input,
                                            amxc_var_t* output,
                                            void* priv);
/**
   @ingroup amxs_sync_utils
   @brief
   Translates data from a dm:object-changed event to data suited for an amxb_set call
   for all parameters in the event that are marked as batch copy parameters.

   @param entry Pointer to the synchronization entry for which the callback is triggered.
   @param direction Direction in which the synchronization is triggered.
   @param input Variant containing the incoming event data.
   @param output Variant to store the converted data, this data will be passed to the action callback.
   @param priv Pointer to user data which was given when the entry was created.

   @return amxs_status_ok when the parameter data is translated successfully.
 */
amxs_status_t amxs_sync_batch_param_copy_trans_cb(const amxs_sync_entry_t* entry,
                                                  amxs_sync_direction_t direction,
                                                  const amxc_var_t* input,
                                                  amxc_var_t* output,
                                                  void* priv);
/**
   @ingroup amxs_sync_utils
   @brief
   Sets the new parameter value

   If a local dm is specified, an amxd transaction will be used to set the value.
   This allows writing read-only parameters.

   If no local dm is specified, amxb_set will be used.

   @param entry Pointer to the synchronization entry for which the callback is triggered.
   @param direction Direction in which the synchronization is triggered.
   @param data Variant containing the parameter data to be set.
   @param priv Pointer to user data which was given when the entry was created.

   @return amxs_status_ok when the value has been set successfully.
 */
amxs_status_t amxs_sync_param_copy_action_cb(const amxs_sync_entry_t* entry,
                                             amxs_sync_direction_t direction,
                                             amxc_var_t* data,
                                             void* priv);

/**
   @ingroup amxs_sync_utils
   @brief
   Translates data from a dm:instance-added or dm:instance-removed event to data suited for
   an amxb call for this instance and all it's parameters.

   @param entry Pointer to the synchronization entry for which the callback is triggered.
   @param direction Direction in which the synchronization is triggered.
   @param input Variant containing the incoming event data.
   @param output Variant to store the converted data, this data will be passed to the action callback.
   @param priv Pointer to user data which was given when the entry was created.

   @return amxs_status_ok when all data is translated successfully.
 */
amxs_status_t amxs_sync_object_copy_trans_cb(const amxs_sync_entry_t* entry,
                                             amxs_sync_direction_t direction,
                                             const amxc_var_t* input,
                                             amxc_var_t* output,
                                             void* priv);

/**
   @ingroup amxs_sync_utils
   @brief
   Adds, removes or updates an object with the given data using an amxb call.

   @param entry Pointer to the synchronization entry for which the callback is triggered.
   @param direction Direction in which the synchronization is triggered.
   @param data Variant containing the object data to be updated.
   @param priv Pointer to user data which was given when the entry was created.

   @return amxs_status_ok when the object has been updated successfully.
 */
amxs_status_t amxs_sync_object_copy_action_cb(const amxs_sync_entry_t* entry,
                                              amxs_sync_direction_t direction,
                                              amxc_var_t* data,
                                              void* priv);

#ifdef __cplusplus
}
#endif

#endif // __AMXS_UTIL_H__

