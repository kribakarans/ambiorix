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

#if !defined(__AMXS_TYPES_H__)
#define __AMXS_TYPES_H__

#ifdef __cplusplus
extern "C"
{
#endif

/**
   @file
   @brief
   Ambiorix Object Synchronization API header file
 */

/**
   @ingroup amxs_sync
   @defgroup amxs_sync_type synchronization API types
 */

#include <amxp/amxp_signal.h>
#include <amxp/amxp_slot.h>
#include <amxd/amxd_types.h>
#include <amxb/amxb.h>

typedef enum _amxs_sync_direction {
    amxs_sync_a_to_b,
    amxs_sync_b_to_a,
    amxs_sync_invalid
} amxs_sync_direction_t;

typedef enum _amxs_status {
    amxs_status_ok,
    amxs_status_duplicate,
    amxs_status_invalid_attr,
    amxs_status_invalid_arg,
    amxs_status_unknown_error,
    amxs_status_empty_context,
    amxs_status_invalid_type,
    amxs_status_object_not_found,
    amxs_status_subscription_failed,
    amxs_status_last
} amxs_status_t;

typedef enum _amxs_sync_entry_type {
    amxs_sync_type_invalid,
    amxs_sync_type_ctx,
    amxs_sync_type_object,
    amxs_sync_type_param
} amxs_sync_entry_type_t;

typedef struct _amxs_sync_entry amxs_sync_ctx_t;
typedef struct _amxs_sync_entry amxs_sync_object_t;
typedef struct _amxs_sync_entry amxs_sync_param_t;
typedef struct _amxs_sync_entry amxs_sync_entry_t;

/**
   @ingroup amxs_sync_type
   @brief
   Definition of the translation callback function.

   Depending on the action function, the input data might need to be formatted
   differently from the default event data structure. This callback function
   will be executed before the action callback function, and the translated
   data will be passed to the action callack.

   @param entry Pointer to the synchronization entry for which this callback
               function was registered.
   @param direction Indication in which direction the translation is needed
   @param input Pointer to a variant containing the initial data.
   @param output Pointer to a variant in which the translated data must be stored.
   @param priv Pointer to private data which is given when creating or initializing
              a synchronization object or parameter.

   @return
   amxs_status_ok when the translation was successful, any other status code otherwise
 */
typedef amxs_status_t (* amxs_translation_cb_t)(const amxs_sync_entry_t* entry,
                                                amxs_sync_direction_t direction,
                                                const amxc_var_t* input,
                                                amxc_var_t* output,
                                                void* priv);

/**
   @ingroup amxs_sync_type
   @brief
   Definition of the action callback function.

   Callback function that will be executed when a synchonized parameter or object changes.
   The event data will first be passed to a translation function, if given, and then this
   function will be invoked to act on the change.

   @param entry Pointer to the synchronization entry for which this callback
               function was registered.
   @param direction Indication in which direction the translation is needed
   @param data Pointer to a variant containing the input data
   @param priv Pointer to private data which is given when creating or initializing
              a synchronization object or parameter.

   @return
   amxs_status_ok when the action was successful, any other status code otherwise
 */
typedef amxs_status_t (* amxs_action_cb_t)(const amxs_sync_entry_t* entry,
                                           amxs_sync_direction_t direction,
                                           amxc_var_t* data,
                                           void* priv);

struct _amxs_sync_entry {
    amxc_llist_it_t it;                   // Linked list iterator, it.list points to the parent object or context
    char* a;                              // Name of object/parameter in object A
    char* b;                              // Name of object/parameter in object B
    int attributes;                       // Sync attributes
    amxs_action_cb_t action_cb;           // Action callback function
    amxs_translation_cb_t translation_cb; // Translation callback function
    void* priv;                           // Private data to be passed to the callback functions
    amxc_llist_t entries;                 // List of child entries
    amxs_sync_entry_type_t type;          // Type of sync entry
    amxb_bus_ctx_t* bus_ctx_a;            // Bus context for object A
    amxb_bus_ctx_t* bus_ctx_b;            // Bus context for object B
    amxc_llist_t subscriptions;           // List of amxb subscriptions
    amxp_signal_mngr_t* sig_mngr;         // Signal manager only set on ctx entries to send/receive internal sync events
    amxc_var_t a_to_b;                    // Htable of objects and parameters synced from A to B in case of a bidirectional sync
    amxc_var_t b_to_a;                    // Htable of objects and parameters synced from B to A in case of a bidirectional sync
    amxd_dm_t* local_dm_a;                // Pointer to the local dm for object A, if available
    amxd_dm_t* local_dm_b;                // Pointer to the local dm for object B, if available
};

/**
   @ingroup amxs_sync_type
   @brief Default synchronization attributes
   @details
   This means:
   - Synchronize bidirectionally
   - The initial values are taken from object A
   - Assume the existence of both objects
 */
#define AMXS_SYNC_DEFAULT     0x00
/**
   @ingroup amxs_sync_type
   @brief Only synchronize from object B to object A
 */
#define AMXS_SYNC_ONLY_B_TO_A 0x01
/**
   @ingroup amxs_sync_type
   @brief Only synchronize from object A to object B
 */
#define AMXS_SYNC_ONLY_A_TO_B 0x02
/**
   @ingroup amxs_sync_type
   @brief Take the initial values from object B
 */
#define AMXS_SYNC_INIT_B      0x04
/**
   @ingroup amxs_sync_type
   @brief Indicate that this parameter may be part of a batch copy operation
 */
#define AMXS_SYNC_PARAM_BATCH      0x08

#ifdef __cplusplus
}
#endif

#endif // __AMXS_TYPES_H__

