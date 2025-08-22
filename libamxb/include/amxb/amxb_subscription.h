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

#if !defined(__AMXB_SUBSCRIPTION_H__)
#define __AMXB_SUBSCRIPTION_H__

#ifdef __cplusplus
extern "C"
{
#endif

void amxb_subscription_remove_it(amxc_llist_it_t* it);

/**
   @ingroup amxb_event
   @brief
   Creates a subscription object and subscribes for events of a object tree.

   Subscribes for all events matching the given filter on an object (sub)tree.

   Using the provided object path, all events matching the given expression,
   of that object or any of the child objects (instances included) are passed
   to the callback function.

   A subscription object amxb_subscription_t is allocated and must be
   freed using using @ref amxb_subscription_delete.

   The allocated subscription object can be stored in a amxc linked list.

   @param subscription The new allocated subscription object
   @param bus_ctx The bus context (or connection)
   @param object object or search path, object paths must end with a "."
   @param expression an expression used to filter the events
   @param slot_cb callback function, called for each matching event
   @param priv private data, passed to the callback function

   @return
   @ref AMXB_STATUS_OK when subscription object was created and subscribing
   for events was successful.
   When failed any other error code can be returned and the subscription object
   is NULL.
 */
int amxb_subscription_new(amxb_subscription_t** subscription,
                          amxb_bus_ctx_t* bus_ctx,
                          const char* object,
                          const char* expression,
                          amxp_slot_fn_t slot_cb,
                          void* priv);

/**
   @ingroup amxb_event
   @brief
   Deletes a subscription object and unsubscribe for events of a object tree.

   Unsubscribes for events of an object (sub)tree.

   The passes subscription object must be created with @ref amxb_subscription_new

   @param subscription The subscription object

   @return
   @ref AMXB_STATUS_OK when subscription object was deleted and unsubscribe
   for events was successful.
   If unsubscribing for events fail, the subscription object will be deleted
 */
int amxb_subscription_delete(amxb_subscription_t** subscription);

/**
   @ingroup amxb_event
   @brief
   Find an exact subscription.

   Searches in the given bus context for the first matching subscription.
   A subscription is matching when the object path, the slot_cb and private data
   is exactly matching .

   @param bus_ctx The bus context (or connection)
   @param object object or search path, object paths must end with a "."
   @param slot_cb callback function, called for each matching event
   @param priv private data, passed to the callback function

   @return
   subscription pointer or NULL if no matching found.
 */
amxb_subscription_t* amxb_subscription_find(amxb_bus_ctx_t* bus_ctx,
                                            const char* object,
                                            amxp_slot_fn_t slot_cb,
                                            void* priv);

/**
   @ingroup amxb_event
   @brief
   Find a parent subscription.

      A parent subscription is a subscription taken on a parent object path.

   If a search path is given only the fixed part of the path is taken into account.

   @param bus_ctx The bus context (or connection)
   @param object object or search path, object paths must end with a "."

   @return
   subscription pointer or NULL if no matching found.
 */
amxb_subscription_t* amxb_subscription_find_parent(amxb_bus_ctx_t* bus_ctx,
                                                   const char* object);

/**
   @ingroup amxb_event
   @brief
   Find a child subscription.

   A child subscription is a subscription taken on a child object path.

   If a search path is given only the fixed part of the path is taken into account.

   @param bus_ctx The bus context (or connection)
   @param object object or search path, object paths must end with a "."

   @return
   subscription pointer or NULL if no matching found.
 */
amxb_subscription_t* amxb_subscription_find_child(amxb_bus_ctx_t* bus_ctx,
                                                  const char* object);
#ifdef __cplusplus
}
#endif

#endif // __AMXB_SUBSCRIPTION_H__
