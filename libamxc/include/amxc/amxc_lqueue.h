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

#if !defined(__AMXC_LQUEUE_H__)
#define __AMXC_LQUEUE_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <amxc/amxc_common.h>
#include <amxc/amxc_llist.h>

/**
   @file
   @brief
   Ambiorix linked queue API header file
 */

/**
   @ingroup amxc_containers
   @defgroup amxc_lqueue Linked Queue
 */

/**
   @ingroup amxc_lqueue
   @brief
   The linked queue structure.
 */
typedef amxc_llist_t amxc_lqueue_t;

/**
   @ingroup amxc_lqueue
   @brief
   The linked queue iterator structure.
 */
typedef amxc_llist_it_t amxc_lqueue_it_t;

/**
   @ingroup amxc_lqueue
   @brief
   Definition of the item delete function.

   A pointer to a delete function is used in the following
   functions @ref amxc_lqueue_delete, @ref amxc_lqueue_clean
 */
typedef amxc_llist_it_delete_t amxc_lqueue_it_delete_t;

/**
   @ingroup amxc_lqueue
   @brief
   Allocates a linked queue.

   Allocates and initializes memory to store a linked queue.
   This function allocates memory from the heap,
   if a linked queue is on the stack, it can be initialized using the
   function @ref amxc_lqueue_init

   @note
   The allocated memory must be freed when not used anymore,
   use @ref amxc_lqueue_delete to free the memory

   @param lqueue a pointer to the location where the pointer to the new linked
                 queue can be stored

   @return
   -1 if an error occured. 0 on success
 */
AMXC_INLINE
int amxc_lqueue_new(amxc_lqueue_t** lqueue) {
    return amxc_llist_new(lqueue);
}

/**
   @ingroup amxc_lqueue
   @brief
   Frees the previously allocated linked queue.

   Removes all items from the linked queue,
   if a delete function is provided, it is called for each item after it was
   removed from the queue

   Frees the allocated memory and sets the pointer to NULL.

   @note
   Only call this function for linked queues that are allocated on the heap
   using @ref amxc_lqueue_new

   @param lqueue a pointer to the location where the pointer to the linked
                 queue is stored
   @param func a pointer to a function that is called to free each item in the
               linked queue
 */
AMXC_INLINE
void amxc_lqueue_delete(amxc_lqueue_t** lqueue, amxc_lqueue_it_delete_t func) {
    amxc_llist_delete(lqueue, func);
}

/**
   @ingroup amxc_lqueue
   @brief
   Initializes a linked queue.

   Initializes the linked queue structure. All pointers are reset to NULL.
   This function is typically called for linked queues that are on the stack.
   Allocating and initializing a linked queue on the heap can be done
   using @ref amxc_lqueue_new

   @note
   When calling this function on an already initialized linked queue,
   that contains items, the linked queue is reset and all items in the queue
   are lost. Use @ref amxc_lqueue_clean to remove all items from the queue.

   @param lqueue a pointer to the linked queue structure.

   @return
   0 on success.
   -1 if a NULL pointer is given.
 */
AMXC_INLINE
int amxc_lqueue_init(amxc_lqueue_t* const lqueue) {
    return amxc_llist_init(lqueue);
}

/**
   @ingroup amxc_lqueue
   @brief
   Removes all items from the linked queue.

   Removes all items from the linked queue,
   if a delete function is provided, it is called for each item after it was
   removed from the queue.

   @param lqueue a pointer to the linked queue structure
   @param func a pointer to a function that is called to free each item in the linked queue
 */
AMXC_INLINE
void amxc_lqueue_clean(amxc_lqueue_t* const lqueue, amxc_lqueue_it_delete_t func) {
    amxc_llist_clean(lqueue, func);
}

/**
   @ingroup amxc_lqueue
   @brief
   Adds an item to the linked queue.

   If the item is already in a queue, it is removed from that queue.

   @note
   Make sure that the iterator of the item is at least initialized when it is
   first used. Initializing an iterator can be done using @ref amxc_lqueue_it_init.
   An iterator that is already used in a linked queue is considered initialized.

   @param lqueue a pointer to the linked queue structure
   @param it a pointer to the linked queue item iterator

   @return
   returns 0 when the item is added, -1 when there was an error
 */
AMXC_INLINE
int amxc_lqueue_add(amxc_lqueue_t* const lqueue, amxc_lqueue_it_t* const it) {
    return amxc_llist_append(lqueue, it);
}

/**
   @ingroup amxc_lqueue
   @brief
   Removes the first added item from the queue.

   @param lqueue a pointer to the linked queue structure

   @return
   The iterator to the first added item or NULL if no more items on the queue
 */
AMXC_INLINE
amxc_lqueue_it_t* amxc_lqueue_remove(amxc_lqueue_t* const lqueue) {
    return amxc_llist_take_first(lqueue);
}

/**
   @ingroup amxc_lqueue
   @brief
   Calculates the size of the queue, expressed in number of items.

   @param lqueue a pointer to the linked queue structure

   @return
   The number of items on the linked queue.
 */
AMXC_INLINE
size_t amxc_lqueue_size(const amxc_lqueue_t* const lqueue) {
    return amxc_llist_size(lqueue);
}

/**
   @ingroup amxc_lqueue
   @brief
   Checks that the linked queue is empty.

   @param lqueue a pointer to the linked queue structure

   @return
   returns true when the linked queue contains no items,
   false when there is at least one item on the queue.
 */
AMXC_INLINE
bool amxc_lqueue_is_empty(const amxc_lqueue_t* const lqueue) {
    return amxc_llist_is_empty(lqueue);
}

/**
   @ingroup amxc_lqueue
   @brief
   Initializes a linked queue iterator.

   Initializes the linked queue iterator structure.
   All pointers are reset to NULL.

   @note
   When calling this function on an already initialized linked queue iterator,
   the linked queue iterator is reset and the queue the iterator was in is
   corrupted. Use @ref amxc_lqueue_remove to remove the iterator from the queue

   @param it a pointer to the linked queue iterator structure.

   @return
   0 on success.
   -1 if a NULL pointer is given.
 */
AMXC_INLINE
int amxc_lqueue_it_init(amxc_lqueue_it_t* const it) {
    return amxc_llist_it_init(it);
}

#ifdef __cplusplus
}
#endif

#endif // __AMXC_LQUEUE_H__
