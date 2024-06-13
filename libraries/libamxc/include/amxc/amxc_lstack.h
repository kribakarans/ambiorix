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

#if !defined(__AMXC_LSTACK_H__)
#define __AMXC_LSTACK_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <amxc/amxc_common.h>
#include <amxc/amxc_llist.h>

/**
   @file
   @brief
   Ambiorix linked stack API header file
 */

/**
   @ingroup amxc_containers
   @defgroup amxc_lstack Linked stack
 */

/**
   @ingroup amxc_lstack
   @brief
   The linked stack structure.
 */
typedef amxc_llist_t amxc_lstack_t;

/**
   @ingroup amxc_lstack
   @brief
   The linked stack iterator structure.
 */
typedef amxc_llist_it_t amxc_lstack_it_t;

/**
   @ingroup amxc_lstack
   @brief
   Definition of the item delete function.

   A pointer to a delete function is used in the following
   functions @ref amxc_lstack_delete, @ref amxc_lstack_clean
 */
typedef amxc_llist_it_delete_t amxc_lstack_it_delete_t;

/**
   @ingroup amxc_lstack
   @brief
   Allocates a linked stack.

   Allocates and initializes memory to store a linked stack.
   This function allocates memory from the heap,
   if a linked stack is on the stack, it can be initialized using
   function @ref amxc_lstack_init

   @note
   The allocated memory must be freed when not used anymore,
   use @ref amxc_lstack_delete to free the memory

   @param lstack a pointer to the location where the pointer to the new
                 linked stack can be stored

   @return
   -1 if an error occured. 0 on success
 */
AMXC_INLINE
int amxc_lstack_new(amxc_lstack_t** lstack) {
    return amxc_llist_new(lstack);
}

/**
   @ingroup amxc_lstack
   @brief
   Frees the previously allocated linked stack.

   Removes all items from the linked stack, if a delete function is provided,
   it is called for each item after it was removed from the stack.

   Frees the allocated memory and sets the pointer to NULL.

   @note
   Only call this function for linked stacks that are allocated on the heap
   using @ref amxc_lstack_new

   @param lstack a pointer to the location where the pointer to the linked stack
                 is stored
   @param func a pointer to a function that is called to free each item in
               the linked stack
 */
AMXC_INLINE
void amxc_lstack_delete(amxc_lstack_t** lstack, amxc_lstack_it_delete_t func) {
    amxc_llist_delete(lstack, func);
}

/**
   @ingroup amxc_lstack
   @brief
   Initializes a linked stack.

   Initializes the linked stack structure. All pointers are reset to NULL.
   This function is typically called for linked stacks that are on the stack.
   Allocating and initializing a linked stack on the heap can be done
   using @ref amxc_lstack_new

   @note
   When calling this function on an already initialized linked stack,
   that contains items, the linked stack is reset and all items in the stack
   are lost. Use @ref amxc_lstack_clean to remove all items from the stack.

   @param lstack a pointer to the linked stack structure.

   @return
   0 on success.
   -1 if a NULL pointer is given.
 */
AMXC_INLINE
int amxc_lstack_init(amxc_lstack_t* const lstack) {
    return amxc_llist_init(lstack);
}

/**
   @ingroup amxc_lstack
   @brief
   Removes all items from the linked stack

   Removes all items from the linked stack,
   if a delete function is provided, it is called for each item after it was
   removed from the stack.

   @param lstack a pointer to the linked stack structure
   @param func a pointer to a function that is called to free each item
               in the linked stack
 */
AMXC_INLINE
void amxc_lstack_clean(amxc_lstack_t* const lstack, amxc_lstack_it_delete_t func) {
    amxc_llist_clean(lstack, func);
}

/**
   @ingroup amxc_lstack
   @brief
   Adds an item to the linked stack.

   If the item is already in a stack, it is removed from that stack.

   @note
   Make sure that the iterator of the item is at least initialized when it is
   first used. Initializing an iterator can be done using @ref amxc_lstack_it_init.
   An iterator that is already used in a linked stack is considered initialized.

   @param lstack a pointer to the linked stack structure
   @param it a pointer to the linked stack item iterator

   @return
   returns 0 when the item is added, -1 when there was an error
 */
AMXC_INLINE
int amxc_lstack_push(amxc_lstack_t* const lstack, amxc_lstack_it_t* const it) {
    return amxc_llist_append(lstack, it);
}

/**
   @ingroup amxc_lstack
   @brief
   Removes the last added item from the stack.

   @param lstack a pointer to the linked stack structure

   @return
   The iterator to the last added item or NULL if no more items on the stack
 */
AMXC_INLINE
amxc_lstack_it_t* amxc_lstack_pop(amxc_lstack_t* const lstack) {
    return amxc_llist_take_last(lstack);
}

/**
   @ingroup amxc_lstack
   @brief
   Peeks the top of the stack, without removing.

   @param lstack a pointer to the linked stack structure

   @return
   The iterator to the last added item or NULL if no more items on the stack
 */
AMXC_INLINE
amxc_lstack_it_t* amxc_lstack_peek(amxc_lstack_t* const lstack) {
    return amxc_llist_get_last(lstack);
}


/**
   @ingroup amxc_lstack
   @brief
   Calculates the size of the stack, expressed in number of items.

   @param lstack a pointer to the linked stack structure

   @return
   The number of items on the linked stack.
 */
AMXC_INLINE
size_t amxc_lstack_size(const amxc_lstack_t* const lstack) {
    return amxc_llist_size(lstack);
}

/**
   @ingroup amxc_lstack
   @brief
   Checks if the linked stack is empty.

   @param lstack a pointer to the linked stack structure

   @return
   returns true when the linked stack contains no items,
   false when there is at least one item on the stack.
 */
AMXC_INLINE
bool amxc_lstack_is_empty(const amxc_lstack_t* const lstack) {
    return amxc_llist_is_empty(lstack);
}

/**
   @ingroup amxc_lstack
   @brief
   Initializes a linked stack iterator.

   Initializes the linked stack iterator structure.
   All pointers are reset to NULL.

   @note
   When calling this function on an already initialized linked stack iterator,
   the linked stack iterator is reset and the stack the iterator was in, is
   corrupted. Use @ref amxc_lstack_pop to remove the iterator from the stack

   @param it a pointer to the linked stack iterator structure.

   @return
   0 on success.
   -1 if a NULL pointer is given.
 */
AMXC_INLINE
int amxc_lstack_it_init(amxc_lstack_it_t* const it) {
    return amxc_llist_it_init(it);
}

#ifdef __cplusplus
}
#endif

#endif // __AMXC_LSTACK_H__
