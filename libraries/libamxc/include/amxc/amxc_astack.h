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

#if !defined(__AMXC_ASTACK_H__)
#define __AMXC_ASTACK_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <amxc/amxc_common.h>
#include <amxc/amxc_array.h>

/**
   @file
   @brief
   Ambiorix array stack API header file
 */

/**
   @ingroup amxc_containers
   @defgroup amxc_astack Array stack

   @brief
   A stack implementation based on @ref amxc_array

   The basic operators on a stack are push and pop.

   Using the @ref amxc_array a stack can be created which has a initial
   size and can grow when needed.

   It is possible to peek at the top of the stack, without removing the element,
   using @ref amxc_astack_peek

   When pushing data on the stack, the data will be put in the first empty bucket,
   if no empty bucket is available, the stack (bucket array) will grow.

   When popping data, the last non empty bucket is returned.
 */

/**
   @ingroup amxc_astack
   @brief
   The array stack structure.
 */
typedef amxc_array_t amxc_astack_t;

/**
   @ingroup amxc_astack
   @brief
   The array stack iterator structure.
 */
typedef amxc_array_it_t amxc_astack_it_t;

/**
   @ingroup amxc_astack
   @brief
   Definition of the item delete function.

   A pointer to a delete function is used in the following functions
   @ref amxc_astack_delete, @ref amxc_astack_clean
 */
typedef amxc_array_it_delete_t amxc_astack_it_delete_t;

/**
   @ingroup amxc_astack
   @brief
   Allocates an array stack.

   Allocates and initializes memory to store an array stack.
   This function allocates memory from the heap, if an array stack is on the
   stack, it can be initialized using function @ref amxc_astack_init

   @note
   The allocated memory must be freed when not used anymore,
   use @ref amxc_astack_delete to free the memory

   @param astack a pointer to the location where the pointer to the new array
                 stack can be stored

   @return
   -1 if an error occured. 0 on success
 */
AMXC_INLINE
int amxc_astack_new(amxc_astack_t** astack) {
    return amxc_array_new(astack, 10);
}

/**
   @ingroup amxc_astack
   @brief
   Frees the previously allocated array stack.

   Removes all items from the array stack,
   if a delete function is provided, it is called for each item on the stack.

   Frees the allocated memory and sets the pointer to NULL.

   @note
   Only call this function for array stacks that are allocated on the heap
   using @ref amxc_astack_new

   @param astack a pointer to the location where the pointer to the array stack
                 is be stored
   @param func pointer to a function that is called to free each item in the
               array stack
 */
AMXC_INLINE
void amxc_astack_delete(amxc_astack_t** astack, amxc_astack_it_delete_t func) {
    amxc_array_delete(astack, func);
}

/**
   @ingroup amxc_astack
   @brief
   Initializes an array stack.

   Initializes the array stack structure. All pointers are reset to NULL.
   This function is typically called for array stacks that are on the stack.
   Allocating and initializing an array stack on the heap can be done
   using @ref amxc_astack_new

   @note
   When calling this function on an already initialized array stack,
   that contains items, the array stack is reset and all items in the stack are
   lost (Could lead to memory loss).
   Use @ref amxc_astack_clean to remove all items from the stack.

   @param astack a pointer to the array stack structure.

   @return
   0 on success.
   -1 if a NULL pointer is given.
 */
AMXC_INLINE
int amxc_astack_init(amxc_astack_t* const astack) {
    return amxc_array_init(astack, 10);
}

/**
   @ingroup amxc_astack
   @brief
   Removes all items from the array stack.

   Removes all items from the array stack.
   If a delete function is provided, it is called for each item on the stack.

   @param astack a pointer to the array stack structure
   @param func a pointer to a function that is called to free each item in the
               array stack
 */
AMXC_INLINE
void amxc_astack_clean(amxc_astack_t* const astack, amxc_astack_it_delete_t func) {
    amxc_array_clean(astack, func);
}

/**
   @ingroup amxc_astack
   @brief
   Adds an item to the array stack.

   If the item is already in a stack, it is removed from that stack.

   @param astack a pointer to the array stack structure
   @param data a pointer to the data that needs to be added to the stack

   @return
   returns 0 when the item is added, -1 when there was an error
 */
AMXC_INLINE
amxc_astack_it_t* amxc_astack_push(amxc_astack_t* const astack, void* data) {
    return amxc_array_append_data(astack, data);
}

/**
   @ingroup amxc_astack
   @brief
   Removes the last added data from the stack.

   @param astack a pointer to the array stack structure

   @return
   The pointer to the data last added to the stack
   or NULL if no more items on the stack.
 */
AMXC_INLINE
void* amxc_astack_pop(amxc_astack_t* const astack) {
    return amxc_array_take_last_data(astack);
}

/**
   @ingroup amxc_astack
   @brief
   Peek the top of the stack, without removing.

   @param astack a pointer to the array stack structure

   @return
   The pointer to the data last added to the stack
   or NULL if no more items on the stack
 */
AMXC_INLINE
void* amxc_astack_peek(amxc_astack_t* const astack) {
    return amxc_array_get_last(astack);
}

/**
   @ingroup amxc_astack
   @brief
   Calculate the number of items on the stack, expressed in number of items.

   @param astack a pointer to the array stack structure

   @return
   The number of items on the array stack.
 */
AMXC_INLINE
size_t amxc_astack_size(const amxc_astack_t* const astack) {
    return amxc_array_size(astack);
}

/**
   @ingroup amxc_astack
   @brief
   Checks that the array stack is empty.

   @param astack a pointer to the array stack structure

   @return
   returns true when the array stack contains no items,
   false when there is at least one item on the stack.
 */
AMXC_INLINE
bool amxc_astack_is_empty(const amxc_astack_t* const astack) {
    return amxc_array_is_empty(astack);
}

#ifdef __cplusplus
}
#endif

#endif // __AMXC_ASTACK_H__
