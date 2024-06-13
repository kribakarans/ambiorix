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

#if !defined(__AMXC_AQUEUE_H__)
#define __AMXC_AQUEUE_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <amxc/amxc_common.h>
#include <amxc/amxc_array.h>

/**
   @file
   @brief
   Ambiorix array based queue API header file
 */

/**
   @ingroup amxc_containers
   @defgroup amxc_aqueue Array Queue

   @brief
   A queue implementation based on @ref amxc_array

   The basic operators on a queue are add and remove.

   Using the @ref amxc_array a queue can be created which has a initial
   size and can grow when needed.

   When adding data to the queue, the data will be put in the first empty bucket,
   if no empty bucket is available, the queue (bucket array) will grow.

   When removing data, the first non empty bucket is returned and all items
   are shifted left.

 */

/**
   @ingroup amxc_aqueue
   @brief
   The array queue structure.
 */
typedef amxc_array_t amxc_aqueue_t;

/**
   @ingroup amxc_aqueue
   @brief
   The array queue iterator structure.
 */
typedef amxc_array_it_t amxc_aqueue_it_t;

/**
   @ingroup amxc_aqueue
   @brief
   Definition of the item delete function.

   A pointer to a delete function is used in the following functions
   @ref amxc_aqueue_delete, @ref amxc_aqueue_clean
 */
typedef amxc_array_it_delete_t amxc_aqueue_it_delete_t;

/**
   @ingroup amxc_aqueue
   @brief
   Allocates an array queue.

   Allocates and initializes memory to store an array queue.
   This function allocates memory from the heap.
   If an array queue is on the stack, it can be initialized using
   function @ref amxc_aqueue_init

   @note
   The allocated memory must be freed when not used anymore.
   Use @ref amxc_aqueue_delete to free the memory

   @param aqueue a pointer to the location where the pointer to the new array
                 queue can be stored

   @return
   -1 if an error occurred. 0 on success
 */
AMXC_INLINE
int amxc_aqueue_new(amxc_aqueue_t** aqueue) {
    return amxc_array_new(aqueue, 10);
}

/**
   @ingroup amxc_aqueue
   @brief
   Frees the previously allocated array queue.

   Removes all items from the array queue.
   If a delete function is provided, it is called for each item in the queue.

   Frees the allocated memory and sets the pointer to NULL.

   @note
   Only call this function for array queues that are allocated on the heap using
   @ref amxc_aqueue_new

   @param aqueue a pointer to the location where the pointer to the array queue
                 is stored
   @param func a pointer to a function that is called to free each item in the
               array queue
 */
AMXC_INLINE
void amxc_aqueue_delete(amxc_aqueue_t** aqueue, amxc_aqueue_it_delete_t func) {
    amxc_array_delete(aqueue, func);
}

/**
   @ingroup amxc_aqueue
   @brief
   Initializes an array queue.

   Initializes the array queue structure. All pointers are reset to NULL.
   This function is typically called for array queues that are on the stack.
   Allocating and initializing an array queue on the heap can be done using
   @ref amxc_aqueue_new

   @note
   When calling this function on an already initialized array queue,
   that contains items, the array queue is reset and all items in the queue
   are lost (Could potentially lead to memory leaks).
   Use @ref amxc_aqueue_clean to remove all items from the queue.

   @param aqueue a pointer to the array queue structure.

   @return
   0 on success.
   -1 if a NULL pointer is given.
 */
AMXC_INLINE
int amxc_aqueue_init(amxc_aqueue_t* const aqueue) {
    return amxc_array_init(aqueue, 10);
}

/**
   @ingroup amxc_aqueue
   @brief
   Removes all items from the array queue.

   Removes all items from the array queue.
   If a delete function is provided, it is called for each item in the queue.

   @param aqueue a pointer to the array queue structure
   @param func a pointer to a function that is called to free each item in the
               array queue
 */
AMXC_INLINE
void amxc_aqueue_clean(amxc_aqueue_t* const aqueue,
                       amxc_aqueue_it_delete_t func) {
    amxc_array_clean(aqueue, func);
}

/**
   @ingroup amxc_aqueue
   @brief
   Adds data to the array queue.

   @param aqueue a pointer to the array queue structure
   @param data a pointer to the data

   @return
   returns the iterator where the data is added, or NULL if adding the data
   failed
 */
AMXC_INLINE
amxc_aqueue_it_t* amxc_aqueue_add(amxc_aqueue_t* const aqueue, void* data) {
    return amxc_array_append_data(aqueue, data);
}

/**
   @ingroup amxc_aqueue
   @brief
   Removes the first added data from the queue.

   @param aqueue a pointer to the array queue structure

   @return
   Pointer to the first added data or NULL if no more items on the queue
 */
AMXC_INLINE
void* amxc_aqueue_remove(amxc_aqueue_t* const aqueue) {
    void* rv = amxc_array_take_first_data(aqueue);
    amxc_array_shift_left(aqueue, 1, NULL);
    return rv;
}

/**
   @ingroup amxc_aqueue
   @brief
   Calculates the number of items in the queue.

   @param aqueue a pointer to the array queue structure

   @return
   The number of items in the array queue.
 */
AMXC_INLINE
size_t amxc_aqueue_size(const amxc_aqueue_t* const aqueue) {
    return amxc_array_size(aqueue);
}

/**
   @ingroup amxc_aqueue
   @brief
   Checks that the array queue is empty.

   @param aqueue a pointer to the array queue structure

   @return
   returns true when the array queue contains no items, false when there is at
   least one item in the queue.
 */
AMXC_INLINE
size_t amxc_aqueue_is_empty(const amxc_aqueue_t* const aqueue) {
    return amxc_array_is_empty(aqueue);
}

#ifdef __cplusplus
}
#endif

#endif // __AMXC_AQUEUE_H__
