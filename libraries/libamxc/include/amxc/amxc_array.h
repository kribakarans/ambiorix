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

#if !defined(__AMXC_ARRAY_H__)
#define __AMXC_ARRAY_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#include <amxc/amxc_common.h>

/**
   @file
   @brief
   Ambiorix array API header file
 */

/**
   @ingroup amxc_containers
   @defgroup amxc_array Array

   @brief
   The Ambiorix Dynamic Bucket Array.

   A bucket is basically a pointer to a memory block (like a structure).
   This array implementation provides an array of pointers (aka buckets), the
   allocated memory for the buckets is a sequential memory block.

   A bucket is considered empty when the pointer is NULL.

   The array will grow dynamically when items are added to the end.

   The items (or buckets) are defined using @ref amxc_array_it_t structure.
   This structure contains the pointer to the data and the pointer to the
   beginning of the array.

   @par Creating A Bucket Array
   A bucket array can be declared on the stack or allocated in the heap. When
   declaring a bucket array on the stack it must be correctly initialized.

   - @ref amxc_array_init - initializes a bucket array declared on the stack
   - @ref amxc_array_new - allocates a bucket array in the heap.

   @par Adding items
   Items can be added:
   - at a specific index - @ref amxc_array_set_data_at
   - after the last used - @ref amxc_array_append_data
   - before the first used - @ref amxc_array_prepend_data

   @par Convert An Array Bucket Iterator To Data Struct
   The @ref amxc_array_it_t contains a pointer (void *) to the data. This
   pointer can be fetched using @ref amxc_array_it_get_data and cast to
   the correct type.

   @par Looping Over A Bucket Array
   Using a simple for loop it is possible to iterate over all buckets available.
   To get the full size, including the empty buckets, use
   @ref amxc_array_capacity. Using an index all buckets can be addressed using
   @ref amxc_array_get_at

   To get the number of used buckets in the array use @ref amxc_array_size.

   If you only want to loop over the used buckets (with a non NULL data pointer),
   use the functions @ref amxc_array_get_first, @ref amxc_array_it_get_next

   @par Removing Data From The Bucket Array
   Removing a pointer from a bucket is basically resetting the data pointer to
   NULL. The function @ref amxc_array_it_take_data will reset the pointer of
   the bucket to NULL and will return the pointer.

   @par Finding Empty Buckets
   It is possible to find the empty buckets:
   - @ref amxc_array_get_first_free - returns the first empty bucket
   - @ref amxc_array_get_last_free - returns the last empty bucket
   - @ref amxc_array_it_get_next_free - returns the next empty bucket starting from a bucket
   - @ref amxc_array_it_get_previous_free - returns the previous empty bucket starting from a bucket

 */

/**
   @ingroup amxc_array
   @defgroup amxc_array_it Array iterators
 */

/**
   @ingroup amxc_array
   @brief
   The array structure.

   The number of available items in the allocated buffer is tracked in the items
   member of this structure. C does not provide any standard way to get the
   size of an allocated memory block.

   The structure also contains the first_used and last_used members. These are
   mainly used to be able to add data after the last taken position or to
   add data before the first taken position.

   Alternatively the functions inserting data after or before can iterate over
   the array start from the end or from the beginning, this could have some
   significant impact on the performance of these functions.

   Although the members of this structure are publicly available it is not
   recommended to access them directly, use the provided functions.
 */
typedef struct _amxc_array {
    size_t items;                   /**< Number of items in the array */
    size_t first_used;              /**< First used index */
    size_t last_used;               /**< Highest used index */
    struct _amxc_array_it* buffer;  /**< The array buffer */
} amxc_array_t;

/**
   @ingroup amxc_array_it
   @brief
   The array iterator structure.
 */
typedef struct _amxc_array_it {
    amxc_array_t* array;            /**< Pointer to the array */
    void* data;                     /**< Pointer to the data */
} amxc_array_it_t;

/**
   @ingroup amxc_array
   @brief
   Definition of the array item delete callback function.

   A pointer to a delete function is used in the following functions:
   @ref amxc_array_delete, @ref amxc_array_clean, @ref amxc_array_shrink,
   @ref amxc_array_shift_right, @ref amxc_array_shift_left.

   When an array contains pointers to heap allocated memory blocks, that are
   possibly nowhere else referenced, this may lead to memory leaks.
   Providing a callback function to free the memory is easier and more efficient
   then first iterating over the array freeing up and then call one of the
   previously mentioned functions.
 */
typedef void (* amxc_array_it_delete_t) (amxc_array_it_t* it);

/** @ingroup amxc_array_it
    @brief
    Type definition of an array iterator compare callback function.

    When sorting an array, the items in the array (iterators) must be
    compared. When calling @ref amxc_array_sort a compare function
    must be provided using this signature.

    @param it1 the first array iterator
    @param it2 the second array iterator

    @return
    The callback function must return
    - 0 when the values are equal
    - < 0 when it1 is smaller then it2
    - > 0 when it1 is bigger then it2
 */
typedef int (* amxc_array_it_cmp_t) (amxc_array_it_t* it1,
                                     amxc_array_it_t* it2);

/**
   @ingroup amxc_array
   @brief
   Allocates an array.

   Allocates and initializes memory to store an array.
   This function allocates memory from the heap, if an array is on the stack,
   it can be initialized using the function @ref amxc_array_init

   The size of the array is not fixed and can be changed with the functions
   @ref amxc_array_grow or @ref amxc_array_shrink

   The size of the array is expressed in number of items that can be stored in
   the array. All items in the allocated array are set to NULL.

   @note
   The allocated memory must be freed when not used anymore,
   use @ref amxc_array_delete to free the memory

   @param array a pointer to the location where the pointer
                to the new array can be stored
   @param items the size of the array in number of items

   @return
   -1 if an error occurred. 0 on success
 */
int8_t amxc_array_new(amxc_array_t** array, const size_t items);

/**
   @ingroup amxc_array
   @brief
   Frees the previously allocated array.

   Removes all items from the array, if a delete function is provided,
   it is called for each used item in the array.

   Frees the allocated memory and sets the pointer to the array to NULL.

   @note
   Only call this function for arrays that are allocated on the heap using
   @ref amxc_array_new

   @param array a pointer to the location where the pointer to the array is
                stored
   @param func a pointer to a function that is called to free each item in the
               array
 */
void amxc_array_delete(amxc_array_t** array, const amxc_array_it_delete_t func);

/**
   @ingroup amxc_array
   @brief
   Initializes an array.

   Initializes the array structure.
   Memory is allocated from the heap to be able to store the number of items
   requested.
   All the items are initialized to NULL.
   This function is typically called for arrays that are on the stack.
   Allocating and initializing an array on the heap can be done using
   @ref amxc_array_new

   @note
   When calling this function on an already initialized array,
   that contains items, the array is reset and all items in the array are lost
   (This could potentially lead to memory leaks).
   Use @ref amxc_array_clean to remove all items from the list.

   @param array a pointer to the array structure.
   @param items the size of the array in number of items

   @return
   0 on success.
   -1 if a NULL pointer is given.
 */
int amxc_array_init(amxc_array_t* const array, const size_t items);

/**
   @ingroup amxc_array
   @brief
   Removes all items from the array.

   Removes all items from the array.
   If a delete function is provided, it is called for each used item in the
   array.

   @param array a pointer to the array structure
   @param func a pointer to a function that is called to free each used item in
               the array
 */
void amxc_array_clean(amxc_array_t* const array, amxc_array_it_delete_t func);

/**
   @ingroup amxc_array
   @brief
   Expands the array

   Expands the array by the given number of items.
   Extra memory is allocated to be able to store the number of items
   requested.

   @param array a pointer to the array structure
   @param items the number of items the array has to grow

   @return
   0 on success.
   -1 if an error has occured.
 */
int amxc_array_grow(amxc_array_t* const array, const size_t items);

/**
   @ingroup amxc_array
   @brief
   Shrinks the array.

   Shrinks the array by the given number of items.
   Memory is freed. If a delete function is provided it is called for each
   used item that is removed from the array.

   @param array a pointer to the array structure
   @param items the number of items the array has to shrink
   @param func pointer to a function that is called to free each used item in the array

   @return
   0 on success.
   -1 if an error has occured
 */
int amxc_array_shrink(amxc_array_t* const array,
                      const size_t items,
                      amxc_array_it_delete_t func);

/**
   @ingroup amxc_array
   @brief
   Shift all items to the right in the array.

   Moves all items in the array to the right with the given number of items.
   Items that are moved out of the array are removed from the array.
   A function can be provided that is called for each used item that is removed
   from the array.

   E.g. Shifting the array to the right by 3 items, moves the item on index 0
   to index 3, the item on index 1 to index 4, ...

   The items in the beginning of the array are reinitialized to NULL.

   @param array a pointer to the array structure
   @param items the number of items that needs to be shifted
   @param func a pointer to a function that is called to free each used item in
               the array, that is moved out of the array.

   @return
   0 on success.
   -1 if an error has occured
 */
int amxc_array_shift_right(amxc_array_t* const array,
                           const size_t items,
                           amxc_array_it_delete_t func);

/**
   @ingroup amxc_array
   @brief
   Shift all items to the left in the array.

   Moves all items in the array to the left with the given number of items.
   Items that are moved out of the array are removed from the array.
   A function can be provided that is called for each used item that is removed
   from the array.

   E.g. Shifting the array to the left by 3 items, moves the item on index 3 to
   index 0, the item on index 4 to index 1, ...

   The items at the end of the array are reinitialized to NULL.

   @param array a pointer to the array structure
   @param items the number of items that needs to be shifted
   @param func a pointer to a function that is called to free each used item in
               the array, that is moved out of the array.

   @return
   0 on success.
   -1 if an error has occured
 */
int amxc_array_shift_left(amxc_array_t* const array,
                          const size_t items,
                          amxc_array_it_delete_t func);

/**
   @ingroup amxc_array
   @brief
   Checks that the array is empty.

   An array is empty if none of the items are used.

   @param array a pointer to the array structure

   @return
   returns true when the array contains no items that are used,
   false when there is at least one item used in the array.
 */
bool amxc_array_is_empty(const amxc_array_t* const array);

/**
   @ingroup amxc_array
   @brief
   Calculates the number of used items in the array

   Loops over all items in the array and counts the used items.
   The size of the array is expressed in used items.

   @note
   Use @ref amxc_array_is_empty to check if an array is empty, do not use this
   function to check if there are used items in the array.
   This function is looping over the complete array and counts the used items.
   For large arrays this could have some noticeable performance impact.

   @param array a pointer to the array structure

   @return
   returns the number of used items in the array
 */
size_t amxc_array_size(const amxc_array_t* const array);

/**
   @ingroup amxc_array
   @brief
   Adds an item after the last used item in the array

   The array grows if the item can not be added to the array.

   @note
   This function sets the pointer in the array.
   It is important that the pointer is valid as long as it is used in
   the array. Before freeing the memory block, remove the pointer from the array.

   @param array a pointer to the array structure
   @param data a pointer to the data that is added to the array

   @return
   returns the array iterator where the data is added,
   or NULL when adding the item fails.
 */
amxc_array_it_t* amxc_array_append_data(amxc_array_t* const array, void* data);

/**
   @ingroup amxc_array
   @brief
   Adds an item before the first used item in the array.

   The array grows if the item can not be added to the array.

   @note
   This function sets the pointer in the array.
   It is important that the pointer is valid as long as it is used in
   the array. Before freeing the memory block, remove the pointer from the array.

   @param array a pointer to the array structure
   @param data a pointer to the data that is added to the array

   @return
   returns the array iterator where the data is added,
   or NULL when adding the item fails.
 */
amxc_array_it_t* amxc_array_prepend_data(amxc_array_t* const array, void* data);

/**
   @ingroup amxc_array
   @brief
   Gets the item iterator for the given index.

   @param array a pointer to the array structure
   @param index the position in the array for which the iterator has to be returned

   @return
   returns the array iterator for the given index
   or NULL if the index is out of boundary.
 */
amxc_array_it_t* amxc_array_get_at(const amxc_array_t* const array,
                                   const unsigned int index);

/**
   @ingroup amxc_array
   @brief
   Sets data at the given index.

   @note
   This function sets the pointer in the array.
   It is important that the pointer is valid as long as it is used in
   the array. Before freeing the memory block, remove the pointer from the array.

   @param array a pointer to the array structure
   @param index position in the array where the data has to be set
   @param data pointer to the data that has to be set in the array

   @return
   returns the array iterator for the given index
   or NULL if the index is out of boundary.
 */
amxc_array_it_t* amxc_array_set_data_at(amxc_array_t* const array,
                                        const unsigned int index,
                                        void* data);

/**
   @ingroup amxc_array
   @brief
   Gets the item iterator of the first used item in the array.

   @param array a pointer to the array structure

   @return
   returns the array iterator for the first used item in the array
   or NULL if there is no used item in the array.
 */
amxc_array_it_t* amxc_array_get_first(const amxc_array_t* const array);

/**
   @ingroup amxc_array
   @brief
   Gets the first free position in the array.

   @param array a pointer to the array structure

   @return
   returns the array iterator for the first free item in the array
   or NULL if there is no free item in the array.
 */
amxc_array_it_t* amxc_array_get_first_free(const amxc_array_t* const array);

/**
   @ingroup amxc_array
   @brief
   Gets the item iterator of the last used item in the array.

   @param array a pointer to the array structure

   @return
   returns the array iterator for the last used item in the array
   or NULL if there is no used item in the array.
 */
amxc_array_it_t* amxc_array_get_last(const amxc_array_t* const array);

/**
   @ingroup amxc_array
   @brief
   Gets the last free position in the array.

   @param array a pointer to the array structure

   @return
   returns the array iterator for the last free item in the array
   or NULL if there is no free item in the array.
 */
amxc_array_it_t* amxc_array_get_last_free(const amxc_array_t* const array);

/**
   @ingroup amxc_array
   @brief
   Takes the data pointer from the first used item in the array.

   @param array a pointer to the array structure

   @return
   returns the data pointer of the first used item in the array
   or NULL if there is no used item in the array.
 */
void* amxc_array_take_first_data(amxc_array_t* const array);

/**
   @ingroup amxc_array
   @brief
   Takes the data pointer from the last used item in the array.

   @param array a pointer to the array structure

   @return
   returns the data pointer of the last used item in the array
   or NULL if there is no used item in the array.
 */
void* amxc_array_take_last_data(amxc_array_t* const array);

/**
   @ingroup amxc_array_it
   @brief
   Gets the next used item in the array,
   starting from the provided array iterator.

   This function iterates forwards over all items starting from the reference
   iterator and searches the next used item.

   @param reference array iterator used as starting point.

   @return
   returns the iterator of the next used item in the array starting from the
   reference iterator, or NULL if there are no more used items (End of array
   reached).
 */
amxc_array_it_t* amxc_array_it_get_next(const amxc_array_it_t* const reference);

/**
   @ingroup amxc_array_it
   @brief
   Gets the next free item in the array,
   starting from the provided array iterator.

   This function iterates forwards over all items starting from the reference
   iterator and searches the next free item.

   @param reference array iterator used as starting point.

   @return
   returns the iterator of the next free item in the array starting from the
   reference iterator, or NULL if there are no more free items (End of array
   reached).
 */
amxc_array_it_t* amxc_array_it_get_next_free(const amxc_array_it_t* const reference);

/**
   @ingroup amxc_array_it
   @brief
   Gets the previous used item in the array,
   starting from the provided array iterator.

   This function iterates backwards over all items starting from the reference
   iterator and searches the previous used item.

   @param reference array iterator used as starting point.

   @return
   returns the iterator of the previous used item in the array starting from the
   reference iterator, or NULL if there are no more used items (Start of array
   reached).
 */
amxc_array_it_t* amxc_array_it_get_previous(const amxc_array_it_t* const reference);

/**
   @ingroup amxc_array_it
   @brief
   Gets the previous free item in the array,
   starting from the provided array iterator.

   This function iterates backwards over all items starting from the reference
   iterator and searches the previous free item.

   @param reference array iterator used as starting point.

   @return
   returns the iterator of the previous free item in the array starting from the
   reference iterator, or NULL if there are no more free items (Start of array
   reached).
 */
amxc_array_it_t* amxc_array_it_get_previous_free(const amxc_array_it_t* const reference);

/**
   @ingroup amxc_array_it
   @brief
   Gets the index of the iterator in the array

   @param it pointer to the array iterator.

   @return
   returns the index of the iterator.
 */
unsigned int amxc_array_it_index(const amxc_array_it_t* const it);

/**
   @ingroup amxc_array
   @brief
   Gets the capacity of the array.

   The capacity of an array is the number of items that can be stored in the
   array.

   @param array pointer to the array structure

   @return
   returns the capacity of the array, expressed in number of items.
 */
AMXC_INLINE
size_t amxc_array_capacity(const amxc_array_t* const array) {
    return (array != NULL) ? array->items : 0;
}

/**
   @ingroup amxc_array
   @brief
   Gets the data pointer of the item at the given index.

   @param array pointer to the array structure
   @param index the index of the item

   @return
   returns the data pointer of the item at the given index or NULL if no data
   pointer was stored in that item or when the index is out of boundery.
 */
AMXC_INLINE
void* amxc_array_get_data_at(const amxc_array_t* const array,
                             const unsigned int index) {
    amxc_array_it_t* it = amxc_array_get_at(array, index);
    return (it != NULL) ? it->data : NULL;
}

/**
   @ingroup amxc_array_it
   @brief
   Gets the data pointer of array iterator.

   @param it pointer to the item iterator

   @return
   returns the data pointer of iterator
   or NULL if no data pointer was stored in that iterator.
 */
AMXC_INLINE
void* amxc_array_it_get_data(const amxc_array_it_t* const it) {
    return (it != NULL) ? it->data : NULL;
}

/**
   @ingroup amxc_array_it
   @brief
   Sets the data pointer of an array iterator.

   @note
   This function sets the pointer in the array.
   It is important that the pointer is valid as long as it is used in the array.
   Before freeing the memory block, remove the pointer from the array.

   @param it pointer to the item iterator
   @param data pointer to the data

   @return
   0 when the data is set, -1 otherwise.
 */
int amxc_array_it_set_data(amxc_array_it_t* const it, void* data);

/**
   @ingroup amxc_array_it
   @brief
   Gets and removes a data pointer from the iterator.

   This functions resets the data pointer of the iterator back to NULL.

   @param it pointer to the item iterator

   @return
   The data pointer of the iterator.
 */
void* amxc_array_it_take_data(amxc_array_it_t* const it);

/**
   @ingroup amxc_array_it
   @brief
   Swaps the content of the two array iterators.

   The array iterators do not have to belong to the same array.

   @param it1 pointer to the item iterator 1
   @param it2 pointer to the item iterator 2

   @return
   0 when the iterators are swapped. TODO -1 if swapping fails.
 */
int amxc_array_it_swap(amxc_array_it_t* const it1, amxc_array_it_t* const it2);

/**
   @ingroup amxc_array
   @brief
   Sorts the content of the array.

   The smallest items according to the compare functions are at the beginning of
   the array, empty buckets are at the end.

   @param array the array that will be sorted
   @param cmp array iterator content compare function

   @return
   0 when the array is sorted. TODO -1 if sorting fails?
 */
int amxc_array_sort(amxc_array_t* const array, amxc_array_it_cmp_t cmp);

#ifdef __cplusplus
}
#endif

#endif // __AMXC_ARRAY_H__
