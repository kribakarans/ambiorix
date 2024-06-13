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

#if !defined(__AMXC_HTABLE_H__)
#define __AMXC_HTABLE_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <amxc/amxc_common.h>
#include <amxc/amxc_array.h>

/**
   @file
   @brief
   Ambiorix hash table API header file
 */

/**
   @ingroup amxc_containers
   @defgroup amxc_htable Hash Table
 */

/**
   @ingroup amxc_htable
   @defgroup amxc_htable_it Hash Table Iterator
 */

/**
   @ingroup amxc_htable_it
   @brief
   Gets the data pointer from an hash table iterator
 */
#define amxc_htable_it_get_data(it, type, member) \
    ((type*) (((char*) it) - offsetof(type, member)))

/**
   @ingroup amxc_htable
   @brief
   Loops over items in the hash table

   Iterates over the hash table and updates the iterator each time.

   @warning
   Do not modify the hash table itself while using this macro.
   It is possible to nest this macro
   It is allowed to delete or remove the current iterator from the hash table.
 */
#define amxc_htable_for_each(it, htable) \
    for(amxc_htable_it_t* it = amxc_htable_get_first(htable), \
        * it ## _next = amxc_htable_it_get_next(it); \
        it; \
        it = it ## _next, \
        it ## _next = amxc_htable_it_get_next(it))

/**
   @ingroup amxc_htable
   @brief
   Loops over items in the hash table

   Iterates over the hash table and updates the iterator each time.

   @warning
   Do not modify the hash table itself while using this macro.
 */
#define amxc_htable_iterate(it, htable) \
    for(amxc_htable_it_t* it = amxc_htable_get_first(htable); \
        it; \
        it = amxc_htable_it_get_next(it))

/**
   @ingroup amxc_htable
   @brief
   Out of range indicator
 */
#define AMXC_HTABLE_RANGE UINT32_MAX

typedef struct _amxc_htable_it amxc_htable_it_t;

/**
   @ingroup amxc_htable_it
   @brief
   The hash table iterator structure.
 */
struct _amxc_htable_it {
    amxc_array_it_t* ait;           /**< Pointer to position in the array */
    char* key;                      /**< The key */
    amxc_htable_it_t* next;         /**< The next one if chained */
};

/**
   @ingroup amxc_htable
   @brief
   Definition of the hash function.

   The hash function calculates a hash from the key.
   A custom hash function can be implemented and set on the hash table using
   @ref amxc_htable_set_hash_func.

   A set of hash functions is already available in see @ref amxc_hash.h.

   The calculated hash is used to calculate the index of the position of the key
   in the array.
 */
typedef unsigned int (* amxc_htable_hash_func_t) (const char* key, const unsigned int len);

/**
   @ingroup amxc_htable
   @brief
   Definition of the hash table item delete function.

   A pointer to a delete function is used in the following functions
   @ref amxc_htable_delete, @ref amxc_htable_clean, @ref amxc_htable_it_clean.
 */
typedef void (* amxc_htable_it_delete_t) (const char* key, amxc_htable_it_t* it);

/**
   @ingroup amxc_htable
   @brief
   The hash table structure.
 */
typedef struct _amxc_htable {
    amxc_array_t table;             /**< The hash table */
    size_t items;                   /**< Number of items in the hash tables */
    amxc_htable_hash_func_t hfunc;  /**< The hash function */
    amxc_htable_it_delete_t it_del; /**< The iterator delete function */
} amxc_htable_t;

/**
   @ingroup amxc_htable
   @brief
   Allocates a hash table.

   Allocates and initializes memory to store a hash table.
   This function allocates memory from the heap,
   if a hash table is on the stack, it can be initialized using
   function @ref amxc_htable_init

   @note
   The allocated memory must be freed when not used anymore,
   use @ref amxc_htable_delete to free the memory

   @param htable a pointer to the location where the pointer to the new hash
                 table can be stored
   @param reserve Number of items that needs to be reserved

   @return
   -1 if an error occurred. 0 on success
 */
int amxc_htable_new(amxc_htable_t** htable, const size_t reserve);

/**
   @ingroup amxc_htable
   @brief
   Frees the previously allocated hash table

   Removes all items from the hash table, if a delete function is provided,
   it is called for each item after it was removed from the hash table.

   Frees the allocated memory and sets the pointer to NULL.

   @note
   Only call this function for hash tables that are allocated on the heap
   using @ref amxc_htable_new

   @param htable a pointer to the location where the pointer to the hash table
                is be stored
   @param func pointer to a function that is called to free each item in the
               hash table
 */
void amxc_htable_delete(amxc_htable_t** htable, amxc_htable_it_delete_t func);

/**
   @ingroup amxc_htable
   @brief
   Initializes a hash table.

   Initializes the hash table structure. All pointers are reset to NULL.
   This function is typically called for hash tables that are on the stack.
   Allocating and initializing a hash table on the heap can be done
   using @ref amxc_htable_new

   @note
   When calling this function on an already initialized hash table,
   that contains items, the hash table is reset and all items in the table are
   lost (Could potentially lead to memory leaks).
   Use @ref amxc_htable_clean to remove all items from the table.

   @param htable a pointer to the hash table structure.
   @param reserve Number of items that needs to be reserved

   @return
   0 on success.
   -1 if a NULL pointer is given.
 */
int amxc_htable_init(amxc_htable_t* const htable, const size_t reserve);

/**
   @ingroup amxc_htable
   @brief
   Removes all items from the hash table

   Removes all items from the hash table, if a delete function is provided,
   it is called for each item after it was removed from the table.
   The buffer used to store the items is freed as well.

   @param htable a pointer to the htable structure
   @param func pointer to a function that is called to free each item in
               the hash table
 */
void amxc_htable_clean(amxc_htable_t* const htable, amxc_htable_it_delete_t func);

/**
   @ingroup amxc_htable
   @brief
   Sets the hash function for the hash table

   A custom implementation for hash calculation function can be set on the
   hash table. By default the @ref amxc_BKDR_hash function is set to calculate
   the hashes. Other hash functions are available, see @ref amxc_hash

   @param htable a pointer to the htable structure
   @param func pointer to a function that is called for each hash that needs
               be calculated
 */
void amxc_htable_set_hash_func(amxc_htable_t* const htable, amxc_htable_hash_func_t func);

/**
   @ingroup amxc_htable
   @brief
   Converts a key into an index

   This function converts a key into an index using the hash function and the
   reserved size of the table

   @param htable a pointer to the htable structure
   @param key the key for which an index must be calculated

   @return
   The calculated index or @ref AMXC_HTABLE_RANGE if no reserved items are
   available in the table
 */
unsigned int amxc_htable_key2index(const amxc_htable_t* const htable,
                                   const char* const key);

/**
   @ingroup amxc_htable
   @brief
   Checks that the hash table is empty

   @param htable a pointer to the hash table structure

   @return
   returns true when the hash table contains no items,
   false when there is at least one item in the table.
 */
AMXC_INLINE
bool amxc_htable_is_empty(const amxc_htable_t* const htable) {
    return htable != NULL ? (htable->items == 0) : true;
}

/**
   @ingroup amxc_htable
   @brief
   Calculates the size of the hash table

   The size of the hash table is expressed in items.

   @note
   Use @ref amxc_htable_is_empty to check if a hash table is empty,
   do not use this function to check if the hash table is empty.
   This function will iterate over all pre-allocated buckets, and could have
   a performance impact for large hash tables.

   @param htable a pointer to the hash table structure

   @return
   returns the number of items in hash table
 */
AMXC_INLINE
size_t amxc_htable_size(const amxc_htable_t* const htable) {
    return htable != NULL ? htable->items : 0;
}

/**
   @ingroup amxc_htable
   @brief
   Calculates the capacity of the hash table

   The capacity is the number of items that is reserved

   @param htable a pointer to the hash table structure

   @return
   returns the number of reserved item positions in hash table
 */
AMXC_INLINE
size_t amxc_htable_capacity(const amxc_htable_t* const htable) {
    return htable != NULL ? htable->table.items : 0;
}

/**
   @ingroup amxc_htable
   @brief
   Inserts an item in the hash table.

   The key provided is converted into an index using @ref amxc_htable_key2index.
   When an position is already taken the items on that position are chained.
   The same key can be used for different items.
   When the number of items in the hash table is above 75% of the capacity,
   the table grows. The number of items that are reserved will be doubled
   with a maximum of 1024 items each time.

   @param htable a pointer to the hash table structure
   @param key the item key
   @param it the item htable iterator

   @return
   0 when the item is inserted, -1 when an error occured
 */
int amxc_htable_insert(amxc_htable_t* const htable,
                       const char* const key,
                       amxc_htable_it_t* const it);

/**
   @ingroup amxc_htable
   @brief
   Gets a hash table iterator from the hash table.

   The key provided is converted into an index using @ref amxc_htable_key2index.
   If multiple items are available at the calculated position with the same key,
   the first one is returned.
   The next item can be retrieved with @ref amxc_htable_it_get_next or
   with @ref amxc_htable_it_get_next_key if it must have the same key.

   @note
   The item is not removed from the hash table.
   To remove the item use @ref amxc_htable_take

   @param htable a pointer to the hash table structure
   @param key the item key

   @return
   Pointer to the hash table iterator or NULL if no iterator was stored with
   the given key. The pointer can be converted to the real data pointer
   using @ref amxc_htable_it_get_data
 */
amxc_htable_it_t* amxc_htable_get(const amxc_htable_t* const htable,
                                  const char* const key);

/**
   @ingroup amxc_htable
   @brief
   Removes a hash table iterator from the hash table.

   The key provided is converted into an index using @ref amxc_htable_key2index.
   If multiple items are available at the calculated position with the same key,
   (collision) the first one is removed and returned.

   @note
   The item is removed from the hash table.
   To fetch the next item in the hash table with the same key, call this
   function again.

   @note
   Use @ref amxc_htable_it_clean to clean up the iterator.

   @param htable a pointer to the hash table structure
   @param key the item key

   @return
   Pointer to the hash table iterator or NULL if no iterator was stored with
   the given key. The pointer can be converted to the real data pointer
   using @ref amxc_htable_it_get_data
 */
amxc_htable_it_t* amxc_htable_take(amxc_htable_t* const htable, const char* const key);

/**
   @ingroup amxc_htable
   @brief
   Gets the first item stored in the table.

   This function iterates the table from the beginning and returns the first
   item encounter.

   @note
   The order of the items in the table is not the same as the order they were
   inserted in the table. So the first item found can be different then the
   first item inserted.

   @param htable a pointer to the hash table structure

   @return
   Pointer to the hash table iterator
   or NULL if no items were stored in the hash table.
 */
amxc_htable_it_t* amxc_htable_get_first(const amxc_htable_t* const htable);

/**
   @ingroup amxc_htable
   @brief
   Gets the last item stored in the table.

   This function iterates the table from the end and returns the last
   item encounter.

   @note
   The order of the items in the table is not the same as the order they were
   inserted in the table. So the last item found can be different then the
   last item inserted.

   @param htable a pointer to the hash table structure

   @return
   Pointer to the hash table iterator
   or NULL if no items were stored in the hash table.
 */
amxc_htable_it_t* amxc_htable_get_last(const amxc_htable_t* const htable);

/**
   @ingroup amxc_htable
   @brief
   Creates an array containing all keys of the hash table

   The array will be sorted in ascending order. If the hash table contains
   duplicate keys, the sorted array will contain duplicate keys as well.

   The array will not contain empty items and the size is matching the number
   of items in the hash table.

   The returned array should be deleted when not used anymore
   using @ref amxc_array_delete, no delete function is needed.

   @warning
   Never delete the strings in the array, as these strings are no copies of the
   keys in the hash table. The array contains pointers to the keys in the
   hash table. Deleting them will render the hash table unusable and could lead
   to undefined behavior.

   @param htable a pointer to the hash table structure

   @return
   A pointer to an amxc_array_t or NULL when the hash table is empty.
 */
amxc_array_t* amxc_htable_get_sorted_keys(const amxc_htable_t* const htable);

/**
   @ingroup amxc_htable
   @brief
   Verifies that a key is in the hash table

   @param htable a pointer to the hash table structure
   @param key the key

   @return
   True when the key is at least once found in the table, false otherwise.
 */
AMXC_INLINE
bool amxc_htable_contains(const amxc_htable_t* const htable, const char* const key) {
    return amxc_htable_get(htable, key) ? true : false;
}

/**
   @ingroup amxc_htable
   @brief
   Moves all items from one hash table to another hash table

   After the move the source hash table will be empty.

   If the destination hash table already contained items, the items of
   the source hash table are added to the destination.

   @note
   if moving fails, the source is not changed and the destination will be an
   ampty hash table

   @param dest a pointer to the destination hash table structure
   @param src a pointer to the source hash table structure

   @return
   0 on success any other return value indicates failure.
 */
int amxc_htable_move(amxc_htable_t* const dest, amxc_htable_t* const src);

/**
   @ingroup amxc_htable_it
   @brief
   Initializes a hash table.iterator

   Initializes the hash table iterator structure. All pointers are reset to NULL.

   @note
   When calling this function on an already initialized hash table iterator,
   the hash table iterator is reset and data can be lost.
   Use @ref amxc_htable_it_clean to remove the iterator from the table and to
   clean up the iterator.

   @param it a pointer to the hash table iterator structure.

   @return
   0 on success.
   -1 if a NULL pointer is given.
 */
int amxc_htable_it_init(amxc_htable_it_t* const it);

/**
   @ingroup amxc_htable_it
   @brief
   Removes the iterator from the htable and frees allocated memory

   If the iterator is in a hash table, it is removed from the table,
   when a delete function is provided, it is called to free up the memory.

   @note
   This function is not freeing the memory taken by the iterator,
   it uses a callback function for this.

   @param it a pointer to the hash table iterator structure
   @param func pointer to a function that is called to free the hash table item
 */
void amxc_htable_it_clean(amxc_htable_it_t* const it, amxc_htable_it_delete_t func);

/**
   @ingroup amxc_htable_it
   @brief
   Gets the next iterator in the hash table

   Searches the next hash table iterator in the hash table, using the provided
   iterator as a reference. The iterator returned can have another key as the
   reference provided. If it must have the same key, you should use
   @ref amxc_htable_it_get_next_key

   @param reference a pointer to the hash table iterator structure

   @return
   The next iterator in the hash table, starting from the reference
   or NULL if the reference was the last in the table.
 */
amxc_htable_it_t* amxc_htable_it_get_next(const amxc_htable_it_t* const reference);

/**
   @ingroup amxc_htable_it
   @brief
   Gets the previous iterator in the hash table

   Searches the previous hash table iterator in the hash table, using the provided
   iterator as a reference. The iterator returned can have another key as the
   reference provided. If it must have the same key, you should use
   @ref amxc_htable_it_get_previous_key

   @param reference a pointer to the hash table iterator structure

   @return
   The previous iterator in the hash table, starting from the reference
   or NULL if the reference was the first in the table.
 */
amxc_htable_it_t* amxc_htable_it_get_previous(const amxc_htable_it_t* const reference);

/**
   @ingroup amxc_htable_it
   @brief
   Gets the next iterator in the hash table with the same key

   Searches the next hash table iterator in the hash table, using the provided
   iterator as a reference. The iterator returned has the same key as the
   reference provided.

   @param reference a pointer to the hash table iterator structure

   @return
   The next iterator in the hash table with the same key, starting from the
   reference or NULL if the reference was the last in the table with that key.
 */
amxc_htable_it_t* amxc_htable_it_get_next_key(const amxc_htable_it_t* const reference);

/**
   @ingroup amxc_htable_it
   @brief
   Gets the previous iterator in the hash table with the same key

   Searches the previous hash table iterator in the hash table, using the provided
   iterator as a reference. The iterator returned has the same key as the
   reference provided.

   @param reference a pointer to the hash table iterator structure

   @return
   The previous iterator in the hash table with the same key, starting from the
   reference or NULL if the reference was the first in the table with that key.
 */
amxc_htable_it_t* amxc_htable_it_get_previous_key(const amxc_htable_it_t* const reference);

/**
   @ingroup amxc_htable_it
   @brief
   Removes the iterator from the hash table

   This function only removes the iterator from the hash table,
   it does not clean any memory allocated for the iterator.

   @param it a pointer to the hash table iterator structure
 */
void amxc_htable_it_take(amxc_htable_it_t* const it);

/**
   @ingroup amxc_htable_it
   @brief
   Gets the key from the iterator

   When an iterator is in a hash table, it has a key set.
   An iterator that is not in a list can have a key set.

   @param it a pointer to the hash table iterator structure

   @return
   the key of the iterator or NULL if the iterator has no key
 */
AMXC_INLINE
const char* amxc_htable_it_get_key(const amxc_htable_it_t* const it) {
    return it != NULL ? it->key : NULL;
}

/**
   @ingroup amxc_htable
   @brief
   Removes the first item stored in the table.

   This function iterates the table from the beginning and removes and returns
   the first one encounter.

   @note
   The order of the items in the table is not the same as the order they were
   inserted in the table. So the first item found can be different then the
   first item inserted.

   @param htable a pointer to the hash table structure

   @return
   Pointer to the hash table iterator
   or NULL if no items were stored in the hash table.
 */
AMXC_INLINE
amxc_htable_it_t* amxc_htable_take_first(const amxc_htable_t* const htable) {
    amxc_htable_it_t* it = amxc_htable_get_first(htable);
    amxc_htable_it_take(it);
    return it;
}

#ifdef __cplusplus
}
#endif

#endif // __AMXC_HTABLE_H__
