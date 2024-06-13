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

#if !defined(__AMXC_SET_H__)
#define __AMXC_SET_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <amxc/amxc_common.h>
#include <amxc/amxc_llist.h>

typedef struct _set amxc_set_t;

/**
   @file
   @brief
   Ambiorix set API header file
 */

/**
   @ingroup amxc_containers
   @defgroup amxc_set Set

   @brief
   The Ambiorix set is an abstract data type that can store unique values.

   A set is an abstract data type that can store unique values, without any
   particular order. It is a computer implementation of the mathematical
   concept of a finite set. Unlike most other collection types, rather than
   retrieving a specific element from a set, one typically tests a value for
   membership in a set.

 */

/**
   @brief
   Flag set alert handler type.

   @details
   If a set alert handler is installed on a set, this handler is called every time
   a flag is set or cleared from the set.

   @param set The set that is modified.
   @param flag The flag that is set/cleared.
   @param value True if the flag was set, false if it was cleared.
   @param priv private data void pointer provided to flagset_alert().

   @remarks
   The handler is called right AFTER the flag is set or cleared.

   @see amxc_set_alert()
 */
typedef void (* amxc_set_alert_t)(amxc_set_t* set,
                                  const char* flag,
                                  bool value,
                                  void* priv);
/**
   @ingroup amxc_set
   @brief
   The flag structure.

   Flags can be added to a set.
 */
typedef struct _flag {
    amxc_llist_it_t it;  /**< Linked list iterator used to store the flag in the linked list */
    char* flag;          /**< The flag value, this can be any arbitrary string */
    uint32_t count;      /**< Only used for counted sets */
} amxc_flag_t;

/**
   @ingroup amxc_set
   @brief
   The set structure.
 */
struct _set {
    amxc_llist_t list;              /**< The linked list containing all set flags */
    amxc_set_alert_t alert_handler; /**< Callback function, is called when a flag is
                                         added or removed from the set */
    void* priv;                     /**< Private data, can be any arbitrary pointer */
    bool counted;                   /**< Indicates if it is a counted set */
    int count;                      /**< Number of flags in the set, or in case of a
                                         counted set, the sum of all flag counts */
};

/**
   @ingroup amxc_set
   @brief
   Allocates a set.

   Allocates and initializes memory to store a set.
   This function allocates memory from the heap,
   if a set is on the stack, it can be initialized using
   function @ref amxc_set_init

   @note
   The allocated memory must be freed when not used anymore,
   use @ref amxc_set_delete to free the memory

   @param set a pointer to the location where the pointer to the new set can be stored
   @param counted If set to true, the created set will keep a counter for each flag.
                 Each time a specific flag is set, the counter is incremented and
                 when the flag is cleared, the counter is decremented. Only when the
                 counter reaches zero, the flag is really removed from the flag set.
                 If set to false, the flag set will have default behaviour,
                 i.e. when clearing a flag, it is removed immediately
                 no matter how many times it has been set.

   @return
   -1 if an error occured. 0 on success
 */
int amxc_set_new(amxc_set_t** set, bool counted);

/**
   @ingroup amxc_set
   @brief
   Frees a set.

   Releases any allocated memory for the flag set.

   @param set The set to destroy. When this function returns, the pointer is set to NULL.
 */
void amxc_set_delete(amxc_set_t** set);

/**
   @ingroup amxc_set
   @brief
   Initializes a set.

   Initializes a set that is declared on the stack.
   When the set is not needed anymore use @ref amxc_set_clean to clean it up.

   @param set a pointer to an amxc_set_t structure
   @param counted If set to true, the initialized set will keep a counter for each flag.
                 Each time a specific flag is set, the counter is incremented and
                 when the flag is cleared, the counter is decremented. Only when the
                 counter reaches zero, the flag is really removed from the flag set.
                 If set to false, the flag set will have default behaviour,
                 i.e. when clearing a flag, it is removed immediately
                 no matter how many times it has been set.

   @return
   -1 if an error occured. 0 on success
 */
int amxc_set_init(amxc_set_t* const set, bool counted);

/**
   @ingroup amxc_set
   @brief
   Cleans a set.

   clean-up a set, which was previously initialized with @ref amxc_set_init.

   @param set a pointer to an amxc_set_t structure
 */
void amxc_set_clean(amxc_set_t* const set);

/**
   @ingroup amxc_set
   @brief
   Copies a set.

   Allocates a new set and copies the flags of the given set into this new set.
   The set alert handler and private data are not copied.

   @note
   The allocated memory must be freed when not used anymore,
   use @ref amxc_set_delete to free the memory.

   @param set a pointer to an amxc_set_t structure
   @return A pointer to the newly allocated amxc_set_t structure if the copy succeeded, NULL otherwise.
 */
amxc_set_t* amxc_set_copy(const amxc_set_t* const set);

/**
   @ingroup amxc_set
   @brief
   Reset or empty a set, i.e. clear all flags.

   @param set The set to reset.
 */
void amxc_set_reset(amxc_set_t* set);

/**
   @ingroup amxc_set
   @brief
   Parses a space-separated string of flags and adds them to the set.

   This function will iterate over the given string, uses space characters
   as delimiter (uses function isspace). Multiple consecutive spaces are
   considered as one single space.

   When the set is a counted set, a flag can be followed by a : sign and a
   number, that number is used as the initial count value. If the set is not
   a counted set, the number is ignored.

   The : sign can not be used in flag names.

   @param set The flag set to store the parsed flags into.
   @param str The string that holds the space separated string of flags.

   @return
   0 if the string was parsed successfully, any other value otherwise.
 */
int amxc_set_parse(amxc_set_t* set, const char* str);

/**
   @ingroup amxc_set
   @brief
   Converts a set to a space-separated string of flags.

   @param set The flag set to convert.

   @return
   A string holding the space-separated string of flags.
   It's allocated on the heap and needs to be freed by the caller with free().
   A NULL pointer is returned if the set is NULL, empty or if memory allocation failed.
 */
char* amxc_set_to_string(const amxc_set_t* const set);

/**
   @ingroup amxc_set
   @brief
   Converts a set to a separated string of flags.

   @param set The flag set to convert.
   @param sep The separation string.

   @return
   A string holding the separated string of flags.
   It's allocated on the heap and needs to be freed by the caller with free().
   A NULL pointer is returned if the set is NULL, empty or if memory allocation failed.
 */
char* amxc_set_to_string_sep(const amxc_set_t* const set, const char* sep);

/**
   @ingroup amxc_set
   @brief
   Adds a flag to a set, or increases the flag counter.

   Adds a flag to a set if it does not contain it already.
   If the set already contains the flag, increase its counter if the flag set
   is a counted set or do nothing at all for normal flag sets.

   @param set The flag set on which a flag needs to be added.
   @param flag The flag to add.
 */
void amxc_set_add_flag(amxc_set_t* set, const char* flag);

/**
   @ingroup amxc_set
   @brief
   Removes a flag from a set or decreases the flag counter

   If the flag set contains the flag, decrease its counter if it is a counted set.
   If it is a normal flag set, or the flag's counter reaches zero, removes the flag
   from the set. If the set does not contain the flag, doesn't do anything at all.

   @param set The set on which a flag needs to be removed.
   @param flag The flag to clear.
 */
void amxc_set_remove_flag(amxc_set_t* set, const char* flag);

/**
   @ingroup amxc_set
   @brief
   Check if a set contains a flag.

   @param set The set on which the flag needs to be checked.
              NULL is considered to be the empty flag set.
   @param flag The flag to check.

   @return
   True if and only if the flag is set.
 */
bool amxc_set_has_flag(const amxc_set_t* const set, const char* flag);

/**
   @ingroup amxc_set
   @brief
   Get a flag counter.

   Get the counter of a specific flag if flag is non-NULL or the global flag
   set counter if flag is NULL. The global counter is the sum of all flag counters.
   For counted sets, the counter of a flag is the number of times the flag was set.
   For normal flag sets, the counter equals 1 if the flag is set.

   @param set The set for which a counter needs to be returned.
              NULL is considered to be the empty flag set.
   @param flag The flag to count. If it equals NULL, the global flag set counter is returned.

   @return
   A flag counter or the flag set's global counter.
 */
uint32_t amxc_set_get_count(const amxc_set_t* const set, const char* flag);

/**
   @ingroup amxc_set
   @brief
   Joins two sets.

   All flags that are set in the set referenced by operand, but are not in the flag
   set referenced by set, are added to set.
   Additionally, for counted sets, the counter of each flag of set will be incremented
   by the counter of the corresponding flag in operand.

   @param set Left hand operand of the union operator, as well as the target to store the result into.
   @param operand Right hand operand of the union operator. NULL is considered to be the empty flag set.
 */
void amxc_set_union(amxc_set_t* const set, const amxc_set_t* const operand);

/**
   @ingroup amxc_set
   @brief
   Intersect a set with another set.

   All flags that are set in the set referenced by set, but not in the set
   referenced by operand, are removed from set.
   Additionally, for counted sets, the counter of each flag of set will be
   set to the minimum of itself and the counter of the corresponding flag in operand.

   @param set Left hand operand of the intersect operator, as well as the target to store the result into.
   @param operand Right hand operand of the intersect operator. NULL is considered to be the empty set.
 */
void amxc_set_intersect(amxc_set_t* const set, const amxc_set_t* const operand);

/**
   @ingroup amxc_set
   @brief
   Subtract a set from another set.

   For normal sets, all flags that are set in both the set referenced by set and the
   set referenced by operand, are removed from set.

   For counted sets, the counter of each flag of set will be decremented by the counter
   of the corresponding flag in operand. If this results in a counter equal to or less
   than zero, the flag is removed from set.

   @param set Left hand operand of the subtract operator, as well as the target to store the result into.
   @param operand Right hand operand of the subtract operator. NULL is considered to be the empty set.
 */
void amxc_set_subtract(amxc_set_t* const set, const amxc_set_t* const operand);

/**
   @ingroup amxc_set
   @brief
   Compare two sets.

   Normal sets are considered to be equal if they contain the exact same set of flags.
   For counted sets, the flag counters have to match as well in order to be considered as equal.

   @param set1 Left hand operand of the equals operator. NULL is considered to be the empty set.
   @param set2 Right hand operand of the equals operator. NULL is considered to be the empty set.

   @return
   True if and only if set1 and set2 are equal.
 */
bool amxc_set_is_equal(const amxc_set_t* const set1,
                       const amxc_set_t* const set2);

/**
   @ingroup amxc_set
   @brief
   Install a set alert callback function.

   For normal sets, this handler is called every time a flag is added or removed
   from the set.

   For counted sets, this handler is called only whenever a flag is really added to
   or removed from the flag set, i.e. not when setting or clearing a flag only causes
   a flag counter to be incremented or decremented.

   @param set The set on which an alert handler needs to be installed.
   @param handler The callback function to be called whenever a flag is set or cleared.
   @param priv A void pointer to be passed to the callback function.
 */
void amxc_set_alert_cb(amxc_set_t* set, amxc_set_alert_t handler, void* priv);

/**
   @ingroup amxc_set
   @brief
   Calculates the symmetric difference of two sets.

   The symmetric difference of two sets is the set of elements which are in either of the sets,
   but not in both. E.g. the symmetric difference of the sets {1,2,3} and {3,4} is {1,2,4}.

   @param set Left hand operand of the operator, as well as the target to store the result into.
   @param operand Right hand operand of the operator. NULL is considered to be the empty flag set.
 */
void amxc_set_symmetric_difference(amxc_set_t* const set, const amxc_set_t* const operand);

#ifdef __cplusplus
}
#endif

#endif // __AMXC_SET_H__
