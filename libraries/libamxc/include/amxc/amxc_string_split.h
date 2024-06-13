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

#if !defined(__AMXC_STRING_SPLIT_H__)
#define __AMXC_STRING_SPLIT_H__

#ifdef __cplusplus
extern "C"
{
#endif

/**
   @ingroup amxc_string
   @defgroup amxc_string_split Split a string into a composite type

   Often string parsing is needed. Either parsing a string is simple, like
   splitting it on each occurrence of separator, or more complex, like taking
   into account quotes and brackets.

   Using these functions may help in parsing a string.
 */


#include <amxc/amxc_variant.h>

/**
   @ingroup amxc_string_split
   @brief
   The possible string split errors
 */
typedef enum _amxc_string_split_status {
    AMXC_STRING_SPLIT_OK,                   /**< No error, all ok */
    AMXC_ERROR_STRING_SPLIT_INVALID_INPUT,  /**< Invalid input */
    AMXC_ERROR_STRING_MISSING_DQUOTE,       /**< Missing double quote */
    AMXC_ERROR_STRING_MISSING_SQUOTE,       /**< Missing single quote */
    AMXC_ERROR_STRING_MISSING_RBRACKET,     /**< Missing round bracket */
    AMXC_ERROR_STRING_MISSING_SBRACKET,     /**< Missing square bracket */
    AMXC_ERROR_STRING_MISSING_CBRACKET,     /**< Missing curly bracket */
} amxc_string_split_status_t;

/**
   @ingroup amxc_string_split
   @brief
   Callback function definition.

   When using @ref amxc_string_split to split a string, a filter/builder
   callback function can be provided.

   The string is splitted into parts as describe in @ref amxc_string_split_word,
   where each part is added to a linked list.

   The filter/builder callback function can then combine parts or filter them
   out before adding them the variant which contains a linked list of variants.

   @param all linked list containing all string parts
   @param var var the result variant.

   @return
   One of the @ref amxc_string_split_status_t status ids.
 */
typedef amxc_string_split_status_t (* amxc_string_split_builder_t) (amxc_llist_t* all,
                                                                    amxc_var_t* var);

/**
   @ingroup amxc_string_split
   @brief
   Helper function to be used with amxc_string_split_llist.

   It gets the reference to amxc_string_t object from
   an amxc_llist_t, it's not a copy.

   The element is free'd when the list is deleted.

   Taking a copy is the programmer's responsibility!

   @param llist a pointer to the linked list structure
   @param index the position in the list

   @return
   A pointer to the string (amxc_string_t) at the index of the llist, when successful.
   NULL when failed to to index the llist
 */
amxc_string_t* amxc_string_get_from_llist(const amxc_llist_t* const llist,
                                          const unsigned int index);

/**
   @ingroup amxc_string_split
   @brief
   Helper function to be used with amxc_string_split_llist.

   It gets the reference to the amxc_string_t object from
   an amxc_llist_t, it's not a copy.

   The element is free'd when the list is deleted.

   Taking a copy is the programmer's responsibility!

   @param llist a pointer to the linked list structure
   @param index the position in the list

   @return
   Pointer to the string buffer at the index of the llist, when successful.
   NULL when failed to point to index the llist.
 */
const char* amxc_string_get_text_from_llist(const amxc_llist_t* const llist,
                                            const unsigned int index);

/**
   @ingroup amxc_string_split
   @brief
   Split a string in individual words or punctuation signs.

   This function splits a string in individual words or punctuation signs and
   puts each individual part in a list. Each part in the list will be a
   @ref amxc_string_t

   A sequence of characters the only consists out of alfa numeric symbols
   [0-9a-zA-Z] is considered as one single word.

   When multiple space characters are encountered after each other only one
   single space is added to the list.

   All space characters are always converted to ' '. So when a tab or new-line
   character is encountered it will be added to the list as a single ' '.

   Brackets and quotes are taken into account, parsing fails when there are
   missing quotes or brackets.

   @param string The string that needs to be splitted
   @param list the linked list that gets filled
   @param reason when provided and parsing fails,
                 will get filled with a human readable error string

   @return
   one of the @ref amxc_string_split_status_t statuses
 */
amxc_string_split_status_t
amxc_string_split_word(const amxc_string_t* const string,
                       amxc_llist_t* list,
                       const char** reason);

/**
   @ingroup amxc_string_split
   @brief
   Split a string in individual words or punctuation signs.

   This functions behaves exactly the same as @ref amxc_string_split_word, with
   following differences:
   - instead of building a linked list of strings it builds a variant containing
     a linked list of variants where each item is a variant containing a string.
   - Provides the possibility to provide a callback function that can filter out
     or modify the items that are put in the list. See @ref amxc_string_split_builder_t

   @param string The string that needs to be splitted
   @param var the top level variant, will be initiated to a variant containing a
              linked list of variants.
   @param fn a filter/build callback function or NULL
   @param reason when provided and parsing fails,
                 will get filled with a human readable error string

   @return
   one of the @ref amxc_string_split_status_t statuses
 */
amxc_string_split_status_t
amxc_string_split(const amxc_string_t* const string,
                  amxc_var_t* var,
                  amxc_string_split_builder_t fn,
                  const char** reason);

/**
   @ingroup amxc_string_split
   @brief
   Split a string in individual parts assuming that the string contains comma separated values.

   Calls @ref amxc_string_split.

   This function takes into account square brackets (for lists in lists),
   double and single quotes. When a ',' is between double or single quotes
   it is considered as part of the string and not as a separator.

   The provided variant will be initialized to a variant containing a linked list
   of variants where each item in the list is a variant containing a string.

   @param string The string that needs to be splitted
   @param var the top level variant, will be initiated to a variant containing a
              linked list of variants.
   @param reason when provided and parsing fails,
                 will get filled with a human readable error string

   @return
   one of the @ref amxc_string_split_status_t statuses
 */
amxc_string_split_status_t
amxc_string_csv_to_var(const amxc_string_t* const string,
                       amxc_var_t* var,
                       const char** reason);

/**
   @ingroup amxc_string_split
   @brief
   Split a string in individual parts assuming that the string contains space separated values.

   Calls @ref amxc_string_split.

   This function takes into account square brackets (for lists in lists),
   double and single quotes. When a ' ' is between double or single quotes
   it is considered as part of the string and not as a separator.

   The provided variant will be initialized to a variant containing a linked list
   of variants where each item in the list is a variant containing a string.

   @param string The string that needs to be splitted
   @param var the top level variant, will be initiated to a variant containing a
              linked list of variants.
   @param reason when provided and parsing fails,
                 will get filled with a human readable error string

   @return
   one of the @ref amxc_string_split_status_t statuses
 */
amxc_string_split_status_t
amxc_string_ssv_to_var(const amxc_string_t* const string,
                       amxc_var_t* var,
                       const char** reason);

/**
   @ingroup amxc_string_split
   @brief
   Simple split function using a single character separator.

   Splits a string into parts using a single character separator. A separator
   must be a punctuation sign except '[' or ']'. Alphanumeric characters are
   not allowed as a separator.

   @param string The string that needs to be splitted
   @param list the result list
   @param separator the single character separator sign

   @return
   one of the @ref amxc_string_split_status_t statuses
 */
amxc_string_split_status_t
amxc_string_split_to_llist(const amxc_string_t* const string,
                           amxc_llist_t* list,
                           const char separator);


#ifdef __cplusplus
}
#endif

#endif // __AMXC_STRING_SPLIT_H__
