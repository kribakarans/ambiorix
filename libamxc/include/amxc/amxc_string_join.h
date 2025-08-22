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

#if !defined(__AMXC_STRING_JOIN_H__)
#define __AMXC_STRING_JOIN_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <amxc/amxc_variant.h>

/**
   @ingroup amxc_string
   @defgroup amxc_string_join Join composite types into a single string

   When a list of strings or a list of variants is available they can be
   joined into a single string using one of these functions
 */

/**
   @ingroup amxc_string_join
   @brief
   Joins a list of amxc_string_t values into a single string with a separator

   All amxc_string_t items in the linked list are joined into one amxc_string_t.
   A single character separator can be provided and will be put between all
   individual items.

   @note
   The characters [ and ] can not be used as a separator.
   When a space character is used (tab, new line, ...) as a separator it is replaced
   with a single space ' '.

   @warning
   This function only works on a linked list where all items are of the type
   amxc_string_t.

   @param string a pointer to a amxc_string_t structure, the joined string will be
                 put in this string.
   @param list the linked list of strings
   @param separator single character separator.

   @return
   0 on success.
   -1 if an error has occurred
 */
int amxc_string_join_llist(amxc_string_t* string,
                           const amxc_llist_t* list,
                           char separator);

/**
   @ingroup amxc_string_join
   @brief
   Joins a variant containing a list of variants into a single string.

   All variants in the linked list of variants are converted to a string and
   added to the result string. A separator string can be provided and
   will be put between the items.

   If an item in the list is a variant containing a list, this list will be added
   as a string starting with '[' and ending with ']'. All items in that list are
   added as a string and separated with ','.

   @warning
   This function only works when the provided variant contains a list of variants.

   @param string a pointer to a amxc_string_t structure, the joined string will be
                 put in this string.
   @param var The variant containing a linked list of variants
   @param sep separator string.

   @return
   0 on success.
   -1 if an error has occurred
 */
int amxc_string_join_var(amxc_string_t* string,
                         const amxc_var_t* const var,
                         const char* sep);

/**
   @ingroup amxc_string_join
   @brief
   Joins a variant containing a list of variants into a single string until
   the end string is encountered .

   All variants in the linked list of variants are converted to a string and
   added to the result string. A separator string can be provided and
   will be put between the items.

   If an item in the list is a variant containing a list, this list will be added
   as a string starting with '[' and ending with ']'. All items in that list are
   added as a string and separated with ','.

   When a variant in the list is encountered that after converting to a string
   matches the end string, joining is stopped. The end string itself is not
   added to the result string.

   When remove is set to true, all variants used will be removed from the list
   of variants.

   @warning
   This function only works when the provided variant contains a list of variants.

   @param string a pointer to a amxc_string_t structure, the joined string will be
                 put in this string.
   @param var The variant containing a linked list of variants
   @param sep separator string or NULL
   @param end end string or NULL
   @param remove when set to true, all used variants are removed from the list.

   @return
   0 on success.
   -1 if an error has occurred
 */
int amxc_string_join_var_until(amxc_string_t* string,
                               const amxc_var_t* const var,
                               const char* sep,
                               const char* end,
                               bool remove);

/**
   @ingroup amxc_string_join
   @brief
   Joins a variant containing a list of variants into a single string using ',' as separator

   This function does the same as @ref amxc_string_join_var and uses ',' as
   the value separator.

   @param string a pointer to a amxc_string_t structure, the joined string will be
                 put in this string.
   @param var The variant containing a linked list of variants

   @return
   0 on success.
   -1 if an error has occurred
 */
int amxc_string_csv_join_var(amxc_string_t* string,
                             const amxc_var_t* const var);

/**
   @ingroup amxc_string_join
   @brief
   Joins a variant containing a list of variants into a single string using ' ' as separator

   This function does the same as @ref amxc_string_join_var and uses '' as
   the value separator.

   @param string a pointer to a amxc_string_t structure, the joined string will be
                 put in this string.
   @param var The variant containing a linked list of variants

   @return
   0 on success.
   -1 if an error has occurred
 */
int amxc_string_ssv_join_var(amxc_string_t* string,
                             const amxc_var_t* const var);
#ifdef __cplusplus
}
#endif

#endif // __AMXC_STRING_JOIN_H__
