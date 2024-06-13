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

#if !defined(__AMXC_UTILS_H__)
#define __AMXC_UTILS_H__

#ifdef __cplusplus
extern "C"
{
#endif

/**
   @ingroup amxc_string
   @defgroup amxc_string_utils string utility functions

   A list of utility functions and macro's that make common string manipulation easier.
 */

/**
   @ingroup amxc_string_utils
   @brief
   Resolves escaped characters in a string.

   Some characters or combinations of characters in a string can have a special
   purpose i.e. "$(my_env_var)". To avoid that these are replaced by functions like
   @ref amxc_string_resolve_env or @ref amxc_string_resolve_var, the characters can
   be escaped with a \ i.e. "\$\(my_env_var\)". This function can be used to
   remove the escape character from the string.

   Only these characters are taken into consideration when removing the escape character:
   $, (, ), {, }, ", ', \.

   @param string an amxc_string_t pointer.

   @return
   the number of replacements that have been done.
 */
int amxc_string_resolve_esc(amxc_string_t* const string);

/**
   @ingroup amxc_string_utils
   @brief
   Add escape characters to a string.

   Some characters or combinations of characters in a string can have a special
   purpose i.e. "$(my_env_var)". To avoid that these are replaced by functions like
   @ref amxc_string_resolve_env or @ref amxc_string_resolve_var, the characters can
   be escaped with a \ i.e. "\$\(my_env_var\)". This function can be used to
   add the escape character.

   Only these characters are taken into consideration when removing the escape character:
   $, (, ), {, }, ", ', \.

   @param string an amxc_string_t pointer.

   @return
   the number of replacements that have been done.
 */
int amxc_string_esc(amxc_string_t* const string);

/**
   @ingroup amxc_string_utils
   @brief
   Resolves environment variables

   Replaces the environment variable with its value. The name of the environment
   variable must be put between $( and ). This function will get the value
   of the environment variable and replaces the $(&lt;NAME&gt;) with the value.

   If the environment variable does not exist, it will be replaced with an empty
   string. If no environment variables are available in the string, the string is
   not changed.

   @param string an amxc_string_t pointer.

   @return
   the number of replacements that have been done.
 */
int amxc_string_resolve_env(amxc_string_t* const string);

/**
   @ingroup amxc_string_utils
   @brief
   Resolves variant path variables

   Replaces the variant path with its value. The variant path must be put
   between ${ and }. This function will get the value of that path
   and replaces the ${&lt;PATH&gt;} with the value.

   If the path does not exist, it will be replaced with an empty string.
   If no variant paths are available in the string, the string is not
   changed.

   @param string an amxc_string_t pointer.
   @param data a variant containing data, preferable a htable or list.

   @return
   the number of replacements that have been done.
 */
int amxc_string_resolve_var(amxc_string_t* const string,
                            const amxc_var_t* const data);

/**
   @ingroup amxc_string_utils
   @brief
   Resolves variant paths and environment variables

   This functions calls @ref amxc_string_resolve_var and @ref amxc_string_resolve_env
   to resolve all environment variables and variant paths mentioned in the string.

   The escape character '\' will be removed using @ref amxc_string_resolve_esc
   when in front of $, (, ), {, }, ", ', \.

   @param string an amxc_string_t pointer.
   @param data a variant containing data, preferable a htable or list.

   @return
   the number of replacements that have been done.
 */
int amxc_string_resolve(amxc_string_t* const string,
                        const amxc_var_t* const data);


/**
   @ingroup amxc_string_utils
   @brief
   Sets the resolved string

   This function will always clear the content of the provided amxc_string_t
   structure (resets it to an empty string).

   If the provided text contains environment variable references or variant
   path references, the resolved text is put in the string, it will also remove
   the escape character '\' when in front of $, (, ), {, }, ", ', \.

   @param string an amxc_string_t pointer.
   @param text the text
   @param data a variant containing data, preferable a htable or list.

   @return
   the number of replacements that have been done.
 */
int amxc_string_set_resolved(amxc_string_t* string,
                             const char* text,
                             const amxc_var_t* const data);

/**
   @ingroup amxc_string_utils
   @brief
   Sets the resolved string

   This function will allocate a new amxc_string_t structure on the heap.

   If the provided text contains environment variable references or variant
   path references, the resolved text is put in the string. it will also remove
   the escape character '\' when in front of $, (, ), {, }, ", ', \.

   @param string an amxc_string_t pointer.
   @param text the text
   @param data a variant containing data, preferable a htable or list.

   @return
   the number of replacements that have been done.
 */
int amxc_string_new_resolved(amxc_string_t** string,
                             const char* text,
                             const amxc_var_t* const data);

/**
   @ingroup amxc_string_utils
   @brief
   Adds a string (char*) to a linked list of amxc_string_t structures

   This function will allocate a new @ref amxc_string_t structure and copies
   the provide string (char*) into the @ref amxc_string_t structure.

   The new allocated structure is appended to the provided linked list using
   @ref amxc_llist_append

   @param llist a pointer to a linked list iterator
   @param text the string

   @return
   The linked list iterator of the new allocated @ref amxc_string_t when
   successful, NULL otherwise
 */
amxc_llist_it_t* amxc_llist_add_string(amxc_llist_t* const llist,
                                       const char* text);
/**
   @ingroup amxc_string_utils
   @brief
   Helper function to delete an item in a linked list.

   This function can be passed to @ref amxc_llist_delete or amxc_llist_clean if
   the linked list only contains @ref amxc_string_t structures.

   @note
   Only use this function when cleaning up a linked list containing only
   amxc_string_t structures.

   @param it a pointer to a linked list iterator
 */
void amxc_string_list_it_free(amxc_llist_it_t* it);

#ifdef __cplusplus
}
#endif

#endif // __AMXC_UTILS_H__