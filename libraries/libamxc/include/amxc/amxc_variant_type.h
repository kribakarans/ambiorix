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

#if !defined(__AMXC_VARIANT_TYPE_H__)
#define __AMXC_VARIANT_TYPE_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <amxc/amxc_htable.h>
#include <amxc/amxc_variant.h>
#include <amxc/amxc_common.h>

/**
   @file
   @brief
   Ambiorix ring buffer API header file
 */

/**
   @ingroup amxc_containers
   @defgroup amxc_variant_type Variant types
 */

/**
   @ingroup amxc_variant_type
   @brief
   Variant type callback function prototype for initializing a variant of a
   certain type.

   Allocating memory to store the data is allowed, but a callback function for
   freeing the data must be provided, see @ref amxc_var_free_fn_t
 */
typedef int (* amxc_var_new_fn_t) (amxc_var_t* const var);

/**
   @ingroup amxc_variant_type
   @brief
   Variant type callback function prototype for freeing previous allocated memory.
 */
typedef void (* amxc_var_free_fn_t) (amxc_var_t* const var);

/**
   @ingroup amxc_variant_type
   @brief
   Variant type callback function prototype for creating a copy.
 */
typedef int (* amxc_var_copy_fn_t) (amxc_var_t* const dst,
                                    const amxc_var_t* const src);

/**
   @ingroup amxc_variant_type
   @brief
   Variant type callback function prototype for moving the content.
 */
typedef int (* amxc_var_move_fn_t) (amxc_var_t* const dst,
                                    amxc_var_t* const src);

/**
   @ingroup amxc_variant_type
   @brief
   Variant type callback function prototype for dynamically converting one type
   to another.
 */
typedef int (* amxc_var_convert_fn_t) (amxc_var_t* const dest,
                                       const amxc_var_t* const src);

/**
   @ingroup amxc_variant_type
   @brief
   Variant type callback function prototype comparing two variants of the same
   type.
 */
typedef int (* amxc_var_compare_fn_t) (const amxc_var_t* const var1,
                                       const amxc_var_t* const var2,
                                       int* const result);

/**
   @ingroup amxc_variant_type
   @brief
   Variant type callback function prototype fetch part of variant by key
 */
typedef amxc_var_t*(* amxc_var_get_key_fn_t) (const amxc_var_t* const src,
                                              const char* const key,
                                              int flags);

/**
   @ingroup amxc_variant_type
   @brief
   Variant type callback function prototype set part of variant by key
 */
typedef int (* amxc_var_set_key_fn_t) (amxc_var_t* const dest,
                                       amxc_var_t* const src,
                                       const char* const key,
                                       int flags);

/**
   @ingroup amxc_variant_type
   @brief
   Variant type callback function prototype fetch part of variant by index
 */
typedef amxc_var_t*(* amxc_var_get_index_fn_t) (const amxc_var_t* const src,
                                                const int64_t index,
                                                int flags);

/**
   @ingroup amxc_variant_type
   @brief
   Variant type callback function prototype set part of variant by index
 */
typedef int (* amxc_var_set_index_fn_t) (amxc_var_t* const dest,
                                         amxc_var_t* const src,
                                         const int64_t index,
                                         int flags);

/**
   @ingroup amxc_variant_type
   @brief
   Variant type callback function prototype add a value to a variant
 */
typedef int (* amxc_var_add_fn_t) (amxc_var_t* const dest,
                                   const amxc_var_t* const value);

/**
   @ingroup amxc_variant_type
   @brief
   A variant type structure.

   New or application specific variants can be defined and registered.
   All function pointers are optional.

   The member type_id and hit will be filled during registration and must never
   be changed.

   A unique name must be provided.

   The init function is called when the type of the variant is set
   see @ref amxc_var_set_type. When the initialization is ok, return 0, otherwise
   return an error code.

   The del function is called when the content of the variant must be cleared.

   The copy function is called when a copy needs to be made.
   @see ref amxc_var_copy. The function must return 0 when the copy was successful,
   an error code otherwise.

   The convert functions convert_from, convert_to are called when conversion
   from one type to another type is needed. These functions take two arguments,
   the destination variant and the source variant.
   These functions are used by @ref amxc_var_convert. If the source variant type
   has a convert_to function, it will be called. If that conversion fails or the
   source variant type does not have a convert_to function, the convert_from function
   of the destination variant type is called.
   When conversion was successful, these functions must return 0, if conversion was
   impossible (not supported) or fails for any other reason an error code must
   be returned.

   The compare function is called to compare two variants. Before calling
   the compare function, one of the variants will be converted to the same type
   as the other one. If none of the variants can be converted to the type
   of the other variant, the compare fails.
   The compare functions must set the result to a number < 0 if the left variant
   is smaller then the right variant, to a number > 0 if the left variant is
   bigger then the right variant, or to 0 if they are the same.
 */
typedef struct _amxc_var_type {
    amxc_var_new_fn_t init;              /**< Initialize function */
    amxc_var_free_fn_t del;              /**< free (delete) function */
    amxc_var_copy_fn_t copy;             /**< Copy function */
    amxc_var_move_fn_t move;             /**< Move function */
    amxc_var_convert_fn_t convert_from;  /**< Convert from function */
    amxc_var_convert_fn_t convert_to;    /**< Convert to function */
    amxc_var_compare_fn_t compare;       /**< Compare function */
    amxc_var_get_key_fn_t get_key;       /**< Fetch part of the variant by key */
    amxc_var_set_key_fn_t set_key;       /**< Set part of the variant by key */
    amxc_var_get_index_fn_t get_index;   /**< Fetch part of the variant by index */
    amxc_var_set_index_fn_t set_index;   /**< Set part of the variant by index */
    amxc_var_add_fn_t add_value;         /**< Add a value to a variant */
    uint32_t type_id;                    /**< Type id - assigned when registered */
    amxc_htable_it_t hit;                /**< Hash table iterator, used to store the type */
    const char* name;                    /**< Unique name of the type */
} amxc_var_type_t;

/**
   @ingroup amxc_variant_type
   @brief
   Register a new variant type.

   After the type has been registered the fields type_id and hit will be filled.
   These values should not be changed.

   The type can be used after registration.

   Typically the registration is done in a constructor function.

   @note
   Make sure that the pointer to the registered structure is valid until the
   type is unregistered.

   @param type pointer to a struct defining this type

   @return
   When registration is successful this function returns 0.
 */
uint32_t amxc_var_register_type(amxc_var_type_t* const type);

/**
   @ingroup amxc_variant_type
   @brief
   Unregisters an already registered variant type.

   Only registered types can be unregistered.

   After unregistering a type it can not be used again until it is registered
   again using @ref amxc_var_register_type.

   Typically unregistration is done in a destructor function.

   @note
   Any variants of this type still existing will become rogue variants.
   It will probably not possible anymore to convert them to other types or to
   free any allocated memory.

   @param type pointer to a struct defining this type

   @return
   When unregistration is successful this function returns 0.
 */
int amxc_var_unregister_type(amxc_var_type_t* const type);

/**
   @ingroup amxc_variant_type
   @brief
   Get the type name.

   Using the type id look-up the type name and return it.

   @param type_id the type id

   @return
   returns the name of the type id, or NULL pointer when no type exists with that
   type id.
 */
const char* amxc_var_get_type_name_from_id(const uint32_t type_id);

/**
   @ingroup amxc_variant_type
   @brief
   Get the type id.

   Using the type name look-up the type id and return it.

   @param name the name of the type

   @return
   returns the type id, or AMXC_VAR_ID_MAX if no type with the given name
   was not found
 */
uint32_t amxc_var_get_type_id_from_name(const char* const name);

/**
   @ingroup amxc_variant_type
   @brief
   Get the type definition structure.

   Get the type definition structure.

   @param type_id the type id

   @return
   returns the type definition structure for the type id or NULL if the
   type id does not exist
 */
amxc_var_type_t* amxc_var_get_type(unsigned int type_id);


#ifdef __cplusplus
}
#endif

#endif // __AMXC_VARIANT_TYPE_H__
