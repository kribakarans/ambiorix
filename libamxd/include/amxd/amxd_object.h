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

#if !defined(__AMXD_OBJECT_H__)
#define __AMXD_OBJECT_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>
#include <amxd/amxd_types.h>
#include <amxd/amxd_common.h>
#include <amxd/amxd_object_hierarchy.h>
#include <amxd/amxd_object_function.h>
#include <amxd/amxd_object_parameter.h>
#include <amxd/amxd_object_action.h>

/**
   @file
   @brief
   Ambiorix Data Model API header file
 */

/**
   @defgroup amxd_object Data Model Objects
 */

/**
   @ingroup amxd_object
   @brief
   Helper macro for iterating object content

   This helper macro can iterator over:
   - all parameters of an object, specify parameter as type
   - all functions of an object, specify function as type
   - all instances of an template object, specify instance as type
   - all child objects of an object, specify child as type

   The iterator should not be declared.

   Using this macro it is allowed to remove (delete) the iterators
   containing data structure

   The iterator can be converted to the correct type using
   amxc_container_of macro.

   For parameters the iterator is a member of the
   amxd_param_t structure, for functions the iterator is a member of the
   amxd_function_t structure, for instances and child objects the iterator
   is a member of the amxd_object_t structure.

   @note
   This macro can not be nested. Use @ref amxd_object_iterate if you need
   nested loops to iterate over the content of objects.

   @param type can be one of [parameter, function, child, instance]
   @param it a linked list iterator
   @param object the object
 */
#define amxd_object_for_each(type, it, object) \
    for(amxc_llist_it_t* it = amxd_object_first_ ## type(object), \
        * _next = amxc_llist_it_get_next(it); \
        it; \
        it = _next, \
        _next = amxc_llist_it_get_next(it))


/**
   @ingroup amxd_object
   @brief
   Helper macro for iterating object content

   This helper macro can iterator over:
   - all parameters of an object, specify parameter as type
   - all functions of an object, specify function as type
   - all instances of an template object, specify instance as type
   - all child objects of an object, specify child as type

   The iterator should not be declared.

   @warning
   Do not delete the iterator or its containing data structure. If you want to
   be able to delete the current iterator (or its containing data structure),
   use the macro @ref amxd_object_for_each

   The iterator can be converted to the correct type using
   amxc_container_of macro. For parameters the iterator is a member of the
   amxd_param_t structure, for functions the iterator is a member of the
   amxd_function_t structure, for instances and child objects the iterator
   is a member of the amxd_object_t structure.

   @param type can be one of [parameter, function, child, instance]
   @param it a linked list iterator
   @param object the object
 */
#define amxd_object_iterate(type, it, object) \
    for(amxc_llist_it_t* it = amxd_object_first_ ## type(object); \
        it; \
        it = amxc_llist_it_get_next(it))

/**
   @ingroup amxd_data_model_types

   @brief
   Name and path format flag - default behavior, use name for instance objects

   - @ref amxd_object_get_name
   - @ref amxd_object_get_path
   - @ref amxd_object_get_rel_path
 */
#define AMXD_OBJECT_NAMED           0x00

/**
   @ingroup amxd_data_model_types

   @brief
   Name and path format flag - use index for instance objects

   - @ref amxd_object_get_name
   - @ref amxd_object_get_path
   - @ref amxd_object_get_rel_path
 */
#define AMXD_OBJECT_INDEXED         0x01

/**
   @ingroup amxd_data_model_types

   @brief
   Path format flag - set name or index of instrance objects between '[' and  ']'

   This flag can be used in these functions:
   - @ref amxd_object_get_path
   - @ref amxd_object_get_rel_path
 */
#define AMXD_OBJECT_EXTENDED        0x02

/**
   @ingroup amxd_data_model_types

   @brief
   Path format flag - create path that can be used as regular expression

   Using this flag will make sure that all dots are excaped.

   This flag can be used in these functions:
   - @ref amxd_object_get_path
   - @ref amxd_object_get_rel_path
 */
#define AMXD_OBJECT_REGEXP          0x04

/**
   @ingroup amxd_data_model_types

   @brief
   Path format flag - when set the object path is terminated with a dot

   This flag can be used in these functions:
   - @ref amxd_object_get_path
   - @ref amxd_object_get_rel_path
 */
#define AMXD_OBJECT_TERMINATE       0x08

/**
   @ingroup amxd_data_model_types

   @brief
   Path format flag - adds {i} as placeholder for an instance object

   This flag can be used in these functions:
   - @ref amxd_object_get_path
   - @ref amxd_object_get_rel_path
 */
#define AMXD_OBJECT_SUPPORTED       0x10

#define AMXD_OBJECT_AUTO_PATH       0x20

/**
   @ingroup amxd_data_model_types

   @brief
   List and describe flag

   When used in @ref amxd_object_list all parameters of the object are added.

   When used in @ref amxd_object_describe all parameters of the object are described.

   This flag can be used in these functions:
   - @ref amxd_object_list
   - @ref amxd_object_describe
 */
#define AMXD_OBJECT_PARAM            0x01

/**
   @ingroup amxd_data_model_types

   @brief
   List and describe flag

   When used in @ref amxd_object_list all functions of the object are added to the list.

   When used in @ref amxd_object_describe all functions of the object are described.

   This flag can be used in these functions:
   - @ref amxd_object_list
   - @ref amxd_object_describe
 */
#define AMXD_OBJECT_FUNC             0x02

/**
   @ingroup amxd_data_model_types

   @brief
   List flag

   All child objects (sub-objects) of the object are added to the list.

   This flag can be used in these functions:
   - @ref amxd_object_list
 */
#define AMXD_OBJECT_CHILD            0x04

/**
   @ingroup amxd_data_model_types

   @brief
   List flag

   All instance of the object are added to the list. This flag only has effect
   when used on a multi-instance object.

   This flag can be used in these functions:
   - @ref amxd_object_list
 */
#define AMXD_OBJECT_INSTANCE         0x08

/**
   @ingroup amxd_data_model_types

   @brief
   List and describe flag

   When this flag is set, no base object functions are added to the list or describe table.

   This flag can be used in these functions:
   - @ref amxd_object_list
   - @ref amxd_object_describe
 */
#define AMXD_OBJECT_NO_BASE          0x10

/**
   @ingroup amxd_data_model_types

   @brief
   List and describe flag

   When this flag is set, all parameters, functions and sub-objects are included.

   This flag can be used in these functions:
   - @ref amxd_object_list
 */
#define AMXD_TEMPLATE_INFO           0x20

#define AMXD_OBJECT_KEY_PARAM        0x40

#define AMXD_OBJECT_EVENT            0x80

/**
   @ingroup amxd_data_model_types

   @brief
   List and describe flag

   This combines all list and describe flags, except @ref AMXD_OBJECT_NO_BASE
 */
#define AMXD_OBJECT_ALL \
    AMXD_OBJECT_PARAM | \
    AMXD_OBJECT_FUNC | \
    AMXD_OBJECT_CHILD | \
    AMXD_OBJECT_INSTANCE

/**
   @ingroup amxd_object
   @brief
   Data model object constructor function

   Allocates memory for a new data model object and initializes the object.

   The following object types can be created with this function:
   - singelton objects
   - template objects
   - mib objects

   Instances of template objects must be created with the function
   @ref amxd_object_new_instance or @ref amxd_object_add_instance

   To be able to create a new object a valid name must be given.
   The name of each node (object) in the hierarchy MUST start with a letter or
   underscore, and subsequent characters MUST be letters, digits, underscores
   or hyphens.

   No attributes are set. Object attributes can be changed by using one of the
   following functions:
   - @ref amxd_object_set_attr
   - @ref amxd_object_set_attrs

   The newly created object is not added to the data model tree automatically.
   You can add the new object in the data model by using the function
   @ref amxd_object_add_object.

   Use @ref amxd_object_delete to remove the object and free all allocated
   memory.

   @param object pointer to an object pointer. The address of the new allocated
                 object is stored in this pointer.
   @param type the object type that needs to be created. this can be one of
               @ref amxd_object_singleton, @ref amxd_object_template,
               @ref amxd_object_mib
   @param name A valid object name. The name of each object in the hierarchy
               MUST start with a letter or underscore, and subsequent
               characters MUST be letters, digits, underscores or hyphens.

   @return
   amxd_status_ok when the object is created, or another status code when
   failed creating the object
 */
amxd_status_t amxd_object_new(amxd_object_t** object,
                              const amxd_object_type_t type,
                              const char* name);

/**
   @ingroup amxd_object
   @brief
   Data model object destructor function

   Frees all memory allocated for an object.

   If the object was in a data model tree, it is removed from that tree.

   If the object has childeren (or instances) all these are freed and removed
   as well.

   @param object pointer to an object pointer.
 */
void amxd_object_free(amxd_object_t** object);

/**
   @ingroup amxd_object
   @brief
   Data model object constructor function

   Creates a new instance of a template object. When passing a NULL pointer
   for the name, the name is the same as the index (but in string format).
   When passing 0 for the index. the next index is taken.

   This function only allocates memory to store the object but will not
   assign values to the parameters. The parameter values passed to this function
   are only used to check if no other instance exists with the same values
   for the key parameters.

   If creation is successful, the values for the key parameters and other
   parameters must still be set. Use @ref amxd_object_add_instance to create
   an instance an fill the parameter values in one go.

   To be able to create a new object a valid name must be given or NULL.
   The name of each node (object) in the hierarchy MUST start with a letter or
   underscore, and subsequent characters MUST be letters, digits, underscores
   or hyphens.

   The name and index (if given) must be unique in the context of the template
   object - no other instance can exist with the same name or index.

   The instance inherts all attributes, all parameters (except template only
   paramters) and all functions (except template only functions) of the
   template object .

   The newly created object will have as parent the template object.

   To remove an instance use @ref amxd_object_delete

   @param object pointer to an object pointer. The address of the new allocated
                 object is stored in this pointer.
   @param templ pointer to template object.
   @param name A valid object name or NULL.  The name of each object in the
               hierarchy MUST start with a letter or underscore, and subsequent
               characters MUST be letters, digits, underscores or hyphens.'
   @param index A uinique index or 0
   @param values A variant containing a hash table with at least all the values
                 for key parameters. These are used to verify that the innstance
                 is unique.

   @return
   amxd_status_ok when the object is created, or another status code when
   failed creating the object
 */
amxd_status_t amxd_object_new_instance(amxd_object_t** object,
                                       amxd_object_t* templ,
                                       const char* name,
                                       uint32_t index,
                                       amxc_var_t* values);

/**
   @ingroup amxd_object
   @brief
   Data model object constructor function

   Creates a new instance of a template object and sets the values of the
   parameters if provided.

   If the template contains key parameters, the values for these parameters
   must be provided.

   This function calls @ref amxd_object_new_instance to allocate memory for the
   object and to check if it can be created (unique name, index and key values)

   If creation is successful, the values for the key parameters and other
   parameters are set in one go.

   To be able to create a new object a valid name must be given or NULL.
   The name of each node (object) in the hierarchy MUST start with a letter or
   underscore, and subsequent characters MUST be letters, digits, underscores
   or hyphens.

   The name and index (if given) must be unique in the context of the template
   object - no other instance can exist with the same name or index.

   The instance inherits all attributes, all parameters (except template only
   parameters) and all functions (except template only functions) of the
   template object.

   The newly created object will have as parent the template object.

   To remove an instance use @ref amxd_object_delete

   @note
   Adding an instance with this function will not generate events. If events
   must be sent automatically, the instance should be created with a transaction.
   Alternatively, it is possible to use functions @ref amxd_object_send_add_inst
   or @ref amxd_object_emit_add_inst to send the events.

   @param object pointer to an object pointer. The address of the new allocated
                 object is stored in this pointer.
   @param templ pointer to template object.
   @param name A valid object name or NULL.  The name of each object in the
               hierarchy MUST start with a letter or underscore, and subsequent
               characters MUST be letters, digits, underscores or hyphens.'
   @param index A uinique index or 0
   @param values A variant containing a hash table with at least all the values
                 for key parameters. These values will be used to set the
                 parameter values.

   @return
   amxd_status_ok when the object is created, or another status code when
   failed creating the object
 */
amxd_status_t amxd_object_add_instance(amxd_object_t** object,
                                       amxd_object_t* templ,
                                       const char* name,
                                       uint32_t index,
                                       amxc_var_t* values);

/**
   @ingroup amxd_object
   @brief
   Invokes the destroy handler(s) of the object.

   This method doesn't remove the object from the data model.

   To remove the object, including the subtree, and free all allocated memory
   use @ref amxd_object_free

   @note
   Deleting an instance with this function will not generate events. If events
   must be sent automatically, the instance should be deleted with a transaction.
   Alternatively, it is possible to use functions @ref amxd_object_send_del_inst
   or @ref amxd_object_emit_del_inst to send the events.

   @param object pointer to an object pointer.
 */
void amxd_object_delete(amxd_object_t** object);

/**
   @ingroup amxd_object
   @brief
   Get the name of the object (or index as a string for instance objects)

   Depending on the flags given the name or index is returned for instance
   objects, for all other types of objects the flags are ignored

   @param object the object pointer
   @param flags can be one of @ref AMXD_OBJECT_NAMED or @ref AMXD_OBJECT_INDEXED

   @return
   Returns the name of the object or NULL.
 */
const char* amxd_object_get_name(const amxd_object_t* const object,
                                 const uint32_t flags);

/**
   @ingroup amxd_object
   @brief
   Get the index of an instance object

   This function returns the index of an instance object.
   For singletons or template objects this function will always return 0.

   @param object the object pointer

   @return
   Returns the index of an instance object or 0.
 */
uint32_t amxd_object_get_index(const amxd_object_t* const object);

/**
   @ingroup amxd_object
   @brief
   Returns the object type

   The type of a data model object can be:
   - amxd_object_root: The root of the data model.
     (only one of this type in the data model tree)
   - @ref amxd_object_singleton
   - @ref amxd_object_template
   - @ref amxd_object_instance
   - amxd_object_mib: a mib object can not be in the data model hierarchy
                           is only used to extend objects

   @param object the object pointer

   @return
   Returns the object type.
 */
static inline
amxd_object_type_t amxd_object_get_type(const amxd_object_t* const object) {
    return object == NULL ? amxd_object_invalid : object->type;
}

/**
   @ingroup amxd_object
   @brief
   Sets or unsets an object attribute

   The following attributes can be set - unset:
   - @ref amxd_oattr_read_only
   - @ref amxd_oattr_persistent
   - @ref amxd_oattr_private
   - @ref amxd_oattr_locked
   - @ref amxd_oattr_protected

   @note
   - Attributes of a locked object can not be changed
   - It is not possible to add functions to a locked object

   @param object the object pointer
   @param attr the object attribute id
   @param enable when true, sets the attribute, when false unsets the attribute

   @return
   Returns amxd_status_ok when attributes is changed, any other when failed
 */
amxd_status_t amxd_object_set_attr(amxd_object_t* const object,
                                   const amxd_oattr_id_t attr,
                                   const bool enable);


/**
   @ingroup amxd_object
   @brief
   Sets or unsets object attributes using a bitmap

   The following attributes can be set - unset:
   - @ref amxd_oattr_read_only
   - @ref amxd_oattr_persistent
   - @ref amxd_oattr_private
   - @ref amxd_oattr_locked
   - @ref amxd_oattr_protected

   Use the macro @ref SET_BIT to transform the attribute id to a bit.
   The bits can be joined together using the bitwise or operator '|'

   @code{.c}
       amxd_object_set_attrs(object,
                             SET_BIT(amxd_oattr_read_only) |
                             SET_BIT(amxd_oattr_persistent),
                             true);
   @endcode

   When setting or unsetting one single attribute the function
   @ref amxd_object_set_attr can be used.

   @note
   - Attributes of a locked object can not be changed
   - It is not possible to add functions to a locked object

   @param object the object pointer
   @param bitmask the object attribute bitmask
   @param enable when true, sets the attributes, when false unsets the attributes

   @return
   Returns amxd_status_ok when attributes is changed, any other when failed
 */
amxd_status_t amxd_object_set_attrs(amxd_object_t* const object,
                                    const uint32_t bitmask,
                                    bool enable);

/**
   @ingroup amxd_object
   @brief
   Gets the set attributes of an object

   This function returns the set attributes of an object as a bitmask.
   To verify if a certain attribute is set, use the macro @ref IS_BIT_SET.

   @code{.c}
       uint32_t attrs = amxd_object_get_attrs(object);

       if(IS_BIT_SET(attrs, amxd_oattr_persistent)) {
           // do something
       }
   @endcode

   To verify that one single attribute is set the function
   @ref amxd_object_is_attr_set can be used.

   @param object the object pointer

   @return
   Returns the attributes set on the object as a bitmask.
 */
uint32_t amxd_object_get_attrs(const amxd_object_t* const object);

/**
   @ingroup amxd_object
   @brief
   Checks if an attribute is set

   The following attribute identifiers can be checked
   - @ref amxd_oattr_read_only
   - @ref amxd_oattr_persistent
   - @ref amxd_oattr_private
   - @ref amxd_oattr_locked
   - @ref amxd_oattr_protected

   @param object the object pointer
   @param attr the object attribute id

   @return
   Returns true if attribute is set and false when unset
 */
bool amxd_object_is_attr_set(const amxd_object_t* const object,
                             const amxd_oattr_id_t attr);

/**
   @ingroup amxd_object
   @defgroup amxd_object_mibs Data Model Objects MIBs
 */

/**
   @ingroup amxd_object_mibs
   @brief
   Get the names of all mibs attached to this object

   @note
   Memory is allocated to store the mib names, the returned pointer must be freed.
   Failing to do so will result in a memory leak.

   @param object the object pointer

   @return
   Returns a space separated string containing the names of the mibs that are
   applied to this object. If no mibs are applied, returns NULL.
 */
char* amxd_object_get_mibs(amxd_object_t* object);

/**
   @ingroup amxd_object
   @defgroup amxd_object_mibs Data Model Objects MIBs
 */

/**
   @ingroup amxd_object_mibs
   @brief
   Checks if a mib has been added to a data model object

   Verifies if the mib with the given name is applied on the object

   if a mib with the given name does not exists, this function returns false.

   @param object the object pointer
   @param mib_name the mib name

   @return
   Returns true if mib was set on the object, false otherwise
 */
bool amxd_object_has_mib(amxd_object_t* object,
                         const char* mib_name);

/**
   @ingroup amxd_object_mibs
   @brief
   Adds a mib to an object

   When it is possible adds a mib with the given name to an object.

   When there is no mib defined with the given name this functions returns
   an error.

   When the mib was already added to the object this function returns an error.

   A mib can not be added to an object when there are name conflicts:
   - when the mib contains a parameter with the same name as a parameter in the
     object
   - when the mib contains a child object with the same name as a child object in
     the object
   - when the mib contains a method with the same name as a method in the object

   When a mib is applied to an object, the object has been extended and will
   contain the parameters, methods and child objects as defined in the mib.

   The mib can be removed from the object using @ref amxd_object_remove_mib

   @param object the object pointer
   @param mib_name the mib name

   @return
   Returns amxd_status_ok when the mib is applied to the object.
   Returns amxd_status_object_not_found when there is no mib with the given name.
   Returns amxd_status_duplicate when the mib can not be applied due to naming
   conflicts.
 */
amxd_status_t amxd_object_add_mib(amxd_object_t* const object,
                                  const char* mib_name);

/**
   @ingroup amxd_object_mibs
   @brief
   Removes a mib from an object

   Removes a mib with the given name from the object.

   Removing a mib will remove all parameters, methods and child objects from
   the object as defined in the mib.

   All data stored in the parameters will be lost.

   If there is no mib found with the given name this function returns an error.

   If the mib with the given name was not set on the object, this function returns
   amxd_status_ok.

   @param object the object pointer
   @param mib_name the mib name

   @return
   Returns amxd_status_ok when the mib is removed from the object.
   Returns amxd_status_object_not_found when there is no mib with the given name.
 */
amxd_status_t amxd_object_remove_mib(amxd_object_t* const object,
                                     const char* mib_name);

amxd_status_t amxd_object_validate(amxd_object_t* const object,
                                   int32_t depth);

amxd_status_t amxd_object_set_counter(amxd_object_t* const object,
                                      const char* name);

amxd_status_t amxd_object_set_max_instances(amxd_object_t* object,
                                            uint32_t max);

amxd_status_t amxd_object_list(amxd_object_t* const object,
                               amxc_var_t* const list,
                               uint32_t flags,
                               amxd_dm_access_t access);

amxd_status_t amxd_object_describe(amxd_object_t* const object,
                                   amxc_var_t* const value,
                                   uint32_t flags,
                                   amxd_dm_access_t access);

amxd_object_t* amxd_object_get_base(const amxd_object_t* const object);

static inline
amxc_llist_it_t* amxd_object_first_function(const amxd_object_t* const object) {
    return object == NULL ? NULL : amxc_llist_get_first(&object->functions);
}

static inline
amxc_llist_it_t* amxd_object_first_parameter(const amxd_object_t* const object) {
    return object == NULL ? NULL : amxc_llist_get_first(&object->parameters);
}

#ifdef __cplusplus
}
#endif

#endif // __AMXD_OBJECT_H__

