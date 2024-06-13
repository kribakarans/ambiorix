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

#if !defined(__AMXD_OBJECT_HIERARCHY_H__)
#define __AMXD_OBJECT_HIERARCHY_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>
#include <amxd/amxd_types.h>

/**
   @ingroup amxd_object
   @defgroup amxd_object_hierarchy Hierarchical Tree
 */

/**
   @ingroup amxd_object_hierarchy
   @brief
   Definition of object filter function.

   Iterating over all objects in a data model or iterating of a part of the
   data model is easy when using the function @ref amxd_object_hierarchy_walk.

   Using a filter function certain objects can be filtered out of the result.
   The filter function must match this singature and will be called for
   each object. If the filter function returns false, the object is filtered
   out, including all child or instance objects underneath it.

   @param object the object
   @param depth corresponds with the leftover depth as given to the
                @ref amxd_object_hierarchy_walk.
                Left over depth = [depth] - [Level from start point]
   @param priv Some private data, can be any pointer, as given to
               @ref amxd_object_hierarchy_walk

   @return
   true when object must be include, false when it must be filtered out.
 */
typedef bool (* amxd_object_filter_fn_t) (amxd_object_t* const object,
                                          int32_t depth,
                                          void* priv);
/**
   @ingroup amxd_object_hierarchy
   @brief
   Definition of object walk callback function.

   Iterating over all objects in a data model or iterating of a part of the
   data model is easy when using the function @ref amxd_object_hierarchy_walk.

   Each object in the data model tree is passed to a callback function
   with this signature.

   @param object the object
   @param depth corresponds with the leftover depth as given to the
                @ref amxd_object_hierarchy_walk.
                Left over depth = [depth] - [Level from start point]
   @param priv Some private data, can be any pointer, as given to
               @ref amxd_object_hierarchy_walk
 */
typedef void (* amxd_object_cb_fn_t) (amxd_object_t* const object,
                                      int32_t depth,
                                      void* priv);

/**
   @ingroup amxd_object_hierarchy
   @brief
   Definition of matching object callback function.

   Often certain tasks need to be performed for some or all object in an
   object tree. Using @ref amxd_object_for_all it is easy to
   iterate over all matching objects and provide an expression filter.

   The @ref amxd_object_for_all takes a callback function that must match
   with this signature. The provided callback is called for each matching
   object.

   @param object the starting object
   @param mobject the matching object
   @param priv Some private data, can be any pointer, as given to
               @ref amxd_object_for_all

   @return
   true when object must be include, false when it must be filtered out.
 */
typedef int (* amxd_mobject_cb_t) (amxd_object_t* object,
                                   amxd_object_t* mobject,
                                   void* priv);

/**
   @ingroup amxd_object_hierarchy
   @deprecated
   Use @ref amxd_mobject_cb_t
 */
typedef int (* amxd_instance_cb_t) (amxd_object_t* templ,
                                    amxd_object_t* instance,
                                    void* priv);
/**
   @ingroup amxd_object_hierarchy
   @brief
   Adds an object in the data model tree

   This function defines the parent - child relationship between objects.

   The object type of the child must be @ref amxd_object_singleton or
   @ref amxd_object_template.

   The object type of the parent can be any type. The parent object must be
   in a data model tree or when not, it must be of the type @ref amxd_object_mib

   An object can only have one parent object. The name of the child object
   must be unique in the context of the parent object. A parent can not have
   two child objects with the same name.

   Adding an object to the root of the data model can be done using
   @ref amxd_dm_add_root_object

   @param parent the parent object
   @param child the child object

   @return
   amxd_status_ok when the object is added to the data model tree, or another
   status code when failed to add the object
 */
amxd_status_t amxd_object_add_object(amxd_object_t* const parent,
                                     amxd_object_t* const child);

/**
   @ingroup amxd_object_hierarchy
   @brief
   Get the parent object

   All objects in the data model tree have a parent.

   The following objects will not have a parent object:
   - mib objects - @ref amxd_object_mib
   - the data model root object - @ref amxd_object_root
   - objects that are not in the data model hierarchical object tree

   If there is a need to go up multiple-levels in the hierarchical tree,
   this function can be called multiple times or as an alternative @ref
   amxd_object_findf can be used.

   @code{.c}
       // assume that curobj = "Ethernet.Interace.1"
       // going up to levels can be done like:
       amxd_object_t *pp = amxd_object_get_parent(amxd_object_get_parent(curobj));

       // alternativly use amxd_object_findf
       amxd_object_t *pp = amxd_object_findf(curobj, "^.^.");
   @endcode

   @param object the object pointer

   @return
   Returns the object pointer of the parent object or NULL if the object
   does not have a parent
 */
amxd_object_t* amxd_object_get_parent(const amxd_object_t* const object);

/**
   @ingroup amxd_object_hierarchy
   @brief
   Get the data model root

   The data model root is the top most object in the data model tree.
   This object does not have a parent object and does not have a name.
   The object type of the root object is @ref amxd_object_root.

   You can add objects to the root object using @ref amxd_dm_add_root_object.

   Objects that are not added to the data model object hierarchy, does not
   have a root object. See @ref amxd_object_get_parent

   @param object the object pointer

   @return
   Returns the data model root object pointer or NULL if the object is not in a
   data model object tree.
 */
amxd_object_t* amxd_object_get_root(const amxd_object_t* const object);

/**
   @ingroup amxd_object_hierarchy
   @brief
   Get the data model

   Gets the data model structure.
   See also @ref amxd_dm_init or @ref amxd_dm_new

   @param object the object pointer

   @return
   Returns the data model pointer or NULL if the object is not in a
   data model object tree.
 */
amxd_dm_t* amxd_object_get_dm(const amxd_object_t* const object);

/**
   @ingroup amxd_object_hierarchy
   @brief
   Get a child of the object

   Searches in the list of childeren for a child with the given name.

   @note
   If this function is called using a template object pointer it is not
   searching through the instances, use @ref amxd_object_get_instance to
   find an instance or @ref amxd_object_get

   @param object the object pointer
   @param name the child name

   @return
   Returns the object pointer of the child matching the name or NULL if there
   is no child object with the given name.
 */
amxd_object_t* amxd_object_get_child(const amxd_object_t* object,
                                     const char* name);

/**
   @ingroup amxd_object_hierarchy
   @brief
   Get an instance of the template object

   Searches in the list of instances for an instance with the given name or index

   This function only works on tempalte objects, for all other object types
   this function always returns a NULL pointer.

   @note
   It is not needed to provide a name and an index. Both are optional, but at
   least one should be given. The name can be a NULL pointer then the search is
   done using the index. The index can be 0, then the search is done using the
   name. If both are given the name is checked first.

   Calling this function on a singleton object has not effect and a NULL pointer
   is returned.

   @param object the object pointer
   @param name the instance name or NULL
   @param index the instance index or NULL

   @return
   Returns the object pointer of the child matching the name or index, NULL if
   there is no instance object with the given name or index.

   @see @ref amxd_object_get_instance, @ref amxd_object_get

 */
amxd_object_t* amxd_object_get_instance(const amxd_object_t* object,
                                        const char* name,
                                        uint32_t index);

/**
   @ingroup amxd_object_hierarchy
   @brief
   Get an instance or child of an object

   This function searches through the instance list and child list for a
   matching object.

   If the object pointer given is pointing to a template object the instances
   are searched first. If the name starts with a digit (0 - 9), it is asumed
   that the name contains an index, and the search on the instances is done using
   the indexes.
   If no instance is found, the search continues in the list of child objects.

   For all other object types only the list of childeren is searched.

   @param object the object pointer
   @param name the child or instance name

   @return
   Returns the object pointer of the child or instance matching the name or NULL
   if there is no child  or instance object with the given name.

   @see @ref amxd_object_get_child, @ref amxd_object_get_instance
 */
amxd_object_t* amxd_object_get(const amxd_object_t* object,
                               const char* name);

/**
   @ingroup amxd_object_hierarchy
   @brief
   Find an object in the data model tree, starting from an object

   Using a starting point, searches the data model object tree. The path is
   relative to the starting point object, The path can be a search path.

   A search path is a path that contains search criteria for addressing a set of
   multi-instance objects. A search path may contain a search expression or
   wildcard.

   Wildcard and search criteria can only be specified on instance objects.

   Spaces in the path are ingored.

   Indexes or object names can be used to address instance objects.

   @note
   If a search path with expressions or wildcards is used and multiple objects
   match the search path, this function will fail. To get a list of all matching
   objects use @ref amxd_object_resolve_pathf

   @param object the start object pointer
   @param rel_path the relative object path, supports printf format
                  can be a search path.

   @return
   Returns the object pointer of the found object or NULL if no matching
   object is found or mulitple matching objects are found.
 */
amxd_object_t* amxd_object_findf(amxd_object_t* object,
                                 const char* rel_path,
                                 ...) __attribute__ ((format(printf, 2, 3)));

/**
   @ingroup amxd_object_hierarchy
   @brief
   Resolves a search path into a list of matching object paths

   Using a starting point, searches the data model object tree. The path is
   relative to the starting point object, The path can be a search path.

   A search path is a path that contains search criteria for addressing a set of
   multi-instance objects. A search path may contain a search expression or
   wildcard.

   Wildcard and search criteria can only be specified on instance objects.

   Spaces in the path are ingored.

   Indexes or object names can be used to address instance objects.

   @param object the start object pointer
   @param paths an initialized linked list, the matching object paths are added
                to this list
   @param rel_path the relative (search) path. Supports printf formatting

   @return
   amxd_status_ok if matching objects are found.
 */
amxd_status_t amxd_object_resolve_pathf(amxd_object_t* object,
                                        amxc_llist_t* paths,
                                        const char* rel_path,
                                        ...)  __attribute__ ((format(printf, 3, 4)));

/**
   @ingroup amxd_object_hierarchy
   @brief
   Resolves a search path into a list of matching object paths

   Using a starting point, searches the data model object tree. The path is
   relative to the starting point object, The path can be a search path.

   A search path is a path that contains search criteria for addressing a set of
   multi-instance objects. A search path may contain a search expression or
   wildcard.

   Wildcard and search criteria can only be specified on instance objects.

   Spaces in the path are ingored.

   Indexes or object names can be used to address instance objects.

   @param object the start object pointer
   @param key_path will be set to true when that paths are key paths
   @param paths an initialized linked list, the matching object paths are added
                to this list
   @param rel_path the relative (search) path. Supports printf formatting

   @return
   amxd_status_ok if matching objects are found.
 */
amxd_status_t amxd_object_resolve_pathf_ext(amxd_object_t* object,
                                            bool* key_path,
                                            amxc_llist_t* paths,
                                            const char* rel_path,
                                            ...) __attribute__ ((format(printf, 4, 5)));

/**
   @ingroup amxd_object_hierarchy
   @brief
   Get the full path of the object.

   For instances the name or index is used depending on the flags given,
   @ref AMXD_OBJECT_INDEXED or @ref AMXD_OBJECT_NAMED, these flags are mutually
   exlusive. If both are given the index path is returned.

   To make clear that a part of the path is refering to an instance object,
   the flag @ref AMXD_OBJECT_EXTENDED can be used to put the name or index
   of the instance object between square brackets.

   When @ref AMXD_OBJECT_REGEXP is used in the flags the returned path is a
   regular expression(all dots are escaped).

   When @ref AMXD_OBJECT_TERMINATE is used in the flags the object path is
   terminated with a dot.

   When @ref AMXD_OBJECT_SUPPORTED is used in the flags all instance are
   replaced with the placeholder '{i}'. The placeholder '{i}' is automatically
   added behind each multi-instance object in the path.

   @note
   This function allocates memory to store the full path. The memory must be
   freed using "free" if not needed anymore.

   @param object the object pointer
   @param flags bit map of @ref AMXD_OBJECT_INDEXED, @ref AMXD_OBJECT_NAMED,
                @ref AMXD_OBJECT_EXTENDED, @ref AMXD_OBJECT_REGEXP,
                @ref AMXD_OBJECT_TERMINATE, @ref AMXD_OBJECT_SUPPORTED separated
                with '|'

   @return
   Returns the full path of the object or NULL.
 */
char* amxd_object_get_path(const amxd_object_t* object, const uint32_t flags);

/**
   @ingroup amxd_object_hierarchy
   @brief
   Get the relative path of the object.

   For instances the name or index is used depending on the flags given,
   @ref AMXD_OBJECT_INDEXED or @ref AMXD_OBJECT_NAMED, these flags are mutually
   exlusive. If both are given the index path is returned.

   To make clear that a part of the path is refering to an instance object,
   the flag @ref AMXD_OBJECT_EXTENDED can be used to put the name or index
   of the instance object between square brackets.

   When @ref AMXD_OBJECT_REGEXP is used in the flags the returned path is a
   regular expression(all dots are escaped).

   When @ref AMXD_OBJECT_TERMINATE is used in the flags the object path is
   terminated with a dot.

   When @ref AMXD_OBJECT_SUPPORTED is used in the flags all instance are
   replaced with the placeholder '{i}'. The placeholder '{i}' is automatically
   added behind each multi-instance object in the path.

   The path returned is relative to the given parent object. The parent
   object must be in the upper hierarchy of the child object.

   If the provided parent is not in the upper hierarchy of the given child object
   the function fails and returns a NULL pointer.

   @note
   This function allocates memory to store the full path. The memory must be
   freed using "free" if not needed anymore.

   @param child the object pointer for which a relative path is requested
   @param parent the object pointer of the "parent" object.
   @param flags bit map of @ref AMXD_OBJECT_INDEXED, @ref AMXD_OBJECT_NAMED,
                @ref AMXD_OBJECT_EXTENDED, @ref AMXD_OBJECT_REGEXP,
                @ref AMXD_OBJECT_TERMINATE, @ref AMXD_OBJECT_SUPPORTED separated
                with '|'

   @return
   Returns the relative path of the child object or NULL.
 */
char* amxd_object_get_rel_path(const amxd_object_t* child,
                               const amxd_object_t* parent,
                               const uint32_t flags);

/**
   @ingroup amxd_object_hierarchy
   @brief
   Checks if the child object is in the hierarchical tree of the parent object.

   @param child the object pointer for which a relative path is requested
   @param parent the object pointer of the "parent" object.

   @return
   true when the child object is a child of the parent object
 */
bool amxd_object_is_child_of(const amxd_object_t* const child,
                             const amxd_object_t* const parent);

/**
   @ingroup amxd_object_hierarchy
   @brief
   Iterates over all objects in the data model tree

   Starting from the specified object, iterates over all the objects in a
   certain direction (up or down). A filter function can be specified (see
   @ref amxd_object_filter_fn_t).

   For each object encountered the callback function is called. (see
   @ref amxd_object_cb_fn_t).

   A depth can be specified, whenever the depth reaches 0, iteration over the
   data model object hierarchy is stopped.

   @param object the object pointer, this is the starting object.
   @param direction can be one of @ref amxd_direction_up or
                    @ref amxd_direction_down
   @param filter filter function, when the filter function returns false
                 the object is not matching and will not be provided to the
                 callback function
   @param cb the callback function, called for each matching object
   @param depth the maximum depth
   @param priv pointer to any data, is passed to the filter (if given) function
               and the callback function
 */
void amxd_object_hierarchy_walk(amxd_object_t* const object,
                                const amxd_direction_t direction,
                                amxd_object_filter_fn_t filter,
                                amxd_object_cb_fn_t cb,
                                int32_t depth,
                                void* priv);

/**
   @ingroup amxd_object_hierarchy
   @brief
   Executes a task for all matching objects in an object tree

   Loops over all objects in an object tree that are matching the expressions
   and calls a callback function for each matching object.

   For each object that is matching the expression given in the search path,
   the callback function is called. The callback function takes three arguments
   1. The starting object pointer
   2. The matching object pointer
   3. The private data pointer

   @param object pointer to the start object
   @param rel_spath search path, used to match the objects, is relative to the start object
   @param fn the task calback function
   @param priv private data pointer, is passed to the callback function as is
 */
void amxd_object_for_all(amxd_object_t* object,
                         const char* rel_spath,
                         amxd_mobject_cb_t fn,
                         void* priv);

/**
   @ingroup amxd_object_hierarchy
   @brief
   Checks if a path is in the supported data model.

   This function checks if a given path is in the supported data model. It does
   not verify if the instances exist.

   @param object an object pointer, the starting point.
   @param rel_path search path, used to match the instances

   @return
   true when the path is a supported path, false otherwise
 */
bool amxd_object_is_supported(amxd_object_t* object,
                              const char* rel_path);
static inline
amxc_llist_it_t* amxd_object_first_instance(const amxd_object_t* const object) {
    return object == NULL ? NULL : amxc_llist_get_first(&object->instances);
}

static inline
amxc_llist_it_t* amxd_object_first_child(const amxd_object_t* const object) {
    return object == NULL ? NULL : amxc_llist_get_first(&object->objects);
}

static inline
uint32_t amxd_object_get_instance_count(const amxd_object_t* object) {
    return object == NULL ? 0 : amxc_llist_size(&object->instances);
}

static inline
uint32_t amxd_object_get_child_count(const amxd_object_t* object) {
    return object == NULL ? 0 : amxc_llist_size(&object->objects);
}

#ifdef __cplusplus
}
#endif

#endif // __AMXD_OBJECT_HIERARCHY_H__
