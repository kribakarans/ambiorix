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

#if !defined(__AMXD_PATH_H__)
#define __AMXD_PATH_H__

#ifdef __cplusplus
extern "C"
{
#endif

/**
   @file
   @brief
   Ambiorix path API header file
 */

/**
   @defgroup amxd_path data model path API
   @brief
   Data model path helper functions.

   These functions help in parsing data model paths.

   Path Names are represented by a hierarchy of Objects (“parents”) and
   Sub-Objects (“children”), separated by the dot “.” character, ending with
   a Parameter if referencing a Parameter Path.
   There are six different types of Path Names used to address the data model:

   - Object Path - This is a Path Name of either a single-instance (“static”)
     Object, or the Path Name to a Multi-Instance Object). An Object Path ends
     in a “.” Character (as specified in TR-106), except when used in a
     reference Parameter. When addressing a multi-instance object in the
     Supported Data Model that contains one or more Multi-Instance Objects in
     the Path Name, the sequence “{i}” is used as a placeholder.
   - Object Instance Path - This is a Path Name to an instance in a multi-instance
     object in the Instantiated Data Model. It uses an Instance Identifier to
     address a particular Instance of the Object. An Object Instance Path ends
     in a “.” Character (as specified in TR-106), except when used in a reference
     Parameter.
   - Parameter Path - This is a Path Name of a particular Parameter of an Object.
   - Command Path - This is a Path Name of an Object defined Operation (aka data model RPC).
   - Event Path - This is a Path Name of an Object defined Event.
   - Search Path - This is a Path Name that contains search criteria for addressing
     a set of Multi-Instance Objects and/or their Parameters.
     A Search Path may contain a Search Expression or Wildcard.

   Reference following.

   The data model can contain parameters that contains reference paths to other
   objects in the data model. The Reference Following mechanism allows references
   to Objects (not Parameters) to be followed from inside a single Path Name.
   Reference Following is indicated by a “+” character after the Parameter Path,
   referencing the Object followed by a “.”, optionally followed by a
   Relative Object or Parameter Path that are children of the Referenced Object.

   For example, "Device.NAT.PortMapping.{i}.Interface" references an IP Interface
   Object (Device.IP.Interface.{i}.) and that Object has a Parameter called “Name”.
   With Reference Following, a Path Name of "Device.NAT.PortMapping.1.Interface+.Name"
   references the “Name” Parameter of the Interface Object that the PortMapping
   is associated with (i.e. it is the equivalent of using Device.IP.Interface.1.Name
   as the Path Name).
 */

/**
   @ingroup amxd_path
   @brief
   Initializes an amxd_path_t structure

   Initializes an amxd_path_t structure and sets the path.

   If the given object path is invalid the structure will be initialized but
   an error is returned

   @param path amxd_path_t struct containing a path
   @param object_path NULL or a valid path string

   @return
   amxd_status_ok when the structure is initialized and a valid path was given,
   otherwise an error code is returned.
 */
amxd_status_t amxd_path_init(amxd_path_t* path,
                             const char* object_path);

/**
   @ingroup amxd_path
   @brief
   Cleans an amxd_path_t structure

   Frees all allocated memory and resets the amxd_path_t structure.

   @param path amxd_path_t struct containing a path
 */
void amxd_path_clean(amxd_path_t* path);

/**
   @ingroup amxd_path
   @brief
   Allocates and initializes an amxd_path_t structure

   Allocates memory on the heap for the amxd_path_t structure and initializes it.

   @note
   The allocated amxd_path_t structures must be freed when not needed anymore using
   @ref amxd_path_delete

   @param path amxd_path_t struct containing a path
   @param object_path NULL or a valid path string

   @return
   amxd_status_ok when the structure is allocated initialized and a valid path was given,
   otherwise an error code is returned.
 */
amxd_status_t amxd_path_new(amxd_path_t** path,
                            const char* object_path);

/**
   @ingroup amxd_path
   @brief
   Frees an allocated amxd_path_t structure

   After freeing the allocated memory, resets the amxd_path_t pointer to NULL.

   @note
   The allocated amxd_path_t structures must be allocated using @ref amxd_path_new

   @param path amxd_path_t struct containing a path
 */
void amxd_path_delete(amxd_path_t** path);

/**
   @ingroup amxd_path
   @brief
   Resets the amxd_path_t structure

   @param path amxd_path_t struct containing a path
 */
void amxd_path_reset(amxd_path_t* path);

/**
   @ingroup amxd_path
   @brief
   Sets or replaces the path contained in the amxd_path_t structure.

   This function does exactly the same as @ref amxd_path_setf, but takes
   a va_list of values.

   @param path amxd_path_t struct containing a path
   @param add_dot makes sure the path is ended with a dot when set to true
   @param obj_path the object path that must be set in the amxd_path_t structure.
                   printf like format string is supported.
   @param args a va_list, containing the values for the printf formatting

   @return
   amxd_status_invalid_path when the given path is invalid, otherwise amxd_status_ok.
 */
amxd_status_t amxd_path_vsetf(amxd_path_t* path,
                              bool add_dot,
                              const char* obj_path,
                              va_list args);

/**
   @ingroup amxd_path
   @brief
   Sets or replaces the path contained in the amxd_path_t structure.

   This function supports printf notations in the object path.

   When the add_dot argument is set to true, a dot will be added to the end, if
   no dot at the end was present.

   If the given path ends with a dot it will be an object path or an instance path.
   If the given path doesn't end with a dot it is a parameter path and the last
   part is the name of the parameter.

   When an invalid object path is given, the function will return amxd_invalid_path
   and the type of the amxd_path_t will be set to amxd_path_invalid.

   @param path amxd_path_t struct containing a path
   @param add_dot makes sure the path is ended with a dot when set to true
   @param obj_path the object path that must be set in the amxd_path_t structure.
                   printf like format string is supported.

   @return
   amxd_status_invalid_path when the given path is invalid, otherwise amxd_status_ok.
 */
amxd_status_t amxd_path_setf(amxd_path_t* path,
                             bool add_dot,
                             const char* obj_path, ...) \
    __attribute__ ((format(printf, 3, 4)));

/**
   @ingroup amxd_path
   @brief
   Appends a parameter name or object name/index to the path.

   Adds a parameter name or object name, instance index, wildcard, search expression
   to the path contained in the amxd_path_t structure.

   When add_dot is set to true, a dot is added if the extension doesn't end with a dot.

   @param path amxd_path_t struct containing a path
   @param extension the string that must be added to the path
   @param add_dot make sure the path ends with a dot, even if the extension doesn't contain a dot.

   @return
   amxd_status_invalid_path when the result is an invalid path, amxd_status_ok otherwise.
 */
amxd_status_t amxd_path_append(amxd_path_t* path, const char* extension, bool add_dot);

/**
   @ingroup amxd_path
   @brief
   Prepends an object name/index to the path.

   Prepends the current path with an object name, instance index, wildcard, search expression
   to the path contained in the amxd_path_t structure.

   The extension can not be a parameter name in this case, as a parameter name
   can only be added to the end of the path.

   @param path amxd_path_t struct containing a path
   @param extension the string that must be prepended to the path

   @return
   amxd_status_invalid_path when the result is an invalid path, amxd_status_ok otherwise.
 */
amxd_status_t amxd_path_prepend(amxd_path_t* path, const char* extension);

/**
   @ingroup amxd_path
   @brief
   Returns the path stored in the amxd_path_t structure.

   Returns the object path as a string that is stored in the amxd_path_t structure.

   When the amxd_path_t structure contains a parameter path, this function will
   only return the object path without the parameter name.

   When the full parameter path is needed use @ref amxd_path_get_param_path

   @param path amxd_path_t struct containing a path
   @param flags bitmap of flags. Currently only AMXD_OBJECT_TERMINATE is supported.

   @return
   the path stored in the structure
 */
const char* amxd_path_get(amxd_path_t* path, int flags);

/**
   @ingroup amxd_path
   @brief
   Gets the parameter name.

   Gets the parameter name if the path is a parameter path. This function returns
   NULL if the path contained in the amxd_path_t structure is not a parameter path.

   @param path amxd_path_t struct containing a path

   @return
   The parameter name or NULL if the path is not a parameter path.
 */
const char* amxd_path_get_param(amxd_path_t* path);

/**
   @ingroup amxd_path
   @brief
   Gets the first part of the path.

   Gets the first part of the path, that is until the first dot encountered.

   When remove is set to true, it is removed from the path contained in the
   amxd_path_t structure.

   @note
   The returned string must be freed when not needed anymore.

   @param path amxd_path_t struct containing a path
   @param remove when set to true it is removed from the path contained in the structure.

   @return
   The first part of the path or NULL when the path is empty.
 */
char* amxd_path_get_first(amxd_path_t* path, bool remove);

/**
   @ingroup amxd_path
   @brief
   Gets the last part of the path.

   Gets the last part of the path, that is the part in front of the last dot.

   When remove is set to true, it is removed from the path contained in the
   amxd_path_t structure.

   Parameter names are not returned by this function, use @ref amxd_path_get_param
   to get the parameter name.

   @note
   The returned string must be freed when not needed anymore.

   @param path amxd_path_t struct containing a path
   @param remove when set to true it is removed from the path contained in the structure.

   @return
   The last part of the path or NULL if the path is empty.
 */
char* amxd_path_get_last(amxd_path_t* path, bool remove);

/**
   @ingroup amxd_path
   @brief
   Gets the fixed part of the path.

   The fixed part of a path is the path starting from the beginning until a
   wildcard or seearch expression.

   If the path doesn't contain a wildcard or search expression the full path
   is returned.

   When remove is set to true, the fixed part is removed from the path.

   @note
   The returned string must be freed when not needed anymore.

   @param path amxd_path_t struct containing a path
   @param remove when set to true it is removed from the path contained in the structure.

   @return
   The fixed part of the path.
 */
char* amxd_path_get_fixed_part(amxd_path_t* path, bool remove);

/**
   @ingroup amxd_path
   @brief
   Translates the path into a path that can be used to fetch the object definition.

   This function will remove the '{i}' placeholders or indices from the path
   contained in the amxd_path_t structure. This will result in an ambiorix
   data model object definition path.

   The resulting path can be used to fetch the object definition.

   @note
   The provided path must not contain search expressions or wildcards.

   @note
   The returned string must be freed when not needed anymore.

   @param path amxd_path_t struct containing a path

   @return
   The ambiorix data model object definition path.
 */
char* amxd_path_get_supported_path(amxd_path_t* path);

/**
   @ingroup amxd_path
   @brief
   Returns the reference path.

   When the given path has reference following decorations, this function will
   return the reference path.

   Example:
   When the path is "Device.NAT.PortMapping.1.Interface+.Name" this function returns
   the string "Device.NAT.PortMapping.1.Interface."

   When remove is set to true the reference path is removed from the path contained
   in the amxd_path_t structure.

   @note
   The returned string must be freed when not needed anymore.

   @param path amxd_path_t struct containing a path
   @param remove when set to true it is removed from the path contained in the structure.

   @return
   The reference path.
 */
char* amxd_path_get_reference_part(amxd_path_t* path, bool remove);

/**
   @ingroup amxd_path
   @brief
   Returns the reference path index.

   When the given path has reference following decorations, this function will
   return the index of the reference.

   When the parameter that contains the reference is a comma separated list
   of references, the index is used to specify which item in the list must be used.
   The index starts with 1 for the first item in the list.

   If no index is provided in the reference following decoration, the index returned
   is 1.

   Example:
   When the path is "Device.NAT.PortMapping.1.Interface+#2.Name" this function returns
   2

   @param path amxd_path_t struct containing a path

   @return
   The reference index.
 */
uint32_t amxd_path_get_reference_index(amxd_path_t* path);

/**
   @ingroup amxd_path
   @brief
   Creates the supported path representation of the given path.

   Replaces each index, wildcard or search string into '{i}' placeholder.

   @note
   The returned string must be freed when not needed anymore.

   @param path amxd_path_t struct containing a path

   @return
   The supported path representation.
 */
char* amxd_path_build_supported_path(amxd_path_t* path);

/**
   @ingroup amxd_path
   @brief
   Creates the search path representation of the given supported path.

   Replaces each '{i}' placeholder into '*' wildcard.

   @note
   The returned string must be freed when not needed anymore.

   @param path amxd_path_t struct containing a path

   @return
   The search path representation.
 */
char* amxd_path_build_search_path(amxd_path_t* path);

/**
   @ingroup amxd_path
   @brief
   Calculates the depth of the path

   Calculates the depth of the path. This is the depth of the hierarchy of the
   path in the data model. Each object in the hierarchy increases the depth, parameters
   are not counted as a depth.

   @param path amxd_path_t struct containing a path

   @return
   The depth of the path
 */
uint32_t amxd_path_get_depth(const amxd_path_t* const path);

/**
   @ingroup amxd_path
   @brief
   Returns the path type.

   See @ref amxd_path_type_t for the supported path types.

   @param path amxd_path_t struct containing a path

   @return
   The path type.
 */
static inline
amxd_path_type_t amxd_path_get_type(amxd_path_t* path) {
    return path == NULL ? amxd_path_invalid : path->type;
}

/**
   @ingroup amxd_path
   @brief
   Checks if the path is valid path.

   Examples of invalid paths:
   - "Device.WiFi.AccessPoint.{some_id}.AssociatedDevice."
   - "Device.WiFi.AccessPoint.*.AssociatedDevice.{i}."

   @param path amxd_path_t struct containing a path

   @return
   true when the path is valid, false otherwise
 */
static inline
bool amxd_path_is_valid(amxd_path_t* path) {
    return path == NULL ? false : (path->type != amxd_path_invalid);
}

/**
   @ingroup amxd_path
   @brief
   Checks if the path is a search path.

   A search path is an object path containing a wildcard character ('*') or it
   contains search expressions (between '[' and ']')

   @param path amxd_path_t struct containing a path

   @return
   true when the path is a search path, false otherwise
 */
static inline
bool amxd_path_is_search_path(amxd_path_t* path) {
    return path == NULL ? false : (path->type == amxd_path_search);
}

/**
   @ingroup amxd_path
   @brief
   Checks if the path is in the supported data model.

   A path is an supported path if it contains '{i}' or it is pointing to a an object
   under a template object (not an instance of the template object).

   @param path amxd_path_t struct containing a path

   @return
   true when the path is in the supported datamodel, false otherwise
 */
static inline
bool amxd_path_is_supported_path(amxd_path_t* path) {
    return path == NULL ? false : (path->type == amxd_path_supported);
}

/**
   @ingroup amxd_path
   @brief
   Checks if the path is an object path.

   An object path is a path pointing to a singleton object or an instance object.

   @param path amxd_path_t struct containing a path

   @return
   true when the path is an object path, false otherwise
 */
static inline
bool amxd_path_is_object_path(amxd_path_t* path) {
    return path == NULL ? false : (path->type == amxd_path_object);
}

/**
   @ingroup amxd_path
   @brief
   Checks if the path is in the instantiated data model.

   A path is in the instantiated data model if the path ends with an instance index,
   a wildcard or a search expression.

   @param path amxd_path_t struct containing a path

   @return
   true when the path is in the instantiated data model, false otherwise
 */
bool amxd_path_is_instance_path(const amxd_path_t* const path);

/**
   @ingroup amxd_path
   @brief
   Get the full parameter path from the provided amxd_path_t struct

   @note
   If the provided path does not contain a parameter, the function will return NULL.

   @param path amxd_path_t struct containing a parameter path

   @return
   Full parameter path in case of success, NULL otherwise
 */
char* amxd_path_get_param_path(amxd_path_t* path);

#ifdef __cplusplus
}
#endif

#endif // __AMXD_PATH_H__

