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

#if !defined(__AMXB_BE_MNGR_H__)
#define __AMXB_BE_MNGR_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <amxb/amxb_types.h>

/**
   @file
   @brief
   Ambiorix Bus Backend Manager API
 */

/**
   @ingroup amxb_baapi
   @defgroup amxb_be_mngr Bus Backend Management
 */

//----------------------------------------------------------------
// backend management
/**
   @ingroup amxb_be_mngr
   @brief
   Registers backend interface

   Backend can call this function to register the function table (backend interface)
   in a constructor function.

   The preferred solution however is backend provides the function table using
   "amxb_be_info" which returns the backend information, this information may
   contain the function table.

   The function table must contain at least:
   - A valid and unique backend name
   - The size filled in the stucture must be smaller or equal to the sizeof(amxb_be_funcs_t)
   - And the following function pointers must be set:
      - connect
      - disconnect
      - get_fd
      - read

   When the backend provides the function "set_config" it will be called if backend
   specific configuration options are available.

   @param funcs The back-end function table

   @return
   returns 0 when the function table is accepted.
 */
int amxb_be_register(amxb_be_funcs_t* const funcs);

/**
   @ingroup amxb_be_mngr
   @brief
   Unregisters a backend interface

   A backend can call this function to remove the function table (backend interface)
   in a destructor function.

   However this is not recommended. The backend will be unloaded from memory
   when it is not required anymore using the function @ref amxb_be_remove or
   @ref amxb_be_remove_all.

   When a backend's function table is unregistered all open connections for that
   backend will be closed before the function table is removed.

   @param funcs The back-end function table

   @return
   returns 0 when the function table is removed.
 */
int amxb_be_unregister(amxb_be_funcs_t* const funcs);

/**
   @ingroup amxb_be_mngr
   @brief
   Gets a backend function table using its name

   This function is mainly used internally to fetch the function table
   of a specific backend.

   @note
   Do not free the returned pointer or store the pointer.
   The backend function table can be removed at any time. Always use this
   function to retrieve the function table pointer.

   @param name name of the backend

   @return
   returns NULL when no backend with the given name is found.
   Otherwise it returns the function table pointer.
 */
amxb_be_funcs_t* amxb_be_find(const char* name);

/**
   @ingroup amxb_be_mngr
   @brief
   Gets a backend information

   Fetches some meta-information from the backend.

   @note
   Do not free the returned pointer or store the pointer.

   @param name name of the backend

   @return
   returns NULL when no backend with the given name is found.
   Otherwise it returns the function table pointer.
 */
const amxb_be_info_t* amxb_be_get_info(const char* name);

/**
   @ingroup amxb_be_mngr
   @brief
   Loads a shared object that implements a bus specific backend interface

   Loads a shared object into memory using dlopen. It is assumed that the
   shared object provides a backend interface implementation.

   The symbol "amxb_be_info" is resolved using dlsym. If the shared object
   does not contain this symbol, the shared object is closed and the loading fails.

   The function "amxb_be_info" is called and must return a backend information
   structure which must contain the minimum and maximum supported version of
   this library. If the version of this library is not within the range, the
   shared object is closed and loading fails.

   @param path_name absolute or relative path to a shared object that implements a backend interface

   @return
   returns 0 when the shared object is loaded successfully and it provides a valid
   backend interface.
 */
int amxb_be_load(const char* path_name);

/**
   @ingroup amxb_be_mngr
   @brief
   Loads multiple shared objects that each implement a bus specific backend interface

   The variant may contain a string or a linked list.

   When the variant contains a string it will be split using ':' as a separator.
   Each individual part is assumed to be an absolute or relative path to a
   shared object file.

   If it is a variant containing a list of variants, each variant in the list
   must contain an absolute or relative path to a shared object file.

   When one or more shared objects can not be loaded, the function will load all
   other shared objects.

   @param bes list of backends

   @return
   returns the number of backends that failed to load
 */
int amxb_be_load_multiple(amxc_var_t* const bes);

/**
   @ingroup amxb_be_mngr
   @brief
   Removes and unloads a backend with a given name

   Before the backend is unloaded all connections that are opened using
   that backend are closed.

   All bus contexts related to that backend will be invalid after this function
   call.

   @param backend_name name of the backend

   @return
   returns 0 when the backend is unloaded.
 */
int amxb_be_remove(const char* backend_name);

/**
   @ingroup amxb_be_mngr
   @brief
   Removes and unloads all backends

   Before the backends are unloaded all connections are closed

   Typically this function is used just before the application exits.
 */
void amxb_be_remove_all(void);

/**
   @ingroup amxb_be_mngr
   @brief
   Get the loaded back-end names.

   This function returns an array of pointers to the loaded back-end names.
   You can iterate over this array using a simple for loop.

   Example:
   @code{.c}
      void dump_backend_names(void) {
         amxc_array_t* names = amxb_be_list();
         size_t size = amxc_array_size(names);

         for(size_t i = 0; i < size; i++) {
            const char* name = (const char *)amxc_array_get_data_at(names, i);
            printf("back-end [%s]\n", name);
         }

         amxc_array_delete(&names, NULL);
      }
   @endcode

   The array must be freed when not needed any more, use `amxc_array_delete`.

   @warning
   Do not free the content of the array, in other words do not provide a delete
   callback to `amxc_array_delete`.

   @return
   returns a pointer to an amxc_array_t.
 */
amxc_array_t* amxb_be_list(void);

/**
   @ingroup amxb_be_mngr
   @brief
   Calls a function on all open connections

   Loops over all backends and calls a functions for each open connection
   for the backend.

   @param fn function to be called
   @param args a variant that is passed to the function
   @param priv some private data, is passed as is to the function

   @return
   0 when at least one connection could perform the task
 */
int amxb_be_for_all_connections(amxb_be_task_fn_t fn,
                                const amxc_var_t* args,
                                void* priv);

/**
   @ingroup amxb_be_mngr
   @brief
   Calls a function on all listen sockets

   Loops over all backends and calls a functions for each listen socket
   for the backend.

   @param fn function to be called
   @param args a variant that is passed to the function
   @param priv some private data, is passed as is to the function

   @return
   0 when no errors occured
 */
int amxb_be_for_all_listeners(amxb_be_task_fn_t fn,
                              const amxc_var_t* args,
                              void* priv);
/**
   @ingroup amxb_be_mngr
   @brief
   Searches a bus context that can provide a certain object

   Loops over all open connections for each back-end. Depending on the
   back-end capabilities a request or message is send to check if
   the object is available and can be reached using the open connection.

   It is possible that the path can only be matched partially, that is also
   considered as available. To check the full path use @ref amxb_be_who_has_ex

   If a bus context is found, it is stored in a lookup cache. When this method
   is called again with same object path, the bus context is retrieved from the
   cache.

   The lookup cache is limited in size (default 5 entries), but can be changed
   by calling @ref amxb_be_cache_set_size.

   @note
   Search or wild-card paths are not supported. The path provided must be
   in the instantiated data model.

   @param object_path an object path in the instantiated data model

   @return
   NULL when no bus context can provide the object.
   A bus context otherwise.
 */
amxb_bus_ctx_t* amxb_be_who_has(const char* object_path);

/**
   @ingroup amxb_be_mngr
   @brief
   Searches a bus context that can provide a certain object

   Loops over all open connections for each back-end. Depending on the
   back-end capabilities a request or message is send to check if
   the object is available and can be reached using the open connection.

   Depending on the value of the full_match argument a partial match is allowed.

   If a bus context is found, it is stored in a lookup cache. When this method
   is called again with same object path, the bus context is retrieved from the
   cache.

   The lookup cache is limited in size (default 5 entries), but can be changed
   by calling @ref amxb_be_cache_set_size.

   @note
   Search or wild-card paths are not supported. The path provided must be
   in the instantiated data model.

   @param object_path an object path in the instantiated data model
   @param full_match when set to false partial matches are allowed.

   @return
   NULL when no bus context can provide the object.
   A bus context otherwise.
 */
amxb_bus_ctx_t* amxb_be_who_has_ex(const char* object_path, bool full_match);

/**
   @ingroup amxb_be_mngr
   @brief
   Removes a bus context from the lookup cache.

   Bus contexts are added to the lookup cache by @ref amxb_be_who_has

   @param ctx a bus context
 */
void amxb_be_cache_remove_ctx(amxb_bus_ctx_t* ctx);

/**
   @ingroup amxb_be_mngr
   @brief
   Removes an object path and its corresponding bus context from the lookup cache.

   Bus contexts are added to the lookup cache by @ref amxb_be_who_has

   @param object_path Object path that must be removed from the cache
 */
void amxb_be_cache_remove_path(const char* object_path);

/**
   @ingroup amxb_be_mngr
   @brief
   Changes the size of the lookup cache.

   Bus contexts are added to the lookup cache by @ref amxb_be_who_has.

   When the new size is smaller then the current size, the oldes entries are
   removed from the cache.

   @param size the new size
 */
void amxb_be_cache_set_size(uint32_t size);

/**
   @ingroup amxb_be_mngr
   @brief
   Passes configuration options to the backends.

   The configuration must be a variant containing a hash table. If in the
   hash table a key is found with the name of a loaded backend, the value
   of that key is passed to the backend. The value itself can also be
   a hash table.

   When passing a NULL pointer the configuration is reset for all
   backends

   @param configuration a hash table variant with configuration options

   @return
   returns 0 when the configuration was set.
 */
int amxb_set_config(amxc_var_t* const configuration);

//----------------------------------------------------------------
// version (verification) functions
/**
   @ingroup amxb_be_mngr
   @brief
   Compares the given version with the library version

   @param be_version the version that must be compared with the library version

   @return
   - 0 when lib version and the given version are equal
   - 1 when lib version is > than be version
   - -1 when lib version is < than be version
 */
int amxb_check_version(const amxb_version_t* be_version);


/**
   @ingroup amxb_be_mngr
   @brief
   Checks if the library version is in the given range

   @param min the minimum version
   @param max the maximum version

   @return
   - 0 when lib version is in the range
   - 1 when lib version is not in the range
 */
int amxb_check_be_versions(const amxb_version_t* min,
                           const amxb_version_t* max);


/**
   @ingroup amxb_be_mngr
   @brief
   Gets the version of the library

   @return
   Returns a amxb_version_t struct containing the version of this library.
 */
const amxb_version_t* amxb_get_version(void);

#ifdef __cplusplus
}
#endif

#endif // __AMXB_BE_MNGR_H__

