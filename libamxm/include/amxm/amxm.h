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
#if !defined(__AMXM_H__)
#define __AMXM_H__

#ifdef __cplusplus
extern "C"
{
#endif

#ifndef __AMXC_VARIANT_H__
#pragma GCC error "include <amxc/amxc_variant.h> before <amxm/amxm.h>"
#endif

#ifndef __AMXC_HTABLE_H__
#pragma GCC error "include <amxc/amxc_htable.h> before <amxm/amxm.h>"
#endif

#ifndef __AMXC_LLIST_H__
#pragma GCC error "include <amxc/amxc_llist.h> before <amxm/amxm.h>"
#endif

/**
   @file
   @brief
   Ambiorix module API header file
 */

/**
   @ingroup amxm
   @defgroup amxm
 */

#define AMXM_CONSTRUCTOR int __attribute__((constructor))
#define AMXM_DESTRUCTOR int __attribute__((destructor))

#define AMXM_FUNCTION_NAME_LENGTH 64
#define AMXM_MODULE_NAME_LENGTH 256
#define AMXM_SHARED_OBJECT_LENGTH 256

/**
   @ingroup amxm
   @brief
   Definition of the modular function you can execute later on.

   A pointer to the function is used in the following functions
   @ref amxm_function_register
 */
typedef int (* amxm_callback_t)(const char* const function_name, amxc_var_t* args, amxc_var_t* ret);

typedef struct amxm_function_callback {
    char function_name[AMXM_FUNCTION_NAME_LENGTH + 1];
    amxm_callback_t function_cb;
    amxc_htable_it_t it;
} amxm_function_callback_t;

typedef struct amxm_module {
    char name[AMXM_MODULE_NAME_LENGTH + 1];
    amxc_htable_t amxm_function_htable;
    amxc_llist_it_t it;
} amxm_module_t;

typedef struct amxm_shared_object {
    char name[AMXM_SHARED_OBJECT_LENGTH + 1];
    char file[AMXM_SHARED_OBJECT_LENGTH + 1];
    void* handle;
    amxc_llist_t amxm_module_llist;
    amxc_llist_it_t it;
} amxm_shared_object_t;

/**
   @ingroup amxm
   @brief
   Retrieves list of loaded shared objects

   @return
   returns the list of loaded shared objects
 */
const amxc_llist_t* amxm_get_so_list(void);

/**
   @ingroup amxm
   @brief
   Close shared object by name, can be used at all time

   @param shared_object_name string name of the shared object
    --> max size AMXM_SHARED_OBJECT_LENGTH

   @return
   returns 0 when shared object is succesfully closed,
   and returns an error code when it fails
 */
int amxm_close_so(const char* const shared_object_name);

int amxm_close_all(void);

/**
   @ingroup amxm
   @brief
   Get shared object by name, can be used at all time

   @param shared_object_name the name of the shared object
    --> max size AMXM_SHARED_OBJECT_LENGTH

   @return
   returns amxm_shared_object_t when so with the same name is found, otherwise NULL
 */
amxm_shared_object_t* amxm_get_so(const char* const shared_object_name);

/**
   @ingroup amxm
   @brief
   Get moduke by name, can be used at all time

   @param shared_object_name the name of the shared object
    --> max size AMXM_SHARED_OBJECT_LENGTH
   @param module_name name of the module namespace that you want to get
    -- max size AMXM_MODULE_NAME_LENGTH

   @return
   returns amxm_module_t when found in the given shared object, otherwise NULL
 */
amxm_module_t* amxm_get_module(const char* const shared_object_name,
                               const char* const module_name);

/**
   @ingroup amxm
   @brief
   Execute function (by name) from within specified module namespace, can be used at all time.
   All the arguments have to be pre allocated (args, ret)

   When no shared object is given (NULL) the "self" amxm_shared_object_t is used
   to get the module from.

   @param shared_object_name name of the shared object that you want to execute in
    --> max size AMXM_SHARED_OBJECT_LENGTH
   @param module_name name of the module namespace that you want to execute the function in
   @param func_name alias of the function that you want to execute
    --> max size: AMXM_FUNCTION_NAME_LENGTH
   @param args variant structure of the dynamic list of arguments to the executed function
   @param ret variant structure of the dynamic list of return values coming from executed function

   @return
   returns 0 when shared object is succesfully executed,
   and returns an error code when it fails
 */
int amxm_execute_function(const char* const shared_object_name,
                          const char* const module_name,
                          const char* const func_name,
                          amxc_var_t* args,
                          amxc_var_t* ret);


/**
   @ingroup amxm
   @brief
   Checks if a function exists in a moduke

   When no shared object is given (NULL) the "self" amxm_shared_object_t is used
   to get the module from.

   @param shared_object_name name of the shared object
    --> max size AMXM_SHARED_OBJECT_LENGTH
   @param module_name name of the module namespace
   @param func_name alias of the function
    --> max size: AMXM_FUNCTION_NAME_LENGTH

   @return
   returns false when no function found otherwise true
 */
bool amxm_has_function(const char* const shared_object_name,
                       const char* const module_name,
                       const char* const func_name);

/***********************
*
* AMXM SO FUNCTIONS
*
***********************/

/**
   @ingroup amxm
   @brief
   Get number of module namespaces that are in a certain shared object

   @param shared_object pointer to the amxm_shared_object_t structure

   @return
   returns amount of module namespaces inside a shared object,
   returns 0 can be that there are no module namespace OR you supplied the wrong arguments
 */
size_t amxm_so_count_modules(const amxm_shared_object_t* const shared_object);

/**
   @ingroup amxm
   @brief
   Probe the name of module namespace inside a shared object by index

   @param shared_object pointer to the amxm_shared_object_t structure
   @param index index of the module namespace inside the shared object

   @return
   returns the name of the module namespace in the so on that index,
   returns NULL when the arguments are wrong or when there is no module namespace at that index
 */
char* amxm_so_probe(const amxm_shared_object_t* const shared_object, size_t index);


/**
   @ingroup amxm
   @brief
   Register module namespace to put functions in, can be used at all time

   When the shared object pointer is NULL, the module will be registered to the
   "self" name space.

   @param shared_object pointer to the amxm_shared_object_t structure
   @param module_name name of the module namespace that you want to create
    --> max size AMXM_MODULE_NAME_LENGTH

   @return
   returns amxm_shared_object_t that is being loaded
   otherwise NULL
 */
amxm_shared_object_t* amxm_so_get_current(void);

/**
   @ingroup amxm
   @brief
   Open shared object, can be used at all time

   @param so a pointer to the location where the pointer
             to the shared object data structure can be stored
   @param shared_object_name the alias name of the shared object
    --> max size AMXM_SHARED_OBJECT_LENGTH
   @param path_to_so the path to shared object in filesystem

   @return
   returns 0 when shared object is succesfully opened,
   and returns -1 when it fails
 */
int amxm_so_open(amxm_shared_object_t** so,
                 const char* shared_object_name,
                 const char* const path_to_so);


/**
   @ingroup amxm
   @brief
   Close shared object, can be used at all time

   The pointer to the shared object structure will be set to NULL and all
   allocated memory is freed

   @param so pointer to the amxm_shared_object_t structure that you want to close

   @return
   returns 0 when shared object is succesfully closed,
   and returns an error code when it fails
 */
int amxm_so_close(amxm_shared_object_t** so);

/**
   @ingroup amxm
   @brief
   Print error if amxm_so_open failed

   @return
   returns NULL when no error occured in dlopen,
   will return a const char* with the error message if an error did occur in dlopen
 */
const char* amxm_so_error(void);

/**
   @ingroup amxm
   @brief
   Get module by name, can be used at all time

   When no shared object is given (NULL) the "self" amxm_shared_object_t is used
   to get the module from.

   @param module_name the name of the module
    --> max size AMXM_MODULE_NAME_LENGTH
   @param shared_object the amxm_shared_object_t pointer to an existing shared object

   @return
   returns amxm_module_t when so with the same name is found inside the shared object,
   otherwise NULL
 */
amxm_module_t* amxm_so_get_module(const amxm_shared_object_t* const shared_object,
                                  const char* const module_name);


/**
   @ingroup amxm
   @brief
   Delete function (in module namespace), can be used at all time

   @param so pointer to the amxm_shared_object_t structure
   @param module_name Name of the namespace you want to delete the function in
    --> max size AMXM_MODULE_NAME_LENGTH
   @param func_name alias of the function that you gave to it
    --> max size: AMXM_FUNCTION_NAME_LENGTH

   @return
   returns 0 when function is succesfully deleted,
   and returns -3 and/or -2 and/or -1 when it fails
 */
int amxm_so_remove_function(amxm_shared_object_t* const so,
                            const char* const module_name,
                            const char* const func_name);

/**
   @ingroup amxm
   @brief
   Execute function (by name) from within specified module namespace, can be used at all time.
   All the arguments have to be pre allocated (args, ret)

   When no shared object is given (NULL) the "self" amxm_shared_object_t is used
   to get the module from.

   @param so pointer to amxm_shared_object_t pointer or NULL for 'self'
   @param module_name name of the module namespace that you want to execute the function in
    --> max size AMXM_MODULE_NAME_LENGTH
   @param func_name alias of the function that you want to execute
    --> max size: AMXM_FUNCTION_NAME_LENGTH
   @param args variant structure of the dynamic list of arguments to the executed function
   @param ret variant structure of the dynamic list of return values coming from executed function

   @return
   returns 0 when shared object is succesfully executed,
   and returns an error code when it fails
 */
int amxm_so_execute_function(amxm_shared_object_t* const so,
                             const char* const module_name,
                             const char* const func_name,
                             amxc_var_t* args,
                             amxc_var_t* ret);

/**
   @ingroup amxm
   @brief
   Checks if a function exists in a moduke

   When no shared object is given (NULL) the "self" amxm_shared_object_t is used
   to get the module from.

   @param so pointer to amxm_shared_object_t pointer or NULL for 'self'
   @param module_name name of the module namespace
    --> max size AMXM_MODULE_NAME_LENGTH
   @param func_name alias of the function
    --> max size: AMXM_FUNCTION_NAME_LENGTH

   @return
   returns false when no function found otherwise true
 */
bool amxm_so_has_function(const amxm_shared_object_t* const so,
                          const char* const module_name,
                          const char* const func_name);


/***********************
*
* AMXM MOD FUNCTIONS
*
***********************/

/**
   @ingroup amxm
   @brief
   Register module namespace to put functions in, can be used at all time

   When the shared object pointer is NULL, the module will be registered to the
   "self" name space.

   This function allocates the module data structure.

   @param mod a pointer to the location where the pointer
              to the module data structure can be stored
   @param shared_object pointer to the amxm_shared_object_t structure
   @param module_name name of the module namespace that you want to create
    --> max size AMXM_MODULE_NAME_LENGTH

   @return
   returns amxm_module_t when module namespace is succesfully created,
   return NULL when the arguments are wrong (should almost always succeed)
 */
int amxm_module_register(amxm_module_t** mod,
                         amxm_shared_object_t* const shared_object,
                         const char* const module_name);

/**
   @ingroup amxm
   @brief
   Close/Deregister module namespace (removes functions inside), can be used at all time

   Frees allocate memory for the module data structure.
   Set the pointer to NULL.

   @param mod pointer to the amxm_module_t structure of the namespace you want to close

   @return
   returns 0 when module namespace is succesfully closed,
   and returns -1 when it fails
 */
int amxm_module_deregister(amxm_module_t** mod);

/**
   @ingroup amxm
   @brief
   Add function (in module namespace), can be used at all time

   @param mod pointer to the amxm_module_t structure of the namespace you want
              to register function to
   @param func_name alias of the function that you want to give to it
    --> max size: AMXM_FUNCTION_NAME_LENGTH
   @param cb amxm_callback_t function callback

   @return
   returns 0 when function is succesfully registered,
   and returns -1 when it fails
 */
int amxm_module_add_function(amxm_module_t* const mod,
                             const char* const func_name,
                             amxm_callback_t cb);

/**
   @ingroup amxm
   @brief
   Delete function (in module namespace), can be used at all time

   @param mod pointer to the amxm_module_t structure of the namespace you want to delete the function
   @param func_name alias of the function that you gave to it
    --> max size: AMXM_FUNCTION_NAME_LENGTH

   @return
   returns 0 when function is succesfully deleted,
   and returns an error code when it fails
 */
int amxm_module_remove_function(amxm_module_t* const mod,
                                const char* const func_name);

/**
   @ingroup amxm
   @brief
   Execute function from within specified module namespace, can be used at all time.
   All the arguments have to be pre allocated (args, ret)

   @param mod pointer to the amxm_module_t structure you want to execute the function from
   @param func_name alias of the function that you want to execute
     --> max size: AMXM_FUNCTION_NAME_LENGTH
   @param args variant structure of the dynamic list of arguments to the executed function
   @param ret variant structure of the dynamic list of return values coming from executed function

   @return
   returns 0 when function is succesfully executed,
   and returns an error code when it fails
 */
int amxm_module_execute_function(amxm_module_t* mod,
                                 const char* const func_name,
                                 amxc_var_t* args,
                                 amxc_var_t* ret);


/**
   @ingroup amxm
   @brief
   Checks if a function exists in a moduke

   @param mod pointer to amxm_module_t pointer
   @param func_name alias of the function
    --> max size: AMXM_FUNCTION_NAME_LENGTH

   @return
   returns false when no function found otherwise true
 */
bool amxm_module_has_function(amxm_module_t* mod,
                              const char* const func_name);


amxc_array_t* amxm_module_get_function_names(amxm_module_t* mod);

#ifdef __cplusplus
}
#endif

#endif // __AMXM_H__
