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

#if !defined(__AMXD_TYPES_H__)
#define __AMXD_TYPES_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>

#if !defined(USE_DOXYGEN)
#define AMXD_INLINE static inline
#else
#define AMXD_INLINE
#endif

/**
   @defgroup amxd_data_model_types Data model structures, enums, typedefs
 */

//-----------------------------------------------------------------------------
// common typedefs, struct, enums
typedef enum _amxd_status {
    amxd_status_ok,
    amxd_status_unknown_error,
    amxd_status_object_not_found,
    amxd_status_function_not_found,
    amxd_status_parameter_not_found,
    amxd_status_function_not_implemented,
    amxd_status_invalid_function,
    amxd_status_invalid_function_argument,
    amxd_status_invalid_name,
    amxd_status_invalid_attr,
    amxd_status_invalid_value,
    amxd_status_invalid_action,
    amxd_status_invalid_type,
    amxd_status_duplicate,
    amxd_status_deferred,
    amxd_status_read_only,
    amxd_status_missing_key,
    amxd_status_file_not_found,
    amxd_status_invalid_arg,
    amxd_status_out_of_mem,
    amxd_status_recursion,
    amxd_status_invalid_path,
    amxd_status_invalid_expr,
    amxd_status_permission_denied,
    amxd_status_not_supported,
    amxd_status_not_instantiated,
    amxd_status_not_a_template,
    amxd_status_timeout,
    amxd_status_last
} amxd_status_t;

typedef enum _amxd_action {
    action_invalid = -1,
    action_any = 0,         // callback functions added with this reason or always called
    action_param_read,      // read parameter value
    action_param_write,     // set parameter value
    action_param_validate,  // validate new value
    action_param_describe,  // get parameter definition
    action_param_destroy,   // remove and clean up parameter
    action_object_read,     // get all parameter values of an object
    action_object_write,    // set parameter values
    action_object_validate, // validate the full object
    action_object_list,     // fetch list(s)
    action_object_describe, // describe object, list all parameters, functions or children
    action_object_tree,     // list full tree, starting from an object
    action_object_add_inst, // add an instance
    action_object_del_inst, // verify instance can be deleted
    action_object_destroy,  // remove and clean up an object (any)
    action_object_add_mib,  // extend the object with a known mib
    action_describe_action, // describe the action itself
} amxd_action_t;

/**
   @ingroup amxd_data_model_types
   @brief
   Access level.
 */
typedef enum _amxd_dm_access {
    amxd_dm_access_public,    /**< public access, all services or applications working
                                  on behalf of external applications like browser,
                                  usp agent, ... - should use this access level*/
    amxd_dm_access_protected, /**< protected access, all services or applications
                                  running in the same environment can use this access level*/
    amxd_dm_access_private    /**< private access, the process owning a data model
                                  can use private access to access private members
                                  of the data model. Remote process can never
                                  use private access.*/
} amxd_dm_access_t;

typedef struct _amxd_object amxd_object_t;
typedef struct _amxd_parameter amxd_param_t;

typedef amxd_status_t (* amxd_action_fn_t) (amxd_object_t* const object,    // the object
                                            amxd_param_t* const param,      // the parameter
                                            amxd_action_t reason,           // the action id (reason)
                                            const amxc_var_t* const args,   // action arguments, when null default behaviour
                                            amxc_var_t* const retval,       // action retval
                                            void* priv);                    // some private cb data (can be NULL)

typedef struct _amxd_dm_cb {
    amxc_llist_it_t it;
    amxd_action_fn_t fn;
    amxd_action_t reason;
    void* priv;
    bool enable;
} amxd_dm_cb_t;
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// object related typedefs, structs & enums
/**
   @ingroup amxd_data_model_types
   @brief
   The different object types.

   Each object is of one of these types.
   Some of these types can be used in the constructor functions to specify
   the type of object you want to create,
 */
typedef enum _amxd_object_type {
    amxd_object_root,       /**< The root object, only one exists for each data
                                 model and is automatically created when
                                 calling @ref amxd_dm_init*/
    amxd_object_singleton,  /**< Singleton object, can be created using
                                 @ref amxd_object_new */
    amxd_object_template,   /**< Template object, can be created using
                                 @ref amxd_object_new. Instances of a template
                                 object can be created using @ref amxd_object_new_instance */
    amxd_object_instance,   /**< Instance object, the parent of an instance object
                                 is always a template object */
    amxd_object_mib,        /**< A mib object does not have a parent, a mib can
                                 be used to extend other objects */
    amxd_object_invalid,    /**< Should not be used */
} amxd_object_type_t;

/**
   @ingroup amxd_data_model_types
   @brief
   The object attributes
 */
typedef enum _amxd_oattr_id {
    amxd_oattr_read_only,   /**< The object is read only */
    amxd_oattr_persistent,  /**< The object is persistent and should be stored
                                 in local persistent storage the object is saved*/
    amxd_oattr_private,     /**< The object is private. It can only used internally
                                 in the application, remote clients will have
                                 no access to it, the object will not be visible
                                 in introspection.*/
    amxd_oattr_locked,      /**< The object is locked. No functions or parameters
                                 can be added when an object is locked. Attributes
                                 of the object can not be changed anymore after
                                 locking the object*/
    amxd_oattr_protected,
    amxd_oattr_max = amxd_oattr_protected
} amxd_oattr_id_t;

typedef enum _amxd_direction {
    amxd_direction_up,
    amxd_direction_down,
    amxd_direction_down_reverse
} amxd_direction_t;

typedef struct _amxd_object_attr {
    uint32_t read_only : 1;             // object can not be changed directly, use functions to interact
                                        // a read-only object is read only for remote clients
    uint32_t persistent : 1;            // object is persistent if in dm tree, dm save will store the object
    uint32_t priv : 1;                  // object is private - not visible to remote clients
    uint32_t locked : 1;                // object is locked - not possible to add new functions or parameters
    uint32_t prot : 1;                  // object is not visible from external sources
} amxd_object_attr_t;

struct _amxd_object {
    amxc_llist_it_t it;                // it.list pointer points to parent object in dm tree
                                       // depending on type the list pointer is pointing to
                                       // objects (singelton & templates)
                                       // instances (instance object)
                                       // data model mibs list

    amxd_object_type_t type;           // object type
    amxd_object_attr_t attr;           // object attributes
    char* name;                        // object name
    char* index_name;                  // index as string, by default always null until requested
    uint32_t index;                    // index - only valid for instance objects
    uint32_t last_index;               // last index used - only valid for template objects

    amxc_llist_t objects;              // list of children in dm tree
    amxc_llist_t instances;            // list of instances - only used for template objects
    amxc_llist_t functions;            // list of functions - for derived objects only overides
    amxc_llist_t parameters;           // list of parameters

    amxc_llist_t derived_objects;      // list of derived objects
    amxc_llist_it_t derived_from;      // derived_from.list points to source object derived_objects

    void* priv;                        // private data

    amxc_llist_t cb_fns;               // action callback functions, see amxd_dm_cb_t
    amxc_array_t mib_names;            // array of added mib names

    amxc_var_t events;                 // list of event names
};

typedef struct _amxd_dm {
    amxd_object_t object;
    amxp_signal_mngr_t sigmngr;
    amxc_llist_t mibs;
    amxd_status_t status;
    amxc_llist_t deferred;
} amxd_dm_t;
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// function related typedefs, structs & enums
typedef struct _amxd_function amxd_function_t;

typedef amxd_status_t (* amxd_object_fn_t) (amxd_object_t* object, // object the function is called on
                                            amxd_function_t* func, // the function definition
                                            amxc_var_t* args,      // incoming arguments (type = htable), can be used as out arguments
                                            amxc_var_t* ret);      // the return value

/**
   @ingroup amxd_data_model_types
   @brief
   The method argument attributes
 */
typedef enum _amxd_aattr_id {
    amxd_aattr_in,                      /**< is an in argument */
    amxd_aattr_out,                     /**< is an out argument */
    amxd_aattr_mandatory,               /**< argument is mandatory */
    amxd_aattr_strict,                  /**< argument type is strict, no conversions are applied */
    amxd_aattr_max = amxd_aattr_strict
} amxd_aattr_id_t;

typedef struct _amxd_arg_attr {
    uint32_t in : 1;                    // in argument
    uint32_t out : 1;                   // out argument
    uint32_t mandatory : 1;             // mandatory argument
    uint32_t strict : 1;                // strict typed (incomming value type must match defined type)
} amxd_arg_attr_t;

typedef struct _amxd_func_arg {
    amxc_llist_it_t it;                // it.list points to the list containing argument in the function def
    amxd_arg_attr_t attr;              // argument attributes
    char* name;                        // argument name
    uint32_t type;                     // argument type, must be existing variant type, can be AMXC_VAR_ID_ANY
    amxc_var_t default_value;          // default value for optional arguments
} amxd_func_arg_t;

/**
   @ingroup amxd_data_model_types
   @brief
   The method attributes
 */
typedef enum _amxd_fattr_id {
    amxd_fattr_template,    /**< Method can be called on template objects */
    amxd_fattr_instance,    /**< Method can be called on instance objects */
    amxd_fattr_private,     /**< The method is private. It can only used internally
                                 in the application, remote clients will have
                                 no access to it, the object will not be visible
                                 in introspection.*/
    amxd_fattr_protected,   /**< The method is protected. External clients (webui,
                                 usp controllers, ...) can not call this method.
                                 Other process on the system can call the method.
                             */
    amxd_fattr_async,       /**< Indicate that this function is handled asynchronously*/
    amxd_fattr_max = amxd_fattr_async
} amxd_fattr_id_t;

typedef struct _amxd_func_attr {
    uint32_t templ : 1;              // function can be called on template objects
    uint32_t instance : 1;           // function can be called on instance objects
                                     // REMARK: functions on singleton objects should ignore these flags
    uint32_t priv : 1;               // function is private - not visible to remote clients
    uint32_t prot : 1;               // not visible from external sources (web-ui, usp, ...)
    uint32_t async : 1;              // function is handled asynchronously
} amxd_func_attr_t;

/**
   @ingroup amxd_data_model_types
   @brief
   RPC method structure

   Holds the RPC method definition.
 */
struct _amxd_function {
    amxc_llist_it_t it;                //< it.list points to the list containing functions in the objects
    amxd_func_attr_t attr;             //< function attributes
    char* name;                        //< function name
    uint32_t ret_type;                 //< function return type, must be a amxc_var_id
    amxc_llist_t args;                 //< function arguments definition
    amxd_object_fn_t impl;             //< function implementation (when null = not implemented)
    amxc_var_t* flags;                 //< function flags
    void* priv;                        //< private user data
};
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
typedef enum _amxd_pattr_id {
    amxd_pattr_template,
    amxd_pattr_instance,
    amxd_pattr_private,
    amxd_pattr_read_only,
    amxd_pattr_persistent,
    amxd_pattr_variable,
    amxd_pattr_counter,
    amxd_pattr_key,
    amxd_pattr_unique,
    amxd_pattr_protected,
    amxd_pattr_mutable,
    amxd_pattr_max = amxd_pattr_mutable
} amxd_pattr_id_t;

typedef struct _amxd_param_attr {
    uint32_t templ : 1;              // parameter is available in template objects
    uint32_t instance : 1;           // parameter is available in instance objects
                                     // REMARK: parametes in singleton objects should ignore these flags
    uint32_t priv : 1;               // parameter is private - not visible to remote clients
    uint32_t read_only : 1;          // parameter is read-only for remote clients
    uint32_t persistent : 1;         // parameter is persistent and should be stored in local
                                     // storage when the containing object is saved
    uint32_t variable : 1;           // the parameter is volatile, no events are send
                                     // rw funcs must be set
    uint32_t counter : 1;            // the parameter is an instance counter
    uint32_t key : 1;                // the parameter is a key parameter
    uint32_t unique : 1;             // Can only be set in combination with the key attribute
    uint32_t prot : 1;               // Not visible from external sources (web-ui, usp, ...)
    uint32_t changeable : 1;         // Indicates that the key parameter can be changed
} amxd_param_attr_t;

struct _amxd_parameter {
    amxc_llist_it_t it;                // it.list points to the list containing parameters in the objects
    amxd_param_attr_t attr;            // parameter attributes
    char* name;                        // parameter name
    amxc_var_t value;                  // parameter value
    amxc_llist_t cb_fns;               // action callback functions, see amxd_dm_cb_t
    void* priv;                        // private data
    amxc_var_t* flags;                 // parameter flags
};
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
typedef enum _amxd_path_type {
    amxd_path_invalid,
    amxd_path_object,
    amxd_path_search,
    amxd_path_supported,
    amxd_path_reference,
} amxd_path_type_t;

typedef struct _amxd_path {
    amxc_string_t path;
    char* param;
    amxc_var_t parts;
    amxd_path_type_t type;
    const char* reason;
    uint64_t ref_index;
} amxd_path_t;

#ifdef __cplusplus
}
#endif

#endif // __AMXD_TYPES_H__

