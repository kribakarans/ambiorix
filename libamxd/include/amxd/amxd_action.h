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

#if !defined(__AMXD_ACTION_H__)
#define __AMXD_ACTION_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>
#include <amxd/amxd_types.h>

/**
   @file
   @brief
   Ambiorix Data Model Default actions header file
 */

/**
   @ingroup amxd_dm
   @defgroup amxd_actions Data Model Actions

   Data model actions are the functions that make the data model work.

   For each action a default implementation is provided. It is however possible
   to provide your own implementation, but in most cases the default one
   will be sufficient.

   When overriding the default implementations, most of the time something extra
   needs to be done (extra check, pushing to system configuration, ...), so
   the default implementation could be called from within your own implementation.

   There are two groups of actions available:
   - object actions: read, write, validate, list, describe, add instance, delete instance,
                     destroy
   - parameter actions: read, write, validate, describe, destroy

   Object actions are invoked on an object and will have a valid object pointer,
   while parameter actions are invoked on a specific parameter, the object and
   parameter pointer will be valid.

   Instance objects and their parameters inherit the actions from the multi-instance
   object (aka the template object) and its parameters. When an instance has been
   created it is possible to set specific action implementation(s) for that instance.

   Invoking actions recursivly (that is invoking actions from within an action) is
   subject to some restrictions. As a general rule it is not possible to invoke
   actions recursively with the following exceptions:

   - Object actions can invoke parameter actions
   - Read actions (read, list, describe) and validate actions can always be
     invoked recursively.
   - Object destroy and delete instance actions can be called recursively on
     child objects (deeper in the hierarchical object tree).

   Multiple action implementations can be set for a single action.
 */

/**
   @ingroup amxd_actions
   @defgroup amxd_param_action Data Model Default Parameter Action Implementations
 */

/**
   @ingroup amxd_actions
   @defgroup amxd_object_action Data Model Default Object Action Implementations
 */


/**
   @ingroup amxd_param_action
   @brief
   Default parameter read action implementation

   Fetches the value of a parameter in the data model. The value must be set in
   the retval variant and must be of the same type as the parameter.

   @param object The data model object that contains the parameter on which the action is invoked.
   @param param The parameter on which the action is invoked
   @param reason The action reason. This should be action_param_read or action_any
                 If the reason is any other action, status amxd_status_function_not_implemented
                 must be returned.
   @param args Not used in the parameter read action
   @param retval A variant that must be filled with the current value of the parameter
   @param priv An opaque pointer (user data), that is added when the action
               callback was set. This pointer can be NULL.

   @return
   - amxd_status_ok if successful.
   - amxd_status_function_not_implemented if called for the wrong reason
   - amxd_status_unknown_error if an error occured
 */
amxd_status_t amxd_action_param_read(amxd_object_t* object,
                                     amxd_param_t* param,
                                     amxd_action_t reason,
                                     const amxc_var_t* const args,
                                     amxc_var_t* const retval,
                                     void* priv);

/**
   @ingroup amxd_param_action
   @brief
   Default parameter read action implementation for hidden values

   This parameter read action implementation will always return an empty string
   as the parameters value, unless the access is protected or private.

   This parameter read action can be used for TR181 parameters where the value
   never can be read (for public access).

   Examples of such parameters in TR181:
   - Device.WiFi.AccessPoint.{i}.Security.WEPKey
   - Device.WiFi.AccessPoint.{i}.Security.PreSharedKey
   - Device.WiFi.AccessPoint.{i}.WPS.PIN
   - Device.PPP.Interface.{i}.Password

   @param object The data model object that contains the parameter on which the action is invoked.
   @param param The parameter on which the action is invoked
   @param reason The action reason. This should be action_param_read or action_any
                 If the reason is any other action, status amxd_status_function_not_implemented
                 must be returned.
   @param args Not used in the parameter read action
   @param retval A variant that must be filled with the current value of the parameter
   @param priv An opaque pointer (user data), that is added when the action
               callback was set. This pointer can be NULL.

   @return
   - amxd_status_ok if successful.
   - amxd_status_function_not_implemented if called for the wrong reason
   - amxd_status_unknown_error if an error occured
 */
amxd_status_t amxd_action_param_read_hidden_value(amxd_object_t* object,
                                                  amxd_param_t* param,
                                                  amxd_action_t reason,
                                                  const amxc_var_t* const args,
                                                  amxc_var_t* const retval,
                                                  void* priv);

/**
   @ingroup amxd_param_action
   @brief
   Default parameter write action implementation

   Sets the value of a parameter in the data model. The value that must be set
   is available in the args variant.

   This default implementation checks:
   - that the parameter is writable
   - the new value doesn't create duplicates in multi-instance objects
     (for key parameters or unique parameters in instance objects)
   - the new value can be converted to the type of the parameter

   It will also set the read-only parameter if the parameter is an immutable key parameter.
   So an immutable key parameter can be set once.

   @param object The data model object that contains the parameter on which the action is invoked.
   @param param The parameter on which the action is invoked
   @param reason The action reason. This should be action_param_write or action_any
                 If the reason is any other action, status amxd_status_function_not_implemented
                 must be returned.
   @param args The value that must be set
   @param retval Not used in the parameter write action
   @param priv An opaque pointer (user data), that is added when the action
               callback was set. This pointer can be NULL.

   @return
   - amxd_status_ok if successful.
   - amxd_status_function_not_implemented if called for the wrong reason
   - amxd_status_invalid_value if an invalid value is provided
     (the new value can not be converted to the parameter type or the new value causes a duplicate instance)
   - amxd_status_invalid_attr if the parameter is not writable
 */
amxd_status_t amxd_action_param_write(amxd_object_t* object,
                                      amxd_param_t* param,
                                      amxd_action_t reason,
                                      const amxc_var_t* const args,
                                      amxc_var_t* const retval,
                                      void* priv);

/**
   @ingroup amxd_param_action
   @brief
   Default parameter validate action implementation

   This default implementation will only check if the new value can be converted
   to the parameter type.

   @param object The data model object that contains the parameter on which the action is invoked.
   @param param The parameter on which the action is invoked
   @param reason The action reason. This should be action_param_validate or action_any
                 If the reason is any other action, status amxd_status_function_not_implemented
                 must be returned.
   @param args The value that must be validated
   @param retval Not used in the parameter validate action
   @param priv An opaque pointer (user data), that is added when the action
               callback was set. This pointer can be NULL.

   @return
   - amxd_status_ok if the new value is valid.
   - amxd_status_function_not_implemented if called for the wrong reason
   - amxd_status_invalid_value if an invalid value is provided
     (null variant or it can not be converted to the parameter type)
 */
amxd_status_t amxd_action_param_validate(amxd_object_t* object,
                                         amxd_param_t* param,
                                         amxd_action_t reason,
                                         const amxc_var_t* const args,
                                         amxc_var_t* const retval,
                                         void* priv);

/**
   @ingroup amxd_param_action
   @brief
   Default check range parameter validate action implementation

   This default implementation checks if the new value fits in the defined range.

   The range must be defined in a variant which must be either a htable variant
   or a list variant. The variant pointer must be set as the priv data.

   When the variant is a htable variant, the minimum value must be set in the
   htable using key "min" and the maximum value must be set in the htable using
   key "max".

   When the variant is a list variant, the first value must be the minimum value
   and the second value must be maximum value.

   It is allowed to use local parameter references as minimum or maximum values.
   A local parameter reference is a full path to a parameter in the local data model.
   When local parameter references are used, the value of the referenced parameter
   is used as minimum or maximum.

   The minimum and maximum are included in the range.

   If the parameter, for which the new value must be validated, is of the type
   string (or ssv string or csv string), the length of the new value (as a string)
   must be in the range defined.

   @param object The data model object that contains the parameter on which the action is invoked.
   @param param The parameter on which the action is invoked
   @param reason The action reason. This should be action_param_validate or action_any
                 If the reason is any other action, status amxd_status_function_not_implemented
                 must be returned.
   @param args The value that must be validated
   @param retval Not used in the parameter validate action
   @param priv A pointer to a variant, containing the minimum and maximum value

   @return
   - amxd_status_ok if the new value is valid.
   - amxd_status_function_not_implemented if called for the wrong reason
   - amxd_status_invalid_value if an invalid value is provided
     (null variant or it can not be converted to the parameter type or out of range)
 */
amxd_status_t amxd_action_param_check_range(amxd_object_t* object,
                                            amxd_param_t* param,
                                            amxd_action_t reason,
                                            const amxc_var_t* const args,
                                            amxc_var_t* const retval,
                                            void* priv);

/**
   @ingroup amxd_param_action
   @brief
   Default check minimum parameter validate action implementation

   This default implementation checks if the new value is equal or higher than a minimum value.

   The minimum value must be defined in a variant which must be convertible to
   int64. The variant pointer must be set as the priv data.

   It is allowed to use local parameter references as minimum value.
   A local parameter reference is a full path to a parameter in the local data model.
   When local parameter reference is used, the value of the referenced parameter
   is used as minimum.

   If the parameter, for which the new value must be validated, is of the type
   string (or ssv string or csv string), the length of the new value (as a string)
   must be at least equal to the minimum.

   @param object The data model object that contains the parameter on which the action is invoked.
   @param param The parameter on which the action is invoked
   @param reason The action reason. This should be action_param_validate or action_any
                 If the reason is any other action, status amxd_status_function_not_implemented
                 must be returned.
   @param args The value that must be validated
   @param retval Not used in the parameter validate action
   @param priv A pointer to a variant, containing the minimum value

   @return
   - amxd_status_ok if the new value is valid.
   - amxd_status_function_not_implemented if called for the wrong reason
   - amxd_status_invalid_value if an invalid value is provided
     (null variant or it can not be converted to the parameter type or below minimum)
 */
amxd_status_t amxd_action_param_check_minimum(amxd_object_t* object,
                                              amxd_param_t* param,
                                              amxd_action_t reason,
                                              const amxc_var_t* const args,
                                              amxc_var_t* const retval,
                                              void* priv);

/**
   @ingroup amxd_param_action
   @brief
   Default check maximum parameter validate action implementation

   This default implementation checks if the new value is equal or lower than a maximum value.

   The maximum value must be defined in a variant which must be convertible to
   int64. The variant pointer must be set as the priv data.

   It is allowed to use local parameter references as maximum value.
   A local parameter reference is a full path to a parameter in the local data model.
   When local parameter reference is used, the value of the referenced parameter
   is used as maximum.

   If the parameter, for which the new value must be validate, is of the type
   string (or ssv string or csv string), the length of the new value (as a string)
   must be at less or equal to the maximum.

   @param object The data model object that contains the parameter on which the action is invoked.
   @param param The parameter on which the action is invoked
   @param reason The action reason. This should be action_param_validate or action_any
                 If the reason is any other action, status amxd_status_function_not_implemented
                 must be returned.
   @param args The value that must be validated
   @param retval Not used in the parameter validate action
   @param priv A pointer to a variant, containing the maximum value

   @return
   - amxd_status_ok if the new value is valid.
   - amxd_status_function_not_implemented if called for the wrong reason
   - amxd_status_invalid_value if an invalid value is provided
     (null variant or it can not be converted to the parameter type or higher then maximum)
 */
amxd_status_t amxd_action_param_check_maximum(amxd_object_t* object,
                                              amxd_param_t* param,
                                              amxd_action_t reason,
                                              const amxc_var_t* const args,
                                              amxc_var_t* const retval,
                                              void* priv);

/**
   @ingroup amxd_param_action
   @brief
   Default check enum parameter validate action implementation

   This default implementation checks if the new value is in a list of allowed values.

   The allowed value must be defined in as a list variant which contains all
   possible values. The variant pointer must be set as the priv data.

   If the new value is a comma or space separated string of values, then each
   value must be in the list of possible values.

   @param object The data model object that contains the parameter on which the action is invoked.
   @param param The parameter on which the action is invoked
   @param reason The action reason. This should be action_param_validate or action_any
                 If the reason is any other action, status amxd_status_function_not_implemented
                 must be returned.
   @param args The value that must be validated
   @param retval Not used in the parameter validate action
   @param priv A pointer to a variant, containing the a variant list of allowed values

   @return
   - amxd_status_ok if the new value is valid.
   - amxd_status_function_not_implemented if called for the wrong reason
   - amxd_status_invalid_value if an invalid value is provided
     (null variant or it can not be converted to the parameter type or not an allowed values)
 */
amxd_status_t amxd_action_param_check_enum(amxd_object_t* object,
                                           amxd_param_t* param,
                                           amxd_action_t reason,
                                           const amxc_var_t* const args,
                                           amxc_var_t* const retval,
                                           void* priv);

/**
   @ingroup amxd_param_action
   @brief
   Default check is in parameter validate action implementation

   This default implementation checks if the new value is in a list of possible
   values. The list of possible values is fetched from a parameter in the local
   data model. The referenced parameter path is provided as a string variant.
   The pointer to the string variant is provided as the private data.

   If the referenced parameter, that contains the list of valid values, is an empty
   string, any value is accepted.

   @param object The data model object that contains the parameter on which the action is invoked.
   @param param The parameter on which the action is invoked
   @param reason The action reason. This should be action_param_validate or action_any
                 If the reason is any other action, status amxd_status_function_not_implemented
                 must be returned.
   @param args The value that must be validated
   @param retval Not used in the parameter validate action
   @param priv A pointer to a string variant, containing the path to a parameter
               that contains the list of possible values (as a csv or ssv string)

   @return
   - amxd_status_ok if the new value is valid.
   - amxd_status_function_not_implemented if called for the wrong reason
   - amxd_status_invalid_value if an invalid value is provided
     (null variant or it can not be converted to the parameter type or not an allowed values)
 */
amxd_status_t amxd_action_param_check_is_in(amxd_object_t* object,
                                            amxd_param_t* param,
                                            amxd_action_t reason,
                                            const amxc_var_t* const args,
                                            amxc_var_t* const retval,
                                            void* priv);

void amxd_param_build_description(amxc_var_t* description,
                                  const char* name,
                                  uint32_t type_id,
                                  uint32_t attrs,
                                  amxc_var_t* flags);

/**
   @ingroup amxd_param_action
   @brief
   Default parameter describe action implementation

   This action is mainly invoked for introspection purposes. It will create
   an htable variant, containing all the parameter attributes, user flags, parameter
   name, parameter type id and parameter type name.

   In most cases, unless `no-param-value` is set in the arguments, the parameter
   value is available as well.

   For this action the args must be NULL or a htable variant and may contain the following
   parameters in the htable:
   - no-param-value - boolean

   When `no-param-value` is set to true, the parameter value is not provided in the
   returned htable variant.

   The resulting htable variant will be set in the `retval`. The retval htable will contain:
   - the parameter attributes (`attributes`) as a htable variant, in which each
     attribute is represented as a boolean value, where the key is the name
     of the attribute, and the value is a boolean, set to true if the attribute
     is set for the parameter.
   - the parameter user flags ('flags') as a list variant, in which each user
     flag is represented as a string variant.
   - the name of the parameter (`name`) as a string variant
   - the parameter type id (`type_id`) as an integer
   - the parameter type name (`type_name`) as a string
   - the parameter value (`value`), a variant with the same type as the parameter definition

   Example of a retval:
   @code
   {
       attributes = {
           counter = false,
           instance = false,
           key = false,
           mutable = false,
           persistent = false
           private = false,
           protected = false,
           read-only = false,
           template = false,
           unique = false,
           volatile = false,
       },
       flags = [
       ],
       name = "Configured",
       type_id = 12
       type_name = "bool",
       value = true,
   }
   @endcode

   @param object The data model object that contains the parameter on which the action is invoked.
   @param param The parameter on which the action is invoked
   @param reason The action reason. This should be action_param_describe or action_any
                 If the reason is any other action, status amxd_status_function_not_implemented
                 must be returned.
   @param args NULL or a variant that is a htable variant
   @param retval The parameter describe result, which is a htable variant.
   @param priv Not used in the parameter describe action

   @return
   - amxd_status_ok if successful.
   - amxd_status_function_not_implemented if called for the wrong reason
 */
amxd_status_t amxd_action_param_describe(amxd_object_t* object,
                                         amxd_param_t* param,
                                         amxd_action_t reason,
                                         const amxc_var_t* const args,
                                         amxc_var_t* const retval,
                                         void* priv);

/**
   @ingroup amxd_param_action
   @brief
   Default parameter destroy action implementation

   This action is invoked when the parameter is removed from the data model.
   This action should never fail, it should either return amxd_status_ok or
   amxd_status_function_not_implemented if called for the wrong reason.

   The parameter pointer becomes invalid when returning from this action implementation,
   as it will be deleted from memory and removed from the data model.

   When adding private data to the parameter pointer, this action provides you
   with the possiblity to do some clean-up (like deleting the private data).

   The default implementation is doing nothing.

   @param object The data model object that contains the parameter on which the action is invoked.
   @param param The parameter on which the action is invoked
   @param reason The action reason. This should be action_param_destroy or action_any
                 If the reason is any other action, status amxd_status_function_not_implemented
                 must be returned.
   @param args Not used in the parameter destroy action
   @param retval Not used in the parameter destroy action
   @param priv Not used in the parameter destroy action

   @return
   - amxd_status_ok if successful.
   - amxd_status_function_not_implemented if called for the wrong reason
 */
amxd_status_t amxd_action_param_destroy(amxd_object_t* object,
                                        amxd_param_t* param,
                                        amxd_action_t reason,
                                        const amxc_var_t* const args,
                                        amxc_var_t* const retval,
                                        void* priv);

/**
   @ingroup amxd_object_action
   @brief
   Default object list action implementation

   This action is mainly invoked for introspection purposes.

   For this action the args must be a htable variant and may contain the following
   parameters in the htable:
   - events - boolean (default = true)
   - functions - boolean (default = true)
   - instances - boolean (default = true) - only applicable on multi-instance objects
   - objects - boolean (default = true)
   - parameters - boolean (default = true)
   - template_info - boolean (default = true) - only applicable on multi-instance objects
   - access - integer (default = amxd_dm_access_public)

   All these are optional, when the boolean parameters are not available, true is
   used as the default value.

   The access parameter, when not available, will be set to amxd_dm_access_public

   The return value will be a htable variant, containing list variants for each requested
   and available topic. The returned htable variant must contain:
   - a list of events, if any available and the events input argument is set to true.
   - a list of functions, if any available and the functions input argument is set to true.
   - a list of instances, if any available and the instances input argument is set to true.
   - a list of objects, if any available and the objects input argument is set to true.
   - a list of parameters, if any available and the parameters input argument is set to true

   When access is set to amxd_dm_access_public, only parameters and objects defined
   as public must be added to the lists. If access is set to amxd_dm_access_protected,
   parameters and objects defined as protected must be added to the lists.

   When template_info is set to true, all parameters, functions and objects defined
   in the multi-instance object must be added to the lists.

   Example of input arguments htable
   @code
   args = {
      access = amxd_dm_access_protected,
      events = false,
      functions = true,
      instances = true,
      objects = true,
      parameters = true,
      template_info = false
   }
   @endcode

   Example of retval htable
   @code
   retval =
   {
       functions = [
           "_list",
           "_describe",
           "_get",
           "_get_instances",
           "_get_supported",
           "_set",
           "_add",
           "_del",
           "_exec"
       ],
       objects = [
           "MyTemplateObject"
       ],
       parameters = [
           "Configured"
       ]
   }
   @endcode

   @param object The data model object on which the action is invoked.
   @param param For object actions this is always NULL
   @param reason The action reason. This should be action_object_list or action_any
                 If the reason is any other action, status amxd_status_function_not_implemented
                 must be returned.
   @param args A variant containing the action arguments
   @param retval A variant that must be filled with the action return data
   @param priv An opaque pointer (user data), that is added when the action
               callback was set. This pointer can be NULL.

   @return
   - amxd_status_ok if successful.
   - amxd_status_function_not_implemented if called for the wrong reason
   - amxd_status_invalid_function_argument if the args is not a htable variant
   - amxd_status_object_not_found if the object can not be accessed
 */
amxd_status_t amxd_action_object_list(amxd_object_t* const object,
                                      amxd_param_t* const param,
                                      amxd_action_t reason,
                                      const amxc_var_t* const args,
                                      amxc_var_t* const retval,
                                      void* priv);

/**
   @ingroup amxd_object_action
   @brief
   Default object describe action implementation

   This action is mainly invoked for introspection purposes.

   For this action the args must be a htable variant and may contain the following
   parameters in the htable:
   - events - boolean (default = true)
   - functions - boolean (default = true)
   - instances - boolean (default = true) - only applicable on multi-instance objects
   - objects - boolean (default = true)
   - parameters - boolean (default = true)
   - template_info - boolean (default = true) - only applicable on multi-instance objects
   - access - integer (default = amxd_dm_access_public)
   - no-param-value - boolean (default = false)

   All these are optional, when the boolean parameters are not available, true is
   used as the default value.

   The access parameter, when not available, will be set to amxd_dm_access_public

   The return value will be a htable variant. The return value is put in the `retval`
   argument and can contain:
   - the object attributes (`attributes`) as a htable variant
   - the object name (`name`) as a string
   - the object path (name notation `object`) as a string
   - the object path (index notation `path`) as a string
   - the list of sub-objects (`objects`) as a list variant
   - the list of parameters (`parameters`) as a htable variant, each parameter
     is represented as a htable where the key is the parameter value and the
     value is the parameter description.
   - the object type id ('type_id') as an integer
   - the object type name ('type_name') as a string

   When access is set to amxd_dm_access_public, only parameters and objects defined
   as public are added to the description. If access is set to amxd_dm_access_protected,
   parameters and objects defined as protected are added to the description.

   When template_info is set to true, all parameters, functions and objects defined
   in the multi-instance object are added to the description.

   Example of input arguments htable
   @code
   args = {
      access = amxd_dm_access_protected,
      events = false,
      functions = true,
      instances = true,
      objects = true,
      parameters = true,
      template_info = false
   }
   @endcode

   Example of retval htable
   @code
   retval =
   {
      attributes = {
          locked = false,
          persistent = false
          private = false,
          protected = false,
          read-only = false,
      },
      name = "MyRootObject",
      object = "MyRootObject.",
      objects = [
          "MyTemplateObject"
      ],
      parameters = {
          Configured = {
              attributes = {
                  counter = false,
                  instance = false,
                  key = false,
                  mutable = false,
                  persistent = false
                  private = false,
                  protected = false,
                  read-only = false,
                  template = false,
                  unique = false,
                  volatile = false,
              },
              flags = [
              ],
              name = "Configured",
              type_id = 12
              type_name = "bool",
              value = true,
          }
      }
      path = "MyRootObject.",
      type_id = 1,
      type_name = "singleton",
   }
   @endcode

   @param object The data model object on which the action is invoked.
   @param param For object actions this is always NULL
   @param reason The action reason. This should be action_object_describe or action_any
                 If the reason is any other action, status amxd_status_function_not_implemented
                 must be returned.
   @param args A variant containing the action arguments
   @param retval A variant that must be filled with the action return data
   @param priv An opaque pointer (user data), that is added when the action
               callback was set. This pointer can be NULL.

   @return
   - amxd_status_ok if successful.
   - amxd_status_function_not_implemented if called for the wrong reason
   - amxd_status_invalid_function_argument if the args is not a htable variant
   - amxd_status_object_not_found if the object can not be accessed
 */
amxd_status_t amxd_action_object_describe(amxd_object_t* object,
                                          amxd_param_t* param,
                                          amxd_action_t reason,
                                          const amxc_var_t* const args,
                                          amxc_var_t* const retval,
                                          void* priv);

amxd_status_t amxd_action_object_read_filter(amxc_string_t* filter,
                                             const amxc_var_t* args);

amxd_status_t amxd_action_object_read(amxd_object_t* const object,
                                      amxd_param_t* const param,
                                      amxd_action_t reason,
                                      const amxc_var_t* const args,
                                      amxc_var_t* const retval,
                                      void* priv);

amxd_status_t amxd_action_object_write(amxd_object_t* const object,
                                       amxd_param_t* const param,
                                       amxd_action_t reason,
                                       const amxc_var_t* const args,
                                       amxc_var_t* const retval,
                                       void* priv);

amxd_status_t amxd_action_object_add_inst(amxd_object_t* const object,
                                          amxd_param_t* const param,
                                          amxd_action_t reason,
                                          const amxc_var_t* const args,
                                          amxc_var_t* const retval,
                                          void* priv);

amxd_status_t amxd_action_object_del_inst(amxd_object_t* const object,
                                          amxd_param_t* const param,
                                          amxd_action_t reason,
                                          const amxc_var_t* const args,
                                          amxc_var_t* const retval,
                                          void* priv);

/**
   @ingroup amxd_object_action
   @brief
   Default object destroy action implementation

   This action is invoked when the object is removed from the data model.
   This action should never fail, it should either return amxd_status_ok or
   amxd_status_function_not_implemented if called for the wrong reason.

   The object pointer becomes invalid when returning from this action implementation,
   as it will be deleted from memory and removed from the data model.

   When adding private data to the object pointer, this action provides you
   with the possiblity to do some clean-up (like deleting the private data).

   The default implementation is doing nothing.

   @param object The data model object on which the action is invoked.
   @param param For object actions this is always NULL
   @param reason The action reason. This should be action_object_destroy or action_any
                 If the reason is any other action, status amxd_status_function_not_implemented
                 must be returned.
   @param args Not used in the object destroy action
   @param retval Not used in the object destroy action
   @param priv An opaque pointer (user data), that is added when the action
               callback was set. This pointer can be NULL.

   @return
   - amxd_status_ok if successful.
   - amxd_status_function_not_implemented if called for the wrong reason
 */
amxd_status_t amxd_action_object_destroy(amxd_object_t* object,
                                         amxd_param_t* const param,
                                         amxd_action_t reason,
                                         const amxc_var_t* const args,
                                         amxc_var_t* const retval,
                                         void* priv);

/**
   @ingroup amxd_object_action
   @brief
   Default object validate action implementation

   This default implementation will check for instances that no duplicate instance
   is created. It will check that the key parameters are not introducing a duplicate
   key with other instances of the same multi-instance object.

   For singleton objects this validate action is doing nothing.

   @param object The data model object on which the action is invoked.
   @param param For object actions this is always NULL
   @param reason The action reason. This should be action_object_validate or action_any
                 If the reason is any other action, status amxd_status_function_not_implemented
                 must be returned.
   @param args Not used in the object validate action
   @param retval Not used in the object validate action
   @param priv An opaque pointer (user data), that is added when the action
               callback was set. This pointer can be NULL.

   @return
   - amxd_status_ok if the object is valid.
   - amxd_status_function_not_implemented if called for the wrong reason
 */
amxd_status_t amxd_action_object_validate(amxd_object_t* const object,
                                          amxd_param_t* const param,
                                          amxd_action_t reason,
                                          const amxc_var_t* const args,
                                          amxc_var_t* const retval,
                                          void* priv);
#ifdef __cplusplus
}
#endif

#endif // __AMXD_ACTION_H__

