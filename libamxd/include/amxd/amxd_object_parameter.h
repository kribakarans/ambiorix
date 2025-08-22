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

#if !defined(__AMXD_OBJECT_PARAMETER_H__)
#define __AMXD_OBJECT_PARAMETER_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>
#include <amxd/amxd_types.h>
#include <amxd/amxd_parameter.h>

/**
   @ingroup amxd_object
   @defgroup amxd_object_parameters Parameters
 */

/**
   @ingroup amxd_object_parameters
   @brief
   Helper macro for setting a value

   This helper macro sets a value for a certain parameter

   @param type the data type, must be a valid parameter type,
               or must be convertable to a valid parameter type
   @param object pointer to a data model object
   @param name parameter name
   @param value the new value, must match the given type
 */
#define amxd_object_set_value(type, object, name, value) \
    amxd_object_set_ ## type(object, name, value)

/**
   @ingroup amxd_object_parameters
   @brief
   Helper macro for getting a value

   This helper macro gets a value, using a type indicator

   @param type the data type that must be returned
   @param object pointer to a data model object
   @param name parameter name
   @param status optional pointer to a amxd_status_t or NULL
 */
#define amxd_object_get_value(type, object, name, status) \
    amxd_object_get_ ## type(object, name, status)

/**
   @ingroup amxd_object_parameters
   @brief
   Adds a parameter definition to an object

   The parameter definition can be created using @ref amxd_param_new.

   Adding the parameter definition to an object fails when:
   - The parameter definition was already added to an object
   - The @ref amxd_oattr_locked atrtribute was set on the object
   - The parameter definition is a key parameter and the object is a mult-instance
     object with instances, is an instance object, is a singleton object,  is
     a mib definition.
   - The object contains already a parameter with the same name

   When adding a parameter definition to a multi-instance object or an instance
   object and none of the following parameters attributes are set:
   - @ref amxd_pattr_instance
   - @ref amxd_pattr_template
   The @ref amxd_pattr_instance attribute is set automatically.

   @param object pointer to a data model object, the parameter definition is
                 added to this object
   @param param pointer to the parameter definition

   @return
   - amxd_status_ok: parameter definition is added to the data model object
   - amxd_status_duplicate: parameter definition can not be added, another
                            parameter exists with the same name
   - amxd_status_invalid_attr: parameter can not be added because the object
                               and parameter attributes do not match
   - amxd_status_unknown_error: any other error
 */
amxd_status_t amxd_object_add_param(amxd_object_t* const object,
                                    amxd_param_t* const param);

/**
   @ingroup amxd_object_parameters
   @brief
   Gets a parameter definition from an object

   @param object pointer to a data model object
   @param name name of the parameter

   @return
   a pointer to a parameter definition or NULL if no parameter definition is
   found for the given name.
 */
amxd_param_t* amxd_object_get_param_def(const amxd_object_t* const object,
                                        const char* name);


/**
   @ingroup amxd_object_get_param_counter_by_counted_object
   @brief
   Gets a parameter definition associated with a counted object

   @param object pointer to a data model object representing the counted object

   @return
   a pointer to a parameter definition or NULL if no parameter definition is
   found for the given counted object.
 */
amxd_param_t* amxd_object_get_param_counter_by_counted_object(const amxd_object_t* const object);


/**
   @ingroup amxd_object_parameters
   @brief
   Sets a value for a parameter in a data model object

   When the type of the new value doesn't match the type of the parameter
   definition, the new value is converted to the type of the parameter.

   This function invokes an @ref action_object_write and can change read-only
   parameters or private and protected parameters.

   The default implementation of the @ref action_object_write will set the new
   value if possible. The following sets are not allowed and will fail:
   - set a value of an instance parameter on a multi-instance object
   - set a value of a template parameter on a instance object.

   The new parameter value is also validated, the @ref action_param_validate is
   invoked before applying the value to the parameter. The set fails if the
   provided value is not valid for the parameter.

   The behavior of this function depends on the implementation of
   - action @ref action_object_write for the given object
   - action @ref action_param_validate for the given parameter definition

   @note
   No object validation is done, it is the responsibility of the caller of this
   function to check if the object is valid after setting the value.

   As an alternative to set a single parameter value of an object the macro
   @ref amxd_object_set_value can be used.

   @param object pointer to a data model object
   @param name name of the parameter
   @param value the new value

   @return
   amxd_status_ok when the new value is set correctly.
 */
amxd_status_t amxd_object_set_param(amxd_object_t* const object,
                                    const char* name,
                                    amxc_var_t* const value);

/**
   @ingroup amxd_object_parameters
   @brief
   Sets multiple parameter values in a data model object

   The behavior of this function is the same as @ref amxd_object_set_param.
   The only differences is that the value arguments is a variant containing
   a hash table where the keys are considered parameter names.

   When the object is a template object, it is possible to pass for each instance
   or some instances a separate hash table as value in the top level table, the
   key must be the name of the instance.

   When a parameter or instance is not found the function fails.

   @param object pointer to a data model object
   @param values a variant containing a hash table where the keys are the
                 parameter names and the values the new values for the
                 parameters.

   @return
   amxd_status_ok when the new value is set correctly.
 */
amxd_status_t amxd_object_set_params(amxd_object_t* const object,
                                     amxc_var_t* const values);

/**
   @ingroup amxd_object_parameters
   @brief
   Gets a single parameter value

   This function invokes an @ref action_object_read and can read private and
   protected parameters.

   The default implementation of the @ref action_object_read will fetch the real
   value of the paranmeter.

   The @ref action_object_read implementation can be overriden.

   As an alternative to get a single parameter value of an object the macro
   @ref amxd_object_get_value can be used.

   @param object pointer to a data model object
   @param name the name of the parameter
   @param value an initialized variant, the value of the parameter will be
                copied in this variant.

   @return
   amxd_status_ok when the new value is set correctly.
 */
amxd_status_t amxd_object_get_param(amxd_object_t* const object,
                                    const char* name,
                                    amxc_var_t* const value);

/**
   @ingroup amxd_object_parameters
   @brief
   Gets the variant in which the parameter value is stored.

   This function will return the pointer to the amxc_var_t structure in which
   the value of the parameter is stored.

   @param object pointer to a data model object
   @param name the name of the parameter

   @return
   The pointer to the variant containing the parameters value or NULL if the
   object doesn't contain a parameter with the given name.
 */
const amxc_var_t* amxd_object_get_param_value(const amxd_object_t* const object,
                                              const char* name);

/**
   @ingroup amxd_object_parameters
   @brief
   Gets all parameter values of an object.

   This function invokes an @ref action_object_read and can read private and
   protected parameters, depending on the provided access value.

   The default implementation of the @ref action_object_read will fetch the real
   value of the paranmeters.

   The @ref action_object_read implementation can be overriden.

   A provided variant will be initialized to a variant containing a hash table.
   For each parameter a key - value pair is added, The key is the parameter name
   and the value is the parameter value. The type is matching the parameter
   type.

   Using the access value, it is possible to filter out some parameters.
   When providing @ref amxd_dm_access_public, no private or protected parameters
   are returned, when using @ref amxd_dm_access_protected no private parameters
   are returned.

   @param object pointer to a data model object
   @param params an initialized variant, the variant will be initialized to the
                 hash table type, the value of the parameters will be
                 copied in this hash table.
   @param access can be set to @ref amxd_dm_access_public, @ref amxd_dm_access_protected,
                 or @ref amxd_dm_access_private

   @return
   amxd_status_ok when the new value is set correctly.
 */
amxd_status_t amxd_object_get_params(amxd_object_t* const object,
                                     amxc_var_t* const params,
                                     amxd_dm_access_t access);

amxd_status_t amxd_object_get_params_with_attr(amxd_object_t* const object,
                                               amxc_var_t* const params,
                                               uint32_t attrs,
                                               amxd_dm_access_t access);

amxd_status_t amxd_object_get_params_filtered(amxd_object_t* const object,
                                              amxc_var_t* const params,
                                              const char* filter,
                                              amxd_dm_access_t access);

amxd_status_t amxd_object_get_key_params(amxd_object_t* const object,
                                         amxc_var_t* const params,
                                         amxd_dm_access_t access);

amxd_status_t amxd_object_list_params(amxd_object_t* const object,
                                      amxc_var_t* const list,
                                      amxd_dm_access_t access);

amxd_status_t amxd_object_describe_params(amxd_object_t* const object,
                                          amxc_var_t* const value,
                                          amxd_dm_access_t access);

amxd_status_t amxd_object_describe_key_params(amxd_object_t* const object,
                                              amxc_var_t* const value,
                                              amxd_dm_access_t access);

uint32_t amxd_object_get_param_count(amxd_object_t* object,
                                     amxd_dm_access_t access);


// helper functions
amxd_status_t amxd_object_set_cstring_t(amxd_object_t* const object,
                                        const char* name,
                                        const char* value);

amxd_status_t amxd_object_set_csv_string_t(amxd_object_t* const object,
                                           const char* name,
                                           const char* value);

amxd_status_t amxd_object_set_ssv_string_t(amxd_object_t* const object,
                                           const char* name,
                                           const char* value);

amxd_status_t amxd_object_set_bool(amxd_object_t* const object,
                                   const char* name,
                                   bool value);


amxd_status_t amxd_object_set_int8_t(amxd_object_t* const object,
                                     const char* name,
                                     int8_t value);

amxd_status_t amxd_object_set_uint8_t(amxd_object_t* const object,
                                      const char* name,
                                      uint8_t value);

amxd_status_t amxd_object_set_int16_t(amxd_object_t* const object,
                                      const char* name,
                                      int16_t value);

amxd_status_t amxd_object_set_uint16_t(amxd_object_t* const object,
                                       const char* name,
                                       uint16_t value);

amxd_status_t amxd_object_set_int32_t(amxd_object_t* const object,
                                      const char* name,
                                      int32_t value);

amxd_status_t amxd_object_set_uint32_t(amxd_object_t* const object,
                                       const char* name,
                                       uint32_t value);

amxd_status_t amxd_object_set_int64_t(amxd_object_t* const object,
                                      const char* name,
                                      int64_t value);

amxd_status_t amxd_object_set_uint64_t(amxd_object_t* const object,
                                       const char* name,
                                       uint64_t value);

amxd_status_t amxd_object_set_double(amxd_object_t* const object,
                                     const char* name,
                                     double value);

amxd_status_t amxd_object_set_amxc_ts_t(amxd_object_t* const object,
                                        const char* name,
                                        amxc_ts_t* value);

char* amxd_object_get_cstring_t(amxd_object_t* const object,
                                const char* name,
                                amxd_status_t* status);

bool amxd_object_get_bool(amxd_object_t* const object,
                          const char* name,
                          amxd_status_t* status);

int8_t amxd_object_get_int8_t(amxd_object_t* const object,
                              const char* name,
                              amxd_status_t* status);

uint8_t amxd_object_get_uint8_t(amxd_object_t* const object,
                                const char* name,
                                amxd_status_t* status);

int16_t amxd_object_get_int16_t(amxd_object_t* const object,
                                const char* name,
                                amxd_status_t* status);

uint16_t amxd_object_get_uint16_t(amxd_object_t* const object,
                                  const char* name,
                                  amxd_status_t* status);

int32_t amxd_object_get_int32_t(amxd_object_t* const object,
                                const char* name,
                                amxd_status_t* status);

uint32_t amxd_object_get_uint32_t(amxd_object_t* const object,
                                  const char* name,
                                  amxd_status_t* status);

int64_t amxd_object_get_int64_t(amxd_object_t* const object,
                                const char* name,
                                amxd_status_t* status);

uint64_t amxd_object_get_uint64_t(amxd_object_t* const object,
                                  const char* name,
                                  amxd_status_t* status);

double amxd_object_get_double(amxd_object_t* const object,
                              const char* name,
                              amxd_status_t* status);

amxc_ts_t* amxd_object_get_amxc_ts_t(amxd_object_t* const object,
                                     const char* name,
                                     amxd_status_t* status);

#ifdef __cplusplus
}
#endif

#endif // __AMXD_OBJECT_PARAMETER_H__

