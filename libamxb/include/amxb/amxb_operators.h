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

#if !defined(__AMXB_OPERATORS_H__)
#define __AMXB_OPERATORS_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <amxb/amxb_types.h>


/**
   @file
   @brief
   Ambiorix Bus Agnostic Data Model Operators API
 */

/**
   @ingroup amxb_baapi
   @defgroup amxb_operator Data Model Operators
 */

#define AMXB_FLAG_PARAMETERS    0x0001
#define AMXB_FLAG_FUNCTIONS     0x0002
#define AMXB_FLAG_EVENTS        0x0004
#define AMXB_FLAG_OBJECTS       0x0008
#define AMXB_FLAG_INSTANCES     0x0010
#define AMXB_FLAG_FIRST_LVL     0x0020
#define AMXB_FLAG_NAMED         0x0040
#define AMXB_FLAG_EXISTS        0x0080
#define AMXB_FLAG_TEMPLATE_INFO 0x0100
#define AMXB_FLAG_PARTIAL       0x0200
#define AMXB_FLAG_PROTECTED     0x0400

/**
   @ingroup amxb_operator
   @brief
   Invokes a data model function

   Calls a data model method. A data model method is a function that is exposed
   in the data model in a specific object.

   The arguments passed must be in a amxc variant of type AMXC_VAR_ID_HTABLE.
   The order of the arguments is not important.

   This function makes uses of @ref amxb_new_invoke and @ref amxb_invoke.

   If no response is received before the timeout expires, this function will
   return an error, but it is possible that the RPC method is still busy.

   @param bus_ctx The bus context (or connection)
   @param object object path to the object that contains the function,
                 object paths must end with a "."
   @param method name of the function being called
   @param args the function arguments in a amxc variant htable type
   @param ret will contain the return value(s) and/or the out arguments
   @param timeout in seconds

   @return
   amxd_status_ok remote function has completed successful
 */
int amxb_call(amxb_bus_ctx_t* const bus_ctx,
              const char* object,
              const char* method,
              amxc_var_t* args,
              amxc_var_t* ret,
              int timeout);

/**
   @ingroup amxb_operator
   @brief
   Invokes a data model function

   Calls a data model method. A data model method is a function that is exposed
   in the data model in a specific object.

   The arguments passed must be in a amxc variant of type AMXC_VAR_ID_HTABLE.
   The order of the arguments is not important.

   This function makes uses of @ref amxb_new_invoke and @ref amxb_async_invoke.

   When the method call fails, the done function is called with NULL as amxb_request_t
   and the status will be the failure status.

   The returned amxb_request_t pointer can be used with @ref amxb_wait_for_request
   to wait until the method call is finished.

   The returned pointer must be freed with @ref amxb_close_request. After calling
   @ref amxb_close_request, the callback function will not be called anymore.

   @param bus_ctx The bus context (or connection)
   @param object object path to the object that contains the function,
                 object paths must end with a "."
   @param method name of the function being called
   @param args the function arguments in a amxc variant htable type
   @param done_fn a done callback function
   @param priv private data that will be passed to the callback function (optional,
               can be NULL)

   @return
   returns an amxb_request_t pointer or NULL when failed to call the method.
 */
amxb_request_t* amxb_async_call(amxb_bus_ctx_t* const bus_ctx,
                                const char* object,
                                const char* method,
                                amxc_var_t* args,
                                amxb_be_done_cb_fn_t done_fn,
                                void* priv);


/**
   @ingroup amxb_operator
   @brief
   Fetches one or more objects or a single parameter.

   Using this method, the parameter values of an object can be retrieved.

   It is possible to get the parameters from multiple objects at once or to get
   one single parameter of one or more objects.

   This function supports following paths:

   - object path - must end with a "."
   - search path - can contain expressions or wildcard to filter out instances.
                   they can end with a parameter name, a "." or a "*"
   - parameter path - must end with a parameter name (no "." at the end)

   In a search path a wildcard "*" or an expression can be put where an instance
   identifier (instance index) is in an object path.

   Examples of valid search paths:
   @code{.c}
   "Phonebook.Contact.*."
   "Phonebook.Contact.*"
   "Phonebook.Contact.[FirstName == 'Jane']."
   "Phonebook.Contact.*.FirstName"
   "Device.IP.Interface.[Type=='Normal'].IPv4Address.[AddressingType=='Static'].IPAddress"
   "Device.IP.Interface.[Type=='Normal' && Stats.ErrorsSent>0].IPv4Address.[AddressingType=='Static'].IPAddress"
   @endcode

   The return value of a get is always an Ambiorix variant:
   @code{.c}
   [
      {
          Phonebook.Contact.1. = {
              FirstName = "John"
              LastName = "Doe",
          },
          Phonebook.Contact.2. = {
              FirstName = "Jane"
              LastName = "Doe",
          },
          Phonebook.Contact.3. = {
              FirstName = "Eva"
              LastName = "Elliott",
          }
      }
   ]
   @endcode

   @param bus_ctx The bus context (or connection)
   @param object Full object path, search path or parameter path
   @param depth relative depth, if not zero it indicates how many levels of child objects are returned
   @param ret will contain the objects and their parameters
   @param timeout in seconds

   @return
   amxd_status_ok when successful, any other value indicates an error.
 */
int amxb_get(amxb_bus_ctx_t* const bus_ctx,
             const char* object,
             int32_t depth,
             amxc_var_t* ret,
             int timeout);

/**
   @ingroup amxb_operator
   @brief
   Fetches one or more objects and their parameters that are matching a filter.

   Using this method, the parameter values of an object can be retrieved.
   This function works exactly the same as @ref amxb_get, but can filter the
   parameters of an object on the meta-data.

   For more details see @ref amxb_get.

   The meta-data of the parameters can be retrieved using @ref amxb_describe.
   If a filter is provided, the filter will be evaluated on the meta-data of the
   parameters, only matching parameters will be available in the result data.

   Example of parameter meta-data:
   @code
   attributes = {
        counter = 1,
        instance = 0,
        key = 0,
        mutable = 0,
        persistent = 0,
        private = 0,
        protected = 0,
        read-only = 1,
        template = 0,
        unique = 0,
        volatile = 0
   },
   flags = [
   ],
   name = "NumberOfHistoryEntries",
   type_id = 8,
   type_name = "uint32_t",
   value = 1
   @endcode

   Example of a filter:
   @code
   "attributes.persistent==true || 'usersetting' in flags"
   @endcode
   The above filter example will only return parameters that have the persistent
   attribute set or have the flag "usersetting", all other parameters will be
   filtered out.

   If no filter (NULL or empty string) is provided, this function will return exactly
   the same as @ref amxb_get.

   @warning
   It is possible that a bus/protocol backend  doesn't have support for filtering
   parameters. When this functionality is not available by the used backend, the
   filter is ignored and this function will return exactly the same as @ref amxb_get.

   @param bus_ctx The bus context (or connection)
   @param object Full object path, search path or parameter path
   @param filter Logical filter expression, only matching parameters are returned.
   @param depth relative depth, if not zero it indicates how many levels of child objects are returned
   @param ret will contain the objects and their parameters
   @param timeout in seconds

   @return
   amxd_status_ok when successful, any other value indicates an error.
 */
int amxb_get_filtered(amxb_bus_ctx_t* const bus_ctx,
                      const char* object,
                      const char* filter,
                      int32_t depth,
                      amxc_var_t* ret,
                      int timeout);

/**
   @ingroup amxb_operator
   @brief
   Fetches one or more (root) objects  or multiple parameters.

   It is possible to get the parameters from multiple objects at once or to get
   one single parameter of one or more objects.

   This function supports an amxc linked list with paths, each path must follow these rules:

   - object path - must end with a "."
   - search path - can contain expressions or wildcard to filter out instances.
                   they can end with a parameter name, a "." or a "*"
   - parameter path - must end with a parameter name (no "." at the end)

   In a search path a wildcard "*" or an expression can be put where an instance
   identifier (instance index) is in an object path.

   Examples of valid use case:
   @code{.c}
   amxc_var_t paths;
   amxc_var_init(&paths);
   amxc_var_set_type(&paths, AMXC_VAR_ID_LIST);
   amxc_var_add(cstring_t, &paths, "Phonebook.Contact.1.FirstName");
   amxc_var_add(cstring_t, &paths, "Phonebook.Contact.2.");
   amxc_var_add(cstring_t, &paths, "Phonebook.Contact.*");
   amxc_var_add(cstring_t, &paths, "Phonebook.Contact.[FirstName == 'Jane'].");
   amxc_var_add(cstring_t, &paths, "Device.IP.Interface.[Type=='Normal'].IPv4Address.[AddressingType=='Static'].IPAddress");

   amxb_get_multiple(bus_ctx, &paths, 0, &ret, 5);
   @endcode

   The return value of a get_multiple is always an Ambiorix htable variant containing the individual responses from amxb_get for each path:
   @code{.c}
   {
    Device.IP.Interface.[Type=='Normal'].IPv4Address.[AddressingType=='Static'].IPAddress = {
        result = [
            {
            }
        ],
        status = 2
    },
    Phonebook.Contact.* = {
        result = [
            {
                Phonebook.Contact.1. = {
                    FirstName = "John"
                    LastName = "Doe",
                },
                Phonebook.Contact.2. = {
                    FirstName = "Pony"
                    LastName = "Goffin",
                }
            }
        ],
        status = 0
    }
    Phonebook.Contact.1.FirstName = {
        result = [
            {
                Phonebook.Contact.1. = {
                    FirstName = "John"
                }
            }
        ],
        status = 0
    },
    Phonebook.Contact.2. = {
        result = [
            {
                Phonebook.Contact.2. = {
                    FirstName = "Pony"
                    LastName = "Goffin",
                }
            }
        ],
        status = 0
    },
    Phonebook.Contact.[FirstName == 'Jane']. = {
        result = [
            {
            }
        ],
        status = 0
    },
   }
   @endcode

   @param bus_ctx The bus context (or connection)
   @param req_paths Amxc variant containing a list of all paths to search for.
   @param depth relative depth, if not zero it indicates how many levels of child objects are returned. This depth is the same for all paths.
   @param ret will contain an amxc variant containing a htable with the objects and their parameters
   @param timeout in seconds (for every individual amxb_get lookup)

   @return
   amxd_status_ok when successful, any other value indicates an error.
 */
int amxb_get_multiple(amxb_bus_ctx_t* const bus_ctx,
                      amxc_var_t* req_paths,
                      int32_t depth,
                      amxc_var_t* ret,
                      int timeout);

/**
   @ingroup amxb_operator
   @brief
   Sets parameter values of one single object or of multiple instance objects

   Using this method, the parameter values of an object can be changed.

   It is not possible to change read-only parameter values using this function.

   This function supports following paths:

   - object path - must end with a "."
   - search path - can contain expressions or wildcard to filter out instances.
                   and must end with a "." or "*"

   In a search path a wildcard "*" or an expression can be put where an instance
   identifier (instance index) is in an object path.

   Examples of valid search paths:
   @code{.c}
   "Phonebook.Contact.*."
   "Phonebook.Contact.*"
   "Phonebook.Contact.[FirstName == 'Jane']."
   "Device.IP.Interface.[Type=='Normal'].IPv4Address.[AddressingType=='Static']."
   "Device.IP.Interface.[Type=='Normal' && Stats.ErrorsSent>0].IPv4Address.[AddressingType=='Static']."
   @endcode

   The parameter values must be passed as a variant containing a hash-table where
   each key is a parameter name and the value is the new value for that parameter.

   When using a search path and multiple instances match the search path, all the
   mentioned parameters are modified for all matching instances.

   The return value of a set is always an Ambiorix variant and will contain
   all changed objects, and the changed parameters. Unchanged parameters are not
   provided in the return value.

   Example:
   When changing all "LastNames" to "Ambiorix" of all contacts using search path
   "Phonebook.Contact.*" the return value could be
   @code{.c}
   [
       Phonebook.Contact.1. = {
           LastName = "Ambiorix"
       },
       Phonebook.Contact.2. = {
           LastName = "Ambiorix"
       },
       Phonebook.Contact.3. = {
           LastName = "Ambiorix"
       }
   ]
   @endcode

   @param bus_ctx The bus context (or connection)
   @param object Full object path, search path or parameter path
   @param values variant hash-table containing the new values
   @param ret will contain the objects and their changed parameters
   @param timeout in seconds

   @return
   amxd_status_ok when successful, any other value indicates an error.
 */
int amxb_set(amxb_bus_ctx_t* const bus_ctx,
             const char* object,
             amxc_var_t* values,
             amxc_var_t* ret,
             int timeout);

/**
   @ingroup amxb_operator
   @brief
   Sets parameter values for multiple objects (request paths)

   Using this method, the parameter values of an object can be changed.

   It is not possible to change read-only parameter values using this function.

   This function supports following paths:

   - object path - must end with a "."
   - search path - can contain expressions or wildcard to filter out instances.
                   and must end with a "." or "*"

   In a search path a wildcard "*" or an expression can be put where an instance
   identifier (instance index) is in an object path.

   Examples of valid search paths:
   @code{.c}
   "Phonebook.Contact.*."
   "Phonebook.Contact.*"
   "Phonebook.Contact.[FirstName == 'Jane']."
   "Device.IP.Interface.[Type=='Normal'].IPv4Address.[AddressingType=='Static']."
   "Device.IP.Interface.[Type=='Normal' && Stats.ErrorsSent>0].IPv4Address.[AddressingType=='Static']."
   @endcode

   The parameter values must be passed as a variant containing a hash-table where
   each key is a parameter name and the value is the new value for that parameter.

   When using a search path and multiple instances match the search path, all the
   mentioned parameters are modified for all matching instances.

   The return value of a set is always an Ambiorix variant and will contain
   all changed objects, and the changed parameters. Unchanged parameters are not
   provided in the return value. For each request path a status is added as well.

   When the status code is 0, the set for that request path was successful.
   All other status codes indicate an error and is always referring to one of the
   amxd_status_t enum.

   When the flag AMXB_FLAG_PARTIAL is set, an error code is returned for each
   parameter that could not be set. The error code is one of the amxd_status_t codes.

   When failed to set an optional parameter, an error code is returned for that
   parameter.

   Example of a valid req_paths variant:
   @code{.c}
    [
        {
            path = "Device.Ethernet.Interface.2.",
            parameters = {
                Status = "dummy-invalid"
            }
        },
        {
            path = "Device.Ethernet.Interface.[Status == 'Dormant'].",
            parameters = {
                Enable = false
            }
        },
        {
            path = "MQTT.Client.*.",
            parameters = {
                Enable = true
            },
            oparameters = {
                TransportProtocol = "TLS"
            }
        },
        {
            path = "MQTT.Client.1.",
            parameters = {
                Enable = true,
                TransportProtocol = "TLS"
            }
        }
    ]
   @endcode

   The above req_paths variant will return in case AMXB_FLAG_PARTIAL is provided:
   @code{.c}
    [
        {
            path = "Device.Ethernet.Interface.2.",
            result = {
                Device.Ethernet.Interface.2. = {
                    Status = {
                        error_code = 10,
                        required = true
                    }
                }
            },
            status = 10
        },
        {
            path = "Device.Ethernet.Interface.[Status == 'Dormant'].",
            result = {
                Device.Ethernet.Interface.1. = {
                    Enable = false
                }
                Device.Ethernet.Interface.5. = {
                    Enable = false
                },
            },
            status = 0
        },
        {
            path = "MQTT.Client.*.",
            result = {
                MQTT.Client.1. = {
                    Enable = true,
                    TransportProtocol = "TLS"
                },
                MQTT.Client.2. = {
                    Enable = true,
                    TransportProtocol = "TLS"
                }
            },
            status = 0
        },
        {
            path = "MQTT.Client.[Alias == 'cpe-mybroker'].",
            result = {
                MQTT.Client.1. = {
                    Enable = true,
                    TransportProtocol = "TLS"
                }
            },
            status = 0
        }
    ]
   @endcode

   In case the AMXB_FLAG_PARTIAL is not provided only the first failing request path
   is returned and all others are not applied.

   @code{.c}
    [
        {
            path = "Device.Ethernet.Interface.2.",
            result = {
                Device.Ethernet.Interface.2. = {
                    Status = {
                        error_code = 10,
                        required = true
                    }
                }
            },
            status = 10
        }
    }
   @endcode

   @param bus_ctx The bus context (or connection)
   @param flags Supported flags are AMXB_FLAG_PARTIAL.
   @param req_paths hash-table variant containing the request paths and parameters to be set
   @param ret will contain for each request path the result and status
   @param timeout in seconds

   @return
   amxd_status_ok when successful, any other value indicates an error.
 */
int amxb_set_multiple(amxb_bus_ctx_t* const bus_ctx,
                      uint32_t flags,
                      amxc_var_t* req_paths,
                      amxc_var_t* ret,
                      int timeout);
/**
   @ingroup amxb_operator
   @brief
   Adds an instance to a multi-instance object.

   Using this method, an instance can be created and the parameters values of
   that instance can be set.

   It is not possible to create an instance for a read-only multi instance object.

   It is not possible to set the value of read-only parameters using this function.

   This function supports following paths:

   - object path - must end with a "."

   The parameter values must be passed as a variant containing a hash-table where
   each key is a parameter name and the value is the value for that parameter.

   It is possible to choose the index (instance identifier) of the new instance using
   the index argument. The index provided must not be in use, otherwise the creation
   of the instance fails. When specifying 0 as the index, the next available
   index will be chosen. The automatic instance numbering never re-uses an already
   used index, even if the instance that was using the index has been deleted.

   Optionally a name can be specified for the instance. When the multi-instance
   object has an "Alias" parameter that is defined as a "unique key", the name
   is used as the value for the "Alias" parameter. When no name needs to be set
   a NULL pointer can be passed.

   When the multi-instance object has "key" parameters the values of these
   parameters must be given using the "values" argument, except for the "Alias"
   parameter if a name is provided. The values of "key" parameters can only be
   set when the instance is created, and are immutable.

   Values of non key parameters are optional and can be set later with
   @ref amxb_set function.

   The return value of an add is always an Ambiorix variant and will contain
   the newly created instance and all its key parameters.

   Example of a return variant:
   @code{.c}
    [
        {
            index = 5,
            name = "5",
            object = "Phonebook.Contact.5.",
            parameters = {
            },
            path = "Phonebook.Contact.5."
        }
    ]
   @endcode

   @param bus_ctx The bus context (or connection)
   @param object Full multi-instance object path
   @param index the index of the instance set to 0 to assign an index automatically
   @param name the name of the instance, or when an Alias parameter exists,
               the value for the Alias. The name can be NULL.
   @param values variant hash-table containing the parameter values, can be NULL
                 when key parameters are defined, at least the key parameters
                 must be set and present in the hash-table.
   @param ret will contain the created object, its key parameters and exta information
   @param timeout in seconds

   @return
   amxd_status_ok_OK when successful, any other value indicates an error.
 */
int amxb_add(amxb_bus_ctx_t* const bus_ctx,
             const char* object,
             uint32_t index,
             const char* name,
             amxc_var_t* values,
             amxc_var_t* ret,
             int timeout);

/**
   @ingroup amxb_operator
   @brief
   Deletes one or more instances of a multi-instance object.

   Using this method, one or more instances can be deleted from a multi-instance
   object.

   It is not possible to delete instances from a read-only multi instance object.

   This function supports following paths:

   - object path - must end with a "."
   - search path - must end with a "." or "*"

   The provided paths must either result or point to:
   - a multi-instance object (should be exactly one)
   - an instance (can be more then one)

   When the given path is a multi-instance object, an index or name of the
   instance that will be deleted must be given. If both an index
   (instance identifier) and a name are given, the index takes precedence.

   When the given path is an instance path, index and name arguments are ignored.

   When the given path is a search path where multiple-instances match, all of
   the matching instances will be deleted and the index and name arguments
   are ignored.

   The full list of deleted objects is returned in a variant containing an
   array of all deleted object paths, this includes the full tree underneath
   the delete instance(s).

   @param bus_ctx The bus context (or connection)
   @param object Full object path or  search path
   @param index the index of the instance that will be deleted
   @param name the name of the instance that will be deleted
   @param ret will contain a list of all deleted objects
   @param timeout in seconds

   @return
   amxd_status_ok when successful, any other value indicates an error.
 */
int amxb_del(amxb_bus_ctx_t* const bus_ctx,
             const char* object,
             uint32_t index,
             const char* name,
             amxc_var_t* ret,
             int timeout);

/**
   @ingroup amxb_operator
   @brief
   Gets the supported data model.

   This function is mainly used to have support for the USP "get supported dm"
   message.

   Use this function for introspection purposes.

   This function does not return any instance, it only indicates which objects are
   multi-instance objects. The place in the object path where normally an
   instance identifier (index) is set, the place holder "{i}" is used.

   The object argument must be in this supported data model notation.

   Example:
   @code
   "Phonebook.Contact.{i}.PhoneNumber.{i}."
   @endcode

   Using the flags argument, the requested information can be manipulated:
   - AMXB_FLAG_FIRST_LVL - do not return child objects
   - AMXB_FLAG_FUNCTIONS - include all RPC methods of the object
   - AMXB_FLAG_PARAMETERS - include all parameters of the object
   - AMXB_FLAG_EVENTS - include all events of the object

   All other flags will be ignored.

   The return value of this function is always an Ambiorix variant and will contain
   the requested information. The return data is stored in the ret argument.

   Example of a return variant:
   @code
   [
      {
          Phonebook.Contact.{i}.PhoneNumber.{i}. = {
              access = 1
              is_multi_instance = true,
              supported_commands = [
              ],
              supported_params = [
                  {
                      access = 1
                      param_name = "Phone",
                  }
              ],
          }
      }
   ]
   @endcode

   @param bus_ctx The bus context (or connection)
   @param object The object path (in supported path notation)
   @param flags bitmap field of or'ed flags
   @param ret will contain the requested information
   @param timeout in seconds

   @return
   amxd_status_ok when successful, any other value indicates an error.
 */
int amxb_get_supported(amxb_bus_ctx_t* const bus_ctx,
                       const char* object,
                       uint32_t flags,
                       amxc_var_t* ret,
                       int timeout);

/**
   @ingroup amxb_operator
   @brief
   Describes an object

   This function is mainly used for data model introspection. Besides the
   values of the parameters, more information can be obtained.

   Information included in the returned data structure is:
   - parameter, object, function attributes
   - index and name - for instance objects
   - indexed and named object path (path and object fields)
   - type information for parameters, objects and functions
   - function names, and all function arguments

   Use this function for introspection purposes.

   Using the flags argument, the requested information can be manipulated:
   - AMXB_FLAG_FUNCTIONS - include all RPC methods of the object
   - AMXB_FLAG_PARAMETERS - include all parameters of the object
   - AMXB_FLAG_EVENTS - include all events of the object
   - AMXB_FLAG_OBJECTS - include the names of child objects
   - AMXB_FLAG_INSTANCES - include index and name of instance objects
   - AMXB_FLAG_EXISTS - return true if the object exists, when this flag is set
     all others are ignored.

   All other flags will be ignored.

   The return value of this function is always an Ambiorix variant and will contain
   the requested information. The return data is stored in the ret argument.

   Example of a return variant:
   @code
   [
       {
           attributes = {
               locked = false,
               persistent = false
               private = false,
               protected = false,
               read-only = false,
           },
           index = 1,
           name = "1",
           object = "Phonebook.Contact.1.E-Mail.",
           objects = [
           ],
           parameters = {
               E-Mail = {
                   attributes = {
                       counter = false,
                       instance = true,
                       key = false
                       persistent = false,
                       private = false,
                       protected = false,
                       read-only = false,
                       template = false,
                       unique = false,
                       volatile = false,
                   },
                   name = "E-Mail",
                   type_id = 1,
                   type_name = "cstring_t"
                   value = "john.d@ambiorix.com",
               }
           }
           path = "Phonebook.Contact.1.E-Mail.",
           type_id = 3,
           type_name = "instance",
       }
   ]
   @endcode

   @param bus_ctx The bus context (or connection)
   @param object The object path
   @param flags bitmap field of or'ed flags
   @param ret will contain the requested information
   @param timeout in seconds

   @return
   amxd_status_ok when successful, any other value indicates an error.
 */
int amxb_describe(amxb_bus_ctx_t* const bus_ctx,
                  const char* object,
                  uint32_t flags,
                  amxc_var_t* ret,
                  int timeout);

/**
   @ingroup amxb_operator
   @brief
   List the service elements/nodes of an object

   This function is mainly used for data model introspection and provides list
   of the service elements/nodes that are part of the object

   Use this function for introspection purposes.

   Using the flags argument, the requested information can be manipulated:
   - AMXB_FLAG_FUNCTIONS - include all RPC methods of the object
   - AMXB_FLAG_PARAMETERS - include all parameters of the object
   - AMXB_FLAG_OBJECTS - include the names of child objects
   - AMXB_FLAG_INSTANCES - include index and name of instance objects

   All other flags will be ignored.

   @param bus_ctx The bus context (or connection)
   @param object The object path (in supported path notation)
   @param flags bitmap field of ored flags
   @param fn callback function
   @param priv private data that will be passed as is to the callback function

   @return
   amxd_status_ok when successful, any other value indicates an error.
 */
int amxb_list(amxb_bus_ctx_t* const bus_ctx,
              const char* object,
              uint32_t flags,
              amxb_be_cb_fn_t fn,
              void* priv);

int amxb_resolve(amxb_bus_ctx_t* bus_ctx,
                 amxd_path_t* obj_path,
                 amxc_var_t* ret_val);

/**
   @ingroup amxb_operator
   @brief
   Fetches the instances and the unique keys of a multi-instance object.

   Using this method, the instances of a multi-instance object and their unique keys can be retrieved.

   It is possible to get the instances and keys from child objects of the provided multi-instance
   object as well by specifying a depth larger than 0.

   This function supports following paths:

   - object path - must end with a "." and must point to a multi-instance object
   - search path - can contain expressions or wildcard to filter out instances, but the expression
                   must resolve to one or several multi-instance objects to get a non-empty result

   In a search path a wildcard "*" or an expression can be put where an instance
   identifier (instance index) is in an object path.

   Examples of valid search paths:
   @code{.c}
   "Phonebook.Contact.*.PhoneNumber."
   "Phonebook.Contact.[FirstName == 'Jane'].PhoneNumber."
   @endcode

   The return value of a get instances is always an Ambiorix variant:
   @code{.c}
   [
     {
       "Phonebook.Contact.1.E-Mail.1.": {
       },
       "Phonebook.Contact.1.": {
         "FirstName": "Jane"
       },
       "Phonebook.Contact.1.PhoneNumber.1.": {
       }
     }
   ]
   @endcode

   In the above example, the FirstName parameter was a unique key parameter

   @param bus_ctx The bus context (or connection)
   @param object Multi-instance object path or search path
   @param depth relative depth, if not zero it indicates for how many levels the child instances are returned
   @param ret will contain the objects and their keys
   @param timeout in seconds

   @return
   amxd_status_ok when successful, any other value indicates an error.
 */
int amxb_get_instances(amxb_bus_ctx_t* const bus_ctx,
                       const char* search_path,
                       int32_t depth,
                       amxc_var_t* ret,
                       int timeout);

#ifdef __cplusplus
}
#endif

#endif // __AMXB_OPERATORS_H__
