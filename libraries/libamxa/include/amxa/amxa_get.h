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

#if !defined(__AMXA_GET_H__)
#define __AMXA_GET_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>

#include <amxc/amxc.h>
#include <amxb/amxb.h>

/**
   @file
   @brief
   Functions related to the get operation
 */

/**
   @defgroup amxa_get Get validation functions
 */

/**
   @ingroup amxa_get
   @brief
   Amxb_get with acl verification.

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
   @param acl json file containing acl rules
   @param depth relative depth, if not zero it indicates how many levels of child objects are returned
   @param ret will contain the objects and their parameters
   @param timeout in seconds

   @return
   @ref 0 in case of succes, any other value indicates an error.
 */
int amxa_get(amxb_bus_ctx_t* bus_ctx,
             const char* object,
             const char* acl,
             int32_t depth,
             amxc_var_t* ret,
             int timeout);

/**
   @ingroup amxa_get
   @brief
   amxb_get_filtered with acl verification.

   Fetches one or more objects and their parameters that are matching a filter.

   Using this method, the parameter values of an object can be retrieved.
   This function works exactly the same as @ref amxa_get, but can filter the
   parameters of an object on the meta-data of the parameters.

   For more details see @ref amxa_get.

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
   @param filter A filter epxression
   @param acl json file containing acl rules
   @param depth relative depth, if not zero it indicates how many levels of child objects are returned
   @param ret will contain the objects and their parameters
   @param timeout in seconds

   @return
   @ref 0 in case of succes, any other value indicates an error.
 */
int amxa_get_filtered(amxb_bus_ctx_t* bus_ctx,
                      const char* object,
                      const char* filter,
                      const char* acl,
                      int32_t depth,
                      amxc_var_t* ret,
                      int timeout);

#ifdef __cplusplus
}
#endif

#endif // __AMXA_GET_H__
