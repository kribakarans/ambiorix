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

#if !defined(__AMXA_GET_INSTANCES_H__)
#define __AMXA_GET_INSTANCES_H__

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
   Functions related to the get instances operation
 */

/**
   @defgroup amxa_get_instances Get Instances validation functions
 */

/**
   @ingroup amxa_get_instances
   @brief
   amxb_get_instances with acl verification.

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
   @param acl_file json file containing the merged acl rules
   @param depth relative depth, if not zero it indicates for how many levels the child instances are returned
   @param ret will contain the objects and their keys
   @param timeout in seconds

   @return
    - amxd_status_ok -> when the operation was successful
    - amxd_status_not_supported -> when the path cannot be found in the supported data model or
      the input is invalid
    - amxd_status_not_a_template -> when the requested path is not a multi-instance object
    - amxd_status_not_instantiated -> when the template object is not found in the instantiated data model
    - amxd_status_permission_denied -> when the operation is not allowed for the provided acl_file
 */
int amxa_get_instances(amxb_bus_ctx_t* bus_ctx,
                       const char* object,
                       const char* acl_file,
                       int32_t depth,
                       amxc_var_t* ret,
                       int timeout);

#ifdef __cplusplus
}
#endif

#endif // __AMXA_GET_INSTANCES_H__
