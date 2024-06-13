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
#if !defined(__AMXA_VALIDATOR_H__)
#define __AMXA_VALIDATOR_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>

#include <amxc/amxc.h>
#include <amxd/amxd_types.h>
#include <amxb/amxb.h>

/**
   @file
   @brief
   ACL validator API header file
 */

/**
   @defgroup amxa_validator ACL validator
 */

/**
   @ingroup amxa_validator
   @brief
   Validates whether a Get request with a search path is allowed.

   Validates whether the @ref AMXA_PERMIT_GET_INST bit is set for the requested_path (or a parent
   of this path) since this bit determines if search paths are allowed for get messages.

   The requested_path provided to this function should be a search path. If it isn't a search path,
   the function will return true because no limitations regarding search paths will apply.

   @note
   If the search path cannot be resolved to any instances, it will also return false, because there
   is no point in executing the request in this case.

   @param ctx bus context to resolve search paths
   @param acl_rules variant containing the merged acl rules
   @param requested_path requested path for the get operation

   @return
   0 in case of success, -1 in case of error
 */
bool amxa_is_search_path_allowed(amxb_bus_ctx_t* ctx,
                                 amxc_var_t* acl_rules,
                                 const char* requested_path);

/**
   @ingroup amxa_validator
   @brief
   Gets a list of filters that need to be applied to the request based on the ACL rules.

   Checks the ACL rules using the requested path and a bitmask as inputs, and fills up a list with
   object, parameter, command and event paths that must be filtered out from the response.

   @note
   The data model paths that are added to the filters are not dot terminated. This is done on
   purpose, because there is no indication of whether an ACL rule is applied to an object or a
   parameter. If parameter paths were added to the filter list and they were dot terminated, this
   would cause issues in filtering out the parameters.

   @param acl_rules variant containing the merged and resolved acl rules
   @param bitmask bitmask indicating the operator that is used in the request
   @param filters emtpy list of filters that will be filled up
   @param requested_path target path that the operator should be applied to

   @return
   0 in case of success, -1 in case of error
 */
int amxa_get_filters(amxc_var_t* acl_rules,
                     uint32_t bitmask,
                     amxc_llist_t* filters,
                     const char* requested_path);

/**
   @ingroup amxa_validator
   @brief
   Filter out objects and parameters from a get response that the requester does not have access to.

   A get operation can be executed with amxb_get, but might need to be filtered out based on the
   access rights. This function takes as input the return variant of an amxb_get and the filters
   retrieved with @ref amxa_get_filters to filter out all objects and parameters from the get
   response that the requester does not have access to.

   @param response get response obtained from amxb_get
   @param filters list of filters that must be applied to the get response

   @return
   0 in case of success, -1 in case of error
 */

int amxa_filter_get_resp(amxc_var_t* response, amxc_llist_t* filters);

/**
   @ingroup amxa_validator
   @brief
   Filter out instances and key parameters from a get instances response that the requester does not
   have access to.

   A get instances operation can be executed with amxb_get_instances, but might need to be filtered
   out based on the access rights. This function takes as input the return variant of an
   amxb_get_instances and the filters retrieved with @ref amxa_get_filters to filter out all
   instances and key parameters from the get instances response that the requester does not have
   access to.

   @param response get instances response obtained from amxb_get_instances
   @param filters list of filters that must be applied to the get instances response

   @return
   0 in case of success, -1 in case of error
 */

int amxa_filter_get_inst_resp(amxc_var_t* response, amxc_llist_t* filters);

/**
   @ingroup amxa_validator
   @brief
   Filter out meta-information about supported objects, parameters, commands and events from a get
   supported dm response that the requester does not have access to.

   A get_supported operation can be executed with amxb_get_supported, but might need to be filtered
   out based on the access rights. The response can be filtered with this function

   @note
   TODO: handle supported paths

   @param requested_path path used to invoke a get_supported operation
   @param response get_supported response obtained from amxb_get_supported
   @param acl_rules variant containing the merged acl rules

   @return
   0 in case of success, -1 in case of error
 */
int amxa_filter_get_supported_resp(const char* requested_path,
                                   amxc_var_t* response,
                                   amxc_var_t* acl_rules);

/**
   @ingroup amxa_validator
   @brief
   Validates whether a get request for a given requested path is allowed.

   Uses the resulting filters from @ref amxa_get_filters to validate whether a get request is
   allowed for the provided path. Even if the get is allowed, the response should still be filtered
   with @ref amxa_filter_get_resp in case the requester does not have access to subobjects.

   @param filters list of filters obtained with @ref amxa_get_filters
   @param requested_path requested path for the get operation

   @return true if the get operation is allowed, false if the operation is not allowed
 */
bool amxa_is_get_allowed(amxc_llist_t* filters, const char* requested_path);

/**
   @ingroup amxa_validator
   @brief
   Validates whether a get instances request for a given requested path is allowed.

   Uses the resulting filters from @ref amxa_get_filters to validate whether a get instances request
   is allowed for the provided path. Even if the get instances is allowed, the response should still
   be filtered with @ref amxa_filter_get_inst_resp because it is possible that the requester does
   not have access to subobjects

   @param filters list of filters obtained with @ref amxa_get_filters
   @param requested_path requested path for the get operation

   @return true if the get instances operation is allowed, false if the operation is not allowed
 */
bool amxa_is_get_inst_allowed(amxc_llist_t* filters, const char* requested_path);

/**
   @ingroup amxa_validator
   @brief
   Validates whether the requester is allowed to get the parameter.

   Uses the resulting filters from @ref amxa_get_filters to validate whether a requester has
   access to read a parameter value under an object. If the requester does not have access, the
   parameter must not be returned.

   @param object object path that contains the parameter
   @param param the parameter name
   @param filters list of filters obtained with @ref amxa_get_filters
   @return true if the get is allowed for the parameter, false if it is not allowed
 */
bool amxa_is_get_param_allowed(const char* object, const char* param, amxc_llist_t* filters);

/**
   @ingroup amxa_validator
   @brief
   Validates whether an add request for a given requested path is allowed.

   Validates whether the @ref AMXA_PERMIT_ADD bit is set/missing for the requested_path (or a parent
   of this path) since this bit determines whether the add operation is allowed.

   The requested_path provided to this function should be a path to a template object.

   @note
   If the requested path is a path that does not exist in the instantiated data model, because one
   of the parent objects does not exist, the function will also return false. It is possible that
   an Add operation is technically still allowed in this case, but this cannot be verified if the
   ACLs contain search paths that cannot be resolved.

   @note
   If parameters are being set with the add operation, it must also be checked if this is allowed
   for each parameter using @ref amxa_is_set_allowed

   @param ctx bus context to verify the template object exists
   @param acl_rules variant containing the merged and resolved acl rules
   @param requested_path requested path for the add operation

   @return true if the add operation is allowed, false if the operation is not allowed or if the
           template object cannot be found
 */
bool amxa_is_add_allowed(amxb_bus_ctx_t* ctx, amxc_var_t* acl_rules, const char* requested_path);

/**
   @ingroup amxa_validator
   @brief
   Validates whether a delete request for a given requested path is allowed.

   Validates whether the @ref AMXA_PERMIT_DEL bit is set/missing for the requested_path (or a parent
   of this path) since this bit determines whether the delete operation is allowed.

   The requested_path provided to this function should be a path to an instance object.

   @note
   If the requested path is a path that does not exist in the instantiated data model, this function
   will return false. It is possible that a Delete operation would still be allowed if the instance
   existed, but this cannot be verified if the ACLs contain search paths that cannot be resolved.

   @param ctx bus context to verify the template object exists
   @param acl_rules variant containing the merged and resolved acl rules
   @param requested_path requested path for the delete operation

   @return true if the delete operation is allowed, false if the operation is not allowed or if the
           instance cannot be found
 */
bool amxa_is_del_allowed(amxb_bus_ctx_t* ctx, amxc_var_t* acl_rules, const char* requested_path);

/**
   @ingroup amxa_validator
   @brief
   Validates whether a set request for a given object parameter is allowed.

   Validates whether the @ref AMXA_PERMIT_SET bit is set/missing for the requested parameter path
   (or a parent of this path) since this bit determines if the set operation is allowed.

   @note
   If the provided object path is a path that does not exist in the instantiated data model, this
   function will return false. It is possible that the Set operation would still be allowed if the
   instance existed, but this cannot be verified if the ACLs contain search paths that cannot be
   resolved.

   @param ctx bus context to verify that the object that owns the parameter exists
   @param acl_rules variant containing the merged and resolved acl rules
   @param obj_path requested object path for the set operation
   @param param parameter name to validate

   @return true if the set operation is allowed, false if the operation is not allowed or if the
           object that owns the parameter cannot be found
 */
bool amxa_is_set_allowed(amxb_bus_ctx_t* ctx,
                         amxc_var_t* acl_rules,
                         const char* obj_path,
                         const char* param);

/**
   @ingroup amxa_validator
   @brief
   Validates whether a data model function can be invoked.

   Validates whether the @ref AMXA_PERMIT_OPER bit is set/missing for the requested object + method
   (or a parent of this path) since this bit determines if it's allowed to execute the method.

   @note
   If the provided object path is a path that does not exist in the instantiated data model, this
   function will return false. It is possible that the function execution would still be allowed if
   the provided object was part of the instantiated data model, but this cannot be verified if the
   ACLs contain search paths that cannot be resolved.

   @param ctx bus context to verify that the object that owns the method exists
   @param acl_rules variant containing the merged and resolved acl rules
   @param obj_path requested object path for the operation
   @param method function name that should be validated

   @return true if the function invocation is allowed, false if the operation is not allowed or if
           the object that owns the method cannot be found
 */
bool amxa_is_operate_allowed(amxb_bus_ctx_t* ctx,
                             amxc_var_t* acl_rules,
                             const char* obj_path,
                             const char* method);

/**
   @ingroup amxa_validator
   @brief
   Validates whether a subscription can be made on the provided path.

   Validates whether a subscription of a given type can be made on the provided path. The type of
   subscription can be provided by passing a flag with one of the following values:
   @ref AMXA_PERMIT_SUBS_VAL_CHANGE
   @ref AMXA_PERMIT_SUBS_OBJ_ADD
   @ref AMXA_PERMIT_SUBS_OBJ_DEL
   @ref AMXA_PERMIT_SUBS_EVT_OPER_COMP

   @param acl_rules variant containing the merged and resolved acl rules
   @param path path to create a subscription on
   @param flag flag indicating the type of subscription

   @return true if it is allowed to create the subscription, false if it is not allowed
 */
bool amxa_is_subs_allowed(amxc_var_t* acl_rules, const char* path, int flag);

/**
   @ingroup amxa_validator
   @brief
   Filter out objects and parameters from a notification that the subscriber does not have access to.

   When creating a subscription, it should be checked with @ref amxa_is_subs_allowed to ensure it is
   allowed to create the subscription. However when a subscription is made for an object, it is made
   recursively for all child objects and parameters as well (if no extra filter if provided).
   While it may be allowed to make a subscription for a parent object, it may not be allowed for a
   child object. Therefore the incoming notifications resulting from subscriptions must be
   filtered before sending them to the subscribers.

   This function takes as input notification data and a set of ACL rules. It will filter out parts
   of the notification data based on these ACL rules or it will add the boolean key 'filter-all' to
   the passed notif_data variant if the entire variant should be filtered. If the boolean key
   'filter-all' is present in the notif_data variant after this function is called, the caller must
   not forward anything about the notification.

   @param notif_data notification data
   @param acl_rules variant containing the merged and resolved acl rules

   @return
   0 in case of success, -1 in case of error
 */
int amxa_filter_notif(amxc_var_t* notif_data, amxc_var_t* acl_rules);

/**
   @ingroup amxa_validator
   @brief
   This function validates whether it is allowed to invoke an RPC method on one or multiple objects
   for a certain ACL file.

   The provided obj_path is an object path that can contain search expressions. The function will
   return a variant of type linked list with the following format:

   ```
   [
      {
         object_path = <string>,
         status = <uint32_t>
      },
      ...
   ]
   ```

   If the provided path is not a search path, the list will always contain a single hash table. If
   the path is a search path, there will be one or multiple results. The list will never be empty.

   The function will first check whether the provided input arguments are not NULL or empty strings.
   If one of them is invalid, the function will return amxd_status_unknown_error in its return
   variant.
   Next, the function will check if the provided method exists in the supported data model. If this
   is not the case, it will return amxd_status_not_supported for that object path.
   Then it will check if there is at least one instance in the instantiated data model to invoke the
   method on. If this is not the case, it will return amxd_status_object_not_found for the provided
   path.
   Finally, the function will check the acl_file to see if it is allowed to invoke the method. If
   this is not the case, the function will return amxd_status_permission_denied for each path that
   the user does not have access to.

   Example return variant
   ```
   [
      {
         object_path = "DHCPv4.Server.Pool.2.",
         status = 24
      }
   ]
   ```

   @param ctx a valid bus context where the data model object can be found
   @param acl_file the ACL file to check the permissions
   @param obj_path an object path, which can be a search path
   @param method RPC method to check
   @return the return variant
 */
amxc_var_t* amxa_validate_operate(amxb_bus_ctx_t* ctx,
                                  const char* acl_file,
                                  const char* obj_path,
                                  const char* method);

#ifdef __cplusplus
}
#endif

#endif // __AMXA_VALIDATOR_H__
