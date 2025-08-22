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
#if !defined(__AMXA_SET_H__)
#define __AMXA_SET_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <amxc/amxc.h>
#include <amxb/amxb.h>

/**
   @brief
   Sets parameter values for multiple objects (request paths) and checks ACLs.

   Using this method, the parameter values of an object can be changed.

   It is not possible to change read-only parameter values or parameters that you have insufficient
   permissions for.

   Permissions are determined based on the provided ACL file. This must be a path to a single ACL
   file that contains the merged rules for that role.

   This function supports the following paths:
   - object path - must end with a "."
   - search path - can contain expressions or wildcards to filter out instances and must end with
     "." or "*"

   In a search path a wildcard "*" or expression can be put where an instance identifier (index)
   is in an object path.

   Refer to the documentation of amxb_set_multiple for examples of request path variants that can be
   provided to this function.

   @param bus_ctx the bus context or connection
   @param flags supported flags are AMXB_FLAG_PARTIAL
   @param acl_file path to an acl file with merged rules for the role
   @param req_paths hash table variant containing the request paths and parameters to be set
   @param ret will contain the request paths and results of the requests
   @param timeout in seconds

   @return 0 in case of success, any other value indicates an error
 */
int amxa_set_multiple(amxb_bus_ctx_t* const bus_ctx,
                      uint32_t flags,
                      const char* acl_file,
                      amxc_var_t* req_paths,
                      amxc_var_t* ret,
                      int timeout);

#ifdef __cplusplus
}
#endif

#endif // __AMXA_SET_H__
