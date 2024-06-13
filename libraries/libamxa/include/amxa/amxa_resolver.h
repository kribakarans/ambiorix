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
#if !defined(__AMXA_RESOLVER_H__)
#define __AMXA_RESOLVER_H__

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
   ACL search path resolver API header file
 */

/**
   @defgroup amxa_resolver ACL search path resolver
 */

/**
   @ingroup amxa_resolver
   @brief
   Resolves the search paths present in the merged ACL rules, starting from a given path.

   A set of (merged) ACL rules can contain search paths. These search paths need to be resolved to
   ensure the ACL rules are applied to the current data model state. This function will resolve the
   search paths present in the ACL rules starting from a fixed path. Any search path that exists in
   the ACL rules, but does not fall under the provided path will not be resolved.

   @note
   The provided fixed_path should be the longest fixed path that corresponds to the request. This is
   needed to make the function as efficient as possible. There is no point in resolving search paths
   in a higher part of the data model tree, because they are irrelevant for the current request.
   As the name suggests, the fixed_path must never be a search path.

   @param ctx bus context used to resolve the search paths
   @param acl_rules variant containing the merged acl rules
   @param fixed_path longest fixed path that corresponds to the request

   @return
   0 in case of success, -1 in case of error
 */
int amxa_resolve_search_paths(amxb_bus_ctx_t* ctx, amxc_var_t* acl_rules, const char* fixed_path);

#ifdef __cplusplus
}
#endif

#endif // __AMXA_RESOLVER_H__
