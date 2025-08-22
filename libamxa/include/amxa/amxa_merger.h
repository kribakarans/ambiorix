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
#if !defined(__AMXA_MERGER_H__)
#define __AMXA_MERGER_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <amxc/amxc.h>

/**
   @file
   @brief
   ACL merger API header file
 */

/**
   @defgroup amxa_merger ACL merger
 */

/**
   @ingroup amxa_merger
   @brief
   Read data from one or more json files and return the data in a variant.

   @note
   The returned variant is dynamically allocated and must be deleted with amxc_var_delete

   @param path can be either a path to a single file or a directory

   @return
   Returns the variant result from parsing the input files or NULL in case of error.
 */
amxc_var_t* amxa_parse_files(const char* path);

/**
   @ingroup amxa_merger
   @brief
   Combine rules from multiple sources.

   It is possible that default ACL rules are added in an ACL file and new rules are added at runtime
   by adding new instances in the ControllerTrust.Role.{i}.Permissions.{i}. data model. These rules
   need to be combined before they are merged into a file with the permission bitmask. This is done
   in this function.

   Another use case is the following:
   If there are separate ACL rules per root object ("Device.DCHPv4.", "Device.MQTT.",...) all of
   these rules can be added to a single variant. Once all rules for a given role are present in the
   same variant, the rules can be merged using the @ref amxa_merge_rules function. This gives a
   single file with all the rules for a given role, which can be used for ACL verification.

   This function combines the rules from the src variant into the dst variant. If a rule already
   exists in the dst variant, the rule with the highest order is kept. Note that this function does
   not filter out overlapping rules based on their order. Only when an identical rule is found in
   both the src and dst variant, the one with the highest order is kept. To merge rules with
   overlapping targets, use @ref amxa_merge_rules

   @param dst variant containing some initial rules and the combined result afterwards
   @param src variant containing some new rules

   @return
   0 in case of success, -1 in case of error
 */
int amxa_combine_rules(amxc_var_t* dst, amxc_var_t* src);

/**
   @ingroup amxa_merger
   @brief
   Merge all rules present in a single variant of type hash table and write the result to a
   destination file.

   The input rules will typically be read from one or more ACL files using @ref amxa_parse_files or
   can come from a combination of rules using @ref amxa_combine_rules

   @param data variant with rules that need to be merged
   @param dest_file path to a destination file

   @return
   0 in case of success, -1 in case of error
 */
int amxa_merge_rules(const amxc_var_t* data, const char* dest_file);

/**
   @ingroup amxa_merger
   @brief
   Combine the merged rules of multiple roles to get a combined result for multiple roles.

   When a requesting service has multiple roles, the ACLs from these roles need to be combined. This
   can be done by first calling @ref amxa_merge_rules on the rules of each role. Then this function
   can be used to combine these merged rules into a single set of rules for the combined roles.

   Two sets of merged rules can be passed to this function. The combined rules will be available in
   the combined_role argument.

   @param combined_role variant containing the merged rules for a role. The merged rules from a
                        different role will be merged into this variant.
   @param new_role variant with merged rules for a new role. Will be combined with the merged rules
                   in merged_roles.
   @param dest_file optional destination file if the result needs to be written to a file.

   @return
   0 in case of success, -1 in case of error
 */
int amxa_combine_roles(amxc_var_t* combined_role, amxc_var_t* new_role, const char* dest_file);

#ifdef __cplusplus
}
#endif

#endif // __AMXA_MERGER_H__
