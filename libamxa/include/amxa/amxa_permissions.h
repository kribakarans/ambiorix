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
#if !defined(__AMXA_PERMISSIONS_H__)
#define __AMXA_PERMISSIONS_H__

#ifdef __cplusplus
extern "C"
{
#endif

/**
   @file
   @brief
   ACL permission bits header file
 */

/**
   @defgroup amxa_permissions ACL permissions
 */

/**
   @ingroup amxa_permissions

   @brief
   Default permissions that should be set on acl directories
 */
#define AMXA_DIR_PERMISSIONS 0750

/**
   @ingroup amxa_permissions

   @brief
   Default permissions that should be set on acl files
 */
#define AMXA_FILE_PERMISSIONS 0640

/**
   @ingroup amxa_permissions

   @brief
   Linux owner of acl files and directories
 */
#define AMXA_OWNER "root"

/**
   @ingroup amxa_permissions

   @brief
   Linux group for acl files and directories
 */
#define AMXA_GROUP "acl"

/**
   @ingroup amxa_permissions

   @brief
   Grants the capability to read the value of the Parameter via Get and read the meta-information of
   the Parameter via GetSupportedDM.
 */
#define AMXA_PERMIT_GET                0x0001

/**
   @ingroup amxa_permissions

   @brief
   Grants the capability to update the value of the Parameter via Add or Set.
 */
#define AMXA_PERMIT_SET                0x0002

/**
   @ingroup amxa_permissions

   @brief
   Grants no capabilities for Singleton Objects. Grants the capability to create a new instance of
   a Multi-Instanced Object via Add.
 */
#define AMXA_PERMIT_ADD                0x0004

/**
   @ingroup amxa_permissions

   @brief
   Grants the capability to remove an existing instance of an Instantiated Object via Delete.
 */
#define AMXA_PERMIT_DEL                0x0008

/**
   @ingroup amxa_permissions

   @brief
   Grants the capability to execute the Command via Operate, but grants no capabilities to an Event.
 */
#define AMXA_PERMIT_OPER               0x0010

/**
   @ingroup amxa_permissions

   @brief
   Grants the capability to use this Parameter in the ReferenceList of an Event or ValueChange
   Subscription.
 */
#define AMXA_PERMIT_SUBS_VAL_CHANGE    0x0020

/**
   @ingroup amxa_permissions

   @brief
   Grants the capability to use this Object in the ReferenceList of an Event or ObjectCreation
   (for multi-instance objects only) Subscription.
 */
#define AMXA_PERMIT_SUBS_OBJ_ADD       0x0040

/**
   @ingroup amxa_permissions

   @brief
   Grants the capability to use this Instantiated Object in the ReferenceList of an Event or
   ObjectDeletion Subscription.
 */
#define AMXA_PERMIT_SUBS_OBJ_DEL       0x0100

/**
   @ingroup amxa_permissions

   @brief
   Grants the capability to use this Event or Command in the ReferenceList of an Event or
   OperationComplete Subscription.
 */
#define AMXA_PERMIT_SUBS_EVT_OPER_COMP 0x0200

/**
   @ingroup amxa_permissions

   @brief
   Grants the capability to read the instance numbers and unique keys of the Instantiated Object via
   GetInstances. Also allows using search paths in get operations.
 */
#define AMXA_PERMIT_GET_INST           0x0080

/**
   @ingroup amxa_permissions

   @brief
   Grants the capability to read the meta-information of the Object via GetSupportedDM.
 */
#define AMXA_PERMIT_OBJ_INFO           0x0400

/**
   @ingroup amxa_permissions

   @brief
   Grants the capability to read the meta-information of the Command (including input and output
   arguments) and Event (including arguments) via GetSupportedDM.
 */
#define AMXA_PERMIT_CMD_INFO           0x0800

/**
   @ingroup amxa_permissions

   @brief
   Grants no capabilities.
 */
#define AMXA_PERMIT_NONE               0x0000

/**
   @ingroup amxa_permissions

   @brief
   Grants all capabilities.
 */
#define AMXA_PERMIT_ALL                0x0FFF

#ifdef __cplusplus
}
#endif

#endif // __AMXA_PERMISSIONS_H__
