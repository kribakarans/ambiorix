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


#if !defined(__AMXB_ERROR_H__)
#define __AMXB_ERROR_H__

#ifdef __cplusplus
extern "C"
{
#endif

/**
   @file
   @brief
   Error code defines
 */

/**
   @ingroup amxb_baapi
   @defgroup amxb_defines Defines
 */

/**
   @ingroup amxb_defines
   @brief
   Unknown error
 */
#define AMXB_ERROR_UNKNOWN                  -1
/**
   @ingroup amxb_defines
   @brief
   All ok
 */
#define AMXB_STATUS_OK                      0
/**
   @ingroup amxb_defines
   @brief
   Internal error
 */
#define AMXB_ERROR_INTERNAL                 1
/**
   @ingroup amxb_defines
   @brief
   Invalid URI
 */
#define AMXB_ERROR_INVALID_URI              2
/**
   @ingroup amxb_defines
   @brief
   URI scheme not supported
 */
#define AMXB_ERROR_NOT_SUPPORTED_SCHEME     3
/**
   @ingroup amxb_defines
   @brief
   Function/operation not supported
 */
#define AMXB_ERROR_NOT_SUPPORTED_OP         4
/**
   @ingroup amxb_defines
   @brief
   Operation in progress
 */
#define AMXB_ERROR_OP_IN_PROGRESS           5
/**
   @ingroup amxb_defines
   @brief
   Invalid file descriptor
 */
#define AMXB_ERROR_INVALID_FD               6
/**
   @ingroup amxb_defines
   @brief
   Back-end failed
 */
#define AMXB_ERROR_BACKEND_FAILED           7

#define AMXB_ERROR_MAX                      8

/**
   The following error codes are deprecated.

   Use amxd_status_t enumeration values instead.

   These are the original defines.

 #define AMXB_ERROR_BUS_INVALID_CMDS         20
 #define AMXB_ERROR_BUS_INVALID_ARG          21
 #define AMXB_ERROR_BUS_METHOD_NOT_FOUND     22
 #define AMXB_ERROR_BUS_NOT_FOUND            23
 #define AMXB_ERROR_BUS_NO_DATA              24
 #define AMXB_ERROR_BUS_PERMISSION_DENIED    25
 #define AMXB_ERROR_BUS_TIMEOUT              26
 #define AMXB_ERROR_BUS_NOT_SUPPORTED        27
 #define AMXB_ERROR_BUS_CONNECTION_FAILED    28
 #define AMXB_ERROR_BUS_UNKNOWN              29
 */

#define AMXB_ERROR_BUS_INVALID_CMDS         amxd_status_unknown_error
#define AMXB_ERROR_BUS_INVALID_ARG          amxd_status_invalid_arg
#define AMXB_ERROR_BUS_METHOD_NOT_FOUND     amxd_status_function_not_found
#define AMXB_ERROR_BUS_NOT_FOUND            amxd_status_object_not_found
#define AMXB_ERROR_BUS_NO_DATA              amxd_status_unknown_error
#define AMXB_ERROR_BUS_PERMISSION_DENIED    amxd_status_permission_denied
#define AMXB_ERROR_BUS_TIMEOUT              amxd_status_timeout
#define AMXB_ERROR_BUS_NOT_SUPPORTED        amxd_status_not_supported
#define AMXB_ERROR_BUS_CONNECTION_FAILED    amxd_status_unknown_error
#define AMXB_ERROR_BUS_UNKNOWN              amxd_status_unknown_error

const char* amxb_get_error(int error);

#ifdef __cplusplus
}
#endif

#endif // __AMXB_ERROR_H__
