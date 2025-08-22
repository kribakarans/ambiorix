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


#if !defined(__AMXP_PROC_INFO_H__)
#define __AMXP_PROC_INFO_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>
#include <amxc/amxc_llist.h>

/**
   @file
   @brief
   Ambiorix process information
 */

/**
   @defgroup amxp_proc_info Process Information

   Process information
 */

/**
   @ingroup amxp_proc_info
   @brief
   Structure containing the process information
 */
typedef struct _proc_info {
    int32_t pid;            /**< The process ID. */
    char* name;             /**< The filename of the executable.
                                 Strings longer than TASK_COMM_LEN (16) characters
                                 are silently truncated. */
    uint8_t state;          /**< A character indicating the state of the process */
    int32_t parent_pid;     /**< The PID of the parent of this process. */
    int32_t process_gid;    /**< The process group ID of the process. */
    int32_t session_id;     /**< The session ID of the process. */
    amxc_llist_it_t it;     /**< Linked list iterator, used to store the data struct in
                                 a linked list */
} amxp_proc_info_t;

/**
   @ingroup amxp_proc_info
   @brief
   Delete a amxp_proc_info_t by it is linked list iterator.

   Frees the structure and its content.

   This function is typically used as a callback function when cleaning a
   linked list of @ref amxp_proc_info_t structures.

   @param it the linked list iterator of a amxp_proc_info_t instance
 */
void amxp_proci_free_it(amxc_llist_it_t* it);

/**
   @ingroup amxp_proc_info
   @brief
   Build a linked list of running processes

   This function scans /proc/&lt;pid&gt;/ and allocates a @ref amxp_proc_info_t
   structure for each found process.

   Optionally a expression filter can be provided. The fields allowed in the
   filter are:
   - name
   - parent_pid or ppid
   - state

   @param result pointer to a linked list, found processes will be added to this list
   @param filter an expression that is used to filter the found processes.

   @return
   0 when successful, otherwise an error code
 */
int amxp_proci_findf(amxc_llist_t* result, const char* filter, ...);

#ifdef __cplusplus
}
#endif

#endif // __AMXP_PROC_INFO_H__

