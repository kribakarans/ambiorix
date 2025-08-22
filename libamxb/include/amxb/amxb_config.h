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

#if !defined(__AMXB_CONFIG_H__)
#define __AMXB_CONFIG_H__

#ifdef __cplusplus
extern "C"
{
#endif

/**
   @file
   @brief
   Ambiorix Bus Agnostic Configuration
 */

/**
   @ingroup amxb_baapi
   @defgroup amxb_config Bus Configuration

   @details
   Some options can be configured with these functions.

   - The log callback function: this callback function will be called when
     a data model operation has been execcuted.
   - The internal timeout: some amxb functions perform extra queries on the data
     model to retrieve extra information when needed. The timeout for these querries
     can be set.
   - The mininal timeout: it is possible to provide a time out to all blocking I/O methods
     If the provided timeout is smaller then the minimal timeout, the minimal timeout
     is used.
 */

/**
   @ingroup amxb_config
   @brief
   Sets a log callback function.

   The log callback function when set will be called for each operation that
   has been executed on a connection.

   The bus context, operator name, object path and the result of the operation
   is passed to the log callback function.

   @note
   Only one function can be set, to remove it use NULL.

   @param log_fn The log callback function, when NULL removes the callback function
 */
void amxb_set_log_cb(amxb_be_logger_t log_fn);

/**
   @ingroup amxb_config
   @brief
   Calls the log callback function if set.

   When a log callback function is set using @ref amxb_set_log_cb, calling this
   function will invoke the log callback.

   @param ctx the bus context
   @param dm_op the data model operator description
   @param path the object path
   @param result the final result of the operation.
 */
void amxb_log(amxb_bus_ctx_t* ctx,
              const char* dm_op,
              const char* path,
              int result);

/**
   @ingroup amxb_config
   @brief
   Sets the internal timeout in seconds

   The default internal timeout is set to 30 seconds. Using this function
   this timeout can be changed.

   @param seconds the new internal timeout in seconds
 */
void amxb_set_internal_timeout(int seconds);

/**
   @ingroup amxb_config
   @brief
   Returns the current internal timeout.

   @return
   The current configured internal timeout in seconds.
 */
int amxb_get_internal_timeout(void);

/**
   @ingroup amxb_config
   @brief
   Sets the minimal timeout in seconds

   The default minimal timeout is set to 10 seconds. Using this function
   this timeout can be changed.

   Functions that takes a timeout argument (typically blocking I/O functions) and
   the provided timeout is smaller then the minimal timeout, the minimal timeout
   is used instead of the provided timedout.

   @param seconds the new minial timeout in seconds
 */
void amxb_set_minimal_timeout(int seconds);

/**
   @ingroup amxb_config
   @brief
   Returns the current minimal timeout.

   @return
   The current configured minimal timeout in seconds.
 */
int amxb_get_minimal_timeout(int timeout);

#ifdef __cplusplus
}
#endif

#endif // __AMXB_CONFIG_H__
