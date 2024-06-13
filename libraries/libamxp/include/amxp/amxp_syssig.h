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


#if !defined(__AMXP_SYSSIG_H__)
#define __AMXP_SYSSIG_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdbool.h>
#include <signal.h>

/**
   @file
   @brief
   Ambiorix Linux Signal Handling
 */

/**
   @defgroup amxp_syssig System Signal Handling

   @brief
   Provides functionality to translate Linux System Signals to Ambiorix signal/slot mechanism

   Handling system signals using the system provided methods have some limitations.
   In a system signal handler the set of possible system calls that can be done
   is very limited.

   The Ambiorix System Signal API translates a system signal to an Ambiorix
   signal. To such a signal you can connect many slots (callback functions).

   For more information about Ambiorix Signal/Slots @see amxp_signal_slots.
 */

/**
   @ingroup amxp_syssig

   @brief
   Defines highest possible system signal
 */
#define AMXP_SYSSIG_MAX 32

/**
   @ingroup amxp_syssig

   @brief
   Enables or disables monitoring of a system signal.

   When a system signal gets enabled, the signal name is added to the global
   Ambiorix signal manager. The name of the signal is retrieved using
   strsignal function.

   @note
   When enabling a system signal it is possible that other parts of the application
   that rely on the signal stop working, as the signal is handeld by Ambiorix.
   So use with caution.

   After enabling a signal it is possible to connect slots (callback) functions
   to it using @ref amxp_slot_connect.

   The name of the signal can be retrieved using "strsignal(sigid)".

   @param sigid id of the system signal example SIGUSR1
   @param enable true to enable monitoring, false to stop monitoring

   @return
   0 when signal is successfully enabled and is being monitored
 */
int amxp_syssig_enable(const int sigid, const bool enable);

/**
   @ingroup amxp_syssig

   @brief
   Checks if a system signal is being monitored

   If a system signal is enabled for monitoring this function will return true.

   @param sigid id of the system signal example SIGUSR1

   @return
   true when the signal was enabled for being monitored
 */
bool amxp_syssig_is_enabled(const int sigid);

/**
   @ingroup amxp_syssig

   @brief
   Returns a file descriptor that can be used in an eventloop.

   System signal monitoring is done using "signalfd". The filedescriptor must
   be added to your eventloop to make it work. When data is available on this
   filedescriptor the function @ref amxp_syssig_read must be called to make
   sure the correct dispatching is done (calling of the slots)

   @return
   A file descriptor or -1 if non is available
 */
int amxp_syssig_get_fd(void);

/**
   @ingroup amxp_syssig

   @brief
   Reads from the file descriptor

   Use this function in an eventloop. When a system signal is received data will
   become available for read on the signal fd. Use @ref amxp_syssig_get_fd to get
   the file descriptor and add it to your eventloop.

   This function will make sure that all data is read from the file descriptor
   and that the correct slots are called.

   @return
   0 when reading and dispatching is done successful, any other value indicates
   an error condition.
 */
int amxp_syssig_read(void);

#ifdef __cplusplus
}
#endif

#endif // __AMXP_SIGNAL_H__