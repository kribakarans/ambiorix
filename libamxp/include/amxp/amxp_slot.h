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


#if !defined(__AMXP_SLOT_H__)
#define __AMXP_SLOT_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <amxc/amxc_variant.h>

/**
   @file
   @brief
   Ambiorix slot API header file
 */

/**
   @ingroup amxp_signal_slots
   @defgroup amxp_slots Slots

   Slots are callback functions that are connected to named signals.

   When a signal is triggered, all slots (callback functions) connected to the
   named signal are called.
 */

/**
   @ingroup amxp_slots
   @brief
   Slot callback function signature

   A slot is a callback function with this signature.

   @param sig_name the name of the signal
   @param data the data of the signal
   @param priv a pointer to some data, provided when connecting
 */
typedef void (* amxp_slot_fn_t) (const char* const sig_name,
                                 const amxc_var_t* const data,
                                 void* const priv);

/**
   @ingroup amxp_slots
   @brief
   Connects a slot (function) to a named signal of a signal manager.

   When the function (slot) is connected to the signal, the function is called
   each time the signal is "triggered".

   When "*"  is used as signal name, the slots is connected to all know signals
   of the given signal manager or when sig_mngr is NULL to all know signals from
   all signal managers.

   When sig_mgr is NULL and sig_name is "*", the slot will also be connected to
   new added signals (signals that were not existing at the time of call to this
   function).

   When a valid expression is added the slot is only called when expression
   evaluates to true, using the signal data as input. If the signal has not data
   the slot is also called even when an expression is provided.

   Use @ref amxp_slot_disconnect or @ref amxp_slot_disconnect_all to disconnect
   the slot from signals.

   @param sig_mngr the signal manager, or null for the global signal manager
   @param sig_name the signal you want to connect to
   @param expression Null or a string containing a valid expression
   @param fn the slot function (callback function)
   @param priv a pointer to some data, will be passed to the slot function
               when the signal is triggered

   @return
   0 when connection was successful, otherwise an error occurred
 */
int amxp_slot_connect(amxp_signal_mngr_t* const sig_mngr,
                      const char* const sig_name,
                      const char* const expression,
                      amxp_slot_fn_t fn,
                      void* const priv);

/**
   @ingroup amxp_slots
   @brief
   Connects a slot (function) to signals using a regular expression

   The slot is connected to all signals of which the name is matching the
   given regular expression. If later signals are added and the name of the new
   signal is also matching the regular expression the slot will be
   automatically connected to the new signal as well.

   Optionally a expression can be added. The expression works only on signals
   the provide a data. The slot is only called when the expression evalutes to
   true or when the signal has no data.

   Use @ref amxp_slot_disconnect or @ref amxp_slot_disconnect_all to disconnect
   the slot from signals.

   @param sig_mngr the signal manager, or null for the global signal manager
   @param sig_reg_exp a regular expression, the slot is connected to all signals
                      matching the regular expression
   @param expression Null or a string containing a valid expression
   @param fn the slot function (callback function)
   @param priv a pointer to some data, will be passed to the slot function
               when the signal is triggered

   @return
   0 when connection was successful, otherwise an error occurred
 */
int amxp_slot_connect_filtered(amxp_signal_mngr_t* const sig_mngr,
                               const char* const sig_reg_exp,
                               const char* const expression,
                               amxp_slot_fn_t fn,
                               void* const priv);
/**
   @ingroup amxp_slots
   @brief
   Connects a slot to all existing and future signals

   This function does exactly the same as @ref amxp_slot_connect where sig_name
   is "*" and sig_mngr is NULL, if no signal regular expression is
   provided (NULL).

   If a regular expression is provided the slot is connected to all known and
   future signals that matches the regular expression.

   @param sig_reg_exp a regular expression, the slot is connected to all signals
                      matching the regular expression
   @param expression Null or a string containing a valid expression
   @param fn the slot function (callback function)
   @param priv a pointer to some data, will be passed to the slot function
               when the signal is triggered

   @return
   0 when connection was successful, otherwise an error occurred
 */
int amxp_slot_connect_all(const char* const sig_reg_exp,
                          const char* const expression,
                          amxp_slot_fn_t fn,
                          void* const priv);

/**
   @ingroup amxp_slots
   @brief
   Disconnects a slot from (a) signal(s).

   Disconnecting a slot using this function will:
   - Remove all connections of the slot from the signal with the matching name
   - Remove all connections with a regular expression matching the name.

   A removed slot will not be called anymore when the signal is triggered.

   When "*" is given as sign_name, the slot will be disconnected from all signals
   of the specified signal manager (sig_mngr), when sig_mngr is NULL, the slot
   is disconnected from all signals it was connected to.

   @param sig_mngr the signal manager, or null for the global signal manager
   @param sig_name the signal you want to disconnect from use "*" for all
   @param fn the slot function (callback function).

   @return
   0 when disconnection was successful, otherwise an error occurred.
 */
int amxp_slot_disconnect(amxp_signal_mngr_t* const sig_mngr,
                         const char* const sig_name,
                         amxp_slot_fn_t fn);

/**
   @ingroup amxp_slots
   @brief
   Disconnects a slot from (a) signal(s).

   Disconnecting a slot using this function will:
   - Remove all connections of the slot with the matching private data from the signals
   - Remove all connections with a regular expression and matching private data

   A removed slot will not be called anymore when the signal is triggered.

   @param sig_mngr the signal manager, or null for the global signal manager
   @param fn the slot function (callback function).
   @param priv The private data pointer that was provided when connecting

   @return
   0 when disconnection was successful, otherwise an error occurred.
 */
int amxp_slot_disconnect_with_priv(amxp_signal_mngr_t* sig_mngr,
                                   amxp_slot_fn_t fn,
                                   void* priv);

/**
   @ingroup amxp_slots
   @brief
   Disconnects a slot from a signal.

   Disconnecting a slot using this function will:
   - Remove all connections of the slot with the matching private data from the
     signal with the given name or from all signals when no signal name is given.
   - Remove all connections with a regular expression and matching private data
     when no signal name is given.

   A removed slot will not be called anymore when the signal is triggered.

   @param sig_mngr the signal manager, or null for the global signal manager
   @param sig_name the signal name, or NULL for all.
   @param fn the slot function (callback function).
   @param priv The private data pointer that was provided when connecting

   @return
   0 when disconnection was successful, otherwise an error occurred.
 */
int amxp_slot_disconnect_signal_with_priv(amxp_signal_mngr_t* sig_mngr,
                                          const char* sig_name,
                                          amxp_slot_fn_t fn,
                                          void* priv);
/**
   @ingroup amxp_slots
   @brief
   Disconnects a slot from all signals it was connected to

   The slot is removed from all signals it was connected to, including
   regular expression slot (see @ref amxp_slot_connect_filtered)

   @param fn the slot function (callback function)
 */
void amxp_slot_disconnect_all(amxp_slot_fn_t fn);

#ifdef __cplusplus
}
#endif

#endif // __AMXP_SLOT_H__
