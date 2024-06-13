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


#if !defined(__AMXP_SIGNAL_H__)
#define __AMXP_SIGNAL_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <amxc/amxc_variant.h>

/**
   @file
   @brief
   Ambiorix signal manager and signal API header file
 */

/**
   @defgroup amxp_signal_slots Signal/Slots

   Signal/Slots implements a generic observer pattern
 */

/**
   @ingroup amxp_signal_slots
   @defgroup amxp_signal_mngr Signal managers

   A signal manager is a collection of named signals. It can trigger or emit
   a signal.
 */

/**
   @ingroup amxp_signal_slots
   @defgroup amxp_signal Signals

   When a signal is triggered, all callback functions (slots) that are connected
   are called immediately. When a signal is emitted, it will be triggered
   after reading from the amxp signal file descriptor. It is recommended
   to implement an eventloop.

   A signal is a name to which slots (callback functions) can connect.
 */

/**
   @ingroup amxp_signal_mngr
   @brief
   Structure containing the signal manager information
 */
typedef struct _amxp_signal_mngr {
    amxc_htable_t signals;            /**< All available signals in this signal manager */
    amxc_lqueue_t signal_queue;       /**< A queue containing emitted signals */
    amxc_llist_t regexp_slots;        /**< Slots connected to the signal manager using a regular expression */
    amxc_llist_it_t it;               /**< Linked list iterator, used to add the signal manager to the list of signal managers */
    bool enabled;                     /**< When set to false no signals are handled, signal manager is disabled */
    bool deleted;                     /**< Signal manager is deleted while handling signals */
    bool triggered;                   /**< Signal manager is currently handling signals */
    bool suspended;                   /**< Signal manager is suspended, all events are queued but not handled until resumed  */
} amxp_signal_mngr_t;

/**
   @ingroup amxp_signal
   @brief
   Structure containing the signal information
 */
typedef struct _amxp_signal {
    amxc_htable_it_t hit;                /**< Hash table iterator */
    amxc_llist_t slots;                  /**< Linked list containig callback functions */
    const char* name;                    /**< Unique name of the signal */
    amxp_signal_mngr_t* mngr;            /**< Pointer to the signal manager containin the signal */
    bool triggered;                      /**< Is set to true while being triggered */
} amxp_signal_t;

/**
   @ingroup amxp_slots
   @brief
   Deferred callback function signature

   Deferred functions are called from the eventloop

   @param data some data
   @param priv a pointer to some data
 */
typedef void (* amxp_deferred_fn_t) (const amxc_var_t* const data,
                                     void* const priv);
/**
   @ingroup amxp_signal_mngr
   @brief
   Constructor function, creates a new signal manager instance.

   This function allocates memory, to free the allocated memory use the
   destruction function @ref amxp_sigmngr_delete

   @param sig_mngr where to store the sig_mngr pointer

   @return
   0 when successful, otherwise an error code
 */
int amxp_sigmngr_new(amxp_signal_mngr_t** sig_mngr);

/**
   @ingroup amxp_signal_mngr
   @brief
   Destructor function, deletes a signal manager instance

   All signals of the signal manager will be removed, all connected slots
   will be automatically disconnected

   @param sig_mngr ponter to the sig_mngr pointer. Will be set to NULL

   @return
   0 when successful, otherwise an error code
 */
int amxp_sigmngr_delete(amxp_signal_mngr_t** sig_mngr);

/**
   @ingroup amxp_signal_mngr
   @brief
   Initializing function, initializes members of the @ref amxp_signal_mngr_t structure.

   Use this function when the @ref amxp_signal_mngr_t structure is declared on
   the stack. It will initialize all members of this structure.

   @param sig_mngr pointer to a @ref amxp_signal_mngr_t structure

   @return
   0 when successful, otherwise an error code
 */
int amxp_sigmngr_init(amxp_signal_mngr_t* sig_mngr);

/**
   @ingroup amxp_signal_mngr
   @brief
   Clean-up functions, cleans-up all members of a @ref amxp_signal_mngr_t structure

   All signals of the signal manager will be removed, all connected slots
   will be automatically disconnected

   @param sig_mngr pointer to a @ref amxp_signal_mngr_t structure

   @return
   0 when successful, otherwise an error code
 */
int amxp_sigmngr_clean(amxp_signal_mngr_t* sig_mngr);

/**
   @ingroup amxp_signal_mngr
   @brief
   Adds a signal to a signal manager

   Creates a new signal with the given name and adds it to the signal manager.
   If sig_mngr is NULL the newly created signal is added to the global signal
   manager. A signal name must be unique. If a signal with the name already
   exists in the signal manager, this function fails.

   @param sig_mngr ponter to the sig_mngr pointer. Will be set to NULL
   @param name the name of the signal

   @return
   0 when successful, otherwise an error code
 */
int amxp_sigmngr_add_signal(amxp_signal_mngr_t* const sig_mngr,
                            const char* name);

/**
   @ingroup amxp_signal_mngr
   @brief
   Removes a signal from a signal manager

   When sig_mngr is NULL, the signal will be removed from the global signal
   manager.

   If no signal is found in the the signal manager with the given name,
   this function fails.

   @note
   This function removes the signal from the signal manager, but does not free
   the memory allocated for the signal. When this function is called from
   within a slot callback function, the memory will be freed automatically when
   the slot callback function returns.

   @param sig_mngr ponter to the sig_mngr pointer. Will be set to NULL
   @param name the name of the signal

   @return
   0 when successful, otherwise an error code
 */
int amxp_sigmngr_remove_signal(amxp_signal_mngr_t* const sig_mngr,
                               const char* name);
/**
   @ingroup amxp_signal_mngr
   @brief
   Get the pointer to the signal

   Searches the signal manager for the given signal, if no signal is found
   with the given name, the functions returns a NULL pointer.

   When sig_mngr is NULL, the signal is searched in the global signal manager.

   The returned pointer can be used in all amxp signal functions that take a
   pointer to @ref amxp_signal_t struct

   @param sig_mngr ponter to the sig_mngr pointer. Will be set to NULL
   @param name the name of the signal

   @return
   A amxp_signal_t pointer or NULL when no signal is found
 */
amxp_signal_t* amxp_sigmngr_find_signal(const amxp_signal_mngr_t* const sig_mngr,
                                        const char* name);

/**
   @ingroup amxp_signal_mngr
   @brief
   Triggers a signal

   Searches the signal manager for the given signal and triggers the signal.
   This function is basically the same as calling @ref amxp_sigmngr_find_signal
   and @ref amxp_signal_trigger in sequence.

   When sig_mngr is NULL, the signal is searched in the global signal manager.

   When no signal is found with the given name, nothing is done.

   @param sig_mngr ponter to the sig_mngr pointer. Will be set to NULL
   @param name the name of the signal
   @param data the data that is passed to all the slots.
 */
void amxp_sigmngr_trigger_signal(amxp_signal_mngr_t* const sig_mngr,
                                 const char* name,
                                 const amxc_var_t* const data);

/**
   @ingroup amxp_signal
   @brief
   Emits a signal

   Searches the signal manager for the given signal and emits the signal.
   This function is basically the same as calling @ref amxp_sigmngr_find_signal
   and @ref amxp_signal_emit in sequence.

   When sig_mngr is NULL, the signal is searched in the global signal manager.

   When no signal is found with the given name, this function fails.

   The signal will be triggered when reading the amxp signal file descriptor
   using function @ref amxp_signal_read.

   To be able to use this method it is recommended to implement an eventloop.

   @param sig_mngr ponter to the sig_mngr pointer. Will be set to NULL
   @param name the name of the signal
   @param data the data that is passed to all the slots.

   @return
   0 when successful, otherwise an error code
 */
int amxp_sigmngr_emit_signal(const amxp_signal_mngr_t* const sig_mngr,
                             const char* name,
                             const amxc_var_t* const data);

/**
   @ingroup amxp_signal
   @brief
   Defers a function call

   Adds a function call to the singal queue. This function will be called at the
   moment the queue is being handled. Using deferred function calls it is
   possible to make synchronous functions behave asynchronously.

   When sig_mngr is NULL, the function call is added to the queue of global
   signal manager.

   The function will be called when reading the amxp signal file descriptor
   using function @ref amxp_signal_read.

   To be able to use this method it is recommended to implement an eventloop.

   @param sig_mngr pointer to the sig_mngr pointer. Will be set to NULL
   @param fn the deferred function
   @param data the data that is passed to the function.
   @param priv some pointer to private data

   @return
   0 when successful, otherwise an error code
 */
int amxp_sigmngr_deferred_call(amxp_signal_mngr_t* const sig_mngr,
                               amxp_deferred_fn_t fn,
                               const amxc_var_t* const data,
                               void* priv);
/**
   @ingroup amxp_signal
   @brief
   Enables or disables the signal manager

   When a signal manager is disabled, all emitted signals or triggered signals
   are discarded, including the signal data.

   @param sig_mngr pointer to the signal manager. Use NULL for the global signal manager.
   @param enable when true signal emitting and triggering is enabled, when false emitting
                 and triggering of signals is blocked for this signal manager.

   @return
   0 when successful, otherwise an error code
 */
int amxp_sigmngr_enable(amxp_signal_mngr_t* const sig_mngr,
                        bool enable);

/**
   @ingroup amxp_signal
   @brief
   Suspends the handling of signals for the signal manager

   When a signal manager is suspended, all emitted signals are queued but not handled
   until the signal manager is resumed with @ref amxp_sigmngr_resume.

   When a signal manager is suspended, all triggered signals are dropped including
   the signal data.

   When the signal manager was already suspended this functions returns a none-zero
   value.

   @param sig_mngr pointer to the signal manager. Use NULL for the global signal manager.

   @return
   0 when successful, otherwise an error code
 */
int amxp_sigmngr_suspend(amxp_signal_mngr_t* const sig_mngr);

/**
   @ingroup amxp_signal
   @brief
   Resumes the handling of signals for the signal manager

   When a signal manager is resumed, all queued signals will be handled by the
   eventloop.

   After resuming a signal manager it will be possible to trigger signals again.

   When the signal manager was not suspended this functions returns a none-zero
   value.

   @param sig_mngr pointer to the signal manager. Use NULL for the global signal manager.

   @return
   0 when successful, otherwise an error code
 */
int amxp_sigmngr_resume(amxp_signal_mngr_t* const sig_mngr);

/**
   @ingroup amxp_signal
   @brief
   Constructor function, creates a new signal.

   Creates a new signal and adds it to the given signal manager. If sig_mngr
   is NULL, the signal is added to the global signal manager.

   @note
   This function allocates memory, the free the allocated memory use the
   destruction function @ref amxp_signal_delete

   @param sig_mngr pointer to signal manager where the signal must be added
   @param signal pointer to the pointer that wil point to the new allocated signal
   @param name name of the signal

   @return
   0 when successful, otherwise an error code
 */
int amxp_signal_new(amxp_signal_mngr_t* sig_mngr,
                    amxp_signal_t** signal,
                    const char* name);

/**
   @ingroup amxp_signal
   @brief
   Destructor function, deletes a signal

   All connected slots will be automatically disconnected.

   The signal is removed from the signal manager it was added to.

   @note
   It is not safe to delete a signal from within a slot callback function.

   @param signal pointer to the pointer that wil point to the new allocated signal.

   @return
   0 when successful, otherwise an error code
 */
int amxp_signal_delete(amxp_signal_t** signal);

/**
   @ingroup amxp_signal
   @brief
   Triggers a signal

   All slots connected to the signal will be called. When a private data pointer
   was given at the time of the connect, the private data is passed to the slot.

   The signal name and the signal data are passed to all the connected slots as
   well.

   @param signal pointer to the signal structure.
   @param data the data that will be passed to all slots.
 */
void amxp_signal_trigger(amxp_signal_t* const signal,
                         const amxc_var_t* const data);

/**
   @ingroup amxp_signal
   @brief
   Emits a signal

   The signal will be triggered when reading the amxp signal file descriptor
   using function @ref amxp_signal_read.

   To be able to use this method it is recommended to implement an eventloop.

   @param signal pointer to the signal structure.
   @param data the data that will be passed to all slots.

   @return
   0 when successful, otherwise an error code
 */
int amxp_signal_emit(const amxp_signal_t* const signal,
                     const amxc_var_t* const data);

/**
   @ingroup amxp_signal
   @brief
   Reads from the amxp signal file descriptor.

   Each signal that was emitted will be read from the file descriptor and
   triggered. This is usefull when you want to do a full stack unwind before
   triggering the slots.

   To be able to use this method it is recommended to implement an eventloop.

   @return
   0 when successful, otherwise an error code
 */
int amxp_signal_read(void);

/**
   @ingroup amxp_signal
   @brief
   Gets the amxp signal file descriptor

   @return
   The amxp signal file descriptor
 */
int amxp_signal_fd(void);

/**
   @ingroup amxp_signal
   @brief
   Disconnects all slots from the signal.

   @param signal pointer to the signal structure.

   @return
   0 when successful, otherwise an error code
 */
int amxp_signal_disconnect_all(amxp_signal_t* const signal);

/**
   @ingroup amxp_signal
   @brief
   Gets the name of the signal

   @param signal pointer to the signal structure.

   @return
   The name of the signal
 */
const char* amxp_signal_name(const amxp_signal_t* const signal);

/**
   @ingroup amxp_signal
   @brief
   Checks if the signal has slots conencted

   @param signal pointer to the signal structure.

   @return
   True when at least one slot is connected, false when no slots are connected.
 */
bool amxp_signal_has_slots(const amxp_signal_t* const signal);

#ifdef __cplusplus
}
#endif

#endif // __AMXP_SIGNAL_H__
