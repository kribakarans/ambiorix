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

#if !defined(__AMXP_TIMER_H__)
#define __AMXP_TIMER_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <sys/time.h>

/**
   @file
   @brief
   Ambiorix timer API header file
 */

/**
   @defgroup amxp_timer Timer

   @brief
   Timers can be used to do a job at regular intervals or once some time later.

   To have timers fully functional an event loop must be started. The timers are
   using the SIGALRM signal. Multiple timers can be started, but only one timer
   will be the next to trigger the SIGALRM.

   @section amxp_timer_using Using timers

   To create a timer, use the @ref amxp_timer_new function. Some arbitrary private
   data can be attached to the timer. This private data is a pointer to memory allocated
   by the caller and must be managed by the caller. This private data can be changed
   at any time by modifying the priv member of the amxp_timer_t structure.
   The pointer to the private data will be passed to the callback function.
   The callback function will be called each time the timer expires.

   To start a timer, use the @ref amxp_timer_start function.

   By default a timer will only expire once. To have the timer repeat, an interval must be set
   before starting the timer, an interval can be set using @ref amxp_timer_set_interval.
   The interval and the initial expire time can be different. While the timer is running
   the interval can be changed and will take effect on the next time the timer expires.

   A timer can be stopped at any time by calling @ref amxp_timer_stop, to restart
   the time call @ref amxp_timer_start again.

   A running timer can be reset to it's initial value by calling @ref amxp_timer_start again.

   All timers can be disabled or enabled again by callling @ref amxp_timers_enable.

   A timer that is not needed any more can be removed by calling @ref amxp_timer_delete.

   The current state of a timer can be fetched using @ref amxp_timer_get_state.

   @section amxp_timer_el Timers and eventloops

   To make the timer implementation work, an eventloop must be available that monitors
   SIG_ALRM system signal. When the SIG_ALRM is triggered the eventloop must call the functions
   - @ref amxp_timers_calculate
   - @ref amxp_timers_check

   The first one will calculate the remaining time for each timer, if the remaining time
   is 0 or lower the time is expired, the state of the timer will be set to expired state.
   Timers in started state will become active when this function is called.

   The @ref amxp_timers_check will call the callback function for each expired timer and
   reset the state of the timer if needed. This function will remove the timers in
   deleted state from memory.
 */

typedef struct _amxp_timer amxp_timer_t;

/**
   @ingroup amxp_timer
   @brief
   Timer timeout callback function

   Definition of the timer timeout callback function. This function is called
   whenever a timer expires. The private data attached to the timer when
   creating the timer using @ref amxp_timer_new is passed as is to this
   callback function.

   It is allowed to delete the timer in the callback function, it is not allowed
   to delete other timers in the callback function.
 */
typedef void (* amxp_timer_cb_t) (amxp_timer_t* timer, void* priv);

/**
   @ingroup amxp_timer
   @brief
   The timer states

   This enum holds all possible timer states
 */
typedef enum _amxp_timer_state {
    amxp_timer_off,       /**< Timer is not running */
    amxp_timer_started,   /**< Timer is started */
    amxp_timer_running,   /**< Timer is running */
    amxp_timer_expired,   /**< Timer has expired */
    amxp_timer_deleted,   /**< Timer is deleted and can not be used anymore */
} amxp_timer_state_t;

/**
   @ingroup amxp_timer
   @brief
   The timer type

   This structure defines a timer.
 */
struct _amxp_timer {
    amxc_llist_it_t it;                    /**< Linked list iterator to put the tiomer in the global list of timers */
    struct itimerval timer;                /**< The timer interval, if not set the timer is a single shot timer */
    amxp_timer_state_t state;              /**< The timer state */
    amxp_timer_cb_t cb;                    /**< The callback function, called when a timer expires */
    void* priv;                            /**< Some user specified private data, the timer doesn't take ownership of this pointer */
};

/**
   @ingroup amxp_timer
   @brief
   Caclulates the remaining time of all timers.

   Updates all timers with the time passed since the last update by subtracting
   the passed time from each timer. If a timer reaches zero or becomes negative
   it is expired and the state is changed to @ref amxp_timer_expired.

   The timer with the smallest remaining time is used to set the SIGALRM signal.

   @note
   Typically this function is called from within an eventloop.
 */
void amxp_timers_calculate(void);

/**
   @ingroup amxp_timer
   @brief
   Check all timers and call the callback function when the timer is in
   @ref amxp_timer expired state.

   Loops over all timers and for each expired timer the timeout callback function
   is called. If the timer has an interval set, the state is reset to
   @ref amxp_timer_running, if no interval is availble the timer state is reset
   to @ref amxp_timer_off.

   @note
   Typically this function is called from within an eventloop and after
   @ref amxp_timers_calculate. This function will call the timer expired callback
   function for all expired timers. In the callback function it is possible to
   delete the timer for which the callback functions was called, but not any
   other timer can be deleted in the callback function as it will modify the
   timer's list.
 */
void amxp_timers_check(void);

/**
   @ingroup amxp_timer
   @brief
   Enable or disable all timers.

   With this function all timers can be disable or enabled. When the timers
   are disabled they can still expire, but the callback functions are not called.
   The next time the timers are enabled all callback function of the expired
   timers will be called in the next iteration in the event loop.

   @param enable True to enable timer handling or false to disable timer handling
 */
void amxp_timers_enable(bool enable);

/**
   @ingroup amxp_timer
   @brief
   Allocate and initializes a new timer

   Allocates and initializes a new timer structure.
   The new timer will be added to the list of timers.

   The *timer must be initialized to NULL before calling this function.

   @param timer will receive the pointer to the new timer.
   @param cb the time callback function, see @ref amxp_timer_cb_t
   @param priv pointer to private data, this pointer is passed to the callback
               function when the timer expires.

   @return
    0 when the imer is allocated and initialized. any other value
    indicates an error
 */
int amxp_timer_new(amxp_timer_t** timer, amxp_timer_cb_t cb, void* priv);

/**
   @ingroup amxp_timer
   @brief
   Deletes a timer.

   Removes the timer timers list and cleanup allocated memory.

   @note
   When private data was attached to the timer and memory was allocated for it,
   it is up to the caller to free that allocated memory.

   @param timer pointer to the timer.
 */
void amxp_timer_delete(amxp_timer_t** timer);

/**
   @ingroup amxp_timer
   @brief
   Sets the interval of a timer in milli seconds

   Assigns an interval to the timer. When the initial timeout of the timer occurs,
   this interval time will be used to restart the timer.

   A timer with an interval set will keep on running until @ref amxp_timer_stop is
   called.

   @param timer pointer to the timer.
   @param msec the interval specified in milliseconds

   @return
   0 on success, any other value indicates an error.
 */
int amxp_timer_set_interval(amxp_timer_t* timer, unsigned int msec);

/**
   @ingroup amxp_timer
   @brief
   Get the remaining time of the timer

   Returns the remaining time of the timer in milliseconds.
   If a timer is not running, this function will always return 0.

   @param timer pointer to the timer.

   @return
   The remaining time in milliseconds
 */
unsigned int amxp_timer_remaining_time(amxp_timer_t* timer);

/**
   @ingroup amxp_timer
   @brief
   Starts or resets a timer

   The timer will be started, the initial time out value is must be provided in
   milliseconds.

   If an interval time was set, the interval will start after the initial timeout.

   If the timer was already started, the timer will be reset and restarted using
   the new timeout value.

   @param timer pointer to the timer.
   @param timeout_msec initial timeout value.

   @return
   0 when the timer is started, any other value indicates an error.
 */
int amxp_timer_start(amxp_timer_t* timer, unsigned int timeout_msec);

/**
   @ingroup amxp_timer
   @brief
   Stops the timer

   This function will stop the timer. After calling this function the timeout
   callback function of the timer will not be called again until the timer is
   restarted using @ref amxp_timer_start

   @param timer pointer to the timer.

   @return
   0 when the timer is stopped, any other value indicates an error.
 */
int amxp_timer_stop(amxp_timer_t* timer);

/**
   @ingroup amxp_timer
   @brief
   Get the timer's state.

   Returns the current state of the timer.

   @param timer pointer to the timer.

   @return
   The current state of the timer, any of @ref amxp_timer_state_t
 */
amxp_timer_state_t amxp_timer_get_state(amxp_timer_t* timer);

#ifdef __cplusplus
}
#endif

#endif // __AMXP_TIMER_H__
