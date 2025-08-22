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

#if !defined(__AMXP_SCHEDULER_H__)
#define __AMXP_SCHEDULER_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdbool.h>
#include <stdint.h>

#include <amxp/amxp_signal.h>
#include <amxp/amxp_slot.h>
#include <amxp/amxp_timer.h>
#include <amxp/amxp_cron.h>

#ifndef __AMXC_LLIST_H__
#error "Missing include <amxc/amxc_llist.h>"
#endif

#ifndef __AMXC_HTABLE_H__
#error "Missing include <amxc/amxc_htable.h>"
#endif

/**
   @file
   @brief
   Ambiorix scheduler
 */

/**
   @defgroup amxp_scheduler Scheduler

   Ambiorix Scheduler.

   A scheduler takes schedule items, which can be defined using a cron expression.
   A schedule item triggers at some point in time, when a schedule is triggered the
   scheduler will emit the signal "trigger:ID".

   Each schedule item has an identifier (which must be unique within the allocated
   scheduler), this identifier is passed as data in the signal and is also used in
   the name of the signal.

   A schedule item can have a duration (in seconds). When the schedule item
   triggers and has a duration different from 0, the scheduler will emit the signal
   "start:ID" and when the duration expires the scheduler will emit the signal
   "stop:ID".

 */

/**
   @ingroup amxp_scheduler
   @brief
   Structure containing a schedule item.

   This structure defines a schedule item. A schedule item defines points in time and
   can optionally have duration. The points in time are defined using a cron expression.
   The duration can either be a fixed time in seconds or another point in time defined
   using a second cron expression.

   A schedule item can be enabled or disabled at any moment.

   A schedule item has a unique identifier, which can be any string, and must be
   unique within a scheduler. The schedule item identifier is used in the signal names.

   To activate a schedule item it must be added to a scheduler. Whenever the defined
   point in time is readched the scheduler will emit or trigger a signal (event).

   Multiple callback functions (slots) can be added to the scheduler, either on all
   schedule items or on a specific item.
 */
typedef struct _scheduler_item {
    amxp_cron_expr_t cron;      /**< The parsed cron expression */
    amxp_cron_expr_t end_cron;  /**< The end time, is used to calculated the duration*/
    uint32_t duration;          /**< The duration of the item in seconds*/
    bool end_time_is_set;       /**< Set to true when end cron is set.*/
    amxc_ts_t next;             /**< Next time this schedule will trigger*/
    amxp_timer_t* timer;        /**< The timer, used when this schedule is triggered with a duration different then 0*/
    bool enabled;               /**< Is this schedule item enabled (true) or disabled (false) */
    amxc_llist_it_t lit;        /**< Used to store the item in the scheduler ordered list*/
    amxc_htable_it_t hit;       /**< Used to store the item in the scheduler, used for look-up by identifier */
} amxp_scheduler_item_t;

/**
   @ingroup amxp_scheduler
   @brief
   Structure containing a scheduler.

   A scheduler can contain multiple schedule items (amxp_scheduler_item_t). Each time
   an item is added (using @ref amxp_scheduler_set_cron_item, @ref amxp_scheduler_set_weekly_item,
   @ref amxp_scheduler_set_cron_begin_end_item, @ref amxp_scheduler_set_weekly_begin_end_item),
   the list of items is updated and sorted again. The first item in the list is
   the item the will be triggered first.

   A scheduler always works on the current time (UTC or local time). So make sure
   that time synchronization has happend before using a scheduler.

   When NTP synchronization didn't happen yet, it is recommened to disable the scheduler
   and enable it again when time synchronization has happened.

   A scheduler can be enabled or disabled using @ref amxp_scheduler_enable.

   A scheduler contains a signal manager. This signal manager will be used
   to emit the signals "trigger:ID", "start:ID", "stop:ID". (Here the ID is the schedule
   item identifier)

   When these signals are emitted, the signal data will contain the schedule item
   identifier and the reason (trigger, start, stop). When the "start" signal is
   emitted, the signal data will also contain the duration in seconds before
   the "stop" signal is emitted.

   Callback functions (slots) can be added using @ref amxp_scheduler_connect or
   by using one of the amxp_slot_connect functions, and removed again using one
   of the amxp_slot_disconnect functions.
 */
typedef struct _scheduler {
    amxp_signal_mngr_t sigmngr; /**< The scheduler signal manager */
    bool use_local_time;        /**< When set to true, this scheduler will use local time to calculate the next trigger time, otherwise UTC is used. */
    amxp_timer_t* timer;        /**< The scheduler timer, this will be started using the calculated time until next event, when it expires a signal is emitted. */
    amxc_htable_t items;        /**< Hash table containing all schedule items, used for look-up by identifier.*/
    amxc_llist_t ordered_items; /**< A linked list containig all schedule items, sorted on next trigger time, smallest first. */
} amxp_scheduler_t;

/**
   @ingroup amxp_scheduler
   @brief
   Allocates a amxp_scheduler_t structures and initializes to an empty scheduler.

   This function allocates a amxp_scheduler_t structure and initializes it to an
   empty scheduler.

   An empty scheduler will be inactive (no timer is started) until the first
   schedule item is added.

   By default the scheduler will be enabled. When adding schedule items they will
   be taken into account immediatly. If more control is needed, first disable
   the scheduler by calling @ref amxp_scheduler_enable.

   By default the scheduler will use UTC time, if all calculations needs to be
   done on local time call the function @ref amxp_scheduler_use_local_time.

   Use @ref amxp_scheduler_set_cron_item, @ref amxp_scheduler_set_cron_begin_end_item,
   @ref amxp_scheduler_set_weekly_item or @ref amxp_scheduler_set_weekly_begin_end_item
   to add schedule items.

   @note
   The allocated memory must be freed when not used anymore,
   use @ref amxp_scheduler_delete to free the memory

   @param scheduler pointer to a pointer that will point to the new allocated amxp_schedule_t structure

   @return
   When allocation is successfull, this functions returns 0.
 */
int amxp_scheduler_new(amxp_scheduler_t** scheduler);

/**
   @ingroup amxp_scheduler
   @brief
   Frees the previously allocated amxp_scheduler_t structure.

   Frees the allocated memory and sets the pointer to NULL.

   All schedule items will be deleted as well, all running timers will be stopped and
   deleted.

   When a schedule item with duration was started, a "stop" signal will be emitted
   before the schedule item is deleted.

   @note
   Only call this function for amxp_scheduler_t structures that are allocated on the heap using
   @ref amxp_scheduler_new.

   @param scheduler pointer to a pointer that points to the allocated amxp_scheduler_t structure
 */
void amxp_scheduler_delete(amxp_scheduler_t** scheduler);

/**
   @ingroup amxp_scheduler
   @brief
   Initializes a amxp_scheduler_t to an empty scheduler.

   This function initializes it to an empty scheduler.

   An empty scheduler will be inactive (no timer is started) until the first
   schedule item is added.

   By default the scheduler will be enabled. When adding schedule items they will
   be taken into account immediatly. If more control is needed, first disable
   the scheduler by calling @ref amxp_scheduler_enable.

   By default the scheduler will use UTC time, if all calculations needs to be
   done on local time call the function @ref amxp_scheduler_use_local_time.

   Use @ref amxp_scheduler_set_cron_item, @ref amxp_scheduler_set_cron_begin_end_item,
   @ref amxp_scheduler_set_weekly_item or @ref amxp_scheduler_set_weekly_begin_end_item
   to add schedule items.

   @note
   When the scheduler is not used any more, the function @ref amxp_scheduler_clean
   must be called. It will do the scheduler clean-up (removes all schedule items and
   timers).

   @param scheduler pointer to a amxp_schedule_t structure

   @return
   When initialization is successfull, this functions returns 0.
 */
int amxp_scheduler_init(amxp_scheduler_t* scheduler);

/**
   @ingroup amxp_scheduler
   @brief
   Cleans the scheduler.

   All schedule items will be removed, all running timers will be stopped and
   deleted.

   When a schedule item with duration was started, a "stop" signal will be emitted
   before the schedule item is deleted.

   Before using the scheduler again, make sure it is initialized again using
   @ref amxp_scheduler_init.

   @param scheduler pointer to an amxp_cron_expr_t structure
 */
void amxp_scheduler_clean(amxp_scheduler_t* scheduler);

/**
   @ingroup amxp_scheduler
   @brief
   Enables or disable the scheduler.

   When enabling a previously disabled scheduler, a recalculation is done
   of all schedule items and a timer is started that will expires when
   the first schedule triggers.

   Enabling an empty scheduler (that is a scheduler without any schedule items),
   will have no effect.

   When disabling a scheduler no signals will be emitted anymore for that
   scheduler, except the "stop" signals. This signal will be
   emitted for schedules that have a duration and were already started.

   @param scheduler pointer to an amxp_scheduler_t structure
   @param enable when set to true, the scheduler will be enable.

   @return
   When successfull, this functions returns 0.
 */
int amxp_scheduler_enable(amxp_scheduler_t* scheduler, bool enable);

/**
   @ingroup amxp_scheduler
   @brief
   Use local time or UTC time in calculation for next trigger times.

   A scheduler calculates for each schedule item when the next occurence will be
   triggered, By default UTC time is used. Using this function the scheduler can be
   switched to use local time.

   @param scheduler pointer to an amxp_scheduler_t structure
   @param use_local_time when set to true, the scheduler will use local time, when set to fals UTC time is used,

   @return
   When successfull, this functions returns 0.
 */
int amxp_scheduler_use_local_time(amxp_scheduler_t* scheduler, bool use_local_time);

/**
   @ingroup amxp_scheduler
   @brief
   Forces recalculation of the schedule items' next occurrence time.

   Under normal circumstances there will be no need to call this function.
   The scheduler itself will do recalculation when needed by itself.

   However this function can be called when system time changes, like NTP synchronizaton
   has happened.

   @param scheduler pointer to an amxp_scheduler_t structure

   @return
   When successfull, this functions returns 0.
 */
int amxp_scheduler_update(amxp_scheduler_t* scheduler);

/**
   @ingroup amxp_scheduler
   @brief
   Connects a callback function to the scheduler.

   A callback functions can be added to a scheduler for a specific schedule item
   identifier or for all currently known schedule items.

   Alternativly the amxp_slot_connection functions can be used to connect to the
   scheduler signals.

   Multiple callback functions can be added to the scheduler.

   The possible scheduler signals are:
   - trigger:ID - only for schedule items without a duration
   - start:ID - only for schedule items with a duration, will be followed by a stop signal
   - stop:ID - only for schedule items with a duration, is always preceded with a start signal

   The ID in above signal names is replaced by the identifier of the scheduler item.

   A pointer to private data can be passed as well. This pointer is passed to the
   callback function. The scheduler itself will not use this private data and will
   not take ownership of the pointer. If memory was allocated it is up to the caller
   to manage the allocated memory.

   @param scheduler pointer to an amxp_scheduler_t structure
   @param id (optional) the identifier for which the callback funcion (slot) must be called
   @param fn the pointer to the callback function
   @param priv private data, will be passed to the callback function

   @return
   When successfull, this functions returns 0.
 */
int amxp_scheduler_connect(amxp_scheduler_t* scheduler,
                           const char* id,
                           amxp_slot_fn_t fn,
                           void* priv);

/**
   @ingroup amxp_scheduler
   @brief
   Disconnects a callback function from the scheduler.

   A previously added callback functions can be removed from a scheduler for a specific
   schedule item identifier or for all currently known schedule items.

   Alternativly the amxp_slot_disconnect functions can be used to disconnect from the
   scheduler signals.

   If a NULL pointer is used as the id the function will be removed from all
   signals from the scheduler.

   @param scheduler pointer to an amxp_scheduler_t structure
   @param id (optional) the identifier for which the callback funcion (slot) must be removed
   @param fn the pointer to the callback function

   @return
   When successfull, this functions returns 0.
 */
int amxp_scheduler_disconnect(amxp_scheduler_t* scheduler, const char* id, amxp_slot_fn_t fn);

/**
   @ingroup amxp_scheduler
   @brief
   Adds a schedule item or updates a schedule item using a cron expression.

   Using a cron expression (see @ref amxp_cron_expr_t) a schedule item is added
   to the scheduler. If a schedule item exists with the given identifier, it will be updated.

   The scheduler will calculate the next time the schedule item should be triggered.

   A duration can be specified. When the duration is not zero (0), the scheduler
   will emit the signal "start:ID" when the schedule is triggered, and starts
   a timer for the defined duration of the schedule item. When the timer expires
   the scheduler will emit the signal "stop:ID".

   For schedule items that have a duration of zero (0), the scheduler will emit
   the signal "trigger:ID" when the schedule item is triggered.

   Each signal will contain the schedule item identifier in the signal data and
   the reason (trigger, start, stop).

   The signal "start:ID" will also contain the duration (in seconds) before
   the "stop:ID" will be send.

   Schedule items with a duration for which the "start" signal was emitted and which
   are deleted before the duration is over, the scheduler will send a "stop" signal
   at the moment they are deleted.

   @param scheduler pointer to an amxp_scheduler_t structure
   @param id the identifier for schedule item
   @param cron_expr a string containing a valid cron expression (see @ref amxp_cron_expr_t)
   @param duration duration in seconds

   @return
   When successfull, this functions returns 0.
 */
int amxp_scheduler_set_cron_item(amxp_scheduler_t* scheduler,
                                 const char* id,
                                 const char* cron_expr,
                                 uint32_t duration);

/**
   @ingroup amxp_scheduler
   @brief
   Adds a schedule item or updates a schedule item using a cron expressions.

   Using a cron expression (see @ref amxp_cron_expr_t) a schedule item is added
   to the scheduler. If a schedule item exists with the given identifier, it will be updated.

   The scheduler will calculate the next time the schedule should be triggered using
   the cron expression provided with argument cron_begin.

   A duration can be specified using a second cron expression (using argument cron_end).
   When the schedule item is triggered, the duration is calculated using the second
   cron expression.

   For schedule items added with this function, the scheduler will emit
   the signal "start:ID" when the schedule is triggered and "stop:ID"
   when the next end time (duration) is reached.

   Each signal will contain the schedule item identifier in the signal data and
   the reason (start, stop).

   The signal "start:ID" will also contain the duration (in seconds) before
   the "stop:ID" will be send.

   Schedule items with a duration for which the "start" signal was emitted and which
   are deleted before the duration is over, the scheduler will send a "stop" signal
   at the moment they are deleted.

   @param scheduler pointer to an amxp_scheduler_t structure
   @param id the identifier for schedule item
   @param cron_begin a string containing a valid cron expression (see @ref amxp_cron_expr_t)
   @param cron_end a string containing a valid cron expression (see @ref amxp_cron_expr_t)

   @return
   When successfull, this functions returns 0.
 */
int amxp_scheduler_set_cron_begin_end_item(amxp_scheduler_t* scheduler,
                                           const char* id,
                                           const char* cron_begin,
                                           const char* cron_end);
/**
   @ingroup amxp_scheduler
   @brief
   Adds a schedule item or updates a schedule item using a time and list of week days.

   Using a time in "HH:MM:SS" (seconds are optional) and a list of week days a
   schedule item is added to the scheduler. If a schedule item exists with the
   given identifier, it will be updated.

   Weekdays must be specified with their name and are case insensitive
   - sunday
   - monday
   - tuesday
   - wednesday
   - thursday
   - friday
   - saturday

   Optionaly a range of weekdays can be specified. (sunday is considered the
   first day of the week).

   Examples for days_of_Week argument:
   @code
   "monday,tuesday,wednesday,thursday,friday"
   "monday-friday"
   @endcode

   The scheduler will calculate the next time the schedule should be triggered.

   A duration can be specified. When the duration is not zero (0), the scheduler
   will emit the signal "start:ID" when the schedule is triggered, and starts
   a timer for the duration. When the timer expires the scheduler will emit the
   signal "stop:ID".

   For schedule items that have a duration of zero (0), the scheduler will emit
   the signal "trigger:ID" when the schedule is triggered.

   Each signal will contain the schedule item identifier in the signal data and
   the reason (start, stop).

   The signal "start:ID" will also contain the duration (in seconds) before
   the "stop:ID" will be send.

   Schedule items with a duration for which the "start" signal was emitted and which
   are deleted before the duration is over, the scheduler will send a "stop" signal
   at the moment they are deleted.

   @param scheduler pointer to an amxp_scheduler_t structure
   @param id the identifier for schedule item
   @param time a string containing a valid time in "HH:MM:SS" format, seconds are optional.
   @param days_of_week a string containing comma separated list of week days or a range.
   @param duration duration in seconds

   @return
   When successfull, this functions returns 0.
 */
int amxp_scheduler_set_weekly_item(amxp_scheduler_t* scheduler,
                                   const char* id,
                                   const char* time,
                                   const char* days_of_week,
                                   uint32_t duration);

/**
   @ingroup amxp_scheduler
   @brief
   Adds a schedule item or updates a schedule item using a start time, end time and list of week days.

   Using a time in "HH:MM:SS" (seconds are optional) and a list of week days a
   schedule item is added to the scheduler. If a schedule item exists with the
   given identifier, it will be updated.

   Weekdays must be specified with their name and are case insensitive
   - sunday
   - monday
   - tuesday
   - wednesday
   - thursday
   - friday
   - saturday

   Optionaly a range of weekdays can be specified. (sunday is considered the
   first day of the week).

   Examples for days_of_Week argument:
   @code
   "monday,tuesday,wednesday,thursday,friday"
   "monday-friday"
   @endcode

   The scheduler will calculate the next time the schedule should be triggered.

   The duration is calculated using the end time. If the end time is smaller then
   the start time, the stop signal will be emitted the next valid day.

   Example:
   @code
   amxp_scheduler_set_weekly_begin_end_item(scheduler, "MyItem", "15:00", "12:00", "saturday,sunday");
   @endcode
   When above schedule item is triggered (started) at a sunday at 15:00, the stop
   signal will be emitted on the next saterday at 12:00. So the item stays active
   for almost a full week.

   Each signal will contain the schedule item identifier in the signal data and
   the reason (start, stop).

   The signal "start:ID" will also contain the duration (in seconds) before
   the "stop:ID" signal will be send.

   Schedule items with a duration for which the "start" signal was emitted and which
   are deleted before the duration is over, the scheduler will send a "stop" signal
   at the moment they are deleted.

   @param scheduler pointer to an amxp_scheduler_t structure
   @param id the identifier for schedule item
   @param start_time a string containing a valid time in "HH:MM:SS" format, seconds are optional.
   @param end_time a string containing a valid time in "HH:MM:SS" format, seconds are optional.
   @param days_of_week a string containing comma separated list of week days or a range.

   @return
   When successfull, this functions returns 0.
 */
int amxp_scheduler_set_weekly_begin_end_item(amxp_scheduler_t* scheduler,
                                             const char* id,
                                             const char* start_time,
                                             const char* end_time,
                                             const char* days_of_week);

/**
   @ingroup amxp_scheduler
   @brief
   Removes a schedule item from the scheduler.

   Removes a schedule item with the provided identifier from the scheduler.

   If the schedule item has a duration time which was started, the "stop:ID"
   signal be emitted when the item is removed.

   When an identifier (ID) is specified, but no scheduler item with that identifier
   is available in this scheduler, the function succeeds but nothing happended.

   @param scheduler pointer to an amxp_scheduler_t structure
   @param id the identifier for schedule item

   @return
   When successfull, this functions returns 0.
 */
int amxp_scheduler_remove_item(amxp_scheduler_t* scheduler,
                               const char* id);

/**
   @ingroup amxp_scheduler
   @brief
   Enables or disable a schedule item.

   When a schedule item is added to the scheduler, it will be enabled by default.

   By disabling the schedule item, the scheduler will still take the item into
   account for time calculation, but will not emit signals for it.

   @param scheduler pointer to an amxp_scheduler_t structure
   @param id the identifier for schedule item
   @param enable false to disable to schedule item, true to enable it.

   @return
   When successfull, this functions returns 0.
 */
int amxp_scheduler_enable_item(amxp_scheduler_t* scheduler,
                               const char* id,
                               bool enable);


/**
   @ingroup amxp_scheduler
   @brief
   Gets the signal manager of a scheduler

   Returns the signal manager of the scheduler. This can be used to connect
   or disconnect slots (callback functions)

   @param scheduler pointer to an amxp_scheduler_t structure

   @return
   Pointer to the signal manager of the scheduler or NULL.
 */
amxp_signal_mngr_t* amxp_scheduler_get_sigmngr(amxp_scheduler_t* scheduler);

#ifdef __cplusplus
}
#endif

#endif // __AMXP_SCHEDULER_H__