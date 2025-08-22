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

#if !defined(__AMXP_CRON_H__)
#define __AMXP_CRON_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdbool.h>
#include <stdint.h>
#include <amxc/amxc_timestamp.h>

/**
   @file
   @brief
   Ambiorix cron expression parser
 */

/* *INDENT-OFF* */
/**
   @defgroup amxp_cron Cron expression parser

   Ambiorix cron expression parser. 

   @code
    ┌───────────── second (0 - 59)
    │ ┌───────────── minute (0 - 59)
    │ │ ┌───────────── hour (0 - 23)
    │ │ │ ┌───────────── day of the month (1 - 31)
    │ │ │ │ ┌───────────── month (1 - 12)
    │ │ │ │ │ ┌───────────── day of the week (0 - 6) (Sunday to Saturday;
    │ │ │ │ │ │                                   7 is also Sunday on some systems)
    │ │ │ │ │ │
    │ │ │ │ │ │
    * * * * * *
   @endcode
 */

/**
   @ingroup amxp_cron
   @brief
   Structure containing parsed cron expression.

   This structure contains a member for each cron expression field.
   Each member will have bits set. Each set bit indicates an active position in time
   for which the cron expression can be trigger.
 */
/* *INDENT-ON* */
typedef struct _cron_expr {
    uint8_t seconds[8];        /**< Stores which seconds should trigger */
    uint8_t minutes[8];        /**< Stores which minutes should trigger */
    uint8_t hours[3];          /**< Stores which hours should trigger */
    uint8_t days_of_week[1];   /**< Stores which days of the week should trigger*/
    uint8_t days_of_month[4];  /**< Stores which days of the month should trigger */
    uint8_t months[2];         /**< Stores which months should trigger */
} amxp_cron_expr_t;

/**
   @ingroup amxp_cron
   @brief
   Allocates an amxp_cron_expr_t structures and initializes it to every second.

   This function allocates memory on the heap for an amxp_cron_expr_t structure
   and initializes it using following cron expression "* * * * * *".
   This cron expression triggers every second.

   Call @ref amxp_cron_parse_expr to set another schedule for the cron expression.

   @note
   The allocated memory must be freed when not used anymore,
   use @ref amxp_cron_delete to free the memory.

   @param cron_expr pointer to a pointer that points to the new allocated amxp_cron_expr_t structure

   @return
   When allocation is successfull, this functions returns 0.
 */
int amxp_cron_new(amxp_cron_expr_t** cron_expr);

/**
   @ingroup amxp_cron
   @brief
   Frees the previously allocated amxp_cron_expr_t structure.

   Frees the allocated memory and sets the pointer to NULL.

   @note
   Only call this function for amxp_cron_expr_t structures that are allocated on the heap using
   @ref amxp_cron_new.

   @param cron_expr pointer to a pointer that points to the allocated amxp_cron_expr_t structure
 */
void amxp_cron_delete(amxp_cron_expr_t** cron_expr);

/**
   @ingroup amxp_cron
   @brief
   Initializes an amxp_cron_expr_t structures to every second.

   This function initializes a amxp_cron_expr_t structure using following
   cron expression "* * * * * *". This cron expression triggers every second.

   Call @ref amxp_cron_parse_expr to set another schedule for the cron expression.

   @param cron_expr pointer to a amxp_cron_expr_t structure that must be initialized.

   @return
   When allocation is successfull, this functions returns 0.
 */
int amxp_cron_init(amxp_cron_expr_t* cron_expr);

/**
   @ingroup amxp_cron
   @brief
   Resets the amxp_cron_expr_t structure to the initialized state.

   Resets the amxp_cron_expr_t structure to the "* * * * * *" cron expression.

   @param cron_expr pointer to an amxp_cron_expr_t structure
 */
void amxp_cron_clean(amxp_cron_expr_t* cron_expr);

/* *INDENT-OFF* */
/**
   @ingroup amxp_cron
   @brief
   Allocates and initializes an amxp_cron_expr_t structures and parses the given cron expression.

   This function allocates memory for an amxp_cron_expr_t structure. This memory must be
   freed when not needed anymore.

   When an invalid expression is provided, no memory will be allocated and an error
   string is put in error.

   A valid cron expression contains 6 fields:
   @code
    ┌───────────── second (0 - 59)
    │ ┌───────────── minute (0 - 59)
    │ │ ┌───────────── hour (0 - 23)
    │ │ │ ┌───────────── day of the month (1 - 31)
    │ │ │ │ ┌───────────── month (1 - 12)
    │ │ │ │ │ ┌───────────── day of the week (0 - 6) (Sunday to Saturday);
    │ │ │ │ │ │                                   
    │ │ │ │ │ │
    │ │ │ │ │ │
    * * * * * *
   @endcode

   Each field can contain a single value, a list of values, a range, and an incrementor.
   - single value: "<number>"
   - list of values: "<number>,<number>,<number>"
   - range: "<number>-<number>"
   - incrementor: "/<number>"

   @note
   - When using a range, make sure that the smallest value is put first.
   - For day of week Sunday can be indicated as 0 or 7.

   To indicate all possible value for that field the * symbol can be used.

   Months can be specified using ordinals:
   "JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC"

   Days of week can be specified using ordinals:
   "SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"

   When using "SUN" to indicate sunday, index 0 for the day of week will be used.

   Examples:
   - Every 2 hours on Sunday: "0 0 0/2 * * 0"

   - Every Saterday at 23:45:00 (11:45 PM): "0 45 23 * * SAT"

   - All weekdays at midnight: "0 0 0 * * MON-FRI"

   - Every first Monday of the month at 12:00:00: "0 0 0 1-7 JAN-DEC MON"

   - Every first Monday of the months June, August, December at 12:00:00: "0 0 0 1-7 JUN,8,DEC MON"

   - Every 15 minutes every day: "0 0/15 * * * *"

   @param target pointer to amxp_cron_expr_t.
   @param expression the cron expression that needs to be parsed.
   @param error (optional) if provided a human readable error string will be placed here.

   @return
   0 when successful, otherwise an error code
 */
/* *INDENT-ON* */
int amxp_cron_parse_expr(amxp_cron_expr_t* target, const char* expression, const char** error);

/**
   @ingroup amxp_cron
   @brief
   Builds a weekly cron expression that is triggered at a certain time on certain days of the week.

   Passing the time "15:10" and list of week days "saterday, sunday" will build the cron
   expression "0 10 15 * * SAT,SUN" and initializes the provided amxp_cron_expr_t
   structure with it.

   The time must be provided in "HH:MM:SS" format, The seconds are optional, when not
   provided the seconds will be set to "00".

   The days of week argument must be a comma separated list of week day names:
   - sunday
   - monday
   - tuesday
   - wednesday
   - thursday
   - friday
   - saterday

   The name of the days is case insensitive. It is allowed to provide a range like "monday-friday".

   @param target pointer to amxp_cron_expr_t.
   @param time a string containing the time in "HH:MM:SS" format, seconds are optional.
   @param days_of_week comma separated list of week days or a range of week days.

   @return
   0 when successful, otherwise an error code
 */
int amxp_cron_build_weekly(amxp_cron_expr_t* target,
                           const char* time,
                           const char* days_of_week);

/**
   @ingroup amxp_cron
   @brief
   Calculates the previous trigger time for a parsed cron expression.

   Given a parsed cron expression and a reference time, calculates the previous trigger time
   for the cron expression.

   Typically the reference time will be the current time.

   Example:
   @code
   void calculate_timing(void) {
       amxp_cron_expr_t* cron_expr = NULL;
       amxc_ts_t start = { 0, 0, 0 };
       amxc_ts_t next = { 0, 0, 0 };
       char str_ts[40];

       amxp_cron_parse_expr(&cron_expr, "0 0 0 1-7 JAN-DEC MON", NULL);
       amxc_ts_parse(&start, "2023-05-18T10:07:24Z", 20);
       amxc_ts_format(&start, str_ts, 40);
       printf("Start = %s\n", str_ts);

       amxp_cron_prev(cron_expr, &start, &next);
       amxc_ts_format(&next, str_ts, 40);
       printf("Previous = %s\n", str_ts);

       start = next;
       amxp_cron_prev(cron_expr, &start, &next);
       amxc_ts_format(&next, str_ts, 40);
       printf("Previous = %s\n", str_ts);
   }
   @endcode

   Calling the above function will provide this output:
   @code
   Start = 2023-05-18T10:07:24Z
   Next = 2023-05-01T00:00:00Z
   Next = 2023-04-03T00:00:00Z
   @endcode

   @note
   The time offset is always taken into consideration.<br>
   If the reference time is local time, the cron expression will work on local time.
   The next occurence will then be expressed in local time as well.<br>
   Consider this local time: "2023-05-19T12:10:00+02:00" and following cron expression
   "0 15 10,12,14 * * *" then the previous occurence was at "2023-05-19T10:15:00+02:00".<br>
   If the local reference time was first converted to UTC it would be:
   - reference time: "2023-05-19T12:10:00+02:00" = "2023-05-19T10:10:00Z" (in UTC)
   - previous time: "2023-05-18T14:15:00Z" (in UTC) = "2023-05-18T16:15:00+02:00".

   @param expr A parsed cron expression.
   @param ref The reference time.
   @param next The calculated next trigger time.

   @return
   0 when successful, otherwise an error code
 */
int amxp_cron_prev(const amxp_cron_expr_t* expr, const amxc_ts_t* ref, amxc_ts_t* next);

/**
   @ingroup amxp_cron
   @brief
   Calculates the next trigger time for a parsed cron expression.

   Given a parsed cron expression and a reference time, calculates the next trigger time
   for the cron expression.

   Typically the reference time will be the current time.

   Example:
   @code
   void calculate_timing(void) {
       amxp_cron_expr_t* cron_expr = NULL;
       amxc_ts_t start = { 0, 0, 0 };
       amxc_ts_t next = { 0, 0, 0 };
       char str_ts[40];

       amxp_cron_parse_expr(&cron_expr, "0 0 0 1-7 JAN-DEC MON", NULL);
       amxc_ts_parse(&start, "2023-05-18T10:07:24Z", 20);
       amxc_ts_format(&start, str_ts, 40);
       printf("Start = %s\n", str_ts);

       amxp_cron_next(cron_expr, &start, &next);
       amxc_ts_format(&next, str_ts, 40);
       printf("Next = %s\n", str_ts);

       start = next;
       amxp_cron_next(cron_expr, &start, &next);
       amxc_ts_format(&next, str_ts, 40);
       printf("Next = %s\n", str_ts);
   }
   @endcode

   Calling the above function will provide this output:
   @code
   Start = 2023-05-18T10:07:24Z
   Next = 2023-06-05T00:00:00Z
   Next = 2023-07-03T00:00:00Z
   @endcode

   @note
   The time offset is always taken into consideration.<br>
   If the reference time is local time, the cron expression will work on local time.
   The next occurence will then be expressed in local time as well.<br>
   Consider this local time: "2023-05-19T14:25:00+02:00" and following cron expression
   "0 15 10,12,14 * * *" then the next occurence will be at "2023-05-20T10:15:00+02:00".<br>
   If the local reference time was first converted to UTC it would be:
   - reference time: "2023-05-19T14:25:00+02:00" = "2023-05-19T12:25:00Z" (in UTC)
   - next time: "2023-05-19T14:25:00Z" (in UTC) = "2023-05-19T16:15:00+02:00".

   @param expr A parsed cron expression.
   @param ref The reference time.
   @param next The calculated next trigger time.

   @return
   0 when successful, otherwise an error code
 */
int amxp_cron_next(const amxp_cron_expr_t* expr, const amxc_ts_t* ref, amxc_ts_t* next);

/**
   @ingroup amxp_cron
   @brief
   Calculates the time in seconds until next trigger of a parsed cron expression occurs.

   Calculates the time in seconds, from the current time until the next trigger
   of the parsed cron expression occurs.

   When local is set to true, the local time is used, otherwise the UTC time is used.

   @param expr A parsed cron expression.
   @param local Set to true to use local time.

   @return
   The time in seconds until next trigger, or negative number when failed to calculate.
 */
int64_t amxp_cron_time_until_next(const amxp_cron_expr_t* expr, bool local);

#ifdef __cplusplus
}
#endif

#endif // __AMXP_CRON_H__