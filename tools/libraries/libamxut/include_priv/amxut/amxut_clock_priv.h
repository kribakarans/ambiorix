/****************************************************************************
**
** SPDX-License-Identifier: BSD-2-Clause-Patent
**
** SPDX-FileCopyrightText: Copyright (c) 2024 SoftAtHome
**
** Redistribution and use in source and binary forms, with or
** without modification, are permitted provided that the following
** conditions are met:
**
** 1. Redistributions of source code must retain the above copyright
** notice, this list of conditions and the following disclaimer.
**
** 2. Redistributions in binary form must reproduce the above
** copyright notice, this list of conditions and the following
** disclaimer in the documentation and/or other materials provided
** with the distribution.
**
** Subject to the terms and conditions of this license, each
** copyright holder and contributor hereby grants to those receiving
** rights under this license a perpetual, worldwide, non-exclusive,
** no-charge, royalty-free, irrevocable (except for failure to
** satisfy the conditions of this license) patent license to make,
** have made, use, offer to sell, sell, import, and otherwise
** transfer this software, where such license applies only to those
** patent claims, already acquired or hereafter acquired, licensable
** by such copyright holder or contributor that are necessarily
** infringed by:
**
** (a) their Contribution(s) (the licensed copyrights of copyright
** holders and non-copyrightable additions of contributors, in
** source or binary form) alone; or
**
** (b) combination of their Contribution(s) with the work of
** authorship to which such Contribution(s) was added by such
** copyright holder or contributor, if, at the time the Contribution
** is added, such addition causes such combination to be necessarily
** infringed. The patent license shall not apply to any other
** combinations which include the Contribution.
**
** Except as expressly stated above, no rights or licenses from any
** copyright holder or contributor is granted under this license,
** whether expressly, by implication, estoppel or otherwise.
**
** DISCLAIMER
**
** THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
** CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
** INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
** MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
** DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR
** CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
** SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
** LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
** USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
** AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
** LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
** ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
** POSSIBILITY OF SUCH DAMAGE.
**
****************************************************************************/


#if !defined(__AMXUT_CLOCK_PRIV_H__)
#define __AMXUT_CLOCK_PRIV_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>
#include <amxc/amxc_macros.h>
#include <amxc/amxc_timestamp.h>

/**
 * Timetravels the clock `ms` miliseconds to the future. Does not touch anything else (like timers).
 */
void PRIVATE amxut_clock_priv_isolated_go_to_future_ms(uint64_t ms);

/**
 * Sets the mocked realtime clock (not the monotonic clock) to the specified date and time.
 *
 * Does not touch anything else (like timers).
 */
void PRIVATE amxut_clock_priv_isolated_set_realtime(amxc_ts_t* datetime);

/**
 * Converts ambiorix timestamp to libc's `struct timespec`.
 *
 * This is here (instead of in libamxc's public header file) because `struct timespec`
 * is not provided by default in uclibc. Adding `#define`s in libamxc's header file
 * to nudge uclibc to provide it (like `#define _GNU_SOURCE`) would immediately affect all
 * C files that include libamxc's header file.
 *
 * @param source_timestamp a pointer to a timestamp structure that needs to be converted
 * @param target_timespec a pointer to a `struct timespec` that needs to contain the timestamp
 *                          of `source_timestamp`.
 *
 * @return
 * -1 if an error occurs.
 * 0 if the action succeeded.
 */
int PRIVATE amxut_clock_priv_amxc_ts_to_timespec(const amxc_ts_t* source_timestamp, struct timespec* target_timespec);

#ifdef __cplusplus
}
#endif

#endif



