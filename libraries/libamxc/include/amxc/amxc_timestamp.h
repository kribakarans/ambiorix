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
/*
 * Copyright (c) 2014 Christian Hansen <chansen@cpan.org>
 * <https://github.com/chansen/c-timestamp>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#if !defined(__AMXC_TIMESTAMP_H__)
#define __AMXC_TIMESTAMP_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

/**
   @file
   @brief
   Ambiorix timestamp header file
 */

/**
   @ingroup amxc_containers
   @defgroup amxc_timestamp Timestamp
 */

/**
   @ingroup amxc_timestamp
   @brief
   The timestamp structure (unix epoch time).
 */
typedef struct _timestamp {
    int64_t sec;    /* Number of seconds since the epoch of 1970-01-01T00:00:00Z */
    int32_t nsec;   /* Nanoseconds [0, 999999999] */
    int16_t offset; /* Offset from UTC in minutes [-1439, 1439] */
} amxc_ts_t;

/**
   @ingroup amxc_timestamp
   @brief
   Takes current time as unix epoch time.

   Fills the given @ref amxc_ts_t structure with the current time in seconds
   from the unix epoch time.

   @param tsp a pointer to the timestamp structure

   @return
   -1 if an error occurred. 0 on success.
 */
int amxc_ts_now(amxc_ts_t* tsp);

/**
   @ingroup amxc_timestamp
   @brief
   Transforms the given string in to unix epoch time.

   Transforms the time stored in a string in <https://tools.ietf.org/html/rfc3339>
   format into unix epoch time stored as a struct.

   @param tsp a pointer to a timestamp structure
   @param str string containing time in RFC3339 format
   @param len length of the string

   @return
   -1 if an error occurred. 0 on success.
 */
int amxc_ts_parse(amxc_ts_t* tsp, const char* str, size_t len);

/**
   @ingroup amxc_timestamp
   @brief
   Transforms unix epoch time to a string.

   Transforms unix epoch time to string in RFC3339 compatible format.

   Use @ref amxc_ts_format_precision to specify the precision.

   @note
   The length of the provided string buffer must be at least 21 bytes.
   The buffer length must be 36 bytes to be able to store nanoseconds and time
   zone offset.
   The buffer must be pre-allocated.

   @param tsp a pointer to a timestamp structure
   @param dst a pointer to a string
   @param len size of the string buffer

   @return
   length of string dst
 */
size_t amxc_ts_format(const amxc_ts_t* tsp, char* dst, size_t len);

/**
   @ingroup amxc_timestamp
   @brief
   Transforms unix epoch time to a string.

   Transforms unix epoch time to string in RFC3339 compatible format.

   @note
   The length of the provided string buffer must be at least 21 bytes.
   The buffer length must be 36 bytes to be able to store nanoseconds and time
   zone offset.
   The buffer must be pre-allocated.

   @param tsp a pointer to a timestamp structure
   @param dst a pointer to a string storing the UTC time
   @param len size of the string buffer
   @param precision number of digits used to express nanoseconds

   @return
   length of string dst
 */
size_t amxc_ts_format_precision(const amxc_ts_t* tsp,
                                char* dst,
                                size_t len,
                                int precision);

/**
   @ingroup amxc_timestamp
   @brief
   Checks if tsp1 comes after tsp2.

   @param tsp1 a pointer to a timestamp structure
   @param tsp2 a pointer to a timestamp structure

   @return
   0 if input is invalid
   1 if tsp1 comes after tsp2
   -1 if tsp2 comes after tsp1
 */
int amxc_ts_compare(const amxc_ts_t* tsp1, const amxc_ts_t* tsp2);

/**
   @ingroup amxc_timestamp
   @brief
   Checks if a timestamp is valid.

   @param tsp a pointer to a timestamp structure

   @return
   true if the timestamp is valid
   false if the timestamp is invalid
 */
bool amxc_ts_is_valid(const amxc_ts_t* tsp);

/**
   @ingroup amxc_timestamp
   @brief
   Converts timestamp in unix epoch time to a struct tm type in UTC time
   (disregarding the time zone offset).

   @param tsp a pointer to a timestamp structure
   @param tmp a pointer to a struct tm type

   @return
   -1 if an error occurs
   0 if the action succeeded
 */
int amxc_ts_to_tm_utc(const amxc_ts_t* tsp, struct tm* tmp);

/**
   @ingroup amxc_timestamp
   @brief
   Converts timestamp in unix epoch time to a struct tm type in local time
   (taking into account the time zone offset).

   @param tsp a pointer to a timestamp structure
   @param tmp a pointer to a struct tm type

   @return
   -1 if an error occurs
   0 if the action succeeded
 */
int amxc_ts_to_tm_local(const amxc_ts_t* tsp, struct tm* tmp);

/**
   @ingroup amxc_timestamp
   @brief
   Adds the local time offset to the timestamp structure.

   @param tsp a pointer to a timestamp structure

   @return
   -1 if an error occurs
   0 if the action succeeded
 */
int amxc_ts_to_local(amxc_ts_t* tsp);

/**
   @ingroup amxc_timestamp
   @brief
   Converts a broken down time in a struct tm to a timestamp structure.

   Using this function a timestamp structure is initialized using a struct tm
   as input.

   @note
   As struct tm doesn't contain timezone information, the offset will be set to 0.

   @param tsp a pointer to a timestamp structure
   @param tmp pointer to struct tm, containing the broken down time.

   @return
   -1 if an error occurs
   0 if the action succeeded
 */
int amxc_ts_from_tm(amxc_ts_t* const tsp, struct tm* tmp);

#ifdef __cplusplus
}
#endif

#endif // __AMXC_TIMESTAMP_H__
