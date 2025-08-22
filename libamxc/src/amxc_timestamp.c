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

/****************************************************************************
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
****************************************************************************/

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <unistd.h>
#include <sys/time.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#include <amxc/amxc_timestamp.h>
#include <amxc/amxc_macros.h>

#define EPOCH INT64_C(62135683200)      /* 1970-01-01T00:00:00 */
#define MIN_SEC INT64_C(-62135596800)   /* 0001-01-01T00:00:00 */
#define MAX_SEC INT64_C(253402300799)   /* 9999-12-31T23:59:59 */
#define RDN_OFFSET INT64_C(62135683200) /* 1970-01-01T00:00:00 */

static const uint32_t Pow10[10] = {
    1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000, 1000000000
};

static const uint16_t DayOffset[13] = {
    0, 306, 337, 0, 31, 61, 92, 122, 153, 184, 214, 245, 275
};

static int leap_year(uint16_t y) {
    return ((y & 3) == 0 && (y % 100 != 0 || y % 400 == 0));
}

static unsigned char month_days(uint16_t y, uint16_t m) {
    static const unsigned char days[2][13] = {
        {0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31},
        {0, 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}
    };
    return days[m == 2 && leap_year(y)][m];
}

static int parse_2d(const unsigned char* const p, size_t i, uint16_t* vp) {
    unsigned char d0, d1;
    if(((d0 = p[i + 0] - '0') > 9) ||
       ((d1 = p[i + 1] - '0') > 9)) {
        return 1;
    }
    *vp = d0 * 10 + d1;
    return 0;
}

static int parse_4d(const unsigned char* const p, size_t i, uint16_t* vp) {
    unsigned char d0, d1, d2, d3;
    if(((d0 = p[i + 0] - '0') > 9) ||
       ((d1 = p[i + 1] - '0') > 9) ||
       ((d2 = p[i + 2] - '0') > 9) ||
       ((d3 = p[i + 3] - '0') > 9)) {
        return 1;
    }
    *vp = d0 * 1000 + d1 * 100 + d2 * 10 + d3;
    return 0;
}

/* Rata Die algorithm by Peter Baum */
static void rdn_to_ymd(uint32_t rdn, uint16_t* yp, uint16_t* mp, uint16_t* dp) {
    uint32_t Z, H, A, B;
    uint16_t y, m, d;

    Z = rdn + 306;
    H = 100 * Z - 25;
    A = H / 3652425;
    B = A - (A >> 2);
    y = (100 * B + H) / 36525;
    d = B + Z - (1461 * y >> 2);
    m = (535 * d + 48950) >> 14;
    if(m > 12) {
        y++, m -= 12;
    }

    *yp = y;
    *mp = m;
    *dp = d - DayOffset[m];
}

static size_t timestamp_format_internal(char* dst,
                                        size_t len,
                                        const amxc_ts_t* tsp,
                                        const int precision) {
    unsigned char* p;
    uint64_t sec;
    uint32_t rdn, v;
    uint16_t y, m, d;
    size_t dlen;

    dlen = sizeof("YYYY-MM-DDThh:mm:ssZ") - 1;
    if(tsp->offset) {
        dlen += 5; /* hh:mm */
    }
    if(precision) {
        dlen += 1 + precision;
    }
    if(dlen >= len) {
        return 0;
    }
    sec = tsp->sec + tsp->offset * 60 + EPOCH;
    rdn = sec / 86400;

    rdn_to_ymd(rdn, &y, &m, &d);

    /*
     *           1
     * 0123456789012345678
     * YYYY-MM-DDThh:mm:ss
     */
    p = (unsigned char*) dst;
    v = sec % 86400;
    p[18] = '0' + (v % 10); v /= 10;
    p[17] = '0' + (v % 6); v /= 6;
    p[16] = ':';
    p[15] = '0' + (v % 10); v /= 10;
    p[14] = '0' + (v % 6); v /= 6;
    p[13] = ':';
    p[12] = '0' + (v % 10); v /= 10;
    p[11] = '0' + (v % 10);
    p[10] = 'T';
    p[ 9] = '0' + (d % 10); d /= 10;
    p[ 8] = '0' + (d % 10);
    p[ 7] = '-';
    p[ 6] = '0' + (m % 10); m /= 10;
    p[ 5] = '0' + (m % 10);
    p[ 4] = '-';
    p[ 3] = '0' + (y % 10); y /= 10;
    p[ 2] = '0' + (y % 10); y /= 10;
    p[ 1] = '0' + (y % 10); y /= 10;
    p[ 0] = '0' + (y % 10);
    p += 19;

    if(precision) {
        v = tsp->nsec / Pow10[9 - precision];
        for(int i = precision; i > 0; i--) {
            p[i] = '0' + (v % 10);
            if(i > 1) {
                v /= 10;
            }
        }
        p[0] = '.';
        p += 1 + precision;
    }

    if(!tsp->offset) {
        *p++ = 'Z';
    } else {
        if(tsp->offset < 0) {
            p[0] = '-', v = -tsp->offset;
        } else {
            p[0] = '+', v = tsp->offset;
        }
        p[5] = '0' + (v % 10); v /= 10;
        p[4] = '0' + (v % 6); v /= 6;
        p[3] = ':';
        p[2] = '0' + (v % 10); v /= 10;
        p[1] = '0' + (v % 10);
        p += 6;
    }
    *p = 0;
    return dlen;
}

/* Rata Die algorithm by Peter Baum */
static void rdn_to_struct_tm(uint32_t rdn, struct tm* tmp) {
    uint32_t Z, H, A, B;
    uint16_t C, y, m, d;

    Z = rdn + 306;
    H = 100 * Z - 25;
    A = H / 3652425;
    B = A - (A >> 2);
    y = (100 * B + H) / 36525;
    C = B + Z - (1461 * y >> 2);
    m = (535 * C + 48950) >> 14;
    if(m > 12) {
        d = C - 306, y++, m -= 12;
    } else {
        d = C + 59 + ((y & 3) == 0 && (y % 100 != 0 || y % 400 == 0));
    }

    tmp->tm_mday = C - DayOffset[m];    /* Day of month [1,31]           */
    tmp->tm_mon = m - 1;                /* Month of year [0,11]          */
    tmp->tm_year = y - 1900;            /* Years since 1900              */
    tmp->tm_wday = rdn % 7;             /* Day of week [0,6] (Sunday =0) */
    tmp->tm_yday = d - 1;               /* Day of year [0,365]           */
}

static int timestamp_to_tm(const amxc_ts_t* tsp,
                           struct tm* tmp,
                           const bool local) {
    uint64_t sec;
    uint32_t rdn, sod;
    int retval = -1;

    when_null(tsp, exit);
    when_null(tmp, exit);
    when_true(!amxc_ts_is_valid(tsp), exit);

    sec = tsp->sec + RDN_OFFSET;
    if(local) {
        sec += tsp->offset * 60;
    }
    rdn = sec / 86400;
    sod = sec % 86400;

    rdn_to_struct_tm(rdn, tmp);
    tmp->tm_sec = sod % 60; sod /= 60;
    tmp->tm_min = sod % 60; sod /= 60;
    tmp->tm_hour = sod;

    retval = 0;

exit:
    return retval;
}

int amxc_ts_now(amxc_ts_t* tsp) {
    int retval = -1;
    struct timespec ts = {0, 0};

    when_null(tsp, exit);
    retval = clock_gettime(CLOCK_REALTIME, &ts);
    tsp->sec = ts.tv_sec;
    tsp->nsec = ts.tv_nsec;

    if(retval != 0) {
        tsp->sec = MIN_SEC;
    }
    tsp->offset = 0;

exit:
    return retval ? -1 : 0;
}

static int amxc_ts_parse_date(const unsigned char* cur,
                              uint16_t* year,
                              uint16_t* month,
                              uint16_t* day) {
    int retval = 1;
    when_true(parse_4d(cur, 0, year) || *year < 1, exit);
    when_true(parse_2d(cur, 5, month) || *month < 1 || *month > 12, exit);
    when_true(parse_2d(cur, 8, day) || *day < 1 || *day > 31, exit);

    retval = 0;
exit:
    return retval;
}

static int amxc_ts_parse_time(const unsigned char* cur,
                              uint16_t* hour,
                              uint16_t* min,
                              uint16_t* sec) {
    int retval = 1;
    when_true(parse_2d(cur, 11, hour) || *hour > 23, exit);
    when_true(parse_2d(cur, 14, min) || *min > 59, exit);
    when_true(parse_2d(cur, 17, sec) || *sec > 59, exit);

    retval = 0;
exit:
    return retval;
}

static int amxc_ts_parse_offset(const unsigned char* cur,
                                const unsigned char* end,
                                int16_t* offset) {
    int retval = -1;
    uint16_t hour;
    uint16_t min;
    unsigned char ch = *cur;
    when_true(cur + 6 < end || !(ch == '+' || ch == '-') || cur[3] != ':', exit);

    when_true(parse_2d(cur + 1, 0, &hour) || hour > 23 ||
              parse_2d(cur + 1, 3, &min) || min > 59, exit);

    *offset = hour * 60 + min;
    if(ch == '-') {
        *offset *= -1;
    }

    retval = 0;
exit:
    return retval;
}

int amxc_ts_parse(amxc_ts_t* tsp,
                  const char* str,
                  size_t len) {
    int retval = -1;
    const unsigned char* cur, * end;
    unsigned char ch;
    uint16_t year, month, day, hour, min, sec;
    uint32_t rdn, sod, nsec;
    int16_t offset;

    when_null(tsp, exit);
    when_null(str, exit);
    when_true(len < 20, exit);
    /*
     *           1
     * 01234567890123456789
     * 2013-12-31T23:59:59Z
     */
    cur = (const unsigned char*) str;
    when_true(cur[4] != '-' || cur[7] != '-' ||
              cur[13] != ':' || cur[16] != ':', exit);

    ch = cur[10];
    when_true(!(ch == 'T' || ch == ' ' || ch == 't'), exit);
    when_failed(amxc_ts_parse_date(cur, &year, &month, &day), exit);
    when_failed(amxc_ts_parse_time(cur, &hour, &min, &sec), exit);
    when_true(day > 28 && day > month_days(year, month), exit);

    if(month < 3) {
        year--;
    }

    rdn = (1461 * year) / 4 - year / 100 + year / 400 + DayOffset[month] + day - 306;
    sod = hour * 3600 + min * 60 + sec;
    end = cur + len;
    cur = cur + 19;
    offset = nsec = 0;

    ch = *cur++;
    if(ch == '.') {
        const unsigned char* start;
        size_t ndigits;

        start = cur;
        for(; cur < end; cur++) {
            const unsigned char digit = *cur - '0';
            if(digit > 9) {
                break;
            }
            nsec = nsec * 10 + digit;
        }

        ndigits = cur - start;
        when_true(ndigits < 1 || ndigits > 9, exit);

        nsec *= Pow10[9 - ndigits];

        when_true(cur == end, exit);

        ch = *cur++;
    }

    if(!((ch == 'Z') || (ch == 'z'))) {
        when_failed(amxc_ts_parse_offset(cur - 1, end, &offset), exit);
        cur += 5;
    }

    when_true(cur != end, exit);

    tsp->sec = ((int64_t) rdn - 719163) * 86400 + sod - offset * 60;
    tsp->nsec = nsec;
    tsp->offset = offset;

    retval = 0;

exit:
    return retval;
}

/*
 *          1         2         3
 * 12345678901234567890123456789012345 (+ null-terminator)
 * YYYY-MM-DDThh:mm:ssZ
 * YYYY-MM-DDThh:mm:ss±hh:mm
 * YYYY-MM-DDThh:mm:ss.123Z
 * YYYY-MM-DDThh:mm:ss.123±hh:mm
 * YYYY-MM-DDThh:mm:ss.123456Z
 * YYYY-MM-DDThh:mm:ss.123456±hh:mm
 * YYYY-MM-DDThh:mm:ss.123456789Z
 * YYYY-MM-DDThh:mm:ss.123456789±hh:mm
 */

size_t amxc_ts_format(const amxc_ts_t* tsp,
                      char* dst,
                      size_t len) {
    size_t retval = 0;
    uint32_t f;
    int precision;

    when_null(tsp, exit);
    when_null(dst, exit);
    when_true(!amxc_ts_is_valid(tsp), exit);

    f = tsp->nsec;
    if(f == 0) {
        precision = 0;
    } else {
        if((f % 1000000) == 0) {
            precision = 3;
        } else if((f % 1000) == 0) {
            precision = 6;
        } else {
            precision = 9;
        }
    }
    retval = timestamp_format_internal(dst, len, tsp, precision);

exit:
    return retval;
}

size_t amxc_ts_format_precision(const amxc_ts_t* tsp,
                                char* dst,
                                size_t len,
                                int precision) {
    int retval = 0;

    when_null(tsp, exit);
    when_null(dst, exit);

    when_true(!amxc_ts_is_valid(tsp) || precision < 0 || precision > 9, exit);
    retval = timestamp_format_internal(dst, len, tsp, precision);

exit:
    return retval;
}

int amxc_ts_compare(const amxc_ts_t* tsp1, const amxc_ts_t* tsp2) {
    when_null(tsp1, exit);
    when_null(tsp2, exit);

    if(tsp1->sec < tsp2->sec) {
        return -1;
    }
    if(tsp1->sec > tsp2->sec) {
        return 1;
    }
    if(tsp1->nsec < tsp2->nsec) {
        return -1;
    }
    if(tsp1->nsec > tsp2->nsec) {
        return 1;
    }

exit:
    return 0;
}

bool amxc_ts_is_valid(const amxc_ts_t* tsp) {
    bool retval = false;
    int64_t sec = 0;
    when_null(tsp, exit);

    sec = tsp->sec + tsp->offset * 60;
    if((sec < MIN_SEC) || (sec > MAX_SEC) ||
       ( tsp->nsec < 0) || ( tsp->nsec > 999999999) ||
       ( tsp->offset < -1439) || ( tsp->offset > 1439)) {
        goto exit;
    }

    retval = true;

exit:
    return retval;
}

int amxc_ts_to_tm_utc(const amxc_ts_t* tsp, struct tm* tmp) {
    return timestamp_to_tm(tsp, tmp, false);
}

int amxc_ts_to_tm_local(const amxc_ts_t* tsp, struct tm* tmp) {
    return timestamp_to_tm(tsp, tmp, true);
}

int amxc_ts_to_local(amxc_ts_t* tsp) {
    int retval = -1;
    time_t rawtime = time(NULL);
    struct tm* ptm = gmtime(&rawtime);
    time_t gmt = 0;

    when_null(ptm, exit);
    when_null(tsp, exit);

    gmt = mktime(ptm);
    ptm = localtime(&rawtime);

    when_null(ptm, exit);

    tsp->offset = (rawtime - gmt + (ptm->tm_isdst ? 3600 : 0)) / 60;
    retval = 0;

exit:
    return retval;
}

int amxc_ts_from_tm(amxc_ts_t* const tsp, struct tm* tmp) {
    int rv = -1;
    time_t epoch = 0;

    when_null(tsp, exit);
    when_null(tmp, exit);

    epoch = mktime(tmp);
    when_true(epoch == -1, exit);

    tsp->sec = epoch;
    tsp->nsec = 0;
    tsp->offset = 0;

    rv = 0;

exit:
    return rv;
}