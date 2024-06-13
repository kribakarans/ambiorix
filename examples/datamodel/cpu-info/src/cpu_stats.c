/****************************************************************************
**
** Copyright (c) 2020 SoftAtHome
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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cpu_info.h"

#define CPU_STATS "/proc/stat"

static char* cpu_info_build_key(int32_t id) {
    char* retval = NULL;
    amxc_string_t key;
    amxc_string_init(&key, 16);

    if(id <= 0) {
        amxc_string_setf(&key, "cpu");
    } else {
        amxc_string_setf(&key, "cpu%d", id);
    }
    retval = amxc_string_take_buffer(&key);

    amxc_string_clean(&key);
    return retval;
}

static void cpu_info_fill_usage_data(cpu_usage_t* data, char* line, size_t len) {
    amxc_string_t str_line;
    amxc_var_t parts;
    uint32_t index = 0;
    uint64_t* fields[7];
    fields[0] = &data->user;
    fields[1] = &data->nice;
    fields[2] = &data->system;
    fields[3] = &data->idle;
    fields[4] = &data->iowait;
    fields[5] = &data->irq;
    fields[6] = &data->softirq;

    amxc_var_init(&parts);
    amxc_string_init(&str_line, 0);
    amxc_string_push_buffer(&str_line, line, len);

    amxc_string_split(&str_line, &parts, NULL, NULL);

    amxc_var_for_each(part, (&parts)) {
        *fields[index] = amxc_var_dyncast(uint64_t, part);
        index++;
        if(index > 6) {
            break;
        }
    }

    amxc_string_take_buffer(&str_line);
    amxc_var_clean(&parts);
    amxc_string_clean(&str_line);
}

int cpu_stats_read(cpu_usage_t* data, int32_t cpu_id) {
    int retval = -1;
    FILE* fp;
    ssize_t read = 0;
    char* line = NULL;
    size_t len = 0;
    char* key = cpu_info_build_key(cpu_id);
    size_t key_len = strlen(key);

    fp = fopen(CPU_STATS, "r");
    when_null(fp, exit);

    read = getline(&line, &len, fp);
    while(read != -1) {
        if(strncmp(key, line, key_len) == 0) {
            break;
        }
        read = getline(&line, &len, fp);
    }

    cpu_info_fill_usage_data(data, line + key_len, len - key_len);

    retval = 0;

exit:
    if(fp != NULL) {
        fclose(fp);
    }
    free(key);
    free(line);
    return retval;
}