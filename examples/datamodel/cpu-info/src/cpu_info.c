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

#define CPU_INFO_FILE "/proc/cpuinfo"

static const char* cpu_info_get_field_name(const char* field) {
    amxc_var_t* config = cpu_get_config();
    amxc_var_t* name_mapping = GET_ARG(config, "cpu_field_names");

    if(name_mapping == NULL) {
        return field;
    }
    return GET_CHAR(name_mapping, field);
}

static void cpu_info_add_line(amxc_var_t* cpu, char* line) {
    amxc_string_t key;
    amxc_string_t value;
    const char* param_name = NULL;
    amxc_var_t* param_value = NULL;
    char* pos = NULL;

    amxc_string_init(&key, 0);
    amxc_string_init(&value, 0);
    pos = strchr(line, ':');

    when_null(pos, exit);
    pos[0] = 0;

    amxc_string_set(&key, line);
    amxc_string_trim(&key, NULL);
    amxc_string_replace(&key, " ", "_", UINT32_MAX);

    param_name = cpu_info_get_field_name(amxc_string_get(&key, 0));
    when_null(param_name, exit);
    when_false(amxd_name_is_valid(param_name), exit);

    amxc_string_set(&value, pos + 1);
    amxc_string_trim(&value, NULL);

    param_value = amxc_var_add_new_key(cpu, param_name);
    amxc_var_set(cstring_t, param_value, amxc_string_get(&value, 0));
    amxc_var_cast(param_value, AMXC_VAR_ID_ANY);

exit:
    amxc_string_clean(&key);
    amxc_string_clean(&value);
}

static void cpu_info_read_lines(FILE* fp, amxc_var_t* data, int32_t cpu_id) {
    amxc_var_t* cpu = NULL;
    int32_t index = 1;
    ssize_t read = 0;
    char* line = NULL;
    size_t len = 0;

    if(cpu_id <= 0) {
        amxc_var_set_type(data, AMXC_VAR_ID_LIST);
    } else {
        cpu = data;
        amxc_var_set_type(cpu, AMXC_VAR_ID_HTABLE);
    }

    read = getline(&line, &len, fp);
    while(read != -1) {
        if(line[0] == '\n') {
            index++;
            if(cpu_id > 0) {
                if(index > cpu_id) {
                    break;
                }
            } else {
                cpu = NULL;
            }
            read = getline(&line, &len, fp);
            continue;
        }
        if(cpu == NULL) {
            cpu = amxc_var_add(amxc_htable_t, data, NULL);
        }
        cpu_info_add_line(cpu, line);
        read = getline(&line, &len, fp);
    }
    free(line);
}

int cpu_info_read(amxc_var_t* data, int32_t cpu_id) {
    int retval = -1;

    FILE* fp;

    fp = fopen(CPU_INFO_FILE, "r");
    when_null(fp, exit);

    cpu_info_read_lines(fp, data, cpu_id);

    retval = 0;

exit:
    if(fp != NULL) {
        fclose(fp);
    }
    return retval;
}
