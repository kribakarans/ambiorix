/****************************************************************************
**
** SPDX-License-Identifier: BSD-2-Clause-Patent
**
** SPDX-FileCopyrightText: Copyright (c) 2022 SoftAtHome
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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <sys/stat.h>
#include <fcntl.h>

#include "amxo_xml_to_assert.h"
#include "amxo_xml_to.h"

static amxc_var_t* amxo_xml_read_config(const char* config_dir, const char* config_file) {
    int read_length = 0;
    amxc_string_t file_name;
    int fd = -1;
    amxc_var_t* var = NULL;
    variant_json_t* reader = NULL;

    amxc_string_init(&file_name, 0);
    amxc_string_setf(&file_name, "%s/xml/%s", config_dir, config_file);

    fd = open(amxc_string_get(&file_name, 0), O_RDONLY);
    if(fd == -1) {
        amxo_xml_print_error("Failed to open [%s]\n", amxc_string_get(&file_name, 0));
        goto exit;
    }

    amxj_reader_new(&reader);

    read_length = amxj_read(reader, fd);
    while(read_length > 0) {
        read_length = amxj_read(reader, fd);
    }

    var = amxj_reader_result(reader);
    amxj_reader_delete(&reader);
    close(fd);

exit:
    amxc_string_clean(&file_name);
    return var;
}

void amxo_xml_set_config(amxc_var_t* config) {
    amxc_var_add_key(cstring_t, config, "cfg-dir", "/etc/amx");
    amxc_var_add_key(cstring_t, config, "cfg-file", "default.conf");
    amxc_var_add_key(cstring_t, config, "output-dir", "./");
}

void amxo_xml_join_config(amxc_var_t* config) {
    const char* config_dir = GET_CHAR(config, "cfg-dir");
    const char* config_file = GET_CHAR(config, "cfg-file");
    const amxc_htable_t* hconfig = NULL;

    amxc_var_t* read = amxo_xml_read_config(config_dir, config_file);
    if(read == NULL) {
        goto leave;
    }
    if(amxc_var_type_of(read) != AMXC_VAR_ID_HTABLE) {
        amxo_xml_print_error("Invalid configuration file [%s/xml/%s]\n", config_dir, config_file);
        goto leave;
    }

    hconfig = amxc_var_constcast(amxc_htable_t, read);
    amxc_htable_for_each(it, hconfig) {
        const char* key = amxc_htable_it_get_key(it);
        amxc_var_t* value = amxc_var_from_htable_it(it);
        amxc_var_t* co = GET_ARG(config, key);
        if(co == NULL) {
            amxc_var_set_key(config, key, value, AMXC_VAR_FLAG_DEFAULT);
        } else {
            amxc_var_delete(&value);
        }
    }

leave:
    amxc_var_delete(&read);
}