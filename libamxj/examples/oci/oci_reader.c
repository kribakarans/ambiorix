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

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <yajl/yajl_gen.h>

#include <amxc/amxc.h>
#include <amxj/amxj_variant.h>

static amxc_var_t* read_config(const char* file) {
    int read_length = 0;
    int fd = open(file, O_RDONLY);
    amxc_var_t* var = NULL;
    variant_json_t* reader = NULL;

    amxj_reader_new(&reader);

    read_length = amxj_read(reader, fd);
    while(read_length > 0) {
        read_length = amxj_read(reader, fd);
    }

    var = amxj_reader_result(reader);
    amxj_reader_delete(&reader);
    close(fd);

    return var;
}

static int write_config(const char* file, amxc_var_t* var) {
    int write_length = 0;
    int fd = open(file, O_WRONLY | O_CREAT, 0644);

    variant_json_t* writer = NULL;

    amxj_writer_new(&writer, var);
    write_length = amxj_write(writer, fd);

    amxj_writer_delete(&writer);
    close(fd);

    return write_length;
}

static int set_var(amxc_var_t* var, const char* value) {
    int retval = -1;
    amxc_var_t new_val;
    amxc_var_init(&new_val);
    amxc_var_set(cstring_t, &new_val, value);

    retval = amxc_var_convert(var, &new_val, amxc_var_type_of(var));

    amxc_var_clean(&new_val);
    return retval;
}

int main(int argc, char** argv) {
    amxc_var_t* oci_config = NULL;
    amxc_var_t* value = NULL;
    char* txt = NULL;
    char* path_dup = NULL;

    if(argc < 2) {
        return -1;
    }

    // read the config json
    oci_config = read_config(argv[1]);

    // fetch the variant on the path
    value = amxc_var_get_path(oci_config, argv[2], AMXC_VAR_FLAG_DEFAULT);

    if(value != NULL) {
        // convert to text and print
        txt = amxc_var_dyncast(cstring_t, value);
        printf("Current value - %s = %s\n", argv[2], txt);
        if(argc > 3) {
            if(set_var(value, argv[3]) == 0) {
                free(txt);
                txt = amxc_var_dyncast(cstring_t, value);
                printf("New value     - %s = %s\n", argv[2], txt);
                write_config(argv[1], oci_config);
            }
        }
    } else {
        printf("!!! Not found !!! - %s\n", argv[2]);
    }

    free(txt);
    free(path_dup);
    amxc_var_delete(&oci_config);
    return 0;
}
