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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include "amx_fcgi.h"

static bool file_exist(const char* file_path) {
    struct stat file_stat;
    bool exist = false;
    memset(&file_stat, 0, sizeof(struct stat));

    when_str_empty(file_path, exit);
    exist = (stat(file_path, &file_stat) != -1);

exit:
    return exist;
}

static int read_file_content(const char* file_path, char** buffer) {
    int rv = -1;
    FILE* file = NULL;
    int file_size = 0;
    int bytes_read = 0;

    when_false(file_exist(file_path), exit);

    file = fopen(file_path, "rb");
    when_null(file, exit);

    fseek(file, 0, SEEK_END);
    file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    *buffer = (char*) malloc(file_size);
    if(*buffer == NULL) {
        fclose(file);
        goto exit;
    }

    bytes_read = fread(*buffer, sizeof(char), file_size, file);
    if(bytes_read != file_size) {
        free(*buffer);
        fclose(file);
        goto exit;
    }

    rv = bytes_read;
    fclose(file);
exit:
    return rv;
}

int amx_fcgi_http_download(amx_fcgi_request_t* fcgi_req,
                           amxc_var_t* data,
                           UNUSED bool acl_verify) {
    int status = 400;
    const char* download_folder = GET_CHAR(amx_fcgi_get_conf_opt("download-folder"), NULL);
    amxc_string_t file_path;
    amxc_var_t* ptr_content = NULL;
    char* buffer = NULL;
    int buffer_size = 0;

    amxc_string_init(&file_path, 0);
    when_str_empty(fcgi_req->raw_path, exit);

    amxc_string_setf(&file_path, "%s", fcgi_req->raw_path);
    amxc_string_prependf(&file_path, "%s/", download_folder);

    buffer_size = read_file_content(file_path.buffer, &buffer);
    when_true(buffer_size == -1, exit);

    amxc_var_set_type(data, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(int32_t, data, "buffer_size", buffer_size);
    amxc_var_add_key(cstring_t, data, "filename", fcgi_req->raw_path);
    ptr_content = amxc_var_add_new_key(data, "content");
    ptr_content->data.data = (void*) buffer;

    status = 200;
exit:
    amxc_string_clean(&file_path);
    return status;
}
