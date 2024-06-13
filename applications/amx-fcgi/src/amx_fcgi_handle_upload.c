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

#include "amx_fcgi.h"

#define CHUNK_SIZE 524288
#define str_is_empty(x) (x == NULL || *x == 0)

typedef struct _stream_data_ {
    char* data;
    int64_t length;
} stream_data_t;

static void stream_data_init(stream_data_t* stream) {
    if(stream != NULL) {
        stream->data = NULL;
        stream->length = 0;
    }
}

static void stream_data_clean(stream_data_t* stream) {
    if(stream != NULL) {
        free(stream->data);
        stream->data = NULL;
        stream->length = 0;
    }
}

static int64_t stream_data_search(stream_data_t* stream, const char* needle, int64_t start_pos) {
    int64_t pos = -1;
    amxc_string_t str_needle;

    amxc_string_init(&str_needle, 0);

    when_null(stream, exit);
    when_null(stream->data, exit);
    when_true(stream->length <= 0, exit);
    when_str_empty(needle, exit);
    when_true(start_pos < 0, exit);
    when_true(start_pos >= stream->length, exit);

    amxc_string_setf(&str_needle, "%s", needle);
    for(int64_t i = start_pos; i < stream->length; i++) {
        bool found = false;
        int64_t needle_size = (int64_t) amxc_string_text_length(&str_needle);
        int64_t needle_index = 0;
        for(int64_t j = i; j < i + needle_size; j++) {
            if(j >= stream->length) {
                break;
            }
            if(stream->data[j] != str_needle.buffer[needle_index]) {
                break;
            }
            if(needle_index >= needle_size - 1) {
                found = true;
                break;
            }
            needle_index++;
        }
        if(found) {
            pos = i;
            break;
        }
    }

exit:
    amxc_string_clean(&str_needle);
    return pos;
}

static int64_t stream_get_line_start(stream_data_t* stream, int64_t start_pos) {
    int64_t pos_start_line = start_pos;

    when_null(stream, exit);
    when_null(stream->data, exit);
    when_true(stream->length <= 0, exit);
    when_true(start_pos < 0, exit);
    when_true(start_pos >= stream->length, exit);

    while(pos_start_line >= 0) {
        if(stream->data[pos_start_line] == '\n') {
            pos_start_line++;
            break;
        }
        pos_start_line--;
    }
    if(pos_start_line < 0) {
        pos_start_line = 0;
    }
    if(pos_start_line > start_pos) {
        pos_start_line = start_pos;
    }

exit:
    return pos_start_line;
}

static int stream_remove_at(stream_data_t* stream, const int64_t pos, int64_t length) {
    int rv = -1;
    int64_t real_length = length;
    int64_t length_remaining = 0;

    when_null(stream, exit);
    when_null(stream->data, exit);
    when_true(stream->length <= 0, exit);
    when_true(pos < 0, exit);
    when_true(length <= 0, exit);
    when_true(pos >= stream->length, exit);

    if(pos + length > stream->length) {
        real_length = stream->length - pos;
    } else {
        real_length = length;
    }
    when_true(real_length <= 0, exit);
    length_remaining = stream->length - pos - real_length;
    when_true(length_remaining < 0, exit);
    if(length_remaining != 0) {
        memmove(stream->data + pos, stream->data + pos + real_length, length_remaining);
    }
    stream->length -= real_length;
    if(stream->length <= 0) {
        free(stream->data);
        stream->data = NULL;
        stream->length = 0;
    } else {
        stream->data = (char*) realloc(stream->data, stream->length + 1);
        stream->data[stream->length] = 0;
    }
    rv = 0;

exit:
    return rv;
}

static int remove_line_from_stream(stream_data_t* stream, int64_t start_pos) {
    int64_t pos_end_line = 0;
    int64_t pos_start_line = 0;
    int64_t size = 0;
    int rv = -1;

    when_null(stream, exit);
    when_null(stream->data, exit);
    when_true(stream->length <= 0, exit);
    when_true(start_pos < 0, exit);
    when_true(start_pos >= stream->length, exit);

    pos_start_line = stream_get_line_start(stream, start_pos);
    when_true(pos_start_line < 0, exit);
    when_true(pos_start_line >= stream->length, exit);

    pos_end_line = stream_data_search(stream, "\n", pos_start_line);
    size = pos_end_line - pos_start_line + 1;
    if(pos_end_line == -1) {
        size = stream->length - pos_start_line;
    }

    rv = stream_remove_at(stream, pos_start_line, size);
    when_failed(rv, exit);

exit:
    return rv;
}

static int remove_line_with_string(stream_data_t* stream, int64_t boundary_pos, const char* boundary, const char* str_filter) {
    int64_t pos_filter = 0;
    int64_t pos_nxt = -1;
    int64_t pos_end_ctx = 0;
    int rv = -1;

    when_null(stream, exit);
    when_false(stream->length > 0, exit);
    when_false(boundary_pos >= 0, exit);
    when_str_empty(boundary, exit);

    pos_nxt = stream_data_search(stream, boundary, boundary_pos);
    pos_end_ctx = (pos_nxt >= 0) ? pos_nxt : stream->length - 1;
    pos_filter = stream_data_search(stream, str_filter, boundary_pos);
    if((pos_filter >= 0) && (pos_filter < pos_end_ctx)) {
        rv = remove_line_from_stream(stream, pos_filter);
        when_failed(rv, exit);
        rv = 1;
    } else {
        rv = 0;
    }

exit:
    return rv;
}

static char* get_boundary_from_content_type(const char* content_type) {
    amxc_string_t boundary;
    int rv = -1;
    int64_t pos = 0;
    char* ret_boundary = NULL;

    amxc_string_init(&boundary, 0);

    when_str_empty(content_type, exit);

    amxc_string_setf(&boundary, "%s", content_type);
    amxc_string_replace(&boundary, "\r", "", UINT32_MAX);
    pos = amxc_string_search(&boundary, "boundary=", 0);
    when_true(pos == -1, exit);
    rv = amxc_string_remove_at(&boundary, 0, pos + 9);
    when_failed(rv, exit);
    when_str_empty(amxc_string_get(&boundary, 0), exit);
    pos = amxc_string_search(&boundary, "\n", 0);
    if(pos != -1) {
        rv = amxc_string_remove_at(&boundary, pos, 1);
        when_failed(rv, exit);
    }
    if(!str_is_empty(amxc_string_get(&boundary, 0))) {
        ret_boundary = amxc_string_take_buffer(&boundary);
    }

exit:
    amxc_string_clean(&boundary);
    return ret_boundary;
}

static int get_string_count(stream_data_t* stream, const char* string) {
    int64_t pos = 0;
    int count = 0;

    when_null(stream, exit);
    when_null(stream->data, exit);
    when_false(stream->length > 0, exit);
    when_str_empty(string, exit);

    pos = stream_data_search(stream, string, 0);
    while(pos >= 0) {
        count++;
        pos = stream_data_search(stream, string, pos + 1);
    }

exit:
    return count;
}

static int parse_multipart_form(stream_data_t* stream, const char* boundary) {
    int64_t pos = 0;
    int64_t pos_nxt = -1;
    int64_t last_pos = 0;
    int rv = -1;
    int ret_value = -1;
    int boundary_count = -1;
    int content_disp_count = -1;
    bool found_content = false;

    when_null(stream, exit);
    when_null(stream->data, exit);
    when_false(stream->length > 0, exit);
    when_str_empty(boundary, exit);
    boundary_count = get_string_count(stream, boundary);
    when_false(boundary_count >= 2, exit);
    content_disp_count = get_string_count(stream, "Content-Disposition");
    when_false(content_disp_count == boundary_count - 1, exit);

    //Remove everything before the boundary
    pos = stream_data_search(stream, boundary, 0);
    if(pos > 0) {
        rv = stream_remove_at(stream, 0, pos);
        when_failed(rv, exit);
    }
    //Parse
    pos = stream_data_search(stream, boundary, 0);
    while(pos >= 0) {
        int64_t pos_filter = 0;
        int64_t pos_end_ctx = 0;
        bool has_content_disp = false;
        bool has_content_type = false;

        //Boundary
        rv = remove_line_from_stream(stream, pos);
        when_failed(rv, exit);
        //Content-Disposition
        rv = remove_line_with_string(stream, pos, boundary, "Content-Disposition");
        when_true(rv < 0, exit);
        has_content_disp = (bool) rv;
        //Content-Type
        rv = remove_line_with_string(stream, pos, boundary, "Content-Type");
        when_true(rv < 0, exit);
        has_content_type = (bool) rv;
        //Remove the rest
        if(has_content_disp && has_content_type && !found_content) {
            found_content = true;
            pos_filter = stream_data_search(stream, "\n", pos);
            if((pos_filter == pos) || (pos_filter == pos + 1)) {
                rv = remove_line_from_stream(stream, pos);
                when_failed(rv, exit);
            }
        } else {
            int64_t pos_start_line = stream_get_line_start(stream, pos);
            pos_nxt = stream_data_search(stream, boundary, pos);
            pos_end_ctx = (pos_nxt != -1) ? pos_nxt : stream->length;
            if(pos_start_line < pos_end_ctx) {
                rv = stream_remove_at(stream, pos_start_line, pos_end_ctx - pos_start_line);
                when_failed(rv, exit);
            }
        }
        pos = stream_data_search(stream, boundary, 0);
    }
    //Remove last end line
    last_pos = stream->length - 1;
    if(last_pos >= 0) {
        if(stream->data[last_pos] == '\n') {
            rv = stream_remove_at(stream, last_pos, 1);
            when_failed(rv, exit);
            last_pos--;
            if(last_pos >= 0) {
                if(stream->data[last_pos] == '\r') {
                    rv = stream_remove_at(stream, last_pos, 1);
                    when_failed(rv, exit);
                }
            }
        }
    }

    ret_value = 0;

exit:
    return ret_value;
}

static int append_bytes_to_file(stream_data_t* stream, const char* file_path, int64_t size_of_chunk) {
    int rv = -1;
    int ret_value = -1;
    FILE* p_file = NULL;
    int size = 0;

    when_str_empty(file_path, exit);
    when_false(size_of_chunk > 0, exit);
    when_false(stream->length > 0, exit);
    size = (size_of_chunk > stream->length) ? stream->length : size_of_chunk;
    when_false(size > 0, exit);

    p_file = fopen(file_path, "a+");
    when_null(p_file, exit);

    rv = fwrite(stream->data, 1, size, p_file);
    fclose(p_file);
    when_false(rv > 0, exit);

    rv = stream_remove_at(stream, 0, size);
    when_failed(rv, exit);

    ret_value = size;
exit:
    return ret_value;
}

static int stream_data_to_file(stream_data_t* stream, const char* file_path) {
    int rv = -1;
    int ret_value = -1;
    int64_t size = 0;

    when_true(stream->length <= 0, exit);
    when_null(stream->data, exit);
    size = stream->length;
    if(access(file_path, F_OK) == 0) {
        remove(file_path);
    }

    while(size > 0) {
        rv = append_bytes_to_file(stream, file_path, CHUNK_SIZE);
        when_false(rv > 0, exit);
        size -= rv;
    }

    ret_value = 0;
exit:
    return ret_value;
}

static int get_file_from_multipart_form(amx_fcgi_request_t* fcgi_req, const char* content_type, int content_length, amxc_var_t* stream_data, const char* file_path) {
    int rv = -1;
    char* boundary = NULL;
    stream_data_t stream;

    stream_data_init(&stream);

    when_null(fcgi_req, exit);
    when_null(stream_data, exit);
    when_null(stream_data->data.data, exit);
    when_false(content_length > 0, exit);
    when_str_empty(file_path, exit);

    //Get boundary
    boundary = get_boundary_from_content_type(content_type);
    when_str_empty(boundary, exit);

    //Initialize stream struct
    stream.data = (char*) stream_data->data.data;
    stream_data->data.data = NULL;
    stream.length = content_length;

    rv = parse_multipart_form(&stream, boundary);
    when_failed(rv, exit);

    rv = stream_data_to_file(&stream, file_path);
    when_failed(rv, exit);

exit:
    stream_data_clean(&stream);
    free(boundary);
    return rv;
}

static int get_file_generic(int content_length, amxc_var_t* stream_data, const char* file_path) {
    int rv = -1;
    stream_data_t stream;

    stream_data_init(&stream);

    when_null(stream_data, exit);
    when_null(stream_data->data.data, exit);
    when_false(content_length > 0, exit);
    when_str_empty(file_path, exit);

    //Initialize stream struct
    stream.data = (char*) stream_data->data.data;
    stream_data->data.data = NULL;
    stream.length = content_length;

    rv = stream_data_to_file(&stream, file_path);
    when_failed(rv, exit);

exit:
    stream_data_clean(&stream);
    return rv;
}

static int save_file_content(amx_fcgi_request_t* fcgi_req, int content_length, amxc_var_t* stream_data, const char* file_path) {
    int rv = -1;
    const char* type = NULL;

    when_null(fcgi_req, exit);
    type = amx_fcgi_get_content_type(&fcgi_req->request);
    when_str_empty(type, exit);
    when_null(stream_data, exit);
    when_null(stream_data->data.data, exit);
    when_false(content_length > 0, exit);
    when_str_empty(file_path, exit);

    if(strstr(type, "multipart/form-data") != NULL) {
        rv = get_file_from_multipart_form(fcgi_req, type, content_length, stream_data, file_path);
    } else {
        rv = get_file_generic(content_length, stream_data, file_path);
    }
    when_failed(rv, exit);

exit:
    return rv;
}

int amx_fcgi_http_upload(amx_fcgi_request_t* fcgi_req,
                         amxc_var_t* data,
                         UNUSED bool acl_verify) {
    int status = 204;
    int rv = 0;
    amxc_string_t file_path;
    amxc_var_t* htable = NULL;
    int content_length = 0;
    const char* upload_folder = GET_CHAR(amx_fcgi_get_conf_opt("upload-folder"), NULL);

    amxc_string_init(&file_path, 0);


    when_null(fcgi_req, exit);
    when_str_empty(fcgi_req->raw_path, exit);
    when_true_status(fcgi_req->authorized == false, exit, status = 401); // When no ACL verify 401 every non-authorized request
    when_null(data, exit);
    when_null(data->data.data, exit);
    content_length = amx_fcgi_get_content_length(&fcgi_req->request);
    when_false(content_length > 0, exit);

    amxc_string_setf(&file_path, "%s", fcgi_req->raw_path);
    amxc_string_replace(&file_path, " ", "", UINT32_MAX);
    when_str_empty(amxc_string_get(&file_path, 0), exit);
    rv = amxc_string_search(&file_path, "/", 0);
    when_true(rv >= 0, exit);
    amxc_string_prependf(&file_path, "%s/", upload_folder);

    rv = save_file_content(fcgi_req, content_length, data, amxc_string_get(&file_path, 0));
    when_failed(rv, exit);

    free(data->data.data);
    data->data.data = NULL;
    amxc_var_set_type(data, AMXC_VAR_ID_LIST);
    htable = amxc_var_add(amxc_htable_t, data, NULL);
    amxc_var_add_key(cstring_t, htable, "file_path", amxc_string_get(&file_path, 0));

    status = 202;
exit:
    if(status != 202) {
        free(data->data.data);
        data->data.data = NULL;
        if(!str_is_empty(amxc_string_get(&file_path, 0)) && (access(amxc_string_get(&file_path, 0), F_OK) == 0)) {
            remove(amxc_string_get(&file_path, 0));
        }
    }
    amxc_string_clean(&file_path);
    return status;
}
