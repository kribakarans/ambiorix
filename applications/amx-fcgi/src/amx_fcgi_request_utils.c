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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include "amx_fcgi.h"

#define PATH_SE_PREFIX_LENGTH  17  // "/serviceElements/"
#define CMD_PREFIX_LENGTH       9  // "/commands"
#define BATCH_PREFIX_LENGTH     8  // "/seBatch"
#define UPLOAD_PREFIX_LENGTH    8  // "/upload/"
#define DOWNLOAD_PREFIX_LENGTH 10  // "/download/"
#define EVENT_PREFIX_LENGTH     8  // "/events/"
#define SESSION_PREFIX_LENGTH   8  // "/session"

#define HTTP_METHOD     "REQUEST_METHOD"
#define HTTP_PATH       "SCRIPT_NAME"
#define HTTP_PATH_INFO  "PATH_INFO"
#define HTTP_QUERY      "QUERY_STRING"
#define REMOTE_USER     "REMOTE_USER"

typedef enum _path_type {
    INVALID,
    SERVICE_ELEMENT,
    COMMAND,
    EVENT,
    SESSION,
    BATCH,
    UPLOAD,
    DOWNLOAD
} path_type_t;

static path_type_t amx_fcgi_get_path_type(FCGX_Request* request) {
    const char* path = FCGX_GetParam(HTTP_PATH, request->envp);
    path_type_t type = INVALID;

    when_str_empty(path, exit);
    if(strncmp(path, "/serviceElements/", PATH_SE_PREFIX_LENGTH) == 0) {
        type = SERVICE_ELEMENT;
    } else if(strncmp(path, "/commands", CMD_PREFIX_LENGTH) == 0) {
        type = COMMAND;
    } else if(strncmp(path, "/events/", EVENT_PREFIX_LENGTH) == 0) {
        type = EVENT;
    } else if(strncmp(path, "/session", SESSION_PREFIX_LENGTH) == 0) {
        type = SESSION;
    } else if(strncmp(path, "/seBatch", BATCH_PREFIX_LENGTH) == 0) {
        type = BATCH;
    } else if(strncmp(path, "/upload/", UPLOAD_PREFIX_LENGTH) == 0) {
        type = UPLOAD;
    } else if(strncmp(path, "/download/", UPLOAD_PREFIX_LENGTH) == 0) {
        type = DOWNLOAD;
    }

exit:
    return type;
}

static request_method_t amx_fcgi_check_path(FCGX_Request* request,
                                            request_method_t method) {
    path_type_t type = amx_fcgi_get_path_type(request);
    if((method == METHOD_POST_PATH)) {
        switch(type) {
        case COMMAND:
            method = METHOD_POST_CMD;
            break;
        case UPLOAD:
            method = METHOD_POST_UPLOAD;
            break;
        case EVENT:
            method = METHOD_SUBSCRIBE;
            break;
        case BATCH:
            method = METHOD_SE_BATCH;
            break;
        case SESSION:
            method = METHOD_SESSION_LOGIN;
            break;
        default:
            break;
        }
    }

    if((method == METHOD_DELETE)) {
        switch(type) {
        case EVENT:
            method = METHOD_UNSUBSCRIBE;
            break;
        case SESSION:
            method = METHOD_SESSION_LOGOUT;
        default:
            break;
        }
    }

    if(method == METHOD_GET_PATH) {
        switch(type) {
        case EVENT:
            method = METHOD_OPEN_STREAM;
            break;
        case DOWNLOAD:
            method = METHOD_GET_DOWNLOAD;
            break;
        default:
            break;
        }
    }

    return method;
}

request_method_t amx_fcgi_get_method(FCGX_Request* request) {
    request_method_t method = METHOD_UNSUPORTED;
    const char* request_method = FCGX_GetParam(HTTP_METHOD, request->envp);
    const char* method_names[] = {
        "INVALID", "POST", "GET", "PATCH", "DELETE", NULL
    };

    when_str_empty(request_method, exit);

    for(uint32_t i = 1; method_names[i] != NULL; i++) {
        if(strcmp(request_method, method_names[i]) == 0) {
            method = (request_method_t) i;
            break;
        }
    }

    if(method != METHOD_UNSUPORTED) {
        method = amx_fcgi_check_path(request, method);
    }

exit:
    return method;
}

const char* amx_fcgi_get_path(FCGX_Request* request) {
    const char* path = FCGX_GetParam(HTTP_PATH, request->envp);

    when_str_empty(path, exit);
    if(strncmp(path, "/serviceElements/", PATH_SE_PREFIX_LENGTH) == 0) {
        path += PATH_SE_PREFIX_LENGTH;
    } else if(strncmp(path, "/events/", EVENT_PREFIX_LENGTH) == 0) {
        path += EVENT_PREFIX_LENGTH;
    } else if(strncmp(path, "/upload/", UPLOAD_PREFIX_LENGTH) == 0) {
        path += UPLOAD_PREFIX_LENGTH;
    } else if(strncmp(path, "/download/", DOWNLOAD_PREFIX_LENGTH) == 0) {
        path += DOWNLOAD_PREFIX_LENGTH;
    } else {
        path = NULL;
    }

exit:
    return path;
}

const char* amx_fcgi_get_info(FCGX_Request* request) {
    const char* path = FCGX_GetParam(HTTP_PATH_INFO, request->envp);

    when_str_empty(path, exit);
    path += 1;

exit:
    return path;
}

int amx_fcgi_get_content_length(FCGX_Request* request) {
    char* contentLength = NULL;
    int len = 0;

    contentLength = FCGX_GetParam("CONTENT_LENGTH", request->envp);

    if(contentLength != NULL) {
        len = strtol(contentLength, NULL, 10);
    }

    return len;
}

const char* amx_fcgi_get_content_type(FCGX_Request* request) {
    const char* contentType = FCGX_GetParam("CONTENT_TYPE", request->envp);

    return contentType;
}

static char* get_input_stream(amx_fcgi_request_t* fcgi_req, int content_length) {
    char* buffer = NULL;
    int read_len = 0;

    buffer = (char*) malloc((size_t) content_length + 1);
    when_null(buffer, exit);
    read_len = FCGX_GetStr(buffer, content_length, fcgi_req->request.in);
    if(read_len != content_length) {
        free(buffer);
        buffer = NULL;
        goto exit;
    }
    buffer[content_length] = 0;

exit:
    return buffer;
}

int amx_fcgi_get_content(amx_fcgi_request_t* fcgi_req, amxc_var_t* data) {
    char* buffer = NULL;
    int retval = 0;
    request_method_t method = METHOD_UNSUPORTED;
    int len = 0;

    when_null_status(fcgi_req, exit, retval = EINVAL);
    len = amx_fcgi_get_content_length(&fcgi_req->request);
    when_true(len <= 0, exit);
    method = fcgi_req->method;

    buffer = get_input_stream(fcgi_req, len);
    when_null_status(buffer, exit, retval = EINVAL);

    //For the upload we use the raw binary streamed.
    if(method == METHOD_POST_UPLOAD) {
        //Use the custom data pointer to store the buffer that is going to be used by the handler
        data->data.data = (void*) buffer;
    } else {
        retval = amxc_var_set(jstring_t, data, buffer);
        when_failed(retval, exit);
        amxc_var_cast(data, AMXC_VAR_ID_ANY);
    }

exit:
    if(method != METHOD_POST_UPLOAD) {
        free(buffer);
    }
    return retval;
}

char* amx_fcgi_get_acl_file(amx_fcgi_request_t* fcgi_req) {
    char* file = NULL;
    amxc_string_t acl_file;
    const char* acl_path = GET_CHAR(amx_fcgi_get_conf_opt("acl.path"), NULL);

    amxc_string_init(&acl_file, 0);
    amxc_string_setf(&acl_file, "%s/untrusted.json", acl_path);

    if(fcgi_req->authorized) {
        amxc_var_t* role = GETI_ARG(&fcgi_req->roles, 0); // for now always take first possible roles
        when_null(role, exit);
        amxc_string_setf(&acl_file, "%s/%s.json", acl_path, GET_CHAR(role, NULL));
    }

exit:
    file = amxc_string_take_buffer(&acl_file);

    amxc_string_clean(&acl_file);
    return file;
}
