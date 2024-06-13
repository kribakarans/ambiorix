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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <ctype.h>
#include <syslog.h>

#include "amx_fcgi.h"

static amx_fcgi_func_t exec_funcs[] = {
    NULL,                       // INVALID
    amx_fcgi_http_add,          // POST PATH (service elements)
    amx_fcgi_http_get,          // GET PATH (service elements)
    amx_fcgi_http_set,          // PATCH PATH (service elements)
    amx_fcgi_http_del,          // DELETE PATH (service elements)
    amx_fcgi_http_cmd,          // POST CMD
    amx_fcgi_http_open_stream,  // OPEN EVENT STREAM
    amx_fcgi_http_subscribe,    // SUBSCRIBE
    amx_fcgi_http_unsubscribe,  // UNSUBSCRIBE
    amx_fcgi_http_batch,        // SEBATCH
    amx_fcgi_http_upload,       // POST UPLOAD
    amx_fcgi_http_download,     // GET DOWNLOAD
    amx_fcgi_http_login,        // POST SESSION
    amx_fcgi_http_logout,       // DELETE SESSION
};

static void amx_fcgi_free_request(amxc_llist_it_t* it) {
    amx_fcgi_request_t* fcgi_req = amxc_container_of(it, amx_fcgi_request_t, it);
    FCGX_Free(&fcgi_req->request, false);
    amxd_path_clean(&fcgi_req->path);
    amxc_var_clean(&fcgi_req->roles);
    free(fcgi_req);
}

static void amx_fcgi_fatal(amx_fcgi_request_t* fcgi_req, uint32_t status) {
    FCGX_Request* request = &fcgi_req->request;

    if((status != 401) || fcgi_req->authorized) {
        FCGX_FPrintF(request->out, "Status: %d\r\n\r\n", status);
    } else {
        FCGX_FPrintF(request->out, "Status: %d\r\nWWW-Authenticate: bearer\r\n\r\n", status);
    }
}

static void amx_fcgi_transform_cmd_path(amxc_var_t* data) {
    amxc_string_t str_path;
    amxd_path_t path;
    amxc_var_t* cmd = GET_ARG(data, "command");

    amxc_string_init(&str_path, 0);
    amxc_string_setf(&str_path, "%s", GET_CHAR(cmd, NULL));
    amxc_string_trimr(&str_path, ispunct);

    amxd_path_init(&path, amxc_string_get(&str_path, 0));
    amxc_var_set(cstring_t, cmd, amxd_path_get(&path, AMXD_OBJECT_TERMINATE));
    amxc_var_add_key(cstring_t, data, "method", amxd_path_get_param(&path));

    amxc_string_clean(&str_path);
    amxd_path_clean(&path);
}

static int amx_fcgi_get_input(amx_fcgi_request_t* fcgi_req, amxc_var_t* data) {
    int retval = -1;

    fcgi_req->method = amx_fcgi_get_method(&fcgi_req->request);
    when_true(fcgi_req->method == 0, exit);
    retval = amx_fcgi_get_content(fcgi_req, data);
    when_failed(retval, exit);
    if(fcgi_req->method == METHOD_POST_CMD) {
        amx_fcgi_transform_cmd_path(data);
        fcgi_req->raw_path = GET_CHAR(data, "command");
    } else if(fcgi_req->method != METHOD_SE_BATCH) {
        fcgi_req->raw_path = amx_fcgi_get_path(&fcgi_req->request);
    }
    when_str_empty(fcgi_req->raw_path, exit);
    if(fcgi_req->method < METHOD_OPEN_STREAM) {
        retval = amxd_path_init(&fcgi_req->path, fcgi_req->raw_path);
    } else {
        retval = amxd_path_init(&fcgi_req->path, NULL);
    }
    if(fcgi_req->method == METHOD_UNSUBSCRIBE) {
        fcgi_req->info = amx_fcgi_get_info(&fcgi_req->request);
    }
    when_failed(retval, exit);

exit:
    return retval;
}

static void amx_fcgi_send_response(FCGX_Request* request,
                                   uint32_t status,
                                   amxc_var_t* data) {
    const char* json_str = NULL;
    amxc_string_t status_code;
    amxc_var_t json;
    const char* sep = "";
    int rv = 0;

    amxc_string_init(&status_code, 0);
    amxc_var_init(&json);

    amxc_string_setf(&status_code, "Status: %d\r\n", status);

    FCGX_PutS(amxc_string_get(&status_code, 0), request->out);
    FCGX_PutS("Content-type: application/json\r\n\r\n", request->out);

    if(amxc_var_type_of(data) == AMXC_VAR_ID_HTABLE) {
        FCGX_PutS("{", request->out);
    } else {
        FCGX_PutS("[", request->out);
    }

    amxc_var_for_each(var, data) {
        FCGX_PutS(sep, request->out);
        if(amxc_var_type_of(data) == AMXC_VAR_ID_HTABLE) {
            FCGX_FPrintF(request->out, "\"%s\":", amxc_var_key(var));
        }
        rv = amxc_var_convert(&json, var, AMXC_VAR_ID_JSON);
        if(rv != 0) {
            syslog(LOG_USER, "ERROR: failed to create json string - convert returned %d", rv);
            amxc_var_log(data);
            continue;
        }
        json_str = amxc_var_constcast(jstring_t, &json);
        if(json_str == NULL) {
            syslog(LOG_USER, "ERROR: Unexpected NULL string");
            amxc_var_log(data);
            continue;
        }
        FCGX_PutS(json_str, request->out);
        sep = ",";
    }

    if(amxc_var_type_of(data) == AMXC_VAR_ID_HTABLE) {
        FCGX_PutS("}", request->out);
    } else {
        FCGX_PutS("]", request->out);
    }

    amxc_var_clean(&json);
    amxc_string_clean(&status_code);
}

static void amx_fcgi_send_download_response(FCGX_Request* request,
                                            uint32_t status,
                                            amxc_var_t* data) {

    amxc_string_t status_code;
    const char* buffer = NULL;
    const char* filename = NULL;
    int32_t buffer_size = 0;
    amxc_var_t* ptr_content = NULL;

    amxc_string_init(&status_code, 0);
    amxc_string_setf(&status_code, "Status: %d\r\n", status);
    buffer_size = GET_INT32(data, "buffer_size");
    filename = GET_CHAR(data, "filename");
    ptr_content = amxc_var_get_path(data, "content", AMXC_VAR_FLAG_DEFAULT);

    buffer = (char*) ptr_content->data.data;

    FCGX_FPrintF(request->out, amxc_string_get(&status_code, 0));
    FCGX_FPrintF(request->out, "Content-type: application/octet-stream\r\n");
    FCGX_FPrintF(request->out, "Content-Disposition: attachment; filename=\"%s\"\r\n\r\n", filename);

    for(int32_t i = 0; i < buffer_size; ++i) {
        FCGX_PutChar(buffer[i], request->out);
    }

    amxc_string_clean(&status_code);
    free(ptr_content->data.data);
}

static int amx_fcgi_respond(amx_fcgi_request_t* fcgi_req,
                            uint32_t status,
                            amxc_var_t* data) {
    int retval = EINVAL;
    FCGX_Request* request = &fcgi_req->request;

    if((fcgi_req->method != METHOD_OPEN_STREAM) &&
       (fcgi_req->method != METHOD_GET_DOWNLOAD)) {
        if(status >= 400) {
            amx_fcgi_fatal(fcgi_req, status);
            FCGX_Finish_r(request);
            goto exit;
        }
        amx_fcgi_send_response(request, status, data);
        amx_fcgi_close(fcgi_req);
    } else if(fcgi_req->method == METHOD_GET_DOWNLOAD) {
        if(status >= 400) {
            amx_fcgi_fatal(fcgi_req, status);
            FCGX_Finish_r(request);
            goto exit;
        }
        amx_fcgi_send_download_response(request, status, data);
        amx_fcgi_close(fcgi_req);
    } else if(fcgi_req->method == METHOD_OPEN_STREAM) {
        amx_fcgi_send_event(fcgi_req, NULL, NULL);
        if(status >= 400) {
            amxc_var_set(uint32_t, data, status);
            amx_fcgi_send_event(fcgi_req, "error", data);
        }
    }

    retval = 0;

exit:
    return retval;
}

void amx_fcgi_handle(UNUSED int fd, UNUSED void* priv) {
    amx_fcgi_request_t* fcgi_req = NULL;
    FCGX_Request* request = NULL;
    int retval = EINVAL;
    amxc_var_t data;
    uint32_t status = 200;
    amx_fcgi_t* amx_fcgi = amx_fcgi_get_app_data();
    bool acl_verify = true;

    amxc_var_init(&data);

    fcgi_req = (amx_fcgi_request_t*) calloc(1, sizeof(amx_fcgi_request_t));
    when_null(fcgi_req, exit);
    request = &fcgi_req->request;
    when_failed(FCGX_InitRequest(request,
                                 amx_fcgi->socket,
                                 FCGI_FAIL_ACCEPT_ON_INTR), exit);
    amxc_var_init(&fcgi_req->roles);
    amxc_var_set_type(&fcgi_req->roles, AMXC_VAR_ID_LIST);
    amxc_llist_append(&amx_fcgi->requests, &fcgi_req->it);

    when_failed(FCGX_Accept_r(request), exit);

    if(amx_fcgi_get_input(fcgi_req, &data) != 0) {
        amx_fcgi_fatal(fcgi_req, 400);
        FCGX_Finish_r(request);
        goto exit;
    }

    acl_verify = !GET_BOOL(amx_fcgi_get_conf_opt("acl.disable"), NULL);
    amx_fcgi_is_request_authorized(fcgi_req);

    status = exec_funcs[fcgi_req->method](fcgi_req, &data, acl_verify);
    when_failed(amx_fcgi_respond(fcgi_req, status, &data), exit);

    retval = 0;

exit:
    if((retval != 0) && (fcgi_req != NULL)) {
        amxc_llist_it_clean(&fcgi_req->it, amx_fcgi_free_request);
    }
    amxc_var_clean(&data);
}

void amx_fcgi_close(amx_fcgi_request_t* fcgi_req) {
    FCGX_Request* request = &fcgi_req->request;

    FCGX_Finish_r(request);
    amxc_llist_it_clean(&fcgi_req->it, amx_fcgi_free_request);
}

void amx_fcgi_finish_request(amxc_llist_it_t* it) {
    amx_fcgi_request_t* fcgi_req = amxc_container_of(it, amx_fcgi_request_t, it);
    FCGX_Finish_r(&fcgi_req->request);
    amx_fcgi_free_request(it);
}
