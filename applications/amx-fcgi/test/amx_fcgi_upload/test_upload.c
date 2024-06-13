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
#include <sys/signalfd.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>

#include <stdlib.h>
#include <stdio.h>
#include <setjmp.h>
#include <stdarg.h>
#include <cmocka.h>
#include <string.h>

#include "amx_fcgi.h"

#include <amxb/amxb_register.h>

#include "../mocks/fcgx_mock.h"
#include "../mocks/dummy_be.h"
#include "../mocks/test_common.h"

#include "test_upload.h"

static amxo_parser_t parser;
static amxd_dm_t dm;
static amxc_string_t* file_content = NULL;

static void read_from_file(const char* fname, amxc_string_t** string) {
    FILE* p_file;
    UNUSED size_t bytes_read;
    cstring_t buffer = 0;
    long length;

    p_file = fopen(fname, "rb");

    if(p_file != NULL) {
        fseek(p_file, 0, SEEK_END);
        length = ftell(p_file);
        fseek(p_file, 0, SEEK_SET);
        buffer = malloc(length);
        bytes_read = fread(buffer, 1, length, p_file);
        fclose(p_file);
    }

    if(buffer != NULL) {
        amxc_string_delete(string);
        amxc_string_new(string, 0);
        amxc_string_append(*string, buffer, length);
        free(buffer);
    }
}

static void delete_file(const cstring_t filename) {
    if(access(filename, F_OK) == 0) {
        remove(filename);
    }
}

int test_amx_fcgi_setup(UNUSED void** state) {
    amxb_bus_ctx_t* bus_ctx = NULL;
    amxd_object_t* root_obj = NULL;
    const char* socket = NULL;

    block_sigalrm();

    amxo_parser_init(&parser);
    amxd_dm_init(&dm);

    root_obj = amxd_dm_get_root(&dm);
    amxo_parser_parse_file(&parser, "../mocks/test.odl", root_obj);

    assert_int_equal(test_register_dummy_be(), 0);
    assert_int_equal(amxb_connect(&bus_ctx, "dummy:/tmp/dummy.sock"), 0);
    amxb_register(bus_ctx, &dm);
    amxb_set_access(bus_ctx, amxd_dm_access_public);

    handle_events();

    assert_int_equal(test_load_dummy_remote("../test_data/odl/greeter_definition.odl"), 0);

    socket = GETP_CHAR(&parser.config, "fcgi-socket");
    expect_string(__wrap_FCGX_OpenSocket, path, socket);
    expect_value(__wrap_FCGX_OpenSocket, backlog, 10);
    will_return(__wrap_FCGX_OpenSocket, 6);
    will_return(__wrap_FCGX_Init, 0);

    assert_int_equal(_amx_fcgi_main(AMXO_START, &dm, &parser), 0);

    return 0;
}

int test_amx_fcgi_teardown(UNUSED void** state) {
    assert_int_equal(_amx_fcgi_main(AMXO_STOP, &dm, &parser), 0);

    amxo_parser_clean(&parser);
    amxd_dm_clean(&dm);
    amxc_string_delete(&file_content);

    test_unregister_dummy_be();
    test_clean_response();

    return 0;
}

void test_upload_null_content(UNUSED void** state) {
    will_return(__wrap_FCGX_InitRequest, 0);
    will_return(__wrap_FCGX_Accept_r, 0);
    // get input
    will_return(__wrap_FCGX_GetParam, "POST");                    // HTTP_METHOD
    will_return(__wrap_FCGX_GetParam, "/upload/upload_test.txt"); // HTTP_PATH
    will_return(__wrap_FCGX_GetParam, "10");                      // CONTENT_LENGTH
    will_return(__wrap_FCGX_GetStr, "");                          // content
    will_return(__wrap_FCGX_GetStr, 0);                           // content
    test_reset_response();
    amx_fcgi_handle(0, NULL);
    assert_string_equal(test_get_response(), "Status: 400\r\n\r\n");

    assert_false(access("/tmp/upload_test.txt", F_OK) == 0);
}

void test_upload_no_content(UNUSED void** state) {
    const char* content = "";
    amxc_var_t length;
    amxc_var_init(&length);
    amxc_var_set(uint32_t, &length, strlen(content));
    amxc_var_cast(&length, AMXC_VAR_ID_CSTRING);

    will_return(__wrap_FCGX_InitRequest, 0);
    will_return(__wrap_FCGX_Accept_r, 0);
    // get input
    will_return(__wrap_FCGX_GetParam, "POST");                    // HTTP_METHOD
    will_return(__wrap_FCGX_GetParam, "/upload/upload_test.txt"); // HTTP_PATH
    will_return(__wrap_FCGX_GetParam, GET_CHAR(&length, NULL));   // CONTENT_LENGTH
    will_return(__wrap_FCGX_GetParam, "/upload/upload_test.txt"); // HTTP_PATH
    set_acl_user(NULL);
    will_return(__wrap_amx_fcgi_is_request_authorized, 0);

    test_reset_response();
    amx_fcgi_handle(0, NULL);
    assert_string_equal(test_get_response(), "Status: 204\r\nContent-type: application/json\r\n\r\n[]");

    assert_false(access("/tmp/upload_test.txt", F_OK) == 0);

    amxc_var_clean(&length);
}

void test_upload_multipart_form(UNUSED void** state) {
    const char* content =
        "SOMETHING\n"
        "------WebKitFormBoundaryOdG43ZTB9ez9KZ9G\n"
        "Content-Disposition: form-data; name=\"filename\"; filename=\"upload_test.txt\"\n"
        "Content-Type: application/txt\n\n"
        "This is an upload test\n\n"
        "------WebKitFormBoundaryOdG43ZTB9ez9KZ9G\n"
        "Content-Disposition: form-data; name=\"submit\"\n\n"
        "------WebKitFormBoundaryOdG43ZTB9ez9KZ9G--\n"
        "SOMETHING ELSE\n";

    amxc_var_t length;
    amxc_var_init(&length);
    amxc_var_set(uint32_t, &length, strlen(content));
    amxc_var_cast(&length, AMXC_VAR_ID_CSTRING);

    will_return(__wrap_FCGX_InitRequest, 0);
    will_return(__wrap_FCGX_Accept_r, 0);
    // get input
    will_return(__wrap_FCGX_GetParam, "POST");                                                                                   // HTTP_METHOD
    will_return(__wrap_FCGX_GetParam, "/upload/upload_test.txt");                                                                // HTTP_PATH
    will_return(__wrap_FCGX_GetParam, GET_CHAR(&length, NULL));                                                                  // CONTENT_LENGTH
    will_return(__wrap_FCGX_GetStr, content);                                                                                    // content
    will_return(__wrap_FCGX_GetStr, strlen(content));                                                                            // content
    will_return(__wrap_FCGX_GetParam, "/upload/upload_test.txt");                                                                // HTTP_PATH
    will_return(__wrap_FCGX_GetParam, GET_CHAR(&length, NULL));                                                                  // CONTENT_LENGTH
    will_return(__wrap_FCGX_GetParam, "Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryOdG43ZTB9ez9KZ9G\r\n"); // CONTENT_TYPE
    set_acl_user(NULL);
    will_return(__wrap_amx_fcgi_is_request_authorized, 0);

    test_reset_response();
    amx_fcgi_handle(0, NULL);
    assert_string_equal(test_get_response(), "Status: 202\r\nContent-type: application/json\r\n\r\n[{\"file_path\":\"/tmp/upload_test.txt\"}]");

    assert_true(access("/tmp/upload_test.txt", F_OK) == 0);
    read_from_file("/tmp/upload_test.txt", &file_content);
    delete_file("/tmp/upload_test.txt");
    assert_false(access("/tmp/upload_test.txt", F_OK) == 0);
    assert_string_equal(amxc_string_get(file_content, 0), "This is an upload test\n");
    amxc_string_delete(&file_content);

    amxc_var_clean(&length);
}

void test_upload_multipart_form_without_filename(UNUSED void** state) {
    const char* content =
        "SOMETHING\n"
        "------WebKitFormBoundaryOdG43ZTB9ez9KZ9G\n"
        "Content-Disposition: form-data; name=\"filename\"; filename=\"upload_test.txt\"\n"
        "Content-Type: application/txt\n\n"
        "This is an upload test\n\n"
        "------WebKitFormBoundaryOdG43ZTB9ez9KZ9G\n"
        "Content-Disposition: form-data; name=\"submit\"\n\n"
        "------WebKitFormBoundaryOdG43ZTB9ez9KZ9G\n"
        "SOMETHING ELSE\n";

    amxc_var_t length;
    amxc_var_init(&length);
    amxc_var_set(uint32_t, &length, strlen(content));
    amxc_var_cast(&length, AMXC_VAR_ID_CSTRING);

    will_return(__wrap_FCGX_InitRequest, 0);
    will_return(__wrap_FCGX_Accept_r, 0);
    // get input
    will_return(__wrap_FCGX_GetParam, "POST");                  // HTTP_METHOD
    will_return(__wrap_FCGX_GetParam, "/upload/");              // HTTP_PATH
    will_return(__wrap_FCGX_GetParam, GET_CHAR(&length, NULL)); // CONTENT_LENGTH
    will_return(__wrap_FCGX_GetStr, content);                   // content
    will_return(__wrap_FCGX_GetStr, strlen(content));           // content
    will_return(__wrap_FCGX_GetParam, "/upload/");              // HTTP_PATH
    set_acl_user(NULL);
    will_return(__wrap_amx_fcgi_is_request_authorized, 0);

    test_reset_response();
    amx_fcgi_handle(0, NULL);
    assert_string_equal(test_get_response(), "Status: 204\r\nContent-type: application/json\r\n\r\n[]");

    assert_false(access("/tmp/upload_test.txt", F_OK) == 0);

    amxc_var_clean(&length);
}

void test_upload_multipart_form_with_subpath(UNUSED void** state) {
    const char* content =
        "SOMETHING\n"
        "------WebKitFormBoundaryOdG43ZTB9ez9KZ9G\n"
        "Content-Disposition: form-data; name=\"filename\"; filename=\"upload_test.txt\"\n"
        "Content-Type: application/txt\n\n"
        "This is an upload test\n\n"
        "------WebKitFormBoundaryOdG43ZTB9ez9KZ9G\n"
        "Content-Disposition: form-data; name=\"submit\"\n\n"
        "------WebKitFormBoundaryOdG43ZTB9ez9KZ9G\n"
        "SOMETHING ELSE\n";

    amxc_var_t length;
    amxc_var_init(&length);
    amxc_var_set(uint32_t, &length, strlen(content));
    amxc_var_cast(&length, AMXC_VAR_ID_CSTRING);

    will_return(__wrap_FCGX_InitRequest, 0);
    will_return(__wrap_FCGX_Accept_r, 0);
    // get input
    will_return(__wrap_FCGX_GetParam, "POST");                            // HTTP_METHOD
    will_return(__wrap_FCGX_GetParam, "/upload/subpath/upload_test.txt"); // HTTP_PATH
    will_return(__wrap_FCGX_GetParam, GET_CHAR(&length, NULL));           // CONTENT_LENGTH
    will_return(__wrap_FCGX_GetStr, content);                             // content
    will_return(__wrap_FCGX_GetStr, strlen(content));                     // content
    will_return(__wrap_FCGX_GetParam, "/upload/subpath/upload_test.txt"); // HTTP_PATH
    will_return(__wrap_FCGX_GetParam, GET_CHAR(&length, NULL));           // CONTENT_LENGTH
    set_acl_user(NULL);
    will_return(__wrap_amx_fcgi_is_request_authorized, 0);

    test_reset_response();
    amx_fcgi_handle(0, NULL);
    assert_string_equal(test_get_response(), "Status: 204\r\nContent-type: application/json\r\n\r\n[]");

    assert_false(access("/tmp/upload_test.txt", F_OK) == 0);

    amxc_var_clean(&length);
}

void test_upload_multipart_form_without_boundary(UNUSED void** state) {
    const char* content =
        "SOMETHING\n"
        "------WebKitFormBoundaryOdG43ZTB9ez9KZ9G\n"
        "Content-Disposition: form-data; name=\"filename\"; filename=\"upload_test.txt\"\n"
        "Content-Type: application/txt\n\n"
        "This is an upload test\n\n"
        "------WebKitFormBoundaryOdG43ZTB9ez9KZ9G\n"
        "Content-Disposition: form-data; name=\"submit\"\n\n"
        "------WebKitFormBoundaryOdG43ZTB9ez9KZ9G\n"
        "SOMETHING ELSE\n";

    amxc_var_t length;
    amxc_var_init(&length);
    amxc_var_set(uint32_t, &length, strlen(content));
    amxc_var_cast(&length, AMXC_VAR_ID_CSTRING);

    will_return(__wrap_FCGX_InitRequest, 0);
    will_return(__wrap_FCGX_Accept_r, 0);
    // get input
    will_return(__wrap_FCGX_GetParam, "POST");                                    // HTTP_METHOD
    will_return(__wrap_FCGX_GetParam, "/upload/upload_test.txt");                 // HTTP_PATH
    will_return(__wrap_FCGX_GetParam, GET_CHAR(&length, NULL));                   // CONTENT_LENGTH
    will_return(__wrap_FCGX_GetStr, content);                                     // content
    will_return(__wrap_FCGX_GetStr, strlen(content));                             // content
    will_return(__wrap_FCGX_GetParam, "/upload/upload_test.txt");                 // HTTP_PATH
    will_return(__wrap_FCGX_GetParam, GET_CHAR(&length, NULL));                   // CONTENT_LENGTH
    will_return(__wrap_FCGX_GetParam, "Content-Type: multipart/form-data; \r\n"); // CONTENT_TYPE
    set_acl_user(NULL);
    will_return(__wrap_amx_fcgi_is_request_authorized, 0);

    test_reset_response();
    amx_fcgi_handle(0, NULL);
    assert_string_equal(test_get_response(), "Status: 204\r\nContent-type: application/json\r\n\r\n[]");

    assert_false(access("/tmp/upload_test.txt", F_OK) == 0);

    amxc_var_clean(&length);
}

void test_upload_multipart_form_empty_boundary(UNUSED void** state) {
    const char* content =
        "SOMETHING\n"
        "------WebKitFormBoundaryOdG43ZTB9ez9KZ9G\n"
        "Content-Disposition: form-data; name=\"filename\"; filename=\"upload_test.txt\"\n"
        "Content-Type: application/txt\n\n"
        "This is an upload test\n\n"
        "------WebKitFormBoundaryOdG43ZTB9ez9KZ9G\n"
        "Content-Disposition: form-data; name=\"submit\"\n\n"
        "------WebKitFormBoundaryOdG43ZTB9ez9KZ9G\n"
        "SOMETHING ELSE\n";

    amxc_var_t length;
    amxc_var_init(&length);
    amxc_var_set(uint32_t, &length, strlen(content));
    amxc_var_cast(&length, AMXC_VAR_ID_CSTRING);

    will_return(__wrap_FCGX_InitRequest, 0);
    will_return(__wrap_FCGX_Accept_r, 0);
    // get input
    will_return(__wrap_FCGX_GetParam, "POST");                                             // HTTP_METHOD
    will_return(__wrap_FCGX_GetParam, "/upload/upload_test.txt");                          // HTTP_PATH
    will_return(__wrap_FCGX_GetParam, GET_CHAR(&length, NULL));                            // CONTENT_LENGTH
    will_return(__wrap_FCGX_GetStr, content);                                              // content
    will_return(__wrap_FCGX_GetStr, strlen(content));                                      // content
    will_return(__wrap_FCGX_GetParam, "/upload/upload_test.txt");                          // HTTP_PATH
    will_return(__wrap_FCGX_GetParam, GET_CHAR(&length, NULL));                            // CONTENT_LENGTH
    will_return(__wrap_FCGX_GetParam, "Content-Type: multipart/form-data; boundary=\r\n"); // CONTENT_TYPE
    set_acl_user(NULL);
    will_return(__wrap_amx_fcgi_is_request_authorized, 0);

    test_reset_response();
    amx_fcgi_handle(0, NULL);
    assert_string_equal(test_get_response(), "Status: 204\r\nContent-type: application/json\r\n\r\n[]");

    assert_false(access("/tmp/upload_test.txt", F_OK) == 0);

    amxc_var_clean(&length);
}

void test_upload_multipart_form_no_content(UNUSED void** state) {
    const char* content =
        "SOMETHING\n"
        "------WebKitFormBoundaryOdG43ZTB9ez9KZ9G\n"
        "Content-Disposition: form-data; name=\"filename\"; filename=\"upload_test.txt\"\n"
        "Content-Type: application/txt\n\n"
        "------WebKitFormBoundaryOdG43ZTB9ez9KZ9G\n"
        "Content-Disposition: form-data; name=\"submit\"\n\n"
        "------WebKitFormBoundaryOdG43ZTB9ez9KZ9G\n"
        "SOMETHING ELSE\n";

    amxc_var_t length;
    amxc_var_init(&length);
    amxc_var_set(uint32_t, &length, strlen(content));
    amxc_var_cast(&length, AMXC_VAR_ID_CSTRING);

    will_return(__wrap_FCGX_InitRequest, 0);
    will_return(__wrap_FCGX_Accept_r, 0);
    // get input
    will_return(__wrap_FCGX_GetParam, "POST");                                                                                   // HTTP_METHOD
    will_return(__wrap_FCGX_GetParam, "/upload/upload_test.txt");                                                                // HTTP_PATH
    will_return(__wrap_FCGX_GetParam, GET_CHAR(&length, NULL));                                                                  // CONTENT_LENGTH
    will_return(__wrap_FCGX_GetStr, content);                                                                                    // content
    will_return(__wrap_FCGX_GetStr, strlen(content));                                                                            // content
    will_return(__wrap_FCGX_GetParam, "/upload/upload_test.txt");                                                                // HTTP_PATH
    will_return(__wrap_FCGX_GetParam, GET_CHAR(&length, NULL));                                                                  // CONTENT_LENGTH
    will_return(__wrap_FCGX_GetParam, "Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryOdG43ZTB9ez9KZ9G\r\n"); // CONTENT_TYPE
    set_acl_user(NULL);
    will_return(__wrap_amx_fcgi_is_request_authorized, 0);

    test_reset_response();
    amx_fcgi_handle(0, NULL);
    assert_string_equal(test_get_response(), "Status: 204\r\nContent-type: application/json\r\n\r\n[]");

    assert_false(access("/tmp/upload_test.txt", F_OK) == 0);

    amxc_var_clean(&length);
}

void test_upload_multipart_form_no_boundaries(UNUSED void** state) {
    const char* content =
        "SOMETHING\n"
        "Content-Disposition: form-data; name=\"filename\"; filename=\"upload_test.txt\"\n"
        "Content-Type: application/txt\n\n"
        "Content-Disposition: form-data; name=\"submit\"\n\n"
        "SOMETHING ELSE\n";

    amxc_var_t length;
    amxc_var_init(&length);
    amxc_var_set(uint32_t, &length, strlen(content));
    amxc_var_cast(&length, AMXC_VAR_ID_CSTRING);

    will_return(__wrap_FCGX_InitRequest, 0);
    will_return(__wrap_FCGX_Accept_r, 0);
    // get input
    will_return(__wrap_FCGX_GetParam, "POST");                                                                                   // HTTP_METHOD
    will_return(__wrap_FCGX_GetParam, "/upload/upload_test.txt");                                                                // HTTP_PATH
    will_return(__wrap_FCGX_GetParam, GET_CHAR(&length, NULL));                                                                  // CONTENT_LENGTH
    will_return(__wrap_FCGX_GetStr, content);                                                                                    // content
    will_return(__wrap_FCGX_GetStr, strlen(content));                                                                            // content
    will_return(__wrap_FCGX_GetParam, "/upload/upload_test.txt");                                                                // HTTP_PATH
    will_return(__wrap_FCGX_GetParam, GET_CHAR(&length, NULL));                                                                  // CONTENT_LENGTH
    will_return(__wrap_FCGX_GetParam, "Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryOdG43ZTB9ez9KZ9G\r\n"); // CONTENT_TYPE
    set_acl_user(NULL);
    will_return(__wrap_amx_fcgi_is_request_authorized, 0);

    test_reset_response();
    amx_fcgi_handle(0, NULL);
    assert_string_equal(test_get_response(), "Status: 204\r\nContent-type: application/json\r\n\r\n[]");

    assert_false(access("/tmp/upload_test.txt", F_OK) == 0);

    amxc_var_clean(&length);
}

void test_upload_multipart_form_wrong_format(UNUSED void** state) {
    const char* content =
        "SOMETHING\n"
        "------WebKitFormBoundaryOdG43ZTB9ez9KZ9G\n"
        "Content-Disposition: form-data; name=\"filename\"; filename=\"upload_test.txt\"\n"
        "Content-Type: application/txt\n\n"
        "------WebKitFormBoundaryOdG43ZTB9ez9KZ9G\n"
        "------WebKitFormBoundaryOdG43ZTB9ez9KZ9G\n"
        "SOMETHING ELSE\n";

    amxc_var_t length;
    amxc_var_init(&length);
    amxc_var_set(uint32_t, &length, strlen(content));
    amxc_var_cast(&length, AMXC_VAR_ID_CSTRING);

    will_return(__wrap_FCGX_InitRequest, 0);
    will_return(__wrap_FCGX_Accept_r, 0);
    // get input
    will_return(__wrap_FCGX_GetParam, "POST");                                                                                   // HTTP_METHOD
    will_return(__wrap_FCGX_GetParam, "/upload/upload_test.txt");                                                                // HTTP_PATH
    will_return(__wrap_FCGX_GetParam, GET_CHAR(&length, NULL));                                                                  // CONTENT_LENGTH
    will_return(__wrap_FCGX_GetStr, content);                                                                                    // content
    will_return(__wrap_FCGX_GetStr, strlen(content));                                                                            // content
    will_return(__wrap_FCGX_GetParam, "/upload/upload_test.txt");                                                                // HTTP_PATH
    will_return(__wrap_FCGX_GetParam, GET_CHAR(&length, NULL));                                                                  // CONTENT_LENGTH
    will_return(__wrap_FCGX_GetParam, "Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryOdG43ZTB9ez9KZ9G\r\n"); // CONTENT_TYPE
    set_acl_user(NULL);
    will_return(__wrap_amx_fcgi_is_request_authorized, 0);

    test_reset_response();
    amx_fcgi_handle(0, NULL);
    assert_string_equal(test_get_response(), "Status: 204\r\nContent-type: application/json\r\n\r\n[]");

    assert_false(access("/tmp/upload_test.txt", F_OK) == 0);

    amxc_var_clean(&length);
}

void test_upload_direct(UNUSED void** state) {
    const char* content = "This is an upload test\n";
    amxc_var_t length;
    amxc_var_init(&length);
    amxc_var_set(uint32_t, &length, strlen(content));
    amxc_var_cast(&length, AMXC_VAR_ID_CSTRING);

    will_return(__wrap_FCGX_InitRequest, 0);
    will_return(__wrap_FCGX_Accept_r, 0);
    // get input
    will_return(__wrap_FCGX_GetParam, "POST");                         // HTTP_METHOD
    will_return(__wrap_FCGX_GetParam, "/upload/upload_test.txt");      // HTTP_PATH
    will_return(__wrap_FCGX_GetParam, GET_CHAR(&length, NULL));        // CONTENT_LENGTH
    will_return(__wrap_FCGX_GetStr, content);                          // content
    will_return(__wrap_FCGX_GetStr, strlen(content));                  // content
    will_return(__wrap_FCGX_GetParam, "/upload/upload_test.txt");      // HTTP_PATH
    will_return(__wrap_FCGX_GetParam, GET_CHAR(&length, NULL));        // CONTENT_LENGTH
    will_return(__wrap_FCGX_GetParam, "Content-Type: text/plain\r\n"); // CONTENT_TYPE
    set_acl_user(NULL);
    will_return(__wrap_amx_fcgi_is_request_authorized, 0);

    test_reset_response();
    amx_fcgi_handle(0, NULL);
    assert_string_equal(test_get_response(), "Status: 202\r\nContent-type: application/json\r\n\r\n[{\"file_path\":\"/tmp/upload_test.txt\"}]");

    assert_true(access("/tmp/upload_test.txt", F_OK) == 0);
    read_from_file("/tmp/upload_test.txt", &file_content);
    delete_file("/tmp/upload_test.txt");
    assert_false(access("/tmp/upload_test.txt", F_OK) == 0);
    assert_string_equal(amxc_string_get(file_content, 0), "This is an upload test\n");
    amxc_string_delete(&file_content);

    amxc_var_clean(&length);
}

void test_upload_direct_without_filename(UNUSED void** state) {
    const char* content = "This is an upload test\n";

    amxc_var_t length;
    amxc_var_init(&length);
    amxc_var_set(uint32_t, &length, strlen(content));
    amxc_var_cast(&length, AMXC_VAR_ID_CSTRING);

    will_return(__wrap_FCGX_InitRequest, 0);
    will_return(__wrap_FCGX_Accept_r, 0);
    // get input
    will_return(__wrap_FCGX_GetParam, "POST");                  // HTTP_METHOD
    will_return(__wrap_FCGX_GetParam, "/upload/");              // HTTP_PATH
    will_return(__wrap_FCGX_GetParam, GET_CHAR(&length, NULL)); // CONTENT_LENGTH
    will_return(__wrap_FCGX_GetStr, content);                   // content
    will_return(__wrap_FCGX_GetStr, strlen(content));           // content
    will_return(__wrap_FCGX_GetParam, "/upload/");              // HTTP_PATH
    set_acl_user(NULL);
    will_return(__wrap_amx_fcgi_is_request_authorized, 0);

    test_reset_response();
    amx_fcgi_handle(0, NULL);
    assert_string_equal(test_get_response(), "Status: 204\r\nContent-type: application/json\r\n\r\n[]");

    assert_false(access("/tmp/upload_test.txt", F_OK) == 0);

    amxc_var_clean(&length);
}

void test_upload_direct_with_subpath(UNUSED void** state) {
    const char* content = "This is an upload test\n";

    amxc_var_t length;
    amxc_var_init(&length);
    amxc_var_set(uint32_t, &length, strlen(content));
    amxc_var_cast(&length, AMXC_VAR_ID_CSTRING);

    will_return(__wrap_FCGX_InitRequest, 0);
    will_return(__wrap_FCGX_Accept_r, 0);
    // get input
    will_return(__wrap_FCGX_GetParam, "POST");                            // HTTP_METHOD
    will_return(__wrap_FCGX_GetParam, "/upload/subpath/upload_test.txt"); // HTTP_PATH
    will_return(__wrap_FCGX_GetParam, GET_CHAR(&length, NULL));           // CONTENT_LENGTH
    will_return(__wrap_FCGX_GetStr, content);                             // content
    will_return(__wrap_FCGX_GetStr, strlen(content));                     // content
    will_return(__wrap_FCGX_GetParam, "/upload/subpath/upload_test.txt"); // HTTP_PATH
    will_return(__wrap_FCGX_GetParam, GET_CHAR(&length, NULL));           // CONTENT_LENGTH
    set_acl_user(NULL);
    will_return(__wrap_amx_fcgi_is_request_authorized, 0);

    test_reset_response();
    amx_fcgi_handle(0, NULL);
    assert_string_equal(test_get_response(), "Status: 204\r\nContent-type: application/json\r\n\r\n[]");

    assert_false(access("/tmp/upload_test.txt", F_OK) == 0);

    amxc_var_clean(&length);
}