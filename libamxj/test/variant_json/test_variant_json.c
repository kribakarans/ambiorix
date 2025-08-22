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

#include <sys/time.h>
#include <sys/resource.h>

#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <inttypes.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <cmocka.h>

#include <yajl/yajl_gen.h>
#include <yajl/yajl_parse.h>

#include <amxc/amxc_string.h>
#include <amxc/amxc_variant_type.h>

#include <amxj/amxj_variant.h>
#include <variant_json_priv.h>

#include "test_variant_json.h"

#include <amxc/amxc_macros.h>
void test_variant_json_init(UNUSED void** state) {
    amxc_var_t var;
    const char* json_string = NULL;

    amxc_var_init(&var);
    assert_int_equal(amxc_var_set_type(&var, AMXC_VAR_ID_JSON), 0);
    assert_int_equal(amxc_var_type_of(&var), AMXC_VAR_ID_JSON);
    assert_string_equal(amxc_var_type_name_of(&var), AMXC_VAR_NAME_JSON);

    assert_ptr_not_equal(var.data.data, NULL);
    json_string = amxc_var_constcast(jstring_t, &var);
    assert_string_equal(json_string, "");

    amxc_var_clean(&var);
}

void test_variant_json_copy(UNUSED void** state) {
    amxc_var_t var;
    amxc_var_t var_copy;
    const char* json_string = NULL;

    amxc_var_init(&var);
    amxc_var_init(&var_copy);

    amxc_var_set(cstring_t, &var, "Hello world");
    assert_int_equal(amxc_var_type_of(&var), AMXC_VAR_ID_CSTRING);
    assert_int_equal(amxc_var_convert(&var_copy, &var, AMXC_VAR_ID_JSON), 0);
    assert_int_equal(amxc_var_type_of(&var_copy), AMXC_VAR_ID_JSON);
    assert_string_equal(amxc_var_type_name_of(&var_copy), AMXC_VAR_NAME_JSON);

    assert_int_equal(amxc_var_copy(&var, &var_copy), 0);
    assert_int_equal(amxc_var_type_of(&var), AMXC_VAR_ID_JSON);
    assert_string_equal(amxc_var_type_name_of(&var), AMXC_VAR_NAME_JSON);

    json_string = amxc_var_constcast(jstring_t, &var);
    assert_ptr_not_equal(json_string, NULL);
    assert_string_equal(json_string, "\"Hello world\"");

    amxc_var_clean(&var);
    amxc_var_clean(&var_copy);
}

void test_variant_json_move(UNUSED void** state) {
    amxc_var_t var;
    amxc_var_t var_copy;
    const char* json_string = NULL;

    amxc_var_init(&var);
    amxc_var_init(&var_copy);

    amxc_var_set(cstring_t, &var, "Hello world");
    assert_int_equal(amxc_var_type_of(&var), AMXC_VAR_ID_CSTRING);
    assert_int_equal(amxc_var_convert(&var_copy, &var, AMXC_VAR_ID_JSON), 0);
    assert_int_equal(amxc_var_type_of(&var_copy), AMXC_VAR_ID_JSON);
    assert_string_equal(amxc_var_type_name_of(&var_copy), AMXC_VAR_NAME_JSON);

    assert_int_equal(amxc_var_move(&var, &var_copy), 0);
    assert_int_equal(amxc_var_type_of(&var), AMXC_VAR_ID_JSON);
    assert_string_equal(amxc_var_type_name_of(&var), AMXC_VAR_NAME_JSON);
    assert_true(amxc_var_is_null(&var_copy));

    json_string = amxc_var_constcast(jstring_t, &var);
    assert_ptr_not_equal(json_string, NULL);
    assert_string_equal(json_string, "\"Hello world\"");

    amxc_var_clean(&var);
    amxc_var_clean(&var_copy);
}

void test_variant_json_from_null(UNUSED void** state) {
    amxc_var_t var;
    amxc_var_t src;
    const char* json_string = NULL;

    amxc_var_init(&var);
    amxc_var_init(&src);

    assert_int_equal(amxc_var_convert(&var, &src, AMXC_VAR_ID_JSON), 0);
    assert_int_equal(amxc_var_type_of(&var), AMXC_VAR_ID_JSON);
    assert_string_equal(amxc_var_type_name_of(&var), AMXC_VAR_NAME_JSON);

    assert_ptr_not_equal(var.data.data, NULL);
    json_string = amxc_var_constcast(jstring_t, &var);
    assert_ptr_not_equal(json_string, NULL);
    assert_string_equal(json_string, "null");

    amxc_var_clean(&var);
    amxc_var_clean(&src);
}

void test_variant_json_from_string(UNUSED void** state) {
    amxc_var_t var;
    amxc_var_t src;
    const char* json_string = NULL;

    amxc_var_init(&var);
    amxc_var_init(&src);

    amxc_var_set(cstring_t, &src, "Hello world");
    assert_int_equal(amxc_var_type_of(&src), AMXC_VAR_ID_CSTRING);
    assert_int_equal(amxc_var_convert(&var, &src, AMXC_VAR_ID_JSON), 0);
    assert_int_equal(amxc_var_type_of(&var), AMXC_VAR_ID_JSON);
    assert_string_equal(amxc_var_type_name_of(&var), AMXC_VAR_NAME_JSON);

    assert_ptr_not_equal(var.data.data, NULL);
    json_string = amxc_var_constcast(jstring_t, &var);
    assert_ptr_not_equal(json_string, NULL);
    assert_string_equal(json_string, "\"Hello world\"");

    amxc_var_set(csv_string_t, &src, "Hello,world");
    assert_int_equal(amxc_var_type_of(&src), AMXC_VAR_ID_CSV_STRING);
    assert_int_equal(amxc_var_convert(&var, &src, AMXC_VAR_ID_JSON), 0);
    assert_int_equal(amxc_var_type_of(&var), AMXC_VAR_ID_JSON);
    assert_string_equal(amxc_var_type_name_of(&var), AMXC_VAR_NAME_JSON);

    assert_ptr_not_equal(var.data.data, NULL);
    json_string = amxc_var_constcast(jstring_t, &var);
    assert_ptr_not_equal(json_string, NULL);
    assert_string_equal(json_string, "\"Hello,world\"");

    amxc_var_set(ssv_string_t, &src, "Hello world");
    assert_int_equal(amxc_var_type_of(&src), AMXC_VAR_ID_SSV_STRING);
    assert_int_equal(amxc_var_convert(&var, &src, AMXC_VAR_ID_JSON), 0);
    assert_int_equal(amxc_var_type_of(&var), AMXC_VAR_ID_JSON);
    assert_string_equal(amxc_var_type_name_of(&var), AMXC_VAR_NAME_JSON);

    assert_ptr_not_equal(var.data.data, NULL);
    json_string = amxc_var_constcast(jstring_t, &var);
    assert_ptr_not_equal(json_string, NULL);
    assert_string_equal(json_string, "\"Hello world\"");

    amxc_var_clean(&var);
    amxc_var_clean(&src);
}

void test_variant_json_from_number(UNUSED void** state) {
    amxc_var_t var;
    amxc_var_t src;
    const char* json_string = NULL;

    amxc_var_init(&var);
    amxc_var_init(&src);

    amxc_var_set(uint64_t, &src, 1234);
    assert_int_equal(amxc_var_type_of(&src), AMXC_VAR_ID_UINT64);
    assert_int_equal(amxc_var_convert(&var, &src, AMXC_VAR_ID_JSON), 0);
    assert_int_equal(amxc_var_type_of(&var), AMXC_VAR_ID_JSON);
    assert_string_equal(amxc_var_type_name_of(&var), AMXC_VAR_NAME_JSON);

    assert_ptr_not_equal(var.data.data, NULL);
    json_string = amxc_var_constcast(jstring_t, &var);
    assert_ptr_not_equal(json_string, NULL);
    assert_string_equal(json_string, "1234");

    amxc_var_set(int64_t, &src, -4321);
    assert_int_equal(amxc_var_type_of(&src), AMXC_VAR_ID_INT64);
    assert_int_equal(amxc_var_convert(&var, &src, AMXC_VAR_ID_JSON), 0);
    assert_int_equal(amxc_var_type_of(&var), AMXC_VAR_ID_JSON);
    assert_string_equal(amxc_var_type_name_of(&var), AMXC_VAR_NAME_JSON);

    assert_ptr_not_equal(var.data.data, NULL);
    json_string = amxc_var_constcast(jstring_t, &var);
    assert_ptr_not_equal(json_string, NULL);
    assert_string_equal(json_string, "-4321");

    amxc_var_clean(&var);
    amxc_var_clean(&src);
}

void test_variant_json_from_bool(UNUSED void** state) {
    amxc_var_t var;
    amxc_var_t src;
    const char* json_string = NULL;

    amxc_var_init(&var);
    amxc_var_init(&src);

    amxc_var_set(bool, &src, true);
    assert_int_equal(amxc_var_type_of(&src), AMXC_VAR_ID_BOOL);
    assert_int_equal(amxc_var_convert(&var, &src, AMXC_VAR_ID_JSON), 0);
    assert_int_equal(amxc_var_type_of(&var), AMXC_VAR_ID_JSON);
    assert_string_equal(amxc_var_type_name_of(&var), AMXC_VAR_NAME_JSON);

    assert_ptr_not_equal(var.data.data, NULL);
    json_string = amxc_var_constcast(jstring_t, &var);
    assert_ptr_not_equal(json_string, NULL);
    assert_string_equal(json_string, "true");

    amxc_var_set(bool, &src, false);
    assert_int_equal(amxc_var_type_of(&src), AMXC_VAR_ID_BOOL);
    assert_int_equal(amxc_var_convert(&var, &src, AMXC_VAR_ID_JSON), 0);
    assert_int_equal(amxc_var_type_of(&var), AMXC_VAR_ID_JSON);
    assert_string_equal(amxc_var_type_name_of(&var), AMXC_VAR_NAME_JSON);

    assert_ptr_not_equal(var.data.data, NULL);
    json_string = amxc_var_constcast(jstring_t, &var);
    assert_ptr_not_equal(json_string, NULL);
    assert_string_equal(json_string, "false");

    amxc_var_clean(&var);
    amxc_var_clean(&src);
}

void test_variant_json_from_ts(UNUSED void** state) {
    amxc_var_t var;
    amxc_var_t src;
    const char* json_string = NULL;

    amxc_ts_t now;

    amxc_ts_now(&now);
    amxc_var_init(&var);
    amxc_var_init(&src);

    amxc_var_set(amxc_ts_t, &src, &now);
    assert_int_equal(amxc_var_type_of(&src), AMXC_VAR_ID_TIMESTAMP);
    assert_int_equal(amxc_var_convert(&var, &src, AMXC_VAR_ID_JSON), 0);
    assert_int_equal(amxc_var_type_of(&var), AMXC_VAR_ID_JSON);

    assert_ptr_not_equal(var.data.data, NULL);
    json_string = amxc_var_constcast(jstring_t, &var);
    assert_ptr_not_equal(json_string, NULL);

    amxc_var_clean(&var);
    amxc_var_clean(&src);
}

void test_variant_json_from_llist(UNUSED void** state) {
    amxc_var_t var;
    amxc_var_t helper;
    amxc_var_t src;
    const char* json_string = NULL;

    amxc_var_init(&var);
    amxc_var_init(&helper);
    amxc_var_init(&src);

    amxc_var_set(cstring_t, &helper, "Hello,world,and,anyone,else,in,the,universe");
    assert_int_equal(amxc_var_convert(&src, &helper, AMXC_VAR_ID_LIST), 0);
    assert_int_equal(amxc_var_type_of(&src), AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_llist_size(&src.data.vl), 8);

    assert_int_equal(amxc_var_convert(&var, &src, AMXC_VAR_ID_JSON), 0);
    assert_int_equal(amxc_var_type_of(&var), AMXC_VAR_ID_JSON);
    assert_string_equal(amxc_var_type_name_of(&var), AMXC_VAR_NAME_JSON);

    assert_ptr_not_equal(var.data.data, NULL);
    json_string = amxc_var_constcast(jstring_t, &var);
    assert_ptr_not_equal(json_string, NULL);
    assert_string_equal(json_string,
                        "[\"Hello\",\"world\",\"and\",\"anyone\",\"else\",\"in\",\"the\",\"universe\"]");

    amxc_var_clean(&var);
    amxc_var_clean(&helper);
    amxc_var_clean(&src);
}

void test_variant_json_from_htable(UNUSED void** state) {
    amxc_var_t var;
    amxc_var_t helper;
    amxc_var_t src;
    const char* json_string = NULL;

    amxc_var_init(&var);
    amxc_var_init(&helper);
    amxc_var_init(&src);

    amxc_var_set(cstring_t, &helper, "Key1:Hello,Key2:world,Key3:and,Key4:anyone,Key5:else,Key6:in,Key7:the,Key8:universe");
    assert_int_equal(amxc_var_convert(&src, &helper, AMXC_VAR_ID_HTABLE), 0);
    assert_int_equal(amxc_var_type_of(&src), AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_htable_size(&src.data.vm), 8);

    assert_int_equal(amxc_var_convert(&var, &src, AMXC_VAR_ID_JSON), 0);
    assert_int_equal(amxc_var_type_of(&var), AMXC_VAR_ID_JSON);
    assert_string_equal(amxc_var_type_name_of(&var), AMXC_VAR_NAME_JSON);

    assert_ptr_not_equal(var.data.data, NULL);
    json_string = amxc_var_constcast(jstring_t, &var);
    assert_ptr_not_equal(json_string, NULL);
    assert_string_equal(json_string,
                        "{\"Key1\":\"Hello\",\"Key2\":\"world\",\"Key3\":\"and\",\"Key4\":\"anyone\",\"Key5\":\"else\",\"Key6\":\"in\",\"Key7\":\"the\",\"Key8\":\"universe\"}");

    amxc_var_clean(&var);
    amxc_var_clean(&helper);
    amxc_var_clean(&src);
}

void test_variant_json_from_jstring(UNUSED void** state) {
    amxc_var_t var;
    amxc_var_t src;
    const char* json_string = NULL;

    amxc_var_init(&var);
    amxc_var_init(&src);

    amxc_var_set(jstring_t, &src, "{\"Key1\":\"Hello\",\"Key2\":\"world\",\"Key3\":\"and\",\"Key4\":\"anyone\",\"Key5\":\"else\",\"Key6\":\"in\",\"Key7\":\"the\",\"Key8\":\"universe\"}");
    assert_int_equal(amxc_var_convert(&var, &src, AMXC_VAR_ID_HTABLE), 0);
    assert_int_equal(amxc_var_type_of(&var), AMXC_VAR_ID_HTABLE);
    assert_int_equal(amxc_htable_size(&var.data.vm), 8);

    assert_int_equal(amxc_var_convert(&var, &src, AMXC_VAR_ID_JSON), 0);
    assert_int_equal(amxc_var_type_of(&var), AMXC_VAR_ID_JSON);
    assert_string_equal(amxc_var_type_name_of(&var), AMXC_VAR_NAME_JSON);

    assert_ptr_not_equal(var.data.data, NULL);
    json_string = amxc_var_constcast(jstring_t, &var);
    assert_ptr_not_equal(json_string, NULL);
    assert_string_equal(json_string,
                        "{\"Key1\":\"Hello\",\"Key2\":\"world\",\"Key3\":\"and\",\"Key4\":\"anyone\",\"Key5\":\"else\",\"Key6\":\"in\",\"Key7\":\"the\",\"Key8\":\"universe\"}");

    amxc_var_clean(&var);
    amxc_var_clean(&src);
}

void test_variant_json_set_get(UNUSED void** state) {
    amxc_var_t var;
    const char* json_string = NULL;

    amxc_var_init(&var);

    assert_int_not_equal(amxc_var_set(jstring_t, NULL, NULL), 0);
    assert_int_not_equal(amxc_var_set(jstring_t, &var, NULL), 0);

    assert_int_not_equal(amxc_var_set(jstring_t, &var, "Text"), 0);
    assert_int_equal(amxc_var_type_of(&var), AMXC_VAR_ID_NULL);
    assert_int_equal(amxc_var_set(jstring_t, &var, "\"Text\""), 0);
    assert_int_equal(amxc_var_type_of(&var), AMXC_VAR_ID_JSON);
    assert_string_equal(amxc_var_type_name_of(&var), AMXC_VAR_NAME_JSON);

    assert_ptr_not_equal(var.data.data, NULL);
    json_string = amxc_var_constcast(jstring_t, &var);
    assert_ptr_not_equal(json_string, NULL);
    assert_string_equal(json_string, "\"Text\"");

    assert_int_equal(amxc_var_set(jstring_t, &var,
                                  "{\"Key1\":\"Hello\",\"Key2\":\"world\",\"Key3\":\"and\",\"Key4\":\"anyone\",\"Key5\":\"else\",\"Key6\":\"in\",\"Key7\":\"the\",\"Key8\":\"universe\"}"), 0);
    assert_int_equal(amxc_var_type_of(&var), AMXC_VAR_ID_JSON);
    assert_string_equal(amxc_var_type_name_of(&var), AMXC_VAR_NAME_JSON);
    json_string = amxc_var_constcast(jstring_t, &var);
    assert_ptr_not_equal(json_string, NULL);
    assert_string_equal(json_string,
                        "{\"Key1\":\"Hello\",\"Key2\":\"world\",\"Key3\":\"and\",\"Key4\":\"anyone\",\"Key5\":\"else\",\"Key6\":\"in\",\"Key7\":\"the\",\"Key8\":\"universe\"}");

    json_string = amxc_var_constcast(jstring_t, NULL);
    assert_ptr_equal(json_string, NULL);

    amxc_var_clean(&var);
}

void test_variant_json_convert_to_htable(UNUSED void** state) {
    amxc_var_t var;
    amxc_var_t converted_var;
    const amxc_var_t* part;
    const char* string = NULL;
    const amxc_htable_t* submap = NULL;

    amxc_var_init(&var);
    amxc_var_init(&converted_var);

    assert_int_equal(amxc_var_set(jstring_t, &var,
                                  "{\"Key1\":\"Hello\",\"Key2\":\"world\",\"Key3\":\"and\",\"Key4\":\"anyone\",\"Key5\":\"else\",\"Key6\":\"in\",\"Key7\":\"the\",\"Key8\":\"universe\"}"), 0);
    assert_int_equal(amxc_var_convert(&converted_var, &var, AMXC_VAR_ID_HTABLE), 0);
    assert_int_equal(amxc_var_type_of(&converted_var), AMXC_VAR_ID_HTABLE);
    assert_string_equal(amxc_var_type_name_of(&converted_var), AMXC_VAR_NAME_HTABLE);
    assert_int_equal(amxc_htable_size(&converted_var.data.vm), 8);

    part = amxc_var_get_key(&converted_var, "Key5", AMXC_VAR_FLAG_DEFAULT);
    assert_ptr_not_equal(part, NULL);
    assert_int_equal(amxc_var_type_of(part), AMXC_VAR_ID_CSTRING);
    string = amxc_var_constcast(cstring_t, part);
    assert_string_equal(string, "else");


    assert_int_equal(amxc_var_set(jstring_t, &var,
                                  "{\"Number\":3,\"Bool\":true,\"Map\":{\"k1\":5,\"k2\":true,\"k3\":\"text2\", \"k4\":null},\"Array\":[true, 5, \"text1\", null],\"String\":\"text\"}"), 0);
    assert_int_equal(amxc_var_convert(&converted_var, &var, AMXC_VAR_ID_HTABLE), 0);
    assert_int_equal(amxc_var_type_of(&converted_var), AMXC_VAR_ID_HTABLE);
    assert_string_equal(amxc_var_type_name_of(&converted_var), AMXC_VAR_NAME_HTABLE);
    assert_int_equal(amxc_htable_size(&converted_var.data.vm), 5);

    part = amxc_var_get_key(&converted_var, "Number", AMXC_VAR_FLAG_DEFAULT);
    assert_ptr_not_equal(part, NULL);
    assert_int_equal(amxc_var_type_of(part), AMXC_VAR_ID_INT64);
    assert_int_equal(amxc_var_dyncast(uint64_t, part), 3);

    part = amxc_var_get_key(&converted_var, "Bool", AMXC_VAR_FLAG_DEFAULT);
    assert_ptr_not_equal(part, NULL);
    assert_int_equal(amxc_var_type_of(part), AMXC_VAR_ID_BOOL);
    assert_true(amxc_var_dyncast(bool, part));

    part = amxc_var_get_key(&converted_var, "Map", AMXC_VAR_FLAG_DEFAULT);
    assert_ptr_not_equal(part, NULL);
    assert_int_equal(amxc_var_type_of(part), AMXC_VAR_ID_HTABLE);
    submap = amxc_var_constcast(amxc_htable_t, part);
    assert_ptr_not_equal(submap, NULL);
    assert_int_equal(amxc_htable_size(submap), 4);

    part = amxc_var_get_key(&converted_var, "Array", AMXC_VAR_FLAG_DEFAULT);
    assert_ptr_not_equal(part, NULL);
    assert_int_equal(amxc_var_type_of(part), AMXC_VAR_ID_LIST);
    assert_ptr_not_equal(amxc_var_constcast(amxc_llist_t, part), NULL);
    assert_int_equal(amxc_llist_size(amxc_var_constcast(amxc_llist_t, part)), 4);

    amxc_var_clean(&var);
    amxc_var_clean(&converted_var);
}

void test_variant_json_convert_to_list(UNUSED void** state) {
    amxc_var_t var;
    amxc_var_t converted_var;
    const amxc_var_t* part;
    const char* string = NULL;
    const amxc_llist_t* sublist = NULL;

    amxc_var_init(&var);
    amxc_var_init(&converted_var);

    assert_int_equal(amxc_var_set(jstring_t, &var,
                                  "[\"Hello\",\"world\",\"and\",\"anyone\",\"else\",\"in\",\"the\",\"universe\"]"), 0);
    assert_int_equal(amxc_var_convert(&converted_var, &var, AMXC_VAR_ID_LIST), 0);
    assert_int_equal(amxc_var_type_of(&converted_var), AMXC_VAR_ID_LIST);
    assert_string_equal(amxc_var_type_name_of(&converted_var), AMXC_VAR_NAME_LIST);
    assert_int_equal(amxc_llist_size(&converted_var.data.vl), 8);

    part = amxc_var_get_index(&converted_var, 4, AMXC_VAR_FLAG_DEFAULT);
    assert_ptr_not_equal(part, NULL);
    assert_int_equal(amxc_var_type_of(part), AMXC_VAR_ID_CSTRING);
    string = amxc_var_constcast(cstring_t, part);
    assert_string_equal(string, "else");

    assert_int_equal(amxc_var_set(jstring_t, &var,
                                  "[3,true,{\"k1\":5,\"k2\":true,\"k3\":\"text2\"},[true, 5, \"text1\"],\"text\"]"), 0);
    assert_int_equal(amxc_var_convert(&converted_var, &var, AMXC_VAR_ID_LIST), 0);
    assert_int_equal(amxc_var_type_of(&converted_var), AMXC_VAR_ID_LIST);
    assert_string_equal(amxc_var_type_name_of(&converted_var), AMXC_VAR_NAME_LIST);
    assert_int_equal(amxc_llist_size(&converted_var.data.vl), 5);

    part = amxc_var_get_index(&converted_var, 0, AMXC_VAR_FLAG_DEFAULT);
    assert_ptr_not_equal(part, NULL);
    assert_int_equal(amxc_var_type_of(part), AMXC_VAR_ID_INT64);
    assert_int_equal(amxc_var_dyncast(uint64_t, part), 3);

    part = amxc_var_get_index(&converted_var, 1, AMXC_VAR_FLAG_DEFAULT);
    assert_ptr_not_equal(part, NULL);
    assert_int_equal(amxc_var_type_of(part), AMXC_VAR_ID_BOOL);
    assert_true(amxc_var_dyncast(bool, part));

    part = amxc_var_get_index(&converted_var, 2, AMXC_VAR_FLAG_DEFAULT);
    assert_ptr_not_equal(part, NULL);
    assert_int_equal(amxc_var_type_of(part), AMXC_VAR_ID_HTABLE);
    assert_ptr_not_equal(amxc_var_constcast(amxc_htable_t, part), NULL);
    assert_int_equal(amxc_htable_size(amxc_var_constcast(amxc_htable_t, part)), 3);

    part = amxc_var_get_index(&converted_var, 3, AMXC_VAR_FLAG_DEFAULT);
    assert_ptr_not_equal(part, NULL);
    assert_int_equal(amxc_var_type_of(part), AMXC_VAR_ID_LIST);
    sublist = amxc_var_constcast(amxc_llist_t, part);
    assert_ptr_not_equal(sublist, NULL);
    assert_int_equal(amxc_llist_size(sublist), 3);

    amxc_var_clean(&var);
    amxc_var_clean(&converted_var);
}

void test_variant_json_convert_to_null(UNUSED void** state) {
    amxc_var_t var;
    amxc_var_t converted_var;

    amxc_var_init(&var);
    amxc_var_init(&converted_var);

    assert_int_equal(amxc_var_set(jstring_t, &var, "null"), 0);
    assert_int_not_equal(amxc_var_convert(&converted_var, &var, AMXC_VAR_ID_LIST), 0);
    assert_int_equal(amxc_var_convert(&converted_var, &var, AMXC_VAR_ID_NULL), 0);
    assert_true(amxc_var_is_null(&converted_var));

    amxc_var_clean(&var);
    amxc_var_clean(&converted_var);
}

void test_variant_json_convert_to_bool(UNUSED void** state) {
    amxc_var_t var;
    amxc_var_t converted_var;

    amxc_var_init(&var);
    amxc_var_init(&converted_var);

    assert_int_equal(amxc_var_set(jstring_t, &var, "true"), 0);
    assert_int_not_equal(amxc_var_convert(&converted_var, &var, AMXC_VAR_ID_LIST), 0);
    assert_int_equal(amxc_var_convert(&converted_var, &var, AMXC_VAR_ID_BOOL), 0);
    assert_true(amxc_var_type_of(&converted_var) == AMXC_VAR_ID_BOOL);
    assert_true(amxc_var_constcast(bool, &converted_var));

    amxc_var_clean(&var);
    amxc_var_clean(&converted_var);
}

void test_variant_json_convert_to_number(UNUSED void** state) {
    amxc_var_t var;
    amxc_var_t converted_var;

    amxc_var_init(&var);
    amxc_var_init(&converted_var);

    assert_int_equal(amxc_var_set(jstring_t, &var, "4451"), 0);
    assert_int_not_equal(amxc_var_convert(&converted_var, &var, AMXC_VAR_ID_LIST), 0);
    assert_int_equal(amxc_var_convert(&converted_var, &var, AMXC_VAR_ID_INT64), 0);
    assert_true(amxc_var_type_of(&converted_var) == AMXC_VAR_ID_INT64);
    assert_int_equal(amxc_var_constcast(int64_t, &converted_var), 4451);

    amxc_var_clean(&var);
    amxc_var_clean(&converted_var);
}

void test_variant_json_convert_to_double(UNUSED void** state) {
    amxc_var_t var;
    amxc_var_t converted_var;

    amxc_var_init(&var);
    amxc_var_init(&converted_var);

    assert_int_equal(amxc_var_set(jstring_t, &var, "3.141595"), 0);
    assert_int_not_equal(amxc_var_convert(&converted_var, &var, AMXC_VAR_ID_LIST), 0);
    assert_int_equal(amxc_var_convert(&converted_var, &var, AMXC_VAR_ID_DOUBLE), 0);
    assert_true(amxc_var_type_of(&converted_var) == AMXC_VAR_ID_DOUBLE);
    assert_true(amxc_var_constcast(double, &converted_var) == 3.141595);

    amxc_var_clean(&var);
    amxc_var_clean(&converted_var);
}

void test_variant_json_convert_to_string(UNUSED void** state) {
    amxc_var_t var;
    amxc_var_t converted_var;

    amxc_var_init(&var);
    amxc_var_init(&converted_var);

    assert_int_equal(amxc_var_set(jstring_t, &var, "\"Hello world\""), 0);
    assert_int_equal(amxc_var_convert(&converted_var, &var, AMXC_VAR_ID_CSTRING), 0);
    assert_true(amxc_var_type_of(&converted_var) == AMXC_VAR_ID_CSTRING);
    assert_string_equal(amxc_var_constcast(cstring_t, &converted_var), "Hello world");

    assert_int_equal(amxc_var_set(jstring_t, &var, "[\"Hello\",\"world\",\"and\",\"anyone\",\"else\",\"in\",\"the\",\"universe\"]"), 0);
    assert_int_equal(amxc_var_convert(&converted_var, &var, AMXC_VAR_ID_CSTRING), 0);
    assert_true(amxc_var_type_of(&converted_var) == AMXC_VAR_ID_CSTRING);
    assert_string_equal(amxc_var_constcast(cstring_t, &converted_var), "[\"Hello\",\"world\",\"and\",\"anyone\",\"else\",\"in\",\"the\",\"universe\"]");

    amxc_var_clean(&var);
    amxc_var_clean(&converted_var);
}

void test_variant_json_convert_to_any(UNUSED void** state) {
    amxc_var_t var;
    amxc_var_t converted_var;

    amxc_var_init(&var);
    amxc_var_init(&converted_var);

    assert_int_equal(amxc_var_set(jstring_t, &var, "3.141595"), 0);
    assert_int_equal(amxc_var_convert(&converted_var, &var, AMXC_VAR_ID_ANY), 0);
    assert_true(amxc_var_type_of(&converted_var) == AMXC_VAR_ID_DOUBLE);
    assert_true(amxc_var_constcast(double, &converted_var) == 3.141595);

    assert_int_equal(amxc_var_set(jstring_t, &var, "{\"key\":[true,false,0,1,2]}"), 0);
    assert_int_equal(amxc_var_convert(&converted_var, &var, AMXC_VAR_ID_ANY), 0);
    assert_true(amxc_var_type_of(&converted_var) == AMXC_VAR_ID_HTABLE);

    amxc_var_clean(&var);
    amxc_var_clean(&converted_var);
}

void test_variant_json_convert_empty_string_to_any(UNUSED void** state) {
    amxc_var_t var;
    amxc_var_t converted_var;

    amxc_var_init(&var);
    amxc_var_init(&converted_var);

    assert_int_not_equal(amxc_var_set(jstring_t, &var, ""), 0);
    assert_int_equal(amxc_var_set(cstring_t, &var, ""), 0);
    assert_int_equal(amxc_var_cast(&var, AMXC_VAR_ID_JSON), 0);

    assert_int_equal(amxc_var_convert(&converted_var, &var, AMXC_VAR_ID_ANY), 0);
    assert_string_equal(GET_CHAR(&converted_var, NULL), "");
    assert_int_not_equal(amxc_var_convert(&converted_var, &var, AMXC_VAR_ID_UINT32), 0);

    assert_int_equal(amxc_var_set(jstring_t, &var, "\"\""), 0);

    amxc_var_clean(&var);
    amxc_var_clean(&converted_var);
}

void test_variant_json_cast(UNUSED void** state) {
    amxc_var_t var;

    amxc_var_init(&var);

    amxc_var_set_type(&var, AMXC_VAR_ID_HTABLE);
    assert_non_null(amxc_var_add_key(uint32_t, &var, "number", 5));

    assert_int_equal(amxc_var_cast(&var, AMXC_VAR_ID_JSON), 0);
    assert_int_equal(amxc_var_type_of(&var), AMXC_VAR_ID_JSON);

    amxc_var_clean(&var);
}

void test_variant_json_from_null_string(UNUSED void** state) {
    amxc_var_t var;
    amxc_var_t src;

    amxc_var_init(&var);
    amxc_var_init(&src);

    assert_int_equal(amxc_var_set_type(&src, AMXC_VAR_ID_CSTRING), 0);
    assert_null(src.data.s);
    assert_int_equal(amxc_var_convert(&var, &src, AMXC_VAR_ID_JSON), 0);
    assert_int_equal(amxc_var_type_of(&var), AMXC_VAR_ID_JSON);

    amxc_var_clean(&var);
    amxc_var_clean(&src);
}
