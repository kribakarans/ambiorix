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

#include "test_amxj_reader.h"

#include <amxc/amxc_macros.h>
void test_amxj_reader_new_delete(UNUSED void** state) {
    variant_json_t* reader = NULL;

    assert_int_equal(amxj_reader_new(&reader), 0);
    assert_ptr_not_equal(reader, NULL);

    amxj_reader_delete(&reader);
    assert_ptr_equal(reader, NULL);
}

void test_amxj_reader(UNUSED void** state) {
    amxc_var_t* var = NULL;
    const amxc_var_t* part = NULL;
    variant_json_t* reader = NULL;
    int read_length = 0;
    int fd = open("test_valid.json", O_RDONLY);

    assert_int_not_equal(fd, -1);

    assert_int_equal(amxj_reader_new(&reader), 0);
    assert_ptr_not_equal(reader, NULL);

    read_length = amxj_read(reader, fd);
    while(read_length > 0) {
        read_length = amxj_read(reader, fd);
    }

    var = amxj_reader_result(reader);
    assert_ptr_not_equal(var, NULL);

    assert_int_equal(amxc_var_type_of(var), AMXC_VAR_ID_HTABLE);
    part = amxc_var_get_key(var, "name", AMXC_VAR_FLAG_DEFAULT);
    assert_int_equal(amxc_var_type_of(part), AMXC_VAR_ID_CSTRING);
    assert_string_equal(amxc_var_constcast(cstring_t, part), "John");
    part = amxc_var_get_key(var, "age", AMXC_VAR_FLAG_DEFAULT);
    assert_int_equal(amxc_var_type_of(part), AMXC_VAR_ID_INT64);
    assert_int_equal(amxc_var_constcast(int64_t, part), 30);
    part = amxc_var_get_key(var, "cars", AMXC_VAR_FLAG_DEFAULT);
    assert_int_equal(amxc_var_type_of(part), AMXC_VAR_ID_LIST);

    amxc_var_delete(&var);

    var = amxj_reader_result(reader);
    assert_ptr_equal(var, NULL);

    amxj_reader_delete(&reader);
    assert_ptr_equal(reader, NULL);

    close(fd);
    amxc_var_delete(&var);
}

void test_amxj_reader_invalid(UNUSED void** state) {
    amxc_var_t* var = NULL;
    variant_json_t* reader = NULL;
    int read_length = 0;
    int fd = open("test_invalid.json", O_RDONLY);

    assert_int_not_equal(fd, -1);

    assert_int_equal(amxj_reader_new(&reader), 0);
    assert_ptr_not_equal(reader, NULL);

    read_length = amxj_read(reader, fd);
    while(read_length > 0) {
        read_length = amxj_read(reader, fd);
    }

    assert_true(read_length < 0);

    var = amxj_reader_result(reader);
    assert_ptr_equal(var, NULL);

    amxj_reader_delete(&reader);
    assert_ptr_equal(reader, NULL);

    close(fd);
    amxc_var_delete(&var);
}

void test_amxj_reader_multiple(UNUSED void** state) {
    amxc_var_t* var = NULL;
    variant_json_t* reader = NULL;
    int read_length = 0;
    int fd = open("test_multiple.json", O_RDONLY);

    assert_int_not_equal(fd, -1);

    assert_int_equal(amxj_reader_new(&reader), 0);
    assert_ptr_not_equal(reader, NULL);

    read_length = amxj_read(reader, fd);
    while(read_length > 0) {
        read_length = amxj_read(reader, fd);
    }

    var = amxj_reader_result(reader);
    assert_ptr_not_equal(var, NULL);
    amxc_var_delete(&var);

    var = amxj_reader_result(reader);
    assert_ptr_not_equal(var, NULL);

    amxj_reader_delete(&reader);
    assert_ptr_equal(reader, NULL);

    close(fd);
    amxc_var_delete(&var);
}

