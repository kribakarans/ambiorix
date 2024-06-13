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

#include "test_amxj_writer.h"

#include <amxc/amxc_macros.h>
void test_amxj_writer_new_delete(UNUSED void** state) {
    variant_json_t* writer = NULL;
    amxc_var_t var;

    amxc_var_init(&var);

    assert_int_not_equal(amxj_writer_new(NULL, NULL), 0);
    assert_int_not_equal(amxj_writer_new(&writer, NULL), 0);
    assert_int_equal(amxj_writer_new(&writer, &var), 0);
    assert_ptr_not_equal(writer, NULL);

    amxj_writer_delete(&writer);
    assert_ptr_equal(writer, NULL);

    amxc_var_clean(&var);
}

void test_amxj_writer_write_null_variant(UNUSED void** state) {
    variant_json_t* writer = NULL;
    amxc_var_t var;
    int fd = open("test_writer.json", O_WRONLY | O_CREAT, 0644);

    amxc_var_init(&var);

    assert_int_equal(amxj_writer_new(&writer, &var), 0);
    assert_ptr_not_equal(writer, NULL);

    assert_int_not_equal(amxj_write(writer, fd), 0);

    amxj_writer_delete(&writer);
    assert_ptr_equal(writer, NULL);

    close(fd);
    amxc_var_clean(&var);
}

void test_amxj_writer_write_list_variant(UNUSED void** state) {
    variant_json_t* writer = NULL;
    amxc_var_t var;
    amxc_var_t var2;
    int fd = open("test_writer2.json", O_WRONLY | O_CREAT, 0644);

    amxc_var_init(&var);
    amxc_var_init(&var2);
    assert_int_equal(amxc_var_set(cstring_t, &var, "Hello,world,and,anyone,else,in,the,universe"), 0);
    assert_int_equal(amxc_var_convert(&var2, &var, AMXC_VAR_ID_LIST), 0);

    assert_int_equal(amxj_writer_new(&writer, &var2), 0);
    assert_ptr_not_equal(writer, NULL);

    assert_int_not_equal(amxj_write(writer, fd), 0);

    amxj_writer_delete(&writer);
    assert_ptr_equal(writer, NULL);

    close(fd);
    amxc_var_clean(&var);
    amxc_var_clean(&var2);
}

void test_amxj_writer_write_json_variant(UNUSED void** state) {
    variant_json_t* writer = NULL;
    amxc_var_t var;
    int fd = open("test_writer3.json", O_WRONLY | O_CREAT, 0644);

    amxc_var_init(&var);
    assert_int_equal(amxc_var_set(jstring_t, &var, "{\"Key1\":\"Hello\",\"Key2\":\"world\",\"Key3\":\"and\",\"Key4\":\"anyone\",\"Key5\":\"else\",\"Key6\":\"in\",\"Key7\":\"the\",\"Key8\":\"universe\"}"), 0);

    assert_int_equal(amxj_writer_new(&writer, &var), 0);
    assert_ptr_not_equal(writer, NULL);

    assert_int_not_equal(amxj_write(writer, fd), 0);

    amxj_writer_delete(&writer);
    assert_ptr_equal(writer, NULL);

    close(fd);
    amxc_var_clean(&var);
}
