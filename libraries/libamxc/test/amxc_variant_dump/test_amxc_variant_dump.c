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
#include <stdarg.h>
#include <stddef.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <setjmp.h>
#include <cmocka.h>
#include <syslog.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <malloc.h>


#include <amxc/amxc_variant_type.h>

#include "test_amxc_variant_dump.h"

#include <amxc/amxc_macros.h>
static amxc_var_type_t my_dummy_type =
{
    .init = NULL,
    .del = NULL,
    .copy = NULL,
    .convert_from = NULL,
    .convert_to = NULL,
    .compare = NULL,
    .name = "my_dummy_type_t"
};

typedef struct {
    int fd;
    char* buffer;
} teststate_t;

/** @implements CMFixtureFunction */
int test_amxc_variant_dump_testsetup(void** state) {
    teststate_t* teststate = calloc(1, sizeof(teststate_t));
    assert_non_null(teststate);

    teststate->fd = shm_open("/test_amxc_variant_dump", O_CREAT | O_TRUNC | O_RDWR, S_IRUSR | S_IWUSR);
    assert_int_not_equal(teststate->fd, -1);
    assert_int_not_equal(-1, ftruncate(teststate->fd, 1024));
    teststate->buffer = mmap(NULL, 1024, PROT_READ | PROT_WRITE, MAP_SHARED, teststate->fd, 0);
    assert_non_null(teststate->buffer);

    *state = teststate;
    return 0;
}

/** @implements CMFixtureFunction */
int test_amxc_variant_dump_testteardown(void** state) {
    assert_non_null(state);
    shm_unlink("/test_amxc_variant_dump");
    free(*state);
    *state = NULL;
    return 0;
}

void test_amxc_variant_dump(UNUSED void** state) {
    amxc_var_t myvar;
    amxc_var_t* subvar = NULL;

    amxc_var_register_type(&my_dummy_type);
    int dummy_type_id = amxc_var_get_type_id_from_name(my_dummy_type.name);

    amxc_var_init(&myvar);
    amxc_var_set_type(&myvar, AMXC_VAR_ID_HTABLE);

    subvar = amxc_var_add_new_key(&myvar, "KEY1");
    amxc_var_set_type(subvar, AMXC_VAR_ID_LIST);
    amxc_var_add_new(subvar);
    amxc_var_add_new(subvar);
    subvar = amxc_var_add_new_key(&myvar, "KEY2");
    amxc_var_set_type(subvar, AMXC_VAR_ID_HTABLE);
    amxc_var_add_new_key(subvar, "Foo");
    amxc_var_add_new_key(subvar, "Bar");
    subvar = amxc_var_add_key(cstring_t, &myvar, "KEY3", "Hello world");
    subvar = amxc_var_add_key(uint64_t, &myvar, "KEY4", 666);
    subvar = amxc_var_add_key(fd_t, &myvar, "KEY5", STDOUT_FILENO);
    subvar = amxc_var_add_new_key(&myvar, "KEY6");
    amxc_var_set_type(subvar, dummy_type_id);

    amxc_var_dump(&myvar, STDOUT_FILENO);

    amxc_var_unregister_type(&my_dummy_type);

    amxc_var_clean(&myvar);
}

void test_amxc_variant_dump2(UNUSED void** state) {
    amxc_var_t myvar;
    amxc_var_t* subvar = NULL;
    FILE* fp = NULL;
    static char msgbuf[512];

    memset(msgbuf, 0, sizeof(msgbuf));
    fp = fmemopen(msgbuf, 512, "w");
    assert_non_null(fp);

    amxc_var_register_type(&my_dummy_type);
    int dummy_type_id = amxc_var_get_type_id_from_name(my_dummy_type.name);

    amxc_var_init(&myvar);
    amxc_var_set_type(&myvar, AMXC_VAR_ID_HTABLE);

    subvar = amxc_var_add_new_key(&myvar, "KEY1");
    amxc_var_set_type(subvar, AMXC_VAR_ID_LIST);
    amxc_var_add_new(subvar);
    amxc_var_add_new(subvar);
    subvar = amxc_var_add_new_key(&myvar, "KEY2");
    amxc_var_set_type(subvar, AMXC_VAR_ID_HTABLE);
    amxc_var_add_new_key(subvar, "Foo");
    amxc_var_add_new_key(subvar, "Bar");
    subvar = amxc_var_add_key(cstring_t, &myvar, "KEY3", "Hello world");
    subvar = amxc_var_add_key(uint64_t, &myvar, "KEY4", 666);
    subvar = amxc_var_add_key(fd_t, &myvar, "KEY5", STDOUT_FILENO);
    subvar = amxc_var_add_new_key(&myvar, "KEY6");
    amxc_var_set_type(subvar, dummy_type_id);

    amxc_var_dump_stream(&myvar, fp);
    fclose(fp);
    assert_non_null(strstr(msgbuf, "KEY1"));
    assert_non_null(strstr(msgbuf, "KEY2"));
    assert_non_null(strstr(msgbuf, "Foo"));
    assert_non_null(strstr(msgbuf, "Bar"));
    assert_non_null(strstr(msgbuf, "KEY3"));
    assert_non_null(strstr(msgbuf, "Hello world"));
    assert_non_null(strstr(msgbuf, "KEY4"));
    assert_non_null(strstr(msgbuf, "666"));
    assert_non_null(strstr(msgbuf, "KEY5"));
    assert_non_null(strstr(msgbuf, "KEY6"));
    assert_non_null(strstr(msgbuf, "my_dummy_type_t"));

    amxc_var_unregister_type(&my_dummy_type);

    amxc_var_clean(&myvar);
}

void test_amxc_variant_log(UNUSED void** state) {
    amxc_var_t myvar;
    amxc_var_t* subvar = NULL;

    openlog("test", LOG_PID | LOG_CONS, LOG_DAEMON);

    amxc_var_register_type(&my_dummy_type);
    int dummy_type_id = amxc_var_get_type_id_from_name(my_dummy_type.name);

    amxc_var_init(&myvar);
    amxc_var_set_type(&myvar, AMXC_VAR_ID_HTABLE);

    subvar = amxc_var_add_new_key(&myvar, "KEY1");
    amxc_var_set_type(subvar, AMXC_VAR_ID_LIST);
    amxc_var_add_new(subvar);
    amxc_var_add_new(subvar);
    subvar = amxc_var_add_new_key(&myvar, "KEY2");
    amxc_var_set_type(subvar, AMXC_VAR_ID_HTABLE);
    amxc_var_add_new_key(subvar, "Foo");
    amxc_var_add_new_key(subvar, "Bar");
    subvar = amxc_var_add_key(cstring_t, &myvar, "KEY3", "Hello world");
    subvar = amxc_var_add_key(uint64_t, &myvar, "KEY4", 666);
    subvar = amxc_var_add_key(fd_t, &myvar, "KEY5", STDOUT_FILENO);
    subvar = amxc_var_add_new_key(&myvar, "KEY6");
    amxc_var_set_type(subvar, dummy_type_id);

    amxc_var_log(&myvar);

    amxc_var_unregister_type(&my_dummy_type);

    amxc_var_clean(&myvar);
    closelog();
}

void test_amxc_variant_dump_null(UNUSED void** state) {
    amxc_var_dump(NULL, STDOUT_FILENO);
}

void test_amxc_variant_dump2_null(UNUSED void** state) {
    amxc_var_t myvar;
    amxc_var_t* subvar = NULL;
    FILE* fp = NULL;
    static char msgbuf[512];

    memset(msgbuf, 0, sizeof(msgbuf));
    fp = fmemopen(msgbuf, 512, "w");
    assert_non_null(fp);

    amxc_var_register_type(&my_dummy_type);
    int dummy_type_id = amxc_var_get_type_id_from_name(my_dummy_type.name);

    amxc_var_init(&myvar);
    amxc_var_set_type(&myvar, AMXC_VAR_ID_HTABLE);

    subvar = amxc_var_add_new_key(&myvar, "KEY1");
    amxc_var_set_type(subvar, AMXC_VAR_ID_LIST);
    amxc_var_add_new(subvar);
    amxc_var_add_new(subvar);
    subvar = amxc_var_add_new_key(&myvar, "KEY2");
    amxc_var_set_type(subvar, AMXC_VAR_ID_HTABLE);
    amxc_var_add_new_key(subvar, "Foo");
    amxc_var_add_new_key(subvar, "Bar");
    subvar = amxc_var_add_key(cstring_t, &myvar, "KEY3", "Hello world");
    subvar = amxc_var_add_key(uint64_t, &myvar, "KEY4", 666);
    subvar = amxc_var_add_key(fd_t, &myvar, "KEY5", STDOUT_FILENO);
    subvar = amxc_var_add_new_key(&myvar, "KEY6");
    amxc_var_set_type(subvar, dummy_type_id);

    amxc_var_dump_stream(NULL, NULL);
    amxc_var_dump_stream(&myvar, NULL);
    amxc_var_dump_stream(NULL, fp);
    fclose(fp);

    amxc_var_unregister_type(&my_dummy_type);

    amxc_var_clean(&myvar);
}

void test_amxc_variant_log_null(UNUSED void** state) {
    amxc_var_log(NULL);
}

void test_amxc_variant_dump_list_comma_position(void** state) {
    amxc_var_t myvar;
    teststate_t* teststate = *state;
    int status = -1;

    // GIVEN a variant containing a list
    amxc_var_init(&myvar);
    amxc_var_set_type(&myvar, AMXC_VAR_ID_LIST);
    amxc_var_add(cstring_t, &myvar, "text1");
    amxc_var_add(cstring_t, &myvar, "text2");
    amxc_var_add(int32_t, &myvar, 3);
    amxc_var_add(bool, &myvar, true);

    // WHEN serializing it
    status = amxc_var_dump(&myvar, teststate->fd);

    // THEN in the serialization output, commas are inbetween the elements
    //      and not after the last element
    assert_int_equal(0, status);
    assert_string_equal(teststate->buffer,
                        "[\n"
                        "    \"text1\",\n"
                        "    \"text2\",\n"
                        "    3,\n"
                        "    true\n"
                        "]\n");

    amxc_var_clean(&myvar);
}

void test_amxc_variant_dump_htable_comma_position(void** state) {
    amxc_var_t myvar;
    teststate_t* teststate = *state;
    int status = -1;

    // GIVEN a variant containing a hashtable
    amxc_var_init(&myvar);
    amxc_var_set_type(&myvar, AMXC_VAR_ID_HTABLE);
    amxc_var_add_key(cstring_t, &myvar, "key1", "text1");
    amxc_var_add_key(cstring_t, &myvar, "key2", "text2");
    amxc_var_add_key(int32_t, &myvar, "key3", 3);
    amxc_var_add_key(bool, &myvar, "key4", true);

    // WHEN serializing it
    status = amxc_var_dump(&myvar, teststate->fd);

    // THEN the element without trailing comma is the last in the in the serialization output
    //      (not the last in hashtable internal order).
    assert_int_equal(0, status);
    assert_string_equal(teststate->buffer,
                        "{\n"
                        "    key1 = \"text1\",\n"
                        "    key2 = \"text2\",\n"
                        "    key3 = 3,\n"
                        "    key4 = true\n"
                        "}\n");

    amxc_var_clean(&myvar);
}