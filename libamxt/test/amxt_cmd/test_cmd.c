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
#include <stdio.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <inttypes.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <cmocka.h>

#include <amxc/amxc.h>
#include <amxp/amxp.h>
#include <amxt/amxt_tty.h>
#include <amxt/amxt_cmd.h>

#include "test_cmd.h"

#include <amxc/amxc_macros.h>
static char input_data[128] = "";

ssize_t __wrap_read(UNUSED int fd, void* buf, size_t count);
ssize_t __wrap_write(UNUSED int fd, UNUSED void* buf, size_t count);
int __wrap_isatty(UNUSED int fd);
int __wrap_ttyname_r(int fd, char* buf, size_t buflen);
int __wrap_open(const char* path, int oflag, int mode);
int __real_open(const char* path, int oflag, int mode);

int __wrap_ttyname_r(UNUSED int fd, char* buf, size_t buflen) {
    strncpy(buf, "/tmp/test_tty", buflen);

    return 0;
}

int __wrap_open(const char* path, int oflag, int mode) {
    if(strcmp(path, "/tmp/test_tty") == 0) {
        return 0;
    }
    return __real_open(path, oflag, mode);
}

ssize_t __wrap_read(UNUSED int fd, void* buf, size_t count) {
    size_t length = strlen(input_data);
    ssize_t bytes = count < length ? count : length;
    memcpy(buf, input_data, bytes);
    return bytes;
}

ssize_t __wrap_write(UNUSED int fd, UNUSED void* buf, size_t count) {
    ssize_t bytes = count;
    return bytes;
}

int __wrap_isatty(UNUSED int fd) {
    return 1;
}

void test_can_parse_cmd_line(UNUSED void** state) {
    char* cmd = strdup("!addonn module cmd arg1 \"arg2a,ARG2b\" {param = 'text'}");
    amxc_var_t parts;
    uint32_t count = 0;
    char* txt = NULL;

    amxc_var_init(&parts);
    assert_int_equal(amxt_cmd_parse_line(cmd, strlen(cmd), &parts, NULL), 0);
    assert_int_equal(amxc_var_type_of(&parts), AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_llist_size(&parts.data.vl), 21);
    assert_int_equal(amxt_cmd_count_parts(&parts), 21);
    assert_false(amxt_cmd_is_empty(&parts));

    txt = amxt_cmd_pop_part(&parts);
    while(txt != NULL) {
        count++;
        free(txt);
        txt = amxt_cmd_pop_part(&parts);
    }
    free(txt);
    assert_int_equal(count, 21);
    assert_true(amxt_cmd_is_empty(&parts));
    free(cmd);

    cmd = strdup("!1 'text!text'");
    assert_int_equal(amxt_cmd_parse_line(cmd, strlen(cmd), &parts, NULL), 0);
    assert_int_equal(amxc_var_type_of(&parts), AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_llist_size(&parts.data.vl), 5);
    assert_int_equal(amxt_cmd_count_parts(&parts), 5);
    free(cmd);

    txt = amxt_cmd_pop_part(&parts);
    count = 0;
    while(txt != NULL) {
        count++;
        free(txt);
        txt = amxt_cmd_pop_part(&parts);
    }
    free(txt);
    assert_int_equal(count, 5);

    cmd = strdup("'!'hallo");
    assert_int_equal(amxt_cmd_parse_line(cmd, strlen(cmd), &parts, NULL), 0);
    assert_int_equal(amxc_var_type_of(&parts), AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_llist_size(&parts.data.vl), 4);
    assert_int_equal(amxt_cmd_count_parts(&parts), 4);
    amxc_var_clean(&parts);
    free(cmd);

    cmd = strdup("hallo!");
    assert_int_equal(amxt_cmd_parse_line(cmd, strlen(cmd), &parts, NULL), 0);
    assert_int_equal(amxc_var_type_of(&parts), AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_llist_size(&parts.data.vl), 2);
    amxc_var_clean(&parts);
    free(cmd);

    cmd = strdup("'hallo world'");
    assert_int_equal(amxt_cmd_parse_line(cmd, strlen(cmd), &parts, NULL), 0);
    assert_int_equal(amxc_var_type_of(&parts), AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_llist_size(&parts.data.vl), 3);
    amxc_var_clean(&parts);
    free(cmd);

    cmd = strdup("! test");
    assert_int_equal(amxt_cmd_parse_line(cmd, strlen(cmd), &parts, NULL), 0);
    assert_int_equal(amxc_var_type_of(&parts), AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_llist_size(&parts.data.vl), 2);
    amxc_var_clean(&parts);
    free(cmd);

    assert_null(amxt_cmd_pop_part(NULL));
    assert_int_equal(amxt_cmd_count_parts(NULL), 0);
    amxc_var_clean(&parts);
    amxc_var_set_type(&parts, AMXC_VAR_ID_LIST);
    assert_null(amxt_cmd_pop_part(&parts));
    assert_int_equal(amxt_cmd_count_parts(&parts), 0);
    amxc_var_clean(&parts);
    assert_null(amxt_cmd_pop_part(&parts));
    assert_int_equal(amxt_cmd_count_parts(&parts), 0);
}

void test_can_parse_cmd_line_embedded_strings(UNUSED void** state) {
    char* cmd = strdup("!addonn module cmd arg1 \"arg2a,ARG2b\" {param = \"'text' in list\"}");
    amxc_var_t parts;
    uint32_t count = 0;
    char* txt = NULL;

    amxc_var_init(&parts);
    assert_int_equal(amxt_cmd_parse_line(cmd, strlen(cmd), &parts, NULL), 0);
    assert_int_equal(amxc_var_type_of(&parts), AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_llist_size(&parts.data.vl), 21);
    assert_int_equal(amxt_cmd_count_parts(&parts), 21);
    assert_false(amxt_cmd_is_empty(&parts));

    txt = amxt_cmd_pop_part(&parts);
    count = 0;
    while(txt != NULL) {
        count++;
        free(txt);
        txt = amxt_cmd_pop_part(&parts);
        if(count == 18) {
            assert_string_equal(txt, "'text' in list");
        }
    }
    free(txt);

    free(cmd);
    amxc_var_clean(&parts);
}

void test_can_get_words(UNUSED void** state) {
    char* cmd = strdup("!addonn module cmd arg1 \"arg2a,ARG2b\" {param = 'text'}");
    amxc_var_t parts;
    uint32_t count = 0;
    char* txt = NULL;

    amxc_var_init(&parts);
    assert_int_equal(amxt_cmd_parse_line(cmd, strlen(cmd), &parts, NULL), 0);
    assert_int_equal(amxc_var_type_of(&parts), AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_llist_size(&parts.data.vl), 21);
    assert_false(amxt_cmd_is_empty(&parts));

    count = amxt_cmd_count_words(&parts);
    assert_int_equal(count, 6);
    assert_false(amxt_cmd_is_empty(&parts));

    txt = amxt_cmd_pop_word(&parts);
    count = 0;
    while(txt != NULL) {
        count++;
        free(txt);
        txt = amxt_cmd_pop_word(&parts);
    }
    free(txt);
    assert_true(amxt_cmd_is_empty(&parts));
    assert_int_equal(count, 6);

    assert_null(amxt_cmd_pop_word(NULL));
    assert_int_equal(amxt_cmd_count_words(NULL), 0);
    amxc_var_clean(&parts);
    assert_null(amxt_cmd_pop_word(&parts));
    assert_int_equal(amxt_cmd_count_words(&parts), 0);
    amxc_var_set_type(&parts, AMXC_VAR_ID_LIST);
    assert_int_equal(amxt_cmd_count_words(&parts), 0);
    amxc_var_clean(&parts);

    free(cmd);
}

void test_can_get_last_word(UNUSED void** state) {
    char* cmd = strdup("!addonn module cmd arg1 \"arg2a,ARG2b\" {param = 'text'}");
    amxc_var_t parts;
    char* txt = NULL;

    amxc_var_init(&parts);
    assert_int_equal(amxt_cmd_parse_line(cmd, strlen(cmd), &parts, NULL), 0);
    assert_int_equal(amxc_var_type_of(&parts), AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_llist_size(&parts.data.vl), 21);
    assert_false(amxt_cmd_is_empty(&parts));
    assert_int_equal(amxt_cmd_count_words(&parts), 6);

    assert_int_equal(amxt_cmd_last_word_size(&parts), 14);
    txt = amxt_cmd_take_last_word(&parts);
    assert_string_equal(txt, "{param = text}");
    free(txt);
    assert_int_equal(amxt_cmd_count_words(&parts), 5);

    assert_null(amxt_cmd_take_last_word(NULL));
    assert_int_equal(amxt_cmd_last_word_size(NULL), 0);
    amxc_var_clean(&parts);
    assert_null(amxt_cmd_take_last_word(&parts));
    assert_int_equal(amxt_cmd_last_word_size(&parts), 0);
    amxc_var_set_type(&parts, AMXC_VAR_ID_LIST);
    assert_int_equal(amxt_cmd_take_last_word(&parts), 0);
    assert_int_equal(amxt_cmd_last_word_size(&parts), 0);
    amxc_var_clean(&parts);

    free(cmd);
}

void test_can_get_words_until_separator(UNUSED void** state) {
    char* cmd = strdup("!addonn module cmd arg1 {param = 'text'}");
    amxc_var_t parts;
    char* txt = NULL;

    amxc_var_init(&parts);
    assert_int_equal(amxt_cmd_parse_line(cmd, strlen(cmd), &parts, NULL), 0);
    assert_int_equal(amxc_var_type_of(&parts), AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_llist_size(&parts.data.vl), 17);
    assert_false(amxt_cmd_is_empty(&parts));

    txt = amxt_cmd_pop_parts_until(&parts, "{");
    assert_string_equal(txt, "!addonn module cmd arg1");
    free(txt);

    amxc_var_clean(&parts);
    assert_int_equal(amxt_cmd_parse_line(cmd, strlen(cmd), &parts, NULL), 0);
    assert_int_equal(amxc_var_type_of(&parts), AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_llist_size(&parts.data.vl), 17);
    assert_false(amxt_cmd_is_empty(&parts));

    txt = amxt_cmd_pop_parts_until(&parts, NULL);
    assert_string_equal(txt, "!addonn module cmd arg1 {param = 'text'}");
    free(txt);

    assert_null(amxt_cmd_pop_parts_until(NULL, "{"));
    amxc_var_clean(&parts);
    assert_null(amxt_cmd_pop_parts_until(&parts, "{"));
    amxc_var_set_type(&parts, AMXC_VAR_ID_LIST);
    assert_null(amxt_cmd_pop_parts_until(&parts, "{"));
    amxc_var_clean(&parts);

    free(cmd);
}

void test_can_strip_leading_and_trailing_spaces(UNUSED void** state) {
    char* cmd = strdup("  a  b  ");
    amxc_var_t parts;

    amxc_var_init(&parts);
    assert_int_equal(amxt_cmd_parse_line(cmd, strlen(cmd), &parts, NULL), 0);
    assert_int_equal(amxc_var_type_of(&parts), AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_llist_size(&parts.data.vl), 4);
    assert_false(amxt_cmd_is_empty(&parts));

    amxt_cmd_trim(&parts, ' ');
    assert_int_equal(amxc_llist_size(&parts.data.vl), 3);
    assert_false(amxt_cmd_is_empty(&parts));

    amxt_cmd_trim(NULL, ' ');
    assert_true(amxt_cmd_is_empty(NULL));
    amxc_var_clean(&parts);
    amxt_cmd_trim(&parts, ' ');
    assert_true(amxt_cmd_is_empty(&parts));
    free(cmd);
}

void test_count_separators(UNUSED void** state) {
    char* cmd = strdup("a,b,[c,d],e,'f,g', [ a , b ]");
    amxc_var_t parts;

    amxc_var_init(&parts);
    assert_int_equal(amxt_cmd_parse_line(cmd, strlen(cmd), &parts, NULL), 0);
    assert_int_equal(amxc_var_type_of(&parts), AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_llist_size(&parts.data.vl), 26);
    assert_int_equal(amxt_cmd_count_separators(&parts, ','), 7);
    assert_int_equal(amxt_cmd_count_words(&parts), 2);

    amxc_var_clean(&parts);
    free(cmd);

    cmd = strdup("a b [c d] e 'f g' [ a  b ]");
    assert_int_equal(amxt_cmd_parse_line(cmd, strlen(cmd), &parts, NULL), 0);
    assert_int_equal(amxc_var_type_of(&parts), AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_llist_size(&parts.data.vl), 23);
    assert_int_equal(amxt_cmd_count_separators(&parts, ' '), 9);
    assert_int_equal(amxt_cmd_count_words(&parts), 6);

    assert_int_equal(amxt_cmd_count_separators(NULL, ' '), 0);
    amxc_var_clean(&parts);
    assert_int_equal(amxt_cmd_count_separators(&parts, ' '), 0);
    free(cmd);
}

void test_remove_until(UNUSED void** state) {
    char* cmd = strdup("a command { arg1, arg2 }");
    amxc_var_t parts;
    char* txt = NULL;

    amxc_var_init(&parts);
    assert_int_equal(amxt_cmd_parse_line(cmd, strlen(cmd), &parts, NULL), 0);
    assert_int_equal(amxc_var_type_of(&parts), AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_llist_size(&parts.data.vl), 12);
    assert_int_equal(amxt_cmd_count_words(&parts), 3);

    amxt_cmd_remove_until(&parts, "{");
    assert_int_equal(amxt_cmd_count_words(&parts), 3);
    txt = amxt_cmd_pop_word(&parts);
    assert_string_equal(txt, "arg1,");
    free(txt);
    txt = amxt_cmd_pop_word(&parts);
    assert_string_equal(txt, "arg2");
    free(txt);

    amxt_cmd_remove_until(NULL, "{");
    amxt_cmd_remove_until(&parts, NULL);
    amxc_var_clean(&parts);
    amxt_cmd_remove_until(&parts, "{");
    free(cmd);
}

void test_remove_last_part(UNUSED void** state) {
    char* cmd = strdup("a command { arg1, arg2 }");
    amxc_var_t parts;
    char* txt = NULL;

    amxc_var_init(&parts);
    assert_int_equal(amxt_cmd_parse_line(cmd, strlen(cmd), &parts, NULL), 0);
    assert_int_equal(amxc_var_type_of(&parts), AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_llist_size(&parts.data.vl), 12);
    assert_int_equal(amxt_cmd_count_words(&parts), 3);

    assert_int_equal(amxt_cmd_last_part_size(&parts), 1);
    txt = amxt_cmd_take_last_part(&parts);
    assert_int_equal(amxt_cmd_count_words(&parts), 3);
    assert_int_equal(amxc_llist_size(&parts.data.vl), 11);
    assert_string_equal(txt, "}");
    free(txt);

    assert_int_equal(amxt_cmd_last_part_size(&parts), 0);
    txt = amxt_cmd_take_last_part(&parts);
    assert_int_equal(amxt_cmd_count_words(&parts), 3);
    assert_int_equal(amxc_llist_size(&parts.data.vl), 10);
    assert_string_equal(txt, "");
    free(txt);

    assert_int_equal(amxt_cmd_last_part_size(&parts), 4);
    txt = amxt_cmd_take_last_part(&parts);
    assert_int_equal(amxt_cmd_count_words(&parts), 3);
    assert_int_equal(amxc_llist_size(&parts.data.vl), 9);
    assert_string_equal(txt, "arg2");
    free(txt);

    assert_int_equal(amxt_cmd_last_part_size(&parts), 0);
    txt = amxt_cmd_take_last_part(&parts);
    assert_int_equal(amxt_cmd_count_words(&parts), 3);
    assert_int_equal(amxc_llist_size(&parts.data.vl), 8);
    assert_string_equal(txt, "");
    free(txt);

    assert_int_equal(amxt_cmd_last_part_size(&parts), 1);
    txt = amxt_cmd_take_last_part(&parts);
    assert_int_equal(amxt_cmd_count_words(&parts), 3);
    assert_int_equal(amxc_llist_size(&parts.data.vl), 7);
    assert_string_equal(txt, ",");
    free(txt);

    assert_int_equal(amxt_cmd_last_part_size(&parts), 4);
    txt = amxt_cmd_take_last_part(&parts);
    assert_int_equal(amxt_cmd_count_words(&parts), 3);
    assert_int_equal(amxc_llist_size(&parts.data.vl), 6);
    assert_string_equal(txt, "arg1");
    free(txt);

    assert_null(amxt_cmd_take_last_part(NULL));
    assert_int_equal(amxt_cmd_last_part_size(NULL), 0);
    amxc_var_clean(&parts);
    assert_null(amxt_cmd_take_last_part(&parts));
    assert_int_equal(amxt_cmd_last_part_size(&parts), 0);

    free(cmd);
}

void test_can_complete_path(UNUSED void** state) {
    char* cmd = strdup("");
    amxc_var_t parts;
    amxc_var_t words;

    amxc_var_init(&parts);
    amxc_var_init(&words);
    amxc_var_set_type(&words, AMXC_VAR_ID_LIST);

    assert_int_equal(amxt_cmd_parse_line(cmd, strlen(cmd), &parts, NULL), 0);
    amxt_cmd_complete_path("", &parts, &words);
    assert_int_equal(amxc_var_type_of(&words), AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_llist_size(&words.data.vl), 6);
    amxc_var_clean(&parts);
    amxc_var_clean(&words);
    amxc_var_set_type(&words, AMXC_VAR_ID_LIST);
    free(cmd);

    cmd = strdup("./testd");
    assert_int_equal(amxt_cmd_parse_line(cmd, strlen(cmd), &parts, NULL), 0);
    amxt_cmd_complete_path("", &parts, &words);
    assert_int_equal(amxc_var_type_of(&words), AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_llist_size(&words.data.vl), 1);
    amxc_var_clean(&parts);
    amxc_var_clean(&words);
    amxc_var_set_type(&words, AMXC_VAR_ID_LIST);
    free(cmd);

    cmd = strdup("./testdata/");
    assert_int_equal(amxt_cmd_parse_line(cmd, strlen(cmd), &parts, NULL), 0);
    amxt_cmd_complete_path("", &parts, &words);
    assert_int_equal(amxc_var_type_of(&words), AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_llist_size(&words.data.vl), 2);
    amxc_var_clean(&parts);
    amxc_var_clean(&words);
    amxc_var_set_type(&words, AMXC_VAR_ID_LIST);
    free(cmd);

    cmd = strdup("hello test ./testdata/");
    assert_int_equal(amxt_cmd_parse_line(cmd, strlen(cmd), &parts, NULL), 0);
    amxt_cmd_complete_path("", &parts, &words);
    assert_int_equal(amxc_var_type_of(&words), AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_llist_size(&words.data.vl), 2);
    amxc_var_clean(&parts);
    amxc_var_clean(&words);
    amxc_var_set_type(&words, AMXC_VAR_ID_LIST);
    free(cmd);

    cmd = strdup("hello test ./notexisting/");
    assert_int_equal(amxt_cmd_parse_line(cmd, strlen(cmd), &parts, NULL), 0);
    amxt_cmd_complete_path("", &parts, &words);
    assert_int_equal(amxc_var_type_of(&words), AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_llist_size(&words.data.vl), 0);
    amxc_var_clean(&parts);
    amxc_var_clean(&words);
    amxc_var_set_type(&words, AMXC_VAR_ID_LIST);
    free(cmd);

    amxt_cmd_complete_path("", NULL, &words);
    amxc_var_set_type(&parts, AMXC_VAR_ID_LIST);
    amxt_cmd_complete_path("", &parts, NULL);
    amxt_cmd_complete_path("", &parts, &words);
    amxc_var_clean(&words);
    amxt_cmd_complete_path("", &parts, &words);
    amxc_var_clean(&parts);
    amxt_cmd_complete_path("", &parts, &words);
}

void test_can_add_parts(UNUSED void** state) {
    char* cmd = strdup(" module ");
    amxc_var_t parts;

    amxc_var_init(&parts);
    assert_int_equal(amxt_cmd_parse_line(cmd, strlen(cmd), &parts, NULL), 0);
    assert_int_equal(amxc_var_type_of(&parts), AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_llist_size(&parts.data.vl), 2);
    assert_int_equal(amxt_cmd_count_parts(&parts), 2);
    assert_false(amxt_cmd_is_empty(&parts));

    assert_int_equal(amxt_cmd_append_part(&parts, "load"), 0);
    assert_int_equal(amxt_cmd_prepend_part(&parts, "!addon"), 0);
    assert_int_equal(amxt_cmd_count_parts(&parts), 4);

    free(cmd);
    amxc_var_clean(&parts);
}

void test_can_parse_short_options(UNUSED void** state) {
    char* cmd = strdup("-io -p=232 -t Other data");
    amxc_var_t parts;
    amxc_var_t options;
    char* txt = NULL;

    amxc_var_init(&parts);
    amxc_var_init(&options);
    assert_int_equal(amxt_cmd_parse_line(cmd, strlen(cmd), &parts, NULL), 0);
    assert_int_equal(amxc_var_type_of(&parts), AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_llist_size(&parts.data.vl), 14);
    assert_int_equal(amxt_cmd_count_words(&parts), 5);

    assert_int_equal(amxt_cmd_get_options(&parts, &options, NULL), 0);

    assert_non_null(GET_ARG(&options, "i"));
    assert_non_null(GET_ARG(&options, "o"));
    assert_non_null(GET_ARG(&options, "t"));
    assert_non_null(GET_ARG(&options, "p"));
    assert_int_equal(GET_UINT32(&options, "p"), 232);
    assert_true(GET_BOOL(&options, "i"));
    assert_true(GET_BOOL(&options, "o"));
    assert_true(GET_BOOL(&options, "t"));

    assert_int_equal(amxc_llist_size(&parts.data.vl), 3);
    assert_int_equal(amxt_cmd_count_words(&parts), 2);

    txt = amxt_cmd_pop_word(&parts);
    assert_string_equal(txt, "Other");
    free(txt);

    free(cmd);
    amxc_var_clean(&parts);
    amxc_var_clean(&options);
}

void test_short_options_with_value_fails_when_combined(UNUSED void** state) {
    char* cmd = strdup("-iop=232 Other data");
    amxc_var_t parts;
    amxc_var_t options;
    char* txt = NULL;

    amxc_var_init(&parts);
    amxc_var_init(&options);
    assert_int_equal(amxt_cmd_parse_line(cmd, strlen(cmd), &parts, NULL), 0);
    assert_int_not_equal(amxt_cmd_get_options(&parts, &options, NULL), 0);

    txt = amxt_cmd_pop_word(&parts);
    assert_string_equal(txt, "-iop=232");
    free(txt);

    free(cmd);
    amxc_var_clean(&parts);
    amxc_var_clean(&options);
}

void test_can_parse_long_options(UNUSED void** state) {
    char* cmd = strdup("--all --text='hallo world' Other data");
    amxc_var_t parts;
    amxc_var_t options;
    char* txt = NULL;

    amxc_var_init(&parts);
    amxc_var_init(&options);

    assert_int_equal(amxt_cmd_parse_line(cmd, strlen(cmd), &parts, NULL), 0);
    assert_int_equal(amxc_var_type_of(&parts), AMXC_VAR_ID_LIST);
    assert_int_equal(amxc_llist_size(&parts.data.vl), 15);
    assert_int_equal(amxt_cmd_count_words(&parts), 4);

    assert_int_equal(amxt_cmd_get_options(&parts, &options, NULL), 0);

    assert_non_null(GET_ARG(&options, "all"));
    assert_non_null(GET_ARG(&options, "text"));

    assert_int_equal(amxc_llist_size(&parts.data.vl), 3);
    assert_int_equal(amxt_cmd_count_words(&parts), 2);

    txt = amxt_cmd_pop_word(&parts);
    assert_string_equal(txt, "Other");
    free(txt);

    free(cmd);
    amxc_var_clean(&parts);
    amxc_var_clean(&options);
}

void test_can_pass_valid_options(UNUSED void** state) {
    char* cmd = strdup("-pf --parameters=true --functions=true Other data");
    const char* valid[] = { "p", "parameters", "f", "functions", NULL };
    amxc_var_t parts;
    amxc_var_t options;
    char* txt = NULL;

    amxc_var_init(&parts);
    amxc_var_init(&options);
    assert_int_equal(amxt_cmd_parse_line(cmd, strlen(cmd), &parts, NULL), 0);
    assert_int_equal(amxt_cmd_get_options(&parts, &options, valid), 0);

    assert_int_equal(amxc_llist_size(&parts.data.vl), 3);
    assert_int_equal(amxt_cmd_count_words(&parts), 2);

    txt = amxt_cmd_pop_word(&parts);
    assert_string_equal(txt, "Other");
    free(txt);
    free(cmd);
    amxc_var_clean(&parts);
    amxc_var_clean(&options);

    cmd = strdup("-p -o -f --functions=true Other data");
    assert_int_equal(amxt_cmd_parse_line(cmd, strlen(cmd), &parts, NULL), 0);
    assert_int_not_equal(amxt_cmd_get_options(&parts, &options, valid), 0);
    txt = amxt_cmd_pop_word(&parts);
    assert_string_equal(txt, "-o");
    free(txt);
    free(cmd);
    amxc_var_clean(&parts);
    amxc_var_clean(&options);

    cmd = strdup("-p -o=111 -f --functions=true Other data");
    assert_int_equal(amxt_cmd_parse_line(cmd, strlen(cmd), &parts, NULL), 0);
    assert_int_not_equal(amxt_cmd_get_options(&parts, &options, valid), 0);
    txt = amxt_cmd_pop_word(&parts);
    assert_string_equal(txt, "-o=111");
    free(txt);
    free(cmd);
    amxc_var_clean(&parts);
    amxc_var_clean(&options);

    cmd = strdup("--functions --instances -p Other data");
    assert_int_equal(amxt_cmd_parse_line(cmd, strlen(cmd), &parts, NULL), 0);
    assert_int_not_equal(amxt_cmd_get_options(&parts, &options, valid), 0);
    txt = amxt_cmd_pop_word(&parts);
    assert_string_equal(txt, "--instances");
    free(txt);
    free(cmd);
    amxc_var_clean(&parts);
    amxc_var_clean(&options);

    cmd = strdup("--functions --instances=enabled -p Other data");
    assert_int_equal(amxt_cmd_parse_line(cmd, strlen(cmd), &parts, NULL), 0);
    assert_int_not_equal(amxt_cmd_get_options(&parts, &options, valid), 0);
    txt = amxt_cmd_pop_word(&parts);
    assert_string_equal(txt, "--instances=enabled");
    free(txt);
    free(cmd);
    amxc_var_clean(&parts);
    amxc_var_clean(&options);
}

void test_last_options_is_taken(UNUSED void** state) {
    char* cmd = strdup("-pf --functions=true");
    const char* valid[] = { "p", "parameters", "f", "functions", NULL };
    amxc_var_t parts;
    amxc_var_t options;

    amxc_var_init(&parts);
    amxc_var_init(&options);
    assert_int_equal(amxt_cmd_parse_line(cmd, strlen(cmd), &parts, NULL), 0);
    assert_int_equal(amxt_cmd_get_options(&parts, &options, valid), 0);

    assert_int_equal(amxc_llist_size(&parts.data.vl), 0);
    assert_int_equal(amxt_cmd_count_words(&parts), 0);

    assert_non_null(GET_ARG(&options, "functions"));

    free(cmd);
    amxc_var_clean(&parts);
    amxc_var_clean(&options);
}

void test_get_option_fails_with_invalid_input(UNUSED void** state) {
    char* cmd = strdup("-pf --functions=true");
    const char* valid[] = { "p", "parameters", "f", "functions", NULL };
    amxc_var_t parts;
    amxc_var_t options;

    amxc_var_init(&parts);
    amxc_var_init(&options);
    assert_int_equal(amxt_cmd_parse_line(cmd, strlen(cmd), &parts, NULL), 0);
    assert_int_not_equal(amxt_cmd_get_options(NULL, &options, valid), 0);
    assert_int_not_equal(amxt_cmd_get_options(&parts, NULL, valid), 0);
    assert_int_equal(amxt_cmd_get_options(&parts, &options, NULL), 0);

    assert_int_equal(amxc_llist_size(&parts.data.vl), 0);
    assert_int_equal(amxt_cmd_count_words(&parts), 0);

    assert_non_null(GET_ARG(&options, "functions"));
    assert_non_null(GET_ARG(&options, "f"));
    assert_non_null(GET_ARG(&options, "p"));

    free(cmd);
    amxc_var_clean(&parts);
    amxc_var_clean(&options);
}

void test_parse_option_print_errors(UNUSED void** state) {
    amxt_tty_t* tty = NULL;
    char* cmd1 = strdup("-f --parameters=true");
    char* cmd2 = strdup("--functions=true");
    const char* valid[] = { "f", "functions", NULL };
    amxc_var_t parts;
    amxc_var_t options;

    amxc_var_init(&parts);
    amxc_var_init(&options);

    assert_int_equal(amxt_tty_open(&tty, fileno(stdin)), 0);

    assert_int_equal(amxt_cmd_parse_line(cmd1, strlen(cmd1), &parts, NULL), 0);
    assert_int_not_equal(amxt_cmd_parse_options(tty, &parts, &options, valid), 0);
    amxc_var_clean(&parts);
    amxc_var_clean(&options);

    assert_int_equal(amxt_cmd_parse_line(cmd1, strlen(cmd1), &parts, NULL), 0);
    assert_int_equal(amxt_cmd_parse_options(tty, &parts, &options, NULL), 0);
    amxc_var_clean(&parts);
    amxc_var_clean(&options);

    assert_int_equal(amxt_cmd_parse_line(cmd1, strlen(cmd1), &parts, NULL), 0);
    assert_int_not_equal(amxt_cmd_parse_options(NULL, &parts, &options, valid), 0);
    amxc_var_clean(&parts);
    amxc_var_clean(&options);

    assert_int_equal(amxt_cmd_parse_line(cmd2, strlen(cmd2), &parts, NULL), 0);
    assert_int_equal(amxt_cmd_parse_options(tty, &parts, &options, valid), 0);
    amxc_var_clean(&parts);
    amxc_var_clean(&options);

    assert_int_not_equal(amxt_cmd_parse_options(NULL, &parts, &options, valid), 0);
    assert_int_not_equal(amxt_cmd_parse_options(tty, NULL, &options, valid), 0);
    assert_int_not_equal(amxt_cmd_parse_options(tty, &parts, NULL, valid), 0);

    free(cmd1);
    free(cmd2);

    amxt_tty_close(&tty);
}

void test_print_help(UNUSED void** state) {
    amxt_tty_t* tty = NULL;
    amxt_cmd_help_t help[] = {
        {
            .cmd = "show",
            .usage = "show",
            .brief = "Shows command history.",
            .desc = "Print all commands in the commad history.\n"
                "Most recent first, the oldest last\n",
            .options = NULL
        },
        {
            .cmd = "clear",
            .usage = "clear",
            .brief = "clear command history.",
            .desc = "If the command history was saved to a file it can be restored with "
                "'!history load <FILE>'",
            .options = NULL
        },
        {
            .cmd = "save",
            .usage = "save <FILE>",
            .brief = "Saves command history to a file.",
            .desc = "Use '!history load <FILE>' to restore the command history at any point.",
            .options = NULL
        },
        {
            .cmd = "load",
            .usage = "load <FILE>",
            .brief = "Loads command history from a file.",
            .desc = "This will overwrite the current command history.",
            .options = NULL
        },
        { NULL, NULL, NULL, NULL, NULL },
    };

    assert_int_equal(amxt_tty_open(&tty, fileno(stdin)), 0);

    amxt_cmd_print_help(tty, help, "show");
    amxt_cmd_print_help(tty, help, NULL);
    amxt_cmd_print_help(tty, NULL, "show");
    amxt_cmd_print_help(NULL, help, "show");

    amxt_tty_close(&tty);
}

void test_get_index(UNUSED void** state) {
    amxt_cmd_help_t help[] = {
        {
            .cmd = "show",
            .usage = "show",
            .brief = "Shows command history.",
            .desc = "Print all commands in the commad history.\n"
                "Most recent first, the oldest last\n",
            .options = NULL
        },
        {
            .cmd = "clear",
            .usage = "clear",
            .brief = "clear command history.",
            .desc = "If the command history was saved to a file it can be restored with "
                "'!history load <FILE>'",
            .options = NULL
        },
        {
            .cmd = "save",
            .usage = "save <FILE>",
            .brief = "Saves command history to a file.",
            .desc = "Use '!history load <FILE>' to restore the command history at any point.",
            .options = NULL
        },
        {
            .cmd = "load",
            .usage = "load <FILE>",
            .brief = "Loads command history from a file.",
            .desc = "This will overwrite the current command history.",
            .options = NULL
        },
        { NULL, NULL, NULL, NULL, NULL },
    };

    assert_int_equal(amxt_cmd_index("show", help), 0);
    assert_int_equal(amxt_cmd_index("dummy", help), -1);
    assert_int_equal(amxt_cmd_index(NULL, help), -1);
    assert_int_equal(amxt_cmd_index("show", NULL), -1);
    assert_int_equal(amxt_cmd_index("load", help), 3);
}

void test_can_complete_help(UNUSED void** state) {
    amxt_tty_t* tty = NULL;
    char* cmd = strdup("show");
    amxt_cmd_help_t help[] = {
        {
            .cmd = "show",
            .usage = "show",
            .brief = "Shows command history.",
            .desc = "Print all commands in the commad history.\n"
                "Most recent first, the oldest last\n",
            .options = NULL
        },
        {
            .cmd = "clear",
            .usage = "clear",
            .brief = "clear command history.",
            .desc = "If the command history was saved to a file it can be restored with "
                "'!history load <FILE>'",
            .options = NULL
        },
        {
            .cmd = "save",
            .usage = "save <FILE>",
            .brief = "Saves command history to a file.",
            .desc = "Use '!history load <FILE>' to restore the command history at any point.",
            .options = NULL
        },
        {
            .cmd = "load",
            .usage = "load <FILE>",
            .brief = "Loads command history from a file.",
            .desc = "This will overwrite the current command history.",
            .options = NULL
        },
        { NULL, NULL, NULL, NULL, NULL },
    };
    amxc_var_t parts;
    amxc_var_t completed;

    amxc_var_init(&parts);
    amxc_var_init(&completed);
    amxc_var_set_type(&completed, AMXC_VAR_ID_LIST);

    assert_int_equal(amxt_tty_open(&tty, fileno(stdin)), 0);

    assert_int_equal(amxt_cmd_parse_line(cmd, strlen(cmd), &parts, NULL), 0);
    amxt_cmd_complete_help(&parts, help, &completed);
    amxt_cmd_complete_help(NULL, help, &completed);
    amxt_cmd_complete_help(&parts, NULL, &completed);
    amxt_cmd_complete_help(&parts, help, NULL);

    free(cmd);
    amxc_var_clean(&completed);
    amxc_var_clean(&parts);
    amxt_tty_close(&tty);
}

void test_can_complete_options(UNUSED void** state) {
    amxt_tty_t* tty = NULL;
    char* cmd1 = strdup("--parameters=true --funct");
    char* cmd2 = strdup("--parameters=true --test-opt");
    const char* options[] = { "p", "parameters", "f", "functions", "test-option", NULL };
    amxc_var_t parts;
    amxc_var_t completed;

    amxc_var_init(&parts);
    amxc_var_init(&completed);
    amxc_var_set_type(&completed, AMXC_VAR_ID_LIST);

    assert_int_equal(amxt_tty_open(&tty, fileno(stdin)), 0);

    assert_int_equal(amxt_cmd_parse_line(cmd1, strlen(cmd1), &parts, NULL), 0);
    assert_int_equal(amxt_cmd_complete_option(&parts, options, &completed), 2);
    assert_int_equal(amxc_var_type_of(&completed), AMXC_VAR_ID_LIST);
    assert_int_equal(amxt_cmd_complete_option(NULL, options, &completed), 0);
    assert_int_equal(amxt_cmd_complete_option(&parts, NULL, &completed), 0);
    assert_int_equal(amxt_cmd_complete_option(&parts, options, NULL), 0);
    free(cmd1);
    amxc_var_clean(&completed);
    amxc_var_clean(&parts);

    amxc_var_set_type(&completed, AMXC_VAR_ID_LIST);
    assert_int_equal(amxt_cmd_parse_line(cmd2, strlen(cmd2), &parts, NULL), 0);
    assert_int_equal(amxt_cmd_complete_option(&parts, options, &completed), 2);
    assert_int_equal(amxc_var_type_of(&completed), AMXC_VAR_ID_LIST);
    assert_int_equal(amxt_cmd_complete_option(NULL, options, &completed), 0);
    assert_int_equal(amxt_cmd_complete_option(&parts, NULL, &completed), 0);
    assert_int_equal(amxt_cmd_complete_option(&parts, options, NULL), 0);
    free(cmd2);
    amxc_var_clean(&completed);
    amxc_var_clean(&parts);

    amxt_tty_close(&tty);
}

void test_complete_invalid_option(UNUSED void** state) {
    amxt_tty_t* tty = NULL;
    char* cmd = strdup("--parameters=true ---funct");
    const char* options[] = { "parameters", "functions", NULL };
    amxc_var_t parts;
    amxc_var_t completed;

    amxc_var_init(&parts);
    amxc_var_init(&completed);
    amxc_var_set_type(&completed, AMXC_VAR_ID_LIST);

    assert_int_equal(amxt_tty_open(&tty, fileno(stdin)), 0);

    assert_int_equal(amxt_cmd_parse_line(cmd, strlen(cmd), &parts, NULL), 0);
    assert_int_equal(amxt_cmd_complete_option(&parts, options, &completed), 3);

    free(cmd);
    amxc_var_clean(&completed);
    amxc_var_clean(&parts);
    amxt_tty_close(&tty);
}

void test_can_complete_option_value(UNUSED void** state) {
    amxt_tty_t* tty = NULL;
    char* cmd = strdup("--parameters=");
    const char* options[] = { "parameters", "functions", NULL };
    amxc_var_t parts;
    amxc_var_t completed;

    amxc_var_init(&parts);
    amxc_var_init(&completed);
    amxc_var_set_type(&completed, AMXC_VAR_ID_LIST);

    assert_int_equal(amxt_tty_open(&tty, fileno(stdin)), 0);

    assert_int_equal(amxt_cmd_parse_line(cmd, strlen(cmd), &parts, NULL), 0);
    assert_int_equal(amxt_cmd_complete_option(&parts, options, &completed), 4);
    assert_int_equal(amxc_var_type_of(&completed), AMXC_VAR_ID_LIST);

    free(cmd);
    amxc_var_clean(&completed);
    amxc_var_clean(&parts);
    amxt_tty_close(&tty);
}

void test_print_excess_args(UNUSED void** state) {
    amxt_tty_t* tty = NULL;
    char* cmd = strdup("-pf --functions=true");
    amxc_var_t parts;

    amxc_var_init(&parts);

    assert_int_equal(amxt_tty_open(&tty, fileno(stdin)), 0);

    assert_int_equal(amxt_cmd_parse_line(cmd, strlen(cmd), &parts, NULL), 0);
    amxt_cmd_error_excess(tty, &parts, NULL);
    amxt_cmd_error_excess(tty, &parts, "TEST");
    amxt_cmd_error_excess(NULL, &parts, "TEST");
    amxt_cmd_error_excess(tty, NULL, "TEST");

    free(cmd);
    amxc_var_clean(&parts);
    amxt_tty_close(&tty);
}

void test_can_parse_simple_table(UNUSED void** state) {
    amxt_tty_t* tty = NULL;
    char* cmd = strdup("{Param1 = 123, Param2 = true, Param3 = -123, Param4 = \"ABC\" }");
    amxc_var_t values;
    amxc_var_t parts;

    amxc_var_init(&parts);
    amxc_var_init(&values);

    assert_int_equal(amxt_tty_open(&tty, fileno(stdin)), 0);

    assert_int_equal(amxt_cmd_parse_line(cmd, strlen(cmd), &parts, NULL), 0);
    assert_int_equal(amxt_cmd_parse_values(tty, &parts, AMXT_VP_TABLE, &values), 0);

    assert_non_null(GET_ARG(&values, "Param1"));
    assert_non_null(GET_ARG(&values, "Param2"));
    assert_non_null(GET_ARG(&values, "Param3"));

    amxc_var_clean(&values);
    amxc_var_clean(&parts);
    free(cmd);
    amxt_tty_close(&tty);
}

void test_can_parse_simple_array(UNUSED void** state) {
    amxt_tty_t* tty = NULL;
    char* cmd = strdup("[123, true, -123, \"ABC\" ]");
    amxc_var_t values;
    amxc_var_t parts;

    amxc_var_init(&parts);
    amxc_var_init(&values);

    assert_int_equal(amxt_tty_open(&tty, fileno(stdin)), 0);

    assert_int_equal(amxt_cmd_parse_line(cmd, strlen(cmd), &parts, NULL), 0);
    assert_int_equal(amxt_cmd_parse_values(tty, &parts, AMXT_VP_ARRAY, &values), 0);

    assert_non_null(GETI_ARG(&values, 0));
    assert_non_null(GETI_ARG(&values, 1));
    assert_non_null(GETI_ARG(&values, 2));

    amxc_var_clean(&values);
    amxc_var_clean(&parts);
    free(cmd);
    amxt_tty_close(&tty);
}

void test_can_parse_values_with_embedded_string(UNUSED void** state) {
    amxt_tty_t* tty = NULL;
    char* cmd = strdup("{param = \"'ABC' in list\"}");
    amxc_var_t values;
    amxc_var_t parts;

    amxc_var_init(&parts);
    amxc_var_init(&values);

    assert_int_equal(amxt_tty_open(&tty, fileno(stdin)), 0);

    assert_int_equal(amxt_cmd_parse_line(cmd, strlen(cmd), &parts, NULL), 0);
    amxc_var_set_type(&values, AMXC_VAR_ID_HTABLE);

    assert_int_equal(amxt_cmd_parse_values(tty, &parts, AMXT_VP_COMPOSITE | AMXT_VP_TABLE, &values), 0);

    amxc_var_clean(&values);
    amxc_var_clean(&parts);
    free(cmd);
    amxt_tty_close(&tty);
}

void test_can_parse_composite_table(UNUSED void** state) {
    amxt_tty_t* tty = NULL;
    char* cmd = strdup("{Param1 = { Param1 = 1, Param2 = 2 }, Param2 = [ 1, 2 ] }");
    amxc_var_t values;
    amxc_var_t parts;
    amxc_var_t* val = NULL;

    amxc_var_init(&parts);
    amxc_var_init(&values);

    assert_int_equal(amxt_tty_open(&tty, fileno(stdin)), 0);

    assert_int_equal(amxt_cmd_parse_line(cmd, strlen(cmd), &parts, NULL), 0);
    assert_int_equal(amxt_cmd_parse_values(tty, &parts,
                                           AMXT_VP_TABLE | AMXT_VP_ARRAY | AMXT_VP_COMPOSITE,
                                           &values), 0);

    val = GET_ARG(&values, "Param1");
    assert_non_null(val);
    assert_int_equal(amxc_var_type_of(val), AMXC_VAR_ID_HTABLE);
    val = GET_ARG(&values, "Param2");
    assert_non_null(val);
    assert_int_equal(amxc_var_type_of(val), AMXC_VAR_ID_LIST);

    amxc_var_clean(&values);
    amxc_var_clean(&parts);
    free(cmd);
    amxt_tty_close(&tty);
}

void test_can_parse_composite_array(UNUSED void** state) {
    amxt_tty_t* tty = NULL;
    char* cmd = strdup("[ { Param1 = 1, Param2 = 'A' }, [ 1, 'A' ] ]");
    amxc_var_t values;
    amxc_var_t parts;
    amxc_var_t* val = NULL;

    amxc_var_init(&parts);
    amxc_var_init(&values);

    assert_int_equal(amxt_tty_open(&tty, fileno(stdin)), 0);

    assert_int_equal(amxt_cmd_parse_line(cmd, strlen(cmd), &parts, NULL), 0);
    assert_int_equal(amxt_cmd_parse_values(tty, &parts,
                                           AMXT_VP_TABLE | AMXT_VP_ARRAY | AMXT_VP_COMPOSITE,
                                           &values), 0);

    amxc_var_dump(&values, STDOUT_FILENO);
    val = GETI_ARG(&values, 0);
    assert_non_null(val);
    assert_int_equal(amxc_var_type_of(val), AMXC_VAR_ID_HTABLE);
    val = GETI_ARG(&values, 1);
    assert_non_null(val);
    assert_int_equal(amxc_var_type_of(val), AMXC_VAR_ID_LIST);

    amxc_var_clean(&values);
    amxc_var_clean(&parts);
    free(cmd);
    amxt_tty_close(&tty);
}

void test_parsing_fails_when_array_not_allowed(UNUSED void** state) {
    amxt_tty_t* tty = NULL;
    char* cmd = strdup("[123, true, -123]");
    amxc_var_t values;
    amxc_var_t parts;

    amxc_var_init(&parts);
    amxc_var_init(&values);

    assert_int_equal(amxt_tty_open(&tty, fileno(stdin)), 0);

    assert_int_equal(amxt_cmd_parse_line(cmd, strlen(cmd), &parts, NULL), 0);
    assert_int_not_equal(amxt_cmd_parse_values(tty, &parts, 0, &values), 0);

    amxc_var_clean(&values);
    amxc_var_clean(&parts);
    free(cmd);
    amxt_tty_close(&tty);
}

void test_parsing_fails_when_table_not_allowed(UNUSED void** state) {
    amxt_tty_t* tty = NULL;
    char* cmd = strdup("{ P1 = 123, P2 = true, p3 = -123 }");
    amxc_var_t values;
    amxc_var_t parts;

    amxc_var_init(&parts);
    amxc_var_init(&values);

    assert_int_equal(amxt_tty_open(&tty, fileno(stdin)), 0);

    assert_int_equal(amxt_cmd_parse_line(cmd, strlen(cmd), &parts, NULL), 0);
    assert_int_not_equal(amxt_cmd_parse_values(tty, &parts, 0, &values), 0);

    amxc_var_clean(&values);
    amxc_var_clean(&parts);
    free(cmd);
    amxt_tty_close(&tty);
}

void test_parsing_fails_when_missing_key(UNUSED void** state) {
    amxt_tty_t* tty = NULL;
    char* cmd1 = strdup("{ P1 = 123, = true, p3 = -123 }");
    char* cmd2 = strdup("{ -123 }");
    amxc_var_t values;
    amxc_var_t parts;

    amxc_var_init(&parts);
    amxc_var_init(&values);

    assert_int_equal(amxt_tty_open(&tty, fileno(stdin)), 0);

    assert_int_equal(amxt_cmd_parse_line(cmd1, strlen(cmd1), &parts, NULL), 0);
    assert_int_not_equal(amxt_cmd_parse_values(tty, &parts, AMXT_VP_TABLE, &values), 0);
    amxc_var_clean(&values);
    amxc_var_clean(&parts);
    free(cmd1);

    assert_int_equal(amxt_cmd_parse_line(cmd2, strlen(cmd2), &parts, NULL), 0);
    assert_int_not_equal(amxt_cmd_parse_values(tty, &parts, AMXT_VP_TABLE, &values), 0);
    amxc_var_clean(&values);
    amxc_var_clean(&parts);
    free(cmd2);

    amxt_tty_close(&tty);
}

void test_parsing_when_missing_value(UNUSED void** state) {
    amxt_tty_t* tty = NULL;
    char* cmd1 = strdup("{ P1 = }");
    amxc_var_t values;
    amxc_var_t parts;

    amxc_var_init(&parts);
    amxc_var_init(&values);

    assert_int_equal(amxt_tty_open(&tty, fileno(stdin)), 0);

    assert_int_equal(amxt_cmd_parse_line(cmd1, strlen(cmd1), &parts, NULL), 0);
    assert_int_equal(amxt_cmd_parse_values(tty, &parts, AMXT_VP_TABLE, &values), 0);
    amxc_var_clean(&values);
    amxc_var_clean(&parts);
    free(cmd1);

    amxt_tty_close(&tty);
}

void test_parsing_fails_when_no_equal(UNUSED void** state) {
    amxt_tty_t* tty = NULL;
    char* cmd1 = strdup("{ P1 [ 123, 666 ] }");
    char* cmd2 = strdup("[ P1 { P1 = 123, P2 = 666 } ]");
    amxc_var_t values;
    amxc_var_t parts;

    amxc_var_init(&parts);
    amxc_var_init(&values);

    assert_int_equal(amxt_tty_open(&tty, fileno(stdin)), 0);

    assert_int_equal(amxt_cmd_parse_line(cmd1, strlen(cmd1), &parts, NULL), 0);
    assert_int_not_equal(amxt_cmd_parse_values(tty, &parts,
                                               AMXT_VP_TABLE | AMXT_VP_ARRAY | AMXT_VP_COMPOSITE,
                                               &values), 0);
    amxc_var_clean(&values);
    amxc_var_clean(&parts);
    free(cmd1);

    assert_int_equal(amxt_cmd_parse_line(cmd2, strlen(cmd2), &parts, NULL), 0);
    assert_int_not_equal(amxt_cmd_parse_values(tty, &parts,
                                               AMXT_VP_TABLE | AMXT_VP_ARRAY | AMXT_VP_COMPOSITE,
                                               &values), 0);
    amxc_var_clean(&values);
    amxc_var_clean(&parts);
    free(cmd2);

    amxt_tty_close(&tty);
}

void test_parsing_composite_fails_when_not_allowed(UNUSED void** state) {
    amxt_tty_t* tty = NULL;
    char* cmd1 = strdup("{ P1 = [ 123, 666 ] }");
    char* cmd2 = strdup("[ P1 , { P1 = 123, P2 = 666 } ]");
    amxc_var_t values;
    amxc_var_t parts;

    amxc_var_init(&parts);
    amxc_var_init(&values);

    assert_int_equal(amxt_tty_open(&tty, fileno(stdin)), 0);

    assert_int_equal(amxt_cmd_parse_line(cmd1, strlen(cmd1), &parts, NULL), 0);
    assert_int_not_equal(amxt_cmd_parse_values(tty, &parts,
                                               AMXT_VP_TABLE | AMXT_VP_ARRAY,
                                               &values), 0);
    amxc_var_clean(&values);
    amxc_var_clean(&parts);
    free(cmd1);

    assert_int_equal(amxt_cmd_parse_line(cmd2, strlen(cmd2), &parts, NULL), 0);
    assert_int_not_equal(amxt_cmd_parse_values(tty, &parts,
                                               AMXT_VP_TABLE | AMXT_VP_ARRAY,
                                               &values), 0);
    amxc_var_clean(&values);
    amxc_var_clean(&parts);
    free(cmd2);

    amxt_tty_close(&tty);
}

void test_parsing_fails_when_key_in_array(UNUSED void** state) {
    amxt_tty_t* tty = NULL;
    char* cmd1 = strdup("[ P1 = \"aaa\" ]");
    amxc_var_t values;
    amxc_var_t parts;

    amxc_var_init(&parts);
    amxc_var_init(&values);

    assert_int_equal(amxt_tty_open(&tty, fileno(stdin)), 0);

    assert_int_equal(amxt_cmd_parse_line(cmd1, strlen(cmd1), &parts, NULL), 0);
    assert_int_not_equal(amxt_cmd_parse_values(tty, &parts,
                                               AMXT_VP_TABLE | AMXT_VP_ARRAY | AMXT_VP_COMPOSITE,
                                               &values), 0);
    amxc_var_clean(&values);
    amxc_var_clean(&parts);
    free(cmd1);

    amxt_tty_close(&tty);
}

void test_parsing_fails_when_double_key(UNUSED void** state) {
    amxt_tty_t* tty = NULL;
    char* cmd1 = strdup("{ P1 = P2 = \"aaa\" }");
    amxc_var_t values;
    amxc_var_t parts;

    amxc_var_init(&parts);
    amxc_var_init(&values);

    assert_int_equal(amxt_tty_open(&tty, fileno(stdin)), 0);

    assert_int_equal(amxt_cmd_parse_line(cmd1, strlen(cmd1), &parts, NULL), 0);
    assert_int_not_equal(amxt_cmd_parse_values(tty, &parts,
                                               AMXT_VP_TABLE | AMXT_VP_ARRAY | AMXT_VP_COMPOSITE,
                                               &values), 0);
    amxc_var_clean(&values);
    amxc_var_clean(&parts);
    free(cmd1);

    amxt_tty_close(&tty);
}

void test_parsing_fails_when_not_array_or_table(UNUSED void** state) {
    amxt_tty_t* tty = NULL;
    char* cmd1 = strdup("false");
    amxc_var_t values;
    amxc_var_t parts;

    amxc_var_init(&parts);
    amxc_var_init(&values);

    assert_int_equal(amxt_tty_open(&tty, fileno(stdin)), 0);

    assert_int_equal(amxt_cmd_parse_line(cmd1, strlen(cmd1), &parts, NULL), 0);
    assert_int_not_equal(amxt_cmd_parse_values(tty, &parts,
                                               AMXT_VP_TABLE | AMXT_VP_ARRAY | AMXT_VP_COMPOSITE,
                                               &values), 0);
    amxc_var_clean(&values);
    amxc_var_clean(&parts);
    free(cmd1);

    amxt_tty_close(&tty);
}

void test_can_parse_primitive(UNUSED void** state) {
    amxt_tty_t* tty = NULL;
    char* cmd1 = strdup("false");
    amxc_var_t values;
    amxc_var_t parts;

    amxc_var_init(&parts);
    amxc_var_init(&values);

    assert_int_equal(amxt_tty_open(&tty, fileno(stdin)), 0);

    assert_int_equal(amxt_cmd_parse_line(cmd1, strlen(cmd1), &parts, NULL), 0);
    assert_int_equal(amxt_cmd_parse_values(tty, &parts, AMXT_VP_PRIMITIVE, &values), 0);
    assert_int_equal(amxc_var_type_of(&values), AMXC_VAR_ID_BOOL);
    amxc_var_clean(&values);
    amxc_var_clean(&parts);
    free(cmd1);

    amxt_tty_close(&tty);
}

void test_can_get_values(UNUSED void** state) {
    amxt_tty_t* tty = NULL;
    char* cmd1 = strdup("'{\"a\":123,\"b\":true}'");
    amxc_var_t values;
    amxc_var_t parts;

    amxc_var_init(&parts);
    amxc_var_init(&values);

    assert_int_equal(amxt_tty_open(&tty, fileno(stdin)), 0);

    assert_int_equal(amxt_cmd_parse_line(cmd1, strlen(cmd1), &parts, NULL), 0);
    assert_int_equal(amxt_cmd_get_values(&parts, AMXT_VP_PRIMITIVE, &values), 0);
    assert_int_equal(amxc_var_type_of(&values), AMXC_VAR_ID_CSTRING);

    assert_string_equal(amxc_var_constcast(cstring_t, &values), "{\"a\":123,\"b\":true}");

    amxc_var_clean(&values);
    amxc_var_clean(&parts);
    free(cmd1);

    amxt_tty_close(&tty);
}

void test_quoted_string_is_a_string(UNUSED void** state) {
    amxt_tty_t* tty = NULL;
    char* cmd1 = strdup("'1234'");
    amxc_var_t values;
    amxc_var_t parts;

    amxc_var_init(&parts);
    amxc_var_init(&values);

    assert_int_equal(amxt_tty_open(&tty, fileno(stdin)), 0);

    assert_int_equal(amxt_cmd_parse_line(cmd1, strlen(cmd1), &parts, NULL), 0);
    assert_int_equal(amxt_cmd_get_values(&parts, AMXT_VP_PRIMITIVE, &values), 0);
    assert_int_equal(amxc_var_type_of(&values), AMXC_VAR_ID_CSTRING);

    assert_string_equal(amxc_var_constcast(cstring_t, &values), "1234");

    amxc_var_clean(&values);
    amxc_var_clean(&parts);
    free(cmd1);

    cmd1 = strdup("1234");

    amxc_var_init(&parts);
    amxc_var_init(&values);

    assert_int_equal(amxt_cmd_parse_line(cmd1, strlen(cmd1), &parts, NULL), 0);
    assert_int_equal(amxt_cmd_get_values(&parts, AMXT_VP_PRIMITIVE, &values), 0);
    assert_int_not_equal(amxc_var_type_of(&values), AMXC_VAR_ID_CSTRING);

    amxc_var_clean(&values);
    amxc_var_clean(&parts);
    free(cmd1);


    amxt_tty_close(&tty);
}
