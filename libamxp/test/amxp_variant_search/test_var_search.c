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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <fcntl.h>
#include <cmocka.h>
#include <errno.h>

#include <yajl/yajl_gen.h>

#include <amxc/amxc.h>
#include <amxp/amxp_expression.h>

#include <amxj/amxj_variant.h>

#include "test_var_search.h"

static amxc_var_t* test_set1 = NULL;
static amxc_var_t* test_set2 = NULL;

static int read_data(const char* file, amxc_var_t** data) {
    int fd = -1;
    variant_json_t* reader = NULL;
    // create a json reader
    if(amxj_reader_new(&reader) != 0) {
        printf("Failed to create json file reader");
        return 1;
    }

    // open the json file
    fd = open(file, O_RDONLY);
    if(fd == -1) {
        amxj_reader_delete(&reader);
        printf("File open file %s - error 0x%8.8X", file, errno);
        return 2;
    }

    // read the json file and parse the json text
    amxj_read(reader, fd);

    // get the variant
    *data = amxj_reader_result(reader);

    // delete the reader and close the file
    amxj_reader_delete(&reader);
    close(fd);

    return 0;
}

int test_var_search_setup(UNUSED void** state) {
    assert_int_equal(read_data("./test_set1.data", &test_set1), 0);
    assert_int_equal(read_data("./test_set2.data", &test_set2), 0);
    return 0;
}

int test_var_search_teardown(UNUSED void** state) {
    amxc_var_delete(&test_set1);
    amxc_var_delete(&test_set2);
    return 0;
}

void test_can_filter_values(UNUSED void** state) {
    const char* sp1 = "94:83:c4:06:da:66.[MACAddress == '00:01:02:03:44:f0'].Extender";
    const char* sp2 = "['Foundation' in Science-fiction].Author";
    const char* sp3 = "*.Awards.*.[year == 1980]";
    const char* sp4 = "0.[Age > 50]";
    const char* sp5 = "0.[Age > 60]";
    const char* sp6 = "0.[Age > 10]";

    amxc_htable_it_t* it = NULL;
    amxc_var_t* data = NULL;
    amxc_htable_t results;
    amxc_htable_init(&results, 5);

    assert_int_equal(amxp_expr_find_var_values(test_set1, &results, sp1), 0);
    assert_int_equal(amxc_htable_size(&results), 1);
    it = amxc_htable_get(&results, "'94:83:c4:06:da:66'.0.'Extender'");
    assert_non_null(it);
    data = amxc_var_from_htable_it(it);
    assert_non_null(data);
    assert_int_equal(amxc_var_type_of(data), AMXC_VAR_ID_BOOL);
    amxc_htable_clean(&results, variant_htable_it_free);

    amxc_htable_init(&results, 5);
    assert_int_equal(amxp_expr_find_var_values(test_set2, &results, sp2), 0);
    assert_int_equal(amxc_htable_size(&results), 1);
    it = amxc_htable_get(&results, "1.'Author'");
    assert_non_null(it);
    data = amxc_var_from_htable_it(it);
    assert_non_null(data);
    assert_int_equal(amxc_var_type_of(data), AMXC_VAR_ID_CSTRING);
    amxc_htable_clean(&results, variant_htable_it_free);

    amxc_htable_init(&results, 5);
    assert_int_equal(amxp_expr_find_var_values(test_set2, &results, sp3), 0);
    assert_int_equal(amxc_htable_size(&results), 1);
    it = amxc_htable_get(&results, "2.'Awards'.'Hugo'.1");
    assert_non_null(it);
    data = amxc_var_from_htable_it(it);
    assert_non_null(data);
    assert_int_equal(amxc_var_type_of(data), AMXC_VAR_ID_HTABLE);
    amxc_htable_clean(&results, variant_htable_it_free);

    amxc_htable_init(&results, 5);
    assert_int_equal(amxp_expr_find_var_values(test_set2, &results, sp4), 0);
    assert_int_equal(amxc_htable_size(&results), 1);
    it = amxc_htable_get(&results, "0.'John Doe'");
    assert_non_null(it);
    data = amxc_var_from_htable_it(it);
    assert_non_null(data);
    assert_int_equal(amxc_var_type_of(data), AMXC_VAR_ID_HTABLE);
    amxc_htable_clean(&results, variant_htable_it_free);

    amxc_htable_init(&results, 5);
    assert_int_equal(amxp_expr_find_var_values(test_set2, &results, sp5), 0);
    assert_int_equal(amxc_htable_size(&results), 0);
    amxc_htable_clean(&results, variant_htable_it_free);

    amxc_htable_init(&results, 5);
    assert_int_equal(amxp_expr_find_var_values(test_set2, &results, sp6), 0);
    assert_int_equal(amxc_htable_size(&results), 2);
    amxc_htable_clean(&results, variant_htable_it_free);
}

void test_can_use_paths(UNUSED void** state) {
    const char* sp1 = "2.'Awards'.'Hugo'.1";
    amxc_llist_it_t* it = NULL;
    amxc_string_t* path = NULL;
    amxc_llist_t results;
    amxc_llist_init(&results);

    assert_int_equal(amxp_expr_find_var_paths(test_set2, &results, sp1), 0);
    assert_int_equal(amxc_llist_size(&results), 1);
    it = amxc_llist_get_first(&results);
    assert_non_null(it);
    path = amxc_string_from_llist_it(it);
    assert_non_null(path);
    assert_string_equal(amxc_string_get(path, 0), sp1);
    amxc_llist_clean(&results, amxc_string_list_it_free);
}

void test_can_get_filtered_value(UNUSED void** state) {
    const char* sp1 = "2.'Awards'.'Hugo'.1";
    const char* sp2 = "*.Awards.*.[year == 1980]";
    amxc_var_t* data = NULL;

    data = amxp_expr_find_var(test_set2, sp1);
    assert_non_null(data);

    data = amxp_expr_find_var(test_set2, sp2);
    assert_non_null(data);
}

void test_get_filtered_value_fails_when_multiple_matches_found(UNUSED void** state) {
    const char* sp1 = "0.[Age > 10]";
    amxc_var_t* data = NULL;

    data = amxp_expr_find_var(test_set2, sp1);
    assert_null(data);
}

void test_filter_fails_if_on_simple_type(UNUSED void** state) {
    const char* sp1 = "0.Age.[Age > 10]";
    amxc_var_t* data = NULL;

    data = amxp_expr_find_var(test_set2, sp1);
    assert_null(data);
}
